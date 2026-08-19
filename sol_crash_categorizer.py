#!/usr/bin/env python3
"""
Group a sol fuzzer crash corpus into unique bugs.

For each crash input:
  1. Replay it through the matching fuzzer binary with PROTO_FUZZER_DUMP_PATH /
     PROTO_FUZZER_DUMP_CALLDATA_PATH set, writing <crash>.sol, <crash>.calldata
     and the fuzzer's own stderr to <crash>.err.  Without the calldata the
     replay calls test() with an empty argument tail and input-dependent
     divergences do not reproduce.
  2. Derive a signature from (a) the assertion text the harness threw and
     (b) a hash of the Solidity source with literals and identifier numbering
     normalized away, so re-discoveries of the same bug collapse together.
  3. Print the buckets, largest first, and write unique_sol_crashes.txt.

Inputs may be crash files or directories; directories are walked recursively,
so a whole AFL findings tree can be passed in one go.  The fuzzer binary is
taken from --fuzzer, else inferred from an "NNN-<binary>" component of the
crash path, else sol_proto_ossfuzz_evmone.

Usage:
    ./sol_crash_categorizer.py ./results/637-sol_proto_ossfuzz_evmone_viair/findings/*/crashes/
    ./sol_crash_categorizer.py --fuzzer sol_ice_ossfuzz -j16 ice_crashes
    ./sol_crash_categorizer.py --replay results/637-*/findings
    ./sol_crash_categorizer.py --summary-only results/637-*/findings
"""

import argparse
import hashlib
import os
import re
import signal
import subprocess
import sys
import tempfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
RUNNER = REPO_ROOT / "build" / "tools" / "runners" / "sol_debug_runner"
FUZZER_DIR = REPO_ROOT / "build_afl" / "tools" / "ossfuzz"
DEFAULT_FUZZER = "sol_proto_ossfuzz_evmone"
DEFAULT_JOBS = min(8, os.cpu_count() or 1)
MAX_EXAMPLES = 3

# Solidity constructs worth naming in the report; the shape hash already
# separates the buckets, this is just a human-readable label for what is in them.
FEATURES = [
    "assembly", "unchecked", "try", "catch", "modifier", "library", "using",
    "interface", "abstract", "struct", "enum", "mapping", "event", "emit",
    "constructor", "fallback", "receive", "payable", "immutable", "constant",
    "delegatecall", "staticcall", "callcode", "selfdestruct", "keccak256",
    "abi.encode", "abi.decode", "abi.encodePacked", "new", "revert", "require",
    "storage", "memory", "calldata", "transient", "function", "for", "while",
]

WHAT_RE = re.compile(r"^\s*what\(\):\s*(.*)$", re.MULTILINE)
TERMINATE_RE = re.compile(r"terminate called after throwing an instance of '([^']+)'")
ASAN_RE = re.compile(r"(AddressSanitizer:\s*\S+|UndefinedBehaviorSanitizer:\s*\S+|runtime error:.*)")
MODE_PREFIX_RE = re.compile(r"^Sol[\w ]*fuzzer(?:\s*\([^)]*\))?:\s*")
DIR_TAG_RE = re.compile(r"^\d+-(sol_\w+)$")


def infer_fuzzer(paths: list[Path]) -> str:
    for p in paths:
        for part in reversed(p.resolve().parts):
            m = DIR_TAG_RE.match(part)
            if m:
                return m.group(1)
    return DEFAULT_FUZZER


def is_crash_input(p: Path) -> bool:
    """Raw AFL/libFuzzer inputs only — not the .sol/.calldata/.err/.out we write next to them."""
    return "." not in p.name and (p.name.startswith("id:") or p.name.startswith("crash-"))


def collect_inputs(paths: list[Path]) -> list[Path]:
    inputs: list[Path] = []
    for p in paths:
        if p.is_dir():
            inputs += [c for c in sorted(p.rglob("*")) if c.is_file() and is_crash_input(c)]
        elif p.is_file():
            inputs.append(p)
    return inputs


def run_limited(cmd, timeout: int, **kwargs) -> subprocess.CompletedProcess:
    """subprocess.run, but a timeout kills the whole process group."""
    with subprocess.Popen(cmd, start_new_session=True, **kwargs) as proc:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            out, err = proc.communicate()
            raise subprocess.TimeoutExpired(cmd, timeout, out, err)
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def dump(crash: Path, dumper: Path, timeout: int) -> str:
    """Run the fuzzer on the input; write the artifacts, return its stderr."""
    env = {**os.environ,
           "PROTO_FUZZER_DUMP_PATH": str(Path(f"{crash}.sol")),
           "PROTO_FUZZER_DUMP_CALLDATA_PATH": str(Path(f"{crash}.calldata"))}
    try:
        result = run_limited([str(dumper), str(crash)], timeout, env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        err = result.stderr
        if result.returncode == 0:
            err += "\nNO-CRASH: fuzzer exited cleanly\n"
    except subprocess.TimeoutExpired as exc:
        partial = exc.stderr or ""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        err = partial + f"\nTIMEOUT after {timeout}s\n"
    Path(f"{crash}.err").write_text(err)
    return err


def calldata_of(crash: Path) -> str:
    p = Path(f"{crash}.calldata")
    return p.read_text(errors="replace").strip() if p.is_file() else ""


def replay(crash: Path, timeout: int, work_root: Path) -> int | None:
    """Re-run the dumped Solidity through sol_debug_runner; return its exit code."""
    sol_out = Path(f"{crash}.sol")
    if not sol_out.is_file():
        return None
    calldata = calldata_of(crash)
    cd_args = ["--calldata", calldata] if calldata else []
    cmd = [str(RUNNER), "--verbose", *cd_args, str(sol_out.resolve())]
    # Per-task cwd: parallel runners would otherwise collide on their output dirs.
    with tempfile.TemporaryDirectory(dir=str(work_root)) as work:
        with Path(f"{crash}.out").open("wb") as out:
            try:
                return run_limited(cmd, timeout, cwd=work, stdout=out,
                                   stderr=subprocess.STDOUT).returncode
            except subprocess.TimeoutExpired:
                return None


def message_of(err_text: str) -> str:
    m = ASAN_RE.search(err_text)
    if m:
        return f"SAN {m.group(1).strip()}"
    if "TIMEOUT after" in err_text:
        return "TIMEOUT"
    if "NO-CRASH" in err_text:
        return "NO-CRASH (does not reproduce)"
    whats = WHAT_RE.findall(err_text)
    if whats:
        # Strip the fuzzer-mode prefix: it is the same for every crash of one binary.
        return MODE_PREFIX_RE.sub("", whats[-1].strip())
    m = TERMINATE_RE.search(err_text)
    if m:
        return f"uncaught {m.group(1)}"
    return "UNKNOWN (no diagnostic in stderr)"


def shape_hash(sol_text: str) -> str:
    """Hash the source with the parts a mutator freely varies normalized away."""
    t = re.sub(r"//[^\n]*|pragma[^\n]*", "", sol_text)
    t = re.sub(r"0x[0-9a-fA-F]+", "N", t)
    t = re.sub(r"\d+", "N", t)
    # Generated names carry a scope suffix (C0_a, f0_0_b, i0_a) that varies freely.
    t = re.sub(r"(?<=[\w])_[a-z]{1,2}\b", "_S", t)
    t = re.sub(r"\s+", " ", t).strip()
    return hashlib.sha1(t.encode()).hexdigest()[:8]


def feature_re(feat: str) -> re.Pattern:
    pat = re.escape(feat)
    if feat[0].isalnum() or feat[0] == "_":
        pat = r"\b" + pat
    if feat[-1].isalnum() or feat[-1] == "_":
        pat = pat + r"\b"
    return re.compile(pat)


FEATURE_RES = [(f, feature_re(f)) for f in FEATURES]


def features_of(sol_text: str) -> str:
    found = [f for f, rx in FEATURE_RES if rx.search(sol_text)]
    return ", ".join(found) if found else "(none)"


def signature(crash: Path) -> tuple[str, str]:
    """Return (signature, feature label) for one already-dumped crash."""
    err_path, sol_path = Path(f"{crash}.err"), Path(f"{crash}.sol")
    msg = message_of(err_path.read_text(errors="replace")) if err_path.is_file() else "NO-ARTIFACT"
    if not sol_path.is_file() or sol_path.stat().st_size == 0:
        return f"{msg}  [no .sol dumped]", "(none)"
    sol = sol_path.read_text(errors="replace")
    return f"{msg}  [shape {shape_hash(sol)}]", features_of(sol)


def summarize(crashes: list[Path], replay_rc: dict[Path, int | None], out_file: Path) -> int:
    buckets: dict[str, list[Path]] = defaultdict(list)
    labels: dict[str, str] = {}
    for c in crashes:
        sig, feats = signature(c)
        buckets[sig].append(c)
        labels.setdefault(sig, feats)

    lines = [f"=== Unique sol crash signatures: {len(buckets)} (from {len(crashes)} inputs) ==="]
    for sig, members in sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        lines += ["", f"[{len(members)}] {sig}", f"    features: {labels[sig]}"]
        if replay_rc:
            rcs = sorted({str(replay_rc.get(m)) for m in members})
            lines.append(f"    sol_debug_runner rc: {', '.join(rcs)}")
        lines.append(f"    representative: {members[0]}")
        others = members[1:MAX_EXAMPLES]
        if others:
            hidden = len(members) - 1 - len(others)
            lines.append("    others: " + ", ".join(str(o) for o in others)
                         + (f" (+{hidden} more)" if hidden else ""))

    by_msg: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for sig, members in buckets.items():
        entry = by_msg[sig.split("  [", 1)[0]]
        entry[0] += len(members)
        entry[1] += 1
    lines += ["", "=== By message ==="]
    for msg, (n_inputs, n_shapes) in sorted(by_msg.items(), key=lambda kv: -kv[1][0]):
        lines.append(f"  {n_inputs:5d} inputs / {n_shapes:4d} shapes  {msg}")

    text = "\n".join(lines) + "\n"
    print(text)
    out_file.write_text(text)
    print(f"Wrote summary to {out_file}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("crashes", nargs="+", help="crash files and/or directories of them")
    parser.add_argument("--fuzzer", default=None,
                        help="fuzzer binary name or path (default: inferred from the crash "
                             f"path, else {DEFAULT_FUZZER})")
    parser.add_argument("--timeout", type=int, default=120, help="per-file timeout in seconds (default: 120)")
    parser.add_argument("-j", "--jobs", type=int, default=DEFAULT_JOBS,
                        help=f"files to process concurrently (default: {DEFAULT_JOBS})")
    parser.add_argument("--replay", action="store_true",
                        help="also run sol_debug_runner on each dump and report its exit code "
                             "(rc=1 means the mismatch reproduces standalone)")
    parser.add_argument("--summary-only", action="store_true",
                        help="skip the dumping step; bucket the existing .sol/.err artifacts")
    parser.add_argument("-o", "--output", default="unique_sol_crashes.txt", help="summary file (default: %(default)s)")
    args = parser.parse_args()

    paths = [Path(c) for c in args.crashes]
    crashes = collect_inputs(paths)
    if not crashes:
        print("ERROR: no crash inputs found", file=sys.stderr)
        return 2

    if args.summary_only:
        return summarize(crashes, {}, Path(args.output))

    name = args.fuzzer or infer_fuzzer(paths)
    dumper = (Path(name) if "/" in name else FUZZER_DIR / name).resolve()
    needed = [dumper] + ([RUNNER] if args.replay else [])
    for p in needed:
        if not (p.is_file() and os.access(p, os.X_OK)):
            print(f"ERROR: missing or not executable: {p}", file=sys.stderr)
            return 2

    replay_rc: dict[Path, int | None] = {}
    total = len(crashes)
    print(f"inputs={total} jobs={args.jobs} dumper={dumper.name}")

    with tempfile.TemporaryDirectory() as work_root:
        def process(crash: Path):
            err = dump(crash, dumper, args.timeout)
            rc = replay(crash, args.timeout, Path(work_root)) if args.replay else None
            return crash, message_of(err), rc

        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            futures = {pool.submit(process, c): c for c in crashes}
            for n, fut in enumerate(as_completed(futures), 1):
                try:
                    crash, msg, rc = fut.result()
                except Exception as e:
                    print(f"[{n}/{total}] FAIL {futures[fut].name}: {e!r}", flush=True)
                    continue
                replay_rc[crash] = rc
                rc_note = f" rc={rc}" if args.replay else ""
                print(f"[{n}/{total}] {crash.name}: {msg}{rc_note}", flush=True)

    print()
    return summarize(crashes, replay_rc if args.replay else {}, Path(args.output))


if __name__ == "__main__":
    sys.exit(main())
