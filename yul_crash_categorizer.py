#!/usr/bin/env python3
"""
Group a yul fuzzer crash corpus into unique bugs.

For each crash input:
  1. Replay it through the matching fuzzer binary with PROTO_FUZZER_DUMP_PATH /
     PROTO_FUZZER_DUMP_SEQ_PATH set, writing <crash>.yul, <crash>.seq and the
     fuzzer's own stderr to <crash>.err.  The calldata is read straight out of
     the (text-format) protobuf input into <crash>.calldata -- the fuzzer does
     not dump it, and without it the replay executes a different program.
  2. Derive a signature from (a) the assertion text the harness threw and
     (b) a hash of the Yul source with literals and identifier numbering
     normalized away, so re-discoveries of the same bug collapse together.
  3. Print the buckets, largest first, and write unique_yul_crashes.txt.

Inputs may be crash files or directories; directories are walked recursively,
so a whole AFL findings tree can be passed in one go.

Usage:
    ./yul_crash_categorizer.py results/639-*/findings
    ./yul_crash_categorizer.py -m no_ssa -j16 no_ssa_crash
    ./yul_crash_categorizer.py --replay results/639-*/findings
    ./yul_crash_categorizer.py --summary-only results/639-*/findings
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
RUNNER = REPO_ROOT / "build" / "tools" / "runners" / "yul_debug_runner"
FUZZER_DIR = REPO_ROOT / "build_afl" / "tools" / "ossfuzz"
DEFAULT_JOBS = min(8, os.cpu_count() or 1)
MAX_EXAMPLES = 3

VALID_PASSES = list("cSLMsrD")
VALID_MODES = ["ssacfg", "check_stack_alloc", "no_ssa", "default"]
VALID_SELECTORS = VALID_PASSES + VALID_MODES

# Yul constructs worth naming in the report; the shape hash already separates
# the buckets, this is just a human-readable label for what is in them.
FEATURES = [
    "tstore", "tload", "sstore", "sload", "mstore", "selfdestruct",
    "create2", "create", "delegatecall", "staticcall", "callcode", "call",
    "log0", "log1", "log2", "log3", "log4", "return", "revert",
    "datacopy", "memoryguard", "verbatim", "function", "for", "switch", "leave",
]

WHAT_RE = re.compile(r"^\s*what\(\):\s*(.*)$", re.MULTILINE)
TERMINATE_RE = re.compile(r"terminate called after throwing an instance of '([^']+)'")
ASAN_RE = re.compile(r"(AddressSanitizer:\s*\S+|UndefinedBehaviorSanitizer:\s*\S+|runtime error:.*)")


def dumper_name(sel: str) -> str:
    if sel in VALID_PASSES:
        return f"yul_proto_ossfuzz_evmone_single_pass_{sel}"
    if sel == "default":
        return "yul_proto_ossfuzz_evmone"
    return f"yul_proto_ossfuzz_evmone_{sel}"


def is_crash_input(p: Path) -> bool:
    """Raw AFL/libFuzzer inputs only — not the .yul/.seq/.err/.out we write next to them."""
    return "." not in p.name and (p.name.startswith("id:") or p.name.startswith("crash-"))


def collect_inputs(paths: list[Path]) -> list[Path]:
    inputs: list[Path] = []
    for p in paths:
        if p.is_dir():
            inputs += [c for c in sorted(p.rglob("*")) if c.is_file() and is_crash_input(c)
                       and c.parent.name not in ("hangs", "queue")]
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


def parse_seq(seq_path: Path) -> tuple[str, str]:
    opt = cleanup = ""
    for line in seq_path.read_text(errors="replace").splitlines():
        if line.startswith("optimizer-sequence:"):
            opt = line.split(":", 1)[1].strip()
        elif line.startswith("optimizer-cleanup-sequence:"):
            cleanup = line.split(":", 1)[1].strip()
    return opt, cleanup


CALLDATA_BLOCK_RE = re.compile(r"^calldata\s*\{(.*?)^\}", re.S | re.M)
STRING_LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
SIMPLE_ESCAPES = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11,
                  "\\": 92, "'": 39, '"': 34, "?": 63}
HEXDIGITS = "0123456789abcdefABCDEF"


def unescape_text_proto(s: str) -> bytes:
    """Decode the C-style escapes protobuf text format uses inside a bytes field."""
    out, i = bytearray(), 0
    while i < len(s):
        if s[i] != "\\":
            out += s[i].encode("latin-1")
            i += 1
            continue
        i += 1
        if i >= len(s):
            break
        e = s[i]
        if e in SIMPLE_ESCAPES:
            out.append(SIMPLE_ESCAPES[e])
            i += 1
        elif e == "x":
            j = i + 1
            while j < len(s) and j < i + 3 and s[j] in HEXDIGITS:
                j += 1
            out.append(int(s[i + 1:j] or "0", 16) & 0xFF)
            i = j
        elif e in "01234567":
            j = i
            while j < len(s) and j < i + 3 and s[j] in "01234567":
                j += 1
            out.append(int(s[i:j], 8) & 0xFF)
            i = j
        else:
            out += e.encode("latin-1")
            i += 1
    return bytes(out)


def calldata_of(crash: Path) -> str:
    """Hex calldata from the text-proto crash input ('' if absent/unparsable)."""
    try:
        text = crash.read_bytes().decode("latin-1")
    except OSError:
        return ""
    m = CALLDATA_BLOCK_RE.search(text)
    if not m:
        return ""
    raw = b"".join(unescape_text_proto(lit) for lit in STRING_LITERAL_RE.findall(m.group(1)))
    return raw.hex()


def dump(crash: Path, dumper: Path, sel: str, timeout: int) -> str:
    """Run the fuzzer on the input; write the artifacts, return its stderr."""
    yul_out = Path(f"{crash}.yul")
    seq_out = Path(f"{crash}.seq")
    env = {**os.environ, "PROTO_FUZZER_DUMP_PATH": str(yul_out)}
    if sel not in VALID_PASSES:
        env["PROTO_FUZZER_DUMP_SEQ_PATH"] = str(seq_out)
    try:
        result = run_limited([str(dumper), str(crash.resolve())], timeout, env=env,
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
    Path(f"{crash}.calldata").write_text(calldata_of(crash) + "\n")
    return err


def replay(crash: Path, sel: str, timeout: int, work_root: Path) -> int | None:
    """Re-run the dumped Yul through yul_debug_runner; return its exit code."""
    yul_out = Path(f"{crash}.yul")
    seq_out = Path(f"{crash}.seq")
    if not yul_out.is_file():
        return None
    if sel in VALID_PASSES:
        seq_args = ["--optimizer-sequence", sel, "--optimizer-cleanup-sequence", ""]
    elif seq_out.is_file():
        seq, cleanup = parse_seq(seq_out)
        seq_args = ["--optimizer-sequence", seq, "--optimizer-cleanup-sequence", cleanup]
    else:
        seq_args = []
    calldata = calldata_of(crash)
    cd_args = ["--calldata", calldata] if calldata else []
    cmd = [str(RUNNER), "--verbose", *seq_args, *cd_args, str(yul_out.resolve())]
    # Per-task cwd: parallel runners would otherwise collide on yul_debug_output-N.
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
        msg = whats[-1].strip()
        return re.sub(r"^Yul evmone fuzzer \([^)]*\):\s*", "", msg)
    m = TERMINATE_RE.search(err_text)
    if m:
        return f"uncaught {m.group(1)}"
    return "UNKNOWN (no diagnostic in stderr)"


def shape_hash(yul_text: str) -> str:
    """Hash the source with the parts a mutator freely varies normalized away."""
    t = re.sub(r"0x[0-9a-fA-F]+", "N", yul_text)
    t = re.sub(r"\b\d+\b", "N", t)
    t = re.sub(r"\b[A-Za-z_]\w*_\d+\b", "V", t)
    t = re.sub(r"\s+", " ", t).strip()
    return hashlib.sha1(t.encode()).hexdigest()[:8]


def features_of(yul_text: str) -> str:
    found = [f for f in FEATURES if re.search(rf"\b{f}\b", yul_text)]
    return ", ".join(found) if found else "(none)"


def signature(crash: Path) -> tuple[str, str]:
    """Return (signature, feature label) for one already-dumped crash."""
    err_path, yul_path = Path(f"{crash}.err"), Path(f"{crash}.yul")
    msg = message_of(err_path.read_text(errors="replace")) if err_path.is_file() else "NO-ARTIFACT"
    if not yul_path.is_file() or yul_path.stat().st_size == 0:
        return f"{msg}  [no .yul dumped]", "(none)"
    yul = yul_path.read_text(errors="replace")
    return f"{msg}  [shape {shape_hash(yul)}]", features_of(yul)


def summarize(crashes: list[Path], replay_rc: dict[Path, int | None], out_file: Path) -> int:
    buckets: dict[str, list[Path]] = defaultdict(list)
    labels: dict[str, str] = {}
    for c in crashes:
        sig, feats = signature(c)
        buckets[sig].append(c)
        labels.setdefault(sig, feats)

    lines = [f"=== Unique yul crash signatures: {len(buckets)} (from {len(crashes)} inputs) ==="]
    for sig, members in sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        lines += ["", f"[{len(members)}] {sig}", f"    features: {labels[sig]}"]
        if replay_rc:
            rcs = sorted({str(replay_rc.get(m)) for m in members})
            lines.append(f"    yul_debug_runner rc: {', '.join(rcs)}")
        lines.append(f"    representative: {members[0]}")
        others = members[1:MAX_EXAMPLES]
        if others:
            hidden = len(members) - 1 - len(others)
            lines.append("    others: " + ", ".join(str(o) for o in others)
                         + (f" (+{hidden} more)" if hidden else ""))

    text = "\n".join(lines) + "\n"
    print(text)
    out_file.write_text(text)
    print(f"Wrote summary to {out_file}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("crashes", nargs="+", help="crash files and/or directories of them")
    parser.add_argument("-m", "--mode", default="ssacfg", choices=VALID_SELECTORS, metavar="SELECTOR",
                        help="fuzzer that produced these crashes: differential mode (%s) or "
                             "single-pass abbreviation (%s) (default: ssacfg)"
                             % (",".join(VALID_MODES), ",".join(VALID_PASSES)))
    parser.add_argument("--dumper", default=None, help="override the fuzzer binary path")
    parser.add_argument("--timeout", type=int, default=120, help="per-file timeout in seconds (default: 120)")
    parser.add_argument("-j", "--jobs", type=int, default=DEFAULT_JOBS,
                        help=f"files to process concurrently (default: {DEFAULT_JOBS})")
    parser.add_argument("--replay", action="store_true",
                        help="also run yul_debug_runner on each dump and report its exit code "
                             "(rc=1 means the mismatch reproduces standalone)")
    parser.add_argument("--summary-only", action="store_true",
                        help="skip the dumping step; bucket the existing .yul/.err artifacts")
    parser.add_argument("-o", "--output", default="unique_yul_crashes.txt", help="summary file (default: %(default)s)")
    args = parser.parse_args()

    crashes = collect_inputs([Path(c) for c in args.crashes])
    if not crashes:
        print("ERROR: no crash inputs found", file=sys.stderr)
        return 2

    if args.summary_only:
        return summarize(crashes, {}, Path(args.output))

    dumper = Path(args.dumper) if args.dumper else FUZZER_DIR / dumper_name(args.mode)
    needed = [dumper] + ([RUNNER] if args.replay else [])
    for p in needed:
        if not (p.is_file() and os.access(p, os.X_OK)):
            print(f"ERROR: missing or not executable: {p}", file=sys.stderr)
            return 2

    replay_rc: dict[Path, int | None] = {}
    total = len(crashes)
    print(f"mode={args.mode} inputs={total} jobs={args.jobs} dumper={dumper.name}")

    with tempfile.TemporaryDirectory() as work_root:
        def process(crash: Path):
            err = dump(crash, dumper, args.mode, args.timeout)
            rc = replay(crash, args.mode, args.timeout, Path(work_root)) if args.replay else None
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
