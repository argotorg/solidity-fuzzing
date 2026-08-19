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
  3. Label each bucket with the known-noise class that explains it (see
     NOISE_CLASSES) and report the unclassified ones first -- those are the
     only candidate bugs.  Written to unique_sol_crashes.txt.

Inputs may be crash files or directories; directories are walked recursively,
so a whole AFL findings tree can be passed in one go.  The fuzzer binary is
taken from --fuzzer, else inferred from an "NNN-<binary>" component of the
crash path, else sol_proto_ossfuzz_evmone.

Usage:
    ./sol_crash_categorizer.py ./results/637-sol_proto_ossfuzz_evmone_viair/findings/*/crashes/
    ./sol_crash_categorizer.py --fuzzer sol_ice_ossfuzz -j16 ice_crashes
    ./sol_crash_categorizer.py --replay results/637-*/findings
    ./sol_crash_categorizer.py --summary-only results/637-*/findings
    ./sol_crash_categorizer.py --all results/637-*/findings   # detail for noise too
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


# The (?![=>]) also keeps mapping(K => V) out of the side-effect scan.
ASSIGN_OP_RE = re.compile(r"<<=|>>=|[+\-*/%&|^]=|(?<![=!<>+\-*/%&|^])=(?![=>])")
INCDEC_RE = re.compile(r"\+\+|--")
SOLO_INCDEC_RE = re.compile(r"^(?:[\w.\[\]]+(?:\+\+|--)|(?:\+\+|--)[\w.\[\]]+)$")
MEM_DECL_RE = re.compile(r"^\s*\w[\w.\[\]]*\s+memory\s+(\w+)\s*[;=]", re.M)
TUPLE_LHS_RE = re.compile(r"^\(([^()]*)\)\s*=\s*\(")
STUB_PRECOMPILE_RE = re.compile(r"\bripemd160\b")


def strip_outer_parens(expr: str) -> str:
    while expr.startswith("(") and expr.endswith(")"):
        depth = 0
        for i, c in enumerate(expr):
            depth += (c == "(") - (c == ")")
            if depth == 0 and i < len(expr) - 1:
                return expr
        expr = expr[1:-1].strip()
    return expr


def nested_side_effect(stmt: str) -> bool:
    """True if an assignment or ++/-- sits inside a subexpression rather than
    being the whole statement -- legacy and IR order siblings differently."""
    expr = strip_outer_parens(stmt.strip().rstrip(";").strip())
    if SOLO_INCDEC_RE.match(expr):
        return False
    depth, i = 0, 0
    while i < len(expr):
        c = expr[i]
        if c in "()":
            depth += 1 if c == "(" else -1
            i += 1
            continue
        mo = ASSIGN_OP_RE.match(expr, i) or INCDEC_RE.match(expr, i)
        if mo:
            # A ++/-- is a side effect wherever it appears next to other operands;
            # a bare assignment is fine as long as it is the statement itself.
            if depth > 0 or INCDEC_RE.match(expr, i):
                return True
            i = mo.end()
            continue
        i += 1
    return False


def has_eval_order_noise(sol: str) -> bool:
    for raw in sol.splitlines():
        line = raw.split("//")[0].strip()
        if line.startswith("for ("):
            clauses = line[line.find("(") + 1:line.rfind(")")].split(";")
            line = ";".join(clauses[:2]) if len(clauses) >= 3 else line
        if nested_side_effect(line):
            return True
    return False


def has_tuple_alias(sol: str) -> bool:
    """Destructuring assignment whose LHS holds a memory local -- the storage
    -> memory copy then races the other components' stores."""
    memory_locals = set(MEM_DECL_RE.findall(sol))
    if not memory_locals:
        return False
    for raw in sol.splitlines():
        mo = TUPLE_LHS_RE.match(raw.strip())
        if mo and any(v.strip() in memory_locals for v in mo.group(1).split(",")):
            return True
    return False


# Ordered: the first match explains the crash. Everything unmatched is a candidate.
NOISE_CLASSES = [
    ("eval-order", has_eval_order_noise,
     "side effect in a subexpression - legacy/IR evaluate siblings in a "
     "different order (solidity docs/ir-breaking-changes.rst)"),
    ("precompile-stub", lambda sol: bool(STUB_PRECOMPILE_RE.search(sol)),
     "ripemd160 - EVMHost only stubs precompile 0x03, the call fails and solc "
     "turns that into a bare revert"),
    ("tuple-alias", has_tuple_alias,
     "tuple assignment with a memory LHS aliasing an overwritten storage var - "
     "known legacy/IR difference, under investigation"),
]
NO_REPRO = ("no-repro", "the input no longer crashes this fuzzer build - stale corpus entry")
CANDIDATE = "candidate"


def noise_class(msg: str, sol: str) -> str:
    if msg.startswith("NO-CRASH") or msg.startswith("TIMEOUT"):
        return NO_REPRO[0]
    for name, matches, _ in NOISE_CLASSES:
        if matches(sol):
            return name
    return CANDIDATE


CLASS_ORDER = [(CANDIDATE, "not explained by any known class -- triage these")] + \
              [(name, why) for name, _, why in NOISE_CLASSES] + [NO_REPRO]


def signature(crash: Path) -> tuple[str, str, str]:
    """Return (signature, feature label, class) for one already-dumped crash."""
    err_path, sol_path = Path(f"{crash}.err"), Path(f"{crash}.sol")
    msg = message_of(err_path.read_text(errors="replace")) if err_path.is_file() else "NO-ARTIFACT"
    if not sol_path.is_file() or sol_path.stat().st_size == 0:
        return f"{msg}  [no .sol dumped]", "(none)", CANDIDATE
    sol = sol_path.read_text(errors="replace")
    return f"{msg}  [shape {shape_hash(sol)}]", features_of(sol), noise_class(msg, sol)


def summarize(crashes: list[Path], replay_rc: dict[Path, int | None], out_file: Path,
              show_all: bool) -> int:
    buckets: dict[str, list[Path]] = defaultdict(list)
    labels: dict[str, str] = {}
    classes: dict[str, str] = {}
    for c in crashes:
        sig, feats, cls = signature(c)
        buckets[sig].append(c)
        labels.setdefault(sig, feats)
        classes.setdefault(sig, cls)

    def detail(sig: str) -> list[str]:
        members = buckets[sig]
        out = [f"[{len(members)}] {sig}", f"    features: {labels[sig]}"]
        if replay_rc:
            rcs = sorted({str(replay_rc.get(m)) for m in members})
            out.append(f"    sol_debug_runner rc: {', '.join(rcs)}")
        out.append(f"    representative: {members[0]}")
        others = members[1:MAX_EXAMPLES]
        if others:
            hidden = len(members) - 1 - len(others)
            out.append("    others: " + ", ".join(str(o) for o in others)
                       + (f" (+{hidden} more)" if hidden else ""))
        return out

    order = sorted(buckets, key=lambda sig: (-len(buckets[sig]), sig))
    lines = [f"=== Unique sol crash signatures: {len(buckets)} (from {len(crashes)} inputs) ===", ""]
    for name, why in CLASS_ORDER:
        sigs = [s for s in order if classes[s] == name]
        n_inputs = sum(len(buckets[s]) for s in sigs)
        lines.append(f"  {n_inputs:5d} inputs / {len(sigs):4d} shapes  {name:16s} {why}")

    for name, _ in CLASS_ORDER:
        sigs = [s for s in order if classes[s] == name]
        if not sigs:
            continue
        collapsed = name != CANDIDATE and not show_all
        header = f"=== {name}: {sum(len(buckets[s]) for s in sigs)} inputs / {len(sigs)} shapes"
        lines += ["", header + (" (largest 3; --all for the rest) ===" if collapsed else " ===")]
        for sig in (sigs[:3] if collapsed else sigs):
            lines += [""] + detail(sig)

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
    parser.add_argument("--all", action="store_true",
                        help="print every bucket, including the known-noise classes")
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
        return summarize(crashes, {}, Path(args.output), args.all)

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
    return summarize(crashes, replay_rc if args.replay else {}, Path(args.output), args.all)


if __name__ == "__main__":
    sys.exit(main())
