#!/usr/bin/env python3
"""
Convert fuzzer crash-* corpus entries into .sol files and collect gdb
backtraces from solc, then group them by crash signature.

For each crash-* input file given on the command line:
  1. Run sol_ice_ossfuzz with PROTO_FUZZER_DUMP_PATH=<crash>.sol so the
     protobuf input is serialized into a Solidity source file.
  2. Compile that .sol with ./build/solidity/solc/solc using the input's own
     via_ir / optimize fields (as the harness does). An ICE is captured from
     solc's stderr; only a signal crash is re-run under gdb (batch mode) for a
     backtrace. The report goes to <crash>.backtrace, solc's stderr to
     <crash>.output. An input that is not an ICE -- by the same allowlist the
     harness applies -- keeps its .sol and gets <crash>.miss with the reason;
     the summary groups those and lists them in misses.txt.
  3. After all inputs are processed (or with --summary-only), scan every
     *.backtrace next to the inputs, compute a signature for each, and print
     the unique buckets.

Arguments may be individual crash files or whole crash directories; several
fuzzer instances can be categorized in one go. Files are processed
concurrently; see -j.

Usage:
    ./sol_ice_crash_backtrace_categorizer.py [-j N] <crash|dir> ...
    ./sol_ice_crash_backtrace_categorizer.py -j16 results/643-*/findings/*/crashes
    ./sol_ice_crash_backtrace_categorizer.py --summary-only [dir ...]
"""

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_DUMPER = REPO_ROOT / "build_afl" / "tools" / "ossfuzz" / "sol_ice_ossfuzz"
DEFAULT_SOLC = REPO_ROOT / "build" / "solidity" / "solc" / "solc"
DEFAULT_JOBS = min(8, os.cpu_count() or 1)
MAX_EXAMPLES = 3

ICE_MARKERS = (
    "Internal compiler error",
    "Solidity assertion failed",
    "Assertion `",
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
)

THROW_RE = re.compile(r"^(/\S+\.(?:cpp|h|hpp|cc)\(\d+\)):\s*Throw in function\s+(.*)$", re.MULTILINE)
SIGNAL_RE = re.compile(r"(Program received signal \w+|Thread \d+ \S+ received signal \w+)")
ASAN_RE = re.compile(r"(AddressSanitizer:\s*\S+|UndefinedBehaviorSanitizer:\s*\S+|runtime error:.*)")
FRAME_RE = re.compile(r"^#\d+\s+(?:0x[0-9a-f]+\s+in\s+)?(.+?)(?:\s+\(.*)?$", re.MULTILINE)
STDERR_SPLIT_RE = re.compile(r"^=== STDERR ===$", re.MULTILINE)


def is_crash_input(p: Path) -> bool:
    """Reject our own artifacts and AFL's README, so `crashes/*` stays usable."""
    return not p.name.endswith((".sol", ".backtrace", ".output", ".miss")) and p.name != "README.txt"


def collect_inputs(paths: list[Path]) -> tuple[list[Path], int]:
    """Expand any directory argument into the crash files it holds. Returns (inputs, ignored count)."""
    inputs: list[Path] = []
    ignored = 0
    for p in paths:
        for c in sorted(p.iterdir()) if p.is_dir() else [p]:
            if p.is_dir() and not c.is_file():
                continue
            if is_crash_input(c):
                inputs.append(c)
            else:
                ignored += 1
    return inputs, ignored


def run_limited(cmd, timeout: int, **kwargs) -> subprocess.CompletedProcess:
    """subprocess.run with a timeout that also reaps grandchildren.

    Plain subprocess.run only kills the direct child; gdb's inferior survives,
    keeps the stdout/stderr pipes open, and the post-kill communicate() then
    blocks forever. Running in a new session lets us kill the whole group.
    """
    with subprocess.Popen(cmd, start_new_session=True, **kwargs) as proc:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            out, err = proc.communicate()
            raise subprocess.TimeoutExpired(cmd, timeout, out, err)
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def dump_sol(dumper: Path, crash: Path, sol_out: Path, timeout: int) -> None:
    env = os.environ.copy()
    env["PROTO_FUZZER_DUMP_PATH"] = str(sol_out)
    try:
        run_limited(
            [str(dumper), str(crash.resolve())],
            timeout,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        pass


# Mirrors what sol_ice_ossfuzz.cpp swallows or skips, so a replay verdict matches the harness's.
KNOWN_NON_BUG_ICES = ("FixedPointType not implemented",)
HARNESS_MAX_SOURCE = 8000
ERROR_LINE_RE = re.compile(r"^(?:Error|\w+Error|TIMEOUT)\b.*$", re.MULTILINE)

TOP_FLAG_RE = re.compile(r"^(via_ir|optimize):\s*(true|false)\s*$", re.MULTILINE)


def solc_flags(crash: Path) -> list[str]:
    """The harness compiles with the proto's top-level via_ir / optimize fields."""
    try:
        text = crash.read_text(errors="replace")
    except OSError:
        text = ""
    fields = dict(TOP_FLAG_RE.findall(text))
    flags = ["--bin", "--no-cbor-metadata"]
    if fields.get("optimize", "true") == "true":
        flags.append("--optimize")
    if fields.get("via_ir", "true") == "true":
        flags.append("--via-ir")
    return flags


def run_solc(solc: Path, sol_in: Path, flags: list[str], timeout: int):
    """Return (crashed, report, solc_stderr). gdb only for signal crashes."""
    cmd = [str(solc), *flags, str(sol_in)]
    try:
        result = run_limited(cmd, timeout, stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE, text=True)
    except subprocess.TimeoutExpired as exc:
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return False, f"TIMEOUT after {timeout}s\n", stderr
    got_ice = any(m in result.stderr for m in ICE_MARKERS) and \
        not any(m in result.stderr for m in KNOWN_NON_BUG_ICES)
    if result.returncode >= 0:
        report = (f"=== solc {' '.join(flags)} exit code: {result.returncode} ===\n"
                  f"=== STDOUT ===\n\n=== STDERR ===\n{result.stderr}\n")
        return got_ice, report, result.stderr
    return run_gdb(solc, sol_in, flags, timeout)


def run_gdb(solc: Path, sol_in: Path, flags: list[str], timeout: int):
    """Return (crashed, report, solc_stderr)."""
    cmd = [
        "gdb",
        "--batch",
        "--nx",
        "-ex", "set pagination off",
        "-ex", "set confirm off",
        "-ex", "set print pretty on",
        "-ex", "run",
        "-ex", "thread apply all bt full",
        "-ex", "quit",
        "--args",
        str(solc),
        *flags,
        str(sol_in),
    ]
    try:
        result = run_limited(
            cmd,
            timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        report = (
            f"TIMEOUT after {timeout}s\n\n"
            f"STDOUT:\n{stdout}\n\n"
            f"STDERR:\n{stderr}\n"
        )
        return True, report, stderr

    report = (
        f"=== gdb exit code: {result.returncode} ===\n"
        f"=== STDOUT ===\n{result.stdout}\n"
        f"=== STDERR ===\n{result.stderr}\n"
    )
    got_signal = "received signal" in result.stdout
    got_ice = any(m in result.stderr for m in ICE_MARKERS)
    return (got_signal or got_ice), report, result.stderr


def process(crash: Path, dumper: Path, solc: Path, timeout: int) -> tuple[bool, str]:
    """Returns (captured, one-line status). Caller does the printing — this runs on a worker thread."""
    if not crash.is_file():
        return False, f"SKIP {crash.name}: not a regular file"

    sol_out = Path(str(crash) + ".sol")
    backtrace_out = Path(str(crash) + ".backtrace")
    output_out = Path(str(crash) + ".output")

    dump_sol(dumper, crash, sol_out, timeout)
    if not sol_out.is_file() or sol_out.stat().st_size == 0:
        sol_out.unlink(missing_ok=True)
        return False, f"FAIL {crash.name}: could not dump .sol"

    miss_out = Path(str(crash) + ".miss")
    if sol_out.stat().st_size > HARNESS_MAX_SOURCE:
        crashed, reason = False, f"harness skips sources > {HARNESS_MAX_SOURCE} bytes"
    else:
        crashed, report, solc_stderr = run_solc(solc, sol_out, solc_flags(crash), timeout)
        m = ERROR_LINE_RE.search(solc_stderr) or ERROR_LINE_RE.search(report)
        reason = m.group(0).strip() if m else "solc reported no error"
    if not crashed:
        backtrace_out.unlink(missing_ok=True)
        output_out.unlink(missing_ok=True)
        miss_out.write_text(reason + "\n")
        return False, f"MISS {crash}: {reason[:120]}"

    miss_out.unlink(missing_ok=True)
    backtrace_out.write_text(report)
    output_out.write_text(solc_stderr)
    return True, f"OK   {crash.name}"


def extract_solc_stderr(backtrace_text: str) -> str:
    """Pull the solc stderr section out of a stored .backtrace file."""
    m = STDERR_SPLIT_RE.search(backtrace_text)
    if not m:
        return ""
    return backtrace_text[m.end():].lstrip("\n")


def normalize_frame(sym: str) -> str:
    """Strip addresses, argument lists, and template noise from a gdb frame symbol."""
    s = sym.strip()
    # Drop trailing " at /path/file:NN" location info.
    s = re.sub(r"\s+at\s+\S+:\d+.*$", "", s)
    # Drop the argument list "( ... )" at the end.
    s = re.sub(r"\s*\(.*\)\s*(const)?\s*$", "", s)
    # Collapse whitespace.
    s = re.sub(r"\s+", " ", s)
    return s


def compute_signature(backtrace_text: str) -> str:
    """Pick the most specific stable identifier for this crash."""
    # 1. ICE: file:line + throwing function is by far the most stable.
    m = THROW_RE.search(backtrace_text)
    if m:
        loc, func = m.group(1), m.group(2).strip()
        return f"ICE {loc} :: {normalize_frame(func)}"

    # 2. Sanitizer report line.
    m = ASAN_RE.search(backtrace_text)
    if m:
        return f"SAN {m.group(1).strip()}"

    # 3. Real signal: top ~5 frames of the crashing thread, normalized.
    m = SIGNAL_RE.search(backtrace_text)
    sig_name = m.group(0).split()[-1] if m else "UNKNOWN"
    frames = []
    for fm in FRAME_RE.finditer(backtrace_text):
        sym = normalize_frame(fm.group(1))
        # Skip libc/gdb noise and raw addresses.
        if not sym or sym.startswith("0x") or sym in ("??",):
            continue
        if sym in frames:
            continue
        frames.append(sym)
        if len(frames) >= 5:
            break
    if frames:
        return f"SIG {sig_name} :: " + " <- ".join(frames)
    return f"SIG {sig_name} :: (no frames)"


def backfill_output(backtrace_path: Path) -> None:
    """Create the .output sibling from an existing .backtrace if missing."""
    output_path = Path(str(backtrace_path).removesuffix(".backtrace") + ".output")
    if output_path.exists():
        return
    try:
        text = backtrace_path.read_text(errors="replace")
    except OSError as e:
        print(f"  WARN: cannot read {backtrace_path.name}: {e}", file=sys.stderr)
        return
    output_path.write_text(extract_solc_stderr(text))


def summarize(dirs: list[Path]) -> int:
    """Group every *.backtrace under `dirs` by signature; print + write a summary."""
    backtraces = sorted({bt for d in dirs for bt in d.glob("*.backtrace")})
    if not backtraces and not any(d.glob("*.miss") for d in dirs):
        print(f"No *.backtrace / *.miss files found in: {', '.join(str(d) for d in dirs)}", file=sys.stderr)
        return 1

    buckets: dict[str, list[str]] = defaultdict(list)
    for bt in backtraces:
        backfill_output(bt)
        try:
            text = bt.read_text(errors="replace")
        except OSError as e:
            print(f"  WARN: cannot read {bt.name}: {e}", file=sys.stderr)
            continue
        sig = compute_signature(text)
        # Crash names repeat across fuzzer instances, so keep the path when several dirs are in play.
        name = bt.name if len(dirs) == 1 else str(bt)
        stem = name.removesuffix(".backtrace")
        buckets[sig].append(stem)

    lines = []
    lines.append(f"=== Unique crash signatures: {len(buckets)} (from {len(backtraces)} backtraces) ===")
    ordered = sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    for sig, members in ordered:
        lines.append("")
        lines.append(f"[{len(members)}] {sig}")
        lines.append(f"    representative: {members[0]}")
        others = members[1:MAX_EXAMPLES]
        if others:
            hidden = len(members) - 1 - len(others)
            suffix = f" (+{hidden} more)" if hidden else ""
            lines.append("    others: " + ", ".join(others) + suffix)

    misses = sorted({m for d in dirs for m in d.glob("*.miss")})
    if misses:
        by_reason: dict[str, list[Path]] = defaultdict(list)
        for m in misses:
            reason = m.read_text(errors="replace").strip()
            by_reason[re.sub(r"\d+", "N", re.sub(r"\b(?:Variable|Slot)\s+\S+|\[.*", "X", reason))[:100]].append(m)
        lines += ["", f"=== Not an ICE on this solc: {len(misses)} inputs (paths in misses.txt) ==="]
        for reason, ms in sorted(by_reason.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"[{len(ms)}] {reason}")
        (Path.cwd() / "misses.txt").write_text(
            "".join(f"{str(m).removesuffix('.miss')}\t{m.read_text(errors='replace').strip()}\n" for m in misses))

    text = "\n".join(lines) + "\n"
    print(text)
    out = Path.cwd() / "unique_crashes.txt"
    out.write_text(text)
    print(f"Wrote summary to {out}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("crashes", nargs="*",
                        help="crash input files and/or directories of them")
    parser.add_argument("--dumper", default=str(DEFAULT_DUMPER),
                        help=f"Path to sol_ice_ossfuzz (default: {DEFAULT_DUMPER})")
    parser.add_argument("--solc", default=str(DEFAULT_SOLC),
                        help=f"Path to solc (default: {DEFAULT_SOLC})")
    parser.add_argument("--timeout", type=int, default=120,
                        help="Per-file solc/gdb timeout in seconds (default: 120)")
    parser.add_argument("-j", "--jobs", type=int, default=DEFAULT_JOBS,
                        help=f"Crash files to process concurrently (default: {DEFAULT_JOBS})")
    parser.add_argument("--summary-only", action="store_true",
                        help="Skip processing; just summarize existing *.backtrace files in the given dirs (default: cwd)")
    parser.add_argument("--no-summary", action="store_true",
                        help="Skip the unique-crash summary step after processing")
    args = parser.parse_args()

    if args.summary_only:
        dirs = [Path(d) for d in args.crashes] or [Path.cwd()]
        for d in dirs:
            if not d.is_dir():
                print(f"ERROR: --summary-only takes directories, not {d}", file=sys.stderr)
                return 2
        return summarize(dirs)

    crashes, ignored = collect_inputs([Path(c) for c in args.crashes])
    if ignored:
        print(f"Ignoring {ignored} non-input file(s) (own output / README)")

    if not crashes:
        print("ERROR: no crash files given (use --summary-only to skip processing)", file=sys.stderr)
        return 2

    dumper = Path(args.dumper)
    solc = Path(args.solc)

    if not dumper.is_file() or not os.access(dumper, os.X_OK):
        print(f"ERROR: dumper not found / not executable: {dumper}", file=sys.stderr)
        return 2
    if not solc.is_file() or not os.access(solc, os.X_OK):
        print(f"ERROR: solc not found / not executable: {solc}", file=sys.stderr)
        return 2
    if shutil.which("gdb") is None:
        print("ERROR: gdb not found on PATH", file=sys.stderr)
        return 2
    if args.jobs < 1:
        print("ERROR: --jobs must be >= 1", file=sys.stderr)
        return 2

    ok = 0
    total = len(crashes)
    print(f"Processing {total} crash files with {args.jobs} thread(s)")
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(process, c, dumper, solc, args.timeout): c for c in crashes}
        for n, fut in enumerate(as_completed(futures), 1):
            try:
                captured, status = fut.result()
            except Exception as e:
                captured, status = False, f"FAIL {futures[fut].name}: {e!r}"
            ok += captured
            print(f"[{n}/{total}] {status}", flush=True)
    print(f"Processed {ok}/{total} crash files")

    if not args.no_summary:
        print()
        summarize(sorted({c.parent for c in crashes}))

    return 0 if ok == len(crashes) else 1


if __name__ == "__main__":
    sys.exit(main())
