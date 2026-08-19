#!/usr/bin/env python3
"""
Convert fuzzer crash-* corpus entries into .sol files and collect gdb
backtraces from solc, then group them by crash signature.

For each crash-* input file given on the command line:
  1. Run sol_ice_ossfuzz with PROTO_FUZZER_DUMP_PATH=<crash>.sol so the
     protobuf input is serialized into a Solidity source file.
  2. Run ./build/solidity/solc/solc under gdb (batch mode) on that .sol
     file, capturing the full gdb report into <crash>.backtrace and solc's
     own stderr into <crash>.output.
  3. After all inputs are processed (or with --summary-only), scan every
     *.backtrace next to the inputs, compute a signature for each, and print
     the unique buckets.

Usage:
    ./tools/runners/sol_ice_crash_backtrace_categorizer.py <crash> [<crash> ...]
    ./tools/runners/sol_ice_crash_backtrace_categorizer.py --summary-only [dir ...]
"""

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DUMPER = REPO_ROOT / "build_afl" / "tools" / "ossfuzz" / "sol_ice_ossfuzz"
DEFAULT_SOLC = REPO_ROOT / "build" / "solidity" / "solc" / "solc"

ICE_MARKERS = (
    "Internal compiler error",
    "UnimplementedFeatureError",
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
    return not p.name.endswith((".sol", ".backtrace", ".output")) and p.name != "README.txt"


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
            [str(dumper), str(crash)],
            timeout,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        pass


def run_gdb(solc: Path, sol_in: Path, timeout: int):
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
        "--optimize",
        "--via-ir",
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


def process(crash: Path, dumper: Path, solc: Path, timeout: int) -> bool:
    if not crash.is_file():
        print(f"SKIP: {crash} is not a regular file", file=sys.stderr)
        return False

    sol_out = Path(str(crash) + ".sol")
    backtrace_out = Path(str(crash) + ".backtrace")
    output_out = Path(str(crash) + ".output")

    print(f"[{crash.name}] dumping -> {sol_out.name}")
    dump_sol(dumper, crash, sol_out, timeout)
    if not sol_out.is_file() or sol_out.stat().st_size == 0:
        print(f"  ERROR: failed to produce {sol_out.name}", file=sys.stderr)
        if sol_out.exists():
            sol_out.unlink()
        return False

    print(f"[{crash.name}] running solc under gdb")
    crashed, report, solc_stderr = run_gdb(solc, sol_out, timeout)
    if not crashed:
        print(f"  ERROR: {crash.name} did NOT crash solc — discarding artifacts", file=sys.stderr)
        sol_out.unlink(missing_ok=True)
        backtrace_out.unlink(missing_ok=True)
        output_out.unlink(missing_ok=True)
        return False

    backtrace_out.write_text(report)
    output_out.write_text(solc_stderr)
    print(f"[{crash.name}] crash captured -> {backtrace_out.name}, {output_out.name}")
    return True


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
    if not backtraces:
        print(f"No *.backtrace files found in: {', '.join(str(d) for d in dirs)}", file=sys.stderr)
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
        stem = bt.name.removesuffix(".backtrace")
        buckets[sig].append(stem)

    lines = []
    lines.append(f"=== Unique crash signatures: {len(buckets)} (from {len(backtraces)} backtraces) ===")
    ordered = sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    for sig, members in ordered:
        lines.append("")
        lines.append(f"[{len(members)}] {sig}")
        lines.append(f"    representative: {members[0]}")
        if len(members) > 1:
            lines.append(f"    others ({len(members) - 1}): " + ", ".join(members[1:]))

    text = "\n".join(lines) + "\n"
    print(text)
    out = Path.cwd() / "unique_crashes.txt"
    out.write_text(text)
    print(f"Wrote summary to {out}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("crashes", nargs="*",
                        help="crash input files (or, with --summary-only, directories)")
    parser.add_argument("--dumper", default=str(DEFAULT_DUMPER),
                        help=f"Path to sol_ice_ossfuzz (default: {DEFAULT_DUMPER})")
    parser.add_argument("--solc", default=str(DEFAULT_SOLC),
                        help=f"Path to solc (default: {DEFAULT_SOLC})")
    parser.add_argument("--timeout", type=int, default=120,
                        help="Per-file gdb timeout in seconds (default: 120)")
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

    crashes = [Path(c) for c in args.crashes]
    ignored = [c for c in crashes if not is_crash_input(c)]
    crashes = [c for c in crashes if is_crash_input(c)]
    if ignored:
        print(f"Ignoring {len(ignored)} non-input file(s) (own output / README)")

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

    ok = 0
    for c in crashes:
        if process(c, dumper, solc, args.timeout):
            ok += 1
    print(f"Processed {ok}/{len(crashes)} crash files")

    if not args.no_summary:
        print()
        summarize(sorted({c.parent for c in crashes}))

    return 0 if ok == len(crashes) else 1


if __name__ == "__main__":
    sys.exit(main())
