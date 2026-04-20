#!/usr/bin/env python3
"""
Convert fuzzer crash-* corpus entries into .sol files and collect gdb
backtraces from solc.

For each crash-* input file given on the command line:
  1. Run sol_ice_ossfuzz with PROTO_FUZZER_DUMP_PATH=<crash>.sol so the
     protobuf input is serialized into a Solidity source file.
  2. Run ./build/solidity/solc/solc under gdb (batch mode) on that .sol
     file, capturing the crash backtrace into <crash>.backtrace.

Usage:
    ./tools/runners/sol_crash_backtrace.py crash-<hash> [crash-<hash> ...]
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DUMPER = REPO_ROOT / "build_ossfuzz" / "tools" / "ossfuzz" / "sol_ice_ossfuzz"
DEFAULT_SOLC = REPO_ROOT / "build" / "solidity" / "solc" / "solc"


def dump_sol(dumper: Path, crash: Path, sol_out: Path) -> None:
    env = os.environ.copy()
    env["PROTO_FUZZER_DUMP_PATH"] = str(sol_out)
    # The fuzzer binary may itself exit non-zero / abort after dumping;
    # we only care that the .sol file got written.
    subprocess.run(
        [str(dumper), str(crash)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


ICE_MARKERS = (
    "Internal compiler error",
    "UnimplementedFeatureError",
    "Solidity assertion failed",
    "Assertion `",
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
)


def run_gdb(solc: Path, sol_in: Path, timeout: int):
    """Run solc under gdb; return (crashed: bool, report: str)."""
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
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        report = (
            f"TIMEOUT after {timeout}s\n\n"
            f"STDOUT:\n{exc.stdout or ''}\n\n"
            f"STDERR:\n{exc.stderr or ''}\n"
        )
        # Treat timeout as a crash (hang) — caller keeps the artifacts.
        return True, report

    report = (
        f"=== gdb exit code: {result.returncode} ===\n"
        f"=== STDOUT ===\n{result.stdout}\n"
        f"=== STDERR ===\n{result.stderr}\n"
    )
    got_signal = "received signal" in result.stdout
    got_ice = any(m in result.stderr for m in ICE_MARKERS)
    return (got_signal or got_ice), report


def process(crash: Path, dumper: Path, solc: Path, timeout: int) -> bool:
    if not crash.is_file():
        print(f"SKIP: {crash} is not a regular file", file=sys.stderr)
        return False

    sol_out = Path(str(crash) + ".sol")
    backtrace_out = Path(str(crash) + ".backtrace")

    print(f"[{crash.name}] dumping -> {sol_out.name}")
    dump_sol(dumper, crash, sol_out)
    if not sol_out.is_file() or sol_out.stat().st_size == 0:
        print(f"  ERROR: failed to produce {sol_out.name}", file=sys.stderr)
        if sol_out.exists():
            sol_out.unlink()
        return False

    print(f"[{crash.name}] running solc under gdb")
    crashed, report = run_gdb(solc, sol_out, timeout)
    if not crashed:
        print(f"  ERROR: {crash.name} did NOT crash solc — discarding .sol", file=sys.stderr)
        sol_out.unlink(missing_ok=True)
        backtrace_out.unlink(missing_ok=True)
        return False

    backtrace_out.write_text(report)
    print(f"[{crash.name}] crash captured -> {backtrace_out.name}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("crashes", nargs="+", help="crash-* input files")
    parser.add_argument("--dumper", default=str(DEFAULT_DUMPER),
                        help=f"Path to sol_ice_ossfuzz (default: {DEFAULT_DUMPER})")
    parser.add_argument("--solc", default=str(DEFAULT_SOLC),
                        help=f"Path to solc (default: {DEFAULT_SOLC})")
    parser.add_argument("--timeout", type=int, default=120,
                        help="Per-file gdb timeout in seconds (default: 120)")
    args = parser.parse_args()

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
    for c in args.crashes:
        if process(Path(c), dumper, solc, args.timeout):
            ok += 1
    print(f"Processed {ok}/{len(args.crashes)} crash files")
    return 0 if ok == len(args.crashes) else 1


if __name__ == "__main__":
    sys.exit(main())
