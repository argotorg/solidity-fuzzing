#!/usr/bin/env python3
"""Replay <pass>_crash/ corpus through yul_debug_runner.

For each crash-<hash> file in the crash dir:
  1. Dump the protobuf to <crash-dir>/crash-<hash>.yul via
     yul_proto_ossfuzz_evmone_single_pass_<pass>.
  2. Replay with yul_debug_runner --verbose --optimizer-sequence <pass>
     --optimizer-cleanup-sequence "" and save its full output to
     <crash-dir>/crash-<hash>.out.
"""
import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

VALID_PASSES = list("cSLMsrD")  # see CLAUDE.md: yul single_pass binaries

RUNNER = Path("./build/tools/runners/yul_debug_runner").resolve()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-p", "--pass", dest="opt_pass", required=True,
                        choices=VALID_PASSES,
                        help="optimizer pass abbreviation (one of: %(choices)s)")
    parser.add_argument("--crash-dir", default=None,
                        help="crash directory (default: <pass>_crash)")
    args = parser.parse_args()

    opt = args.opt_pass
    crash_dir = Path(args.crash_dir) if args.crash_dir else Path(f"{opt}_crash")
    dumper = Path(f"./build_ossfuzz/tools/ossfuzz/yul_proto_ossfuzz_evmone_single_pass_{opt}").resolve()

    for p in (dumper, RUNNER):
        if not (p.is_file() and os.access(p, os.X_OK)):
            print(f"missing or not executable: {p}", file=sys.stderr)
            return 1
    if not crash_dir.is_dir():
        print(f"missing dir: {crash_dir}", file=sys.stderr)
        return 1

    crashes = sorted(f for f in crash_dir.iterdir()
                     if f.is_file() and f.name.startswith("crash-") and "." not in f.name)
    total = len(crashes)
    done = 0

    print(f"pass='{opt}' crash_dir={crash_dir} total={total}")

    # Throwaway cwd so the runner's yul_debug_output-N artifacts are discarded.
    with tempfile.TemporaryDirectory() as work:
        for i, crash in enumerate(crashes, 1):
            yul_out = (crash_dir / f"{crash.name}.yul").resolve()
            run_out = (crash_dir / f"{crash.name}.out").resolve()

            print(f"[{i}/{total}] {crash.name} ... ", end="", flush=True)

            # 1. Dump. Harness deliberately crashes after writing the .yul,
            # so a non-zero exit is expected.
            env = {**os.environ, "PROTO_FUZZER_DUMP_PATH": str(yul_out)}
            subprocess.run([str(dumper), str(crash)],
                           env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=False)

            if not yul_out.is_file() or yul_out.stat().st_size == 0:
                print("dump-failed")
                continue

            # 2. Replay through yul_debug_runner.
            with run_out.open("wb") as out:
                rc = subprocess.run(
                    [str(RUNNER), "--verbose",
                     "--optimizer-sequence", opt,
                     "--optimizer-cleanup-sequence", "",
                     str(yul_out)],
                    cwd=work, stdout=out, stderr=subprocess.STDOUT,
                    check=False,
                ).returncode

            done += 1
            print(f"rc={rc}")

    print()
    print(f"done: {done} / {total} processed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
