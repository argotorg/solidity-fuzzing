#!/usr/bin/env python3
"""Replay ice_crash/ corpus through solc.

For each crash-<hash> file in the crash dir:
  1. Dump the protobuf to <crash-dir>/crash-<hash>.sol via sol_ice_ossfuzz.
  2. Compile with solc and save its full output (stdout+stderr) to
     <crash-dir>/crash-<hash>.out.
"""
import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

DUMPER = Path("./build_ossfuzz/tools/ossfuzz/sol_ice_ossfuzz").resolve()
SOLC = Path("./build/solidity/solc/solc").resolve()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--crash-dir", default="ice_crash",
                        help="crash directory (default: ice_crash)")
    parser.add_argument("--solc-args", default="--via-ir --optimize",
                        help="extra args passed to solc (default: %(default)r)")
    args = parser.parse_args()

    crash_dir = Path(args.crash_dir)
    extra_args = args.solc_args.split()

    for p in (DUMPER, SOLC):
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

    print(f"crash_dir={crash_dir} total={total} solc_args={extra_args}")

    with tempfile.TemporaryDirectory() as work:
        for i, crash in enumerate(crashes, 1):
            sol_out = (crash_dir / f"{crash.name}.sol").resolve()
            run_out = (crash_dir / f"{crash.name}.out").resolve()

            print(f"[{i}/{total}] {crash.name} ... ", end="", flush=True)

            # 1. Dump. Harness writes the .sol then attempts the compile,
            # which may crash; either way the .sol should be on disk.
            env = {**os.environ, "PROTO_FUZZER_DUMP_PATH": str(sol_out)}
            subprocess.run([str(DUMPER), str(crash)],
                           env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=False)

            if not sol_out.is_file() or sol_out.stat().st_size == 0:
                print("dump-failed")
                continue

            # 2. Re-run solc on the dumped source.
            with run_out.open("wb") as out:
                rc = subprocess.run(
                    [str(SOLC), *extra_args, str(sol_out)],
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
