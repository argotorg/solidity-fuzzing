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
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DUMPER = Path("./build_ossfuzz/tools/ossfuzz/sol_ice_ossfuzz").resolve()
SOLC = Path("./build/solidity/solc/solc").resolve()


def process_one(crash: Path, crash_dir: Path, extra_args: list, work_root: Path):
    sol_out = (crash_dir / f"{crash.name}.sol").resolve()
    run_out = (crash_dir / f"{crash.name}.out").resolve()

    # 1. Dump. Harness writes the .sol then attempts the compile,
    # which may crash; either way the .sol should be on disk.
    env = {**os.environ, "PROTO_FUZZER_DUMP_PATH": str(sol_out)}
    subprocess.run([str(DUMPER), str(crash)],
                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=False)

    if not sol_out.is_file() or sol_out.stat().st_size == 0:
        return crash.name, None, "dump-failed"

    # Per-task cwd to keep any solc-side artifacts isolated between threads.
    with tempfile.TemporaryDirectory(dir=str(work_root)) as work:
        with run_out.open("wb") as out:
            rc = subprocess.run(
                [str(SOLC), *extra_args, str(sol_out)],
                cwd=work, stdout=out, stderr=subprocess.STDOUT,
                check=False,
            ).returncode
    return crash.name, rc, None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--crash-dir", default="ice_crash",
                        help="crash directory (default: ice_crash)")
    parser.add_argument("--solc-args", default="--via-ir --optimize",
                        help="extra args passed to solc (default: %(default)r)")
    parser.add_argument("--threads", "-j", type=int, default=os.cpu_count() or 1,
                        help="number of parallel workers (default: %(default)d)")
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
    threads = max(1, args.threads)

    print(f"crash_dir={crash_dir} total={total} solc_args={extra_args} threads={threads}")

    print_lock = threading.Lock()
    completed = 0

    with tempfile.TemporaryDirectory() as work_root:
        work_root_path = Path(work_root)
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(process_one, c, crash_dir, extra_args, work_root_path)
                       for c in crashes]
            for fut in as_completed(futures):
                name, rc, err = fut.result()
                with print_lock:
                    completed += 1
                    if err is not None:
                        print(f"[{completed}/{total}] {name} ... {err}")
                    else:
                        done += 1
                        print(f"[{completed}/{total}] {name} ... rc={rc}")

    print()
    print(f"done: {done} / {total} processed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
