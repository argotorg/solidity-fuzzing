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
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

VALID_PASSES = list("cSLMsrD")  # see CLAUDE.md: yul single_pass binaries

RUNNER = Path("./build/tools/runners/yul_debug_runner").resolve()


def process_one(crash: Path, crash_dir: Path, dumper: Path, opt: str, work_root: Path):
    yul_out = (crash_dir / f"{crash.name}.yul").resolve()
    run_out = (crash_dir / f"{crash.name}.out").resolve()

    # 1. Dump. Harness deliberately crashes after writing the .yul,
    # so a non-zero exit is expected.
    env = {**os.environ, "PROTO_FUZZER_DUMP_PATH": str(yul_out)}
    subprocess.run([str(dumper), str(crash)],
                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=False)

    if not yul_out.is_file() or yul_out.stat().st_size == 0:
        return crash.name, None, "dump-failed"

    # Per-task cwd so parallel runners don't collide on yul_debug_output-N artifacts.
    with tempfile.TemporaryDirectory(dir=str(work_root)) as work:
        with run_out.open("wb") as out:
            rc = subprocess.run(
                [str(RUNNER), "--verbose",
                 "--optimizer-sequence", opt,
                 "--optimizer-cleanup-sequence", "",
                 str(yul_out)],
                cwd=work, stdout=out, stderr=subprocess.STDOUT,
                check=False,
            ).returncode
    return crash.name, rc, None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-p", "--pass", dest="opt_pass", required=True,
                        choices=VALID_PASSES,
                        help="optimizer pass abbreviation (one of: %(choices)s)")
    parser.add_argument("--crash-dir", default=None,
                        help="crash directory (default: <pass>_crash)")
    parser.add_argument("--threads", "-j", type=int, default=os.cpu_count() or 1,
                        help="number of parallel workers (default: %(default)d)")
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
    threads = max(1, args.threads)

    print(f"pass='{opt}' crash_dir={crash_dir} total={total} threads={threads}")

    print_lock = threading.Lock()
    completed = 0

    with tempfile.TemporaryDirectory() as work_root:
        work_root_path = Path(work_root)
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(process_one, c, crash_dir, dumper, opt, work_root_path)
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
