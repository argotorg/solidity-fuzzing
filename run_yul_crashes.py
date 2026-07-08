#!/usr/bin/env python3
"""Replay a yul fuzzer crash corpus through yul_debug_runner.

Works for both the single-pass fuzzers and the whole-sequence differential
modes (ssacfg / check_stack_alloc / no_ssa / default), selected via -p.

For each crash-<hash> file in the crash dir:
  1. Dump the protobuf to <crash-dir>/crash-<hash>.yul via the matching fuzzer
     binary. For non-single-pass modes also dump the optimizer sequence to
     <crash-dir>/crash-<hash>.seq (the harness bakes each mode's differential
     into that sequence).
  2. Replay with yul_debug_runner --verbose, passing the target pass (single
     pass) or the dumped sequence (other modes) as --optimizer-sequence /
     --optimizer-cleanup-sequence, and save its full output to
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
# Non-single-pass differential modes. Each is a distinct fuzzer binary whose
# differential is baked into the optimizer sequence the harness dumps, so we
# replay them by feeding that dumped sequence to the runner (which already runs
# the unoptimized / optimized-legacy / optimized-SSACFG configs and compares).
VALID_MODES = ["ssacfg", "check_stack_alloc", "no_ssa", "default"]
VALID_SELECTORS = VALID_PASSES + VALID_MODES

RUNNER = Path("./build/tools/runners/yul_debug_runner").resolve()


def dumper_name(sel: str) -> str:
    """Map a -p selector to its fuzzer binary name."""
    if sel in VALID_PASSES:
        return f"yul_proto_ossfuzz_evmone_single_pass_{sel}"
    if sel == "default":
        return "yul_proto_ossfuzz_evmone"
    return f"yul_proto_ossfuzz_evmone_{sel}"


def parse_seq(seq_path: Path):
    """Read the optimizer sequences the harness dumped to a .seq file.

    Format (see yulProtoFuzzerEvmone.cpp):
        optimizer-sequence: <steps>
        optimizer-cleanup-sequence: <steps>
    Returns (seq, cleanup); either may be an empty string.
    """
    opt = cleanup = ""
    for line in seq_path.read_text().splitlines():
        if line.startswith("optimizer-sequence:"):
            opt = line.split(":", 1)[1].strip()
        elif line.startswith("optimizer-cleanup-sequence:"):
            cleanup = line.split(":", 1)[1].strip()
    return opt, cleanup


def optimizer_args(sel: str, seq_out: Path) -> list:
    """Runner --optimizer-* args for this selector.

    Single-pass replays just the one target pass with an empty cleanup; the
    other modes replay the sequence the harness dumped to seq_out. Returns []
    when no sequence is available, letting the runner use its default.
    """
    if sel in VALID_PASSES:
        seq, cleanup = sel, ""
    elif seq_out.is_file():
        seq, cleanup = parse_seq(seq_out)
    else:
        return []
    return ["--optimizer-sequence", seq, "--optimizer-cleanup-sequence", cleanup]


def is_crash_file(name: str) -> bool:
    """True for a raw fuzzer crash input, not our generated artifacts.

    Accepts both libFuzzer ("crash-<hash>") and AFL++ ("id:000000,sig:...")
    naming. The "." guard excludes the per-crash .yul/.out files we write
    alongside, plus AFL's crashes/README.txt.
    """
    if "." in name:
        return False
    return name.startswith("crash-") or name.startswith("id:")


def process_one(crash: Path, crash_dir: Path, dumper: Path, sel: str, work_root: Path):
    yul_out = (crash_dir / f"{crash.name}.yul").resolve()
    run_out = (crash_dir / f"{crash.name}.out").resolve()
    seq_out = (crash_dir / f"{crash.name}.seq").resolve()

    # 1. Dump the Yul source. The harness deliberately crashes after writing the
    # .yul, so a non-zero exit is expected. Non-single-pass modes also dump their
    # optimizer sequence so we can replay the exact differential.
    env = {**os.environ, "PROTO_FUZZER_DUMP_PATH": str(yul_out)}
    if sel not in VALID_PASSES:
        env["PROTO_FUZZER_DUMP_SEQ_PATH"] = str(seq_out)
    subprocess.run([str(dumper), str(crash)],
                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=False)

    if not yul_out.is_file() or yul_out.stat().st_size == 0:
        return crash.name, None, "dump-failed"

    # 2. Replay. Per-task cwd so parallel runners don't collide on the
    # yul_debug_output-N artifacts the runner writes.
    run_cmd = [str(RUNNER), "--verbose", *optimizer_args(sel, seq_out), str(yul_out)]
    with tempfile.TemporaryDirectory(dir=str(work_root)) as work:
        with run_out.open("wb") as out:
            rc = subprocess.run(
                run_cmd, cwd=work, stdout=out, stderr=subprocess.STDOUT,
                check=False,
            ).returncode
    return crash.name, rc, None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-p", "--pass", dest="opt_pass", required=True,
                        choices=VALID_SELECTORS, metavar="SELECTOR",
                        help="single-pass abbreviation (%s) or differential mode (%s)"
                             % (",".join(VALID_PASSES), ",".join(VALID_MODES)))
    parser.add_argument("--crash-dir", default=None,
                        help="crash directory (default: <selector>_crash)")
    parser.add_argument("--threads", "-j", type=int, default=os.cpu_count() or 1,
                        help="number of parallel workers (default: %(default)d)")
    args = parser.parse_args()

    sel = args.opt_pass
    crash_dir = Path(args.crash_dir) if args.crash_dir else Path(f"{sel}_crash")
    dumper = Path(f"./build_afl/tools/ossfuzz/{dumper_name(sel)}").resolve()

    for p in (dumper, RUNNER):
        if not (p.is_file() and os.access(p, os.X_OK)):
            print(f"missing or not executable: {p}", file=sys.stderr)
            return 1
    if not crash_dir.is_dir():
        print(f"missing dir: {crash_dir}", file=sys.stderr)
        return 1

    crashes = sorted(f for f in crash_dir.iterdir()
                     if f.is_file() and is_crash_file(f.name))
    total = len(crashes)
    done = 0
    threads = max(1, args.threads)

    kind = "pass" if sel in VALID_PASSES else "mode"
    print(f"{kind}='{sel}' crash_dir={crash_dir} total={total} threads={threads}")

    print_lock = threading.Lock()
    completed = 0

    with tempfile.TemporaryDirectory() as work_root:
        work_root_path = Path(work_root)
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(process_one, c, crash_dir, dumper, sel, work_root_path)
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
