#!/usr/bin/env python3
"""Replay ice_crash/ corpus through solc.

For each crash-<hash> file in the crash dir:
  1. Dump the protobuf to <crash-dir>/crash-<hash>.sol via sol_ice_ossfuzz.
  2. Compile with solc and save its full output (stdout+stderr) to
     <crash-dir>/crash-<hash>.out.
  3. If solc crashes — killed by a signal (segfault / boost-assert abort) or
     reporting an "Internal compiler error" (a solAssert that solc catches and
     prints with exit code 2) — re-run it under gdb and save the backtrace to
     <crash-dir>/crash-<hash>.bt.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DUMPER = Path("./build_afl/tools/ossfuzz/sol_ice_ossfuzz").resolve()
SOLC = Path("./build/solidity/solc/solc").resolve()


def is_crash_file(name: str) -> bool:
    """True for a raw fuzzer crash input, not our generated artifacts.

    Accepts both libFuzzer ("crash-<hash>") and AFL++ ("id:000000,sig:...")
    naming. The "." guard excludes the per-crash .sol/.out/.bt files we write
    alongside, plus AFL's crashes/README.txt.
    """
    if "." in name:
        return False
    return name.startswith("crash-") or name.startswith("id:")

ICE_MARKER = "Internal compiler error"
# solc prints e.g. "Dynamic exception type: boost::wrapexcept<solidity::langutil::InternalCompilerError>"
EXC_TYPE_RE = re.compile(r"Dynamic exception type:\s*(?:boost::wrapexcept<)?([\w:]+)")

# A gdb frame line, e.g. "#3  0x000055.. in solidity::frontend::Foo::bar(...) ()"
FRAME_RE = re.compile(r"^#\d+\s+(?:0x[0-9a-fA-F]+ in )?(.+)$")
# Frames that are throw/abort plumbing, not the actual fault site.
NOISE_FRAMES = ("__cxa_throw", "__cxa_rethrow", "throw_exception", "solThrowImpl",
                "std::terminate", "__cxxabiv1", "abort", "raise", "gsignal",
                "__pthread_kill", "__GI_", "libc_message")


def ice_signature(bt_text: str) -> str:
    """Pick the fault-site frame from a gdb backtrace as the ICE signature.

    Skips throw/abort plumbing and returns the first real frame, trimmed to its
    qualified function name (argument list dropped) so identical asserts group.
    """
    frames = []
    for line in bt_text.splitlines():
        m = FRAME_RE.match(line.strip())
        if not m:
            continue
        sym = m.group(1).split(" from ")[0].strip()  # drop "... from /usr/lib/.."
        frames.append(sym)
    if not frames:
        return "?"
    pick = next((s for s in frames if not any(n in s for n in NOISE_FRAMES)),
                frames[0])
    cut = pick.find("(")
    return pick[:cut].strip() if cut != -1 else pick


def dump_backtrace(sol_out: Path, extra_args: list, bt_out: Path, work: str,
                   exc_type=None):
    """Re-run solc under gdb and write the backtrace to bt_out.

    If exc_type is given (a caught C++ exception, e.g. an ICE), stop at that
    throw so the backtrace points at the assertion site. Otherwise just run to
    the crashing signal.
    """
    catch = ["-ex", f"catch throw {exc_type}"] if exc_type else []
    cmd = ["gdb", "-batch", "-nx", "-ex", "set debuginfod enabled off",
           *catch, "-ex", "run", "-ex", "bt full", "-ex", "quit",
           "--args", str(SOLC), *extra_args, str(sol_out)]
    with bt_out.open("wb") as out:
        subprocess.run(cmd, cwd=work, stdout=out, stderr=subprocess.STDOUT,
                       check=False)


def process_one(crash: Path, crash_dir: Path, extra_args: list, work_root: Path):
    sol_out = (crash_dir / f"{crash.name}.sol").resolve()
    run_out = (crash_dir / f"{crash.name}.out").resolve()
    bt_out = (crash_dir / f"{crash.name}.bt").resolve()

    # 1. Dump. Harness writes the .sol then attempts the compile,
    # which may crash; either way the .sol should be on disk.
    env = {**os.environ, "PROTO_FUZZER_DUMP_PATH": str(sol_out)}
    subprocess.run([str(DUMPER), str(crash)],
                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=False)

    if not sol_out.is_file() or sol_out.stat().st_size == 0:
        return crash.name, None, "dump-failed", False, None

    # Per-task cwd to keep any solc-side artifacts isolated between threads.
    with tempfile.TemporaryDirectory(dir=str(work_root)) as work:
        with run_out.open("wb") as out:
            rc = subprocess.run(
                [str(SOLC), *extra_args, str(sol_out)],
                cwd=work, stdout=out, stderr=subprocess.STDOUT,
                check=False,
            ).returncode

        # Two flavours of "crash":
        #   rc < 0              -> killed by a signal (SIGSEGV, boost-assert abort)
        #   "Internal compiler error" in output -> solAssert that solc caught and
        #                          printed gracefully (exit code 2)
        crashed = False
        exc_type = None
        if rc < 0:
            crashed = True
        else:
            out_text = run_out.read_text(errors="replace")
            if ICE_MARKER in out_text:
                crashed = True
                m = EXC_TYPE_RE.search(out_text)
                exc_type = m.group(1) if m else "solidity::langutil::InternalCompilerError"

        signature = None
        if crashed:
            dump_backtrace(sol_out, extra_args, bt_out, work, exc_type)
            signature = ice_signature(bt_out.read_text(errors="replace"))
    return crash.name, rc, None, crashed, signature


def print_signature_table(by_signature: dict):
    """Print a table of distinct ICE fault sites, most frequent first."""
    if not by_signature:
        return
    rows = sorted(by_signature.items(), key=lambda kv: (-kv[1][0], kv[0]))
    sig_w = max(len("fault site"), *(len(sig) for sig, _ in rows))
    ex_w = max(len("example"), *(len(ex) for _, (_, ex) in rows))
    print()
    print(f"distinct ICEs: {len(rows)}")
    print(f"{'fault site':<{sig_w}}  {'count':>5}  {'example':<{ex_w}}")
    print(f"{'-' * sig_w}  {'-' * 5}  {'-' * ex_w}")
    for sig, (count, example) in rows:
        print(f"{sig:<{sig_w}}  {count:>5}  {example:<{ex_w}}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--crash-dir", default="ice_crash",
                        help="crash directory (default: ice_crash)")
    parser.add_argument("--solc-args", default="--via-ir --optimize",
                        help="extra args passed to solc (default: %(default)r)")
    parser.add_argument("--threads", "-j", type=int, default=os.cpu_count() or 1,
                        help="number of parallel workers (default: %(default)d)")
    parser.add_argument("--limit", type=int, default=None,
                        help="process at most this many crashes (default: all)")
    args = parser.parse_args()

    crash_dir = Path(args.crash_dir)
    extra_args = args.solc_args.split()
    crashed_count = 0

    for p in (DUMPER, SOLC):
        if not (p.is_file() and os.access(p, os.X_OK)):
            print(f"missing or not executable: {p}", file=sys.stderr)
            return 1
    if not crash_dir.is_dir():
        print(f"missing dir: {crash_dir}", file=sys.stderr)
        return 1

    crashes = sorted(f for f in crash_dir.iterdir()
                     if f.is_file() and is_crash_file(f.name))
    if args.limit is not None:
        crashes = crashes[:args.limit]
    total = len(crashes)
    done = 0
    threads = max(1, args.threads)

    print(f"crash_dir={crash_dir} total={total} solc_args={extra_args} threads={threads}")

    print_lock = threading.Lock()
    completed = 0
    # signature -> [count, first-seen example crash name]
    by_signature: dict = {}

    with tempfile.TemporaryDirectory() as work_root:
        work_root_path = Path(work_root)
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(process_one, c, crash_dir, extra_args, work_root_path)
                       for c in crashes]
            for fut in as_completed(futures):
                name, rc, err, crashed, signature = fut.result()
                with print_lock:
                    completed += 1
                    if err is not None:
                        print(f"[{completed}/{total}] {name} ... {err}")
                    else:
                        done += 1
                        bt = "  (crashed, backtrace saved)" if crashed else ""
                        if crashed:
                            crashed_count += 1
                            entry = by_signature.setdefault(signature, [0, name])
                            entry[0] += 1
                        print(f"[{completed}/{total}] {name} ... rc={rc}{bt}")

    print()
    print(f"done: {done} / {total} processed, {crashed_count} crashed (backtraces in *.bt)")
    print_signature_table(by_signature)
    return 0


if __name__ == "__main__":
    sys.exit(main())
