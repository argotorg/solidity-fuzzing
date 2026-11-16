#!/usr/bin/env python3
"""Run a fixed-duration multi-fuzzer AFL++ campaign (no tmux) and summarize it per fuzzer.

Usage:
  tools/afl/run_campaign.py --duration 3600 -o OUT sol_afl_diff_runner_viair=16 sol_afl_ice_runner=6 \\
      sol_proto_ossfuzz_evmone_viair=8
  tools/afl/run_campaign.py --stats-only -o OUT

Each NAME=CORES gets one -M main plus CORES-1 -S secondaries syncing through OUT/NAME. `sol_afl_*` names run
the tree-sitter mutator over --corpus; anything else is a proto fuzzer from build_afl/tools/ossfuzz with its
LPM mutator. Triage afterwards: run_afl_crashes.py OUT/<sol_afl mode> --mode <mode>, sol_crash_categorizer.py /
sol_ice_crash_backtrace_categorizer.py for the proto ones.
"""
import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
AFL_FUZZ = REPO / "AFLplusplus" / "afl-fuzz"
LPM_GRAMMAR = [("sol_proto_ossfuzz_evmone", "sol2Proto"), ("sol_ice_ossfuzz", "sol2Proto"),
               ("yul_proto_ossfuzz_evmone", "yulProto"), ("sol_proto_ossfuzz_nondiff", "solProto"),
               ("shuffler_proto_ossfuzz", "shufflerProto"), ("sol_recstruct_alias_ossfuzz", "solRecStructAliasProto"),
               ("sol_roundtrip_ossfuzz", "solRoundtripProto"), ("abiv2_proto_ossfuzz", "abiV2Proto")]
STAT_KEYS = ["execs_done", "execs_per_sec", "corpus_count", "bitmap_cvg", "saved_crashes", "saved_hangs", "stability"]


def base_env() -> dict:
    env = {"AFL_SKIP_CPUFREQ": "1", "AFL_NO_UI": "1", "AFL_CUSTOM_MUTATOR_ONLY": "1",
           "AFL_HANG_TMOUT": os.environ.get("AFL_HANG_TMOUT", "10000")}
    pattern = Path("/proc/sys/kernel/core_pattern")
    if pattern.is_file() and pattern.read_text().startswith("|"):
        # afl-fuzz refuses piped core handlers; crashes are still caught, but slow core dumping can turn a
        # crash into a timeout. Better: `echo core | sudo tee /proc/sys/kernel/core_pattern`.
        print("warning: core_pattern is piped; running with AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1", file=sys.stderr)
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    return env


def fuzzer_setup(name: str, corpus: Path, proto_corpus: Path) -> tuple[Path, Path, dict]:
    env = base_env()
    if name.startswith("sol_afl_"):
        env["AFL_CUSTOM_MUTATOR_LIBRARY"] = str(REPO / "afl-ts" / "libts.so")
        env["TS_GRAMMAR"] = str(REPO / "tree-sitter-solidity" / "libtree-sitter-solidity.so")
        # Otherwise every instance calibrates all ~8.5k seeds before fuzzing: most of a short campaign
        env["AFL_NO_STARTUP_CALIBRATION"] = "1"
        return REPO / "build_afl" / "tools" / "afl" / name, corpus, env
    grammar = next((g for prefix, g in LPM_GRAMMAR if name.startswith(prefix)), None)
    if grammar is None:
        sys.exit(f"unknown fuzzer: {name}")
    env["AFL_CUSTOM_MUTATOR_LIBRARY"] = str(REPO / "deps_afl" / "lib" / f"lib{grammar}_lpm_mutator.so")
    # AFL's byte trimming bypasses the custom mutator and corrupts text protos
    env["AFL_DISABLE_TRIM"] = "1"
    return REPO / "build_afl" / "tools" / "ossfuzz" / name, proto_corpus, env


def ensure_proto_seed(corpus: Path) -> None:
    # afl-fuzz needs one non-empty input; a comment line is a valid, empty text-format proto
    if not corpus.is_dir() or not any(f.is_file() and f.stat().st_size for f in corpus.iterdir()):
        corpus.mkdir(parents=True, exist_ok=True)
        (corpus / "seed").write_text("# empty seed: valid text-format protobuf\n")


def read_stats(instance: Path) -> dict:
    stats = {}
    f = instance / "fuzzer_stats"
    if f.is_file():
        for line in f.read_text().splitlines():
            k, _, v = line.partition(":")
            stats[k.strip()] = v.strip()
    return stats


def summarize(out: Path) -> str:
    lines = [f"{'fuzzer':42s} {'inst':>4s} {'execs':>12s} {'exec/s':>8s} {'corpus':>7s} {'cvg':>7s} "
             f"{'crashes':>7s} {'hangs':>6s} {'stability':>9s}"]
    for d in sorted(p for p in out.iterdir() if p.is_dir()):
        instances = [read_stats(i) for i in sorted(d.iterdir()) if (i / "fuzzer_stats").is_file()]
        if not instances:
            continue
        num = lambda k: sum(float(s.get(k, "0").rstrip("%") or 0) for s in instances)
        # execs_per_sec is a short-window figure and meaningless during calibration
        rate = sum(float(s.get("execs_done", 0)) / max(1.0, float(s.get("last_update", 0)) - float(s.get("start_time", 0)))
                   for s in instances)
        crashes = sum(len([c for c in (i / "crashes").glob("id:*")]) for i in d.iterdir() if (i / "crashes").is_dir())
        hangs = sum(len([c for c in (i / "hangs").glob("id:*")]) for i in d.iterdir() if (i / "hangs").is_dir())
        corpus = max(int(s.get("corpus_count", "0")) for s in instances)
        cvg = max(float(s.get("bitmap_cvg", "0%").rstrip("%")) for s in instances)
        stab = num("stability") / len(instances)
        lines.append(f"{d.name:42s} {len(instances):4d} {int(num('execs_done')):12d} {rate:8.1f} "
                     f"{corpus:7d} {cvg:6.2f}% {crashes:7d} {hangs:6d} {stab:8.1f}%")
    text = "\n".join(lines) + "\n"
    (out / "campaign_stats.txt").write_text(text)
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("alloc", nargs="*", help="NAME=CORES")
    ap.add_argument("-o", "--out", type=Path, required=True)
    ap.add_argument("--duration", type=int, default=3600, help="seconds (afl-fuzz -V)")
    ap.add_argument("--corpus", type=Path, default=REPO / "corpus_afl")
    ap.add_argument("--proto-corpus", type=Path, default=None, help="default: OUT/proto_seed")
    ap.add_argument("--timeout-ms", type=int, default=2000, help="afl-fuzz -t per exec")
    ap.add_argument("--stats-only", action="store_true")
    args = ap.parse_args()

    out = args.out.resolve()
    if args.stats_only:
        print(summarize(out))
        return 0
    if not args.alloc:
        ap.error("give at least one NAME=CORES")
    proto_corpus = (args.proto_corpus or out / "proto_seed").resolve()
    ensure_proto_seed(proto_corpus)
    out.mkdir(parents=True, exist_ok=True)

    procs = []
    for spec in args.alloc:
        name, _, cores = spec.partition("=")
        binary, corpus, extra_env = fuzzer_setup(name, args.corpus.resolve(), proto_corpus)
        for path in (binary, Path(extra_env["AFL_CUSTOM_MUTATOR_LIBRARY"]), AFL_FUZZ):
            if not path.is_file():
                sys.exit(f"missing: {path}")
        for i in range(int(cores or 1)):
            role = ["-M", "main"] if i == 0 else ["-S", f"s{i:02d}"]
            cmd = [str(AFL_FUZZ), "-i", str(corpus), "-o", str(out / name), *role, "-m", "none",
                   "-t", str(args.timeout_ms), "-V", str(args.duration), "--", str(binary)]
            log_path = out / f"{name}.{i:02d}.log"
            with log_path.open("wb") as log:
                procs.append((log_path, subprocess.Popen(cmd, env={**os.environ, **extra_env}, stdout=log,
                                                         stderr=subprocess.STDOUT, start_new_session=True)))
    print(f"launched {len(procs)} afl-fuzz instances for {args.duration}s; logs in {out}", flush=True)

    time.sleep(min(60, args.duration))
    dead = [(spec, p) for spec, p in procs if p.poll() is not None]
    if dead and args.duration > 60:
        for _, p in procs:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGINT)
        for spec, p in dead:
            tail = spec.read_bytes()[-2000:].decode(errors="replace")
            abort = [l for l in tail.splitlines() if "ABORT" in l or "Location" in l or "[-]" in l]
            print(f"instance died early: {spec.name}\n  " + "\n  ".join(abort[-4:]), file=sys.stderr)
        return 1

    deadline = time.monotonic() + args.duration + 300
    try:
        for _, p in procs:
            p.wait(timeout=max(1, deadline - time.monotonic()))
    except (KeyboardInterrupt, subprocess.TimeoutExpired):
        for _, p in procs:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGINT)
        for _, p in procs:
            p.wait()
    print(summarize(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
