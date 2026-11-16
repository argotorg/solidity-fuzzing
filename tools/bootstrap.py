#!/usr/bin/env python3
"""Build everything needed to fuzz, from a fresh clone, inside `nix develop` (see flake.nix).

Usage: nix develop --command python3 tools/bootstrap.py [--steps afl,host,proto,aflharness,corpus] [-j N]

Steps run in order; each logs to bootstrap_logs/<step>.log. -j defaults to min(physical cores, available RAM /
1.5 GB): a solidity compile process takes ~1-1.5 GB and more jobs than that gets the machine OOM-killed.
"""
import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
STEPS = ["afl", "host", "proto", "aflharness", "corpus"]


def physical_cores() -> int:
    try:
        out = subprocess.run(["lscpu", "-p=core,socket"], capture_output=True, text=True, check=True).stdout
        return len({l for l in out.splitlines() if not l.startswith("#")}) or os.cpu_count() or 1
    except (OSError, subprocess.CalledProcessError):
        return os.cpu_count() or 1


def available_gb() -> float:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) / 1024 / 1024
    return 8.0


def run(step: str, cmds: list[list[str]], env: dict, logs: Path, cwd: Path = REPO) -> None:
    log = logs / f"{step}.log"
    start = time.monotonic()
    print(f"[{step}] ... (log: {log})", flush=True)
    with log.open("w") as f:
        for cmd in cmds:
            f.write(f"$ {' '.join(cmd)}\n")
            f.flush()
            if subprocess.run(cmd, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT).returncode != 0:
                sys.exit(f"[{step}] FAILED: {' '.join(cmd)}\n  see {log}")
    print(f"[{step}] done in {time.monotonic() - start:.0f}s", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--steps", default=",".join(STEPS), help=f"comma-separated subset of {','.join(STEPS)}")
    ap.add_argument("-j", "--jobs", type=int, default=0, help="compile jobs (default: see above)")
    args = ap.parse_args()

    steps = [s for s in args.steps.split(",") if s]
    unknown = [s for s in steps if s not in STEPS]
    if unknown:
        ap.error(f"unknown steps: {unknown}")
    jobs = args.jobs or max(1, min(physical_cores(), int(available_gb() / 1.5)))
    missing = [t for t in ("make", "cmake", "clang", "llvm-config", "protoc", "pkg-config", "cargo", "git")
               if shutil.which(t) is None]
    if missing:
        sys.exit(f"missing tools {missing}: run inside `nix develop`")
    env = {**os.environ, "BUILD_JOBS": str(jobs)}
    logs = REPO / "bootstrap_logs"
    logs.mkdir(exist_ok=True)
    print(f"jobs={jobs} ({physical_cores()} physical cores, {available_gb():.0f} GB available)", flush=True)

    if not (REPO / "solidity" / "CMakeLists.txt").is_file():
        run("submodules", [["git", "submodule", "update", "--init", "--recursive"]], env, logs)
    if "afl" in steps:
        run("afl", [["make", "-C", "AFLplusplus", f"-j{jobs}", "source-only", "NO_NYX=1"]], env, logs)
    if "host" in steps:
        (REPO / "build").mkdir(exist_ok=True)
        run("host", [
            ["cmake", "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
             "-DCMAKE_C_COMPILER_LAUNCHER=ccache", "-DCMAKE_CXX_COMPILER_LAUNCHER=ccache",
             "-DCMAKE_CXX_FLAGS=-fno-omit-frame-pointer", "-DCMAKE_C_FLAGS=-fno-omit-frame-pointer", ".."],
            ["make", f"-j{jobs}"],
            # EXCLUDE_FROM_ALL: the tree-sitter mutator and grammar the AFL harness runs with
            ["make", f"-j{jobs}", "afl_ts", "tree_sitter_solidity"],
        ], env, logs, cwd=REPO / "build")
    if "proto" in steps:
        run("proto", [["tools/ossfuzz/build_ossfuzz.sh"]], env, logs)
    if "aflharness" in steps:
        run("aflharness", [["tools/afl/build_instrumented.sh"]], env, logs)
    if "corpus" in steps:
        run("corpus", [["tools/afl/fetch_realworld.sh"], ["tools/afl/build_corpus.sh"],
                       ["tools/afl/build_corpus_tsgen.sh"]], env, logs)
        tsgen = REPO / "corpus_tsgen"
        if tsgen.is_dir():
            for f in tsgen.glob("*.sol"):
                shutil.copy2(f, REPO / "corpus_afl" / f.name)

    pattern = Path("/proc/sys/kernel/core_pattern")
    if pattern.is_file() and pattern.read_text().startswith("|"):
        print("note: core_pattern is piped; for AFL run `echo core | sudo tee /proc/sys/kernel/core_pattern`")
    return 0


if __name__ == "__main__":
    sys.exit(main())
