#!/usr/bin/env python3
"""Run inputs through sol_afl_diff_runner modes; report aborts (grouped) and how much code actually executed.

Usage: tools/afl/afl_sweep.py [--mode M ...] [--build build] [--sample N] [-j N] -o OUT <file|dir> ...
Use it for false-positive sweeps over a corpus after a harness change, and for checking which PoCs a mode catches.
"""
import argparse
import os
import random
import re
import subprocess
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODES = ["sol_afl_diff_runner", "sol_afl_diff_runner_viair", "sol_afl_diff_runner_viair_opt",
         "sol_afl_diff_runner_ssacfg", "sol_afl_diff_runner_ssacfg_noopt", "sol_afl_diff_runner_optseq", "sol_afl_diff_runner_evmversion",
         "sol_afl_diff_runner_metamorphic", "sol_afl_diff_runner_legacy_knobs"]
WHAT_RE = re.compile(r"what\(\):\s*(.*)")
CALL_RE = re.compile(r"^call #\d+ (.*?): (\S+) / (\S+)", re.MULTILINE)
STOP_RE = re.compile(r"^stop: (.*)$", re.MULTILINE)
COMPILE_ERROR_RE = re.compile(r"^compile error: (.*)$", re.MULTILINE)
DEPLOY_RE = re.compile(r"^deploy: (.+?) / (.+)$", re.MULTILINE)


def stage(err: str, calls: list) -> str:
    """How far an input got"""
    if m := STOP_RE.search(err):
        return m.group(1)
    if m := DEPLOY_RE.search(err):
        if m.group(1) != "success" or m.group(2) != "success":
            return f"deploy {m.group(1)} / {m.group(2)}"
        if not calls:
            return "deployed, no calls"
        if not any(a == "0" for _, a, _ in calls):
            return "deployed, every call fails"
        return "successful call"
    return "other"


def normalize_error(msg: str) -> str:
    return re.sub(r'"[^"]*"', '"…"', msg)[:110]


def collect(paths: list[Path], sample: int) -> list[Path]:
    files = []
    for p in paths:
        files += sorted(f for f in p.rglob("*") if f.is_file()) if p.is_dir() else [p]
    files = [f.resolve() for f in files]
    return random.Random(0).sample(files, sample) if 0 < sample < len(files) else files


def run(runner: Path, path: Path, timeout: int) -> tuple[int | str, str]:
    env = {**os.environ, "AFL_RUNNER_VERBOSE": "1"}
    try:
        p = subprocess.run([str(runner), str(path)], env=env, capture_output=True, timeout=timeout,
                           text=True, errors="replace")
        return p.returncode, p.stderr
    except subprocess.TimeoutExpired:
        return "timeout", ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", type=Path)
    ap.add_argument("-o", "--out", type=Path, required=True)
    ap.add_argument("--mode", action="append", choices=MODES + ["sol_afl_ice_runner", "sol_afl_ice_runner_ssacfg"],
                    help="runner binary (repeatable; default: all diff modes)")
    ap.add_argument("--build", type=Path, default=REPO_ROOT / "build", help="build tree holding tools/afl/")
    ap.add_argument("--sample", type=int, default=0, help="random sample of this many inputs (0 = all)")
    ap.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--timeout", type=int, default=60)
    args = ap.parse_args()

    files = collect(args.inputs, args.sample)
    modes = args.mode or MODES
    args.out.mkdir(parents=True, exist_ok=True)
    lines = [f"{len(files)} inputs, build {args.build}"]
    for mode in modes:
        runner = args.build / "tools" / "afl" / mode
        if not runner.is_file():
            print(f"missing runner: {runner}", file=sys.stderr)
            return 2
        with ThreadPoolExecutor(args.jobs) as pool:
            results = list(pool.map(lambda f: run(runner, f, args.timeout), files))

        hits: dict[str, list[Path]] = defaultdict(list)
        stats = Counter()
        stages = Counter()
        compile_errors = Counter()
        for f, (rc, err) in zip(files, results):
            stats["deployed"] += "deploy: success / success" in err
            calls = CALL_RE.findall(err)
            stages[stage(err, calls)] += 1
            if m := COMPILE_ERROR_RE.search(err):
                compile_errors[normalize_error(m.group(1))] += 1
            ok = [c for c in calls if c[1] == c[2] == "0" and not c[0].startswith("<")]
            stats["calls"] += len(calls)
            stats["successful calls"] += len(ok)
            stats["inputs with a successful call"] += bool(ok)
            if rc == 0:
                continue
            m = WHAT_RE.search(err)
            msg = re.sub(r"call #\d+", "call #N", m.group(1)) if m else f"rc={rc}"
            hits[msg].append(f)
            (args.out / f"{mode}__{f.name}.err").write_text(err + f"\nrc={rc}\n")

        lines += ["", f"== {mode}: {sum(len(v) for v in hits.values())} aborts; "
                  + ", ".join(f"{k}={v}" for k, v in stats.items())]
        lines.append("  where inputs stopped:")
        lines += [f"    {n:5} {100 * n / len(files):5.1f}%  {k}" for k, n in stages.most_common()]
        lines.append("  top compile errors:")
        lines += [f"    {n:5}  {k}" for k, n in compile_errors.most_common(12)]
        for msg, fs in sorted(hits.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"  [{len(fs)}] {msg}")
            lines += [f"      {f}" for f in fs[:3]]
    text = "\n".join(lines) + "\n"
    (args.out / "summary.txt").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
