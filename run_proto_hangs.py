#!/usr/bin/env python3
"""Time proto-fuzzer AFL hangs by replaying each through its fuzzer binary; dump sources of the slowest.

Usage: ./run_proto_hangs.py [-j N] [--timeout S] [--top N] [--sample N] -o OUT results/NNN-<fuzzer>/findings [...]
"""
import argparse
import hashlib
import os
import random
import re
import signal
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
FUZZER_DIR = REPO_ROOT / "build_afl" / "tools" / "ossfuzz"
DIR_TAG_RE = re.compile(r"^\d+-(\w+ossfuzz\w*)$")
BUCKETS = [2, 5, 10, 20]


def fuzzer_of(p: Path) -> str | None:
    for part in reversed(p.resolve().parts):
        m = DIR_TAG_RE.match(part)
        if m:
            return m.group(1)
    return None


def collect(roots: list[Path], sample: int) -> list[Path]:
    seen, out = set(), []
    rng = random.Random(0)
    for r in roots:
        mine = []
        for f in sorted(r.rglob("id:*")):
            if f.is_file() and f.parent.name == "hangs":
                h = hashlib.md5(f.read_bytes()).hexdigest()
                if h not in seen:
                    seen.add(h)
                    mine.append(f)
        out += rng.sample(mine, sample) if 0 < sample < len(mine) else mine
    return out


def timed(cmd, timeout, env=None) -> tuple[float, str]:
    t0 = time.monotonic()
    with subprocess.Popen(cmd, start_new_session=True, env=env, stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE) as p:
        try:
            p.communicate(timeout=timeout)
            status = "ok" if p.returncode == 0 else f"rc={p.returncode}"
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()
            return timeout, "TIMEOUT"
    return time.monotonic() - t0, status


def dump(f: Path, fuzzer: Path, out: Path, timeout: int) -> None:
    ext = ".yul" if "yul" in fuzzer.name else ".sol"
    base = out / "sources" / f"{f.parent.parent.name}__{f.name.split(',')[0]}"
    env = {**os.environ, "PROTO_FUZZER_DUMP_PATH": str(base) + ext,
           "PROTO_FUZZER_DUMP_SEQ_PATH": str(base) + ".seq",
           "PROTO_FUZZER_DUMP_CALLDATA_PATH": str(base) + ".calldata"}
    timed([str(fuzzer), str(f.resolve())], timeout, env)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("roots", nargs="+", type=Path)
    ap.add_argument("-o", "--out", type=Path, required=True)
    ap.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--fuzzer", default=None)
    ap.add_argument("--sample", type=int, default=0, help="random hangs per root (0 = all)")
    args = ap.parse_args()

    hangs = collect(args.roots, args.sample)
    (args.out / "sources").mkdir(parents=True, exist_ok=True)
    fz = {h: FUZZER_DIR / (args.fuzzer or fuzzer_of(h)) for h in hangs}
    print(f"{len(hangs)} unique hangs, {args.jobs} jobs, cap {args.timeout}s", flush=True)

    with ThreadPoolExecutor(args.jobs) as pool:
        res = list(pool.map(lambda h: timed([str(fz[h]), str(h.resolve())], args.timeout), hangs))

    rows = sorted(zip(hangs, res), key=lambda r: -r[1][0])
    with (args.out / "per_hang.tsv").open("w") as tsv:
        tsv.write("seconds\tstatus\tfuzzer\tpath\n")
        for h, (sec, st) in rows:
            tsv.write(f"{sec:.2f}\t{st}\t{fz[h].name}\t{h}\n")

    top = rows[:args.top]
    with ThreadPoolExecutor(args.jobs) as pool:
        list(pool.map(lambda r: dump(r[0], fz[r[0]], args.out, 5), top))

    lines = []
    for name in sorted({p.name for p in fz.values()}):
        secs = [s for h, (s, _) in rows if fz[h].name == name]
        hist = Counter(next((f"<{b}s" for b in BUCKETS if s < b), f">={BUCKETS[-1]}s") for s in secs)
        timeouts = sum(1 for h, (_, st) in rows if fz[h].name == name and st == "TIMEOUT")
        order = [f"<{b}s" for b in BUCKETS] + [f">={BUCKETS[-1]}s"]
        lines.append(f"{name}: {len(secs)} hangs, {timeouts} hit the {args.timeout}s cap; "
                     + "  ".join(f"{k}:{hist[k]}" for k in order))
    lines += ["", f"Top {len(top)} slowest (sources in {args.out}/sources):"]
    lines += [f"  {s:6.2f}s {st:8s} {h}" for h, (s, st) in top]
    text = "\n".join(lines) + "\n"
    (args.out / "summary.txt").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
