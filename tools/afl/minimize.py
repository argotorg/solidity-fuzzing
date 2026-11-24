#!/usr/bin/env python3
"""Minimize an AFL diff-runner crash by line-level ddmin, keeping its bucket signature (see run_afl_crashes.py): the
difference, or for sol_afl_ice_runner the ICE's throw site.

Usage: tools/afl/minimize.py --mode sol_afl_diff_runner_viair [-j 4] <crash> -o min.sol
The calldata region and trailer are kept as they are; only source lines are removed.
"""
import argparse
import os
import struct
import subprocess
import sys
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
from run_afl_crashes import bucket_of, parse_diff_runner_outcome, split_afl_input  # noqa: E402


def assemble(source: bytes, calldata: bytes, had_trailer: bool) -> bytes:
    if not had_trailer:
        return source
    return source + calldata + struct.pack("<H", len(source)) + b"\xca\xfe"


class Oracle:
    def __init__(self, runner: Path, calldata: bytes, had_trailer: bool, workdir: Path):
        self.runner, self.calldata, self.had_trailer, self.workdir = runner, calldata, had_trailer, workdir
        self.counter = 0

    def signature(self, source: bytes) -> str:
        self.counter += 1
        path = self.workdir / uuid.uuid4().hex
        path.write_bytes(assemble(source, self.calldata, self.had_trailer))
        try:
            p = subprocess.run([str(self.runner), str(path)], capture_output=True, timeout=60,
                               env={**os.environ, "AFL_RUNNER_VERBOSE": "1"})
            out = (p.stdout + p.stderr).decode(errors="replace")
            category, _ = parse_diff_runner_outcome(p.returncode, out)
            return (bucket_of(category, out) if category.startswith(("crash:abort:diff:", "crash:abort:ice:"))
                    else "no difference")
        except subprocess.TimeoutExpired:
            return "timeout"
        finally:
            path.unlink(missing_ok=True)


def ddmin(lines: list[bytes], keeps, jobs: int) -> list[bytes]:
    n = 2
    while len(lines) >= 2:
        size = max(1, len(lines) // n)
        chunks = [(i, min(i + size, len(lines))) for i in range(0, len(lines), size)]
        complements = [lines[:a] + lines[b:] for a, b in chunks]
        with ThreadPoolExecutor(jobs) as pool:
            results = list(pool.map(keeps, complements))
        reduced = next((c for c, ok in zip(complements, results) if ok), None)
        if reduced is not None:
            lines = reduced
            n = max(n - 1, 2)
        elif size == 1:
            break
        else:
            n = min(n * 2, len(lines))
    return lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("crash", type=Path)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--build", type=Path, default=REPO_ROOT / "build")
    ap.add_argument("-j", "--jobs", type=int, default=4)
    ap.add_argument("-o", "--out", type=Path, required=True)
    args = ap.parse_args()

    runner = args.build / "tools" / "afl" / args.mode
    raw = args.crash.read_bytes()
    had_trailer = len(raw) >= 4 and raw[-2:] == b"\xca\xfe"
    source, calldata = split_afl_input(raw)
    with tempfile.TemporaryDirectory() as tmp:
        oracle = Oracle(runner, calldata, had_trailer, Path(tmp))
        target = oracle.signature(source)
        if target in ("no difference", "timeout"):
            print(f"input does not abort with a difference or an ICE ({target})", file=sys.stderr)
            return 1
        print(f"bucket: {target}", file=sys.stderr)
        keeps = lambda lines: oracle.signature(b"".join(lines)) == target  # noqa: E731
        lines = ddmin(source.splitlines(keepends=True), keeps, args.jobs)
        lines = [l for l in lines if l.strip()] if keeps([l for l in lines if l.strip()]) else lines
    minimized = b"".join(lines)
    args.out.write_bytes(minimized)
    print(f"{len(source)} -> {len(minimized)} bytes, {oracle.counter} runs: {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
