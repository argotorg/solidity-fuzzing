#!/usr/bin/env python3
"""Replay AFL *hangs* through sol_debug_runner --afl and collect per-config solc runtimes.

Walks <findings_root>/*/hangs/* (default findings_root=findings_afl). For each
hang file (raw AFL input, possibly carrying the [src][calldata][lenLE][0xCA 0xFE]
trailer used by the AFL diff harness):

  1. Runs sol_debug_runner --afl --timeout <per_config_timeout> <hang>
       - With --timeout > 0, the runner replaces the in-process compile with an
         external `timeout N solc ...` subprocess per config, prints per-config
         "Time: <ms> ms" or "TIMED OUT (>Ns)" lines, and skips the differential
         check. This is exactly the "hang-triage" path.
       - Five configs are exercised (see Config table in sol_debug_runner.cpp):
           noOpt_viaIR=true, opt_viaIR=true,
           noOpt_viaIR=false, opt_viaIR=false,
           opt_ssaCFG

  2. Parses each "Running: <label>..." / "Time: <N> ms" pair (and "TIMED OUT")
     to extract per-config solc wall-clock time. Timeouts are recorded as
     `per_config_timeout * 1000` ms with a sentinel flag so they sort to the top.

  3. Splits the hang into [source, calldata] using the same 0xCA 0xFE trailer
     logic the C++ harness uses, writes the .sol for human review.

Outputs:
  <out_dir>/per_hang.tsv              one row per hang (campaign, hang, sizes,
                                      per-config times in ms, totals, ranks)
  <out_dir>/by_runtime.txt            ranked summary (top N slowest, plus
                                      per-config worst offenders)
  <out_dir>/logs/<key>.debug.log      raw sol_debug_runner stdout+stderr
  <out_dir>/sources/<key>.sol         extracted source slice (for inspection)

The script intentionally mirrors run_afl_crashes.py's structure (split logic,
key naming, parallel walker, TSV+summary layout) — same authors will be looking
at both pipelines.

Note on overhead: sol_debug_runner *also* runs `perf record` per config after
the timed solc invocation (the "Time:" line measures only the first run, not
perf). That doubles wall-clock per hang on top of the perf overhead itself.
We accept that — outer wall-clock per hang is sized accordingly.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DEBUG_RUNNER = Path("./build/tools/runners/sol_debug_runner").resolve()

# Per-config solc timeout passed to sol_debug_runner --timeout. A hang that
# burns past this is reported as TIMED_OUT in that config. Aggregation uses
# this same value (in ms) as the recorded time for timed-out configs so they
# sort to the top of the "worst" list.
DEFAULT_PER_CONFIG_TIMEOUT_S = 30
# Outer wall-clock per sol_debug_runner invocation. Each config runs solc twice
# (once timed, once under perf record), each capped at per_config_timeout. Five
# configs => 5 * 2 * timeout + slack.
DEFAULT_OUTER_TIMEOUT_S = 600

# The five labels printed by sol_debug_runner (see Config table in
# sol_debug_runner.cpp::main). Order matters — used as TSV column order.
CONFIG_LABELS = [
    "noOpt_viaIR=true",
    "opt_viaIR=true",
    "noOpt_viaIR=false",
    "opt_viaIR=false",
    "opt_ssaCFG",
]

# "Running: <label>..." opens a config block; "Time: <N> ms" or "TIMED OUT
# (>Ns)" closes the timing window. We pair them in order; "Compilation failed"
# / IR notes between them are ignored for timing purposes.
RUNNING_RE = re.compile(r"^Running:\s+(\S+)\.\.\.\s*$", re.MULTILINE)
TIME_RE = re.compile(r"^\s*Time:\s+(\d+)\s*ms\s*$", re.MULTILINE)
TIMEOUT_RE = re.compile(r"^\s*TIMED OUT\s*\(>\s*(\d+)\s*s\)\s*$", re.MULTILINE)


def split_afl_input(data: bytes) -> tuple[bytes, bytes]:
    """Mirror sol_afl_diff_runner.cpp::splitInput in Python.

    Returns (source_bytes, calldata_bytes). When no magic trailer is present,
    the whole file is treated as source.
    """
    if len(data) >= 4 and data[-2] == 0xCA and data[-1] == 0xFE:
        src_len = data[-4] | (data[-3] << 8)
        if src_len <= len(data) - 4:
            return data[:src_len], data[src_len:-4]
    return data, b""


def safe_key(campaign: str, hang_name: str) -> str:
    """Filesystem-safe key for log/source filenames."""
    return f"{campaign}__{re.sub(r'[^A-Za-z0-9._-]+', '_', hang_name)}"


def find_hangs(findings_root: Path) -> list[Path]:
    """Find AFL hang files: <root>/*/hangs/id:* (skip README and .* files)."""
    out: list[Path] = []
    for d in sorted(findings_root.glob("*/hangs")):
        for f in sorted(d.iterdir()):
            if f.is_file() and f.name.startswith("id:"):
                out.append(f)
    return out


def run_with_timeout(cmd: list[str], timeout_s: int,
                     cwd: str | None = None) -> tuple[int | str, str]:
    """Run a subprocess; return (returncode_or_'TIMEOUT', combined_output)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout_s, check=False, cwd=cwd,
        )
        out = (proc.stdout or b"") + (proc.stderr or b"")
        return proc.returncode, out.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as e:
        partial = b""
        if e.stdout:
            partial += e.stdout if isinstance(e.stdout, bytes) else e.stdout.encode()
        if e.stderr:
            partial += e.stderr if isinstance(e.stderr, bytes) else e.stderr.encode()
        return "TIMEOUT", partial.decode("utf-8", errors="replace")


def parse_per_config_times(output: str,
                            per_config_timeout_ms: int) -> dict[str, tuple[int, bool]]:
    """Walk through the output linearly, pairing each "Running: LABEL" with the
    next "Time: <ms>" or "TIMED OUT" that follows it.

    Returns {label: (time_ms, timed_out_bool)}. Missing configs map to (-1, False).
    Timeouts are recorded as `per_config_timeout_ms` so they rank at the top of
    per-config "worst" ordering.
    """
    out: dict[str, tuple[int, bool]] = {}
    # Tokenise: collect (position, kind, payload) tuples and walk in order.
    events: list[tuple[int, str, str]] = []
    for m in RUNNING_RE.finditer(output):
        events.append((m.start(), "run", m.group(1)))
    for m in TIME_RE.finditer(output):
        events.append((m.start(), "time", m.group(1)))
    for m in TIMEOUT_RE.finditer(output):
        events.append((m.start(), "timeout", m.group(1)))
    events.sort(key=lambda e: e[0])

    current_label: str | None = None
    saw_timeout_for_current = False
    for _pos, kind, payload in events:
        if kind == "run":
            # A new config opens — if the previous one was opened but never
            # closed (e.g. process killed mid-config), record it as timeout.
            if current_label is not None and current_label not in out:
                out[current_label] = (per_config_timeout_ms, True)
            current_label = payload
            saw_timeout_for_current = False
        elif kind == "timeout":
            saw_timeout_for_current = True
            if current_label is not None:
                out[current_label] = (per_config_timeout_ms, True)
        elif kind == "time":
            if current_label is not None and current_label not in out:
                # If we already saw a TIMED OUT line for this config the time
                # we now see is the elapsed-wall-time of the std::system call
                # (~= timeout). Keep the timeout flag, but use the precise ms.
                ms = int(payload)
                out[current_label] = (ms, saw_timeout_for_current)
    # Tail: if the last config block had no Time/TIMED OUT (process killed),
    # mark it as a timeout.
    if current_label is not None and current_label not in out:
        out[current_label] = (per_config_timeout_ms, True)
    return out


def process_one(hang: Path, out_dir: Path, per_config_timeout: int,
                outer_timeout: int) -> dict:
    campaign = hang.parent.parent.name
    key = safe_key(campaign, hang.name)

    # Save split source for human review.
    raw = hang.read_bytes()
    src, calldata = split_afl_input(raw)
    (out_dir / "sources" / f"{key}.sol").write_bytes(src)

    per_config_timeout_ms = per_config_timeout * 1000

    # sol_debug_runner creates a `sol_debug_output-K` dir in CWD per run; with
    # parallel workers sharing CWD we'd hit name collisions. Run each worker
    # from its own scratch dir.
    with tempfile.TemporaryDirectory(prefix="sol_dbg_hang_") as scratch:
        # Use the absolute hang path — CWD is the scratch dir, so relative
        # paths from the launcher's CWD would no longer resolve.
        cmd = [str(DEBUG_RUNNER), "--afl",
               "--timeout", str(per_config_timeout),
               str(hang.resolve())]
        rc, output = run_with_timeout(cmd, outer_timeout, cwd=scratch)

    (out_dir / "logs" / f"{key}.debug.log").write_text(output)

    times = parse_per_config_times(output, per_config_timeout_ms)

    row: dict = {
        "campaign": campaign,
        "hang": hang.name,
        "path": str(hang.resolve()),
        "key": key,
        "size": len(raw),
        "src_size": len(src),
        "calldata_size": len(calldata),
        "has_magic": int(len(raw) >= 2 and raw[-2:] == b"\xca\xfe"),
        "rc": str(rc),
    }
    total_ms = 0
    max_ms = 0
    max_label = ""
    timeouts = 0
    measured = 0
    for label in CONFIG_LABELS:
        t = times.get(label)
        if t is None:
            row[f"{label}_ms"] = ""
            row[f"{label}_to"] = ""
            continue
        ms, to = t
        measured += 1
        total_ms += ms
        if ms > max_ms:
            max_ms = ms
            max_label = label
        if to:
            timeouts += 1
        row[f"{label}_ms"] = ms
        row[f"{label}_to"] = int(to)
    row["total_ms"] = total_ms
    row["max_ms"] = max_ms
    row["max_label"] = max_label
    row["timeouts"] = timeouts
    row["measured_configs"] = measured
    return row


HEADER = (
    ["campaign", "hang", "path", "size", "src_size", "calldata_size", "has_magic", "rc"]
    + [f"{l}_ms" for l in CONFIG_LABELS]
    + [f"{l}_to" for l in CONFIG_LABELS]
    + ["total_ms", "max_ms", "max_label", "timeouts", "measured_configs"]
)


def fmt_ms(ms) -> str:
    if ms == "" or ms is None:
        return "  —   "
    if isinstance(ms, str):
        ms = int(ms)
    if ms >= 10000:
        return f"{ms / 1000:6.2f}s"
    return f"{ms:5d}ms"


def write_summary(out_dir: Path, rows: list[dict], per_config_timeout: int,
                  top_n: int) -> None:
    out = out_dir / "by_runtime.txt"
    per_config_timeout_ms = per_config_timeout * 1000

    # Ranked by total time across all 5 configs (timeouts count for full
    # per-config timeout).
    by_total = sorted(rows, key=lambda r: -int(r.get("total_ms") or 0))
    # Ranked by single-config max (which config was slowest in absolute terms).
    by_max = sorted(rows, key=lambda r: -int(r.get("max_ms") or 0))

    with out.open("w") as fh:
        fh.write("# AFL hang runtime triage — sol_debug_runner --afl --timeout "
                 f"{per_config_timeout}\n\n")
        fh.write(f"Total hangs processed: {len(rows)}\n")
        fh.write(f"Per-config inner timeout: {per_config_timeout}s "
                 f"(=> {per_config_timeout_ms} ms cap per config)\n\n")

        # ---- Top by TOTAL time across all 5 configs ----
        fh.write(f"## Top {top_n} hangs by TOTAL solc time across 5 configs\n")
        fh.write("(timeouts counted as full per-config cap)\n\n")
        col_w = 11
        header = "rank | total    | max       | tos | " + " | ".join(
            l.rjust(col_w) for l in CONFIG_LABELS) + " | file"
        fh.write(header + "\n")
        fh.write("-" * len(header) + "\n")
        for i, r in enumerate(by_total[:top_n], 1):
            cols = " | ".join(
                (("TO " if r.get(f"{l}_to") == 1 else "   ") + fmt_ms(r.get(f"{l}_ms"))).rjust(col_w)
                for l in CONFIG_LABELS
            )
            fh.write(
                f"{i:4d} | {fmt_ms(r['total_ms'])} | {fmt_ms(r['max_ms'])} | "
                f"{r['timeouts']:3d} | {cols} | {r['path']}\n"
            )
        fh.write("\n")

        # ---- Top by single-config max ----
        fh.write(f"## Top {top_n} hangs by SINGLE-CONFIG MAX time\n")
        fh.write("(which one config dominated the run)\n\n")
        fh.write(header + "\n")
        fh.write("-" * len(header) + "\n")
        for i, r in enumerate(by_max[:top_n], 1):
            cols = " | ".join(
                (("TO " if r.get(f"{l}_to") == 1 else "   ") + fmt_ms(r.get(f"{l}_ms"))).rjust(col_w)
                for l in CONFIG_LABELS
            )
            fh.write(
                f"{i:4d} | {fmt_ms(r['total_ms'])} | {fmt_ms(r['max_ms'])} | "
                f"{r['timeouts']:3d} | {cols} | {r['path']}\n"
            )
        fh.write("\n")

        # ---- Per-config "worst offenders" ----
        fh.write(f"## Per-config worst offenders (top {top_n} each)\n\n")
        for label in CONFIG_LABELS:
            ranked = sorted(
                (r for r in rows if isinstance(r.get(f"{label}_ms"), int)),
                key=lambda r: -int(r[f"{label}_ms"]),
            )
            fh.write(f"### {label}\n")
            for i, r in enumerate(ranked[:top_n], 1):
                ms = r[f"{label}_ms"]
                to = " (TIMED OUT)" if r.get(f"{label}_to") == 1 else ""
                fh.write(f"  {i:3d}. {fmt_ms(ms)}{to}   {r['path']}\n")
            fh.write("\n")

        # ---- Coverage / health ----
        n_timeouts = sum(r["timeouts"] for r in rows)
        n_any_timeout = sum(1 for r in rows if r["timeouts"] > 0)
        fh.write("## Coverage\n")
        fh.write(f"  Configs that hit per-config timeout: {n_timeouts} "
                 f"(across {n_any_timeout} hangs)\n")
        per_cfg_tos = {l: sum(1 for r in rows if r.get(f"{l}_to") == 1) for l in CONFIG_LABELS}
        for l, n in per_cfg_tos.items():
            fh.write(f"    {l:24s} {n:4d}\n")
        n_missing = sum(1 for r in rows if r["measured_configs"] < len(CONFIG_LABELS))
        fh.write(f"  Hangs with <5 configs measured (parse miss / runner crash): "
                 f"{n_missing}\n")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings_root", nargs="?", default="findings_afl",
                    help="root holding <campaign>/hangs/<id> (default: findings_afl)")
    ap.add_argument("out_dir", nargs="?", default="afl_hang_triage",
                    help="output directory (default: afl_hang_triage)")
    ap.add_argument("--threads", "-j", type=int, default=max(1, (os.cpu_count() or 4) // 2),
                    help="parallel workers (default: half of nproc, since each worker "
                         "spawns solc + perf which compete for CPU)")
    ap.add_argument("--per-config-timeout", type=int,
                    default=DEFAULT_PER_CONFIG_TIMEOUT_S,
                    help="per-solc-config timeout in seconds (passed to "
                         "sol_debug_runner --timeout). Default: %(default)d.")
    ap.add_argument("--outer-timeout", type=int, default=DEFAULT_OUTER_TIMEOUT_S,
                    help="wall-clock timeout per sol_debug_runner invocation (seconds). "
                         "Default: %(default)d.")
    ap.add_argument("--limit", type=int, default=0,
                    help="process at most this many hangs (0 = all)")
    ap.add_argument("--top-n", type=int, default=100,
                    help="rows to print in the ranked summary tables (default 100)")
    args = ap.parse_args()

    findings_root = Path(args.findings_root)
    out_dir = Path(args.out_dir)

    if not (DEBUG_RUNNER.is_file() and os.access(DEBUG_RUNNER, os.X_OK)):
        print(f"missing or not executable: {DEBUG_RUNNER}", file=sys.stderr)
        return 2
    if not findings_root.is_dir():
        print(f"findings_root not a directory: {findings_root}", file=sys.stderr)
        return 2

    (out_dir / "logs").mkdir(parents=True, exist_ok=True)
    (out_dir / "sources").mkdir(parents=True, exist_ok=True)

    hangs = find_hangs(findings_root)
    if args.limit:
        hangs = hangs[: args.limit]
    total = len(hangs)
    print(f"Found {total} hangs under {findings_root}", file=sys.stderr)
    print(f"  threads={args.threads}  per-config-timeout={args.per_config_timeout}s  "
          f"outer-timeout={args.outer_timeout}s", file=sys.stderr)

    tsv_path = out_dir / "per_hang.tsv"
    rows: list[dict] = []
    print_lock = threading.Lock()
    completed = 0
    with tsv_path.open("w") as tsv:
        tsv.write("\t".join(HEADER) + "\n")
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            futs = {ex.submit(process_one, h, out_dir,
                              args.per_config_timeout, args.outer_timeout): h
                    for h in hangs}
            for fut in as_completed(futs):
                r = fut.result()
                with print_lock:
                    completed += 1
                    rows.append(r)
                    tsv.write("\t".join(str(r.get(h, "")) for h in HEADER) + "\n")
                    tsv.flush()
                    print(
                        f"[{completed}/{total}] {r['campaign']}/{r['hang']}  "
                        f"total={r['total_ms']}ms  max={r['max_ms']}ms"
                        f"@{r['max_label']}  tos={r['timeouts']}",
                        file=sys.stderr, flush=True,
                    )

    write_summary(out_dir, rows, args.per_config_timeout, args.top_n)

    print(f"\nPer-hang TSV: {tsv_path}", file=sys.stderr)
    print(f"Summary:      {out_dir / 'by_runtime.txt'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
