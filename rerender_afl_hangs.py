#!/usr/bin/env python3
"""Re-render afl_hang_triage/by_runtime.txt from the existing per_hang.tsv
without re-running sol_debug_runner.

Use this when the sweep is already done and you just want a different --top-n
or to inject the full path column into the summary (older TSVs predate that
column; we reconstruct it from <findings_root>/<campaign>/hangs/<hang>).
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from run_afl_hangs import CONFIG_LABELS, write_summary


def load_rows(tsv_path: Path, findings_root: Path) -> list[dict]:
    with tsv_path.open() as fh:
        reader = csv.DictReader(fh, delimiter="\t")
        rows = list(reader)

    findings_abs = findings_root.resolve()
    for r in rows:
        # Coerce numeric fields the summary code needs as ints. Empty strings
        # (config not measured) stay as "" so fmt_ms shows them as "—".
        for k in ("total_ms", "max_ms", "timeouts", "measured_configs"):
            r[k] = int(r.get(k) or 0)
        for label in CONFIG_LABELS:
            ms_k, to_k = f"{label}_ms", f"{label}_to"
            ms = r.get(ms_k, "")
            r[ms_k] = int(ms) if ms not in ("", None) else ""
            to = r.get(to_k, "")
            r[to_k] = int(to) if to not in ("", None) else ""
        # Reconstruct the absolute path the new write_summary expects.
        if not r.get("path"):
            r["path"] = str(findings_abs / r["campaign"] / "hangs" / r["hang"])
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tsv", default="afl_hang_triage/per_hang.tsv")
    ap.add_argument("--out-dir", default="afl_hang_triage",
                    help="where to write by_runtime.txt (default: %(default)s)")
    ap.add_argument("--findings-root", default="findings_afl",
                    help="used to reconstruct full hang paths if TSV lacks 'path'")
    ap.add_argument("--per-config-timeout", type=int, default=20,
                    help="value the original sweep used (only affects the header line "
                         "and the TIMED-OUT sentinel in fmt). Default: %(default)d.")
    ap.add_argument("--top-n", type=int, default=0,
                    help="rows per ranked section. 0 = print all. Default: %(default)d.")
    args = ap.parse_args()

    tsv_path = Path(args.tsv)
    out_dir = Path(args.out_dir)
    findings_root = Path(args.findings_root)
    if not tsv_path.is_file():
        print(f"TSV not found: {tsv_path}", file=sys.stderr)
        return 2
    if not out_dir.is_dir():
        print(f"out_dir not a directory: {out_dir}", file=sys.stderr)
        return 2

    rows = load_rows(tsv_path, findings_root)
    # write_summary slices [:top_n] and also prints "Top {top_n}" in the
    # header — pass len(rows) when "all" is requested so the header reads
    # correctly.
    top_n = args.top_n if args.top_n > 0 else len(rows)
    write_summary(out_dir, rows, args.per_config_timeout, top_n)
    print(f"Re-rendered {out_dir / 'by_runtime.txt'} "
          f"({len(rows)} rows, top_n={'ALL' if args.top_n == 0 else args.top_n})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
