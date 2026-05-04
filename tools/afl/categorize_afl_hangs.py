#!/usr/bin/env python3
"""Replay every AFL hang through sol_debug_runner --afl --verbose and bucket
each by per-config timing + the hottest non-trivial perf symbol.

Walks <findings_root>/*/hangs/* (default findings_root=findings_afl). For each
hang:

  1. Runs sol_debug_runner --afl --verbose <hang>
  2. Parses the per-config "Time: <ms>" lines
  3. Reads the perf_top50.txt of the slowest config and picks the first
     non-trivial symbol
  4. Maps that symbol to a coarse category (SMT, Optimizer:*, IRGen, CodeGen,
     Parser, Analysis, Assembly, Other)
  5. Removes the per-run sol_debug_output-* directory so the disk does not
     fill up

Outputs:
  <out_dir>/per_hang.tsv       one row per hang
  <out_dir>/by_category.txt    counts + sample hangs per category
  <out_dir>/logs/*.log         raw runner output for each hang
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

CONFIGS = [
    "noOpt_viaIR=true",
    "opt_viaIR=true",
    "noOpt_viaIR=false",
    "opt_viaIR=false",
    "opt_ssaCFG",
]

# (regex, category). First match wins. Patterns are searched against the raw
# perf-top symbol string.
CATEGORY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"smtutil::|::BMC::|::CHC::|SMTEncoder|z3::|libz3"), "SMT"),
    (re.compile(r"CommonSubexpressionEliminator"), "Optimizer:CSE"),
    (re.compile(r"ExpressionSimplifier"), "Optimizer:ExpressionSimplifier"),
    (re.compile(r"LoadResolver|UnusedStoreEliminator|EqualStoreEliminator"), "Optimizer:LoadStore"),
    (re.compile(r"FullInliner|ExpressionInliner"), "Optimizer:Inliner"),
    (re.compile(r"DataFlowAnalyzer"), "Optimizer:DataFlowAnalyzer"),
    (re.compile(r"SSATransform|SSAReverser"), "Optimizer:SSA"),
    (re.compile(r"StackCompressor|StackLayoutGenerator|StackLayout|OptimizedCodeTransform|StackToMemoryMover|StackLimitEvader|yul::Multiplicity|combineStack"), "Optimizer:Stack"),
    (re.compile(r"yul::optimiser|OptimiserSuite|yul::Pass"), "Optimizer:Other"),
    (re.compile(r"IRGenerator|IRGenerationContext"), "IRGen"),
    (re.compile(r"ContractCompiler|ExpressionCompiler|::Compiler::"), "CodeGen"),
    (re.compile(r"Parser::|Scanner"), "Parser"),
    (re.compile(r"TypeChecker|ReferencesResolver|NameAndTypeResolver|ViewPureChecker|DeclarationContainer"), "Analysis"),
    (re.compile(r"evmasm::|::Assembly"), "Assembly"),
]

# Generic frames that show up at the top of every flat profile. We skip these
# both when looking for "hottest by self %" and when scanning the inclusive-%
# list, because they wrap *every* compile and tell us nothing about why this
# particular input was slow.
SYMBOL_SKIP = re.compile(
    r"^(?:__libc_start_main(?:_impl)?(?: \(inlined\))?|_start|main"
    r"|call_init(?: \(inlined\))?|0x[0-9a-f]+|\[unknown\])$"
    r"|^solidity::frontend::CommandLineInterface::"
    r"|^solidity::frontend::CompilerStack::(?:compile|processInput|analyze|parse"
    r"|importASTs|link|prepareOutput|generateIR)\b"
    r"|^solidity::yul::YulStack::(?:optimize|assemble|parseAndAnalyze)\b"
    r"|^solidity::yul::ObjectOptimizer::optimize\b"
    r"|^solidity::yul::OptimiserSuite::run(?:Sequence)?\b"
    r"|^std::|^boost::"
)


def parse_perf_top(path: Path) -> str:
    """Return the most informative hot symbol in a perf_top50 file, or ''.

    The runner writes the file in inclusive-% order. We want where work is
    *actually* spent, so we re-rank by self %% (column 2) and skip wrapper
    frames that bracket every solc invocation. If nothing survives the skip
    list, we fall back to the topmost inclusive-% entry that survives.
    """
    try:
        with path.open() as fh:
            lines = fh.readlines()
    except OSError:
        return ""
    by_self: list[tuple[float, float, str]] = []  # (self_pct, incl_pct, symbol)
    for line in lines:
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        try:
            incl = float(parts[0].rstrip("%"))
            self_pct = float(parts[1].rstrip("%"))
        except ValueError:
            continue
        sym = parts[4].rstrip("\n").strip()
        if not sym or SYMBOL_SKIP.search(sym):
            continue
        # Plain ::visit/::accept walker frames carry no info unless they're
        # SMT/optimiser-specific (those names already match category patterns).
        if re.search(r"::(?:visit|accept)\(", sym) and not re.search(
            r"SMT|BMC|CHC|optimiser|yul::|StackLayout", sym
        ):
            continue
        by_self.append((self_pct, incl, sym))
    if not by_self:
        return ""
    # Sort: highest self %% first, ties broken by inclusive %%.
    by_self.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return by_self[0][2]


def classify(symbol: str) -> str:
    if not symbol or symbol == "(none)":
        return "Unknown"
    for pat, cat in CATEGORY_PATTERNS:
        if pat.search(symbol):
            return cat
    return "Other"


TIME_RE = re.compile(r"^\s*Time:\s+(\d+)\s+ms\s*$")
RUNNING_RE = re.compile(r"^Running:\s+(.+?)\.\.\.\s*$")
OUTDIR_RE = re.compile(r"^Output directory:\s+(\S+)\s*$")


def parse_runner_log(text: str) -> tuple[dict[str, int], str | None]:
    """Return ({config_label: ms}, output_dir) parsed from runner stdout."""
    times: dict[str, int] = {}
    out_dir: str | None = None
    current: str | None = None
    for line in text.splitlines():
        m = OUTDIR_RE.match(line)
        if m:
            out_dir = m.group(1)
            continue
        m = RUNNING_RE.match(line)
        if m:
            current = m.group(1).strip()
            continue
        m = TIME_RE.match(line)
        if m and current is not None:
            times[current] = int(m.group(1))
            current = None
    return times, out_dir


def find_hangs(findings_root: Path) -> list[Path]:
    return sorted(p for p in findings_root.glob("*/hangs/*") if p.is_file())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings_root", nargs="?", default="findings_afl",
                    help="root holding <campaign>/hangs/<id> (default: findings_afl)")
    ap.add_argument("out_dir", nargs="?", default="hang_triage",
                    help="output directory (default: hang_triage)")
    ap.add_argument("--runner", default="./build/tools/runners/sol_debug_runner",
                    help="path to sol_debug_runner binary")
    ap.add_argument("--per-config-timeout", type=int, default=10,
                    help="per-config solc timeout in seconds (passed as runner "
                         "--timeout). 0 disables.")
    ap.add_argument("--limit", type=int, default=0,
                    help="process at most this many hangs (0 = all)")
    ap.add_argument("--keep-output-dirs", action="store_true",
                    help="do not delete sol_debug_output-* dirs after parsing")
    ap.add_argument("--reclassify", action="store_true",
                    help="skip the runner; just re-classify symbols from an existing per_hang.tsv "
                         "in <out_dir> and rewrite by_category.txt")
    args = ap.parse_args()

    findings_root = Path(args.findings_root)
    out_dir = Path(args.out_dir)
    runner = Path(args.runner)

    if not runner.is_file() or not os.access(runner, os.X_OK):
        print(f"runner not executable: {runner}", file=sys.stderr)
        return 2
    if not findings_root.is_dir():
        print(f"findings_root not a directory: {findings_root}", file=sys.stderr)
        return 2

    log_dir = out_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    tsv_path = out_dir / "per_hang.tsv"

    if args.reclassify:
        if not tsv_path.is_file():
            print(f"reclassify: missing {tsv_path}", file=sys.stderr)
            return 2
        rows: list[tuple[str, ...]] = []
        with tsv_path.open() as fh:
            header_line = fh.readline()  # header
            for raw in fh:
                cols = raw.rstrip("\n").split("\t")
                if len(cols) < 11:
                    continue
                cols[10] = classify(cols[9])
                rows.append(tuple(cols))
        with tsv_path.open("w") as fh:
            fh.write(header_line)
            for r in rows:
                fh.write("\t".join(r) + "\n")
        write_summary(out_dir, rows)
        print(f"Reclassified {len(rows)} rows.", file=sys.stderr)
        return 0

    hangs = find_hangs(findings_root)
    if args.limit:
        hangs = hangs[: args.limit]
    print(f"Found {len(hangs)} hang files under {findings_root}", file=sys.stderr)

    header = (
        "campaign", "hang",
        "t_noOpt_viaIR_true", "t_opt_viaIR_true",
        "t_noOpt_viaIR_false", "t_opt_viaIR_false",
        "t_opt_ssaCFG",
        "slowest_config", "slowest_ms",
        "top_symbol", "category",
    )

    rows: list[tuple[str, ...]] = []
    with tsv_path.open("w") as tsv:
        tsv.write("\t".join(header) + "\n")
        for i, hang in enumerate(hangs, 1):
            campaign = hang.parent.parent.name
            hang_id = hang.name
            print(f"[{i}/{len(hangs)}] {campaign} / {hang_id}", file=sys.stderr, flush=True)

            log_path = log_dir / f"{campaign}__{hang_id.replace('/', '_')}.log"
            cmd = [str(runner), "--afl", "--verbose", str(hang)]
            if args.per_config_timeout > 0:
                cmd += ["--timeout", str(args.per_config_timeout)]
            # Cap the wall-clock outer timeout generously above N*5 to allow
            # for perf-record overhead per config.
            outer_timeout = max(600, args.per_config_timeout * 30)
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=outer_timeout,
                )
                stdout = proc.stdout + proc.stderr
            except subprocess.TimeoutExpired as e:
                def _to_text(v: object) -> str:
                    if v is None:
                        return ""
                    if isinstance(v, bytes):
                        return v.decode("utf-8", errors="replace")
                    return str(v)
                stdout = _to_text(e.stdout) + _to_text(e.stderr) + f"\n[OUTER TIMEOUT >{outer_timeout}s]\n"
            log_path.write_text(stdout)

            times, run_out_dir = parse_runner_log(stdout)
            t_vals = [str(times.get(c, "NA")) for c in CONFIGS]

            slowest_cfg = "NA"
            slowest_ms = -1
            for cfg in CONFIGS:
                v = times.get(cfg)
                if v is not None and v > slowest_ms:
                    slowest_ms = v
                    slowest_cfg = cfg
            slowest_ms_str = str(slowest_ms) if slowest_ms >= 0 else "NA"

            top_sym = ""
            category = "Unknown"
            if run_out_dir and slowest_cfg != "NA":
                perf = Path(run_out_dir) / f"{slowest_cfg}.perf_top50.txt"
                if perf.is_file():
                    top_sym = parse_perf_top(perf)
                    category = classify(top_sym)
                if not args.keep_output_dirs and Path(run_out_dir).is_dir():
                    shutil.rmtree(run_out_dir, ignore_errors=True)
            # If the slowest config hit (or got within 100 ms of) the configured
            # per-config timeout and we couldn't extract a meaningful symbol,
            # call it "TimedOut" — that's strictly more informative than
            # "Unknown" and is what the user wants to see for these.
            if (
                args.per_config_timeout > 0
                and slowest_ms >= args.per_config_timeout * 1000 - 100
                and category in ("Unknown", "Other")
            ):
                category = "TimedOut"

            row = (campaign, hang_id, *t_vals, slowest_cfg, slowest_ms_str,
                   top_sym or "(none)", category)
            tsv.write("\t".join(s.replace("\t", " ") for s in row) + "\n")
            tsv.flush()
            rows.append(row)

    write_summary(out_dir, rows)

    print(f"\nPer-hang TSV: {tsv_path}", file=sys.stderr)
    print(f"Summary:      {out_dir / 'by_category.txt'}", file=sys.stderr)
    return 0


def write_summary(out_dir: Path, rows: list[tuple[str, ...]]) -> None:
    summary_path = out_dir / "by_category.txt"
    counts: dict[str, int] = {}
    by_cat: dict[str, list[tuple[str, ...]]] = {}
    for row in rows:
        cat = row[-1]
        counts[cat] = counts.get(cat, 0) + 1
        by_cat.setdefault(cat, []).append(row)

    with summary_path.open("w") as out:
        out.write("# Hangs grouped by category (slowest config + top non-trivial symbol)\n\n")
        for cat, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            out.write(f"{n:5d}  {cat}\n")
        out.write("\n# Per-category sample (campaign / hang / slowest_cfg / ms / symbol)\n")
        for cat in sorted(by_cat):
            out.write(f"\n## {cat}  ({counts[cat]})\n")
            for row in by_cat[cat][:10]:
                out.write(f"  {row[0]} / {row[1]}  [{row[7]}, {row[8]} ms]  {row[9]}\n")


if __name__ == "__main__":
    sys.exit(main())
