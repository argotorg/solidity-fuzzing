#!/usr/bin/env python3
"""Replay AFL crashes through sol_afl_diff_runner and sol_debug_runner --afl.

Walks <findings_root>/*/crashes/* (default findings_root=findings_afl). For each
crash file (raw AFL input, possibly carrying the [src][calldata][lenLE][0xCA 0xFE]
trailer used by the AFL diff harness):

  1. Runs sol_afl_diff_runner <crash>
       - The crash itself is *expected*: any solAssert in the harness throws
         InternalCompilerError, std::terminate raises SIGABRT, AFL records it.
       - Captures exit code, signal, stderr (assertion message identifies the
         differential bucket: status / output / logs / storage / tstorage /
         revert data, or "(other)").
       - A negative return code < -1 means the runner died on a signal (e.g.
         -6 SIGABRT, -11 SIGSEGV) — distinguishes assertion-driven diffs from
         genuine memory-safety crashes inside solc.

  2. Runs sol_debug_runner --afl --quiet <crash>
       - Cross-checks via the multi-config debug runner.
       - Exit 0=match / 1=MISMATCH / 2=COMPILATION_FAILED / 3=INTERNAL_ERROR.

  3. Splits the crash into [source, calldata] using the same 0xCA 0xFE trailer
     logic as the C++ harness, writes the .sol for human review.

Outputs:
  <out_dir>/per_crash.tsv         one row per crash
  <out_dir>/by_category.txt       grouped counts + samples
  <out_dir>/logs/<key>.diff.log   raw sol_afl_diff_runner stderr+stdout
  <out_dir>/logs/<key>.debug.log  raw sol_debug_runner stderr+stdout
  <out_dir>/sources/<key>.sol     extracted source slice (for human inspection)
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DIFF_RUNNER = Path("./build/tools/afl/sol_afl_diff_runner").resolve()
DEBUG_RUNNER = Path("./build/tools/runners/sol_debug_runner").resolve()

# Per-config solc timeout passed to sol_debug_runner --timeout. The AFL
# diff_runner has no built-in timeout; we wall-clock it from outside.
DEFAULT_PER_CONFIG_TIMEOUT_S = 30
DEFAULT_OUTER_TIMEOUT_S = 180

# Diff-runner assertion buckets. solAssert(...) message format is:
#   "Sol AFL diff fuzzer: <bucket>"
# See tools/afl/sol_afl_diff_runner.cpp.
DIFF_ASSERT_BUCKETS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"status code differs"), "diff:status"),
    (re.compile(r"output differs"),       "diff:output"),
    (re.compile(r"logs differ"),          "diff:logs"),
    (re.compile(r"transient storage differs"), "diff:tstorage"),
    (re.compile(r"storage differs"),      "diff:storage"),
    (re.compile(r"revert data differs"),  "diff:revert"),
]

# Common solc-internal assertion / exception strings for further sub-bucketing
# when the AFL harness's own solAssert was NOT the trigger (e.g. solidity
# itself ICEd before the diff check ran).
INTERNAL_ASSERT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"std::bad_alloc"),                "std::bad_alloc"),
    (re.compile(r"std::bad_cast"),                 "std::bad_cast"),
    (re.compile(r"std::bad_function_call"),        "std::bad_function_call"),
    (re.compile(r"std::out_of_range"),             "std::out_of_range"),
    (re.compile(r"std::length_error"),             "std::length_error"),
    (re.compile(r"std::regex_error"),              "std::regex_error"),
    (re.compile(r"std::system_error"),             "std::system_error"),
    (re.compile(r"std::logic_error"),              "std::logic_error"),
    (re.compile(r"InternalCompilerError"),         "ice:internal-compiler-error"),
    (re.compile(r"UnimplementedFeatureError"),     "ice:unimplemented-feature"),
    (re.compile(r"StackTooDeep"),                  "ice:stack-too-deep"),
    (re.compile(r"YulException|YulAssertion"),     "ice:yul-assertion"),
    (re.compile(r"solAssert"),                     "ice:solAssert"),
    (re.compile(r"Assertion .* failed"),           "ice:libc-assert"),
]


def split_afl_input(data: bytes) -> tuple[bytes, bytes]:
    """Mirror sol_afl_diff_runner.cpp::splitInput in Python.

    Returns (source_bytes, calldata_bytes). When no magic trailer is present,
    the whole file is treated as source and calldata is left empty (we do not
    need to recompute keccak — the source alone is what humans review).
    """
    if len(data) >= 4 and data[-2] == 0xCA and data[-1] == 0xFE:
        src_len = data[-4] | (data[-3] << 8)
        if src_len <= len(data) - 4:
            return data[:src_len], data[src_len:-4]
    return data, b""


def safe_key(campaign: str, crash_name: str) -> str:
    """Filesystem-safe key for log/source filenames."""
    return f"{campaign}__{re.sub(r'[^A-Za-z0-9._-]+', '_', crash_name)}"


def parse_diff_runner_outcome(rc: int, output: str) -> tuple[str, str]:
    """Categorize the diff-runner result.

    Returns (category, detail). Category is one of:
      crash:abort:diff:<bucket>   solAssert in the AFL harness -> differential
      crash:abort:ice:<sub>       solidity-internal assertion (ICE in either
                                  config that escaped runOnce's catch list)
      crash:abort:other           SIGABRT but no recognised message
      crash:segv                  SIGSEGV / SIGBUS / SIGFPE — memory-safety bug
      crash:signal:<n>            other signal
      timeout                     wall-clock timeout
      ok                          rc == 0, no diff (likely no longer reproduces)
      other:rc=<n>                non-zero exit without a signal
    """
    if rc == "TIMEOUT":  # type: ignore[comparison-overlap]
        return "timeout", "wall-clock timeout"
    # subprocess returns negative rc for terminate-by-signal on POSIX.
    if isinstance(rc, int) and rc < 0:
        sig = -rc
        if sig == 6:  # SIGABRT
            for pat, bucket in DIFF_ASSERT_BUCKETS:
                if pat.search(output):
                    return f"crash:abort:{bucket}", pat.pattern
            for pat, sub in INTERNAL_ASSERT_PATTERNS:
                if pat.search(output):
                    return f"crash:abort:{sub}", pat.pattern
            return "crash:abort:other", "SIGABRT, unrecognised message"
        if sig in (11, 7, 8):  # SEGV / BUS / FPE
            sig_name = {11: "SIGSEGV", 7: "SIGBUS", 8: "SIGFPE"}[sig]
            return "crash:segv", sig_name
        return f"crash:signal:{sig}", f"signal {sig}"
    if isinstance(rc, int) and rc == 0:
        return "ok", "rc=0 (no longer reproduces?)"
    return f"other:rc={rc}", f"non-zero exit without signal"


# sol_debug_runner --quiet emits one summary line; capture it verbatim.
DEBUG_SUMMARY_RE = re.compile(r"^(MATCH|MISMATCH|COMPILATION_FAILED|INTERNAL_ERROR)\b.*$",
                               re.MULTILINE)


def parse_debug_runner_outcome(rc: int, output: str) -> tuple[str, str]:
    """Map sol_debug_runner --afl --quiet exit code to a category."""
    if rc == "TIMEOUT":  # type: ignore[comparison-overlap]
        return "debug:timeout", "wall-clock timeout"
    if isinstance(rc, int) and rc < 0:
        return f"debug:signal:{-rc}", f"sol_debug_runner died on signal {-rc}"
    summary = ""
    m = DEBUG_SUMMARY_RE.search(output or "")
    if m:
        summary = m.group(0).strip()
    mapping = {
        0: "debug:match",
        1: "debug:mismatch",
        2: "debug:compile-failed",
        3: "debug:internal-error",
    }
    return mapping.get(rc, f"debug:rc={rc}"), summary or f"rc={rc}"


def find_crashes(findings_root: Path) -> list[Path]:
    """Find AFL crash files: <root>/*/crashes/id:* (skip README and .* files)."""
    out: list[Path] = []
    for d in sorted(findings_root.glob("*/crashes")):
        for f in sorted(d.iterdir()):
            if f.is_file() and f.name.startswith("id:"):
                out.append(f)
    return out


def run_with_timeout(cmd: list[str], timeout_s: int) -> tuple[int | str, str]:
    """Run a subprocess; return (returncode_or_'TIMEOUT', combined_output)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout_s, check=False,
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


def process_one(crash: Path, out_dir: Path, per_config_timeout: int,
                outer_timeout: int) -> dict:
    campaign = crash.parent.parent.name
    key = safe_key(campaign, crash.name)

    # Save split source for human review.
    raw = crash.read_bytes()
    src, calldata = split_afl_input(raw)
    src_path = out_dir / "sources" / f"{key}.sol"
    try:
        src_path.write_bytes(src)
    except OSError:
        pass

    # 1. Diff runner — this is the one AFL ran when it found the crash.
    diff_rc, diff_out = run_with_timeout([str(DIFF_RUNNER), str(crash)], outer_timeout)
    (out_dir / "logs" / f"{key}.diff.log").write_text(diff_out)
    diff_cat, diff_detail = parse_diff_runner_outcome(diff_rc, diff_out)

    # 2. Debug runner — multi-config cross-check.
    debug_cmd = [str(DEBUG_RUNNER), "--afl", "--quiet", str(crash)]
    if per_config_timeout > 0:
        debug_cmd += ["--timeout", str(per_config_timeout)]
    debug_rc, debug_out = run_with_timeout(debug_cmd, outer_timeout)
    (out_dir / "logs" / f"{key}.debug.log").write_text(debug_out)
    debug_cat, debug_detail = parse_debug_runner_outcome(debug_rc, debug_out)

    return {
        "campaign": campaign,
        "crash": crash.name,
        "key": key,
        "size": len(raw),
        "src_size": len(src),
        "calldata_size": len(calldata),
        "has_magic": int(len(raw) >= 2 and raw[-2:] == b"\xca\xfe"),
        "diff_rc": str(diff_rc),
        "diff_cat": diff_cat,
        "diff_detail": diff_detail.replace("\t", " ").replace("\n", " ")[:200],
        "debug_rc": str(debug_rc),
        "debug_cat": debug_cat,
        "debug_detail": debug_detail.replace("\t", " ").replace("\n", " ")[:200],
    }


HEADER = (
    "campaign", "crash", "size", "src_size", "calldata_size", "has_magic",
    "diff_rc", "diff_cat", "diff_detail",
    "debug_rc", "debug_cat", "debug_detail",
)


def write_summary(out_dir: Path, rows: list[dict]) -> None:
    counts: dict[str, int] = {}
    by_cat: dict[str, list[dict]] = {}
    for r in rows:
        # Joint category — the diff runner's verdict is primary; the debug
        # runner's verdict is appended for cross-check.
        cat = r["diff_cat"]
        counts[cat] = counts.get(cat, 0) + 1
        by_cat.setdefault(cat, []).append(r)

    debug_counts: dict[str, int] = {}
    for r in rows:
        debug_counts[r["debug_cat"]] = debug_counts.get(r["debug_cat"], 0) + 1

    cross: dict[tuple[str, str], int] = {}
    for r in rows:
        k = (r["diff_cat"], r["debug_cat"])
        cross[k] = cross.get(k, 0) + 1

    out = out_dir / "by_category.txt"
    with out.open("w") as fh:
        fh.write("# AFL crash triage summary\n\n")
        fh.write(f"Total crashes processed: {len(rows)}\n\n")

        fh.write("## sol_afl_diff_runner verdict (primary)\n")
        for cat, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            fh.write(f"  {n:4d}  {cat}\n")
        fh.write("\n")

        fh.write("## sol_debug_runner --afl verdict (cross-check)\n")
        for cat, n in sorted(debug_counts.items(), key=lambda kv: -kv[1]):
            fh.write(f"  {n:4d}  {cat}\n")
        fh.write("\n")

        fh.write("## Cross-tab (diff_cat x debug_cat)\n")
        for (a, b), n in sorted(cross.items(), key=lambda kv: -kv[1]):
            fh.write(f"  {n:4d}  {a:40s} | {b}\n")
        fh.write("\n")

        fh.write("## Per-category samples (up to 10 each)\n")
        for cat in sorted(by_cat):
            fh.write(f"\n### {cat}  ({counts[cat]})\n")
            for r in by_cat[cat][:10]:
                fh.write(
                    f"  {r['campaign']} / {r['crash']}\n"
                    f"      diff:  {r['diff_cat']:30s} {r['diff_detail']}\n"
                    f"      debug: {r['debug_cat']:30s} {r['debug_detail']}\n"
                    f"      sizes: total={r['size']} src={r['src_size']} "
                    f"calldata={r['calldata_size']} magic={r['has_magic']}\n"
                )


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings_root", nargs="?", default="findings_afl",
                    help="root holding <campaign>/crashes/<id> (default: findings_afl)")
    ap.add_argument("out_dir", nargs="?", default="afl_crash_triage",
                    help="output directory (default: afl_crash_triage)")
    ap.add_argument("--threads", "-j", type=int, default=os.cpu_count() or 1,
                    help="parallel workers (default: %(default)d)")
    ap.add_argument("--per-config-timeout", type=int,
                    default=DEFAULT_PER_CONFIG_TIMEOUT_S,
                    help="per-solc-config timeout in seconds (passed to "
                         "sol_debug_runner --timeout). 0 disables.")
    ap.add_argument("--outer-timeout", type=int, default=DEFAULT_OUTER_TIMEOUT_S,
                    help="wall-clock timeout per binary invocation (seconds)")
    ap.add_argument("--limit", type=int, default=0,
                    help="process at most this many crashes (0 = all)")
    args = ap.parse_args()

    findings_root = Path(args.findings_root)
    out_dir = Path(args.out_dir)

    for p in (DIFF_RUNNER, DEBUG_RUNNER):
        if not (p.is_file() and os.access(p, os.X_OK)):
            print(f"missing or not executable: {p}", file=sys.stderr)
            return 2
    if not findings_root.is_dir():
        print(f"findings_root not a directory: {findings_root}", file=sys.stderr)
        return 2

    (out_dir / "logs").mkdir(parents=True, exist_ok=True)
    (out_dir / "sources").mkdir(parents=True, exist_ok=True)

    crashes = find_crashes(findings_root)
    if args.limit:
        crashes = crashes[: args.limit]
    total = len(crashes)
    print(f"Found {total} crashes under {findings_root}", file=sys.stderr)

    tsv_path = out_dir / "per_crash.tsv"
    rows: list[dict] = []
    print_lock = threading.Lock()
    completed = 0
    with tsv_path.open("w") as tsv:
        tsv.write("\t".join(HEADER) + "\n")
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            futs = {ex.submit(process_one, c, out_dir,
                              args.per_config_timeout, args.outer_timeout): c
                    for c in crashes}
            for fut in as_completed(futs):
                r = fut.result()
                with print_lock:
                    completed += 1
                    rows.append(r)
                    tsv.write("\t".join(str(r[h]) for h in HEADER) + "\n")
                    tsv.flush()
                    print(f"[{completed}/{total}] {r['campaign']}/{r['crash']}  "
                          f"diff={r['diff_cat']}  debug={r['debug_cat']}",
                          file=sys.stderr, flush=True)

    write_summary(out_dir, rows)

    print(f"\nPer-crash TSV: {tsv_path}", file=sys.stderr)
    print(f"Summary:       {out_dir / 'by_category.txt'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
