#!/usr/bin/env python3
"""Replay a libFuzzer crash dir through the matching debug runner.

Works for every differential proto fuzzer — both the sol family
(sol_debug_runner) and the yul family (yul_debug_runner):

    sol_proto_ossfuzz_evmone[_viair]
    yul_proto_ossfuzz_evmone[_ssacfg|_no_ssa|_check_stack_alloc]
    yul_proto_ossfuzz_evmone_single_pass_<c S L M s r D>

For each crash-<hash> file in the crash dir:

  1. Dump the protobuf to <crash>.sol / <crash>.yul via the fuzzer binary,
     capturing its replay stderr to <crash>.dump.txt. That stderr carries the
     *actual* difference the fuzzer found, e.g.
        ...InternalCompilerError>: Sol proto2 fuzzer (viaIR mode): storage differs
     (yul fuzzers also dump the optimizer sequence to <crash>.seq).
  2. Re-run it through the host debug runner in --quiet mode (fast: no perf /
     flamegraph) to get an independent verdict + exit code, saved to <crash>.out.

Then print ONE ROW PER CRASH (not grouped / not aggregated): the runner verdict,
its exit code, whether the host build reproduced the fuzzer's crash, and the
fuzzer's own difference message.

The fuzzer binary is inferred from the crash-dir name by stripping a leading
"NNN-" prefix (so `488-sol_proto_ossfuzz_evmone_viair` -> that binary); override
with --fuzzer. Exit-code meanings (both runners):
  0 = all match   1 = mismatch (differential bug)
  2 = compile fail 3 = internal compiler error
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

OSSFUZZ_DIR = Path("./build_ossfuzz/tools/ossfuzz")
SOL_RUNNER = Path("./build/tools/runners/sol_debug_runner").resolve()
YUL_RUNNER = Path("./build/tools/runners/yul_debug_runner").resolve()

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# rc -> short verdict; both runners share this scheme (see --help / CLAUDE.md).
VERDICT = {0: "OK", 1: "MISMATCH", 2: "COMPILE_FAIL", 3: "INTERNAL_ERR"}


def verdict_for(rc):
    if rc is None:
        return "TIMEOUT"
    if rc < 0:
        return f"SIGNAL:{-rc}"
    return VERDICT.get(rc, f"rc={rc}")


def extract_message(dump_text: str) -> str:
    """Pull the single most informative line out of the fuzzer's replay stderr —
    the what() of the uncaught exception that made libFuzzer save the crash."""
    text = ANSI_RE.sub("", dump_text)
    # 1. The canonical libc++ terminate line: "...of type <TYPE>: <what>".
    #    TYPE contains "::" (no space); the type/message separator is ": "
    #    (colon + whitespace), so split on the first one after "of type ".
    m = re.search(r"uncaught exception of type (.+)", text)
    if m:
        rest = m.group(1)
        sep = re.search(r":\s", rest)
        if sep:
            return rest[sep.end():].strip()
        return rest.strip()
    # 2. Sanitizer reports (ASan/MSan/UBSan) and libFuzzer's own diagnostics.
    m = re.search(r"==\d+==\s*ERROR:\s*(.+)", text)
    if m:
        return m.group(1).strip()
    m = re.search(r"SUMMARY:\s*(.+)", text)
    if m:
        return m.group(1).strip()
    # 3. Fall back to the last non-empty line.
    for line in reversed(text.splitlines()):
        if line.strip():
            return line.strip()
    return "(no message)"


def parse_seq(seq_path: Path):
    """Return (sequence, cleanup) from a yul .seq dump, or (None, None)."""
    seq = cleanup = None
    try:
        for line in seq_path.read_text().splitlines():
            if line.startswith("optimizer-sequence:"):
                seq = line.split(":", 1)[1].strip()
            elif line.startswith("optimizer-cleanup-sequence:"):
                cleanup = line.split(":", 1)[1].strip()
    except OSError:
        pass
    return seq, cleanup


def run_with_timeout(cmd, env, cwd, timeout):
    try:
        p = subprocess.run(cmd, env=env, cwd=cwd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout, check=False)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode("utf-8", "replace") if e.stdout else ""
        return None, out


def process_one(crash, family, dumper, runner, timeout, work_root):
    ext = ".sol" if family == "sol" else ".yul"
    src = (crash.parent / f"{crash.name}{ext}").resolve()
    dump_log = crash.parent / f"{crash.name}.dump.txt"
    run_out = crash.parent / f"{crash.name}.out"
    seq_path = crash.parent / f"{crash.name}.seq"
    calldata_path = crash.parent / f"{crash.name}.calldata"

    # 1. Dump. The harness writes the source then crashes on replay; the crash
    #    stderr is exactly the difference we want, so capture it.
    env = {**os.environ, "PROTO_FUZZER_DUMP_PATH": str(src)}
    if family == "yul":
        env["PROTO_FUZZER_DUMP_SEQ_PATH"] = str(seq_path)
    else:
        # The sol differential fuzzer appends proto calldata_data after the
        # test() selector; without it the runner calls test() with empty
        # calldata and input-dependent divergences (e.g. calldataload(...))
        # collapse and won't reproduce. Dump it so we can replay --calldata.
        env["PROTO_FUZZER_DUMP_CALLDATA_PATH"] = str(calldata_path)
    _, dump_text = run_with_timeout([str(dumper), str(crash)], env, None, timeout)
    dump_log.write_text(dump_text)

    if not src.is_file() or src.stat().st_size == 0:
        return dict(name=crash.name, rc=None, verdict="DUMP_FAILED",
                    detail=extract_message(dump_text), repro="-")

    detail = extract_message(dump_text)

    # 2. Replay through the host debug runner (quiet => no perf/flamegraph).
    cmd = [str(runner), "--quiet"]
    if family == "yul":
        seq, cleanup = parse_seq(seq_path)
        if seq is not None:
            cmd += ["--optimizer-sequence", seq,
                    "--optimizer-cleanup-sequence", cleanup or ""]
    else:
        # Feed the fuzzer's calldata so input-dependent paths reproduce. An
        # empty/absent file means "no extra calldata" — skip the flag then.
        calldata_hex = ""
        if calldata_path.is_file():
            calldata_hex = calldata_path.read_text().strip()
        if calldata_hex:
            cmd += ["--calldata", calldata_hex]
    cmd.append(str(src))

    with tempfile.TemporaryDirectory(dir=str(work_root)) as work:
        rc, run_text = run_with_timeout(cmd, os.environ.copy(), work, timeout)
    run_out.write_text(run_text)

    # Did the host build reproduce the fuzzer's finding? rc 1/3 = yes.
    if rc in (1, 3):
        repro = "yes"
    elif rc in (0, 2):
        repro = "NO"
    else:
        repro = "?"
    return dict(name=crash.name, rc=rc, verdict=verdict_for(rc),
                detail=detail, repro=repro)


def print_table(rows, max_detail):
    """One row per crash. No grouping, no aggregation."""
    def short(name):
        return name[6:] if name.startswith("crash-") else name

    cols = [
        ("#", lambda r, i: str(i)),
        ("crash", lambda r, i: short(r["name"])),
        ("rc", lambda r, i: "-" if r["rc"] is None else str(r["rc"])),
        ("verdict", lambda r, i: r["verdict"]),
        ("repro", lambda r, i: r.get("repro", "-")),
        ("difference (from fuzzer replay)", lambda r, i: r["detail"]),
    ]
    table = [[fn(r, i) for _, fn in cols] for i, r in enumerate(rows, 1)]
    # Truncate only the last (detail) column, and only if asked.
    if max_detail > 0:
        for row in table:
            if len(row[-1]) > max_detail:
                row[-1] = row[-1][:max_detail - 1] + "…"
    headers = [h for h, _ in cols]
    widths = [max(len(headers[c]), *(len(row[c]) for row in table)) if table
              else len(headers[c]) for c in range(len(headers))]
    # Last column is left unbounded (no padding) so long messages aren't cut.
    def fmt(cells):
        out = []
        for c, cell in enumerate(cells):
            out.append(cell if c == len(cells) - 1 else cell.ljust(widths[c]))
        return "  ".join(out)
    print(fmt(headers))
    print("  ".join("-" * widths[c] if c < len(headers) - 1
                    else "-" * len(headers[c]) for c in range(len(headers))))
    for row in table:
        print(fmt(row))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("crash_dir", help="directory of crash-<hash> files")
    ap.add_argument("--fuzzer", default=None,
                    help="ossfuzz binary name or path (default: inferred from "
                         "crash-dir name with a leading 'NNN-' stripped)")
    ap.add_argument("--runner", default=None,
                    help="override debug-runner path (default: per family)")
    ap.add_argument("--threads", "-j", type=int, default=os.cpu_count() or 1,
                    help="parallel workers (default: %(default)d)")
    ap.add_argument("--limit", type=int, default=None,
                    help="process at most this many crashes")
    ap.add_argument("--timeout", type=int, default=120,
                    help="per-step timeout in seconds (default: %(default)d)")
    ap.add_argument("--max-detail", type=int, default=0,
                    help="truncate the difference column to N chars (0 = full)")
    args = ap.parse_args()

    crash_dir = Path(args.crash_dir)
    if not crash_dir.is_dir():
        print(f"missing dir: {crash_dir}", file=sys.stderr)
        return 1

    # Infer the fuzzer binary from the crash-dir name (strip leading "NNN-").
    name = args.fuzzer or re.sub(r"^\d+-", "", crash_dir.name)
    dumper = Path(name) if "/" in name else (OSSFUZZ_DIR / name)
    dumper = dumper.resolve()
    base = dumper.name

    if base.startswith("yul_"):
        family = "yul"
    elif base.startswith("sol_"):
        family = "sol"
    else:
        print(f"cannot tell family (sol/yul) from '{base}'; pass --fuzzer",
              file=sys.stderr)
        return 1
    runner = (Path(args.runner).resolve() if args.runner
              else (SOL_RUNNER if family == "sol" else YUL_RUNNER))

    for p in (dumper, runner):
        if not (p.is_file() and os.access(p, os.X_OK)):
            print(f"missing or not executable: {p}", file=sys.stderr)
            return 1

    crashes = sorted(f for f in crash_dir.iterdir()
                     if f.is_file() and f.name.startswith("crash-")
                     and "." not in f.name)
    if args.limit is not None:
        crashes = crashes[:args.limit]
    total = len(crashes)
    threads = max(1, args.threads)

    print(f"fuzzer={base} family={family} runner={runner.name}")
    print(f"crash_dir={crash_dir} total={total} threads={threads}")
    print()

    rows = []
    lock = threading.Lock()
    done = 0
    with tempfile.TemporaryDirectory() as work_root:
        work_root_path = Path(work_root)
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(process_one, c, family, dumper, runner,
                                 args.timeout, work_root_path) for c in crashes]
            for fut in as_completed(futures):
                row = fut.result()
                rows.append(row)
                with lock:
                    done += 1
                    print(f"[{done}/{total}] {row['name'][6:]} ... "
                          f"{row['verdict']}", file=sys.stderr)

    rows.sort(key=lambda r: r["name"])
    print()
    print_table(rows, args.max_detail)

    # A small NON-aggregated footer: how many host reproductions, by verdict.
    by_verdict = {}
    for r in rows:
        by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + 1
    print()
    print("totals: " + ", ".join(f"{v}={n}" for v, n in sorted(by_verdict.items())))
    bug = sum(1 for r in rows if r["rc"] in (1, 3))
    print(f"host build reproduced a bug (rc 1/3) for {bug}/{total} crashes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
