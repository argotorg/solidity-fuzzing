#!/usr/bin/env python3
"""Categorize ice_crash/*.out files by the throwing site, skipping FixedPointType cases."""

import re
from collections import defaultdict
from pathlib import Path

ICE_DIR = Path(__file__).parent / "ice_crash"

# Lines look like:
#   /solidity/libsolidity/analysis/TypeChecker.cpp(2378): Throw in function <signature>
LOC_RE = re.compile(r"^(?P<file>/?\S+\.(?:cpp|h))\((?P<line>\d+)\): Throw in function (?P<func>.*)$")

def short_func(sig: str) -> str:
    """Strip namespace noise so categories stay readable."""
    sig = sig.strip()
    # drop trailing "const" / "noexcept" qualifiers
    sig = re.sub(r"\s+const\s*$", "", sig)
    # try to extract just "ClassName::method" or "method"
    m = re.search(r"([A-Za-z_][\w:]*)\s*\(", sig)
    name = m.group(1) if m else sig
    # collapse leading namespaces solidity::frontend::Foo::bar -> Foo::bar
    parts = name.split("::")
    if len(parts) >= 2:
        name = "::".join(parts[-2:])
    return name

def parse(out_path: Path):
    text = out_path.read_text(errors="replace")
    if "FixedPointType not implemented" in text:
        return None  # caller filters these
    if "Internal compiler error" not in text:
        # No ICE — likely just warnings or a normal compile error.
        return ("(no ICE: warnings/error only)", "", "")
    if "Solidity assertion failed" not in text:
        return ("(ICE without 'Solidity assertion failed')", "", out_path.name)
    for line in text.splitlines():
        m = LOC_RE.search(line)
        if m:
            return (m.group("file"), m.group("line"), short_func(m.group("func")))
    return ("(ICE, location unparsed)", "", out_path.name)

def main():
    files = sorted(ICE_DIR.glob("crash-*.out"))
    total = len(files)
    skipped_fpt = 0
    buckets: dict[tuple, list[str]] = defaultdict(list)

    for f in files:
        rec = parse(f)
        if rec is None:
            skipped_fpt += 1
            continue
        key = (rec[0], rec[1], rec[2])
        buckets[key].append(f.stem)

    print(f"# total .out files:           {total}")
    print(f"# skipped (FixedPointType):   {skipped_fpt}")
    print(f"# remaining (assert / other): {total - skipped_fpt}")
    print(f"# distinct throw sites:       {len(buckets)}")
    print()

    # Sort by count desc
    rows = sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0]))

    print(f"{'count':>6}  {'file':<55} {'line':>5}  function")
    print("-" * 110)
    for (file, line, func), members in rows:
        # trim file to last 2 path segments for table compactness
        short = "/".join(file.rsplit("/", 2)[-2:]) if "/" in file else file
        print(f"{len(members):>6}  {short:<55} {line:>5}  {func}")

    # Also dump example crash hash per bucket so user can pick reproducers
    print()
    print("# example crash per bucket (first one alphabetically):")
    for (file, line, func), members in rows:
        short = "/".join(file.rsplit("/", 2)[-2:])
        print(f"  {short}:{line}  {func:<45}  -> {sorted(members)[0]}")

if __name__ == "__main__":
    main()
