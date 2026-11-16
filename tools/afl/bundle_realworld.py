#!/usr/bin/env python3
"""Bundle each realworld_cache/ .sol file with its transitive imports into one multi-source AFL input.

Usage: tools/afl/bundle_realworld.py [--cache realworld_cache] [--max-bytes 16384] -o corpus_rw_bundled
"""
import argparse
import hashlib
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EXCLUDE_DIRS = {".git", "node_modules", "lib", "out", "cache", "artifacts", "coverage", "typechain",
                "typechain-types", "dist", "build", "target", "certora", "echidna", "halmos"}
# Dependencies the shallow clones would get from git submodules / npm, mapped onto the other cached repos
KNOWN_REMAPPINGS = {
    "@openzeppelin/contracts/": "openzeppelin-contracts/contracts/",
    "openzeppelin-contracts/contracts/": "openzeppelin-contracts/contracts/",
    "openzeppelin/": "openzeppelin-contracts/contracts/",
    "forge-std/": "forge-std/src/",
    "solady/src/": "solady/src/",
    "solady/": "solady/src/",
    "solmate/src/": "solmate/src/",
    "solmate/": "solmate/src/",
    "@aave/core-v3/": "aave-v3-core/",
    "@uniswap/v4-core/": "uniswap-v4-core/",
    "v4-core/": "uniswap-v4-core/src/",
    "@uniswap/v3-core/": "uniswap-v3-core/",
    "@prb/math/": "prb-math/",
}
IMPORT_RE = re.compile(r'\bimport\b[^;"\']*["\']([^"\']+)["\'][^;]*;')
# Strings first so that comment markers inside them survive
TOKEN_RE = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//[^\n]*|/\*.*?\*/', re.S)
CONCRETE_CONTRACT_RE = re.compile(r"(?<!abstract )\bcontract\s+\w+[^;]*?\{")
# Inline assembly is fine: the runner skips only assembly a call graph reaches
ORACLE_UNSAFE_RE = re.compile(r"\bgasleft\s*\(|\bgas\s*\(|\.gas\s*:|\{\s*gas\s*:|tx\.gasprice|"
                              r"creationCode|runtimeCode")


def strip_comments(src: str) -> str:
    out = TOKEN_RE.sub(lambda m: m.group(0) if m.group(0)[0] in "\"'" else
                       ("\n" * m.group(0).count("\n")), src)
    return re.sub(r"\n\s*\n+", "\n", out)


def sol_files(cache: Path) -> list[Path]:
    files = []
    for f in cache.rglob("*.sol"):
        rel = f.relative_to(cache)
        if not EXCLUDE_DIRS.intersection(rel.parts[1:-1]) and f.is_file():
            files.append(f)
    return sorted(files)


class Resolver:
    def __init__(self, cache: Path, files: list[Path]):
        self.cache = cache
        self.by_suffix: dict[str, list[Path]] = defaultdict(list)
        for f in files:
            parts = f.relative_to(cache).parts
            for i in range(1, len(parts)):
                self.by_suffix["/".join(parts[i:])].append(f)
        self.remappings: dict[str, dict[str, str]] = {}

    def repo_remappings(self, repo: str) -> dict[str, str]:
        if repo not in self.remappings:
            maps = {}
            txt = self.cache / repo / "remappings.txt"
            if txt.is_file():
                for line in txt.read_text(errors="replace").splitlines():
                    if "=" in line and not line.startswith("#"):
                        key, target = line.split("=", 1)
                        maps[key.split(":")[-1].strip()] = f"{repo}/{target.strip()}"
            self.remappings[repo] = maps
        return self.remappings[repo]

    def resolve(self, importer: Path, path: str) -> Path | None:
        repo = importer.relative_to(self.cache).parts[0]
        candidates = []
        if path.startswith("."):
            candidates.append(importer.parent / path)
        candidates.append(self.cache / repo / path)
        for maps in (self.repo_remappings(repo), KNOWN_REMAPPINGS):
            for prefix, target in sorted(maps.items(), key=lambda kv: -len(kv[0])):
                if path.startswith(prefix):
                    candidates.append(self.cache / (target + path[len(prefix):]))
        for c in candidates:
            c = Path(*[p for p in c.parts])
            try:
                c = c.resolve()
            except OSError:
                continue
            if c.is_file() and c.is_relative_to(self.cache.resolve()):
                return c
        parts = path.split("/")
        for i in range(1, len(parts)):
            matches = self.by_suffix.get("/".join(parts[i:]), [])
            same_repo = [m for m in matches if m.relative_to(self.cache).parts[0] == repo]
            pick = same_repo or matches
            if len(pick) == 1:
                return pick[0].resolve()
        return None


def bundle(main: Path, resolver: Resolver, cache: Path, max_bytes: int) -> str | None:
    """None if an import does not resolve, the bundle is too big, or it is oracle-unsafe"""
    cache = cache.resolve()
    main = main.resolve()
    names: dict[Path, str] = {main: "~main.sol"}
    units: dict[str, str] = {}
    todo = [main]
    total = 0
    while todo:
        f = todo.pop()
        src = strip_comments(f.read_text(errors="replace"))
        if ORACLE_UNSAFE_RE.search(src) or (f == main and not CONCRETE_CONTRACT_RE.search(src)):
            return None

        def rewrite(m: re.Match) -> str:
            target = resolver.resolve(f, m.group(1))
            if target is None:
                raise LookupError(m.group(1))
            if target not in names:
                names[target] = str(target.relative_to(cache))
                todo.append(target)
            return m.group(0).replace(m.group(1), names[target])

        try:
            src = IMPORT_RE.sub(rewrite, src)
        except LookupError:
            return None
        units[names[f]] = src
        total += len(src)
        if total > max_bytes:
            return None
    out = "".join(f"==== Source: {name} ====\n{src.rstrip()}\n" for name, src in sorted(units.items()))
    return out if len(out) <= max_bytes else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cache", type=Path, default=REPO_ROOT / "realworld_cache")
    ap.add_argument("--max-bytes", type=int, default=16384)
    ap.add_argument("-o", "--out", type=Path, required=True)
    args = ap.parse_args()

    files = sol_files(args.cache)
    resolver = Resolver(args.cache, files)
    args.out.mkdir(parents=True, exist_ok=True)
    seen = set()
    written = rejected = 0
    for f in files:
        text = bundle(f, resolver, args.cache, args.max_bytes)
        if text is None:
            rejected += 1
            continue
        digest = hashlib.sha256(text.encode()).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        rel = f.relative_to(args.cache)
        (args.out / ("rwb_" + "__".join(rel.parts))).write_text(text)
        written += 1
    print(f"{len(files)} files: {written} bundles written, {rejected} rejected "
          "(unresolved import, too big, no concrete contract, or gas/bytecode introspection)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
