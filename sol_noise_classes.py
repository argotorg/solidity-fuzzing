"""Known legacy/IR noise classes for differential Solidity crashes, matched on the source text."""
import re

ASSIGN_OP_RE = re.compile(r"<<=|>>=|[+\-*/%&|^]=|(?<![=!<>+\-*/%&|^])=(?![=>])")
INCDEC_RE = re.compile(r"\+\+|--")
SOLO_INCDEC_RE = re.compile(r"^(?:[\w.\[\]]+(?:\+\+|--)|(?:\+\+|--)[\w.\[\]]+)$")
MEM_DECL_RE = re.compile(r"^\s*\w[\w.\[\]]*\s+memory\s+(\w+)\s*[;=]", re.M)
TUPLE_LHS_RE = re.compile(r"^\(([^()]*)\)\s*=\s*\(")
STUB_PRECOMPILE_RE = re.compile(r"\bripemd160\b")


def strip_outer_parens(expr: str) -> str:
    while expr.startswith("(") and expr.endswith(")"):
        depth = 0
        for i, c in enumerate(expr):
            depth += (c == "(") - (c == ")")
            if depth == 0 and i < len(expr) - 1:
                return expr
        expr = expr[1:-1].strip()
    return expr


def nested_side_effect(stmt: str) -> bool:
    """True if an assignment or ++/-- sits inside a subexpression rather than
    being the whole statement -- legacy and IR order siblings differently."""
    expr = strip_outer_parens(stmt.strip().rstrip(";").strip())
    if SOLO_INCDEC_RE.match(expr):
        return False
    depth, i = 0, 0
    while i < len(expr):
        c = expr[i]
        if c in "()":
            depth += 1 if c == "(" else -1
            i += 1
            continue
        mo = ASSIGN_OP_RE.match(expr, i) or INCDEC_RE.match(expr, i)
        if mo:
            # A ++/-- is a side effect wherever it appears next to other operands;
            # a bare assignment is fine as long as it is the statement itself.
            if depth > 0 or INCDEC_RE.match(expr, i):
                return True
            i = mo.end()
            continue
        i += 1
    return False


def has_eval_order_noise(sol: str) -> bool:
    for raw in sol.splitlines():
        line = raw.split("//")[0].strip()
        if line.startswith("for ("):
            clauses = line[line.find("(") + 1:line.rfind(")")].split(";")
            line = ";".join(clauses[:2]) if len(clauses) >= 3 else line
        if nested_side_effect(line):
            return True
    return False


def tuple_alias_lines(sol: str) -> list[int]:
    """Destructuring assignments whose LHS holds a memory local -- the storage
    -> memory copy then races the other components' stores."""
    memory_locals = set(MEM_DECL_RE.findall(sol))
    if not memory_locals:
        return []
    hits = []
    for i, raw in enumerate(sol.splitlines()):
        mo = TUPLE_LHS_RE.match(raw.strip())
        if mo and any(v.strip() in memory_locals for v in mo.group(1).split(",")):
            hits.append(i)
    return hits


def has_tuple_alias(sol: str) -> bool:
    return bool(tuple_alias_lines(sol))


# Ordered: the first match explains the crash. Everything unmatched is a candidate.
NOISE_CLASSES = [
    ("eval-order", has_eval_order_noise,
     "side effect in a subexpression - legacy/IR evaluate siblings in a "
     "different order (solidity docs/ir-breaking-changes.rst)"),
    ("precompile-stub", lambda sol: bool(STUB_PRECOMPILE_RE.search(sol)),
     "ripemd160 - EVMHost only stubs precompile 0x03, the call fails and solc "
     "turns that into a bare revert"),
    ("tuple-alias", has_tuple_alias,
     "tuple assignment with a memory LHS aliasing an overwritten storage var - "
     "known legacy/IR difference (argotorg/solidity#16685)"),
]
NO_REPRO = ("no-repro", "the input no longer crashes this fuzzer build - stale corpus entry")
CANDIDATE = "candidate"


def noise_class(msg: str, sol: str) -> str:
    if msg.startswith("NO-CRASH") or msg.startswith("TIMEOUT"):
        return NO_REPRO[0]
    for name, matches, _ in NOISE_CLASSES:
        if matches(sol):
            return name
    return CANDIDATE
