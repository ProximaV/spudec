"""
Calling-convention modelling.

The register sets here follow the SPU ABI and were cross-checked against the
GhidraSPU processor module's `spu.cspec`, whose `<input>`/`<output>` lists are
r3..r74 and whose `<unaffected>` list is exactly r80..r127.

No IDA imports: unit-testable standalone.
"""

import re

from .ir import Op, Insn, Var
from . import regs

ARG_REGS = tuple("r%d" % i for i in range(regs.ARG_FIRST, regs.ARG_LAST + 1))
CALLER_SAVED = frozenset(regs.reg_name(r) for r in regs.VOLATILE)
CALLEE_SAVED = frozenset("r%d" % i for i in range(regs.CALLEE_SAVED_FIRST, regs.NGPR))

_CALL_CONVS = frozenset((
    "__cdecl", "__stdcall", "__fastcall", "__thiscall", "_cdecl",
    "__spucall", "__usercall", "__userpurge", "__spoils",
))

_C_TYPE_WORDS = frozenset((
    "void", "char", "short", "int", "long", "unsigned", "signed",
    "float", "double", "bool", "_Bool", "const", "volatile", "restrict",
    "struct", "union", "enum", "class",
    "qword", "qword_unaligned", "u8", "u16", "u32", "u64",
    "s8", "s16", "s32", "s64", "size_t", "ssize_t", "ptrdiff_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "uintptr_t", "intptr_t", "__int8", "__int16", "__int32", "__int64",
    "BYTE", "WORD", "DWORD", "QWORD", "BOOL",
))


def _looks_like_type_token(tok):
    """Heuristic: whether a bare token is a C type name rather than a parameter name."""
    if not tok:
        return False
    if tok in _C_TYPE_WORDS:
        return True
    if tok.startswith("vec_") or tok.endswith("_t") or "::" in tok:
        return True
    return False


def _normalize_type_stars(base_parts, nstars):
    """Join type parts and attach pointer stars cleanly ('const char **')."""
    base = " ".join(p for p in base_parts if p).strip()
    if nstars <= 0:
        return base or "qword"
    if not base:
        return "void " + ("*" * nstars)
    return f"{base} {'*' * nstars}"


def _parse_one_param(arg_str, idx):
    """Parse a single C parameter declaration into (type_str, name)."""
    s = arg_str.strip()
    if not s or s == "...":
        return None
    # Strip trailing array brackets (e.g. `u8 buf[16]` -> `u8 *buf`)
    arr_dims = 0
    m_arr = re.search(r"(\s*\[[^\]]*\])+$", s)
    if m_arr:
        arr_dims = m_arr.group(0).count("[")
        s = s[:m_arr.start()].strip()

    # Tokenize keeping '*' as separate tokens so `const char **argv`, `void*p`,
    # `char * * argv`, and `struct Foo *` all parse identically.
    raw_tokens = re.findall(r"\*|[A-Za-z_~][A-Za-z0-9_:~<>]*", s)
    raw_tokens = [t for t in raw_tokens if t not in _CALL_CONVS]
    if not raw_tokens:
        return None

    # Trailing '*' means definitely an unnamed pointer parameter (`const char *`, `void **`)
    if raw_tokens[-1] == "*":
        stars = arr_dims
        while raw_tokens and raw_tokens[-1] == "*":
            stars += 1
            raw_tokens.pop()
        return _normalize_type_stars(raw_tokens, stars), f"a{idx + 1}"

    # Single token: distinguish a bare type (`int`, `u32`, `size_t`, `Elf32_Ehdr`) vs bare name (`a1`)
    if len(raw_tokens) == 1:
        tok = raw_tokens[0]
        if _looks_like_type_token(tok) or (tok[0].isupper() and "_" in tok):
            return _normalize_type_stars([tok], arr_dims), f"a{idx + 1}"
        return _normalize_type_stars(["qword"], arr_dims), tok

    last = raw_tokens[-1]
    prev = raw_tokens[:-1]

    # If the last token is a C type keyword (e.g. `unsigned int`, `const char`, `long long`)
    # OR preceded directly by `struct`/`union`/`enum`/`class` with no trailing name
    # (e.g. `struct Foo`, `const struct Foo`), it's an unnamed parameter!
    if last in _C_TYPE_WORDS or (prev and prev[-1] in ("struct", "union", "enum", "class")):
        stars = arr_dims
        while raw_tokens and raw_tokens[-1] == "*":
            stars += 1
            raw_tokens.pop()
        return _normalize_type_stars(raw_tokens, stars), f"a{idx + 1}"

    # Otherwise `last` is the parameter name and `prev` is the type (possibly ending in `*`s)
    pname = last
    stars = arr_dims
    while prev and prev[-1] == "*":
        stars += 1
        prev.pop()
    # Handle qualifiers placed after `*`, e.g. `char * const p`
    post_quals = []
    while prev and prev[-1] in ("const", "volatile", "restrict") and "*" in prev:
        post_quals.insert(0, prev.pop())
        while prev and prev[-1] == "*":
            stars += 1
            prev.pop()
    ptype = _normalize_type_stars(prev, stars)
    if post_quals:
        ptype = f"{ptype} {' '.join(post_quals)}"
    return ptype, pname


def format_proto(ret_type, name, params):
    """Format a C function prototype from return type, name, and Param list or (name, type) pairs."""
    pstrs = []
    for p in (params or ()):
        if isinstance(p, Param):
            pt, pn = p.type_str, p.name
        else:
            pn, pt = p[0], p[1]
        sep = "" if pt.endswith("*") else " "
        pstrs.append(f"{pt}{sep}{pn}")
    pjoin = ", ".join(pstrs) if pstrs else "void"
    rsep = "" if ret_type.endswith("*") else " "
    return f"{ret_type}{rsep}{name}({pjoin})"


def sanitize_decl_for_ida(proto_str, replace_this=False, replace_qualified_types=False):
    """Sanitize a C/C++ prototype string so ida_typeinf.parse_decl can parse it.

    Replaces C++ qualified/operator declarator names (e.g. `lv0::elf_access::set_elf`)
    with a valid C identifier `_spudec_fn`. Optionally renames parameter `this` -> `_this_ptr`
    and replaces qualified C++ parameter pointer types (`ns::cls *`) with `void *`.
    """
    clean = proto_str.strip().rstrip(";")
    if "(" not in clean or ")" not in clean:
        return clean + ";"
    sig = _parse_proto(clean)
    if sig is None:
        return clean + ";"

    fn_name = sig.name or "_spudec_fn"
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", fn_name):
        fn_name = "_spudec_fn"

    ret_type = sig.ret_type
    if replace_qualified_types and "::" in ret_type:
        stars = ret_type.count("*")
        ret_type = ("void " + ("*" * stars)) if stars else "qword"

    sanitized_params = []
    for i, p in enumerate(sig.params):
        pt = p.type_str
        pn = p.name
        if replace_this and pn == "this":
            pn = "_this_ptr"
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", pn):
            pn = f"a{i + 1}"
        if replace_qualified_types and "::" in pt:
            stars = pt.count("*")
            pt = ("void " + ("*" * stars)) if stars else "qword"
        sanitized_params.append(Param(name=pn, type_str=pt, location=p.location))

    return format_proto(ret_type, fn_name, sanitized_params) + ";"


class Param:
    __slots__ = ("name", "type_str", "location")

    def __init__(self, name, type_str="qword", location="r3"):
        self.name = name
        self.type_str = type_str
        self.location = location

    def __repr__(self):
        return f"{self.type_str} {self.name}"


class FunctionSig:
    def __init__(self, name=None, ret_type="void", ret_expr=None, params=None):
        self.name = name
        self.ret_type = ret_type
        self.ret_expr = ret_expr
        self.params = list(params) if params else []

    def format_signature(self, func_name=None):
        name = func_name or self.name or "sub_unknown"
        if self.params:
            pstr = ", ".join(f"{p.type_str}{'' if p.type_str.endswith('*') else ' '}{p.name}" for p in self.params)
        else:
            pstr = "void"
        sep = "" if self.ret_type.endswith("*") else " "
        return f"{self.ret_type}{sep}{name}({pstr})"


def _parse_proto(proto_str, default_name="sub_unknown"):
    """Parse a C/C++ function prototype string: 'int *foo(const char **a, unsigned int)'."""
    try:
        clean = proto_str.strip().rstrip(";")
        if "(" not in clean or ")" not in clean:
            return None
        head, args_part = clean.split("(", 1)
        args_part = args_part.rsplit(")", 1)[0].strip()

        head_tokens = re.findall(r"\*|[A-Za-z_~][A-Za-z0-9_:~<>]*", head.strip())
        head_tokens = [tok for tok in head_tokens if tok not in _CALL_CONVS]
        if not head_tokens:
            return None

        # Handle anonymous prototype like `int (int, void *)`
        if head_tokens[-1] == "*" or (len(head_tokens) == 1 and head_tokens[0] in _C_TYPE_WORDS):
            fn_name = default_name
            ret_tokens = list(head_tokens)
        else:
            fn_name = head_tokens[-1] or default_name
            ret_tokens = head_tokens[:-1]

        ret_stars = 0
        while ret_tokens and ret_tokens[-1] == "*":
            ret_stars += 1
            ret_tokens.pop()
        if not ret_tokens:
            ret_type = ("void " + ("*" * ret_stars)) if ret_stars else "void"
        else:
            ret_type = _normalize_type_stars(ret_tokens, ret_stars)

        params = []
        if args_part and args_part.strip() != "void":
            for idx, arg_str in enumerate(args_part.split(",")):
                parsed_arg = _parse_one_param(arg_str, idx)
                if parsed_arg is None:
                    continue
                ptype, pname = parsed_arg
                loc_reg = regs.ARG_FIRST + len(params)
                loc = regs.reg_name(loc_reg) if loc_reg <= regs.ARG_LAST else f"arg_{len(params)+1}"
                params.append(Param(name=pname, type_str=ptype, location=loc))

        ret_expr = regs.reg_name(regs.ARG_FIRST) if ret_type != "void" else None
        return FunctionSig(name=fn_name, ret_type=ret_type, ret_expr=ret_expr, params=params)
    except Exception:
        return None


def insert_call_clobbers(func):
    """
    Give every call a definition of each volatile register it destroys.

    Without this, a register written before a call and read after it carries
    the same SSA name across the call, so constant propagation happily folds
    the pre-call value into the post-call use.  That is the worst class of
    decompiler bug: the output is confidently wrong and looks fine.

    Only registers this function actually writes need clobbering.  Everything
    else is already live-in at version 0, so a clobber would add no
    information -- and this keeps the cost to a handful of instructions per
    call instead of one per volatile register.  DCE then removes every clobber
    whose value nothing reads, so the ones that survive are exactly the
    genuine read-after-call sites.
    """
    written = {i.dst.reg for i in func.insns()
               if i.dst is not None and regs.is_gpr(i.dst.reg)}
    vol = sorted(written & regs.VOLATILE)
    if not vol:
        return 0

    n = 0
    for b in func.blocks:
        out = []
        for insn in b.insns:
            out.append(insn)
            if insn.op in (Op.CALL, Op.ICALL):
                for r in vol:
                    c = Insn(Op.UNDEF, Var(r), [], ea=insn.ea,
                             comment="clobbered by call")
                    c.block = b
                    out.append(c)
                    n += 1
        b.insns = out
    return n
