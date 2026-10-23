"""
Calling-convention modelling.

The register sets here follow the SPU ABI and were cross-checked against the
GhidraSPU processor module's `spu.cspec`, whose `<input>`/`<output>` lists are
r3..r74 and whose `<unaffected>` list is exactly r80..r127.

No IDA imports: unit-testable standalone.
"""

from .ir import Op, Insn, Var
from . import regs

ARG_REGS = tuple("r%d" % i for i in range(regs.ARG_FIRST, regs.ARG_LAST + 1))
CALLER_SAVED = frozenset(regs.reg_name(r) for r in regs.VOLATILE)
CALLEE_SAVED = frozenset("r%d" % i for i in range(regs.CALLEE_SAVED_FIRST, regs.NGPR))


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
    """Parse a simple C function prototype string: 'int foo(int a, void *b)'."""
    try:
        clean = proto_str.strip().rstrip(";")
        if "(" not in clean or ")" not in clean:
            return None
        head, args_part = clean.split("(", 1)
        args_part = args_part.rsplit(")", 1)[0].strip()

        CALL_CONVS = {"__cdecl", "__stdcall", "__fastcall", "__thiscall", "_cdecl", "__spucall", "__usercall"}
        head_tokens = [tok for tok in head.strip().split() if tok not in CALL_CONVS]
        if not head_tokens:
            return None
        raw_fn = head_tokens[-1]
        stars_fn = raw_fn.count("*")
        fn_name = raw_fn.replace("*", "").strip() or default_name
        base_ret = " ".join(head_tokens[:-1]) if len(head_tokens) > 1 else ("int" if stars_fn else "void")
        ret_type = (base_ret.rstrip("*").strip() + " " + ("*" * (stars_fn + base_ret.count("*")))).strip() if (stars_fn or "*" in base_ret) else base_ret

        params = []
        if args_part and args_part != "void":
            for idx, arg_str in enumerate(args_part.split(",")):
                arg_tokens = arg_str.strip().split()
                if not arg_tokens:
                    continue
                if len(arg_tokens) == 1:
                    raw = arg_tokens[0]
                    stars = raw.count("*")
                    pname = raw.replace("*", "") or f"a{idx+1}"
                    ptype = "qword" + (" *" if stars else "")
                else:
                    raw_name = arg_tokens[-1]
                    stars = raw_name.count("*")
                    pname = raw_name.replace("*", "") or f"a{idx+1}"
                    base_type = " ".join(arg_tokens[:-1])
                    ptype = (base_type + " *") if stars else base_type
                loc_reg = regs.ARG_FIRST + idx
                loc = regs.reg_name(loc_reg) if loc_reg <= regs.ARG_LAST else f"arg_{idx+1}"
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
