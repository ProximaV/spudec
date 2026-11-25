#include "spudec/ir.hpp"
#include "spudec/channels.hpp"
#include <cstdio>
#include <sstream>

namespace spudec {

bool op_is_terminator(Op op) {
    switch (op) {
        case Op::JMP:
        case Op::CJMP:
        case Op::IJMP:
        case Op::RET:
        case Op::STOP:
        case Op::TCALL:
            return true;
        default:
            return false;
    }
}

bool op_has_side_effects(Op op) {
    switch (op) {
        case Op::STOREQ:
        case Op::STORE:
        case Op::WRCH:
        case Op::RDCH:
        case Op::RCHCNT:
        case Op::MTSPR:
        case Op::MFSPR:
        case Op::STOP:
        case Op::SYNC:
        case Op::HALT:
        case Op::INTRINSIC:
        case Op::CALL:
        case Op::ICALL:
        case Op::CIJMP:
        case Op::TCALL:
            return true;
        default:
            return false;
    }
}

bool op_is_mem_read(Op op) {
    return op == Op::LOADQ || op == Op::LOAD || op == Op::LOADU;
}

bool op_is_mem_write(Op op) {
    return op == Op::STOREQ || op == Op::STORE;
}

bool op_is_abi(Op op, int *out_leading_real) {
    int n = -1;
    switch (op) {
        case Op::CALL:  n = 0; break;
        case Op::ICALL: n = 1; break;
        case Op::IJMP:  n = 1; break;
        case Op::RET:   n = 0; break;
        case Op::STOP:  n = 0; break;
        case Op::TCALL: n = 0; break;
        default: return false;
    }
    if (out_leading_real) *out_leading_real = n;
    return true;
}

bool op_ew_significant(Op op) {
    switch (op) {
        case Op::ADD: case Op::SUB: case Op::MUL: case Op::CG: case Op::BG:
        case Op::ADDX: case Op::SUBX: case Op::CGX: case Op::BGX:
        case Op::SHL: case Op::SHR: case Op::SAR: case Op::ROL: case Op::ROTM: case Op::ROTMA:
        case Op::CMPEQ: case Op::CMPGT: case Op::CMPGTU:
        case Op::GB: case Op::FSM: case Op::GENCTL: case Op::EXTS:
        case Op::FADD: case Op::FSUB: case Op::FMUL: case Op::FMA:
        case Op::FMS: case Op::FNMS: case Op::FNMA:
        case Op::FCMPEQ: case Op::FCMPGT: case Op::FCMPMEQ: case Op::FCMPMGT:
        case Op::LOAD: case Op::STORE:
            return true;
        default:
            return false;
    }
}

const char *op_name(Op op) {
    switch (op) {
        case Op::PHI: return "phi"; case Op::MOV: return "mov";
        case Op::CONST: return "const"; case Op::INTRINSIC: return "intr";
        case Op::UNDEF: return "undef";
        case Op::ADD: return "add"; case Op::SUB: return "sub";
        case Op::MUL: return "mul"; case Op::CG: return "cg";
        case Op::BG: return "bg"; case Op::ADDX: return "addx";
        case Op::SUBX: return "subx"; case Op::CGX: return "cgx";
        case Op::BGX: return "bgx"; case Op::ABSDB: return "absdb";
        case Op::AVGB: return "avgb"; case Op::SUMB: return "sumb";
        case Op::MPY: return "mpy"; case Op::MPYU: return "mpyu";
        case Op::MPYH: return "mpyh"; case Op::MPYS: return "mpys";
        case Op::MPYHH: return "mpyhh"; case Op::MPYHHU: return "mpyhhu";
        case Op::MPYHHA: return "mpyhha"; case Op::MPYHHAU: return "mpyhhau";
        case Op::MPYA: return "mpya";
        case Op::AND: return "and"; case Op::OR: return "or";
        case Op::XOR: return "xor"; case Op::NAND: return "nand";
        case Op::NOR: return "nor"; case Op::ANDC: return "andc";
        case Op::ORC: return "orc"; case Op::EQV: return "eqv";
        case Op::NOT: return "not";
        case Op::SHL: return "shl"; case Op::SHR: return "shr";
        case Op::SAR: return "sar"; case Op::ROL: return "rol";
        case Op::ROTM: return "rotm"; case Op::ROTMA: return "rotma";
        case Op::QROTBY: return "qrotby"; case Op::QROTBI: return "qrotbi";
        case Op::QROTMBY: return "qrotmby"; case Op::QROTMBI: return "qrotmbi";
        case Op::QSHLBY: return "qshlby"; case Op::QSHLBI: return "qshlbi";
        case Op::SHUFB: return "shufb"; case Op::SELB: return "selb";
        case Op::GENCTL: return "genctl"; case Op::GB: return "gb";
        case Op::FSM: return "fsm";
        case Op::CLZ: return "clz"; case Op::CNTB: return "cntb";
        case Op::ORX: return "orx"; case Op::EXTS: return "exts";
        case Op::CMPEQ: return "cmpeq"; case Op::CMPGT: return "cmpgt";
        case Op::CMPGTU: return "cmpgtu";
        case Op::FADD: return "fadd"; case Op::FSUB: return "fsub";
        case Op::FMUL: return "fmul"; case Op::FMA: return "fma";
        case Op::FMS: return "fms"; case Op::FNMS: return "fnms";
        case Op::FNMA: return "fnma";
        case Op::FCMPEQ: return "fcmpeq"; case Op::FCMPGT: return "fcmpgt";
        case Op::FCMPMEQ: return "fcmpmeq"; case Op::FCMPMGT: return "fcmpmgt";
        case Op::FI: return "fi"; case Op::FREST: return "frest";
        case Op::FRSQEST: return "frsqest"; case Op::FESD: return "fesd";
        case Op::FRDS: return "frds"; case Op::CSFLT: return "csflt";
        case Op::CUFLT: return "cuflt"; case Op::CFLTS: return "cflts";
        case Op::CFLTU: return "cfltu"; case Op::DFTSV: return "dftsv";
        case Op::LOADQ: return "loadq"; case Op::STOREQ: return "storeq";
        case Op::LOAD: return "load"; case Op::STORE: return "store";
        case Op::LOADU: return "loadu";
        case Op::JMP: return "jmp"; case Op::CJMP: return "cjmp";
        case Op::CALL: return "call"; case Op::ICALL: return "icall";
        case Op::IJMP: return "ijmp"; case Op::RET: return "ret";
        case Op::CIJMP: return "cijmp"; case Op::TCALL: return "tcall";
        case Op::RDCH: return "rdch"; case Op::WRCH: return "wrch";
        case Op::RCHCNT: return "rchcnt"; case Op::MFSPR: return "mfspr";
        case Op::MTSPR: return "mtspr"; case Op::STOP: return "stop";
        case Op::SYNC: return "sync"; case Op::NOP: return "nop";
        case Op::HALT: return "halt";
    }
    return "op?";
}

const char *op_infix(Op op) {
    switch (op) {
        case Op::ADD: return "+"; case Op::SUB: return "-";
        case Op::MUL: case Op::MPY: case Op::MPYU: return "*";
        case Op::AND: return "&"; case Op::OR: return "|"; case Op::XOR: return "^";
        case Op::SHL: return "<<"; case Op::SHR: case Op::SAR: return ">>";
        case Op::ROL: return "<<<";
        case Op::CMPEQ: return "=="; case Op::CMPGT: case Op::CMPGTU: return ">";
        case Op::FADD: return "+"; case Op::FSUB: return "-"; case Op::FMUL: return "*";
        default: return nullptr;
    }
}

std::string Operand::fmt_const(EW ctx_ew) const {
    if (val.is_zero()) return "#0";
    EW eff = (ctx_ew != EW::None) ? ctx_ew : ew;
    EW cands[5];
    int nc = 0;
    if (eff != EW::None && eff != EW::Q) cands[nc++] = eff;
    for (EW c : {EW::B, EW::H, EW::W, EW::D}) {
        bool seen = false;
        for (int i = 0; i < nc; ++i) if (cands[i] == c) seen = true;
        if (!seen) cands[nc++] = c;
    }
    for (int i = 0; i < nc; ++i) {
        uint64_t lane = 0;
        if (val.is_replicated(cands[i], &lane)) {
            char buf[48];
            std::snprintf(buf, sizeof(buf), "#0x%llx:%s%d",
                          static_cast<unsigned long long>(lane),
                          ew_suffix(cands[i]), ew_count(cands[i]));
            return buf;
        }
    }
    return "#0x" + val.hex32_lower();
}

std::string Operand::addr_str() const {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "@0x%X", val.word0());
    return buf;
}

std::string Operand::scalar_str() const {
    uint32_t w = val.word0();
    char buf[24];
    if (w >= 0x80000000u && (0x100000000ULL - w) <= 0xFFFFULL) {
        std::snprintf(buf, sizeof(buf), "-0x%X", static_cast<uint32_t>(0x100000000ULL - w));
    } else {
        std::snprintf(buf, sizeof(buf), "0x%X", w);
    }
    return buf;
}

std::string Operand::str() const {
    if (is_const) return fmt_const();
    std::string rn = regs::reg_name(reg);
    if (ver < 0) return rn;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "#%d", ver);
    return rn + buf;
}

static std::string fmt_aux(const Insn &ins) {
    char buf[64];
    if (ins.op == Op::JMP || ins.op == Op::CALL || ins.op == Op::TCALL) {
        std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(ins.aux_ea));
        return buf;
    }
    if (ins.op == Op::CJMP) {
        std::snprintf(buf, sizeof(buf), "0x%llX if %s",
                      static_cast<unsigned long long>(ins.aux_ea), cond_kind_str(ins.cond_kind));
        return buf;
    }
    if (ins.op == Op::CIJMP) {
        return cond_kind_str(ins.cond_kind);
    }
    if (ins.op == Op::RDCH || ins.op == Op::WRCH || ins.op == Op::RCHCNT) {
        return channels::label(static_cast<int>(ins.aux_int));
    }
    if (!ins.aux_str.empty()) return ins.aux_str;
    std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(ins.aux_int));
    return buf;
}

std::string Insn::to_string() const {
    std::string name = op_name(op);
    if (op_ew_significant(op)) {
        name += ".";
        name += ew_suffix(ew);
    }

    std::string line;
    if (has_dst) {
        std::string ds = dst_as_var().str();
        char pad[32];
        std::snprintf(pad, sizeof(pad), "%-10s = ", ds.c_str());
        line += pad;
    } else {
        line += "             ";
    }

    int abi_real = 0;
    const char *inf = op_infix(op);
    if (op == Op::CONST && !srcs.empty()) {
        line += scalar ? srcs[0].scalar_str() : srcs[0].str();
    } else if (scalar && inf != nullptr && srcs.size() == 2) {
        auto s0 = srcs[0].is_const ? srcs[0].scalar_str() : srcs[0].str();
        auto s1 = srcs[1].is_const ? srcs[1].scalar_str() : srcs[1].str();
        line += s0 + " " + inf + " " + s1;
    } else if (scalar && op == Op::MOV && !srcs.empty()) {
        line += srcs[0].is_const ? srcs[0].scalar_str() : srcs[0].str();
    } else if (op_is_abi(op, &abi_real)) {
        line += name;
        if (has_aux) line += " {" + fmt_aux(*this) + "}";
        if (abi_real > 0 && static_cast<int>(srcs.size()) >= abi_real) {
            line += " ";
            for (int i = 0; i < abi_real; ++i) {
                if (i > 0) line += ", ";
                line += srcs[i].str();
            }
        }
        char abuf[32];
        std::snprintf(abuf, sizeof(abuf), "  [abi: %d regs]",
                      static_cast<int>(srcs.size()) - abi_real);
        line += abuf;
    } else if (op == Op::PHI) {
        line += "phi(";
        for (size_t i = 0; i < srcs.size(); ++i) {
            if (i > 0) line += ", ";
            line += srcs[i].str() + ":";
            if (i < phi_preds.size() && phi_preds[i] >= 0) {
                line += "B" + std::to_string(phi_preds[i]);
            } else {
                line += "?";
            }
        }
        line += ")";
    } else {
        EW lane = op_ew_significant(op) ? ew : EW::None;
        int addr_at = (op_is_mem_read(op) || op_is_mem_write(op)) ? 1 : -1;
        line += name;
        if (!srcs.empty()) {
            line += " ";
            for (size_t i = 0; i < srcs.size(); ++i) {
                if (i > 0) line += ", ";
                if (srcs[i].is_const) {
                    line += (static_cast<int>(i) == addr_at) ? srcs[i].addr_str() : srcs[i].fmt_const(lane);
                } else {
                    line += srcs[i].str();
                }
            }
        }
        if (has_aux && op != Op::PHI) {
            line += " {" + fmt_aux(*this) + "}";
        }
    }

    if (!comment.empty()) {
        line += "    ; " + comment;
    }
    return line;
}

Insn *Block::add(std::unique_ptr<Insn> ins) {
    ins->block_id = id;
    Insn *raw = ins.get();
    insns.push_back(std::move(ins));
    return raw;
}

Block *Function::new_block(uint64_t s_ea, uint64_t e_ea) {
    int bid = static_cast<int>(blocks.size());
    auto b = std::make_unique<Block>();
    b->id = bid;
    b->start_ea = s_ea;
    b->end_ea = e_ea;
    Block *raw = b.get();
    blocks.push_back(std::move(b));
    if (entry_id < 0) entry_id = bid;
    return raw;
}

std::unique_ptr<Insn> Function::make_insn(Op op, EW ew, uint64_t ea) {
    auto ins = std::make_unique<Insn>();
    ins->uid = next_insn_uid++;
    ins->op = op;
    ins->ew = ew;
    ins->ea = ea;
    return ins;
}

std::string Function::dump() const {
    std::ostringstream os;
    char hbuf[64];
    std::snprintf(hbuf, sizeof(hbuf), "0x%llX", static_cast<unsigned long long>(start_ea));
    std::string nm = name.empty() ? ("sub_" + std::string(hbuf + 2)) : name;
    os << "; ---- " << nm << " @ " << hbuf << " " << (ssa ? "(SSA)" : "(pre-SSA)");

    for (const auto &b : blocks) {
        os << "\n\nB" << b->id << ":  ; ";
        char rbuf[64];
        std::snprintf(rbuf, sizeof(rbuf), "0x%llX..0x%llX",
                      static_cast<unsigned long long>(b->start_ea),
                      static_cast<unsigned long long>(b->end_ea));
        os << rbuf << "  preds: ";
        if (b->preds.empty()) {
            os << "-";
        } else {
            for (size_t i = 0; i < b->preds.size(); ++i) {
                if (i > 0) os << ", ";
                os << "B" << b->preds[i];
            }
        }
        for (const auto &ins : b->insns) {
            os << "\n    " << ins->to_string();
        }
    }
    return os.str();
}

} // namespace spudec
