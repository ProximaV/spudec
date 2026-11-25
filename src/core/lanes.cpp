#include "spudec/lanes.hpp"
#include "spudec/regs.hpp"
#include "spudec/sem.hpp"

namespace spudec {
namespace lanes {

namespace {

bool is_bytewise_op(Op op) {
    switch (op) {
        case Op::AND: case Op::OR: case Op::XOR: case Op::NAND:
        case Op::NOR: case Op::ANDC: case Op::ORC: case Op::EQV:
        case Op::NOT: case Op::SELB:
            return true;
        default:
            return false;
    }
}

bool is_elementwise_op(Op op) {
    switch (op) {
        case Op::ADD: case Op::SUB: case Op::MUL: case Op::CG: case Op::BG:
        case Op::ADDX: case Op::SUBX: case Op::CGX: case Op::BGX:
        case Op::SHL: case Op::SHR: case Op::SAR: case Op::ROL: case Op::ROTM: case Op::ROTMA: case Op::EXTS:
        case Op::CMPEQ: case Op::CMPGT: case Op::CMPGTU: case Op::CLZ: case Op::CNTB: case Op::AVGB: case Op::ABSDB:
        case Op::MPY: case Op::MPYU: case Op::MPYH: case Op::MPYS:
        case Op::MPYHH: case Op::MPYHHU: case Op::MPYHHA: case Op::MPYHHAU: case Op::MPYA:
        case Op::FADD: case Op::FSUB: case Op::FMUL: case Op::FMA: case Op::FMS: case Op::FNMS: case Op::FNMA:
        case Op::FCMPEQ: case Op::FCMPGT: case Op::FCMPMEQ: case Op::FCMPMGT:
        case Op::FI: case Op::FREST: case Op::FRSQEST:
        case Op::CSFLT: case Op::CUFLT: case Op::CFLTS: case Op::CFLTU:
            return true;
        default:
            return false;
    }
}

std::optional<u128_t> const_of(const Operand &v, const std::unordered_map<VarKey, const Insn *> &defs) {
    if (v.is_const) return v.val;
    auto it = defs.find(v.key());
    int guard = 0;
    while (it != defs.end() && it->second->op == Op::MOV && !it->second->srcs.empty() && guard++ < 32) {
        const Operand &s = it->second->srcs[0];
        if (s.is_const) return s.val;
        it = defs.find(s.key());
    }
    if (it != defs.end() && it->second->op == Op::CONST && !it->second->srcs.empty() && it->second->srcs[0].is_const) {
        return it->second->srcs[0].val;
    }
    return std::nullopt;
}

const Insn *genctl_def_of(const Operand &v, const std::unordered_map<VarKey, const Insn *> &defs) {
    if (!v.is_var()) return nullptr;
    auto it = defs.find(v.key());
    int guard = 0;
    while (it != defs.end() && it->second->op == Op::MOV && !it->second->srcs.empty() && guard++ < 16) {
        const Operand &s = it->second->srcs[0];
        if (!s.is_var()) return nullptr;
        it = defs.find(s.key());
    }
    if (it != defs.end() && it->second->op == Op::GENCTL && !it->second->srcs.empty()) {
        return it->second;
    }
    return nullptr;
}

std::optional<u128_t> genctl_const_of(const Operand &v, const std::unordered_map<VarKey, const Insn *> &defs) {
    const Insn *d = genctl_def_of(v, defs);
    if (!d) return std::nullopt;

    Operand cur = d->srcs[0];
    uint32_t off = 0;
    bool aligned = false;
    bool saw_add = false;
    bool has_base = false;
    VarKey base = 0;

    for (int step = 0; step < 16; ++step) {
        if (cur.is_const) {
            off += cur.val.word0();
            return sem::genctl(off & 0xFu, d->ew);
        }
        auto it = defs.find(cur.key());
        if (it == defs.end()) {
            has_base = true;
            base = cur.key();
            break;
        }
        const Insn *ad = it->second;
        if (ad->op == Op::MOV && !ad->srcs.empty()) {
            cur = ad->srcs[0];
            continue;
        }
        if (ad->op == Op::CONST && !ad->srcs.empty() && ad->srcs[0].is_const) {
            off += ad->srcs[0].val.word0();
            return sem::genctl(off & 0xFu, d->ew);
        }
        if (ad->op == Op::AND && ad->srcs.size() == 2 && ad->srcs[1].is_const &&
            (ad->srcs[1].val.word0() == 0x0003FFF0u || ad->srcs[1].val.word0() == 0xFFFFFFF0u)) {
            if (saw_add) {
                has_base = true;
                base = cur.key();
                aligned = false;
                break;
            }
            aligned = true;
            cur = ad->srcs[0];
            continue;
        }
        if (ad->op == Op::ADD && ad->ew == EW::W && ad->srcs.size() == 2) {
            if (auto c1 = const_of(ad->srcs[1], defs); c1.has_value()) {
                off += c1->word0();
                saw_add = true;
                cur = ad->srcs[0];
                continue;
            }
            if (auto c0 = const_of(ad->srcs[0], defs); c0.has_value()) {
                off += c0->word0();
                saw_add = true;
                cur = ad->srcs[1];
                continue;
            }
        }
        has_base = true;
        base = cur.key();
        break;
    }
    if (!has_base || key_reg(base) == regs::SP || aligned) {
        return sem::genctl(off & 0xFu, d->ew);
    }
    return std::nullopt;
}

namespace {

const Insn *peel_mov_def_lanes(const std::unordered_map<VarKey, const Insn *> &defs, Operand op) {
    for (int depth = 0; depth < 16 && op.is_var(); ++depth) {
        auto it = defs.find(op.key());
        if (it == defs.end()) return nullptr;
        const Insn *d = it->second;
        if (d->op == Op::MOV && d->srcs.size() == 1 && d->srcs[0].is_var()) {
            op = d->srcs[0];
            continue;
        }
        return d;
    }
    return nullptr;
}

bool is_clean_ret_extra(const std::unordered_map<VarKey, const Insn *> &defs, const Operand &src) {
    const Insn *d = peel_mov_def_lanes(defs, src);
    if (!d) return false;
    if (d->op == Op::PHI) {
        bool any_src = false;
        for (const auto &s : d->srcs) {
            if (!s.is_var() || s.ver == 0) return false;
            if (d->has_dst && s.key() == d->dst_key()) continue;
            any_src = true;
            const Insn *sd = peel_mov_def_lanes(defs, s);
            if (!sd || sd->op == Op::UNDEF || sd->op == Op::CONST) return false;
        }
        return any_src;
    }
    return d->op != Op::UNDEF && d->op != Op::CONST;
}

} // namespace

void abi_contrib(const Insn &insn, const CalleeDemandFn &callee,
                 const std::unordered_map<VarKey, const Insn *> &defs,
                 const std::unordered_map<VarKey, int> &non_ret_uses,
                 std::vector<uint16_t> &out) {
    out.clear();
    out.reserve(insn.srcs.size());

    std::optional<std::unordered_map<int, uint16_t>> masks;
    if (callee && (insn.op == Op::CALL || insn.op == Op::TCALL) && insn.has_aux) {
        masks = callee(insn.aux_ea);
    }

    int real = 0;
    op_is_abi(insn.op, &real);
    bool prev_ret_ok = false;
    for (size_t i = 0; i < insn.srcs.size(); ++i) {
        if (static_cast<int>(i) < real) {
            out.push_back(W0);
            continue;
        }
        const Operand &src = insn.srcs[i];
        if (!src.is_var()) {
            out.push_back(NONE);
            if (insn.op == Op::RET) prev_ret_ok = false;
            continue;
        }
        int r = src.reg;
        if (regs::is_pseudo(r)) {
            out.push_back(ALL);
        } else if (r == regs::LR) {
            out.push_back(W0);
        } else if (insn.op == Op::RET) {
            if (r == regs::ARG_FIRST) {
                out.push_back(ALL);
                prev_ret_ok = true;
            } else {
                bool qualifies = prev_ret_ok && src.ver != 0 &&
                                 non_ret_uses.find(src.key()) == non_ret_uses.end();
                if (qualifies) {
                    qualifies = is_clean_ret_extra(defs, src);
                }
                if (qualifies) {
                    out.push_back(ALL);
                } else {
                    out.push_back(NONE);
                    prev_ret_ok = false;
                }
            }
        } else if (masks.has_value()) {
            auto mit = masks->find(r);
            out.push_back(mit != masks->end() ? mit->second : ALL);
        } else {
            out.push_back(ALL);
        }
    }
}

void contrib(const Insn &insn, uint16_t out_mask,
             const std::unordered_map<VarKey, const Insn *> &defs,
             const std::unordered_map<VarKey, int> &non_ret_uses,
             const CalleeDemandFn &callee,
             std::vector<uint16_t> &out) {
    const Op op = insn.op;
    const size_t n = insn.srcs.size();

    if (op_is_abi(op)) {
        abi_contrib(insn, callee, defs, non_ret_uses, out);
        return;
    }
    out.clear();
    if (op == Op::CJMP) {
        out.push_back((insn.cond_kind == CondKind::HZ || insn.cond_kind == CondKind::HNZ) ? H0 : W0);
        return;
    }
    if (op == Op::CIJMP) {
        out.push_back((insn.cond_kind == CondKind::HZ || insn.cond_kind == CondKind::HNZ) ? H0 : W0);
        out.push_back(W0);
        return;
    }
    if (op == Op::STOREQ) {
        out.assign({ALL, W0, ALL});
        return;
    }
    if (op == Op::STORE) {
        out.assign({ALL, W0, slot_low_mask(insn.ew)});
        return;
    }
    if (op == Op::LOADQ || op == Op::LOAD || op == Op::LOADU) {
        out.assign({ALL, W0});
        return;
    }
    if (op == Op::RDCH || op == Op::RCHCNT || op == Op::MFSPR || op == Op::SYNC ||
        op == Op::WRCH || op == Op::MTSPR || op == Op::HALT || op == Op::INTRINSIC) {
        out.assign(n, ALL);
        return;
    }

    if (out_mask == NONE) {
        out.assign(n, NONE);
        return;
    }

    if (op == Op::MOV || op == Op::PHI) {
        out.assign(n, out_mask);
        return;
    }
    if (op == Op::CONST) {
        out.assign(n, NONE);
        return;
    }
    if (is_bytewise_op(op)) {
        out.assign(n, out_mask);
        return;
    }
    if (is_elementwise_op(op)) {
        out.assign(n, expand_mask(out_mask, insn.ew));
        return;
    }
    if (op == Op::GENCTL || op == Op::FSM) {
        out.assign({W0});
        return;
    }
    if (op == Op::GB || op == Op::ORX) {
        out.assign({ALL});
        return;
    }
    if (op == Op::SHUFB && n >= 3) {
        auto ctl = const_of(insn.srcs[2], defs);
        if (!ctl.has_value()) {
            ctl = genctl_const_of(insn.srcs[2], defs);
        }
        if (!ctl.has_value()) {
            if (const Insn *gd = genctl_def_of(insn.srcs[2], defs)) {
                out.assign({slot_low_mask(gd->ew), out_mask, W0});
                return;
            }
            out.assign({ALL, ALL, ALL});
            return;
        }
        uint16_t da = 0, db = 0;
        for (int i = 0; i < 16; ++i) {
            if (((out_mask >> i) & 1u) == 0) continue;
            uint8_t cb = ctl->byte_lane(i);
            if ((cb & 0xC0u) == 0x80u || (cb & 0xE0u) == 0xC0u || (cb & 0xE0u) == 0xE0u) {
                continue;
            }
            uint8_t idx = cb & 0x1Fu;
            if (idx < 16) da |= static_cast<uint16_t>(1u << idx);
            else db |= static_cast<uint16_t>(1u << (idx - 16));
        }
        out.assign({da, db, W0});
        return;
    }
    if ((op == Op::QROTBY || op == Op::QROTBI || op == Op::QROTMBY ||
         op == Op::QROTMBI || op == Op::QSHLBY || op == Op::QSHLBI) && n >= 2) {
        auto cnt = const_of(insn.srcs[1], defs);
        if (!cnt.has_value()) {
            out.assign({ALL, W0});
            return;
        }
        uint32_t c = cnt->word0();
        if (op == Op::QROTBI || op == Op::QROTMBI || op == Op::QSHLBI) {
            out.assign({ALL, W0});
            return;
        }
        if (op == Op::QROTBY) {
            out.assign({rotl_mask(out_mask, c & 0xFu), W0});
            return;
        }
        if (op == Op::QSHLBY) {
            uint32_t k = c & 0x1Fu;
            out.assign({k >= 16 ? NONE : static_cast<uint16_t>((out_mask << k) & ALL), W0});
            return;
        }
        if (op == Op::QROTMBY) {
            uint32_t k = (0u - c) & 0x1Fu;
            out.assign({k >= 16 ? NONE : static_cast<uint16_t>((out_mask >> k) & ALL), W0});
            return;
        }
    }

    out.assign(n, ALL);
}

} // namespace

uint16_t expand_mask(uint16_t mask, EW ew) {
    int n = static_cast<int>(ew);
    if (n <= 1 || n >= 16) return (n >= 16 && mask != NONE) ? ALL : mask;
    uint16_t out = 0;
    uint16_t full = static_cast<uint16_t>((1u << n) - 1u);
    for (int e = 0; e < 16 / n; ++e) {
        uint16_t sel = static_cast<uint16_t>(full << (e * n));
        if (mask & sel) out |= sel;
    }
    return out;
}

uint16_t rotl_mask(uint16_t mask, uint32_t n) {
    n &= 0xFu;
    if (n == 0) return mask;
    return static_cast<uint16_t>(((mask << n) | (mask >> (16u - n))) & ALL);
}

std::unordered_map<VarKey, uint16_t> compute_demand(const Function &func, const CalleeDemandFn &callee) {
    std::unordered_map<VarKey, const Insn *> defs;
    std::unordered_map<VarKey, int> non_ret_uses;
    std::vector<const Insn *> order;
    for (const auto &b : func.blocks) {
        for (const auto &i : b->insns) {
            if (i->defines()) defs[i->dst_key()] = i.get();
            if (i->op != Op::RET) {
                for (const auto &s : i->srcs) {
                    if (s.is_var()) ++non_ret_uses[s.key()];
                }
            }
        }
    }
    for (auto bit = func.blocks.rbegin(); bit != func.blocks.rend(); ++bit) {
        const auto &insns = (*bit)->insns;
        for (auto iit = insns.rbegin(); iit != insns.rend(); ++iit) {
            order.push_back(iit->get());
        }
    }

    // Cache direct call demand answers once per callee EA within a compute_demand pass.
    std::unordered_map<uint64_t, std::optional<std::unordered_map<int, uint16_t>>> callee_cache;
    CalleeDemandFn cached_callee;
    if (callee) {
        cached_callee = [&](uint64_t ea) -> std::optional<std::unordered_map<int, uint16_t>> {
            auto it = callee_cache.find(ea);
            if (it != callee_cache.end()) return it->second;
            auto res = callee(ea);
            callee_cache.emplace(ea, res);
            return res;
        };
    }

    std::unordered_map<VarKey, uint16_t> demand;
    demand.reserve(defs.size() + 32);
    std::vector<uint16_t> src_masks;
    src_masks.reserve(160);

    bool changed = true;
    while (changed) {
        changed = false;
        for (const Insn *insn : order) {
            uint16_t out = NONE;
            if (insn->defines()) {
                auto dit = demand.find(insn->dst_key());
                if (dit != demand.end()) out = dit->second;
            }
            contrib(*insn, out, defs, non_ret_uses, cached_callee, src_masks);
            const size_t limit = std::min(insn->srcs.size(), src_masks.size());
            for (size_t i = 0; i < limit; ++i) {
                const Operand &src = insn->srcs[i];
                uint16_t add = src_masks[i];
                if (!src.is_var() || add == NONE) continue;
                auto &cur = demand[src.key()];
                uint16_t nw = static_cast<uint16_t>(cur | add);
                if (nw != cur) {
                    cur = nw;
                    changed = true;
                }
            }
        }
    }
    return demand;
}

EW narrowest_lead(uint16_t mask) {
    for (EW ew : {EW::B, EW::H, EW::W, EW::D}) {
        if (fits_lead(mask, ew)) return ew;
    }
    for (EW ew : {EW::B, EW::H, EW::W, EW::D}) {
        if (fits_slot_low(mask, ew)) return ew;
    }
    return EW::None;
}

EW narrowest_slot_low(uint16_t mask) {
    for (EW ew : {EW::B, EW::H, EW::W, EW::D}) {
        if (fits_slot_low(mask, ew)) return ew;
    }
    return EW::None;
}

} // namespace lanes
} // namespace spudec
