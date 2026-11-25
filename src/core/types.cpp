#include "spudec/types.hpp"
#include "spudec/lanes.hpp"
#include <algorithm>
#include <cstdio>

namespace spudec {
namespace types {

namespace {

constexpr inline int rank_of(TyKind k) {
    switch (k) {
        case TyKind::UNK: return 0;
        case TyKind::INT: return 1;
        case TyKind::VEC: return 2;
        case TyKind::FLT: return 3;
        case TyKind::PTR: return 4;
    }
    return 0;
}

bool is_float_op(Op op) {
    switch (op) {
        case Op::FADD: case Op::FSUB: case Op::FMUL: case Op::FMA:
        case Op::FMS: case Op::FNMS: case Op::FNMA:
        case Op::FI: case Op::FREST: case Op::FRSQEST:
            return true;
        default:
            return false;
    }
}

bool is_fcmp_op(Op op) {
    return op == Op::FCMPEQ || op == Op::FCMPGT || op == Op::FCMPMEQ || op == Op::FCMPMGT;
}

bool is_lanewise_op(Op op) {
    switch (op) {
        case Op::ADD: case Op::SUB: case Op::MUL:
        case Op::CMPEQ: case Op::CMPGT: case Op::CMPGTU:
        case Op::SHL: case Op::SHR: case Op::SAR: case Op::ROL:
        case Op::AVGB: case Op::ABSDB: case Op::CNTB: case Op::CLZ:
            return true;
        default:
            return false;
    }
}

bool is_quadword_vec_op(Op op) {
    switch (op) {
        case Op::SHUFB: case Op::SELB: case Op::GB: case Op::FSM: case Op::GENCTL:
        case Op::QROTBY: case Op::QROTBI: case Op::QROTMBY:
        case Op::QROTMBI: case Op::QSHLBY: case Op::QSHLBI:
            return true;
        default:
            return false;
    }
}

} // namespace

const char *kind_name(TyKind k) {
    switch (k) {
        case TyKind::UNK: return "unk";
        case TyKind::INT: return "int";
        case TyKind::FLT: return "flt";
        case TyKind::PTR: return "ptr";
        case TyKind::VEC: return "vec";
    }
    return "unk";
}

bool Ty::same_key(const Ty &o) const {
    if (kind != o.kind || width != o.width || is_signed != o.is_signed) return false;
    if (!pointee && !o.pointee) return true;
    if (!pointee || !o.pointee) return false;
    return pointee->same_key(*o.pointee);
}

std::string Ty::str() const {
    if (kind == TyKind::PTR) {
        std::string pt = pointee ? pointee->str() : Ty(TyKind::INT, 4).str();
        return pt + " *";
    }
    if (kind == TyKind::FLT) {
        return (width == 8) ? "double" : "float";
    }
    if (kind == TyKind::VEC) {
        int w = (width > 0) ? width : 1;
        const char *elem = "uchar";
        if (w == 2) elem = "ushort";
        else if (w == 4) elem = "uint";
        else if (w == 8) elem = "ullong";
        char buf[32];
        std::snprintf(buf, sizeof(buf), "vec_%s%d", elem, 16 / w);
        return buf;
    }
    if (kind == TyKind::INT ||
        (kind == TyKind::UNK && (width == 1 || width == 2 || width == 4 || width == 8))) {
        const char *base = "int";
        if (width == 1) base = "char";
        else if (width == 2) base = "short";
        else if (width == 8) base = "long long";
        if (!is_signed.has_value() || !(*is_signed)) {
            return std::string("unsigned ") + base;
        }
        return base;
    }
    return "qword";
}

Ty join(const Ty &a, const Ty &b, int *contradictions) {
    if (a.kind == TyKind::UNK && b.kind == TyKind::UNK) {
        int w = std::max(a.width, b.width);
        auto s = a.is_signed.has_value() ? a.is_signed : b.is_signed;
        return Ty(TyKind::UNK, w, s);
    }

    const bool a_ge_b = (rank_of(a.kind) >= rank_of(b.kind));
    const TyKind kind = a_ge_b ? a.kind : b.kind;
    const Ty &hi = a_ge_b ? a : b;
    const Ty &lo = a_ge_b ? b : a;

    if (contradictions &&
        ((lo.kind == TyKind::FLT && hi.kind == TyKind::PTR) ||
         (lo.kind == TyKind::PTR && hi.kind == TyKind::FLT))) {
        ++(*contradictions);
    }

    int width = (kind == TyKind::PTR) ? 4 : std::max(a.width, b.width);
    std::optional<bool> sgn = a.is_signed;
    bool amb = a.ambiguous || b.ambiguous;
    if (!a.is_signed.has_value()) {
        sgn = b.is_signed;
    } else if (b.is_signed.has_value() && *b.is_signed != *a.is_signed) {
        sgn = std::nullopt;
        amb = true;
    }

    std::shared_ptr<const Ty> pt = hi.pointee ? hi.pointee : lo.pointee;
    if (a.pointee && b.pointee) {
        pt = std::make_shared<Ty>(join(*a.pointee, *b.pointee, contradictions));
    }
    return Ty(kind, width, sgn, std::move(pt), amb);
}

int width_from_demand(uint16_t mask) {
    if (mask == lanes::NONE) return 0;
    if ((mask & ~0x0008u) == 0) return 1;
    if ((mask & ~0x000Cu) == 0) return 2;
    if ((mask & ~0x000Fu) == 0) return 4;
    if ((mask & ~0x00FFu) == 0) return 8;
    return 16;
}

std::unordered_map<std::string, int> TypeMap::counts() const {
    std::unordered_map<std::string, int> out;
    for (const auto &[_, t] : tys_) {
        const char *k = kind_name(t.kind);
        if (t.kind == TyKind::UNK && (t.width == 1 || t.width == 2 || t.width == 4 || t.width == 8)) {
            k = "int";
        }
        ++out[k];
    }
    return out;
}

std::pair<TypeMap, TypeStats> infer(
    const Function &func,
    const std::unordered_map<VarKey, uint16_t> &demand,
    const std::vector<std::vector<VarKey>> &groups,
    const std::function<bool(const u128_t &)> &is_string) {

    std::unordered_map<VarKey, VarKey> rep;
    for (const auto &g : groups) {
        if (g.empty()) continue;
        VarKey r0 = g[0];
        for (VarKey k : g) rep[k] = r0;
    }

    std::unordered_map<VarKey, Ty> ty;
    TypeStats stats;

    auto resolve = [&](VarKey k) -> VarKey {
        auto it = rep.find(k);
        return (it != rep.end()) ? it->second : k;
    };

    auto get_ty = [&](VarKey k) -> const Ty * {
        auto it = ty.find(resolve(k));
        return (it != ty.end()) ? &it->second : nullptr;
    };

    auto add_ty = [&](VarKey k, const Ty &t) -> bool {
        VarKey rk = resolve(k);
        auto it = ty.find(rk);
        if (it == ty.end()) {
            ty.emplace(rk, t);
            return true;
        }
        Ty nw = join(it->second, t, &stats.contradictions);
        if (!nw.same_key(it->second)) {
            it->second = std::move(nw);
            return true;
        }
        return false;
    };

    auto add_val = [&](const Operand &v, const Ty &t) -> bool {
        return v.is_var() ? add_ty(v.key(), t) : false;
    };

    // 1. Seed widths from demand masks (< 16 bytes)
    for (const auto &b : func.blocks) {
        for (const auto &insn : b->insns) {
            if (!insn->defines()) continue;
            auto dit = demand.find(insn->dst_key());
            uint16_t mask = (dit != demand.end()) ? dit->second : lanes::ALL;
            if (mask == lanes::ALL) continue;
            int w = width_from_demand(mask);
            if (w > 0 && w != 16) {
                add_ty(insn->dst_key(), Ty(TyKind::UNK, w));
            }
        }
    }

    // 2. Fixpoint propagation (up to 24 rounds)
    for (int round = 0; round < 24; ++round) {
        bool changed = false;
        for (const auto &b : func.blocks) {
            for (const auto &insn_ptr : b->insns) {
                const Insn &insn = *insn_ptr;
                const Op op = insn.op;
                const bool has_d = insn.defines();
                const VarKey dk = insn.dst_key();
                const auto &srcs = insn.srcs;

                if (op == Op::CONST && has_d && !srcs.empty() && srcs[0].is_const) {
                    if (is_string && is_string(srcs[0].val)) {
                        if (add_ty(dk, ptr_to(Ty(TyKind::INT, 1, true)))) {
                            ++stats.strings;
                            changed = true;
                        }
                    }
                    continue;
                }

                if (op == Op::LOAD && srcs.size() >= 2) {
                    int w = static_cast<int>(insn.ew);
                    if (has_d) changed |= add_ty(dk, Ty(TyKind::UNK, w));
                    changed |= add_val(srcs[1], ptr_to(Ty(TyKind::UNK, w)));
                    continue;
                }
                if (op == Op::STORE && srcs.size() >= 3) {
                    int w = static_cast<int>(insn.ew);
                    changed |= add_val(srcs[1], ptr_to(Ty(TyKind::UNK, w)));
                    changed |= add_val(srcs[2], Ty(TyKind::UNK, w));
                    continue;
                }
                if ((op == Op::LOADQ || op == Op::LOADU) && srcs.size() >= 2) {
                    if (has_d) changed |= add_ty(dk, Ty(TyKind::VEC, 1));
                    changed |= add_val(srcs[1], ptr_to(Ty(TyKind::VEC, 1)));
                    continue;
                }
                if (op == Op::STOREQ && srcs.size() >= 3) {
                    changed |= add_val(srcs[1], ptr_to(Ty(TyKind::VEC, 1)));
                    changed |= add_val(srcs[2], Ty(TyKind::VEC, 1));
                    continue;
                }

                if (is_float_op(op) || is_fcmp_op(op)) {
                    int w = (insn.ew == EW::D) ? 8 : 4;
                    Ty ft(TyKind::FLT, w, true);
                    for (const auto &s : srcs) changed |= add_val(s, ft);
                    if (has_d && is_float_op(op)) changed |= add_ty(dk, ft);
                    continue;
                }
                if ((op == Op::CSFLT || op == Op::CUFLT) && !srcs.empty()) {
                    changed |= add_val(srcs[0], scalar_ty(4, op == Op::CSFLT));
                    if (has_d) changed |= add_ty(dk, Ty(TyKind::FLT, 4, true));
                    continue;
                }
                if (op == Op::DFTSV) {
                    if (!srcs.empty()) changed |= add_val(srcs[0], Ty(TyKind::FLT, 8, true));
                    if (has_d) changed |= add_ty(dk, Ty(TyKind::VEC, 8));
                    continue;
                }
                if ((op == Op::CFLTS || op == Op::CFLTU) && !srcs.empty()) {
                    changed |= add_val(srcs[0], Ty(TyKind::FLT, 4, true));
                    if (has_d) changed |= add_ty(dk, scalar_ty(4, op == Op::CFLTS));
                    continue;
                }

                if (op == Op::CMPGT || op == Op::CMPGTU) {
                    Ty t = scalar_ty(static_cast<int>(insn.ew), op == Op::CMPGT);
                    for (const auto &s : srcs) changed |= add_val(s, t);
                    continue;
                }
                if ((op == Op::SAR || op == Op::SHR) && !srcs.empty()) {
                    Ty t = scalar_ty(static_cast<int>(insn.ew), op == Op::SAR);
                    changed |= add_val(srcs[0], t);
                    if (has_d) changed |= add_ty(dk, t);
                    continue;
                }
                if (op == Op::EXTS && !srcs.empty()) {
                    int w = static_cast<int>(insn.ew);
                    changed |= add_val(srcs[0], scalar_ty(std::max(w / 2, 1), true));
                    if (has_d) changed |= add_ty(dk, scalar_ty(w, true));
                    continue;
                }

                // Pointer arithmetic (no early continue: falls through to lanewise rule too)
                if ((op == Op::ADD || op == Op::SUB) && insn.ew == EW::W && srcs.size() == 2) {
                    for (int i = 0; i < 2; ++i) {
                        if (srcs[i].is_var()) {
                            const Ty *st = get_ty(srcs[i].key());
                            if (st && st->kind == TyKind::PTR && has_d) {
                                Ty copy = *st;
                                changed |= add_ty(dk, copy);
                            }
                        }
                    }
                    if (has_d) {
                        const Ty *td = get_ty(dk);
                        if (td && td->kind == TyKind::PTR) {
                            Ty copy = *td;
                            for (int i = 0; i < 2; ++i) {
                                if (srcs[i].is_const) {
                                    changed |= add_val(srcs[1 - i], copy);
                                }
                            }
                        }
                    }
                }

                if (op == Op::CJMP && !srcs.empty()) {
                    changed |= add_val(srcs[0], Ty(TyKind::UNK, 4));
                    continue;
                }
                if (op == Op::CIJMP && srcs.size() >= 2) {
                    changed |= add_val(srcs[0], Ty(TyKind::UNK, 4));
                    changed |= add_val(srcs[1], Ty(TyKind::UNK, 4));
                    continue;
                }
                if ((op == Op::IJMP || op == Op::ICALL) && !srcs.empty()) {
                    changed |= add_val(srcs[0], Ty(TyKind::UNK, 4));
                    continue;
                }

                if (op == Op::MOV || op == Op::PHI) {
                    if (!has_d) continue;
                    std::optional<Ty> td_copy;
                    if (const Ty *td = get_ty(dk)) td_copy = *td;
                    for (const auto &s : srcs) {
                        if (!s.is_var()) continue;
                        if (const Ty *st = get_ty(s.key())) {
                            Ty scopy = *st;
                            changed |= add_ty(dk, scopy);
                        }
                        if (td_copy.has_value()) {
                            changed |= add_val(s, *td_copy);
                        }
                    }
                    continue;
                }

                if ((op == Op::AND || op == Op::OR || op == Op::XOR || op == Op::NOT ||
                     op == Op::ANDC || op == Op::ORC) && insn.scalar && has_d) {
                    auto dit = demand.find(dk);
                    uint16_t dm = (dit != demand.end()) ? dit->second : lanes::W0;
                    int w = ((dm & ~0x000Fu) != 0 && (dm & ~0x00FFu) == 0) ? 8 : 4;
                    Ty t(TyKind::UNK, w);
                    changed |= add_ty(dk, t);
                    for (const auto &s : srcs) changed |= add_val(s, t);
                    continue;
                }

                if (is_lanewise_op(op) && insn.ew != EW::Q) {
                    int w = static_cast<int>(insn.ew);
                    Ty t = insn.scalar ? scalar_ty(w) : Ty(TyKind::VEC, w);
                    if (has_d) changed |= add_ty(dk, t);
                    for (const auto &s : srcs) changed |= add_val(s, t);
                    continue;
                }

                if (is_quadword_vec_op(op)) {
                    if (has_d) changed |= add_ty(dk, Ty(TyKind::VEC, 1));
                    continue;
                }
            }
        }
        if (!changed) break;
    }

    for (const auto &[_, t] : ty) {
        if (t.ambiguous) ++stats.ambiguous;
    }
    TypeMap tm(std::move(ty), std::move(rep));
    stats.kinds = tm.counts();
    return {std::move(tm), std::move(stats)};
}

} // namespace types
} // namespace spudec
