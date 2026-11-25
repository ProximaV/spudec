#include "spudec/scalarize.hpp"
#include "spudec/database.hpp"
#include "spudec/regs.hpp"
#include "spudec/sem.hpp"
#include <algorithm>
#include <cstdio>
#include <optional>
#include <vector>

namespace spudec {
namespace scalarize {

namespace {

constexpr inline bool is_align_mask(uint32_t w) {
    return w == 0x0003FFF0u || w == 0xFFFFFFF0u;
}

constexpr inline bool is_mem_def_op(Op op) {
    return op == Op::STOREQ || op == Op::STORE || op == Op::SYNC ||
           op == Op::CALL || op == Op::ICALL || op == Op::TCALL;
}

Operand clone_op(const Operand &v) {
    if (v.is_const) return Operand::make_const(v.val, v.ew);
    return Operand::make_var(v.reg, v.ver, v.def_insn);
}

std::unordered_map<VarKey, Insn *> build_defmap(Function &func) {
    std::unordered_map<VarKey, Insn *> m;
    for (auto &b : func.blocks) {
        for (auto &i : b->insns) {
            if (i->defines()) {
                m[i->dst_key()] = i.get();
            }
        }
    }
    return m;
}

bool same_base(bool has_k1, VarKey k1, bool has_k2, VarKey k2,
               const std::unordered_map<VarKey, Insn *> *defs = nullptr,
               int depth = 0) {
    if (!has_k1 && !has_k2) return true;
    if (has_k1 != has_k2) return false;
    if (k1 == k2) return true;
    if (!defs || depth > 4) return false;

    int guard = 0;
    while (guard++ < 16) {
        auto it = defs->find(k1);
        if (it != defs->end() && it->second->op == Op::MOV &&
            !it->second->srcs.empty() && it->second->srcs[0].is_var()) {
            k1 = it->second->srcs[0].key();
        } else {
            break;
        }
    }
    guard = 0;
    while (guard++ < 16) {
        auto it = defs->find(k2);
        if (it != defs->end() && it->second->op == Op::MOV &&
            !it->second->srcs.empty() && it->second->srcs[0].is_var()) {
            k2 = it->second->srcs[0].key();
        } else {
            break;
        }
    }
    if (k1 == k2) return true;

    auto it1 = defs->find(k1);
    auto it2 = defs->find(k2);
    if (it1 == defs->end() || it2 == defs->end()) return false;
    const Insn *d1 = it1->second;
    const Insn *d2 = it2->second;
    if (d1->op == d2->op && d1->ew == d2->ew && d1->srcs.size() == d2->srcs.size() && d1->op == Op::ADD &&
        d1->srcs.size() == 2) {
        auto match_src = [&](const Operand &x, const Operand &y) -> bool {
            if (x.is_var() && y.is_var()) {
                return same_base(true, x.key(), true, y.key(), defs, depth + 1);
            }
            if (x.is_const && y.is_const) {
                return x.val == y.val;
            }
            return false;
        };
        const Operand &a1 = d1->srcs[0], &b1 = d1->srcs[1];
        const Operand &a2 = d2->srcs[0], &b2 = d2->srcs[1];
        if ((match_src(a1, a2) && match_src(b1, b2)) || (match_src(a1, b2) && match_src(b1, a2))) {
            return true;
        }
    }
    return false;
}

bool same_target(const AddrExpr &a, const AddrExpr &b, const std::unordered_map<VarKey, Insn *> *defs = nullptr) {
    return same_base(a.has_base, a.base, b.has_base, b.base, defs) && a.offset == b.offset;
}

bool same_slot(const AddrExpr &a, const AddrExpr &b, const std::unordered_map<VarKey, Insn *> *defs = nullptr) {
    if (same_base(a.has_base, a.base, b.has_base, b.base, defs) && (a.offset & 0xFu) == (b.offset & 0xFu)) {
        return true;
    }
    if (defs && a.has_base && b.has_base) {
        auto it1 = defs->find(a.base);
        auto it2 = defs->find(b.base);
        const Insn *d1 = (it1 != defs->end()) ? it1->second : nullptr;
        const Insn *d2 = (it2 != defs->end()) ? it2->second : nullptr;

        if (d1 && d2 && d1->op == Op::ADD && d2->op == Op::ADD &&
            d1->ew == EW::W && d2->ew == EW::W && d1->srcs.size() == 2 && d2->srcs.size() == 2) {
            for (int p1 = 0; p1 < 2; ++p1) {
                const Operand &idx1 = d1->srcs[p1];
                const Operand &base1 = d1->srcs[1 - p1];
                for (int p2 = 0; p2 < 2; ++p2) {
                    const Operand &idx2 = d2->srcs[p2];
                    const Operand &base2 = d2->srcs[1 - p2];
                    if (idx1.is_var() && idx2.is_var() &&
                        same_base(true, idx1.key(), true, idx2.key(), defs)) {
                        if ((base1.is_var() && base1.reg == regs::SP) ||
                            (base2.is_var() && base2.reg == regs::SP)) {
                            if ((a.offset & 0xFu) == (b.offset & 0xFu)) return true;
                        }
                    }
                }
            }
        }
        if (d1 && d1->op == Op::ADD && d1->ew == EW::W && d1->srcs.size() == 2) {
            for (int p1 = 0; p1 < 2; ++p1) {
                const Operand &idx = d1->srcs[p1];
                const Operand &base = d1->srcs[1 - p1];
                if (idx.is_var() && same_base(true, idx.key(), true, b.base, defs) &&
                    base.is_var() && base.reg == regs::SP &&
                    (a.offset & 0xFu) == (b.offset & 0xFu)) {
                    return true;
                }
            }
        }
        if (d2 && d2->op == Op::ADD && d2->ew == EW::W && d2->srcs.size() == 2) {
            for (int p2 = 0; p2 < 2; ++p2) {
                const Operand &idx = d2->srcs[p2];
                const Operand &base = d2->srcs[1 - p2];
                if (idx.is_var() && same_base(true, idx.key(), true, a.base, defs) &&
                    base.is_var() && base.reg == regs::SP &&
                    (a.offset & 0xFu) == (b.offset & 0xFu)) {
                    return true;
                }
            }
        }
    }
    return false;
}

std::optional<uint32_t> slot_of(const AddrExpr &expr) {
    if (!expr.has_base) return expr.offset & 0xFu;
    if (key_reg(expr.base) == regs::SP) return expr.offset & 0xFu;
    return std::nullopt;
}

bool disjoint_qwords(const AddrExpr &a, const AddrExpr &b, const std::unordered_map<VarKey, Insn *> *defs = nullptr) {
    if (!same_base(a.has_base, a.base, b.has_base, b.base, defs)) return false;
    uint32_t d = a.offset - b.offset;
    uint64_t abs_d = (d >= 0x80000000u) ? (0x100000000ULL - static_cast<uint64_t>(d)) : static_cast<uint64_t>(d);
    return abs_d >= 16ULL;
}

int fresh_reg(Function &func) {
    if (func.scal_tmp == 0) {
        int mx = 0;
        for (const auto &b : func.blocks) {
            for (const auto &i : b->insns) {
                if (i->defines()) mx = std::max(mx, i->dst_reg);
                for (const auto &u : i->srcs) {
                    if (u.is_var()) mx = std::max(mx, u.reg);
                }
            }
        }
        func.scal_tmp = mx + 1;
    }
    return func.scal_tmp++;
}

void insert_before(Block &blk, Insn *target, std::unique_ptr<Insn> nw) {
    nw->block_id = blk.id;
    auto it = std::find_if(blk.insns.begin(), blk.insns.end(),
                           [target](const std::unique_ptr<Insn> &p) { return p.get() == target; });
    blk.insns.insert(it, std::move(nw));
}

void insert_after(Block &blk, Insn *target, std::unique_ptr<Insn> nw) {
    nw->block_id = blk.id;
    auto it = std::find_if(blk.insns.begin(), blk.insns.end(),
                           [target](const std::unique_ptr<Insn> &p) { return p.get() == target; });
    if (it != blk.insns.end()) ++it;
    blk.insns.insert(it, std::move(nw));
}

Operand offset_addr(Function &func, Insn *insn, const Operand &base_val, uint32_t slot,
                    const std::unordered_map<VarKey, Insn *> *defs = nullptr) {
    Operand base = defs ? unaligned_of(base_val, *defs) : base_val;
    if (slot == 0) return clone_op(base);

    int r = fresh_reg(func);
    auto add = func.make_insn(Op::ADD, EW::W, insn->ea);
    add->has_dst = true;
    add->dst_reg = r;
    add->dst_ver = 1;
    add->scalar = true;
    add->srcs = {clone_op(base), Operand::make_const(u128_t::repl(slot, EW::W))};
    char cbuf[48];
    std::snprintf(cbuf, sizeof(cbuf), "byte %u within the quadword", slot);
    add->comment = cbuf;
    Insn *add_ptr = add.get();
    insert_before(*func.blocks[insn->block_id], insn, std::move(add));
    return Operand::make_var(r, 1, add_ptr);
}

Operand effective_addr(const Operand &addr, const AddrExpr &sa, const AddrExpr &ca,
                       const std::unordered_map<VarKey, Insn *> &defs) {
    if (!sa.has_base) {
        uint32_t combined = (sa.offset & ~0xFu) | (ca.offset & 0xFu);
        return Operand::make_const(u128_t::from_word0(combined));
    }
    return clone_op(unaligned_of(addr, defs));
}

std::optional<std::vector<Insn *>> chain_hazards(
    const Operand &store_mem,
    const Operand &load_mem,
    const std::unordered_map<VarKey, Insn *> &defs,
    const AddrExpr &target,
    int limit = 64) {
    std::vector<Insn *> hazards;
    Operand cur = store_mem;
    for (int step = 0; step < limit; ++step) {
        if (!cur.is_var()) return std::nullopt;
        if (cur.key() == load_mem.key()) return hazards;
        auto it = defs.find(cur.key());
        if (it == defs.end()) return std::nullopt;
        Insn *d = it->second;
        if (d->op == Op::PHI) {
            if (cur.key() == store_mem.key()) return hazards;
            return std::nullopt;
        }
        if (!is_mem_def_op(d->op) || d->srcs.empty()) return std::nullopt;
        if ((d->op == Op::STOREQ || d->op == Op::STORE) && d->srcs.size() >= 2) {
            if (!disjoint_qwords(addr_expr(d->srcs[1], defs), target, &defs)) {
                hazards.push_back(d);
            }
        } else {
            hazards.push_back(d);
        }
        cur = d->srcs[0];
    }
    return std::nullopt;
}

struct ShufLink {
    Insn *shuf = nullptr;
    Operand val;
    Insn *ctl = nullptr;
};

bool unwrap_shufb_chain(const Operand &val, const std::unordered_map<VarKey, Insn *> &defs,
                        std::vector<ShufLink> &out_chain, Operand &out_base, int limit = 32) {
    out_chain.clear();
    Operand cur = val;
    for (int step = 0; step < limit; ++step) {
        if (!cur.is_var()) break;
        auto it = defs.find(cur.key());
        if (it == defs.end()) break;
        Insn *shuf = it->second;
        if (shuf->op != Op::SHUFB || shuf->srcs.size() != 3) break;
        const Operand &a = shuf->srcs[0];
        const Operand &b = shuf->srcs[1];
        const Operand &c = shuf->srcs[2];
        if (!c.is_var()) break;
        auto cit = defs.find(c.key());
        if (cit == defs.end() || cit->second->op != Op::GENCTL || cit->second->srcs.empty()) break;
        out_chain.push_back({shuf, a, cit->second});
        cur = b;
    }
    if (out_chain.empty()) return false;
    std::reverse(out_chain.begin(), out_chain.end());
    out_base = cur;
    return true;
}

struct StoreItem {
    Insn *ctl = nullptr;
    Operand val;
    bool has_eff = false;
    Operand eff;
    uint32_t slot = 0;
};

struct StoreMatch {
    Insn *insn = nullptr;
    std::vector<StoreItem> items;
    Insn *ld = nullptr;
    std::vector<Insn *> hazards;
    std::vector<Insn *> shufs;
};

std::optional<StoreMatch> match_store(Insn *insn, const std::unordered_map<VarKey, Insn *> &defs, bool strict) {
    if (insn->srcs.size() < 3) return std::nullopt;
    const Operand &mem = insn->srcs[0];
    const Operand &addr = insn->srcs[1];
    const Operand &val = insn->srcs[2];
    if (!val.is_var()) return std::nullopt;

    std::vector<ShufLink> chain;
    Operand base;
    if (!unwrap_shufb_chain(val, defs, chain, base)) return std::nullopt;

    Insn *ld = nullptr;
    if (base.is_var()) {
        auto it = defs.find(base.key());
        if (it != defs.end()) ld = it->second;
    }
    bool is_loadq = (ld != nullptr && ld->op == Op::LOADQ && ld->srcs.size() >= 2);
    bool is_const0 = (base.is_const && base.val.is_zero()) ||
                     (ld != nullptr && ld->op == Op::CONST && !ld->srcs.empty() &&
                      ld->srcs[0].is_const && ld->srcs[0].val.is_zero());
    if (!is_loadq && !is_const0) return std::nullopt;

    AddrExpr sa = addr_expr(addr, defs);
    if (is_loadq) {
        AddrExpr la = addr_expr(ld->srcs[1], defs);
        if (!(sa.aligned && la.aligned)) return std::nullopt;
        if (!same_target(sa, la, &defs)) return std::nullopt;
    } else {
        if (!sa.aligned) return std::nullopt;
    }

    StoreMatch m;
    m.insn = insn;
    m.ld = is_loadq ? ld : nullptr;
    for (const auto &lnk : chain) {
        m.shufs.push_back(lnk.shuf);
        AddrExpr ca = addr_expr(lnk.ctl->srcs[0], defs);
        StoreItem item;
        item.ctl = lnk.ctl;
        item.val = lnk.val;
        if (same_slot(sa, ca, &defs)) {
            item.has_eff = true;
            item.eff = effective_addr(addr, sa, ca, defs);
        } else {
            auto sl = slot_of(ca);
            if (!sl.has_value()) return std::nullopt;
            item.has_eff = false;
            item.slot = *sl;
        }
        m.items.push_back(std::move(item));
    }

    if (is_loadq) {
        auto hz = chain_hazards(mem, ld->srcs[0], defs, sa);
        if (!hz.has_value()) return std::nullopt;
        if (!hz->empty() && strict) return std::nullopt;
        m.hazards = std::move(*hz);
    }
    return m;
}

struct LoadMatch {
    Insn *insn = nullptr;
    Insn *ld = nullptr;
    bool has_addr = false;
    Operand addr;
    uint32_t slot = 0;
    bool byte_only = false;
};

std::optional<LoadMatch> match_load(Insn *insn, const std::unordered_map<VarKey, Insn *> &defs) {
    if (insn->op != Op::QROTBY || insn->srcs.size() < 2 || !insn->defines()) return std::nullopt;
    const Operand &q = insn->srcs[0];
    const Operand &cnt = insn->srcs[1];
    if (!q.is_var()) return std::nullopt;
    auto it = defs.find(q.key());
    if (it == defs.end() || it->second->op != Op::LOADQ || it->second->srcs.size() < 2) return std::nullopt;
    Insn *ld = it->second;

    AddrExpr la = addr_expr(ld->srcs[1], defs);
    AddrExpr ca = addr_expr(cnt, defs);
    if (!la.aligned) return std::nullopt;

    if (same_slot(la, ca, &defs)) {
        return LoadMatch{insn, ld, true, effective_addr(ld->srcs[1], la, ca, defs), 0, false};
    }
    if (!la.has_base && !ca.has_base) {
        uint32_t combined = (la.offset & ~0xFu) | (ca.offset & 0xFu);
        return LoadMatch{insn, ld, true, Operand::make_const(u128_t::from_word0(combined)), 0, false};
    }
    if (same_base(la.has_base, la.base, ca.has_base, ca.base, &defs)) {
        uint32_t d = ca.offset - la.offset;
        if (d < 16u || d >= 0xFFFFFFF0u) {
            if (!ca.has_base) {
                return LoadMatch{insn, ld, true, Operand::make_const(u128_t::from_word0(ca.offset)), 0, false};
            }
            return LoadMatch{insn, ld, true, clone_op(unaligned_of(cnt, defs)), 0, false};
        }
        if ((la.offset & 0xFu) == 0 && (ca.offset & ~0xFu) == 0) {
            return LoadMatch{insn, ld, false, Operand{}, ca.offset, true};
        }
    }
    auto sl = slot_of(ca);
    if (sl.has_value()) {
        return LoadMatch{insn, ld, false, Operand{}, *sl, false};
    }
    return std::nullopt;
}

std::string format_hazard_comment(const std::vector<Insn *> &hazards) {
    std::string where;
    size_t lim = std::min<size_t>(hazards.size(), 3);
    for (size_t i = 0; i < lim; ++i) {
        if (i > 0) where += ", ";
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(hazards[i]->ea));
        where += buf;
    }
    return "was cwd/lqd/shufb/stqd; assumes no alias with the write at " + where;
}

} // namespace

AddrExpr addr_expr(const Operand &v, const std::unordered_map<VarKey, Insn *> &defs, int limit) {
    uint32_t off = 0;
    bool aligned = false;
    bool saw_add = false;
    Operand cur = v;

    for (int step = 0; step < limit; ++step) {
        if (cur.is_const) {
            off += cur.val.word0();
            return AddrExpr{false, 0, off, aligned || (off & 0xFu) == 0};
        }
        auto it = defs.find(cur.key());
        if (it == defs.end()) {
            return AddrExpr{true, cur.key(), off, aligned};
        }
        Insn *d = it->second;
        if (d->op == Op::MOV && !d->srcs.empty()) {
            cur = d->srcs[0];
            continue;
        }
        if (d->op == Op::CONST && !d->srcs.empty() && d->srcs[0].is_const) {
            off += d->srcs[0].val.word0();
            return AddrExpr{false, 0, off, aligned || (off & 0xFu) == 0};
        }
        if (d->op == Op::AND && d->srcs.size() == 2 && d->srcs[1].is_const &&
            is_align_mask(d->srcs[1].val.word0())) {
            if (saw_add) {
                return AddrExpr{true, cur.key(), off, false};
            }
            aligned = true;
            cur = d->srcs[0];
            continue;
        }
        if (d->op == Op::ADD && d->ew == EW::W && d->srcs.size() == 2) {
            const Operand &a = d->srcs[0];
            const Operand &b = d->srcs[1];
            if (b.is_const) {
                off += b.val.word0();
                saw_add = true;
                cur = a;
                continue;
            }
            if (a.is_const) {
                off += a.val.word0();
                saw_add = true;
                cur = b;
                continue;
            }
        }
        return AddrExpr{true, cur.key(), off, aligned};
    }
    return AddrExpr{cur.is_var(), cur.is_var() ? cur.key() : 0, off, aligned};
}

Operand unaligned_of(const Operand &v, const std::unordered_map<VarKey, Insn *> &defs, int limit) {
    Operand cur = v;
    for (int step = 0; step < limit; ++step) {
        if (cur.is_const) return cur;
        auto it = defs.find(cur.key());
        if (it == defs.end()) return cur;
        Insn *d = it->second;
        if (d->op == Op::MOV && !d->srcs.empty()) {
            cur = d->srcs[0];
            continue;
        }
        if (d->op == Op::AND && d->srcs.size() == 2 && d->srcs[1].is_const &&
            is_align_mask(d->srcs[1].val.word0())) {
            return d->srcs[0];
        }
        return cur;
    }
    return cur;
}

bool hoist_phi_shufb(Function &func) {
    auto defs = build_defmap(func);
    std::unordered_map<int, int> max_ver;
    for (const auto &b : func.blocks) {
        for (const auto &i : b->insns) {
            if (i->defines()) max_ver[i->dst_reg] = std::max(max_ver[i->dst_reg], i->dst_ver);
            for (const auto &s : i->srcs) {
                if (s.is_var()) max_ver[s.reg] = std::max(max_ver[s.reg], s.ver);
            }
        }
    }

    bool changed = false;
    for (auto &b : func.blocks) {
        bool blk_changed = false;
        for (size_t idx = 0; idx < b->insns.size(); ++idx) {
            Insn *insn = b->insns[idx].get();
            if (insn->op != Op::PHI || !insn->defines() || insn->dst_reg == regs::R_MEM) continue;
            if (insn->srcs.size() < 2) continue;

            std::vector<Insn *> shufs;
            shufs.reserve(insn->srcs.size());
            for (const auto &s : insn->srcs) {
                if (!s.is_var()) break;
                auto it = defs.find(s.key());
                if (it == defs.end() || it->second->op != Op::SHUFB || it->second->srcs.size() != 3) break;
                shufs.push_back(it->second);
            }
            if (shufs.size() != insn->srcs.size()) continue;

            Insn *ctl0 = nullptr;
            if (shufs[0]->srcs[2].is_var()) {
                auto it = defs.find(shufs[0]->srcs[2].key());
                if (it != defs.end()) ctl0 = it->second;
            }
            if (!ctl0 || ctl0->op != Op::GENCTL || ctl0->srcs.empty()) continue;
            AddrExpr ca0 = addr_expr(ctl0->srcs[0], defs);
            auto slot0 = slot_of(ca0);

            bool compatible = true;
            for (size_t k = 1; k < shufs.size(); ++k) {
                Insn *ctli = nullptr;
                if (shufs[k]->srcs[2].is_var()) {
                    auto it = defs.find(shufs[k]->srcs[2].key());
                    if (it != defs.end()) ctli = it->second;
                }
                if (!ctli || ctli->op != Op::GENCTL || ctli->ew != ctl0->ew || ctli->srcs.empty()) {
                    compatible = false;
                    break;
                }
                AddrExpr cai = addr_expr(ctli->srcs[0], defs);
                auto sloti = slot_of(cai);
                if (slot0.has_value() && sloti.has_value()) {
                    if (*slot0 != *sloti) {
                        compatible = false;
                        break;
                    }
                } else if (!same_slot(ca0, cai, &defs)) {
                    compatible = false;
                    break;
                }
            }
            if (!compatible) continue;

            Insn *ld0 = nullptr;
            if (shufs[0]->srcs[1].is_var()) {
                auto it = defs.find(shufs[0]->srcs[1].key());
                if (it != defs.end()) ld0 = it->second;
            }
            if (!ld0 || ld0->op != Op::LOADQ || ld0->srcs.size() < 2) continue;
            AddrExpr la0 = addr_expr(ld0->srcs[1], defs);

            for (size_t k = 1; k < shufs.size(); ++k) {
                Insn *ldi = nullptr;
                if (shufs[k]->srcs[1].is_var()) {
                    auto it = defs.find(shufs[k]->srcs[1].key());
                    if (it != defs.end()) ldi = it->second;
                }
                if (!ldi || ldi->op != Op::LOADQ || ldi->srcs.size() < 2) {
                    compatible = false;
                    break;
                }
                AddrExpr lai = addr_expr(ldi->srcs[1], defs);
                if (!same_base(la0.has_base, la0.base, lai.has_base, lai.base, &defs) || la0.offset != lai.offset) {
                    compatible = false;
                    break;
                }
            }
            if (!compatible) continue;

            int target_reg = shufs[0]->srcs[0].is_var() ? shufs[0]->srcs[0].reg
                                                        : (insn->dst_reg > 2 ? insn->dst_reg : 100);
            int nv = ++max_ver[target_reg];

            auto scalar_phi = func.make_insn(Op::PHI, EW::W, insn->ea);
            scalar_phi->has_dst = true;
            scalar_phi->dst_reg = target_reg;
            scalar_phi->dst_ver = nv;
            scalar_phi->block_id = b->id;
            scalar_phi->phi_preds = insn->phi_preds;
            for (Insn *sh : shufs) {
                scalar_phi->srcs.push_back(clone_op(sh->srcs[0]));
            }
            Insn *sphi_ptr = scalar_phi.get();
            defs[sphi_ptr->dst_key()] = sphi_ptr;

            insn->op = Op::SHUFB;
            insn->ew = EW::Q;
            insn->srcs = {Operand::make_var(target_reg, nv, sphi_ptr),
                          clone_op(shufs[0]->srcs[1]),
                          clone_op(shufs[0]->srcs[2])};
            insn->phi_preds.clear();

            b->insns.insert(b->insns.begin() + static_cast<std::ptrdiff_t>(idx), std::move(scalar_phi));
            ++idx; // advance past newly inserted scalar_phi
            changed = true;
            blk_changed = true;
        }
        if (blk_changed) {
            std::stable_partition(b->insns.begin(), b->insns.end(),
                                  [](const std::unique_ptr<Insn> &i) { return i->op == Op::PHI; });
        }
    }
    return changed;
}

std::pair<int, int> recover_stores(Function &func, bool strict) {
    hoist_phi_shufb(func);
    auto defs = build_defmap(func);

    std::vector<StoreMatch> matches;
    for (auto &b : func.blocks) {
        for (auto &i : b->insns) {
            if (i->op == Op::STOREQ) {
                auto m = match_store(i.get(), defs, strict);
                if (m.has_value()) matches.push_back(std::move(*m));
            }
        }
    }

    int max_mem = 0;
    std::unordered_map<int, int> max_ver;
    for (const auto &b : func.blocks) {
        for (const auto &i : b->insns) {
            if (i->defines()) {
                if (i->dst_reg == regs::R_MEM) max_mem = std::max(max_mem, i->dst_ver);
                max_ver[i->dst_reg] = std::max(max_ver[i->dst_reg], i->dst_ver);
            }
            for (const auto &s : i->srcs) {
                if (s.is_var()) {
                    if (s.reg == regs::R_MEM) max_mem = std::max(max_mem, s.ver);
                    max_ver[s.reg] = std::max(max_ver[s.reg], s.ver);
                }
            }
        }
    }

    int n = 0;
    int assumed = 0;
    for (auto &m : matches) {
        Insn *insn = m.insn;
        Operand orig_val = insn->srcs[2];
        Operand base_addr = clone_op(insn->srcs[1]);

        std::vector<Insn *> other_users;
        for (auto &b2 : func.blocks) {
            for (auto &u : b2->insns) {
                if (u.get() == insn) continue;
                for (const auto &s : u->srcs) {
                    if (s.is_var() && s.key() == orig_val.key()) {
                        other_users.push_back(u.get());
                        break;
                    }
                }
            }
        }

        if (m.ld) {
            if (m.ld->defines()) func.store_idiom_roots.insert(m.ld->dst_key());
            for (const auto &s : m.ld->srcs) {
                if (s.is_var()) func.store_idiom_roots.insert(s.key());
            }
        }
        for (Insn *shuf : m.shufs) {
            if (shuf->defines()) func.store_idiom_roots.insert(shuf->dst_key());
            for (const auto &s : shuf->srcs) {
                if (s.is_var()) func.store_idiom_roots.insert(s.key());
            }
        }
        for (const auto &it : m.items) {
            if (it.ctl->defines()) func.store_idiom_roots.insert(it.ctl->dst_key());
            for (const auto &s : it.ctl->srcs) {
                if (s.is_var()) func.store_idiom_roots.insert(s.key());
            }
        }

        Operand cur_mem = insn->srcs[0];
        Block &blk = *func.blocks[insn->block_id];
        for (size_t i = 0; i < m.items.size(); ++i) {
            auto &item = m.items[i];
            Operand eff = item.has_eff ? item.eff : offset_addr(func, insn, base_addr, item.slot, &defs);
            bool is_last = (i + 1 == m.items.size());

            if (!is_last) {
                int next_m = ++max_mem;
                auto new_st = func.make_insn(Op::STORE, item.ctl->ew, insn->ea);
                new_st->has_dst = true;
                new_st->dst_reg = regs::R_MEM;
                new_st->dst_ver = next_m;
                new_st->srcs = {clone_op(cur_mem), eff, clone_op(item.val)};
                if (!m.hazards.empty()) {
                    ++assumed;
                    new_st->comment = format_hazard_comment(m.hazards);
                } else {
                    new_st->comment = "was cwd/lqd/shufb/stqd";
                }
                Insn *st_ptr = new_st.get();
                insert_before(blk, insn, std::move(new_st));
                cur_mem = Operand::make_var(regs::R_MEM, next_m, st_ptr);
            } else {
                insn->op = Op::STORE;
                insn->ew = item.ctl->ew;
                insn->srcs = {clone_op(cur_mem), eff, clone_op(item.val)};
                if (!m.hazards.empty()) {
                    ++assumed;
                    insn->comment = format_hazard_comment(m.hazards);
                } else {
                    insn->comment = "was cwd/lqd/shufb/stqd";
                }
                cur_mem = insn->dst_as_var();
            }
            ++n;
        }

        if (!other_users.empty()) {
            int nv = ++max_ver[orig_val.reg];
            auto reload_insn = func.make_insn(Op::LOADQ, EW::Q, insn->ea);
            reload_insn->has_dst = true;
            reload_insn->dst_reg = orig_val.reg;
            reload_insn->dst_ver = nv;
            reload_insn->srcs = {clone_op(cur_mem), base_addr};
            Insn *rl_ptr = reload_insn.get();
            insert_after(blk, insn, std::move(reload_insn));
            Operand reload_var = Operand::make_var(orig_val.reg, nv, rl_ptr);
            for (Insn *u : other_users) {
                for (auto &s : u->srcs) {
                    if (s.is_var() && s.key() == orig_val.key()) {
                        s = reload_var;
                    }
                }
            }
        }
    }
    return {n, assumed};
}

int recover_loads(Function &func, const std::unordered_map<VarKey, uint16_t> &demand) {
    auto defs = build_defmap(func);
    std::vector<LoadMatch> matches;
    for (auto &b : func.blocks) {
        for (auto &i : b->insns) {
            auto m = match_load(i.get(), defs);
            if (m.has_value()) matches.push_back(std::move(*m));
        }
    }

    int n = 0;
    for (auto &m : matches) {
        auto dit = demand.find(m.insn->dst_key());
        uint16_t mask = (dit != demand.end()) ? dit->second : lanes::ALL;
        EW ew = lanes::narrowest_lead(mask);
        if (m.byte_only && ew != EW::B) {
            continue;
        }
        Operand addr = m.has_addr ? m.addr : offset_addr(func, m.insn, m.ld->srcs[1], m.slot, &defs);
        if (ew != EW::None) {
            m.insn->op = Op::LOAD;
            m.insn->ew = ew;
        } else {
            m.insn->op = Op::LOADU;
            m.insn->ew = EW::Q;
        }
        m.insn->srcs = {clone_op(m.ld->srcs[0]), addr};
        m.insn->comment = "was lqd/rotqby";
        ++n;
    }
    return n;
}

int recover_aligned_loads(Function &func, const std::unordered_map<VarKey, uint16_t> &demand) {
    auto defs = build_defmap(func);
    int n = 0;
    for (auto &b : func.blocks) {
        for (auto &insn : b->insns) {
            if (insn->op != Op::LOADQ || !insn->defines() || insn->srcs.size() < 2) continue;
            auto dit = demand.find(insn->dst_key());
            uint16_t mask = (dit != demand.end()) ? dit->second : lanes::ALL;
            if (mask == lanes::NONE || (mask & ~lanes::W0) != 0) continue;
            AddrExpr a = addr_expr(insn->srcs[1], defs);
            if (!a.aligned) continue;
            insn->op = Op::LOAD;
            insn->ew = EW::W;
            insn->comment = "aligned word load";
            ++n;
        }
    }
    return n;
}

int propagate_scalar_slots(Function &func, const std::unordered_map<VarKey, uint16_t> &demand) {
    auto defs = build_defmap(func);
    int n = 0;
    for (auto &b : func.blocks) {
        for (auto &insn : b->insns) {
            if (insn->op != Op::SHUFB || insn->srcs.size() != 3 || !insn->defines()) continue;
            const Operand &val = insn->srcs[0];
            const Operand &old = insn->srcs[1];
            const Operand &ctl = insn->srcs[2];
            if (!ctl.is_var()) continue;
            auto cit = defs.find(ctl.key());
            if (cit == defs.end() || cit->second->op != Op::GENCTL || cit->second->srcs.empty()) continue;
            Insn *ctl_def = cit->second;
            auto sl = slot_of(addr_expr(ctl_def->srcs[0], defs));
            if (!sl.has_value()) continue;

            const Operand *target = nullptr;
            if (*sl >= 4 && old.is_var()) {
                target = &old;
            } else if (*sl == 0 && ctl_def->ew == EW::W) {
                target = &val;
            }
            if (!target) continue;

            const VarKey dst_k = insn->dst_key();
            auto dit = demand.find(dst_k);
            const uint16_t dst_mask = (dit != demand.end()) ? dit->second : lanes::ALL;
            const bool dst_is_scalar = lanes::is_scalar(dst_mask);

            for (auto &b2 : func.blocks) {
                for (auto &user : b2->insns) {
                    if (user.get() == insn.get()) continue;
                    bool user_is_scalar = false;
                    if (user->defines()) {
                        auto udit = demand.find(user->dst_key());
                        if (udit != demand.end() && lanes::is_scalar(udit->second)) {
                            user_is_scalar = true;
                        }
                    } else if (user->op == Op::CJMP || user->op == Op::CIJMP) {
                        user_is_scalar = true;
                    }
                    if (!dst_is_scalar && !user_is_scalar) continue;
                    for (auto &u : user->srcs) {
                        if (u.is_var() && u.key() == dst_k) {
                            if ((op_infix(user->op) != nullptr && user->ew == EW::W && user_is_scalar) || dst_is_scalar) {
                                u = clone_op(*target);
                                ++n;
                            }
                        }
                    }
                }
            }
        }
    }
    return n;
}

namespace {

Insn *peel_mov(const Operand &v, const std::unordered_map<VarKey, Insn *> &defs) {
    if (!v.is_var()) return nullptr;
    auto it = defs.find(v.key());
    int guard = 0;
    while (it != defs.end() && it->second->op == Op::MOV && !it->second->srcs.empty() && guard++ < 16) {
        const Operand &s = it->second->srcs[0];
        if (!s.is_var()) return nullptr;
        it = defs.find(s.key());
    }
    return (it != defs.end()) ? it->second : nullptr;
}

bool same_operand_val(const Operand &a, const Operand &b, const std::unordered_map<VarKey, Insn *> &defs) {
    if (a.is_const && b.is_const) return a.val == b.val;
    if (a.is_var() && b.is_var()) return same_base(true, a.key(), true, b.key(), &defs);
    return false;
}

std::optional<u128_t> read_qword_mask(const Operand &op,
                                      const std::unordered_map<VarKey, Insn *> &defs,
                                      const IDatabaseProvider *db) {
    if (op.is_const) return op.val;
    Operand cur = op;
    int guard = 0;
    while (cur.is_var() && guard++ < 16) {
        auto it = defs.find(cur.key());
        if (it == defs.end()) return std::nullopt;
        const Insn *d = it->second;
        if (d->op == Op::MOV && !d->srcs.empty()) {
            cur = d->srcs[0];
            if (cur.is_const) return cur.val;
            continue;
        }
        if (d->op == Op::CONST && !d->srcs.empty() && d->srcs[0].is_const) {
            return d->srcs[0].val;
        }
        if (d->op == Op::LOADQ && d->srcs.size() >= 2 && db != nullptr) {
            AddrExpr ae = addr_expr(d->srcs[1], defs);
            if (!ae.has_base) {
                uint8_t buf[16]{};
                if (db->read_bytes(ae.offset, buf, 16) == 16) {
                    uint64_t hi = 0, lo = 0;
                    for (int i = 0; i < 8; ++i) {
                        hi = (hi << 8) | buf[i];
                        lo = (lo << 8) | buf[8 + i];
                    }
                    return u128_t(hi, lo);
                }
            }
        }
        return std::nullopt;
    }
    return cur.is_const ? std::optional<u128_t>(cur.val) : std::nullopt;
}

bool is_carry_word1_mask(const u128_t &m, bool expect_ones_pad) {
    if (m.byte_lane(0) != 0x04 || m.byte_lane(1) != 0x05 ||
        m.byte_lane(2) != 0x06 || m.byte_lane(3) != 0x07) {
        return false;
    }
    uint8_t b7 = m.byte_lane(7);
    if (expect_ones_pad) {
        return (b7 & 0xE0u) == 0xC0u;
    }
    return (b7 & 0xC0u) == 0x80u;
}

} // namespace

int fold_u64_arith(Function &func, const IDatabaseProvider *db) {
    auto defs = build_defmap(func);
    int n = 0;
    for (auto &b : func.blocks) {
        for (auto &insn : b->insns) {
            if (insn->ew != EW::W || insn->srcs.size() != 3) continue;
            if (insn->op != Op::ADDX && insn->op != Op::SUBX) continue;

            Insn *sh = peel_mov(insn->srcs[2], defs);
            if (!sh || sh->op != Op::SHUFB || sh->srcs.size() != 3) continue;

            Insn *cbg = peel_mov(sh->srcs[0], defs);
            if (!cbg || cbg->ew != EW::W || cbg->srcs.size() != 2) continue;

            if (insn->op == Op::ADDX) {
                if (cbg->op != Op::CG) continue;
                bool match_pair =
                    (same_operand_val(cbg->srcs[0], insn->srcs[0], defs) &&
                     same_operand_val(cbg->srcs[1], insn->srcs[1], defs)) ||
                    (same_operand_val(cbg->srcs[0], insn->srcs[1], defs) &&
                     same_operand_val(cbg->srcs[1], insn->srcs[0], defs));
                if (!match_pair) continue;

                auto mask = read_qword_mask(sh->srcs[2], defs, db);
                if (!mask.has_value() || !is_carry_word1_mask(*mask, false)) continue;

                insn->op = Op::ADD;
                insn->ew = EW::D;
                insn->srcs = {clone_op(insn->srcs[0]), clone_op(insn->srcs[1])};
                insn->scalar = true;
                insn->comment = "64-bit add (cg/shufb/addx)";
                ++n;
            } else {
                if (cbg->op != Op::BG) continue;
                // Lifter emits SUBX(rb, ra, rt) where `sfx rt, ra, rb` computes `rb - ra - borrow`.
                // `bg rt, ra, rb` produces `BG(ra, rb)`, i.e. `cbg->srcs = {insn->srcs[1], insn->srcs[0]}`.
                if (!(same_operand_val(cbg->srcs[0], insn->srcs[1], defs) &&
                      same_operand_val(cbg->srcs[1], insn->srcs[0], defs))) {
                    continue;
                }

                auto mask = read_qword_mask(sh->srcs[2], defs, db);
                if (!mask.has_value() || !is_carry_word1_mask(*mask, true)) continue;

                insn->op = Op::SUB;
                insn->ew = EW::D;
                insn->srcs = {clone_op(insn->srcs[0]), clone_op(insn->srcs[1])};
                insn->scalar = true;
                insn->comment = "64-bit sub (bg/shufb/sfx)";
                ++n;
            }
        }
    }
    return n;
}

int prune_dead_shufb_inputs(Function &func,
                            const std::unordered_map<VarKey, uint16_t> &demand,
                            const IDatabaseProvider *db) {
    auto defs = build_defmap(func);
    int n = 0;
    for (auto &b : func.blocks) {
        for (auto &insn : b->insns) {
            if (insn->op != Op::SHUFB || insn->srcs.size() != 3) continue;

            std::optional<u128_t> ctl = read_qword_mask(insn->srcs[2], defs, db);
            if (!ctl.has_value()) {
                if (Insn *gd = peel_mov(insn->srcs[2], defs); gd && gd->op == Op::GENCTL && !gd->srcs.empty()) {
                    AddrExpr ca = addr_expr(gd->srcs[0], defs);
                    if (!ca.has_base || key_reg(ca.base) == regs::SP || ca.aligned) {
                        ctl = sem::genctl(ca.offset & 0xFu, gd->ew);
                    }
                }
            }
            if (!ctl.has_value()) continue;

            uint16_t out_mask = lanes::NONE;
            if (insn->defines()) {
                auto dit = demand.find(insn->dst_key());
                if (dit != demand.end()) out_mask = dit->second;
            }

            uint16_t da = 0, db_mask = 0;
            for (int i = 0; i < 16; ++i) {
                if (((out_mask >> i) & 1u) == 0) continue;
                uint8_t cb = ctl->byte_lane(i);
                if ((cb & 0xC0u) == 0x80u || (cb & 0xE0u) == 0xC0u || (cb & 0xE0u) == 0xE0u) {
                    continue;
                }
                uint8_t idx = cb & 0x1Fu;
                if (idx < 16) da |= static_cast<uint16_t>(1u << idx);
                else db_mask |= static_cast<uint16_t>(1u << (idx - 16));
            }

            if (da == 0 && !insn->srcs[0].is_const) {
                insn->srcs[0] = Operand::make_const(u128_t::zero());
                ++n;
            }
            if (db_mask == 0 && !insn->srcs[1].is_const) {
                insn->srcs[1] = Operand::make_const(u128_t::zero());
                ++n;
            }
        }
    }
    return n;
}

int mark_scalars(Function &func, const std::unordered_map<VarKey, uint16_t> &demand) {
    int n = 0;
    for (auto &b : func.blocks) {
        for (auto &insn : b->insns) {
            if (!insn->defines()) continue;
            auto dit = demand.find(insn->dst_key());
            uint16_t mask = (dit != demand.end()) ? dit->second : lanes::NONE;
            if (mask == lanes::NONE) continue;
            const bool sc32 = lanes::is_scalar(mask);
            const bool sc64 = lanes::fits_lead(mask, EW::D);
            if (!sc32 && !sc64) continue;

            if (insn->op == Op::CONST || insn->op == Op::MOV) {
                insn->scalar = true;
                ++n;
            } else if (op_infix(insn->op) != nullptr && insn->srcs.size() == 2) {
                bool is_bitwise = (insn->op == Op::AND || insn->op == Op::OR ||
                                   insn->op == Op::XOR || insn->op == Op::ANDC ||
                                   insn->op == Op::ORC);
                if ((insn->ew == EW::W && sc32) ||
                    (insn->ew == EW::D && sc64) ||
                    (is_bitwise && sc64)) {
                    insn->scalar = true;
                    ++n;
                }
            } else if (insn->op == Op::NOT && insn->srcs.size() == 1 && sc64) {
                insn->scalar = true;
                ++n;
            }
        }
    }
    return n;
}

ScalarizeStats scalarize(Function &func,
                       const lanes::CalleeDemandFn &callee,
                       bool strict,
                       const IDatabaseProvider *db) {
    ScalarizeStats stats;
    auto [st, assumed] = recover_stores(func, strict);
    stats.stores = st;
    stats.assumed_noalias = assumed;

    fold_u64_arith(func, db);

    auto demand = lanes::compute_demand(func, callee);
    if (prune_dead_shufb_inputs(func, demand, db) > 0) {
        demand = lanes::compute_demand(func, callee);
    }
    stats.loads = recover_loads(func, demand);

    demand = lanes::compute_demand(func, callee);
    stats.aligned_loads = recover_aligned_loads(func, demand);

    demand = lanes::compute_demand(func, callee);
    propagate_scalar_slots(func, demand);

    demand = lanes::compute_demand(func, callee);
    stats.scalars = mark_scalars(func, demand);
    func.demand = std::move(demand);
    return stats;
}

} // namespace scalarize
} // namespace spudec
