#include "spudec/ssa.hpp"
#include <algorithm>
#include <cstdio>
#include <unordered_map>
#include <unordered_set>

namespace spudec {
namespace ssa {

std::vector<int> reverse_postorder(const Function &func) {
    std::vector<int> order;
    if (func.entry_id < 0 || func.entry_id >= static_cast<int>(func.blocks.size())) {
        return order;
    }
    const size_t nb = func.blocks.size();
    BitVec seen(nb);
    struct Frame {
        int blk_id;
        size_t next_idx;
    };
    std::vector<Frame> stack;
    stack.reserve(nb);
    seen.set(static_cast<size_t>(func.entry_id));
    stack.push_back({func.entry_id, 0});

    while (!stack.empty()) {
        auto &top = stack.back();
        const auto &succs = func.blocks[top.blk_id]->succs;
        bool advanced = false;
        while (top.next_idx < succs.size()) {
            int sid = succs[top.next_idx++];
            if (sid >= 0 && static_cast<size_t>(sid) < nb && !seen.test(static_cast<size_t>(sid))) {
                seen.set(static_cast<size_t>(sid));
                stack.push_back({sid, 0});
                advanced = true;
                break;
            }
        }
        if (!advanced) {
            order.push_back(top.blk_id);
            stack.pop_back();
        }
    }
    std::reverse(order.begin(), order.end());
    return order;
}

std::vector<int> compute_dominators(Function &func) {
    std::vector<int> rpo = reverse_postorder(func);
    const int nb = static_cast<int>(func.blocks.size());
    for (auto &b : func.blocks) {
        b->idom = -1;
        b->dom_children.clear();
    }
    if (rpo.empty() || func.entry_id < 0 || func.entry_id >= nb) {
        return rpo;
    }

    std::vector<int> rpo_num(nb, -1);
    for (int i = 0; i < static_cast<int>(rpo.size()); ++i) {
        rpo_num[rpo[i]] = i;
    }

    const int entry = func.entry_id;
    func.blocks[entry]->idom = entry;

    auto intersect = [&](int a, int b) -> int {
        while (a != b) {
            while (rpo_num[a] > rpo_num[b]) a = func.blocks[a]->idom;
            while (rpo_num[b] > rpo_num[a]) b = func.blocks[b]->idom;
        }
        return a;
    };

    bool changed = true;
    while (changed) {
        changed = false;
        for (int bid : rpo) {
            if (bid == entry) continue;
            Block *b = func.blocks[bid].get();
            int new_idom = -1;
            for (int pid : b->preds) {
                if (pid < 0 || pid >= nb) continue;
                if (func.blocks[pid]->idom < 0 || rpo_num[pid] < 0) continue;
                new_idom = (new_idom < 0) ? pid : intersect(pid, new_idom);
            }
            if (new_idom >= 0 && b->idom != new_idom) {
                b->idom = new_idom;
                changed = true;
            }
        }
    }

    for (auto &b : func.blocks) {
        if (b->idom >= 0 && b->id != entry) {
            func.blocks[b->idom]->dom_children.push_back(b->id);
        }
    }
    return rpo;
}

void compute_dominance_frontiers(Function &func) {
    const int nb = static_cast<int>(func.blocks.size());
    std::vector<BitVec> df_bits(nb, BitVec(static_cast<size_t>(nb)));
    for (auto &b : func.blocks) {
        b->domfront.clear();
    }
    for (auto &b : func.blocks) {
        if (b->preds.size() < 2) continue;
        for (int pid : b->preds) {
            int runner = pid;
            while (runner >= 0 && runner != b->idom) {
                df_bits[runner].set(static_cast<size_t>(b->id));
                int next = func.blocks[runner]->idom;
                if (next == runner) break; // reached entry
                runner = next;
            }
        }
    }
    for (int i = 0; i < nb; ++i) {
        df_bits[i].for_each_set([&](size_t bit) {
            func.blocks[i]->domfront.push_back(static_cast<int>(bit));
        });
    }
}

std::vector<int> compute_postdominators(const Function &func) {
    const int nb = static_cast<int>(func.blocks.size());
    std::vector<int> result(nb, IPDOM_UNREACHABLE);
    if (nb == 0) return result;

    std::vector<int> exits;
    for (const auto &b : func.blocks) {
        bool is_ret_or_stop = !b->insns.empty() &&
                              (b->insns.back()->op == Op::RET || b->insns.back()->op == Op::STOP);
        if (b->succs.empty() || is_ret_or_stop) {
            exits.push_back(b->id);
        }
    }
    if (exits.empty()) {
        exits.push_back(func.blocks.back()->id);
    }

    const int EXIT = nb;
    const int total = nb + 1;
    std::vector<std::vector<int>> rsucc(total);
    std::vector<std::vector<int>> rpred(total);
    rsucc[EXIT] = exits;
    for (const auto &b : func.blocks) {
        rsucc[b->id] = b->preds;
        rpred[b->id] = b->succs;
    }
    for (int eid : exits) {
        rpred[eid].push_back(EXIT);
    }

    std::vector<int> order;
    order.reserve(total);
    BitVec seen(static_cast<size_t>(total));
    struct Frame {
        int nd;
        size_t idx;
    };
    std::vector<Frame> stack;
    seen.set(static_cast<size_t>(EXIT));
    stack.push_back({EXIT, 0});
    while (!stack.empty()) {
        auto &top = stack.back();
        const auto &succs = rsucc[top.nd];
        bool advanced = false;
        while (top.idx < succs.size()) {
            int s = succs[top.idx++];
            if (s >= 0 && s < total && !seen.test(static_cast<size_t>(s))) {
                seen.set(static_cast<size_t>(s));
                stack.push_back({s, 0});
                advanced = true;
                break;
            }
        }
        if (!advanced) {
            order.push_back(top.nd);
            stack.pop_back();
        }
    }
    std::reverse(order.begin(), order.end());

    std::vector<int> num(total, -1);
    for (int i = 0; i < static_cast<int>(order.size()); ++i) {
        num[order[i]] = i;
    }

    std::vector<int> ipdom(total, -1);
    ipdom[EXIT] = EXIT;

    auto intersect = [&](int a, int b) -> int {
        while (a != b) {
            while (num[a] > num[b]) a = ipdom[a];
            while (num[b] > num[a]) b = ipdom[b];
        }
        return a;
    };

    bool changed = true;
    while (changed) {
        changed = false;
        for (int nd : order) {
            if (nd == EXIT) continue;
            int nw = -1;
            for (int p : rpred[nd]) {
                if (p < 0 || p >= total) continue;
                if (ipdom[p] < 0 || num[p] < 0) continue;
                nw = (nw < 0) ? p : intersect(p, nw);
            }
            if (nw >= 0 && ipdom[nd] != nw) {
                ipdom[nd] = nw;
                changed = true;
            }
        }
    }

    for (int i = 0; i < nb; ++i) {
        if (ipdom[i] < 0) {
            result[i] = IPDOM_UNREACHABLE;
        } else if (ipdom[i] == EXIT) {
            result[i] = IPDOM_EXIT;
        } else {
            result[i] = ipdom[i];
        }
    }
    return result;
}

bool dominates(const Function &func, int a_id, int b_id) {
    const int nb = static_cast<int>(func.blocks.size());
    if (a_id < 0 || a_id >= nb || b_id < 0 || b_id >= nb) return false;
    int cur = b_id;
    while (cur >= 0 && cur < nb) {
        if (cur == a_id) return true;
        int next = func.blocks[cur]->idom;
        if (next == cur) return false;
        cur = next;
    }
    return false;
}

int insert_phis(Function &func) {
    const int nb = static_cast<int>(func.blocks.size());
    if (nb == 0) return 0;

    std::unordered_set<int> globals_set;
    std::unordered_map<int, BitVec> defsites;
    std::unordered_set<int> killed;

    for (const auto &b : func.blocks) {
        killed.clear();
        for (const auto &insn : b->insns) {
            for (const auto &u : insn->srcs) {
                if (u.is_var() && killed.find(u.reg) == killed.end()) {
                    globals_set.insert(u.reg);
                }
            }
            if (insn->defines()) {
                killed.insert(insn->dst_reg);
                auto &bv = defsites[insn->dst_reg];
                if (bv.empty()) bv.resize(static_cast<size_t>(nb));
                bv.set(static_cast<size_t>(b->id));
            }
        }
    }

    std::vector<int> globals(globals_set.begin(), globals_set.end());
    std::sort(globals.begin(), globals.end());

    int count = 0;
    BitVec placed(static_cast<size_t>(nb));
    std::vector<int> work;

    for (int reg : globals) {
        auto it = defsites.find(reg);
        if (it == defsites.end()) continue;
        const BitVec &sites = it->second;
        placed.clear_all();
        work.clear();
        sites.for_each_set([&](size_t bid) { work.push_back(static_cast<int>(bid)); });

        while (!work.empty()) {
            int bid = work.back();
            work.pop_back();
            for (int df_id : func.blocks[bid]->domfront) {
                if (placed.test(static_cast<size_t>(df_id))) continue;
                placed.set(static_cast<size_t>(df_id));

                Block *df = func.blocks[df_id].get();
                auto phi = func.make_insn(Op::PHI, EW::W, df->start_ea);
                phi->has_dst = true;
                phi->dst_reg = reg;
                phi->dst_ver = -1;
                phi->block_id = df_id;
                phi->srcs.reserve(df->preds.size());
                for (size_t k = 0; k < df->preds.size(); ++k) {
                    phi->srcs.push_back(Operand::make_var(reg));
                }
                phi->phi_preds = df->preds;
                df->insns.insert(df->insns.begin(), std::move(phi));
                ++count;

                if (!sites.test(static_cast<size_t>(df_id))) {
                    work.push_back(df_id);
                }
            }
        }
    }
    return count;
}

void rename(Function &func) {
    if (func.entry_id < 0 || func.entry_id >= static_cast<int>(func.blocks.size())) return;

    struct VerEntry {
        int ver;
        Insn *def_insn;
    };
    std::unordered_map<int, std::vector<VerEntry>> stacks;
    std::unordered_map<int, int> counter;

    auto top = [&](int reg) -> VerEntry {
        auto &st = stacks[reg];
        if (st.empty()) {
            st.push_back({0, nullptr});
            counter.emplace(reg, 0);
        }
        return st.back();
    };

    constexpr int ENTER = 0;
    constexpr int EXIT = 1;
    std::vector<std::vector<int>> scope(func.blocks.size());
    std::vector<std::pair<int, int>> work;
    work.push_back({func.entry_id, ENTER});

    while (!work.empty()) {
        auto [bid, phase] = work.back();
        work.pop_back();

        if (phase == EXIT) {
            for (int reg : scope[bid]) {
                stacks[reg].pop_back();
            }
            scope[bid].clear();
            continue;
        }

        Block *blk = func.blocks[bid].get();
        std::vector<int> pushed;
        for (auto &insn : blk->insns) {
            if (insn->op != Op::PHI) {
                for (auto &u : insn->srcs) {
                    if (u.is_var()) {
                        VerEntry cur = top(u.reg);
                        u.ver = cur.ver;
                        u.def_insn = cur.def_insn;
                    }
                }
            }
            if (insn->defines()) {
                int reg = insn->dst_reg;
                int n = ++counter[reg];
                insn->dst_ver = n;
                auto &st = stacks[reg];
                if (st.empty()) st.push_back({0, nullptr});
                st.push_back({n, insn.get()});
                pushed.push_back(reg);
            }
        }

        // Populate corresponding slot(s) in each successor's phi nodes.
        for (int sid : blk->succs) {
            Block *s = func.blocks[sid].get();
            for (size_t j = 0; j < s->preds.size(); ++j) {
                if (s->preds[j] != bid) continue;
                for (auto &phi : s->insns) {
                    if (phi->op != Op::PHI) break;
                    if (j < phi->srcs.size()) {
                        auto &src = phi->srcs[j];
                        VerEntry cur = top(src.reg);
                        src.ver = cur.ver;
                        src.def_insn = cur.def_insn;
                    }
                }
            }
        }

        scope[bid] = std::move(pushed);
        work.push_back({bid, EXIT});
        for (int cid : blk->dom_children) {
            work.push_back({cid, ENTER});
        }
    }
}

void to_ssa(Function &func) {
    if (func.ssa) return;
    // If the entry block is itself a branch/loop target (has incoming predecessors),
    // insert a synthetic pre-entry block so the implicit function-entry edge is explicit
    // in dominance frontiers, PHI placement, and SSA renaming.
    if (func.entry_id >= 0 && func.entry_id < static_cast<int>(func.blocks.size()) &&
        !func.blocks[func.entry_id]->preds.empty()) {
        int orig_id = func.entry_id;
        uint64_t entry_ea = func.blocks[orig_id]->start_ea;
        Block *pre = func.new_block(entry_ea, entry_ea);
        auto jmp = func.make_insn(Op::JMP, EW::W, entry_ea);
        jmp->has_aux = true;
        jmp->aux_ea = entry_ea;
        jmp->comment = "entry preheader";
        pre->add(std::move(jmp));
        pre->succs.push_back(orig_id);
        Block *orig = func.blocks[orig_id].get();
        orig->preds.insert(orig->preds.begin(), pre->id);
        func.entry_id = pre->id;
    }
    compute_dominators(func);
    compute_dominance_frontiers(func);
    insert_phis(func);
    rename(func);
    func.ssa = true;
}

std::vector<std::string> verify(const Function &func) {
    std::vector<std::string> problems;
    std::unordered_map<VarKey, std::pair<const Insn *, int>> defs;

    for (const auto &b : func.blocks) {
        for (const auto &insn : b->insns) {
            if (!insn->defines()) continue;
            VarKey k = insn->dst_key();
            if (defs.find(k) != defs.end()) {
                char buf[128];
                std::snprintf(buf, sizeof(buf), "0x%llX: %s defined twice",
                              static_cast<unsigned long long>(insn->ea),
                              insn->dst_as_var().str().c_str());
                problems.emplace_back(buf);
            }
            defs[k] = {insn.get(), b->id};
        }
    }

    for (const auto &b : func.blocks) {
        bool seen_nonphi = false;
        for (const auto &insn : b->insns) {
            if (insn->op == Op::PHI) {
                if (seen_nonphi) {
                    char buf[64];
                    std::snprintf(buf, sizeof(buf), "B%d: phi after a non-phi", b->id);
                    problems.emplace_back(buf);
                }
                if (insn->srcs.size() != b->preds.size()) {
                    char buf[128];
                    std::snprintf(buf, sizeof(buf), "B%d: phi for %s has %zu args but %zu preds",
                                  b->id, insn->dst_as_var().str().c_str(),
                                  insn->srcs.size(), b->preds.size());
                    problems.emplace_back(buf);
                }
            } else {
                seen_nonphi = true;
            }

            for (size_t idx = 0; idx < insn->srcs.size(); ++idx) {
                const auto &u = insn->srcs[idx];
                if (!u.is_var() || u.ver == 0) continue;
                auto it = defs.find(u.key());
                if (it == defs.end()) {
                    char buf[128];
                    std::snprintf(buf, sizeof(buf), "0x%llX: use of %s with no definition",
                                  static_cast<unsigned long long>(insn->ea), u.str().c_str());
                    problems.emplace_back(buf);
                    continue;
                }
                int dblk_id = it->second.second;
                if (insn->op == Op::PHI) {
                    int pred_id = (idx < insn->phi_preds.size())
                                      ? insn->phi_preds[idx]
                                      : (idx < b->preds.size() ? b->preds[idx] : -1);
                    if (!dominates(func, dblk_id, pred_id)) {
                        char buf[128];
                        std::snprintf(buf, sizeof(buf), "B%d: phi arg %s not available from B%d",
                                      b->id, u.str().c_str(), pred_id);
                        problems.emplace_back(buf);
                    }
                } else if (!dominates(func, dblk_id, b->id)) {
                    char buf[128];
                    std::snprintf(buf, sizeof(buf), "0x%llX: use of %s not dominated by its definition",
                                  static_cast<unsigned long long>(insn->ea), u.str().c_str());
                    problems.emplace_back(buf);
                }
            }
        }
        if (!b->insns.empty() && !b->insns.back()->is_terminator()) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "B%d: no terminator", b->id);
            problems.emplace_back(buf);
        }
    }
    return problems;
}

} // namespace ssa
} // namespace spudec
