#include "spudec/outssa.hpp"
#include "spudec/ssa.hpp"
#include <algorithm>
#include <unordered_map>
#include <vector>

namespace spudec {
namespace outssa {

namespace {

void liveness_uses(const Insn &insn, const CallArgsMap *call_args, std::vector<VarKey> &out) {
    out.clear();
    int leading = 0;
    if (!op_is_abi(insn.op, &leading)) {
        for (const auto &s : insn.srcs) {
            if (s.is_var()) out.push_back(s.key());
        }
        return;
    }
    for (int i = 0; i < leading && i < static_cast<int>(insn.srcs.size()); ++i) {
        if (insn.srcs[i].is_var()) out.push_back(insn.srcs[i].key());
    }
    if (insn.op == Op::RET) return;

    if (call_args) {
        auto it = call_args->find(insn.uid);
        if (it != call_args->end()) {
            for (const auto &a : it->second) {
                if (a.is_var()) out.push_back(a.key());
            }
            return;
        }
    }
    // Unknown arity: conservatively keep the remaining operands live.
    for (size_t i = static_cast<size_t>(leading); i < insn.srcs.size(); ++i) {
        if (insn.srcs[i].is_var()) out.push_back(insn.srcs[i].key());
    }
}

struct DenseVars {
    std::vector<VarKey> keys;
    std::unordered_map<VarKey, size_t> index_of;
};

DenseVars collect_dense_vars(const Function &func) {
    DenseVars dv;
    std::unordered_set<VarKey> seen;
    for (const auto &b : func.blocks) {
        for (const auto &ins : b->insns) {
            if (ins->defines()) seen.insert(ins->dst_key());
            for (const auto &u : ins->srcs) {
                if (u.is_var()) seen.insert(u.key());
            }
        }
    }
    dv.keys.assign(seen.begin(), seen.end());
    std::sort(dv.keys.begin(), dv.keys.end(), [](VarKey a, VarKey b) {
        int ra = key_reg(a), rb = key_reg(b);
        if (ra != rb) return ra < rb;
        return key_ver(a) < key_ver(b);
    });
    dv.index_of.reserve(dv.keys.size() * 2 + 1);
    for (size_t i = 0; i < dv.keys.size(); ++i) {
        dv.index_of[dv.keys[i]] = i;
    }
    return dv;
}

std::vector<BitVec> compute_dense_live_out(const Function &func, const DenseVars &dv, const CallArgsMap *call_args) {
    const size_t nb = func.blocks.size();
    const size_t nv = dv.keys.size();
    std::vector<BitVec> use_of(nb, BitVec(nv));
    std::vector<BitVec> def_of(nb, BitVec(nv));
    std::unordered_map<uint64_t, BitVec> edge_use;

    auto make_edge = [](int p, int s) -> uint64_t {
        return (static_cast<uint64_t>(static_cast<uint32_t>(p)) << 32) |
               static_cast<uint64_t>(static_cast<uint32_t>(s));
    };

    std::vector<VarKey> uses_buf;
    uses_buf.reserve(160);

    for (const auto &b : func.blocks) {
        BitVec &u = use_of[b->id];
        BitVec &d = def_of[b->id];
        for (const auto &ins : b->insns) {
            if (ins->op == Op::PHI) {
                if (ins->defines()) {
                    d.set(dv.index_of.at(ins->dst_key()));
                }
                size_t lim = std::min(ins->srcs.size(), b->preds.size());
                for (size_t j = 0; j < lim; ++j) {
                    if (ins->srcs[j].is_var()) {
                        auto &eb = edge_use[make_edge(b->preds[j], b->id)];
                        if (eb.empty()) eb.resize(nv);
                        eb.set(dv.index_of.at(ins->srcs[j].key()));
                    }
                }
                continue;
            }
            liveness_uses(*ins, call_args, uses_buf);
            for (VarKey k : uses_buf) {
                size_t ki = dv.index_of.at(k);
                if (!d.test(ki)) u.set(ki);
            }
            if (ins->defines()) {
                d.set(dv.index_of.at(ins->dst_key()));
            }
        }
    }

    std::vector<BitVec> live_in(nb, BitVec(nv));
    std::vector<BitVec> live_out(nb, BitVec(nv));
    BitVec out_tmp(nv);
    BitVec inn_tmp(nv);

    bool changed = true;
    while (changed) {
        changed = false;
        for (auto bit = func.blocks.rbegin(); bit != func.blocks.rend(); ++bit) {
            const Block *b = bit->get();
            out_tmp.clear_all();
            for (int sid : b->succs) {
                out_tmp.or_with(live_in[sid]);
                auto eit = edge_use.find(make_edge(b->id, sid));
                if (eit != edge_use.end()) {
                    out_tmp.or_with(eit->second);
                }
            }
            inn_tmp = out_tmp;
            inn_tmp.and_not(def_of[b->id]);
            inn_tmp.or_with(use_of[b->id]);

            if (out_tmp != live_out[b->id] || inn_tmp != live_in[b->id]) {
                live_out[b->id] = out_tmp;
                live_in[b->id] = inn_tmp;
                changed = true;
            }
        }
    }
    return live_out;
}

int split_edge(Function &func, int pred_id, int succ_id, size_t j, uint64_t next_ea) {
    Block *pred = func.blocks[pred_id].get();
    Block *succ = func.blocks[succ_id].get();
    int cnt = 0;
    size_t succ_pos = 0;
    for (size_t i = 0; i < pred->succs.size(); ++i) {
        if (pred->succs[i] == succ_id) {
            ++cnt;
            succ_pos = i;
        }
    }
    if (cnt != 1) return -1;

    Block *nb = func.new_block(next_ea, next_ea);
    auto jmp = func.make_insn(Op::JMP, EW::W, next_ea);
    jmp->has_aux = true;
    jmp->aux_ea = succ->start_ea;
    jmp->comment = "split edge";
    nb->add(std::move(jmp));

    pred->succs[succ_pos] = nb->id;
    nb->preds.push_back(pred_id);
    nb->succs.push_back(succ_id);
    succ->preds[j] = nb->id;

    Insn *term = pred->terminator();
    if (term && term->has_aux && (term->op == Op::CJMP || term->op == Op::JMP) &&
        term->aux_ea == succ->start_ea) {
        term->aux_ea = next_ea;
    }

    for (auto &phi : succ->insns) {
        if (phi->op != Op::PHI) break;
        if (j < phi->phi_preds.size()) {
            phi->phi_preds[j] = nb->id;
        }
    }
    return nb->id;
}

} // namespace

std::vector<std::unordered_set<VarKey>> liveness(const Function &func, const CallArgsMap *call_args) {
    DenseVars dv = collect_dense_vars(func);
    auto dense_out = compute_dense_live_out(func, dv, call_args);
    std::vector<std::unordered_set<VarKey>> res(func.blocks.size());
    for (size_t bid = 0; bid < dense_out.size(); ++bid) {
        dense_out[bid].for_each_set([&](size_t vi) {
            res[bid].insert(dv.keys[vi]);
        });
    }
    return res;
}

Colouring colours(const Function &func, const CallArgsMap *call_args) {
    Colouring result;
    DenseVars dv = collect_dense_vars(func);
    const size_t nv = dv.keys.size();
    if (nv == 0) return result;

    // 1. Build PHI webs via Union-Find over dense indices.
    std::vector<size_t> parent(nv);
    for (size_t i = 0; i < nv; ++i) parent[i] = i;

    auto find_root = [&](size_t x) -> size_t {
        size_t r = x;
        while (parent[r] != r) r = parent[r];
        while (parent[x] != x) {
            size_t nxt = parent[x];
            parent[x] = r;
            x = nxt;
        }
        return r;
    };

    for (const auto &b : func.blocks) {
        for (const auto &ins : b->insns) {
            if (ins->op != Op::PHI || !ins->defines()) continue;
            size_t di = dv.index_of.at(ins->dst_key());
            for (const auto &s : ins->srcs) {
                if (!s.is_var()) continue;
                size_t si = dv.index_of.at(s.key());
                size_t ra = find_root(di);
                size_t rb = find_root(si);
                if (ra != rb) {
                    // Keep the smaller dense index as canonical root so webs sort identically to Python.
                    if (ra < rb) parent[rb] = ra;
                    else parent[ra] = rb;
                }
            }
        }
    }

    std::vector<size_t> web_of(nv);
    std::unordered_map<size_t, std::vector<size_t>> webs;
    std::vector<size_t> roots;
    for (size_t i = 0; i < nv; ++i) {
        size_t r = find_root(i);
        web_of[i] = r;
        auto &vec = webs[r];
        if (vec.empty()) roots.push_back(r);
        vec.push_back(i);
    }
    std::sort(roots.begin(), roots.end());

    // 2. Compute intra-web interference using dense BitVec live ranges.
    auto live_out = compute_dense_live_out(func, dv, call_args);
    // Map each variable to its intra-web index (0 .. |web|-1) and maintain per-member interference bitmasks.
    std::vector<size_t> pos_in_web(nv, 0);
    std::unordered_map<size_t, std::vector<BitVec>> web_inter;
    for (size_t r : roots) {
        const auto &members = webs[r];
        if (members.size() <= 1) continue;
        auto &adj = web_inter[r];
        adj.assign(members.size(), BitVec(members.size()));
        for (size_t p = 0; p < members.size(); ++p) {
            pos_in_web[members[p]] = p;
        }
    }

    std::vector<VarKey> uses_buf;
    uses_buf.reserve(160);
    for (const auto &b : func.blocks) {
        BitVec live = live_out[b->id];
        for (auto iit = b->insns.rbegin(); iit != b->insns.rend(); ++iit) {
            const Insn &ins = **iit;
            if (ins.defines()) {
                size_t ki = dv.index_of.at(ins.dst_key());
                live.reset(ki);
                size_t r = web_of[ki];
                const auto &members = webs[r];
                if (members.size() > 1) {
                    auto &adj = web_inter[r];
                    size_t pk = pos_in_web[ki];
                    for (size_t pm = 0; pm < members.size(); ++pm) {
                        if (pm != pk && live.test(members[pm])) {
                            adj[pk].set(pm);
                            adj[pm].set(pk);
                        }
                    }
                }
            }
            if (ins.op != Op::PHI) {
                liveness_uses(ins, call_args, uses_buf);
                for (VarKey u : uses_buf) {
                    live.set(dv.index_of.at(u));
                }
            }
        }
    }

    // 3. Greedy web colouring in SSA order.
    result.key_to_colour.reserve(nv * 2 + 1);
    for (size_t r : roots) {
        const auto &members = webs[r];
        if (members.size() == 1) {
            int cid = static_cast<int>(result.groups.size());
            VarKey k = dv.keys[members[0]];
            result.key_to_colour[k] = cid;
            result.groups.push_back({k});
            continue;
        }

        const auto &adj = web_inter[r];
        std::vector<std::vector<size_t>> picked; // intra-web positions per colour
        for (size_t p = 0; p < members.size(); ++p) {
            bool placed = false;
            for (auto &c : picked) {
                bool clash = false;
                for (size_t existing_p : c) {
                    if (adj[p].test(existing_p)) {
                        clash = true;
                        break;
                    }
                }
                if (!clash) {
                    c.push_back(p);
                    placed = true;
                    break;
                }
            }
            if (!placed) {
                picked.push_back({p});
            }
        }

        for (const auto &c : picked) {
            int cid = static_cast<int>(result.groups.size());
            std::vector<VarKey> grp;
            grp.reserve(c.size());
            for (size_t p : c) {
                VarKey k = dv.keys[members[p]];
                result.key_to_colour[k] = cid;
                grp.push_back(k);
            }
            result.groups.push_back(std::move(grp));
        }
    }
    return result;
}

int lower_phis(Function &func, const CallArgsMap *call_args) {
    if (!func.ssa) return 0;
    auto col = colours(func, call_args);
    auto &colour = col.key_to_colour;

    std::unordered_map<int, int> version;
    for (const auto &b : func.blocks) {
        for (const auto &ins : b->insns) {
            if (ins->defines()) {
                version[ins->dst_reg] = std::max(version[ins->dst_reg], ins->dst_ver);
            }
        }
    }

    uint64_t max_end = func.start_ea;
    for (const auto &b : func.blocks) {
        if (b->end_ea > max_end) max_end = b->end_ea;
    }
    uint64_t next_ea = max_end + 4;
    int split = 0;
    int n = 0;

    int max_reg = regs::NREG;
    for (const auto &b : func.blocks) {
        for (const auto &ins : b->insns) {
            if (ins->defines() && ins->dst_reg >= max_reg) max_reg = ins->dst_reg + 1;
            for (const auto &s : ins->srcs) {
                if (s.is_var() && s.reg >= max_reg) max_reg = s.reg + 1;
            }
        }
    }
    int next_colour = static_cast<int>(col.groups.size());

    struct PendingCopy {
        Insn *phi = nullptr;
        size_t edge_idx = 0;
        int dst_col = -1;
        int src_col = -1;
        Operand arg;
    };
    // Group parallel copies by (where_id, at_end) so copies on the same edge are
    // sequentialized together and swap cycles are broken with a fresh temporary.
    std::vector<std::pair<int, bool>> group_order;
    std::unordered_map<uint64_t, std::vector<PendingCopy>> groups;
    auto group_key = [](int where_id, bool at_end) -> uint64_t {
        return (static_cast<uint64_t>(static_cast<uint32_t>(where_id)) << 1) | (at_end ? 1ULL : 0ULL);
    };

    const size_t orig_block_count = func.blocks.size();
    for (size_t bi = 0; bi < orig_block_count; ++bi) {
        Block *b = func.blocks[bi].get();
        for (size_t ii = 0; ii < b->insns.size(); ++ii) {
            Insn *insn = b->insns[ii].get();
            if (insn->op != Op::PHI || !insn->defines()) continue;
            auto wit = colour.find(insn->dst_key());
            if (wit == colour.end()) continue;
            const int want = wit->second;

            const size_t num_edges = std::min(insn->srcs.size(), b->preds.size());
            for (size_t j = 0; j < num_edges; ++j) {
                Operand arg = insn->srcs[j];
                int pred_id = b->preds[j];
                if (!arg.is_var()) continue;
                auto ait = colour.find(arg.key());
                if (ait != colour.end() && ait->second == want) continue;

                int where_id = -1;
                bool at_end = true;
                if (func.blocks[pred_id]->succs.size() == 1) {
                    where_id = pred_id;
                    at_end = true;
                } else if (b->preds.size() == 1) {
                    where_id = b->id;
                    at_end = false;
                } else {
                    where_id = split_edge(func, pred_id, b->id, j, next_ea + 4ULL * static_cast<uint64_t>(split));
                    if (where_id < 0) continue;
                    ++split;
                    at_end = true;
                }

                uint64_t gk = group_key(where_id, at_end);
                auto &vec = groups[gk];
                if (vec.empty()) group_order.push_back({where_id, at_end});
                int src_col = (ait != colour.end()) ? ait->second : -1;
                vec.push_back(PendingCopy{insn, j, want, src_col, arg});
            }
        }
    }

    for (const auto &[where_id, at_end] : group_order) {
        Block *where = func.blocks[where_id].get();
        auto &pending = groups[group_key(where_id, at_end)];

        std::vector<std::unique_ptr<Insn>> emitted;
        emitted.reserve(pending.size() + 2);

        while (!pending.empty()) {
            // Find a copy whose dst_col is not read as src_col by any other remaining copy.
            size_t ready_idx = pending.size();
            for (size_t i = 0; i < pending.size(); ++i) {
                bool clobbers_other = false;
                for (size_t k = 0; k < pending.size(); ++k) {
                    if (k != i && pending[k].src_col == pending[i].dst_col) {
                        clobbers_other = true;
                        break;
                    }
                }
                if (!clobbers_other) {
                    ready_idx = i;
                    break;
                }
            }

            if (ready_idx < pending.size()) {
                PendingCopy pc = pending[ready_idx];
                pending.erase(pending.begin() + static_cast<std::ptrdiff_t>(ready_idx));

                int fresh_ver = ++version[pc.phi->dst_reg];
                auto copy = func.make_insn(Op::MOV, pc.phi->ew, where->start_ea);
                copy->has_dst = true;
                copy->dst_reg = pc.phi->dst_reg;
                copy->dst_ver = fresh_ver;
                copy->block_id = where->id;
                copy->srcs = {Operand::make_var(pc.arg.reg, pc.arg.ver, pc.arg.def_insn)};
                copy->comment = "merge";
                Insn *copy_ptr = copy.get();
                emitted.push_back(std::move(copy));

                pc.phi->srcs[pc.edge_idx] = Operand::make_var(pc.phi->dst_reg, fresh_ver, copy_ptr);
                colour[make_var_key(pc.phi->dst_reg, fresh_ver)] = pc.dst_col;
                ++n;
            } else {
                // Parallel copy cycle (swap problem): save pending[0].arg into a fresh temp register
                // and redirect all remaining copies reading pending[0].src_col to read the temp.
                int tmp_reg = max_reg++;
                int tmp_ver = ++version[tmp_reg];
                int tmp_col = next_colour++;
                int saved_src_col = pending[0].src_col;
                Operand saved_arg = pending[0].arg;

                auto tmp_mov = func.make_insn(Op::MOV, pending[0].phi->ew, where->start_ea);
                tmp_mov->has_dst = true;
                tmp_mov->dst_reg = tmp_reg;
                tmp_mov->dst_ver = tmp_ver;
                tmp_mov->block_id = where->id;
                tmp_mov->srcs = {Operand::make_var(saved_arg.reg, saved_arg.ver, saved_arg.def_insn)};
                tmp_mov->comment = "phi swap temp";
                Insn *tmp_ptr = tmp_mov.get();
                emitted.push_back(std::move(tmp_mov));

                colour[make_var_key(tmp_reg, tmp_ver)] = tmp_col;
                for (auto &pc : pending) {
                    if (pc.src_col == saved_src_col) {
                        pc.src_col = tmp_col;
                        pc.arg = Operand::make_var(tmp_reg, tmp_ver, tmp_ptr);
                    }
                }
                ++n;
            }
        }

        if (at_end) {
            size_t k = where->insns.size();
            while (k > 0 && where->insns[k - 1]->is_terminator()) --k;
            for (auto &mv : emitted) {
                where->insns.insert(where->insns.begin() + static_cast<std::ptrdiff_t>(k++), std::move(mv));
            }
        } else {
            size_t k = 0;
            while (k < where->insns.size() && where->insns[k]->op == Op::PHI) ++k;
            for (auto &mv : emitted) {
                where->insns.insert(where->insns.begin() + static_cast<std::ptrdiff_t>(k++), std::move(mv));
            }
        }
    }

    if (split > 0) {
        ssa::compute_dominators(func);
        ssa::compute_dominance_frontiers(func);
    }
    return n;
}

} // namespace outssa
} // namespace spudec
