#include "spudec/opt.hpp"
#include "spudec/sem.hpp"
#include <algorithm>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace spudec {
namespace opt {

namespace {

struct InsnHookEntry {
    int id;
    OptInsnHook cb;
};
struct BlockHookEntry {
    int id;
    OptBlockHook cb;
};

std::mutex g_hook_mu;
int g_next_hook_id = 1;
std::vector<InsnHookEntry> g_insn_hooks;
std::vector<BlockHookEntry> g_block_hooks;

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

std::unordered_map<VarKey, int> build_usecount(const Function &func) {
    std::unordered_map<VarKey, int> n;
    for (const auto &b : func.blocks) {
        for (const auto &i : b->insns) {
            for (const auto &u : i->srcs) {
                if (u.is_var()) {
                    ++n[u.key()];
                }
            }
        }
    }
    return n;
}

Operand clone_var(const Operand &v) {
    return Operand::make_var(v.reg, v.ver, v.def_insn);
}

std::optional<u128_t> const_value(const Operand &v, const std::unordered_map<VarKey, Insn *> &defs) {
    if (v.is_const) return v.val;
    auto it = defs.find(v.key());
    if (it != defs.end() && it->second->op == Op::CONST &&
        !it->second->srcs.empty() && it->second->srcs[0].is_const) {
        return it->second->srcs[0].val;
    }
    return std::nullopt;
}

} // namespace

int register_optinsn_hook(OptInsnHook cb) {
    std::lock_guard<std::mutex> lk(g_hook_mu);
    int id = g_next_hook_id++;
    g_insn_hooks.push_back({id, std::move(cb)});
    return id;
}

bool unregister_optinsn_hook(int handle) {
    std::lock_guard<std::mutex> lk(g_hook_mu);
    auto it = std::remove_if(g_insn_hooks.begin(), g_insn_hooks.end(),
                             [handle](const InsnHookEntry &e) { return e.id == handle; });
    if (it == g_insn_hooks.end()) return false;
    g_insn_hooks.erase(it, g_insn_hooks.end());
    return true;
}

int register_optblock_hook(OptBlockHook cb) {
    std::lock_guard<std::mutex> lk(g_hook_mu);
    int id = g_next_hook_id++;
    g_block_hooks.push_back({id, std::move(cb)});
    return id;
}

bool unregister_optblock_hook(int handle) {
    std::lock_guard<std::mutex> lk(g_hook_mu);
    auto it = std::remove_if(g_block_hooks.begin(), g_block_hooks.end(),
                             [handle](const BlockHookEntry &e) { return e.id == handle; });
    if (it == g_block_hooks.end()) return false;
    g_block_hooks.erase(it, g_block_hooks.end());
    return true;
}

void clear_opt_hooks() {
    std::lock_guard<std::mutex> lk(g_hook_mu);
    g_insn_hooks.clear();
    g_block_hooks.clear();
}

int run_custom_opt_hooks(Function &func) {
    std::vector<InsnHookEntry> ihooks;
    std::vector<BlockHookEntry> bhooks;
    {
        std::lock_guard<std::mutex> lk(g_hook_mu);
        if (g_insn_hooks.empty() && g_block_hooks.empty()) return 0;
        ihooks = g_insn_hooks;
        bhooks = g_block_hooks;
    }
    int total = 0;
    for (auto &b : func.blocks) {
        for (const auto &ih : ihooks) {
            for (size_t idx = 0; idx < b->insns.size(); ++idx) {
                total += ih.cb(func, *b, *b->insns[idx]);
            }
        }
        for (const auto &bh : bhooks) {
            total += bh.cb(func, *b);
        }
    }
    return total;
}

bool simplify_phis(Function &func) {
    auto defs = build_defmap(func);
    bool changed = false;
    std::vector<Block *> touched;

    for (auto &b : func.blocks) {
        bool blk_touched = false;
        for (auto &insn : b->insns) {
            if (insn->op != Op::PHI || insn->srcs.empty() || !insn->defines()) continue;
            const VarKey dst_k = insn->dst_key();

            std::vector<Operand> args;
            args.reserve(insn->srcs.size());
            for (const auto &s : insn->srcs) {
                if (!(s.is_var() && s.key() == dst_k)) {
                    args.push_back(s);
                }
            }
            if (args.empty()) continue;

            auto v0 = const_value(args[0], defs);
            bool all_same_const = v0.has_value();
            if (all_same_const) {
                for (size_t i = 1; i < args.size(); ++i) {
                    auto vi = const_value(args[i], defs);
                    if (!vi.has_value() || *vi != *v0) {
                        all_same_const = false;
                        break;
                    }
                }
            }

            if (all_same_const) {
                insn->op = Op::CONST;
                insn->srcs = {Operand::make_const(*v0)};
                insn->phi_preds.clear();
                insn->has_aux = false;
                changed = true;
                blk_touched = true;
                continue;
            }

            bool all_same_var = args[0].is_var();
            if (all_same_var) {
                VarKey k0 = args[0].key();
                for (size_t i = 1; i < args.size(); ++i) {
                    if (!args[i].is_var() || args[i].key() != k0) {
                        all_same_var = false;
                        break;
                    }
                }
            }
            if (all_same_var) {
                insn->op = Op::MOV;
                insn->srcs = {clone_var(args[0])};
                insn->phi_preds.clear();
                insn->has_aux = false;
                changed = true;
                blk_touched = true;
            }
        }
        if (blk_touched) touched.push_back(b.get());
    }

    // Maintain invariant: all Op::PHI instructions appear before non-PHIs in every block.
    for (Block *b : touched) {
        std::stable_partition(b->insns.begin(), b->insns.end(),
                              [](const std::unique_ptr<Insn> &i) { return i->op == Op::PHI; });
    }
    return changed;
}

bool propagate(Function &func) {
    auto defs = build_defmap(func);
    bool changed = false;

    for (auto &b : func.blocks) {
        for (auto &insn : b->insns) {
            if (op_is_abi(insn->op) || insn->op == Op::PHI) {
                continue;
            }
            for (auto &s : insn->srcs) {
                if (!s.is_var()) continue;
                auto it = defs.find(s.key());
                if (it == defs.end() || it->second == insn.get()) continue;
                Insn *d = it->second;
                if (d->op == Op::CONST && !d->srcs.empty() && d->srcs[0].is_const) {
                    EW cew = (d->srcs[0].ew != EW::None) ? d->srcs[0].ew : insn->ew;
                    s = Operand::make_const(d->srcs[0].val, cew);
                    changed = true;
                } else if (d->op == Op::MOV && !d->srcs.empty()) {
                    const Operand &src = d->srcs[0];
                    if (src.is_const) {
                        EW cew = (src.ew != EW::None) ? src.ew : insn->ew;
                        s = Operand::make_const(src.val, cew);
                        changed = true;
                    } else if (src.is_var() && src.key() != s.key()) {
                        s = clone_var(src);
                        changed = true;
                    }
                }
            }
        }
    }
    return changed;
}

bool fold(Function &func) {
    bool changed = false;
    std::vector<u128_t> args;
    args.reserve(4);

    for (auto &b : func.blocks) {
        for (auto &insn : b->insns) {
            if (insn->op == Op::CONST || insn->op == Op::PHI || !insn->defines()) continue;
            if (op_has_side_effects(insn->op) || insn->is_terminator()) continue;
            if (insn->srcs.empty()) continue;

            bool all_const = true;
            args.clear();
            for (const auto &s : insn->srcs) {
                if (!s.is_const) {
                    all_const = false;
                    break;
                }
                args.push_back(s.val);
            }
            if (!all_const) continue;

            auto res = sem::evaluate(insn->op, insn->ew, args.data(), args.size());
            if (!res.has_value()) continue;

            if (insn->comment.empty()) {
                insn->comment = std::string("folded ") + op_name(insn->op);
            }
            insn->op = Op::CONST;
            insn->srcs = {Operand::make_const(*res)};
            insn->has_aux = false;
            insn->aux_ea = 0;
            insn->aux_int = 0;
            insn->aux_str.clear();
            changed = true;
        }
    }
    return changed;
}

bool simplify_identities(Function &func) {
    bool changed = false;
    for (auto &b : func.blocks) {
        for (auto &insn : b->insns) {
            if (insn->srcs.size() != 2) continue;
            const Operand &a = insn->srcs[0];
            const Operand &b_op = insn->srcs[1];
            bool same = (a.is_var() && b_op.is_var() && a.key() == b_op.key()) ||
                        (a.is_const && b_op.is_const && a.val == b_op.val);
            if (!same) continue;

            if (insn->op == Op::AND || insn->op == Op::OR) {
                Operand keep = a;
                insn->op = Op::MOV;
                insn->srcs = {keep};
            } else if (insn->op == Op::NOR || insn->op == Op::NAND) {
                Operand keep = a;
                insn->op = Op::NOT;
                insn->srcs = {keep};
            } else if (insn->op == Op::XOR) {
                insn->op = Op::CONST;
                insn->srcs = {Operand::make_const(u128_t::zero())};
                insn->ew = EW::Q;
            } else if (insn->op == Op::EQV) {
                insn->op = Op::CONST;
                insn->srcs = {Operand::make_const(u128_t::all_ones())};
                insn->ew = EW::Q;
            } else {
                continue;
            }
            changed = true;
        }
    }
    return changed;
}

int dce(Function &func) {
    int removed = 0;
    while (true) {
        auto used = build_usecount(func);
        int round_removed = 0;
        for (auto &b : func.blocks) {
            auto it = std::remove_if(b->insns.begin(), b->insns.end(),
                                     [&](const std::unique_ptr<Insn> &insn) {
                                         if (op_has_side_effects(insn->op) || insn->is_terminator()) {
                                             return false;
                                         }
                                         if (!insn->defines()) return false;
                                         auto uit = used.find(insn->dst_key());
                                         return uit == used.end() || uit->second == 0;
                                     });
            round_removed += static_cast<int>(std::distance(it, b->insns.end()));
            b->insns.erase(it, b->insns.end());
        }
        if (round_removed == 0) break;
        removed += round_removed;
    }
    return removed;
}

OptStats optimize(Function &func, int rounds) {
    OptStats stats;
    for (int r = 0; r < rounds; ++r) {
        bool changed = false;
        changed |= simplify_phis(func);
        changed |= simplify_identities(func);
        changed |= propagate(func);
        changed |= fold(func);
        int custom = run_custom_opt_hooks(func);
        if (custom > 0) {
            stats.custom_changes += custom;
            changed = true;
        }
        ++stats.rounds;
        if (!changed) break;
    }
    stats.removed = dce(func);
    return stats;
}

} // namespace opt
} // namespace spudec
