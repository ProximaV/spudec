#include "spudec/structure.hpp"
#include "spudec/ssa.hpp"
#include <algorithm>

namespace spudec {
namespace structure {

std::string Cond::to_string() const {
    CondKind k = effective();
    std::string v = value.str();
    switch (k) {
        case CondKind::Z:   return v + " == 0";
        case CondKind::NZ:  return v + " != 0";
        case CondKind::HZ:  return "(" + v + " & 0xFFFF) == 0";
        case CondKind::HNZ: return "(" + v + " & 0xFFFF) != 0";
    }
    return v + " != 0";
}

Cond cond_of(const Insn &insn) {
    Operand v = insn.srcs.empty() ? Operand::make_const(u128_t::zero()) : insn.srcs[0];
    return Cond(v, insn.cond_kind, false);
}

std::unique_ptr<Stmt> Stmt::make_basic(int blk_id, std::vector<Insn *> list) {
    auto s = std::make_unique<Stmt>();
    s->kind = StmtKind::Basic;
    s->block_id = blk_id;
    s->insns = std::move(list);
    return s;
}

std::unique_ptr<Stmt> Stmt::make_if(Cond c, std::vector<std::unique_ptr<Stmt>> th,
                                    std::vector<std::unique_ptr<Stmt>> el, uint64_t branch_ea) {
    auto s = std::make_unique<Stmt>();
    s->kind = StmtKind::If;
    s->cond = std::move(c);
    s->has_cond = true;
    s->then_body = std::move(th);
    s->els_body = std::move(el);
    s->ea = branch_ea;
    s->has_ea = true;
    return s;
}

std::unique_ptr<Stmt> Stmt::make_loop(std::vector<std::unique_ptr<Stmt>> bd, int header_id,
                                      LoopKind lk, const Cond *c) {
    auto s = std::make_unique<Stmt>();
    s->kind = StmtKind::Loop;
    s->body = std::move(bd);
    s->block_id = header_id;
    s->loop_kind = lk;
    if (c) {
        s->cond = *c;
        s->has_cond = true;
    }
    return s;
}

std::unique_ptr<Stmt> Stmt::make_break() {
    auto s = std::make_unique<Stmt>();
    s->kind = StmtKind::Break;
    return s;
}

std::unique_ptr<Stmt> Stmt::make_continue() {
    auto s = std::make_unique<Stmt>();
    s->kind = StmtKind::Continue;
    return s;
}

std::unique_ptr<Stmt> Stmt::make_goto(int target_blk_id) {
    auto s = std::make_unique<Stmt>();
    s->kind = StmtKind::Goto;
    s->block_id = target_blk_id;
    return s;
}

std::unique_ptr<Stmt> Stmt::make_label(int blk_id) {
    auto s = std::make_unique<Stmt>();
    s->kind = StmtKind::Label;
    s->block_id = blk_id;
    return s;
}

std::unique_ptr<Stmt> Stmt::make_return(Insn *ret_insn) {
    auto s = std::make_unique<Stmt>();
    s->kind = StmtKind::Return;
    s->insn = ret_insn;
    return s;
}

std::unique_ptr<Stmt> Stmt::make_tail(Insn *tail_insn) {
    auto s = std::make_unique<Stmt>();
    s->kind = StmtKind::Tail;
    s->insn = tail_insn;
    return s;
}

namespace {

std::unordered_set<int> natural_body(const Function &func, int header_id, int latch_id) {
    std::unordered_set<int> body;
    body.insert(header_id);
    std::vector<int> stack;
    if (latch_id != header_id) {
        body.insert(latch_id);
        stack.push_back(latch_id);
    }
    while (!stack.empty()) {
        int bid = stack.back();
        stack.pop_back();
        for (int pid : func.blocks[bid]->preds) {
            if (body.insert(pid).second) {
                stack.push_back(pid);
            }
        }
    }
    return body;
}

bool is_duplicable(const Block &b) {
    if (!b.succs.empty() || b.insns.empty()) return false;
    Op last_op = b.insns.back()->op;
    if (last_op != Op::RET && last_op != Op::STOP && last_op != Op::JMP) return false;
    for (size_t i = 0; i + 1 < b.insns.size(); ++i) {
        if (b.insns[i]->op != Op::PHI) return false;
    }
    return true;
}

bool is_marker(const Stmt &s) {
    if (s.kind == StmtKind::Label) return true;
    if (s.kind == StmtKind::Basic) {
        for (const Insn *i : s.insns) {
            if (i->op != Op::PHI) return false;
        }
        return true;
    }
    return false;
}

bool arm_is_empty(const std::vector<std::unique_ptr<Stmt>> &arm) {
    for (const auto &s : arm) {
        if (!is_marker(*s)) return false;
    }
    return true;
}

bool arm_is(const std::vector<std::unique_ptr<Stmt>> &arm, StmtKind k) {
    int count = 0;
    for (const auto &s : arm) {
        if (is_marker(*s)) continue;
        if (s->kind != k) return false;
        ++count;
    }
    return count == 1;
}

std::vector<std::unique_ptr<Stmt>> drop_indices(std::vector<std::unique_ptr<Stmt>> &body,
                                                size_t skip1, size_t skip2 = static_cast<size_t>(-1)) {
    std::vector<std::unique_ptr<Stmt>> out;
    out.reserve(body.size());
    for (size_t i = 0; i < body.size(); ++i) {
        if (i == skip1 || i == skip2) continue;
        out.push_back(std::move(body[i]));
    }
    return out;
}

void refine_loop(Stmt &loop) {
    std::vector<size_t> real_idx;
    for (size_t i = 0; i < loop.body.size(); ++i) {
        if (!is_marker(*loop.body[i])) real_idx.push_back(i);
    }
    if (real_idx.empty()) return;

    // 1. `if (c) break; else { body; continue; }` (or inverted)
    if (real_idx.size() == 1 && loop.body[real_idx[0]]->kind == StmtKind::If) {
        size_t i0 = real_idx[0];
        Stmt &s0 = *loop.body[i0];
        if (arm_is(s0.then_body, StmtKind::Break) &&
            !s0.els_body.empty() && s0.els_body.back()->kind == StmtKind::Continue) {
            loop.loop_kind = LoopKind::While;
            loop.cond = s0.cond.negate();
            loop.has_cond = true;
            std::vector<std::unique_ptr<Stmt>> nb;
            for (size_t k = 0; k < i0; ++k) nb.push_back(std::move(loop.body[k]));
            for (size_t k = 0; k + 1 < s0.els_body.size(); ++k) nb.push_back(std::move(s0.els_body[k]));
            loop.body = std::move(nb);
            return;
        }
        if (arm_is(s0.els_body, StmtKind::Break) &&
            !s0.then_body.empty() && s0.then_body.back()->kind == StmtKind::Continue) {
            loop.loop_kind = LoopKind::While;
            loop.cond = s0.cond;
            loop.has_cond = true;
            std::vector<std::unique_ptr<Stmt>> nb;
            for (size_t k = 0; k < i0; ++k) nb.push_back(std::move(loop.body[k]));
            for (size_t k = 0; k + 1 < s0.then_body.size(); ++k) nb.push_back(std::move(s0.then_body[k]));
            loop.body = std::move(nb);
            return;
        }
    }

    // 2. `if (c) { body; continue; } break;`
    if (real_idx.size() == 2) {
        size_t i0 = real_idx[0], i1 = real_idx[1];
        if (loop.body[i0]->kind == StmtKind::If && loop.body[i1]->kind == StmtKind::Break) {
            Stmt &s0 = *loop.body[i0];
            if (!s0.then_body.empty() && s0.els_body.empty() && s0.then_body.back()->kind == StmtKind::Continue) {
                loop.loop_kind = LoopKind::While;
                loop.cond = s0.cond;
                loop.has_cond = true;
                std::vector<std::unique_ptr<Stmt>> nb;
                for (size_t k = 0; k < i0; ++k) nb.push_back(std::move(loop.body[k]));
                for (size_t k = 0; k + 1 < s0.then_body.size(); ++k) nb.push_back(std::move(s0.then_body[k]));
                loop.body = std::move(nb);
                return;
            }
            if (!s0.els_body.empty() && s0.then_body.empty() && s0.els_body.back()->kind == StmtKind::Continue) {
                loop.loop_kind = LoopKind::While;
                loop.cond = s0.cond.negate();
                loop.has_cond = true;
                std::vector<std::unique_ptr<Stmt>> nb;
                for (size_t k = 0; k < i0; ++k) nb.push_back(std::move(loop.body[k]));
                for (size_t k = 0; k + 1 < s0.els_body.size(); ++k) nb.push_back(std::move(s0.els_body[k]));
                loop.body = std::move(nb);
                return;
            }
        }
    }

    // 3. Leading `if (c) break;` followed by statements
    {
        size_t i0 = real_idx[0];
        if (loop.body[i0]->kind == StmtKind::If && real_idx.size() > 1) {
            Stmt &s0 = *loop.body[i0];
            if (arm_is(s0.then_body, StmtKind::Break) && s0.els_body.empty()) {
                loop.loop_kind = LoopKind::While;
                loop.cond = s0.cond.negate();
                loop.has_cond = true;
                loop.body = drop_indices(loop.body, i0);
                return;
            }
            if (arm_is(s0.els_body, StmtKind::Break) && s0.then_body.empty()) {
                loop.loop_kind = LoopKind::While;
                loop.cond = s0.cond;
                loop.has_cond = true;
                loop.body = drop_indices(loop.body, i0);
                return;
            }
        }
    }

    // 4. Bottom test -> do-while (`if (c) continue; break;`)
    if (real_idx.size() >= 2) {
        size_t i1 = real_idx[real_idx.size() - 2];
        size_t i2 = real_idx[real_idx.size() - 1];
        if (loop.body[i1]->kind == StmtKind::If && loop.body[i2]->kind == StmtKind::Break) {
            Stmt &s1 = *loop.body[i1];
            if (arm_is(s1.then_body, StmtKind::Continue) && s1.els_body.empty()) {
                loop.loop_kind = LoopKind::DoWhile;
                loop.cond = s1.cond;
                loop.has_cond = true;
                loop.body = drop_indices(loop.body, i1, i2);
                return;
            }
            if (arm_is(s1.els_body, StmtKind::Continue) && s1.then_body.empty()) {
                loop.loop_kind = LoopKind::DoWhile;
                loop.cond = s1.cond.negate();
                loop.has_cond = true;
                loop.body = drop_indices(loop.body, i1, i2);
                return;
            }
        }
    }

    // 5. Strip redundant trailing `continue`, then refine trailing `if` -> do-while
    while (!real_idx.empty() && loop.body[real_idx.back()]->kind == StmtKind::Continue) {
        size_t iC = real_idx.back();
        loop.body = drop_indices(loop.body, iC);
        real_idx.pop_back();
        if (real_idx.empty()) return;
    }
    size_t iL = real_idx.back();
    if (loop.body[iL]->kind == StmtKind::If) {
        Stmt &sL = *loop.body[iL];
        struct Case {
            const std::vector<std::unique_ptr<Stmt>> *arm;
            const std::vector<std::unique_ptr<Stmt>> *other;
            StmtKind cls;
            StmtKind other_cls;
            bool invert;
        };
        const Case cases[4] = {
            {&sL.then_body, &sL.els_body, StmtKind::Continue, StmtKind::Break, false},
            {&sL.els_body, &sL.then_body, StmtKind::Continue, StmtKind::Break, true},
            {&sL.then_body, &sL.els_body, StmtKind::Break, StmtKind::Continue, true},
            {&sL.els_body, &sL.then_body, StmtKind::Break, StmtKind::Continue, false},
        };
        for (const auto &cs : cases) {
            if (arm_is(*cs.arm, cs.cls) && (arm_is_empty(*cs.other) || arm_is(*cs.other, cs.other_cls))) {
                loop.loop_kind = LoopKind::DoWhile;
                loop.cond = cs.invert ? sL.cond.negate() : sL.cond;
                loop.has_cond = true;
                loop.body = drop_indices(loop.body, iL);
                return;
            }
        }
    }
}

struct Ctx {
    Function &func;
    const std::vector<int> &ipdom;
    const std::unordered_map<int, LoopInfo> &loops;
    std::unordered_set<int> emitted;
    std::unordered_set<int> open_loops;
    std::vector<std::pair<int, int>> loop_stack; // (header_id, follow_id)
    std::unordered_set<int> labels;
    int gotos = 0;
    std::unordered_map<std::string, int> why;
    int dups = 0;
    std::unordered_map<int, int> dup_per;

    bool may_duplicate(const Block &b) const {
        if (loops.find(b.id) != loops.end() || dups >= DUP_BUDGET) return false;
        auto it = dup_per.find(b.id);
        if (it != dup_per.end() && it->second >= DUP_PER_BLOCK) return false;
        int non_phis = 0;
        for (const auto &i : b.insns) {
            if (i->op != Op::PHI) ++non_phis;
        }
        return non_phis <= DUP_MAX_INSNS;
    }

    void note_duplicate(int bid) {
        ++dups;
        ++dup_per[bid];
    }

    std::unique_ptr<Stmt> make_goto(int bid, const char *reason) {
        labels.insert(bid);
        ++gotos;
        ++why[reason];
        return Stmt::make_goto(bid);
    }

    std::unique_ptr<Stmt> loop_control(int bid) {
        if (loop_stack.empty()) return nullptr;
        auto [h, f] = loop_stack.back();
        if (bid == h) return Stmt::make_continue();
        if (f >= 0 && bid == f) return Stmt::make_break();
        for (size_t i = loop_stack.size() - 1; i-- > 0;) {
            auto [oh, of] = loop_stack[i];
            if (bid == oh || (of >= 0 && bid == of)) {
                return make_goto(bid, "outer-loop boundary");
            }
        }
        return nullptr;
    }

    std::pair<int, int> cjmp_targets(const Block &b) const {
        const Insn *term = b.insns.back().get();
        uint64_t target_ea = term->has_aux ? term->aux_ea : UINT64_MAX;
        int taken = -1, fall = -1;
        for (int sid : b.succs) {
            if (func.blocks[sid]->start_ea == target_ea && taken < 0) {
                taken = sid;
            } else {
                fall = sid;
            }
        }
        if (taken < 0 && !b.succs.empty()) taken = b.succs[0];
        if (fall < 0) fall = taken;
        return {taken, fall};
    }

    bool reaches_without(int src, int dst, int avoid, int stop_id, BitVec &visited) const {
        if (src == dst) return true;
        if (src < 0 || src == avoid || (stop_id >= 0 && src == stop_id)) return false;
        if (visited.test(static_cast<size_t>(src))) return false;
        visited.set(static_cast<size_t>(src));
        for (int sid : func.blocks[src]->succs) {
            if (reaches_without(sid, dst, avoid, stop_id, visited)) return true;
        }
        return false;
    }

    bool is_early_exit(int node_id, int target_id) const {
        if (node_id < 0) return true;
        BitVec visited(func.blocks.size());
        std::vector<int> stack = {node_id};
        while (!stack.empty()) {
            int curr = stack.back();
            stack.pop_back();
            if (curr == target_id) return false;
            if (visited.test(static_cast<size_t>(curr))) continue;
            visited.set(static_cast<size_t>(curr));
            const Block &cb = *func.blocks[curr];
            if (!cb.insns.empty() && (cb.insns.back()->op == Op::RET || cb.insns.back()->op == Op::STOP)) {
                continue;
            }
            if (cb.succs.empty()) continue;
            for (int sid : cb.succs) {
                if (!visited.test(static_cast<size_t>(sid))) {
                    stack.push_back(sid);
                }
            }
        }
        return true;
    }

    int if_follow(int bid, int stop_id) const {
        int f = (bid >= 0 && bid < static_cast<int>(ipdom.size()) && ipdom[bid] >= 0) ? ipdom[bid] : -1;
        auto [taken, fall] = cjmp_targets(*func.blocks[bid]);
        if (taken < 0 || fall < 0) {
            return (f >= 0) ? f : stop_id;
        }

        const size_t nb = func.blocks.size();
        BitVec v1(nb), v2(nb);
        bool tf = reaches_without(taken, fall, bid, stop_id, v1);
        bool ft = reaches_without(fall, taken, bid, stop_id, v2);
        if (tf && !ft) return fall;
        if (ft && !tf) return taken;
        if (is_early_exit(taken, fall)) return fall;
        if (is_early_exit(fall, taken)) return taken;

        if (f < 0 || (stop_id >= 0 && f == stop_id)) return stop_id;
        return f;
    }
};

std::vector<std::unique_ptr<Stmt>> build_stmts(int start_id, int stop_id, Ctx &ctx,
                                               int depth = 0, int skip_control_id = -1);

std::vector<std::unique_ptr<Stmt>> build_loop(const LoopInfo &li, Ctx &ctx, int depth) {
    ctx.open_loops.insert(li.header_id);
    ctx.loop_stack.push_back({li.header_id, li.follow_id});
    auto body = build_stmts(li.header_id, -1, ctx, depth, li.header_id);
    ctx.loop_stack.pop_back();
    ctx.open_loops.erase(li.header_id);

    std::vector<std::unique_ptr<Stmt>> out;
    size_t lead_end = 0;
    while (lead_end < body.size() && body[lead_end]->kind == StmtKind::Label) {
        out.push_back(std::move(body[lead_end]));
        ++lead_end;
    }
    std::vector<std::unique_ptr<Stmt>> rem;
    rem.reserve(body.size() - lead_end);
    for (size_t i = lead_end; i < body.size(); ++i) {
        rem.push_back(std::move(body[i]));
    }
    auto lp = Stmt::make_loop(std::move(rem), li.header_id);
    refine_loop(*lp);
    out.push_back(std::move(lp));
    return out;
}

std::vector<std::unique_ptr<Stmt>> build_stmts(int start_id, int stop_id, Ctx &ctx,
                                               int depth, int skip_control_id) {
    std::vector<std::unique_ptr<Stmt>> out;
    int cur_id = start_id;
    bool first = true;

    while (cur_id >= 0 && cur_id != stop_id) {
        if (depth > MAX_DEPTH) {
            out.push_back(ctx.make_goto(cur_id, "nesting depth limit"));
            return out;
        }

        if (!(first && cur_id == skip_control_id)) {
            auto ctl = ctx.loop_control(cur_id);
            if (ctl) {
                out.push_back(std::move(ctl));
                return out;
            }
        }

        Block &cur = *ctx.func.blocks[cur_id];
        if (ctx.emitted.find(cur_id) != ctx.emitted.end()) {
            if (is_duplicable(cur)) {
                Insn *last = cur.insns.back().get();
                if (last->op == Op::JMP || last->op == Op::IJMP || last->op == Op::TCALL) {
                    out.push_back(Stmt::make_tail(last));
                } else {
                    out.push_back(Stmt::make_return(last));
                }
                return out;
            }
            if (ctx.may_duplicate(cur)) {
                ctx.note_duplicate(cur_id);
            } else {
                out.push_back(ctx.make_goto(cur_id, "block already emitted"));
                return out;
            }
        }

        auto lit = ctx.loops.find(cur_id);
        if (lit != ctx.loops.end() && ctx.open_loops.find(cur_id) == ctx.open_loops.end()) {
            auto lp_stmts = build_loop(lit->second, ctx, depth + 1);
            for (auto &s : lp_stmts) out.push_back(std::move(s));
            cur_id = lit->second.follow_id;
            first = false;
            continue;
        }

        ctx.emitted.insert(cur_id);
        first = false;
        out.push_back(Stmt::make_label(cur_id));

        Insn *term = cur.insns.empty() ? nullptr : cur.insns.back().get();
        size_t body_len = (term && term->is_terminator()) ? (cur.insns.size() - 1) : cur.insns.size();
        if (body_len > 0) {
            std::vector<Insn *> body_insns;
            body_insns.reserve(body_len);
            for (size_t i = 0; i < body_len; ++i) {
                body_insns.push_back(cur.insns[i].get());
            }
            out.push_back(Stmt::make_basic(cur_id, std::move(body_insns)));
        }

        if (!term) break;
        if (term->op == Op::CJMP) {
            int f_id = ctx.if_follow(cur_id, stop_id);
            auto [taken, fall] = ctx.cjmp_targets(cur);
            auto then_stmts = build_stmts(taken, f_id, ctx, depth + 1);
            auto els_stmts = build_stmts(fall, f_id, ctx, depth + 1);

            std::vector<std::unique_ptr<Stmt>> trailing;
            auto all_markers = [](const std::vector<std::unique_ptr<Stmt>> &vec) -> bool {
                if (vec.empty()) return false;
                for (const auto &s : vec) if (!is_marker(*s)) return false;
                return true;
            };
            if (all_markers(then_stmts)) {
                for (auto &s : then_stmts) trailing.push_back(std::move(s));
                then_stmts.clear();
            }
            if (all_markers(els_stmts)) {
                for (auto &s : els_stmts) trailing.push_back(std::move(s));
                els_stmts.clear();
            }

            Cond cond = cond_of(*term);
            if (then_stmts.empty() && !els_stmts.empty()) {
                cond = cond.negate();
                then_stmts = std::move(els_stmts);
                els_stmts.clear();
            }
            out.push_back(Stmt::make_if(std::move(cond), std::move(then_stmts), std::move(els_stmts), term->ea));
            for (auto &s : trailing) out.push_back(std::move(s));
            cur_id = f_id;
        } else if (term->op == Op::RET || term->op == Op::STOP) {
            out.push_back(Stmt::make_return(term));
            return out;
        } else if (term->op == Op::IJMP || term->op == Op::TCALL) {
            out.push_back(Stmt::make_tail(term));
            if (cur.succs.empty() || term->op == Op::TCALL) {
                return out;
            }
            int f_id = ctx.if_follow(cur_id, stop_id);
            for (int sid : cur.succs) {
                ctx.labels.insert(sid);
                auto case_stmts = build_stmts(sid, f_id, ctx, depth + 1);
                for (auto &s : case_stmts) out.push_back(std::move(s));
            }
            if (f_id < 0 || f_id == stop_id) return out;
            cur_id = f_id;
            first = false;
            continue;
        } else if (term->op == Op::JMP && cur.succs.empty()) {
            out.push_back(Stmt::make_tail(term));
            return out;
        } else if (!cur.succs.empty()) {
            cur_id = cur.succs[0];
        } else {
            break;
        }
    }
    return out;
}

} // namespace

std::unordered_map<int, LoopInfo> find_loops(const Function &func, const std::unordered_map<int, int> &rpo_index) {
    std::unordered_map<int, LoopInfo> loops;
    for (const auto &u : func.blocks) {
        for (int vid : u->succs) {
            if (!ssa::dominates(func, vid, u->id)) continue;
            auto &li = loops[vid];
            if (li.header_id < 0) li.header_id = vid;
            li.latches.push_back(u->id);
            auto nb = natural_body(func, vid, u->id);
            li.body.insert(nb.begin(), nb.end());
        }
    }

    for (auto &[hid, li] : loops) {
        std::vector<int> exits;
        for (int bid : li.body) {
            for (int sid : func.blocks[bid]->succs) {
                if (li.body.find(sid) == li.body.end() &&
                    std::find(exits.begin(), exits.end(), sid) == exits.end()) {
                    exits.push_back(sid);
                }
            }
        }
        if (!exits.empty()) {
            std::sort(exits.begin(), exits.end(), [&](int a, int b) {
                auto ia = rpo_index.find(a);
                auto ib = rpo_index.find(b);
                int ra = (ia != rpo_index.end()) ? ia->second : (1 << 30);
                int rb = (ib != rpo_index.end()) ? ib->second : (1 << 30);
                return ra < rb;
            });
            li.follow_id = exits[0];
        }

        const Block &hdr = *func.blocks[hid];
        const Insn *head_term = hdr.insns.empty() ? nullptr : hdr.insns.back().get();
        bool head_tests = head_term && head_term->op == Op::CJMP &&
                          std::any_of(hdr.succs.begin(), hdr.succs.end(),
                                      [&](int s) { return li.body.find(s) == li.body.end(); });
        bool self_latch = std::find(li.latches.begin(), li.latches.end(), hid) != li.latches.end();
        if (self_latch) {
            li.kind = LoopKind::DoWhile;
        } else if (head_tests) {
            li.kind = LoopKind::While;
        } else {
            bool latch_tests = false;
            for (int lid : li.latches) {
                const Block &lb = *func.blocks[lid];
                if (!lb.insns.empty() && lb.insns.back()->op == Op::CJMP &&
                    std::any_of(lb.succs.begin(), lb.succs.end(),
                                [&](int s) { return li.body.find(s) == li.body.end(); })) {
                    latch_tests = true;
                    break;
                }
            }
            li.kind = latch_tests ? LoopKind::DoWhile : LoopKind::Endless;
        }
    }
    return loops;
}

std::pair<std::vector<std::unique_ptr<Stmt>>, StructureInfo> structure(Function &func) {
    auto rpo = ssa::compute_dominators(func);
    std::unordered_map<int, int> rpo_index;
    for (int i = 0; i < static_cast<int>(rpo.size()); ++i) {
        rpo_index[rpo[i]] = i;
    }
    ssa::compute_dominance_frontiers(func);
    auto ipdom = ssa::compute_postdominators(func);
    auto loops = find_loops(func, rpo_index);

    Ctx ctx{func, ipdom, loops, {}, {}, {}, {}, 0, {}, 0, {}};
    auto body = build_stmts(func.entry_id, -1, ctx);

    StructureInfo info;
    info.labels = std::move(ctx.labels);
    info.gotos = ctx.gotos;
    info.goto_why = std::move(ctx.why);
    info.duplicated = ctx.dups;
    info.loops = static_cast<int>(loops.size());
    for (const auto &b : func.blocks) {
        if (ctx.emitted.find(b->id) == ctx.emitted.end()) {
            info.unreached.push_back(b->id);
        }
    }
    return {std::move(body), std::move(info)};
}

} // namespace structure
} // namespace spudec
