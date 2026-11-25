#include "spudec/lifter.hpp"
#include "spudec/abi.hpp"
#include <algorithm>
#include <cstdio>

namespace spudec {
namespace cfg {

namespace {

void add_fallthrough_jumps(Function &func, const Lifter &lifter) {
    for (auto &b : func.blocks) {
        if (!b->insns.empty() && b->insns.back()->is_terminator()) continue;
        if (b->succs.size() == 1) {
            int succ_id = b->succs[0];
            auto j = func.make_insn(Op::JMP, EW::W, b->end_ea);
            j->has_aux = true;
            j->aux_ea = func.blocks[succ_id]->start_ea;
            j->comment = "fallthrough";
            b->add(std::move(j));
        } else if (b->succs.empty()) {
            if (b->start_ea == b->end_ea) {
                // Zero-length flowchart stub for direct tail call outside this function
                auto tc = func.make_insn(Op::TCALL, EW::W, b->start_ea);
                tc->has_aux = true;
                tc->aux_ea = b->start_ea;
                tc->comment = "tail call outside this function";
                tc->srcs.push_back(Operand::make_var(regs::R_MEM));
                tc->srcs.push_back(Operand::make_var(regs::R_CH));
                for (int r : lifter.abi_args()) tc->srcs.push_back(Operand::make_var(r));
                b->add(std::move(tc));
            } else {
                auto ret = func.make_insn(Op::RET, EW::W, b->end_ea);
                ret->srcs = lifter.make_abi_ret_srcs();
                ret->comment = "implicit end of block";
                b->add(std::move(ret));
            }
        }
    }
}

void prune_unreachable(Function &func) {
    const size_t n = func.blocks.size();
    if (n == 0 || func.entry_id < 0) return;

    std::vector<uint8_t> seen(n, 0);
    std::vector<int> work;
    work.push_back(func.entry_id);
    while (!work.empty()) {
        int bid = work.back();
        work.pop_back();
        if (bid < 0 || static_cast<size_t>(bid) >= n || seen[bid]) continue;
        seen[bid] = 1;
        for (int s : func.blocks[bid]->succs) {
            if (s >= 0 && static_cast<size_t>(s) < n && !seen[s]) work.push_back(s);
        }
    }

    std::vector<std::pair<uint64_t, uint64_t>> raw;
    for (size_t i = 0; i < n; ++i) {
        if (!seen[i] && func.blocks[i]->end_ea > func.blocks[i]->start_ea) {
            raw.emplace_back(func.blocks[i]->start_ea, func.blocks[i]->end_ea);
        }
    }
    std::sort(raw.begin(), raw.end());
    func.unreachable.clear();
    for (const auto &rng : raw) {
        if (!func.unreachable.empty() && rng.first <= func.unreachable.back().second) {
            func.unreachable.back().second = std::max(func.unreachable.back().second, rng.second);
        } else {
            func.unreachable.push_back(rng);
        }
    }

    size_t kept_count = 0;
    for (uint8_t s : seen) if (s) ++kept_count;
    if (kept_count == n) return;

    std::vector<int> old_to_new(n, -1);
    std::vector<std::unique_ptr<Block>> kept;
    kept.reserve(kept_count);
    for (size_t i = 0; i < n; ++i) {
        if (!seen[i]) continue;
        int new_id = static_cast<int>(kept.size());
        old_to_new[i] = new_id;
        func.blocks[i]->id = new_id;
        for (auto &ins : func.blocks[i]->insns) ins->block_id = new_id;
        kept.push_back(std::move(func.blocks[i]));
    }

    for (auto &b : kept) {
        std::vector<int> npreds, nsuccs;
        for (int p : b->preds) if (p >= 0 && static_cast<size_t>(p) < n && old_to_new[p] >= 0) npreds.push_back(old_to_new[p]);
        for (int s : b->succs) if (s >= 0 && static_cast<size_t>(s) < n && old_to_new[s] >= 0) nsuccs.push_back(old_to_new[s]);
        b->preds = std::move(npreds);
        b->succs = std::move(nsuccs);
    }

    func.blocks = std::move(kept);
    func.entry_id = func.blocks.empty() ? -1 : 0;
}

} // namespace

std::unique_ptr<Function> build(const IDatabaseProvider &db,
                                uint64_t func_ea,
                                bool drop_hints,
                                std::string *out_err) {
    uint64_t start_ea = 0;
    std::vector<FlowBlockRange> fc_blocks;
    if (!db.get_flowchart(func_ea, &start_ea, &fc_blocks) || fc_blocks.empty()) {
        if (out_err) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "no function at 0x%llX", static_cast<unsigned long long>(func_ea));
            *out_err = buf;
        }
        return nullptr;
    }

    auto func = std::make_unique<Function>(start_ea, db.get_func_name(start_ea));
    std::vector<std::pair<uint64_t, uint64_t>> ranges;
    ranges.reserve(fc_blocks.size());
    std::unordered_map<int, int> id_map;
    for (const auto &fb : fc_blocks) {
        id_map[fb.id] = static_cast<int>(ranges.size());
        ranges.emplace_back(fb.start_ea, fb.end_ea);
    }

    Lifter lifter(drop_hints);
    auto ir_blocks = lifter.lift_ranges(db, *func, ranges);
    func->unhandled = lifter.unhandled();

    for (const auto &fb : fc_blocks) {
        int src_idx = id_map[fb.id];
        for (int sid : fb.succs) {
            auto it = id_map.find(sid);
            if (it == id_map.end()) continue;
            int dst_idx = it->second;
            ir_blocks[src_idx]->succs.push_back(dst_idx);
            ir_blocks[dst_idx]->preds.push_back(src_idx);
        }
    }

    add_fallthrough_jumps(*func, lifter);
    prune_unreachable(*func);
    func->clobbers = abi::insert_call_clobbers(*func);
    return func;
}

} // namespace cfg
} // namespace spudec
