#include "spudec/frame.hpp"
#include "spudec/regs.hpp"
#include "spudec/scalarize.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <unordered_map>

namespace spudec {
namespace frame {

namespace {

std::string fmt_slot(int64_t off) {
    char buf[48];
    uint64_t mag = static_cast<uint64_t>(off < 0 ? -off : off);
    std::snprintf(buf, sizeof(buf), "sp%s0x%llX", (off < 0 ? "-" : "+"),
                  static_cast<unsigned long long>(mag));
    return buf;
}

} // namespace

std::optional<std::string> FrameInfo::describe() const {
    if (!static_cast<bool>(*this)) return std::nullopt;

    std::vector<std::string> parts;
    if (size.has_value() && *size > 0) {
        char buf[48];
        std::snprintf(buf, sizeof(buf), "frame 0x%llX", static_cast<unsigned long long>(*size));
        parts.emplace_back(buf);
    }

    if (!saves.empty()) {
        auto by_reg = saves;
        std::sort(by_reg.begin(), by_reg.end(),
                  [](const auto &a, const auto &b) { return a.second < b.second; });
        std::vector<std::vector<std::pair<int64_t, int>>> runs;
        for (const auto &item : by_reg) {
            if (!runs.empty()) {
                auto [po, pr] = runs.back().back();
                if (item.second == pr + 1 && item.first - po == -0x10) {
                    runs.back().push_back(item);
                    continue;
                }
            }
            runs.push_back({item});
        }
        std::string s = "saves ";
        for (size_t i = 0; i < runs.size(); ++i) {
            if (i > 0) s += ", ";
            const auto &run = runs[i];
            auto [o0, r0] = run.front();
            auto [o1, r1] = run.back();
            if (run.size() == 1) {
                s += regs::reg_name(r0) + " at " + fmt_slot(o0);
            } else {
                s += regs::reg_name(r0) + "-" + regs::reg_name(r1) +
                     " at " + fmt_slot(o0) + ".." + fmt_slot(o1);
            }
        }
        parts.push_back(std::move(s));
    }

    if (back_chain.has_value()) {
        parts.push_back("back chain at " + fmt_slot(*back_chain));
    }

    std::string out = "prologue: ";
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) out += "; ";
        out += parts[i];
    }
    return out;
}

FrameInfo analyse(Function &func) {
    FrameInfo fr;
    std::unordered_map<VarKey, Insn *> defs;
    for (auto &b : func.blocks) {
        for (auto &i : b->insns) {
            if (i->defines()) defs[i->dst_key()] = i.get();
        }
    }

    const VarKey sp_in = make_var_key(regs::SP, 0);

    // Record every (sp_in, offset) slot read by any load in the function.
    std::unordered_set<uint32_t> sp_read_offs;
    for (const auto &b : func.blocks) {
        for (const auto &i : b->insns) {
            if (op_is_mem_read(i->op) && i->srcs.size() > 1) {
                auto ae = scalarize::addr_expr(i->srcs[1], defs);
                if (ae.has_base && ae.base == sp_in) {
                    sp_read_offs.insert(ae.offset);
                }
            }
        }
    }

    // Frame size from `sp_next = sp_in + (-frame_size)`
    for (const auto &b : func.blocks) {
        for (const auto &i : b->insns) {
            if (!i->defines() || i->dst_reg != regs::SP || i->dst_ver == 0) continue;
            if (i->op == Op::ADD && i->srcs.size() == 2) {
                const Operand &a = i->srcs[0];
                const Operand &b_op = i->srcs[1];
                bool has_k = b_op.is_const || a.is_const;
                if (!has_k) continue;
                uint32_t k = b_op.is_const ? b_op.val.word0() : a.val.word0();
                const Operand &other = b_op.is_const ? a : b_op;
                if (other.is_var() && other.reg == regs::SP) {
                    int64_t delta = signed_offset(k);
                    if (delta < 0 && other.key() == sp_in) {
                        fr.size = -delta;
                    }
                    fr.hidden_uids.insert(i->uid);
                }
            }
        }
    }

    // Callee-save & LR stores + back-chain store
    for (const auto &b : func.blocks) {
        for (const auto &i : b->insns) {
            if (i->op != Op::STOREQ || i->srcs.size() < 3) continue;
            const Operand &val = i->srcs[2];
            if (!val.is_var() || val.ver != 0) continue;
            auto ae = scalarize::addr_expr(i->srcs[1], defs);
            if (!ae.has_base || ae.base != sp_in || sp_read_offs.find(ae.offset) != sp_read_offs.end()) {
                continue;
            }
            int64_t soff = signed_offset(ae.offset);
            if (val.reg == regs::SP) {
                fr.back_chain = soff;
            } else if (val.reg == regs::LR || regs::is_callee_saved(val.reg)) {
                fr.saves.push_back({soff, val.reg});
            } else {
                continue;
            }
            fr.hidden_uids.insert(i->uid);
        }
    }

    std::sort(fr.saves.begin(), fr.saves.end());
    fr.saves.erase(std::unique(fr.saves.begin(), fr.saves.end()), fr.saves.end());
    return fr;
}

} // namespace frame
} // namespace spudec
