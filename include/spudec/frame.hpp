#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>
#include "ir.hpp"

namespace spudec {
namespace frame {

constexpr inline int64_t signed_offset(uint32_t off) {
    return (off >= 0x80000000u) ? (static_cast<int64_t>(off) - 0x100000000LL) : static_cast<int64_t>(off);
}

struct FrameInfo {
    std::vector<std::pair<int64_t, int>> saves; // (signed_offset, reg)
    std::optional<int64_t> back_chain;
    std::optional<int64_t> size;
    std::unordered_set<uint32_t> hidden_uids;   // Insn::uid of suppressed prologue instructions

    explicit operator bool() const { return !saves.empty() || back_chain.has_value(); }
    std::optional<std::string> describe() const;
};

FrameInfo analyse(Function &func);

} // namespace frame
} // namespace spudec
