#pragma once

#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "ir.hpp"

namespace spudec {
namespace outssa {

// Narrowed real call argument operands keyed by Insn::uid.
using CallArgsMap = std::unordered_map<uint32_t, std::vector<Operand>>;

struct Colouring {
    std::unordered_map<VarKey, int> key_to_colour;
    std::vector<std::vector<VarKey>> groups;
};

// Live-out SSA keys per block id.
std::vector<std::unordered_set<VarKey>> liveness(const Function &func, const CallArgsMap *call_args = nullptr);

// Greedy web colouring respecting intra-web interference.
Colouring colours(const Function &func, const CallArgsMap *call_args = nullptr);

// Materialize copies along incoming edges (splitting critical edges as needed) where phi arguments
// do not share their destination's colour. Returns the number of copies inserted.
int lower_phis(Function &func, const CallArgsMap *call_args = nullptr);

} // namespace outssa
} // namespace spudec
