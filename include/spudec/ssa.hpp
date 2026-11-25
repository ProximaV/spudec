#pragma once

#include <string>
#include <vector>
#include "ir.hpp"

namespace spudec {
namespace ssa {

constexpr int IPDOM_UNREACHABLE = -1;
constexpr int IPDOM_EXIT = -2;

std::vector<int> reverse_postorder(const Function &func);
std::vector<int> compute_dominators(Function &func);
void compute_dominance_frontiers(Function &func);

// Returns an array indexed by block->id:
//   >= 0               -> immediate post-dominator block id
//   IPDOM_EXIT (-2)    -> post-dominated only by the virtual function exit (no internal join)
//   IPDOM_UNREACHABLE  -> cannot reach any exit block (e.g. endless loop)
std::vector<int> compute_postdominators(const Function &func);

bool dominates(const Function &func, int a_id, int b_id);
int insert_phis(Function &func);
void rename(Function &func);
void to_ssa(Function &func);

// Verify SSA invariants; returns human-readable problem strings (empty if valid).
std::vector<std::string> verify(const Function &func);

} // namespace ssa
} // namespace spudec
