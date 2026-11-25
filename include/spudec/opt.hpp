#pragma once

#include <functional>
#include "ir.hpp"

namespace spudec {
namespace opt {

struct OptStats {
    int rounds = 0;
    int removed = 0;
    int custom_changes = 0;
};

// Custom IR optimization hooks (for C++ & IDAPython scripting, analogous to Hex-Rays optinsn_t / optblock_t).
// Return count of modifications (>0 triggers another fixpoint round).
using OptInsnHook = std::function<int(Function &func, Block &blk, Insn &insn)>;
using OptBlockHook = std::function<int(Function &func, Block &blk)>;

int register_optinsn_hook(OptInsnHook cb);
bool unregister_optinsn_hook(int handle);
int register_optblock_hook(OptBlockHook cb);
bool unregister_optblock_hook(int handle);
void clear_opt_hooks();
int run_custom_opt_hooks(Function &func);

bool simplify_phis(Function &func);
bool propagate(Function &func);
bool fold(Function &func);
bool simplify_identities(Function &func);
int dce(Function &func);

OptStats optimize(Function &func, int rounds = 16);

} // namespace opt
} // namespace spudec
