#pragma once

#include <cstdint>
#include <unordered_map>
#include <utility>
#include "ir.hpp"
#include "lanes.hpp"

namespace spudec {
class IDatabaseProvider;
namespace scalarize {

struct AddrExpr {
    bool has_base = false;
    VarKey base = 0;
    uint32_t offset = 0;
    bool aligned = false;
};

struct ScalarizeStats {
    int stores = 0;
    int loads = 0;
    int aligned_loads = 0;
    int scalars = 0;
    int assumed_noalias = 0;
};

AddrExpr addr_expr(const Operand &v, const std::unordered_map<VarKey, Insn *> &defs, int limit = 16);
Operand unaligned_of(const Operand &v, const std::unordered_map<VarKey, Insn *> &defs, int limit = 16);

bool hoist_phi_shufb(Function &func);
std::pair<int, int> recover_stores(Function &func, bool strict = false);
int recover_loads(Function &func, const std::unordered_map<VarKey, uint16_t> &demand);
int recover_aligned_loads(Function &func, const std::unordered_map<VarKey, uint16_t> &demand);
int propagate_scalar_slots(Function &func, const std::unordered_map<VarKey, uint16_t> &demand);
int fold_u64_arith(Function &func, const IDatabaseProvider *db = nullptr);
int prune_dead_shufb_inputs(Function &func,
                            const std::unordered_map<VarKey, uint16_t> &demand,
                            const IDatabaseProvider *db = nullptr);
int mark_scalars(Function &func, const std::unordered_map<VarKey, uint16_t> &demand);

ScalarizeStats scalarize(Function &func,
                       const lanes::CalleeDemandFn &callee = nullptr,
                       bool strict = false,
                       const IDatabaseProvider *db = nullptr);

} // namespace scalarize
} // namespace spudec
