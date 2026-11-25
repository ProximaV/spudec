#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "cgen.hpp"
#include "ctree.hpp"
#include "database.hpp"
#include "ir.hpp"
#include "structure.hpp"
#include "user_data.hpp"

namespace spudec {

inline constexpr const char *SPUDEC_VERSION = "2.0.0-native";

// Lifecycle event codes matching Hex-Rays hexrays_event_t semantics for C++ & Python scripting!
enum spudec_event_t : int {
    spe_lifting_done   = 1, // Function CFG lifted (arg0 = Function *)
    spe_ssa_optimized  = 2, // SSA + scalarization + outssa completed (arg0 = Function *)
    spe_maturity       = 3, // ctree synthesized at CMAT_FINAL (arg0 = cfunc_t *)
    spe_func_printed   = 4, // cfunc_t lines & SCOLOR_* sv generated (arg0 = cfunc_t *)
    spe_open_pseudocode = 5,
    spe_switch_pseudocode = 6,
    spe_refresh_pseudocode = 7,
    spe_close_pseudocode = 8,
    spe_curpos         = 9,
    spe_double_click   = 10,
    spe_keyboard       = 11,
    spe_populating_popup = 12,
};

using SpudecEventCallback = std::function<int(spudec_event_t ev, void *arg0, void *arg1)>;

int register_event_callback(SpudecEventCallback cb);
bool unregister_event_callback(int handle);
void notify_event(spudec_event_t ev, void *arg0 = nullptr, void *arg1 = nullptr);

struct DecompileOptions {
    bool optimize_ir = true;
    bool run_scalarize = true;
    bool drop_hints = true;
    bool verify_ssa = true;
    bool hide_casts = false;
    FuncUserData user_data;
};

struct DecompileOutput {
    std::unique_ptr<Function> ir_func;
    structure::StructureInfo struct_info;
    cfuncptr_t cfunc;
    std::string error;
};

// Stage 1: Lift -> SSA -> Optimize -> Scalarize -> Optimize -> OutSSA.
std::unique_ptr<Function> lift_and_optimize(IDatabaseProvider &db,
                                            uint64_t ea,
                                            const DecompileOptions &opts = {},
                                            std::string *out_error = nullptr);

// Full pipeline: Stage 1 + Structuring + CGen + ctree + lifecycle event notifications.
DecompileOutput decompile_function(IDatabaseProvider &db,
                                   uint64_t ea,
                                   const DecompileOptions &opts = {});

// Shallow interprocedural helpers (used by summary cache & standalone provider).
bool analyze_is_variadic(IDatabaseProvider &db, uint64_t func_ea);
std::optional<int> analyze_callee_arity(IDatabaseProvider &db, uint64_t func_ea,
                                        const std::optional<std::string> &user_proto = std::nullopt);
std::unordered_map<int, uint16_t> analyze_param_demand(IDatabaseProvider &db, uint64_t func_ea);

} // namespace spudec
