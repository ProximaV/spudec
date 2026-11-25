#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "ctree.hpp"
#include "database.hpp"
#include "ir.hpp"
#include "structure.hpp"
#include "user_data.hpp"

namespace spudec {
namespace cgen {

struct CGenOptions {
    IDatabaseProvider *db = nullptr;
    FuncUserData user_data;
    bool hide_casts = false;

    // Optional standalone callback overrides (used when `db == nullptr` or in unit tests)
    std::function<std::string(uint64_t)> name_of;
    std::function<std::optional<int>(uint64_t)> arity_of;
    std::function<bool(uint64_t)> is_variadic_of;
    std::function<std::optional<std::string>(uint64_t)> str_of;
    std::function<std::optional<std::string>(uint64_t)> relaxed_str_of;
    std::function<std::optional<StackSlotHit>(uint64_t)> stk_of;
    std::function<std::optional<std::string>(uint64_t)> this_of;
    std::function<std::optional<std::string>(uint64_t)> sym_of;
    std::function<std::optional<UdtInfo>(const std::string &)> struct_resolver;
};

// Recover contiguous ABI parameter register list [r3 .. r_hi] for `func`.
std::vector<int> recover_params(const Function &func,
                                const std::function<std::optional<int>(uint64_t)> &arity_of = nullptr,
                                const std::function<bool(uint64_t)> &is_variadic_of = nullptr);

// Synthesize full `cfunc_t` (explicit ctree AST, lvars, CodeLines, EA maps, and SCOLOR_* sv lines).
cfuncptr_t generate(Function &func,
                    const std::vector<std::unique_ptr<structure::Stmt>> &stmts,
                    const structure::StructureInfo &info,
                    const CGenOptions &opts = {});

} // namespace cgen
} // namespace spudec
