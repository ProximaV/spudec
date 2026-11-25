#pragma once

#include <ida.hpp>
#include <idp.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "spudec/ctree.hpp"
#include "spudec/database.hpp"
#include "spudec/pipeline.hpp"

namespace spudec {

class IdaDatabaseProvider;

class SummaryCache : public event_listener_t {
public:
    SummaryCache() = default;
    ~SummaryCache() override = default;

    // IDB event listener for surgical incremental cache invalidation
    ssize_t idaapi on_event(ssize_t code, va_list va) override;

    void clear_all();
    void clear_arity_and_demand();
    void invalidate_func(uint64_t func_ea);
    void invalidate_names_and_symbols();
    void invalidate_types();

    // Cached cfunc_t lookup & storage (supports `< 0.5 ms` instant re-print / scripting!)
    cfuncptr_t get_cached_cfunc(uint64_t func_ea) const;
    void put_cached_cfunc(uint64_t func_ea, cfuncptr_t cf);

    // Session-cached symbol/string/member/frame/interprocedural resolvers
    std::string get_func_name(uint64_t ea);
    int demangled_count() const { return demangled_count_; }
    std::optional<std::string> get_string_literal(const IdaDatabaseProvider &prov, uint64_t ea);
    std::optional<std::string> get_symbol_name(const IdaDatabaseProvider &prov, uint64_t ea);
    std::optional<std::string> get_member_class(uint64_t func_ea);
    std::optional<StackSlotHit> get_stack_slot(uint64_t insn_ea);

    std::optional<int> get_callee_arity(IdaDatabaseProvider &prov, uint64_t callee_ea);
    bool is_callee_variadic(IdaDatabaseProvider &prov, uint64_t callee_ea);
    std::optional<std::unordered_map<int, uint16_t>> get_callee_param_demand(
        IdaDatabaseProvider &prov, uint64_t callee_ea);

private:
    void ensure_shared_names();
    void ensure_class_set();
    const std::unordered_map<uint64_t, StackSlotHit> &ensure_frame_members(uint64_t func_start_ea);
    std::optional<uint64_t> resolve_thunk_target(uint64_t ea) const;

    bool shared_names_ready_ = false;
    std::unordered_set<std::string> shared_names_;
    std::unordered_map<uint64_t, std::string> func_names_;
    int demangled_count_ = 0;

    bool classes_ready_ = false;
    std::unordered_set<std::string> classes_;
    std::unordered_map<uint64_t, std::optional<std::string>> member_classes_;

    std::unordered_map<uint64_t, std::optional<std::string>> strings_;
    std::unordered_map<uint64_t, std::optional<std::string>> symbols_;

    std::unordered_map<uint64_t, std::unordered_map<uint64_t, StackSlotHit>> frame_members_;
    std::unordered_map<uint64_t, std::optional<StackSlotHit>> insn_slots_;

    std::unordered_map<uint64_t, std::optional<int>> arities_;
    std::unordered_set<uint64_t> arity_active_;

    std::unordered_map<uint64_t, bool> variadics_;
    std::unordered_set<uint64_t> variadic_active_;

    std::unordered_map<uint64_t, std::unordered_map<int, uint16_t>> param_demands_;
    std::unordered_set<uint64_t> demand_active_;

    std::unordered_map<uint64_t, cfuncptr_t> cfunc_cache_;
};

// Global per-plugin SummaryCache accessor
SummaryCache &global_summary_cache();

} // namespace spudec
