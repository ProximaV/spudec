#pragma once

#include <ida.hpp>
#include <typeinf.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "spudec/database.hpp"

namespace spudec {

class SummaryCache;

// Standalone IDA helper utilities shared across provider, viewer, and scripting SDK.
std::optional<std::string> demangle_spu_name(const std::string &raw);
std::string escape_c_string_literal(const std::string &text, size_t max_len = 96);
bool looks_like_text_bytes(const uint8_t *buf, size_t len);

void ensure_spu_types();
bool parse_c_type_tinfo(const std::string &type_str, tinfo_t *out_tif);
bool apply_proto_to_ida(ea_t ea, const std::string &proto_str);
std::vector<std::string> find_ida_enum_matches(uint64_t val);

class IdaDatabaseProvider : public IDatabaseProvider {
public:
    explicit IdaDatabaseProvider(SummaryCache *cache = nullptr) : cache_(cache) {}

    bool is_loaded(uint64_t ea) const override;
    bool read_u32_be(uint64_t ea, uint32_t *out_word) const override;
    size_t read_bytes(uint64_t ea, uint8_t *buf, size_t max_len) const override;

    bool get_func_start(uint64_t ea, uint64_t *out_start_ea) const override;
    bool get_flowchart(uint64_t func_ea,
                       uint64_t *out_func_start,
                       std::vector<FlowBlockRange> *out_blocks) const override;
    std::vector<uint64_t> get_func_items(uint64_t func_ea) const override;

    std::string get_func_name(uint64_t ea) const override;
    std::optional<std::string> get_string_literal(uint64_t ea) const override;
    std::optional<std::string> get_relaxed_cstr(uint64_t ea) const override;
    std::optional<std::string> get_symbol_name(uint64_t ea) const override;
    std::optional<std::string> get_member_class(uint64_t func_ea) const override;
    std::optional<StackSlotHit> get_stack_slot(uint64_t insn_ea) const override;
    std::optional<UdtInfo> get_udt_info(const std::string &type_name) const override;
    std::optional<std::string> get_ida_func_proto(uint64_t func_ea) const override;

    std::optional<int> get_callee_arity(uint64_t callee_ea) override;
    bool is_callee_variadic(uint64_t callee_ea) override;
    std::optional<std::unordered_map<int, uint16_t>> get_callee_param_demand(uint64_t callee_ea) override;

    // Uncached direct resolvers called by SummaryCache on cache miss
    std::optional<std::string> lookup_string_uncached(uint64_t ea) const;
    std::optional<std::string> lookup_symbol_uncached(uint64_t ea) const;

private:
    SummaryCache *cache_ = nullptr;
};

} // namespace spudec
