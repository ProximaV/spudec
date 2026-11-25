#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace spudec {

struct FlowBlockRange {
    int id = 0;
    uint64_t start_ea = 0;
    uint64_t end_ea = 0;
    std::vector<int> succs;
    std::vector<int> preds;
};

struct UdtFieldInfo {
    int byte_offset = 0;
    int byte_size = 0;
    std::string name;
    std::string type_str;
    int array_elem_size = 0; // >0 when array member
};

struct UdtInfo {
    int size = 0;
    std::vector<UdtFieldInfo> fields;
};

struct StackSlotHit {
    std::string name;
    int size = 0;
};

// Abstract interface decoupling spudec_core from IDA SDK headers.
class IDatabaseProvider {
public:
    virtual ~IDatabaseProvider() = default;

    // Raw instruction / byte access
    virtual bool is_loaded(uint64_t ea) const = 0;
    virtual bool read_u32_be(uint64_t ea, uint32_t *out_word) const = 0;
    virtual size_t read_bytes(uint64_t ea, uint8_t *buf, size_t max_len) const = 0;

    // Function & CFG boundaries
    virtual bool get_func_start(uint64_t ea, uint64_t *out_start_ea) const = 0;
    virtual bool get_flowchart(uint64_t func_ea,
                               uint64_t *out_func_start,
                               std::vector<FlowBlockRange> *out_blocks) const = 0;
    virtual std::vector<uint64_t> get_func_items(uint64_t func_ea) const { (void)func_ea; return {}; }

    // Naming, strings, symbols, C++ class membership, stack slots, UDTs
    virtual std::string get_func_name(uint64_t ea) const = 0;
    virtual std::optional<std::string> get_string_literal(uint64_t ea) const { (void)ea; return std::nullopt; }
    virtual std::optional<std::string> get_relaxed_cstr(uint64_t ea) const { (void)ea; return std::nullopt; }
    virtual std::optional<std::string> get_symbol_name(uint64_t ea) const { (void)ea; return std::nullopt; }
    virtual std::optional<std::string> get_member_class(uint64_t func_ea) const { (void)func_ea; return std::nullopt; }
    virtual std::optional<StackSlotHit> get_stack_slot(uint64_t insn_ea) const { (void)insn_ea; return std::nullopt; }
    virtual std::optional<UdtInfo> get_udt_info(const std::string &type_name) const { (void)type_name; return std::nullopt; }
    virtual std::optional<std::string> get_ida_func_proto(uint64_t func_ea) const { (void)func_ea; return std::nullopt; }

    // Interprocedural summary queries
    virtual std::optional<int> get_callee_arity(uint64_t callee_ea) { (void)callee_ea; return std::nullopt; }
    virtual bool is_callee_variadic(uint64_t callee_ea) { (void)callee_ea; return false; }
    virtual std::optional<std::unordered_map<int, uint16_t>> get_callee_param_demand(uint64_t callee_ea) {
        (void)callee_ea;
        return std::nullopt;
    }
};

// Lightweight in-memory provider for unit tests and CLI tools.
class MockDatabaseProvider : public IDatabaseProvider {
public:
    std::unordered_map<uint64_t, uint8_t> mem;
    std::unordered_map<uint64_t, std::vector<FlowBlockRange>> flowcharts;
    std::unordered_map<uint64_t, std::string> func_names;
    std::unordered_map<uint64_t, std::string> strings;
    std::unordered_map<uint64_t, std::string> symbols;
    std::unordered_map<uint64_t, std::string> member_classes;
    std::unordered_map<uint64_t, StackSlotHit> stack_slots;
    std::unordered_map<std::string, UdtInfo> udts;
    std::unordered_map<uint64_t, int> arities;
    std::unordered_map<uint64_t, bool> variadics;
    std::unordered_map<uint64_t, std::unordered_map<int, uint16_t>> param_demands;

    void write_u32_be(uint64_t ea, uint32_t word) {
        mem[ea + 0] = static_cast<uint8_t>((word >> 24) & 0xFF);
        mem[ea + 1] = static_cast<uint8_t>((word >> 16) & 0xFF);
        mem[ea + 2] = static_cast<uint8_t>((word >> 8) & 0xFF);
        mem[ea + 3] = static_cast<uint8_t>(word & 0xFF);
    }

    bool is_loaded(uint64_t ea) const override {
        return mem.find(ea) != mem.end();
    }

    bool read_u32_be(uint64_t ea, uint32_t *out_word) const override {
        uint8_t b[4];
        for (int i = 0; i < 4; ++i) {
            auto it = mem.find(ea + static_cast<uint64_t>(i));
            if (it == mem.end()) return false;
            b[i] = it->second;
        }
        *out_word = (static_cast<uint32_t>(b[0]) << 24) |
                    (static_cast<uint32_t>(b[1]) << 16) |
                    (static_cast<uint32_t>(b[2]) << 8) |
                    static_cast<uint32_t>(b[3]);
        return true;
    }

    size_t read_bytes(uint64_t ea, uint8_t *buf, size_t max_len) const override {
        size_t n = 0;
        for (; n < max_len; ++n) {
            auto it = mem.find(ea + n);
            if (it == mem.end()) break;
            buf[n] = it->second;
        }
        return n;
    }

    bool get_func_start(uint64_t ea, uint64_t *out_start_ea) const override {
        if (flowcharts.count(ea)) {
            *out_start_ea = ea;
            return true;
        }
        for (const auto &kv : flowcharts) {
            for (const auto &blk : kv.second) {
                if (ea >= blk.start_ea && ea < blk.end_ea) {
                    *out_start_ea = kv.first;
                    return true;
                }
            }
        }
        return false;
    }

    bool get_flowchart(uint64_t func_ea,
                       uint64_t *out_func_start,
                       std::vector<FlowBlockRange> *out_blocks) const override {
        uint64_t start = func_ea;
        if (!get_func_start(func_ea, &start)) return false;
        auto it = flowcharts.find(start);
        if (it == flowcharts.end()) return false;
        *out_func_start = start;
        *out_blocks = it->second;
        return true;
    }

    std::string get_func_name(uint64_t ea) const override {
        auto it = func_names.find(ea);
        if (it != func_names.end()) return it->second;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "sub_%llX", static_cast<unsigned long long>(ea));
        return buf;
    }

    std::optional<std::string> get_string_literal(uint64_t ea) const override {
        auto it = strings.find(ea);
        if (it != strings.end()) return it->second;
        return std::nullopt;
    }

    std::optional<std::string> get_symbol_name(uint64_t ea) const override {
        auto it = symbols.find(ea);
        if (it != symbols.end()) return it->second;
        return std::nullopt;
    }

    std::optional<std::string> get_member_class(uint64_t func_ea) const override {
        auto it = member_classes.find(func_ea);
        if (it != member_classes.end()) return it->second;
        return std::nullopt;
    }

    std::optional<StackSlotHit> get_stack_slot(uint64_t insn_ea) const override {
        auto it = stack_slots.find(insn_ea);
        if (it != stack_slots.end()) return it->second;
        return std::nullopt;
    }

    std::optional<UdtInfo> get_udt_info(const std::string &type_name) const override {
        auto it = udts.find(type_name);
        if (it != udts.end()) return it->second;
        return std::nullopt;
    }

    std::optional<int> get_callee_arity(uint64_t callee_ea) override {
        auto it = arities.find(callee_ea);
        if (it != arities.end()) return it->second;
        return std::nullopt;
    }

    bool is_callee_variadic(uint64_t callee_ea) override {
        auto it = variadics.find(callee_ea);
        return it != variadics.end() && it->second;
    }

    std::optional<std::unordered_map<int, uint16_t>> get_callee_param_demand(uint64_t callee_ea) override {
        auto it = param_demands.find(callee_ea);
        if (it != param_demands.end()) return it->second;
        return std::nullopt;
    }
};

} // namespace spudec
