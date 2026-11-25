#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace spudec {

struct LvarUserEntry {
    std::string name;
    std::string type;
    int flags = 0;
};

// Exact schema persisted in IDA netnode "$ spudec" supstr(func_ea).
struct FuncUserData {
    std::unordered_map<std::string, std::string> renames;
    std::unordered_map<std::string, std::string> types;
    std::optional<std::string> proto;
    std::unordered_map<std::string, LvarUserEntry> lvars;
    std::unordered_map<std::string, std::string> cmts;
    std::unordered_map<std::string, std::string> numforms;
    std::vector<uint64_t> iflags;

    void set_var_rename(const std::string &old_name, const std::string &new_name);
    void set_var_type(const std::string &var_name, const std::string &type_str);
    void set_var_locator(const std::string &locator,
                         const std::optional<std::string> &name = std::nullopt,
                         const std::optional<std::string> &type_str = std::nullopt,
                         int flags = 0);
    void set_statement_cmt(uint64_t stmt_ea, const std::string &cmt_str);
    std::optional<std::string> get_statement_cmt(uint64_t stmt_ea) const;
    void set_numform(uint64_t stmt_ea, int op_idx, const std::string &form_str);
    std::optional<std::string> get_numform(uint64_t stmt_ea, int op_idx = 0) const;
    bool toggle_iflag(uint64_t branch_ea);
    bool is_iflag_inverted(uint64_t branch_ea) const;
    void set_func_proto(const std::string &proto_str);
    void clear();
};

// Persisted in "$ spudec" supstr(WIN_STATE_KEY = 0x7FFFFFFF).
struct WindowState {
    bool is_open = false;
    std::optional<uint64_t> func_ea;
    int lineno = 0;
    int col = 0;
    std::string mode = "c";
};

constexpr uint64_t SPUDEC_WIN_STATE_KEY = 0x7FFFFFFFULL;

bool parse_func_user_data_json(const std::string &json_text, FuncUserData &out);
std::string serialize_func_user_data_json(const FuncUserData &data);

bool parse_window_state_json(const std::string &json_text, WindowState &out);
std::string serialize_window_state_json(const WindowState &st);

} // namespace spudec
