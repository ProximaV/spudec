#include <ida.hpp>
#include <netnode.hpp>

#include "db.hpp"

namespace spudec {
namespace idadb {

namespace {

constexpr const char *BLOB_SENTINEL = "__SPUDEC_BLOB_V1__";
constexpr uchar BLOB_TAG = 'B';

WindowState g_mem_win_state;
bool g_has_mem_win_state = false;

netnode get_or_create_node() {
    netnode node;
    node.create(SPUDEC_NODE_NAME);
    return node;
}

std::optional<std::string> read_node_str(uint64_t key) {
    if (!netnode_inited()) return std::nullopt;
    netnode node(SPUDEC_NODE_NAME);
    if (node == BADNODE) return std::nullopt;

    qstring qval;
    if (node.supstr(&qval, static_cast<nodeidx_t>(key)) < 0) {
        return std::nullopt;
    }
    if (qval == BLOB_SENTINEL) {
        bytevec_t blob;
        if (netnode_qgetblob(node, &blob, 1, static_cast<nodeidx_t>(key << 8), BLOB_TAG) > 0) {
            size_t len = blob.size();
            while (len > 0 && blob[len - 1] == 0) --len;
            return std::string(reinterpret_cast<const char *>(blob.begin()), len);
        }
        return std::nullopt;
    }
    return std::string(qval.c_str(), qval.length());
}

void write_node_str(uint64_t key, const std::string &val) {
    if (!netnode_inited()) return;
    netnode node = get_or_create_node();
    if (node == BADNODE) return;

    if (val.size() + 1 <= MAXSPECSIZE) {
        node.delblob(static_cast<nodeidx_t>(key << 8), BLOB_TAG);
        node.supset(static_cast<nodeidx_t>(key), val.c_str(), val.size() + 1);
    } else {
        node.setblob(val.c_str(), val.size() + 1, static_cast<nodeidx_t>(key << 8), BLOB_TAG);
        node.supset(static_cast<nodeidx_t>(key), BLOB_SENTINEL);
    }
}

} // namespace

FuncUserData get_func_data(uint64_t func_ea) {
    FuncUserData out;
    if (auto raw = read_node_str(func_ea); raw.has_value()) {
        parse_func_user_data_json(*raw, out);
    }
    return out;
}

void set_func_data(uint64_t func_ea, const FuncUserData &data) {
    write_node_str(func_ea, serialize_func_user_data_json(data));
}

void set_var_rename(uint64_t func_ea, const std::string &old_name, const std::string &new_name) {
    auto d = get_func_data(func_ea);
    d.set_var_rename(old_name, new_name);
    set_func_data(func_ea, d);
}

void set_var_type(uint64_t func_ea, const std::string &var_name, const std::string &type_str) {
    auto d = get_func_data(func_ea);
    d.set_var_type(var_name, type_str);
    set_func_data(func_ea, d);
}

void set_var_locator(uint64_t func_ea, const std::string &locator,
                     const std::optional<std::string> &name,
                     const std::optional<std::string> &type_str,
                     int flags) {
    auto d = get_func_data(func_ea);
    d.set_var_locator(locator, name, type_str, flags);
    set_func_data(func_ea, d);
}

void set_statement_cmt(uint64_t func_ea, uint64_t stmt_ea, const std::string &cmt_str) {
    auto d = get_func_data(func_ea);
    d.set_statement_cmt(stmt_ea, cmt_str);
    set_func_data(func_ea, d);
}

std::optional<std::string> get_statement_cmt(uint64_t func_ea, uint64_t stmt_ea) {
    return get_func_data(func_ea).get_statement_cmt(stmt_ea);
}

void set_numform(uint64_t func_ea, uint64_t stmt_ea, int op_idx, const std::string &form_str) {
    auto d = get_func_data(func_ea);
    d.set_numform(stmt_ea, op_idx, form_str);
    set_func_data(func_ea, d);
}

std::optional<std::string> get_numform(uint64_t func_ea, uint64_t stmt_ea, int op_idx) {
    return get_func_data(func_ea).get_numform(stmt_ea, op_idx);
}

void clear_func_overrides(uint64_t func_ea) {
    FuncUserData empty;
    set_func_data(func_ea, empty);
}

bool toggle_iflag(uint64_t func_ea, uint64_t branch_ea) {
    auto d = get_func_data(func_ea);
    bool inv = d.toggle_iflag(branch_ea);
    set_func_data(func_ea, d);
    return inv;
}

bool is_iflag_inverted(uint64_t func_ea, uint64_t branch_ea) {
    return get_func_data(func_ea).is_iflag_inverted(branch_ea);
}

void set_func_proto(uint64_t func_ea, const std::string &proto_str) {
    auto d = get_func_data(func_ea);
    d.set_func_proto(proto_str);
    set_func_data(func_ea, d);
}

bool get_sync_enabled() {
    if (!netnode_inited()) return true;
    netnode node(SPUDEC_NODE_NAME);
    if (node == BADNODE) return true;
    return node.altval(0) != 2;
}

void set_sync_enabled(bool enabled) {
    if (!netnode_inited()) return;
    netnode node = get_or_create_node();
    if (node != BADNODE) {
        node.altset(0, enabled ? 1 : 2);
    }
}

bool get_hide_casts() {
    if (!netnode_inited()) return false;
    netnode node(SPUDEC_NODE_NAME);
    if (node == BADNODE) return false;
    return node.altval(1) == 1;
}

void set_hide_casts(bool enabled) {
    if (!netnode_inited()) return;
    netnode node = get_or_create_node();
    if (node != BADNODE) {
        node.altset(1, enabled ? 1 : 2);
    }
}

void save_window_state(bool is_open, std::optional<uint64_t> func_ea,
                       int lineno, int col, const std::string &mode, bool persist) {
    WindowState st;
    st.is_open = is_open;
    st.func_ea = func_ea;
    st.lineno = lineno;
    st.col = col;
    st.mode = mode;
    g_mem_win_state = st;
    g_has_mem_win_state = true;
    if (persist) {
        write_node_str(SPUDEC_WIN_STATE_KEY, serialize_window_state_json(st));
    }
}

WindowState load_window_state() {
    if (auto raw = read_node_str(SPUDEC_WIN_STATE_KEY); raw.has_value()) {
        WindowState st;
        if (parse_window_state_json(*raw, st)) {
            g_mem_win_state = st;
            g_has_mem_win_state = true;
            return st;
        }
    }
    if (g_has_mem_win_state) return g_mem_win_state;
    return WindowState{};
}

void clear_all() {
    g_mem_win_state = WindowState{};
    g_has_mem_win_state = false;
    if (!netnode_inited()) return;
    netnode node(SPUDEC_NODE_NAME);
    if (node != BADNODE) {
        node.kill();
    }
}

} // namespace idadb
} // namespace spudec
