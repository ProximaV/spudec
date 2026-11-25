#pragma once

/*
 * Header-only C++ Plugin-to-Plugin SDK for spudec (`<spudec/spudec_api.hpp>`)
 *
 * Allows any other native C++ IDA 9.5 plugin to invoke `spudec` on Cell SPU
 * databases via `callui(ui_broadcast, ...)` without linking against `spudec.lib`.
 */

#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>

#include <cstdint>
#include <memory>
#include <string>

#include "ctree.hpp"
#include "pipeline.hpp"

namespace spudec {
namespace sdk {

inline constexpr int BROADCAST_MAGIC = 0x53505544; // 'SPUD'

struct BroadcastReq {
    uint32_t struct_size = sizeof(BroadcastReq);
    int op = 0;
    uint64_t ea = 0;
    uint64_t ea2 = 0;
    int flags = 0;
    const char *str_arg1 = nullptr;
    const char *str_arg2 = nullptr;
    void *ptr_arg = nullptr;
    int status = -1;
    void *out_ptr = nullptr;
    qstring out_str;
};

enum BroadcastOp : int {
    OP_PING            = 1,
    OP_DECOMPILE_CFUNC = 2,
    OP_DECOMPILE_TEXT  = 3,
    OP_DUMP_IR_TEXT    = 4,
    OP_OPEN_PSEUDOCODE = 5,
    OP_MARK_DIRTY      = 6,
    OP_CLEAR_CACHES    = 7,
    OP_RENAME_LVAR     = 8,
    OP_SET_LVAR_TYPE   = 9,
    OP_SET_PROTO       = 10,
    OP_SET_CMT         = 11,
    OP_SET_NUMFORM     = 12,
    OP_INVERT_IF       = 13,
    OP_REG_EVENT_CB    = 14,
    OP_UNREG_EVENT_CB  = 15,
};

inline bool init_spudec_plugin() {
    if (PH.id != PLFM_SPU) return false;
    BroadcastReq req;
    req.op = OP_PING;
    if (callui(ui_broadcast, BROADCAST_MAGIC, &req).i != 0 && req.status == 0) {
        return true;
    }
    load_plugin("spudec");
    req = BroadcastReq{};
    req.op = OP_PING;
    return callui(ui_broadcast, BROADCAST_MAGIC, &req).i != 0 && req.status == 0;
}

inline cfuncptr_t decompile(ea_t ea, int flags = 0, qstring *out_err = nullptr) {
    if (!init_spudec_plugin()) {
        if (out_err) *out_err = "spudec plugin unavailable or non-SPU database";
        return nullptr;
    }
    cfuncptr_t holder;
    BroadcastReq req;
    req.op = OP_DECOMPILE_CFUNC;
    req.ea = static_cast<uint64_t>(ea);
    req.flags = flags;
    req.ptr_arg = &holder;
    callui(ui_broadcast, BROADCAST_MAGIC, &req);
    if (req.status != 0 || !holder) {
        if (out_err) *out_err = req.out_str;
        return nullptr;
    }
    return holder;
}

inline std::string decompile_text(ea_t ea) {
    if (!init_spudec_plugin()) return {};
    BroadcastReq req;
    req.op = OP_DECOMPILE_TEXT;
    req.ea = static_cast<uint64_t>(ea);
    callui(ui_broadcast, BROADCAST_MAGIC, &req);
    return (req.status == 0) ? std::string(req.out_str.c_str()) : std::string();
}

inline std::string dump_ir_text(ea_t ea) {
    if (!init_spudec_plugin()) return {};
    BroadcastReq req;
    req.op = OP_DUMP_IR_TEXT;
    req.ea = static_cast<uint64_t>(ea);
    callui(ui_broadcast, BROADCAST_MAGIC, &req);
    return (req.status == 0) ? std::string(req.out_str.c_str()) : std::string();
}

inline bool open_pseudocode(ea_t ea, int flags = 0) {
    if (!init_spudec_plugin()) return false;
    BroadcastReq req;
    req.op = OP_OPEN_PSEUDOCODE;
    req.ea = static_cast<uint64_t>(ea);
    req.flags = flags;
    callui(ui_broadcast, BROADCAST_MAGIC, &req);
    return req.status == 0;
}

inline void mark_cfunc_dirty(ea_t ea = BADADDR) {
    if (!init_spudec_plugin()) return;
    BroadcastReq req;
    req.op = OP_MARK_DIRTY;
    req.ea = static_cast<uint64_t>(ea);
    callui(ui_broadcast, BROADCAST_MAGIC, &req);
}

inline void clear_cached_cfuncs() {
    if (!init_spudec_plugin()) return;
    BroadcastReq req;
    req.op = OP_CLEAR_CACHES;
    callui(ui_broadcast, BROADCAST_MAGIC, &req);
}

inline bool rename_lvar(ea_t func_ea, const char *old_name, const char *new_name) {
    if (!init_spudec_plugin()) return false;
    BroadcastReq req;
    req.op = OP_RENAME_LVAR;
    req.ea = static_cast<uint64_t>(func_ea);
    req.str_arg1 = old_name;
    req.str_arg2 = new_name;
    callui(ui_broadcast, BROADCAST_MAGIC, &req);
    return req.status == 0;
}

inline bool set_lvar_type(ea_t func_ea, const char *var_name, const char *type_str) {
    if (!init_spudec_plugin()) return false;
    BroadcastReq req;
    req.op = OP_SET_LVAR_TYPE;
    req.ea = static_cast<uint64_t>(func_ea);
    req.str_arg1 = var_name;
    req.str_arg2 = type_str;
    callui(ui_broadcast, BROADCAST_MAGIC, &req);
    return req.status == 0;
}

inline int install_callback(SpudecEventCallback cb) {
    if (!init_spudec_plugin()) return -1;
    BroadcastReq req;
    req.op = OP_REG_EVENT_CB;
    req.ptr_arg = &cb;
    callui(ui_broadcast, BROADCAST_MAGIC, &req);
    return req.status;
}

inline bool remove_callback(int handle) {
    if (!init_spudec_plugin()) return false;
    BroadcastReq req;
    req.op = OP_UNREG_EVENT_CB;
    req.flags = handle;
    callui(ui_broadcast, BROADCAST_MAGIC, &req);
    return req.status == 0;
}

} // namespace sdk
} // namespace spudec