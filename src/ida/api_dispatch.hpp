#pragma once

#include <ida.hpp>
#include <cstdint>

namespace spudec {

inline constexpr int SPUDEC_BROADCAST_MAGIC = 0x53505544; // 'SPUD'

struct SpudecBroadcastReq {
    uint32_t struct_size = sizeof(SpudecBroadcastReq);
    int op = 0;
    uint64_t ea = 0;
    uint64_t ea2 = 0;
    int flags = 0;
    const char *str_arg1 = nullptr;
    const char *str_arg2 = nullptr;
    void *ptr_arg = nullptr;
    // Outputs
    int status = -1;
    void *out_ptr = nullptr;
    qstring out_str;
};

enum SpudecBroadcastOp : int {
    SPUDEC_BCAST_PING            = 1,
    SPUDEC_BCAST_DECOMPILE_CFUNC = 2, // out_ptr -> std::shared_ptr<cfunc_t>* (caller adopts or borrows)
    SPUDEC_BCAST_DECOMPILE_TEXT  = 3, // out_str -> pseudocode text
    SPUDEC_BCAST_DUMP_IR_TEXT    = 4, // out_str -> lifted IR text
    SPUDEC_BCAST_OPEN_PSEUDOCODE = 5, // out_ptr -> SpuVdui*
    SPUDEC_BCAST_MARK_DIRTY      = 6,
    SPUDEC_BCAST_CLEAR_CACHES    = 7,
    SPUDEC_BCAST_RENAME_LVAR     = 8,
    SPUDEC_BCAST_SET_LVAR_TYPE   = 9,
    SPUDEC_BCAST_SET_PROTO       = 10,
    SPUDEC_BCAST_SET_CMT         = 11,
    SPUDEC_BCAST_SET_NUMFORM     = 12,
    SPUDEC_BCAST_INVERT_IF       = 13,
    SPUDEC_BCAST_REG_EVENT_CB    = 14,
    SPUDEC_BCAST_UNREG_EVENT_CB  = 15,
};

bool handle_spudec_broadcast(SpudecBroadcastReq *req);
void clear_api_handles();

} // namespace spudec