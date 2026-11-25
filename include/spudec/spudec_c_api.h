#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
  #if defined(SPUDEC_BUILDING_DLL)
    #define SPUDEC_API_EXPORT __declspec(dllexport)
  #else
    #define SPUDEC_API_EXPORT __declspec(dllimport)
  #endif
#else
  #define SPUDEC_API_EXPORT __attribute__((visibility("default")))
#endif

/*
 * Stable C ABI exported by spudec.dll for:
 *   1. Python ctypes SDK (`spudec` + `ida_hexrays` compatibility shim on PLFM_SPU)
 *   2. External native tools / plugins
 *
 * Returned `char *` buffers allocated by spudec must be freed via `spudec_abi_free_str`.
 */

typedef int (__cdecl *spudec_abi_event_cb_t)(int event_code, uint64_t cfunc_handle, uint64_t aux, void *ud);
typedef int (__cdecl *spudec_abi_optinsn_cb_t)(uint64_t func_ea, int block_id, int insn_idx,
                                               int op_code, uint64_t insn_ea, void *ud);

SPUDEC_API_EXPORT const char * __cdecl spudec_abi_version(void);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_is_spu_db(void);
SPUDEC_API_EXPORT void         __cdecl spudec_abi_free_str(char *s);

/* Cache & lifecycle */
SPUDEC_API_EXPORT void         __cdecl spudec_abi_clear_caches(void);
SPUDEC_API_EXPORT void         __cdecl spudec_abi_mark_dirty(uint64_t func_ea, int close_views);

/* Core decompilation & cfunc_t handle management */
SPUDEC_API_EXPORT uint64_t     __cdecl spudec_abi_decompile(uint64_t ea, int flags, char **out_err);
SPUDEC_API_EXPORT void         __cdecl spudec_abi_release_cfunc(uint64_t handle);
SPUDEC_API_EXPORT char *       __cdecl spudec_abi_cfunc_text(uint64_t handle);
SPUDEC_API_EXPORT char *       __cdecl spudec_abi_cfunc_json(uint64_t handle, int include_ctree);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_cfunc_mutate_item(
    uint64_t handle,
    uint32_t obj_id,
    int new_op,
    uint64_t new_numval,
    int new_var_idx,
    const char *new_str,
    const char *new_helper);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_cfunc_swap_if(uint64_t handle, uint32_t if_obj_id);
SPUDEC_API_EXPORT char *       __cdecl spudec_abi_cfunc_refresh_ctext(uint64_t handle);

/* Fast text helpers */
SPUDEC_API_EXPORT char *       __cdecl spudec_abi_decompile_text(uint64_t ea, char **out_err);
SPUDEC_API_EXPORT char *       __cdecl spudec_abi_dump_ir(uint64_t ea, char **out_err);
SPUDEC_API_EXPORT char *       __cdecl spudec_abi_decompile_all(const char *out_path, int *out_ok, int *out_fail);

/* Interactive pseudocode viewer (vdui_t) */
SPUDEC_API_EXPORT int          __cdecl spudec_abi_open_pseudocode(uint64_t ea, int open_flags);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_vdui_is_open(void);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_vdui_refresh(int force_redecompile);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_vdui_switch_to(uint64_t ea, int push_history);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_vdui_get_state(
    uint64_t *out_func_ea,
    uint64_t *out_cfunc_handle,
    int *out_lineno,
    int *out_col,
    uint32_t *out_citem_id);

/* Persistent "$ spudec" netnode user annotations */
SPUDEC_API_EXPORT char *       __cdecl spudec_abi_get_user_data_json(uint64_t func_ea);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_set_user_data_json(uint64_t func_ea, const char *json_str);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_rename_lvar(uint64_t func_ea, const char *old_name, const char *new_name);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_set_lvar_type(uint64_t func_ea, const char *var_name, const char *type_str);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_set_proto(uint64_t func_ea, const char *proto_str);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_set_cmt(uint64_t func_ea, uint64_t stmt_ea, const char *cmt_str);
SPUDEC_API_EXPORT char *       __cdecl spudec_abi_get_cmt(uint64_t func_ea, uint64_t stmt_ea);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_set_numform(uint64_t func_ea, uint64_t stmt_ea, int op_idx, const char *form_str);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_invert_if(uint64_t func_ea, uint64_t branch_ea);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_get_hide_casts(void);
SPUDEC_API_EXPORT void         __cdecl spudec_abi_set_hide_casts(int hide);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_reset_overrides(uint64_t func_ea);

/* Scripting callbacks & custom IR passes */
SPUDEC_API_EXPORT int          __cdecl spudec_abi_register_callback(spudec_abi_event_cb_t cb, void *ud);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_unregister_callback(int cb_handle);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_register_optinsn(spudec_abi_optinsn_cb_t cb, void *ud);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_unregister_optinsn(int hook_handle);
SPUDEC_API_EXPORT int          __cdecl spudec_abi_optinsn_nop(uint64_t func_ea, int block_id, int insn_idx);

#ifdef __cplusplus
}
#endif