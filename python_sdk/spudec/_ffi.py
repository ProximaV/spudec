"""Low-level ctypes FFI binding to native spudec.dll."""

from __future__ import annotations

import ctypes
import json
import os
from typing import Any, Callable, Optional

_DLL: Optional[ctypes.CDLL] = None
_ACTIVE_EVENT_CBS: dict[int, Any] = {}
_ACTIVE_OPT_CBS: dict[int, Any] = {}

EVENT_CB_TYPE = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_void_p,
)

OPTINSN_CB_TYPE = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_uint64,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_uint64,
    ctypes.c_void_p,
)


def is_spu_processor() -> bool:
    """Return True if the active IDA database uses the Cell SPU processor (PLFM_SPU == 59)."""
    try:
        import ida_idp
        return ida_idp.ph_get_id() == getattr(ida_idp, "PLFM_SPU", 59)
    except Exception:
        return False


def _ensure_ida_plugin_loaded() -> None:
    if not is_spu_processor():
        return
    try:
        import ida_loader
        ida_loader.load_plugin("spudec")
    except Exception:
        pass


def _bind_signatures(dll: ctypes.CDLL) -> None:
    dll.spudec_abi_version.argtypes = []
    dll.spudec_abi_version.restype = ctypes.c_char_p

    dll.spudec_abi_is_spu_db.argtypes = []
    dll.spudec_abi_is_spu_db.restype = ctypes.c_int

    dll.spudec_abi_free_str.argtypes = [ctypes.c_void_p]
    dll.spudec_abi_free_str.restype = None

    dll.spudec_abi_clear_caches.argtypes = []
    dll.spudec_abi_clear_caches.restype = None

    dll.spudec_abi_mark_dirty.argtypes = [ctypes.c_uint64, ctypes.c_int]
    dll.spudec_abi_mark_dirty.restype = None

    dll.spudec_abi_decompile.argtypes = [ctypes.c_uint64, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    dll.spudec_abi_decompile.restype = ctypes.c_uint64

    dll.spudec_abi_release_cfunc.argtypes = [ctypes.c_uint64]
    dll.spudec_abi_release_cfunc.restype = None

    dll.spudec_abi_cfunc_text.argtypes = [ctypes.c_uint64]
    dll.spudec_abi_cfunc_text.restype = ctypes.c_void_p

    dll.spudec_abi_cfunc_json.argtypes = [ctypes.c_uint64, ctypes.c_int]
    dll.spudec_abi_cfunc_json.restype = ctypes.c_void_p

    dll.spudec_abi_cfunc_mutate_item.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    dll.spudec_abi_cfunc_mutate_item.restype = ctypes.c_int

    dll.spudec_abi_cfunc_swap_if.argtypes = [ctypes.c_uint64, ctypes.c_uint32]
    dll.spudec_abi_cfunc_swap_if.restype = ctypes.c_int

    dll.spudec_abi_cfunc_refresh_ctext.argtypes = [ctypes.c_uint64]
    dll.spudec_abi_cfunc_refresh_ctext.restype = ctypes.c_void_p

    dll.spudec_abi_decompile_text.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_void_p)]
    dll.spudec_abi_decompile_text.restype = ctypes.c_void_p

    dll.spudec_abi_dump_ir.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_void_p)]
    dll.spudec_abi_dump_ir.restype = ctypes.c_void_p

    dll.spudec_abi_decompile_all.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
    ]
    dll.spudec_abi_decompile_all.restype = ctypes.c_void_p

    dll.spudec_abi_open_pseudocode.argtypes = [ctypes.c_uint64, ctypes.c_int]
    dll.spudec_abi_open_pseudocode.restype = ctypes.c_int

    dll.spudec_abi_vdui_is_open.argtypes = []
    dll.spudec_abi_vdui_is_open.restype = ctypes.c_int

    dll.spudec_abi_vdui_refresh.argtypes = [ctypes.c_int]
    dll.spudec_abi_vdui_refresh.restype = ctypes.c_int

    dll.spudec_abi_vdui_switch_to.argtypes = [ctypes.c_uint64, ctypes.c_int]
    dll.spudec_abi_vdui_switch_to.restype = ctypes.c_int

    dll.spudec_abi_vdui_get_state.argtypes = [
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    dll.spudec_abi_vdui_get_state.restype = ctypes.c_int

    dll.spudec_abi_get_user_data_json.argtypes = [ctypes.c_uint64]
    dll.spudec_abi_get_user_data_json.restype = ctypes.c_void_p

    dll.spudec_abi_set_user_data_json.argtypes = [ctypes.c_uint64, ctypes.c_char_p]
    dll.spudec_abi_set_user_data_json.restype = ctypes.c_int

    dll.spudec_abi_rename_lvar.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]
    dll.spudec_abi_rename_lvar.restype = ctypes.c_int

    dll.spudec_abi_set_lvar_type.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]
    dll.spudec_abi_set_lvar_type.restype = ctypes.c_int

    dll.spudec_abi_set_proto.argtypes = [ctypes.c_uint64, ctypes.c_char_p]
    dll.spudec_abi_set_proto.restype = ctypes.c_int

    dll.spudec_abi_set_cmt.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p]
    dll.spudec_abi_set_cmt.restype = ctypes.c_int

    dll.spudec_abi_get_cmt.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    dll.spudec_abi_get_cmt.restype = ctypes.c_void_p

    dll.spudec_abi_set_numform.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
    dll.spudec_abi_set_numform.restype = ctypes.c_int

    dll.spudec_abi_invert_if.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    dll.spudec_abi_invert_if.restype = ctypes.c_int

    dll.spudec_abi_get_hide_casts.argtypes = []
    dll.spudec_abi_get_hide_casts.restype = ctypes.c_int

    dll.spudec_abi_set_hide_casts.argtypes = [ctypes.c_int]
    dll.spudec_abi_set_hide_casts.restype = None

    dll.spudec_abi_reset_overrides.argtypes = [ctypes.c_uint64]
    dll.spudec_abi_reset_overrides.restype = ctypes.c_int

    dll.spudec_abi_register_callback.argtypes = [EVENT_CB_TYPE, ctypes.c_void_p]
    dll.spudec_abi_register_callback.restype = ctypes.c_int

    dll.spudec_abi_unregister_callback.argtypes = [ctypes.c_int]
    dll.spudec_abi_unregister_callback.restype = ctypes.c_int

    dll.spudec_abi_register_optinsn.argtypes = [OPTINSN_CB_TYPE, ctypes.c_void_p]
    dll.spudec_abi_register_optinsn.restype = ctypes.c_int

    dll.spudec_abi_unregister_optinsn.argtypes = [ctypes.c_int]
    dll.spudec_abi_unregister_optinsn.restype = ctypes.c_int

    dll.spudec_abi_optinsn_nop.argtypes = [ctypes.c_uint64, ctypes.c_int, ctypes.c_int]
    dll.spudec_abi_optinsn_nop.restype = ctypes.c_int


def get_dll() -> ctypes.CDLL:
    """Locate and bind the in-process spudec.dll loaded by IDA."""
    global _DLL
    if _DLL is not None:
        _ensure_ida_plugin_loaded()
        return _DLL

    _ensure_ida_plugin_loaded()

    if os.name == "nt":
        k32 = ctypes.windll.kernel32
        k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
        k32.GetModuleHandleW.restype = ctypes.c_void_p
        for mod_name in ("spudec.dll", "spudec64.dll"):
            hmod = k32.GetModuleHandleW(mod_name)
            if hmod:
                dll = ctypes.CDLL(mod_name, handle=hmod)
                _bind_signatures(dll)
                _DLL = dll
                return _DLL

    # Fallback: load from plugins directory adjacent to `spudec` package
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(pkg_dir)
    candidates = [
        os.path.join(parent_dir, "spudec.dll"),
        os.path.join(parent_dir, "build", "spudec.dll"),
        os.path.join(parent_dir, "build", "Release", "spudec.dll"),
    ]
    try:
        import ida_diskio
        user_plg = os.path.join(ida_diskio.get_user_idadir(), "plugins", "spudec.dll")
        candidates.insert(0, user_plg)
    except Exception:
        pass

    for path in candidates:
        if os.path.isfile(path):
            dll = ctypes.CDLL(path)
            _bind_signatures(dll)
            _DLL = dll
            return _DLL

    raise RuntimeError("spudec.dll could not be located in IDA plugins directory.")


def take_str(ptr: Optional[int]) -> Optional[str]:
    """Decode a heap-allocated UTF-8 C string from spudec.dll and free it."""
    if not ptr:
        return None
    dll = get_dll()
    try:
        raw = ctypes.cast(ptr, ctypes.c_char_p).value
        return raw.decode("utf-8", errors="replace") if raw is not None else ""
    finally:
        dll.spudec_abi_free_str(ptr)


def take_json(ptr: Optional[int]) -> Any:
    s = take_str(ptr)
    if not s:
        return None
    return json.loads(s)


def register_event_cb(py_fn: Callable[[int, int, int], int]) -> int:
    dll = get_dll()

    @EVENT_CB_TYPE
    def _trampoline(ev: int, cf_handle: int, aux: int, _ud: int) -> int:
        try:
            rc = py_fn(ev, cf_handle, aux)
            return int(rc) if rc is not None else 0
        except Exception as exc:
            print(f"[spudec] Python event callback error: {exc}")
            return 0

    handle = dll.spudec_abi_register_callback(_trampoline, None)
    if handle >= 0:
        _ACTIVE_EVENT_CBS[handle] = (_trampoline, py_fn)
    return handle


def unregister_event_cb_by_fn(py_fn: Callable[..., Any]) -> bool:
    dll = get_dll()
    for h, (_tramp, orig) in list(_ACTIVE_EVENT_CBS.items()):
        if orig == py_fn:
            dll.spudec_abi_unregister_callback(h)
            del _ACTIVE_EVENT_CBS[h]
            return True
    return False


def unregister_event_cb_handle(handle: int) -> bool:
    dll = get_dll()
    ok = bool(dll.spudec_abi_unregister_callback(handle))
    _ACTIVE_EVENT_CBS.pop(handle, None)
    return ok


def register_optinsn_cb(py_fn: Callable[[int, int, int, int, int], int]) -> int:
    dll = get_dll()

    @OPTINSN_CB_TYPE
    def _trampoline(func_ea: int, blk_id: int, insn_idx: int, op_code: int, insn_ea: int, _ud: int) -> int:
        try:
            rc = py_fn(func_ea, blk_id, insn_idx, op_code, insn_ea)
            return int(rc) if rc is not None else 0
        except Exception as exc:
            print(f"[spudec] Python optinsn callback error: {exc}")
            return 0

    handle = dll.spudec_abi_register_optinsn(_trampoline, None)
    if handle >= 0:
        _ACTIVE_OPT_CBS[handle] = (_trampoline, py_fn)
    return handle


def unregister_optinsn_handle(handle: int) -> bool:
    dll = get_dll()
    ok = bool(dll.spudec_abi_unregister_optinsn(handle))
    _ACTIVE_OPT_CBS.pop(handle, None)
    return ok
