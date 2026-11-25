"""Native C++-backed Python SDK for `spudec` (Cell Broadband Engine SPU Decompiler).

Provides:
  1. Legacy `spudec.*` convenience API (`decompile`, `dump`, `pseudocode`, `decompile_all`, `clear_caches`, `db.*`).
  2. Rich Hex-Rays-compatible `cfunc_t` / `ctree` / `vdui_t` / `Hexrays_Hooks` / `optinsn` scripting API.
  3. Automatic `ida_hexrays` compatibility shim on `PLFM_SPU` databases.
"""

from __future__ import annotations

import ctypes
from typing import Callable, Optional

from . import _ffi, ctree, db, hexrays_compat
from .ctree import (
    CV_FAST,
    CV_INSNS,
    CV_PARENTS,
    CV_POST,
    CV_PRUNE,
    CV_RESTART,
    DECOMP_NO_CACHE,
    DecompilationFailure,
    cblock_t,
    cexpr_t,
    cfunc_t,
    cif_t,
    cinsn_t,
    citem_t,
    cnumber_t,
    ctree_visitor_t,
    hexrays_failure_t,
    lvar_t,
    vdui_t,
)
from .hexrays_compat import (
    Hexrays_Hooks,
    clear_cached_cfuncs,
    get_widget_vdui,
    init_hexrays_plugin,
    install_hexrays_callback,
    install_hexrays_compat,
    mark_cfunc_dirty,
    modify_user_lvars,
    open_pseudocode,
    remove_hexrays_callback,
    rename_lvar,
)

__version__ = "2.0.0-native"


def version() -> str:
    v = _ffi.get_dll().spudec_abi_version()
    return v.decode("utf-8") if v else __version__


def cfunc(ea: int, flags: int = 0) -> cfunc_t:
    """Decompile `ea` and return the structured `cfunc_t` AST object."""
    res = hexrays_compat.decompile(ea, None, flags)
    if res is None:
        raise DecompilationFailure(f"Failed to decompile 0x{int(ea):x}", int(ea))
    return res


def decompile(ea: int) -> str:
    """Decompile SPU function at `ea` and return plain C pseudocode text."""
    dll = _ffi.get_dll()
    err_ptr = ctypes.c_void_p(0)
    txt = _ffi.take_str(dll.spudec_abi_decompile_text(int(ea), ctypes.byref(err_ptr)))
    if txt is None:
        err = _ffi.take_str(err_ptr.value) or f"Decompilation failed at 0x{int(ea):x}"
        raise DecompilationFailure(err, int(ea))
    return txt


def dump(ea: int) -> str:
    """Lift and optimize SPU function at `ea` and return SSA/OutSSA IR dump text."""
    dll = _ffi.get_dll()
    err_ptr = ctypes.c_void_p(0)
    txt = _ffi.take_str(dll.spudec_abi_dump_ir(int(ea), ctypes.byref(err_ptr)))
    if txt is None:
        err = _ffi.take_str(err_ptr.value) or f"IR lift failed at 0x{int(ea):x}"
        raise DecompilationFailure(err, int(ea))
    return txt


def pseudocode(ea: Optional[int] = None) -> Optional[vdui_t]:
    """Open or focus the interactive SPU Pseudocode viewer at `ea` (or current screen EA)."""
    if ea is None:
        import ida_kernwin
        ea = ida_kernwin.get_screen_ea()
    return open_pseudocode(int(ea), 1)


def decompile_all(out_path: Optional[str] = None) -> str:
    """Decompile all functions in the SPU database (optionally writing `.c` to `out_path`)."""
    dll = _ffi.get_dll()
    ok_cnt = ctypes.c_int(0)
    fail_cnt = ctypes.c_int(0)
    enc = out_path.encode("utf-8") if out_path else None
    res = _ffi.take_str(
        dll.spudec_abi_decompile_all(enc, ctypes.byref(ok_cnt), ctypes.byref(fail_cnt))
    )
    return res or ""


def clear_caches() -> None:
    """Invalidate all cached function summaries and `cfunc_t` results."""
    _ffi.get_dll().spudec_abi_clear_caches()


def register_optinsn(cb: Callable[[int, int, int, int, int], int]) -> int:
    """Register a custom IR instruction pass callback `(func_ea, blk_id, insn_idx, op, insn_ea) -> int`."""
    return _ffi.register_optinsn_cb(cb)


def unregister_optinsn(handle: int) -> bool:
    """Unregister a custom IR instruction pass callback."""
    return _ffi.unregister_optinsn_handle(handle)


def optinsn_nop(func_ea: int, blk_id: int, insn_idx: int) -> int:
    """Replace an IR instruction with `NOP` from inside a `register_optinsn` callback."""
    return int(_ffi.get_dll().spudec_abi_optinsn_nop(int(func_ea), int(blk_id), int(insn_idx)))


# Automatically activate the PLFM_SPU-scoped ida_hexrays bridge when `spudec` is imported
if _ffi.is_spu_processor():
    install_hexrays_compat()
