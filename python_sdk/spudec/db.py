"""Backward-compatible `spudec.db` Python module backed by native spudec.dll."""

from __future__ import annotations

import json
from typing import Any, Optional
from . import _ffi

SPUDEC_NODE_NAME = "$ spudec"


def get_func_data(func_ea: int) -> dict[str, Any]:
    dll = _ffi.get_dll()
    res = _ffi.take_json(dll.spudec_abi_get_user_data_json(int(func_ea)))
    if not isinstance(res, dict):
        return {
            "renames": {},
            "types": {},
            "proto": None,
            "lvars": {},
            "cmts": {},
            "numforms": {},
            "iflags": [],
        }
    res.setdefault("renames", {})
    res.setdefault("types", {})
    res.setdefault("proto", None)
    res.setdefault("lvars", {})
    res.setdefault("cmts", {})
    res.setdefault("numforms", {})
    res.setdefault("iflags", [])
    return res


def set_func_data(func_ea: int, data: dict[str, Any]) -> bool:
    dll = _ffi.get_dll()
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return bool(dll.spudec_abi_set_user_data_json(int(func_ea), payload))


def set_var_rename(func_ea: int, old_name: str, new_name: str) -> bool:
    dll = _ffi.get_dll()
    return bool(
        dll.spudec_abi_rename_lvar(
            int(func_ea),
            old_name.encode("utf-8"),
            (new_name or "").encode("utf-8"),
        )
    )


def set_var_type(func_ea: int, var_name: str, type_str: str) -> bool:
    dll = _ffi.get_dll()
    return bool(
        dll.spudec_abi_set_lvar_type(
            int(func_ea),
            var_name.encode("utf-8"),
            (type_str or "").encode("utf-8"),
        )
    )


def set_func_proto(func_ea: int, proto_str: str) -> bool:
    dll = _ffi.get_dll()
    return bool(dll.spudec_abi_set_proto(int(func_ea), (proto_str or "").encode("utf-8")))


def set_statement_cmt(func_ea: int, stmt_ea: int, cmt_str: str) -> bool:
    dll = _ffi.get_dll()
    return bool(
        dll.spudec_abi_set_cmt(int(func_ea), int(stmt_ea), (cmt_str or "").encode("utf-8"))
    )


def get_statement_cmt(func_ea: int, stmt_ea: int) -> Optional[str]:
    dll = _ffi.get_dll()
    return _ffi.take_str(dll.spudec_abi_get_cmt(int(func_ea), int(stmt_ea)))


def set_numform(func_ea: int, stmt_ea: int, op_idx: int, form_str: str) -> bool:
    dll = _ffi.get_dll()
    return bool(
        dll.spudec_abi_set_numform(
            int(func_ea), int(stmt_ea), int(op_idx), (form_str or "").encode("utf-8")
        )
    )


def toggle_iflag(func_ea: int, branch_ea: int) -> bool:
    dll = _ffi.get_dll()
    return bool(dll.spudec_abi_invert_if(int(func_ea), int(branch_ea)))


def get_hide_casts() -> bool:
    return bool(_ffi.get_dll().spudec_abi_get_hide_casts())


def set_hide_casts(enabled: bool) -> None:
    _ffi.get_dll().spudec_abi_set_hide_casts(1 if enabled else 0)


def clear_func_overrides(func_ea: int) -> bool:
    return bool(_ffi.get_dll().spudec_abi_reset_overrides(int(func_ea)))
