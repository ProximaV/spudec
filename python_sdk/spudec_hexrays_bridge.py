"""Lightweight IDAPython bootstrapper for `spudec` Hex-Rays (`ida_hexrays`) compatibility.

On Cell SPU databases (`PLFM_SPU == 59`), installs the `spudec` dynamic
`ida_hexrays` compatibility proxy automatically at database load time so generic
IDAPython scripts and MCP tools (`import ida_hexrays; ida_hexrays.decompile(ea)`)
work out-of-the-box without requiring `import spudec` first.

On all non-SPU architectures (x86, x64, ARM, PPC, MIPS, RISC-V, etc.), returns
`PLUGIN_SKIP` immediately without importing `spudec` or touching `ida_hexrays`.
"""

import ida_idaapi
import ida_idp


class _SpuHexraysBridgePlugmod(ida_idaapi.plugmod_t):
    def run(self, _arg):
        return True


class _SpuHexraysBridgePlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_MULTI
    comment = "spudec ida_hexrays compatibility bridge (PLFM_SPU only)"
    help = ""
    wanted_name = "spudec_hexrays_bridge"
    wanted_hotkey = ""

    def init(self):
        if ida_idp.ph_get_id() != getattr(ida_idp, "PLFM_SPU", 59):
            return None
        try:
            import spudec.hexrays_compat as hxc
            hxc.install_hexrays_compat()
        except Exception as exc:
            print(f"[spudec] Failed to install ida_hexrays bridge: {exc}")
        return _SpuHexraysBridgePlugmod()


def PLUGIN_ENTRY():
    return _SpuHexraysBridgePlugin()
