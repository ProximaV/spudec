"""
Interactive IDA custom viewer for spudec pseudocode.

Provides Hex-Rays-style interactivity:
- Navigation without history flooding:
  - Scrolling / cursor sync in the same function uses UIJMP_DONTPUSH so IDA's
    Back/Forward arrows navigate between functions rather than line-by-line.
  - Enter / double-click on a callee, symbol, or address pushes one nav point.
  - Esc navigates Back, Ctrl-Enter navigates Forward, Tab switches to Disassembly,
    G jumps to an address, X opens Cross-References.
- Variable / symbol / function editing:
  - N: rename variable, parameter, stack slot, global symbol, or function.
  - Y: set type for local/stack var, parameter (anywhere), callee prototype,
       global symbol, return type, or full function prototype (with C++ `::`
       sanitization and IDA stack frame + type library propagation).
- Constant & display formatting (per-constant on multi-constant lines):
  - H: toggle Hexadecimal <-> Decimal (or String -> Hex address)
  - A: create/toggle ASCII string literal at address, or char literal on immediate
  - R: toggle Character constant ('E', '\\x7FELF')
  - B: toggle Binary (0b...)
  - _: invert sign (signed <-> unsigned)
  - ~: bitwise negate (~0x...)
  - O: toggle Offset / Symbol (&sym)
  - M: apply IDA symbolic enum constant
  - / or ;: add/edit statement comment
  - I: invert if-statement (swap then/else)
  - \\: toggle Hide/Show casts
  - Shift-I: toggle C Pseudocode / SSA IR
  - F5: refresh decompilation
- Reusable dockable window that updates in place during navigation.
"""

import re
import ida_kernwin
import ida_funcs
import ida_lines
import ida_typeinf
import idaapi

from .ir import Op
from . import highlight, db
from . import regs

_EA = re.compile(r"\b(?:loc_|sub_)([0-9A-Fa-f]+)\b")
_ADDR_HEX = re.compile(r"\b0x([0-9A-Fa-f]{3,8})\b")
_VIEW_TITLE = "spudec - Pseudocode"

ACTION_DECOMPILE = "spudec:decompile"
ACTION_RENAME = "spudec:rename_var"
ACTION_SET_TYPE = "spudec:set_type"
ACTION_EDIT_CMT = "spudec:edit_comment"
ACTION_EDIT_CMT_SEMI = "spudec:edit_comment_semi"
ACTION_TOGGLE_HEX = "spudec:toggle_hex"
ACTION_TOGGLE_CHAR = "spudec:toggle_char"
ACTION_MAKE_ASCII = "spudec:make_ascii"
ACTION_TOGGLE_BIN = "spudec:toggle_bin"
ACTION_TOGGLE_SIGNED = "spudec:toggle_signed"
ACTION_TOGGLE_INV = "spudec:toggle_inv"
ACTION_TOGGLE_OFFSET = "spudec:toggle_offset"
ACTION_SET_ENUM = "spudec:set_enum"
ACTION_INVERT_IF = "spudec:invert_if"
ACTION_TOGGLE_CASTS = "spudec:toggle_casts"
ACTION_SHOW_XREFS = "spudec:show_xrefs"
ACTION_JUMP_ADDR = "spudec:jump_addr"
ACTION_JUMP_DISASM = "spudec:jump_disasm"
ACTION_SWITCH_DISASM = "spudec:switch_disasm"
ACTION_NAV_BACK = "spudec:nav_back"
ACTION_NAV_FORWARD = "spudec:nav_forward"
ACTION_TOGGLE_SYNC = "spudec:toggle_sync"
ACTION_TOGGLE_IR = "spudec:toggle_ir"
ACTION_REFRESH = "spudec:refresh"
ACTION_RESET_OVERRIDES = "spudec:reset_overrides"

_ALL_VIEW_ACTIONS = (
    ACTION_RENAME,
    ACTION_SET_TYPE,
    ACTION_EDIT_CMT,
    ACTION_EDIT_CMT_SEMI,
    ACTION_TOGGLE_HEX,
    ACTION_TOGGLE_CHAR,
    ACTION_MAKE_ASCII,
    ACTION_TOGGLE_BIN,
    ACTION_TOGGLE_SIGNED,
    ACTION_TOGGLE_INV,
    ACTION_TOGGLE_OFFSET,
    ACTION_SET_ENUM,
    ACTION_INVERT_IF,
    ACTION_TOGGLE_CASTS,
    ACTION_SHOW_XREFS,
    ACTION_JUMP_ADDR,
    ACTION_JUMP_DISASM,
    ACTION_SWITCH_DISASM,
    ACTION_NAV_BACK,
    ACTION_NAV_FORWARD,
    ACTION_TOGGLE_SYNC,
    ACTION_TOGGLE_IR,
    ACTION_REFRESH,
    ACTION_RESET_OVERRIDES,
)

_active_viewer = None
_ui_hooks = None
_view_hooks = None


def _is_dark_theme():
    """Detect if IDA is currently using a dark theme."""
    try:
        from PySide6 import QtWidgets, QtGui
        app = QtWidgets.QApplication.instance()
        if app:
            pal = app.palette()
            role = QtGui.QPalette.ColorRole.Base if hasattr(QtGui.QPalette, "ColorRole") else QtGui.QPalette.Base
            return pal.color(role).lightness() < 128
    except Exception:
        pass
    try:
        from PyQt5 import QtWidgets, QtGui
        app = QtWidgets.QApplication.instance()
        if app:
            pal = app.palette()
            role = QtGui.QPalette.ColorRole.Base if hasattr(QtGui.QPalette, "ColorRole") else QtGui.QPalette.Base
            return pal.color(role).lightness() < 128
    except Exception:
        pass
    return False


def _get_highlight_colors():
    """Return (asm_highlight_color, decomp_highlight_bg) based on active IDA theme."""
    if _is_dark_theme():
        # Soft slate blue / dark cyan highlight in dark mode
        return 0x304855, 0x283848
    else:
        # Soft sky blue / cyan highlight in light mode
        return 0xC0E0FF, 0xD0E8FF


def _line_ea(line):
    """Extract code linear address from loc_XXXXX, sub_XXXXX, or 0xXXXXX in line."""
    clean = ida_lines.tag_remove(line) if hasattr(ida_lines, "tag_remove") else line
    m = _EA.search(clean)
    if m:
        try:
            return int(m.group(1), 16)
        except ValueError:
            pass
    m = _ADDR_HEX.search(clean)
    if m:
        try:
            return int(m.group(1), 16)
        except ValueError:
            pass
    return None


def _jumpto_disasm(ea, push_history=False, activate=False):
    """Jump to ea in IDA disassembly view (IDA View-A).

    Uses UIJMP_DONTPUSH by default so cursor movement / scrolling inside a
    function does NOT flood IDA's Back/Forward navigation history.
    Pass push_history=True only for explicit cross-function or symbol jumps.
    """
    if ea is None:
        return False
    try:
        flags = getattr(ida_kernwin, "UIJMP_IDAVIEW", 0x0004)
        if not push_history:
            flags |= getattr(ida_kernwin, "UIJMP_DONTPUSH", 0x0002)
        if activate:
            flags |= getattr(ida_kernwin, "UIJMP_ACTIVATE", 0x0001)
        return ida_kernwin.jumpto(ea, -1, flags)
    except Exception:
        try:
            return idaapi.jumpto(ea)
        except Exception:
            return False


def _parse_c_type_tinfo(type_str):
    """Parse a C type string into an IDA tinfo_t, or return None."""
    try:
        tif = ida_typeinf.tinfo_t()
        clean = type_str.strip().rstrip(";")
        if not clean:
            return None
        if ida_typeinf.parse_decl(tif, None, clean + ";", ida_typeinf.PT_TYP):
            return tif
        if ida_typeinf.parse_decl(tif, None, f"{clean} _spudec_var;", ida_typeinf.PT_SIL) is not None:
            return tif
        # Fallback: direct named type lookup (structs/typedefs + pointer stars)
        stars = 0
        bare = clean
        while bare.endswith("*"):
            stars += 1
            bare = bare[:-1].strip()
        for prefix in ("const ", "volatile ", "struct ", "union ", "enum "):
            if bare.startswith(prefix):
                bare = bare[len(prefix):].strip()
        if bare and tif.get_named_type(None, bare):
            for _ in range(stars):
                ptif = ida_typeinf.tinfo_t()
                ptif.create_ptr(tif)
                tif = ptif
            return tif
    except Exception:
        pass
    return None


def _apply_proto_to_ida(ea, proto_str):
    """Parse prototype string (including C++ qualified names) and apply to ea in IDA."""
    from . import abi
    try:
        candidates = [
            proto_str.strip().rstrip(";") + ";",
            abi.sanitize_decl_for_ida(proto_str, replace_this=False, replace_qualified_types=False),
            abi.sanitize_decl_for_ida(proto_str, replace_this=True, replace_qualified_types=False),
            abi.sanitize_decl_for_ida(proto_str, replace_this=True, replace_qualified_types=True),
        ]
        seen = set()
        for decl in candidates:
            if not decl or decl in seen:
                continue
            seen.add(decl)
            tif = ida_typeinf.tinfo_t()
            if ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL) is not None and tif.is_func():
                ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
                return True
    except Exception:
        pass
    return False


def _find_ida_enum_matches(val):
    """Search IDA's local type library and enums for symbolic constants matching val."""
    matches = []
    seen = set()
    # 1. IDA 9.x Local Type Library enums (tinfo_t::is_enum)
    try:
        til = ida_typeinf.get_idati()
        if til is not None:
            limit = ida_typeinf.get_ordinal_limit(til)
            for ordinal in range(1, limit):
                tif = ida_typeinf.tinfo_t()
                if not tif.get_numbered_type(til, ordinal):
                    continue
                if not tif.is_enum():
                    continue
                etd = ida_typeinf.enum_type_data_t()
                if not tif.get_enum_details(etd):
                    continue
                for edm in etd:
                    if edm.value == val and edm.name and edm.name not in seen:
                        seen.add(edm.name)
                        matches.append(edm.name)
    except Exception:
        pass
    # 2. Legacy ida_enum API fallback
    try:
        import ida_enum
        for idx in range(ida_enum.get_enum_qty()):
            eid = ida_enum.getn_enum(idx)
            cid = ida_enum.get_enum_member(eid, val, 0, ida_enum.DEFMASK)
            if cid != idaapi.BADADDR:
                nm = ida_enum.get_enum_member_name(cid)
                if nm and nm not in seen:
                    seen.add(nm)
                    matches.append(nm)
    except Exception:
        pass
    return matches


class _ActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, view, callback):
        super().__init__()
        self.view = view
        self.callback = callback

    def activate(self, ctx):
        self.callback()
        return 1

    def update(self, ctx):
        if not self.view:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
        widget = self.view.GetWidget()
        if widget and ctx.widget == widget:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class _DecompilerView(ida_kernwin.simplecustviewer_t):
    def __init__(self):
        super().__init__()
        self.current_func = None
        self.current_func_ea = None
        self.current_func_name = None
        self.mode = "c"
        self.line_ea = []
        self.line_to_eas = {}
        self.ea_to_line = {}
        self.line_consts = {}
        self.call_eas = {}
        self.sym_eas = {}
        self.raw_lines = []
        self.header_count = 0
        self.var_types = {}
        self.params = []
        self.param_types = {}
        self.sig_line = None
        self.ret_type = "void"
        self._selected_line = None
        self._highlighted_asm_eas = set()
        self._sync_lock = False
        self.sync_with_disasm = db.get_sync_enabled()
        self._nav_history = []
        self._nav_forward = []
        self._last_token = None
        self._highlighted_token_lines = set()

    def build_or_refresh(self, target, mode=None, preserve_cursor=False):
        """Populate or update lines with decompiled Function or EA."""
        import spudec

        if mode is not None:
            self.mode = mode

        saved_pos = self.GetPos() if preserve_cursor else None

        if isinstance(target, int):
            try:
                func = spudec.decompile(target, check=True)
            except Exception as exc:
                print("spudec: decompilation failed for 0x%X: %s" % (target, exc))
                return False
        else:
            func = target

        self.current_func = func
        self.current_func_ea = func.start_ea
        self.current_func_name = func.name or ("sub_%X" % func.start_ea)
        self.clear_asm_highlights()

        prev_lock = self._sync_lock
        self._sync_lock = True
        try:
            if self.mode == "c":
                try:
                    lines = spudec.pseudocode(func)
                except Exception as exc:
                    print("spudec: pseudocode failed for %s: %s" % (self.current_func_name, exc))
                    return False
                self.header_count = getattr(lines, "header_count", 0)
                self.line_to_eas = getattr(lines, "line_to_eas", {}) or {}
                self.ea_to_line = getattr(lines, "ea_to_line", {}) or {}
                self.line_consts = getattr(lines, "line_consts", {}) or {}
                self.call_eas = getattr(lines, "call_eas", {}) or {}
                self.sym_eas = getattr(lines, "sym_eas", {}) or {}
                self.raw_lines = list(lines)
                self.var_types = getattr(lines, "var_types", {}) or {}
                self.params = getattr(lines, "params", []) or []
                self.param_types = getattr(lines, "param_types", {}) or {}
                self.sig_line = getattr(lines, "sig_line", None)
                self.ret_type = getattr(lines, "ret_type", "void")
                self._selected_line = None

                self.ClearLines()
                self.line_ea = []
                fn_line_eas = getattr(lines, "line_eas", None)
                for i, ln in enumerate(lines):
                    self.AddLine(highlight.colorize(ln))
                    ea = fn_line_eas[i] if (fn_line_eas and i < len(fn_line_eas)) else None
                    self.line_ea.append(ea if ea is not None else _line_ea(ln))
                self.Refresh()

                initial_stmt_line = None
                try:
                    screen_ea = ida_kernwin.get_screen_ea()
                    if screen_ea is not None and screen_ea in self.ea_to_line:
                        cand = self.ea_to_line[screen_ea]
                        if cand >= self.header_count:
                            initial_stmt_line = cand
                except Exception:
                    pass

                if saved_pos and 0 <= saved_pos[0] < len(self.raw_lines):
                    self.select_line(saved_pos[0], jump=True, update_asm=True, jump_asm=False)
                    try:
                        self.Jump(saved_pos[0], saved_pos[1])
                    except Exception:
                        pass
                elif initial_stmt_line is not None and initial_stmt_line < len(self.raw_lines):
                    self.select_line(initial_stmt_line, jump=True, update_asm=True, jump_asm=False)
                else:
                    self._selected_line = None
                    try:
                        self.Jump(0, 0)
                    except Exception:
                        pass
            else:
                # SSA IR mode
                self.header_count = 0
                self.line_to_eas = {}
                self.ea_to_line = {}
                self.line_consts = {}
                self.call_eas = {}
                self.sym_eas = {}
                self.raw_lines = []
                self.var_types = {}
                self.params = []
                self.param_types = {}
                self.sig_line = None
                self.ret_type = "void"
                self._selected_line = None
                self.ClearLines()
                self.line_ea = []
                self._render_ir(func)
                self.Refresh()
        finally:
            self._sync_lock = prev_lock

        return True

    def _render_ir(self, func):
        def _c(text, color):
            return ida_lines.COLSTR(text, color)

        name = func.name or "sub_%X" % func.start_ea
        self._add_ir_line(_c("; SPU SSA IR  --  %s  @ 0x%X" % (name, func.start_ea),
                             ida_lines.SCOLOR_AUTOCMT), func.start_ea)

        stats = getattr(func, "stats", {}) or {}
        if stats:
            self._add_ir_line(_c("; opt: %d rounds, %d instructions eliminated"
                                 % (stats.get("rounds", 0), stats.get("removed", 0)),
                                 ida_lines.SCOLOR_AUTOCMT))

        sc = getattr(func, "scalar_stats", {}) or {}
        if sc:
            line = ("; scalarised: %d scalar stores, %d scalar loads, "
                    "%d aligned loads, %d scalar ops"
                    % (sc.get("stores", 0), sc.get("loads", 0),
                       sc.get("aligned_loads", 0), sc.get("scalars", 0)))
            self._add_ir_line(_c(line, ida_lines.SCOLOR_AUTOCMT))

        unhandled = getattr(func, "unhandled", {}) or {}
        if unhandled:
            worst = sorted(unhandled.items(), key=lambda kv: -kv[1])
            self._add_ir_line(_c("; unmodelled (lifted as intrinsics): %s"
                                 % ", ".join("%s x%d" % (k, v) for k, v in worst),
                                 ida_lines.SCOLOR_ERROR))

        problems = getattr(func, "problems", []) or []
        for p in problems:
            self._add_ir_line(_c("; SSA PROBLEM: " + p, ida_lines.SCOLOR_ERROR))

        for b in func.blocks:
            self._add_ir_line("")
            preds = ", ".join("B%d" % p.id for p in b.preds) or "-"
            succs = ", ".join("B%d" % s.id for s in b.succs) or "-"
            self._add_ir_line(
                _c("B%d:" % b.id, ida_lines.SCOLOR_CREFTAIL) +
                _c("  ; 0x%X..0x%X  preds: %s  succs: %s"
                   % (b.start_ea, b.end_ea, preds, succs),
                   ida_lines.SCOLOR_AUTOCMT),
                b.start_ea)
            for insn in b.insns:
                text = str(insn)
                if insn.op == Op.PHI:
                    c_text = _c(text, ida_lines.SCOLOR_MACRO)
                elif insn.op.is_terminator:
                    c_text = _c(text, ida_lines.SCOLOR_KEYWORD)
                elif insn.op in (Op.LOADQ, Op.STOREQ, Op.LOAD, Op.STORE, Op.LOADU):
                    c_text = _c(text, ida_lines.SCOLOR_DREF)
                elif insn.op == Op.INTRINSIC:
                    c_text = _c(text, ida_lines.SCOLOR_ERROR)
                else:
                    c_text = text
                self._add_ir_line("    " + c_text, insn.ea)

    def _add_ir_line(self, text, ea=None):
        lineno = len(self.raw_lines)
        self.raw_lines.append(text)
        self.AddLine(text)
        self.line_ea.append(ea)
        if ea is not None:
            self.line_to_eas[lineno] = [ea]
            if ea not in self.ea_to_line:
                self.ea_to_line[ea] = lineno

    def clear_asm_highlights(self):
        """Restore default background color for all previously highlighted asm instructions."""
        self._last_token = None
        self._highlighted_token_lines.clear()
        if not self._highlighted_asm_eas:
            return
        import ida_nalt
        for ea in list(self._highlighted_asm_eas):
            try:
                ida_nalt.del_item_color(ea)
            except Exception:
                pass
        self._highlighted_asm_eas.clear()
        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass

    def _primary_ea_for_line(self, lineno):
        """Best instruction EA for a given pseudocode line number."""
        if lineno is None:
            return self.current_func_ea
        eas = self.line_to_eas.get(lineno, [])
        if eas:
            return eas[0]
        if 0 <= lineno < len(self.line_ea) and self.line_ea[lineno] is not None:
            return self.line_ea[lineno]
        if self.line_to_eas:
            nearest_line = min(self.line_to_eas.keys(), key=lambda l: abs(l - lineno))
            if self.line_to_eas[nearest_line]:
                return self.line_to_eas[nearest_line][0]
        return self.current_func_ea

    def select_line(self, lineno, jump=False, update_asm=True, jump_asm=True):
        """Move selection to lineno, visually highlight row, and sync asm highlight."""
        if lineno < 0 or lineno >= len(self.raw_lines):
            return
        prev_line = self._selected_line
        self._selected_line = lineno

        _, decomp_bg = _get_highlight_colors()

        if prev_line is not None and prev_line != lineno and 0 <= prev_line < len(self.raw_lines):
            try:
                colored = highlight.colorize(self.raw_lines[prev_line]) if self.mode == "c" else self.raw_lines[prev_line]
                self.EditLine(prev_line, colored, bgcolor=0xFFFFFFFF)
            except Exception:
                pass

        if self.raw_lines[lineno].strip():
            try:
                colored = highlight.colorize(self.raw_lines[lineno]) if self.mode == "c" else self.raw_lines[lineno]
                self.EditLine(lineno, colored, bgcolor=decomp_bg)
                self.RefreshCurrent()
            except Exception:
                pass
        else:
            self._selected_line = None

        if jump:
            try:
                self.Jump(lineno, 0)
            except Exception:
                pass

        if update_asm:
            self._update_asm_highlight_for_line(lineno, jump_asm=jump_asm)

    def _update_asm_highlight_for_line(self, lineno, jump_asm=True):
        """Highlight assembly instructions in IDA disassembly corresponding to decompiled line."""
        import ida_nalt

        for ea in list(self._highlighted_asm_eas):
            try:
                ida_nalt.del_item_color(ea)
            except Exception:
                pass
        self._highlighted_asm_eas.clear()

        eas = self.line_to_eas.get(lineno, [])
        if not eas and lineno < len(self.line_ea) and self.line_ea[lineno] is not None:
            eas = [self.line_ea[lineno]]

        if not eas:
            if self.line_to_eas:
                nearest_line = min(self.line_to_eas.keys(), key=lambda l: abs(l - lineno))
                eas = self.line_to_eas[nearest_line]
            elif self.current_func_ea is not None:
                eas = [self.current_func_ea]

        if eas:
            asm_color, _ = _get_highlight_colors()
            for ea in eas:
                try:
                    ida_nalt.set_item_color(ea, asm_color)
                    self._highlighted_asm_eas.add(ea)
                except Exception:
                    pass
            try:
                ida_kernwin.refresh_idaview_anyway()
            except Exception:
                pass

            # Intra-function sync MUST pass push_history=False (UIJMP_DONTPUSH)
            # so scrolling/clicking lines never pollutes IDA's Back/Forward stack!
            if self.sync_with_disasm and jump_asm:
                prev_lock = self._sync_lock
                self._sync_lock = True
                try:
                    _jumpto_disasm(eas[0], push_history=False, activate=False)
                except Exception:
                    pass
                finally:
                    self._sync_lock = prev_lock
        else:
            try:
                ida_kernwin.refresh_idaview_anyway()
            except Exception:
                pass

    def sync_from_disasm_ea(self, ea):
        """Called when cursor moves in disassembly; syncs selection in decompiled view."""
        if self._sync_lock:
            return
        lineno = self.ea_to_line.get(ea)
        if lineno is None:
            lineno = self._find_closest_line(ea)

        if lineno is None or (self.mode == "c" and lineno < self.header_count):
            if self._selected_line is not None:
                if 0 <= self._selected_line < len(self.raw_lines):
                    try:
                        colored = highlight.colorize(self.raw_lines[self._selected_line]) if self.mode == "c" else self.raw_lines[self._selected_line]
                        self.EditLine(self._selected_line, colored, bgcolor=0xFFFFFFFF)
                    except Exception:
                        pass
                self._selected_line = None
            self.clear_asm_highlights()
            return

        if lineno == self._selected_line:
            return

        self._sync_lock = True
        try:
            self.select_line(lineno, jump=True, update_asm=True, jump_asm=False)
        finally:
            self._sync_lock = False

    def _find_closest_line(self, ea):
        """Find the decompiled line whose instruction EA is closest to ea."""
        if not self.ea_to_line:
            return None
        closest_ea = min(self.ea_to_line.keys(), key=lambda e: abs(e - ea))
        return self.ea_to_line[closest_ea]

    def _update_token_highlight(self):
        """Highlight all occurrences of the identifier under caret across the view."""
        if self.mode != "c" or not self.raw_lines:
            return
        word, lineno, col = self.get_word_under_cursor()
        active_token = None
        if word and (word[0].isalpha() or word[0] == "_"):
            if word not in highlight.C_KEYWORDS and word not in highlight.C_TYPES:
                active_token = word

        if active_token == self._last_token:
            return

        self._last_token = active_token
        _, decomp_bg = _get_highlight_colors()

        to_restore = set(self._highlighted_token_lines)
        self._highlighted_token_lines.clear()

        new_matching = set()
        if active_token:
            pat = re.compile(r"\b" + re.escape(active_token) + r"\b")
            for idx, raw in enumerate(self.raw_lines):
                if idx >= self.header_count and pat.search(raw):
                    new_matching.add(idx)

        affected = to_restore.union(new_matching)
        for idx in affected:
            if 0 <= idx < len(self.raw_lines):
                try:
                    colored = highlight.colorize(self.raw_lines[idx], highlight_ident=active_token)
                    bg = decomp_bg if idx == self._selected_line else 0xFFFFFFFF
                    self.EditLine(idx, colored, bgcolor=bg)
                    if idx in new_matching:
                        self._highlighted_token_lines.add(idx)
                except Exception:
                    pass
        if affected:
            try:
                self.RefreshCurrent()
            except Exception:
                pass

    def on_cursor_changed(self):
        """Called when user clicks or moves cursor in decompiler window."""
        if self._sync_lock:
            return
        pos = self.GetPos()
        if not pos:
            return
        lineno = pos[0]
        if lineno < 0 or lineno >= len(self.raw_lines):
            return

        self._sync_lock = True
        try:
            if lineno != self._selected_line:
                self.select_line(lineno, jump=False, update_asm=True, jump_asm=True)
            self._update_token_highlight()
            if self.current_func_ea is not None:
                # Update in-memory cursor position without dirtying the IDB netnode on every scroll
                db.save_window_state(True, self.current_func_ea, lineno=lineno, col=pos[1],
                                     mode=self.mode, persist=False)
        finally:
            self._sync_lock = False

    def OnCursorPosChanged(self):
        self.on_cursor_changed()

    def OnClick(self, shift):
        self.on_cursor_changed()

    def Close(self):
        self.clear_asm_highlights()
        if self.current_func_ea is not None:
            db.save_window_state(False, self.current_func_ea, mode=self.mode, persist=True)
        return super().Close()

    def show_func(self, ea, preserve_cursor=False):
        """Decompile function at ea and refresh view."""
        import spudec
        pfn = ida_funcs.get_func(ea)
        entry = pfn.start_ea if pfn else ea
        spudec.clear_caches()
        return self.build_or_refresh(entry, mode=self.mode, preserve_cursor=preserve_cursor)

    def _navigate_to_func(self, target_ea, push_history=True):
        """Explicitly navigate to a different function, recording one nav history entry."""
        if target_ea is None:
            return False
        pfn = ida_funcs.get_func(target_ea)
        entry = pfn.start_ea if pfn else target_ea
        if entry == self.current_func_ea:
            # Already in this function; jump to matching line without pushing nav history
            if target_ea in self.ea_to_line:
                self.select_line(self.ea_to_line[target_ea], jump=True, update_asm=True, jump_asm=True)
            return True

        pos = self.GetPos() or (0, 0)
        if push_history and self.current_func_ea is not None:
            if not self._nav_history or self._nav_history[-1][0] != self.current_func_ea:
                self._nav_history.append((self.current_func_ea, pos[0], pos[1]))
            self._nav_forward.clear()

        # Sync IDA View-A with push_history=True (ONE history point for the function jump!)
        prev_lock = self._sync_lock
        self._sync_lock = True
        try:
            _jumpto_disasm(entry, push_history=push_history, activate=False)
        finally:
            self._sync_lock = prev_lock

        ok = self.show_func(entry)
        if ok and target_ea != entry and target_ea in self.ea_to_line:
            self.select_line(self.ea_to_line[target_ea], jump=True, update_asm=True, jump_asm=False)
        if ok and self.current_func_ea is not None:
            cur_pos = self.GetPos() or (0, 0)
            db.save_window_state(True, self.current_func_ea, lineno=cur_pos[0], col=cur_pos[1],
                                 mode=self.mode, persist=True)
        return ok

    def on_nav_back(self):
        """Navigate back to previous function (Esc)."""
        if self._nav_history:
            prev_ea, prev_line, prev_col = self._nav_history.pop()
            if self.current_func_ea is not None:
                cur_pos = self.GetPos() or (0, 0)
                self._nav_forward.append((self.current_func_ea, cur_pos[0], cur_pos[1]))
            self.show_func(prev_ea)
            if 0 <= prev_line < len(self.raw_lines):
                prev_lock = self._sync_lock
                self._sync_lock = True
                try:
                    self.select_line(prev_line, jump=True, update_asm=True, jump_asm=False)
                    try:
                        self.Jump(prev_line, prev_col)
                    except Exception:
                        pass
                    target_asm_ea = self._primary_ea_for_line(prev_line)
                    if self.sync_with_disasm and target_asm_ea is not None:
                        _jumpto_disasm(target_asm_ea, push_history=False, activate=False)
                finally:
                    self._sync_lock = prev_lock
            return True

        # Local history empty: delegate to IDA's global Back history rather than closing the tab
        try:
            if ida_kernwin.process_ui_action("JumpOp"):
                return True
        except Exception:
            pass
        return False

    def on_nav_forward(self):
        """Navigate forward in function history (Ctrl-Enter)."""
        if self._nav_forward:
            next_ea, next_line, next_col = self._nav_forward.pop()
            if self.current_func_ea is not None:
                cur_pos = self.GetPos() or (0, 0)
                self._nav_history.append((self.current_func_ea, cur_pos[0], cur_pos[1]))
            self.show_func(next_ea)
            if 0 <= next_line < len(self.raw_lines):
                prev_lock = self._sync_lock
                self._sync_lock = True
                try:
                    self.select_line(next_line, jump=True, update_asm=True, jump_asm=False)
                    try:
                        self.Jump(next_line, next_col)
                    except Exception:
                        pass
                    target_asm_ea = self._primary_ea_for_line(next_line)
                    if self.sync_with_disasm and target_asm_ea is not None:
                        _jumpto_disasm(target_asm_ea, push_history=False, activate=False)
                finally:
                    self._sync_lock = prev_lock
            return True

        try:
            if ida_kernwin.process_ui_action("JumpNew"):
                return True
        except Exception:
            pass
        return False

    def on_switch_to_disasm(self):
        """Switch focus to IDA disassembly at the current statement's EA (Tab, Hex-Rays parity)."""
        pos = self.GetPos()
        lineno = pos[0] if pos else self._selected_line
        ea = self._primary_ea_for_line(lineno)
        if ea is not None:
            _jumpto_disasm(ea, push_history=False, activate=True)
            return True
        return False

    def on_jump_addr(self):
        """Jump to an arbitrary address or function (G)."""
        default_ea = self.current_func_ea if self.current_func_ea is not None else 0
        ea = ida_kernwin.ask_addr(default_ea, "Jump to address")
        if ea is None or ea == idaapi.BADADDR:
            return False
        pfn = ida_funcs.get_func(ea)
        if pfn is not None:
            return self._navigate_to_func(ea, push_history=True)
        return _jumpto_disasm(ea, push_history=True, activate=True)

    def get_word_under_cursor(self):
        """Return (word, lineno, col) under cursor (C identifier / number word)."""
        pos = self.GetPos()
        if not pos:
            word = self.GetCurrentWord()
            return word or "", 0, 0
        lineno, col = pos[0], pos[1]
        if lineno < 0 or lineno >= len(self.raw_lines):
            return "", lineno, col
        line = self.raw_lines[lineno]
        if not line:
            return "", lineno, col
        if col < 0:
            col = 0
        elif col >= len(line):
            col = len(line) - 1

        if not (line[col].isalnum() or line[col] == "_"):
            if col > 0 and (line[col - 1].isalnum() or line[col - 1] == "_"):
                col -= 1
            elif col + 1 < len(line) and (line[col + 1].isalnum() or line[col + 1] == "_"):
                col += 1
            else:
                return "", lineno, col

        start = col
        while start > 0 and (line[start - 1].isalnum() or line[start - 1] == "_"):
            start -= 1
        end = col
        while end < len(line) and (line[end].isalnum() or line[end] == "_"):
            end += 1
        return line[start:end], lineno, col

    def get_token_under_cursor(self):
        """Return (qualified_token, lineno, col) supporting C++ `ns::cls::fn` identifiers."""
        pos = self.GetPos()
        if not pos:
            w = self.GetCurrentWord()
            return w or "", 0, 0
        lineno, col = pos[0], pos[1]
        if lineno < 0 or lineno >= len(self.raw_lines):
            return "", lineno, col
        line = self.raw_lines[lineno]
        if not line:
            return "", lineno, col
        c = max(0, min(col, len(line) - 1))

        def _is_qchar(ch):
            return ch.isalnum() or ch in ("_", ":", "~")

        if not _is_qchar(line[c]):
            if c > 0 and _is_qchar(line[c - 1]):
                c -= 1
            elif c + 1 < len(line) and _is_qchar(line[c + 1]):
                c += 1
            else:
                return "", lineno, col

        start = c
        while start > 0 and _is_qchar(line[start - 1]):
            start -= 1
        end = c
        while end < len(line) and _is_qchar(line[end]):
            end += 1
        tok = line[start:end].strip(":")
        return tok, lineno, col

    def _get_const_under_cursor(self):
        """Return the constant metadata dict under (or nearest to) the cursor on the current line."""
        pos = self.GetPos()
        if not pos:
            return None
        lineno, col = pos[0], pos[1]
        consts = self.line_consts.get(lineno)
        if not consts:
            return None
        # Exact span match (with 1-column tolerance at right edge)
        for c in consts:
            cs = c.get("col_start", 0)
            ce = c.get("col_end", 0)
            if cs - 1 <= col <= ce:
                return c
        # Nearest constant on the same line
        return min(consts, key=lambda c: min(abs(col - c.get("col_start", 0)),
                                             abs(col - c.get("col_end", 0))))

    def _validate_c_type(self, type_str):
        """Validate type_str against IDA type library (native SPU types, structs, typedefs)."""
        try:
            return _parse_c_type_tinfo(type_str) is not None
        except Exception:
            return True

    def _update_param_type(self, param_name, new_type):
        """Update a single parameter's type in prototype and IDA type info."""
        from . import abi
        data = db.get_func_data(self.current_func_ea)
        proto_str = data.get("proto")
        if not proto_str and self.sig_line is not None and self.sig_line < len(self.raw_lines):
            proto_str = self.raw_lines[self.sig_line].strip()
        if not proto_str:
            proto_str = f"{self.ret_type} {self.current_func_name}()"

        parsed = abi._parse_proto(proto_str, self.current_func_name)
        if parsed:
            found = False
            for p in parsed.params:
                if p.name == param_name:
                    p.type_str = new_type if new_type else "qword"
                    found = True
                    break
            if not found and new_type:
                parsed.params.append(abi.Param(name=param_name, type_str=new_type))

            new_proto = abi.format_proto(parsed.ret_type, parsed.name, parsed.params)
            db.set_func_proto(self.current_func_ea, new_proto)
            db.set_var_type(self.current_func_ea, param_name, new_type if new_type else None)
            _apply_proto_to_ida(self.current_func_ea, new_proto)
        else:
            db.set_var_type(self.current_func_ea, param_name, new_type if new_type else None)

    def _resolve_callee_under_cursor(self, word, qtok, lineno, col):
        """Return (callee_ea, callee_name) if cursor is on a called function, else (None, None)."""
        if qtok and qtok in self.call_eas:
            return self.call_eas[qtok], qtok
        if word and word in self.call_eas:
            return self.call_eas[word], word
        if word and 0 <= lineno < len(self.raw_lines):
            line = self.raw_lines[lineno]
            # Check if identifier is followed by '('
            m = re.search(r"\b" + re.escape(word) + r"\s*\(", line)
            if m:
                try:
                    import ida_name, ida_idaapi
                    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, qtok or word)
                    if ea == ida_idaapi.BADADDR and word != qtok:
                        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, word)
                    if ea != ida_idaapi.BADADDR:
                        pfn = ida_funcs.get_func(ea)
                        if pfn and pfn.start_ea == ea:
                            return ea, qtok or word
                except Exception:
                    pass
                m_sub = _EA.match(word)
                if m_sub and word.startswith("sub_"):
                    try:
                        ea = int(m_sub.group(1), 16)
                        pfn = ida_funcs.get_func(ea)
                        if pfn and pfn.start_ea == ea:
                            return ea, word
                    except Exception:
                        pass
        return None, None

    def _resolve_global_under_cursor(self, word, qtok):
        """Return (sym_ea, sym_name) if cursor is on a global data symbol, else (None, None)."""
        if qtok and qtok in self.sym_eas:
            return self.sym_eas[qtok], qtok
        if word and word in self.sym_eas:
            return self.sym_eas[word], word
        if word and word not in self.var_types and word not in self.params:
            try:
                import ida_name, ida_idaapi
                ea = ida_name.get_name_ea(ida_idaapi.BADADDR, qtok or word)
                if ea == ida_idaapi.BADADDR and word != qtok:
                    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, word)
                if ea != ida_idaapi.BADADDR:
                    pfn = ida_funcs.get_func(ea)
                    if pfn is None or pfn.start_ea != ea:
                        return ea, qtok or word
            except Exception:
                pass
        return None, None

    def on_rename(self):
        """Rename variable, parameter, callee, global symbol, or function under cursor (N)."""
        from . import abi
        if self.current_func_ea is None:
            return
        word, lineno, col = self.get_word_under_cursor()
        qtok, _, _ = self.get_token_under_cursor()
        if not word and not qtok:
            word = ida_kernwin.ask_str("", 0, "Enter identifier to rename")
            if not word:
                return
            qtok = word

        # 1. Renaming the current function itself
        if (qtok == self.current_func_name or word == self.current_func_name or
                (self.sig_line is not None and lineno == self.sig_line and
                 (qtok == self.current_func_name or word == self.current_func_name))):
            cur_nm = self.current_func_name
            new_name = ida_kernwin.ask_str(cur_nm, 0, f"Rename Function '{cur_nm}'")
            if new_name is None:
                return
            new_name = new_name.strip()
            if new_name and new_name != cur_nm:
                import ida_name
                ida_name.set_name(self.current_func_ea, new_name)
                data = db.get_func_data(self.current_func_ea)
                if data.get("proto"):
                    parsed = abi._parse_proto(data["proto"])
                    if parsed:
                        new_proto = abi.format_proto(parsed.ret_type, new_name, parsed.params)
                        db.set_func_proto(self.current_func_ea, new_proto)
                self.current_func_name = new_name
            self.show_func(self.current_func_ea, preserve_cursor=True)
            return

        # 2. Renaming a callee function in the body
        callee_ea, callee_nm = self._resolve_callee_under_cursor(word, qtok, lineno, col)
        if callee_ea is not None and callee_ea != self.current_func_ea:
            new_name = ida_kernwin.ask_str(callee_nm, 0, f"Rename Callee '{callee_nm}'")
            if new_name is None:
                return
            new_name = new_name.strip()
            if new_name and new_name != callee_nm:
                try:
                    import ida_name
                    ida_name.set_name(callee_ea, new_name)
                except Exception:
                    pass
                callee_data = db.get_func_data(callee_ea)
                if callee_data.get("proto"):
                    parsed = abi._parse_proto(callee_data["proto"])
                    if parsed:
                        new_proto = abi.format_proto(parsed.ret_type, new_name, parsed.params)
                        db.set_func_proto(callee_ea, new_proto)
                self.show_func(self.current_func_ea, preserve_cursor=True)
            return

        # 3. Renaming a parameter or local/stack/global variable
        is_param = (word in self.params) or (self.sig_line is not None and lineno == self.sig_line and "(" in self.raw_lines[lineno])
        prompt_label = f"parameter '{word}'" if is_param else f"variable '{word}'"
        new_name = ida_kernwin.ask_str(word, 0, f"Rename {prompt_label} in {self.current_func_name}")
        if new_name is None:
            return
        new_name = new_name.strip()

        db.set_var_rename(self.current_func_ea, word, new_name)

        data = db.get_func_data(self.current_func_ea)
        if data.get("proto"):
            parsed = abi._parse_proto(data["proto"])
            if parsed and parsed.params:
                modified = False
                for p in parsed.params:
                    if p.name == word:
                        p.name = new_name if new_name else word
                        modified = True
                        break
                if modified:
                    new_proto = abi.format_proto(parsed.ret_type, parsed.name, parsed.params)
                    db.set_func_proto(self.current_func_ea, new_proto)
                    _apply_proto_to_ida(self.current_func_ea, new_proto)

        self._rename_frame_member(word, new_name)

        # Rename global symbol in IDA if applicable
        sym_ea, _ = self._resolve_global_under_cursor(word, qtok)
        if sym_ea is not None and new_name:
            try:
                import ida_name
                ida_name.set_name(sym_ea, new_name)
            except Exception:
                pass

        self.show_func(self.current_func_ea, preserve_cursor=True)

    def _rename_frame_member(self, old_name, new_name):
        """Rename stack variable member in IDA's frame structure if present."""
        if not new_name:
            return
        try:
            import ida_frame
            pfn = ida_funcs.get_func(self.current_func_ea)
            if not pfn:
                return
            tif = ida_typeinf.tinfo_t()
            if ida_frame.get_func_frame(tif, pfn):
                udt = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt):
                    for idx, m in enumerate(udt):
                        if m.name == old_name:
                            if hasattr(tif, "rename_udm"):
                                tif.rename_udm(idx, new_name)
                            else:
                                m.name = new_name
                                tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
                            break
        except Exception:
            pass

    def _set_frame_member_type(self, var_name, type_str):
        """Update stack variable member type in IDA's frame structure if present."""
        if not type_str:
            return
        try:
            import ida_frame
            pfn = ida_funcs.get_func(self.current_func_ea)
            if not pfn:
                return
            new_tif = _parse_c_type_tinfo(type_str)
            if new_tif is None:
                return
            frame_tif = ida_typeinf.tinfo_t()
            if ida_frame.get_func_frame(frame_tif, pfn):
                udt = ida_typeinf.udt_type_data_t()
                if frame_tif.get_udt_details(udt):
                    for idx, m in enumerate(udt):
                        if m.name == var_name:
                            if hasattr(ida_frame, "set_frame_member_type"):
                                ida_frame.set_frame_member_type(pfn, m.offset // 8, new_tif)
                            elif hasattr(frame_tif, "set_udm_type"):
                                frame_tif.set_udm_type(idx, new_tif)
                            break
        except Exception:
            pass

    def on_set_type(self):
        """Set variable type, parameter type, callee prototype, global type, or function prototype (Y)."""
        import spudec
        from . import abi
        if self.current_func_ea is None:
            return

        spudec.ensure_spu_types()
        word, lineno, col = self.get_word_under_cursor()
        qtok, _, _ = self.get_token_under_cursor()
        is_sig_line = (self.sig_line is not None and lineno == self.sig_line) or \
                      (lineno == 0 and len(self.raw_lines) > 0 and
                       "(" in self.raw_lines[0] and ")" in self.raw_lines[0] and
                       not self.raw_lines[0].startswith("//"))

        # 1. Cursor is on the function signature line
        if is_sig_line:
            line_str = self.raw_lines[lineno]
            # 1a. Specific parameter in the signature
            param_match = None
            if word and word in self.params:
                param_match = word
            elif "(" in line_str and ")" in line_str:
                lparen = line_str.index("(")
                rparen = line_str.rindex(")")
                if lparen < col <= rparen:
                    args_str = line_str[lparen + 1:rparen]
                    arg_parts = args_str.split(",")
                    curr_offset = lparen + 1
                    for idx, part in enumerate(arg_parts):
                        part_len = len(part)
                        if curr_offset <= col <= curr_offset + part_len + 1:
                            if idx < len(self.params):
                                param_match = self.params[idx]
                            break
                        curr_offset += part_len + 1

            if param_match:
                curr_type = self.param_types.get(param_match, "qword")
                new_type = ida_kernwin.ask_str(curr_type, 0, f"Set Type for parameter '{param_match}'")
                if new_type is None:
                    return
                new_type = new_type.strip()
                if new_type and not self._validate_c_type(new_type):
                    ida_kernwin.warning(f"Warning: '{new_type}' could not be parsed by IDA's type library. Applying override anyway.")
                self._update_param_type(param_match, new_type)
                self.show_func(self.current_func_ea, preserve_cursor=True)
                return

            # 1b. Return type in signature (anything before the function name)
            fn_pos = line_str.find(self.current_func_name) if self.current_func_name else -1
            if fn_pos < 0 and "(" in line_str:
                fn_pos = line_str.find("(")
            if word and fn_pos > 0 and col < fn_pos:
                new_ret = ida_kernwin.ask_str(self.ret_type, 0, f"Set Return Type for {self.current_func_name}")
                if new_ret is None:
                    return
                new_ret = new_ret.strip()
                if new_ret:
                    if not self._validate_c_type(new_ret):
                        ida_kernwin.warning(f"Warning: '{new_ret}' could not be parsed by IDA. Applying override anyway.")
                    db.set_var_type(self.current_func_ea, "__return__", new_ret)
                    data = db.get_func_data(self.current_func_ea)
                    if data.get("proto"):
                        parsed = abi._parse_proto(data["proto"], self.current_func_name)
                        if parsed:
                            new_proto = abi.format_proto(new_ret, parsed.name, parsed.params)
                            db.set_func_proto(self.current_func_ea, new_proto)
                            _apply_proto_to_ida(self.current_func_ea, new_proto)
                else:
                    db.set_var_type(self.current_func_ea, "__return__", None)
                self.show_func(self.current_func_ea, preserve_cursor=True)
                return

            # 1c. Function name or general signature line -> edit full prototype
            data = db.get_func_data(self.current_func_ea)
            curr_proto = data.get("proto") or line_str.strip()
            new_proto = ida_kernwin.ask_str(curr_proto, 0, f"Set Function Prototype for {self.current_func_name}")
            if new_proto is None:
                return
            new_proto = new_proto.strip()
            if not new_proto:
                db.set_func_proto(self.current_func_ea, None)
            else:
                db.set_func_proto(self.current_func_ea, new_proto)
                if not _apply_proto_to_ida(self.current_func_ea, new_proto):
                    if abi._parse_proto(new_proto) is None:
                        ida_kernwin.warning(f"Warning: Prototype '{new_proto}' could not be parsed. Storing override anyway.")
            self.show_func(self.current_func_ea, preserve_cursor=True)
            return

        if not word and not qtok:
            return

        # 2. Parameter name referenced anywhere inside the function body
        if word and word in self.params:
            curr_type = self.param_types.get(word, self.var_types.get(word, "qword"))
            new_type = ida_kernwin.ask_str(curr_type, 0, f"Set Type for parameter '{word}'")
            if new_type is None:
                return
            new_type = new_type.strip()
            if new_type and not self._validate_c_type(new_type):
                ida_kernwin.warning(f"Warning: '{new_type}' could not be parsed by IDA's type library. Applying override anyway.")
            self._update_param_type(word, new_type)
            self.show_func(self.current_func_ea, preserve_cursor=True)
            return

        # 3. Callee function name in the body -> edit callee prototype
        callee_ea, callee_nm = self._resolve_callee_under_cursor(word, qtok, lineno, col)
        if callee_ea is not None and callee_ea != self.current_func_ea:
            callee_data = db.get_func_data(callee_ea)
            curr_proto = callee_data.get("proto")
            if not curr_proto:
                try:
                    import ida_nalt
                    tif = ida_typeinf.tinfo_t()
                    if ida_nalt.get_tinfo(tif, callee_ea) and tif.is_func():
                        d = tif.dstr()
                        if "(" in d:
                            rp, ap = d.split("(", 1)
                            curr_proto = f"{rp.strip()} {callee_nm}({ap}"
                except Exception:
                    pass
            if not curr_proto:
                n = spudec.arity_of(callee_ea)
                pstr = ", ".join(f"qword a{i + 1}" for i in range(n or 0)) or "void"
                curr_proto = f"qword {callee_nm}({pstr})"

            new_proto = ida_kernwin.ask_str(curr_proto, 0, f"Set Prototype for callee '{callee_nm}'")
            if new_proto is None:
                return
            new_proto = new_proto.strip()
            if not new_proto:
                db.set_func_proto(callee_ea, None)
            else:
                db.set_func_proto(callee_ea, new_proto)
                _apply_proto_to_ida(callee_ea, new_proto)
            spudec.clear_arity_cache()
            self.show_func(self.current_func_ea, preserve_cursor=True)
            return

        # 4. Global data symbol in the body -> apply type to global EA in IDA
        sym_ea, sym_nm = self._resolve_global_under_cursor(word, qtok)
        if sym_ea is not None:
            curr_type = ""
            try:
                import ida_nalt
                tif = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif, sym_ea):
                    curr_type = tif.dstr()
            except Exception:
                pass
            new_type = ida_kernwin.ask_str(curr_type or "u32", 0, f"Set Type for global '{sym_nm}'")
            if new_type is None:
                return
            new_type = new_type.strip()
            if new_type:
                tif = _parse_c_type_tinfo(new_type)
                if tif is not None:
                    try:
                        ida_typeinf.apply_tinfo(sym_ea, tif, ida_typeinf.TINFO_DEFINITE)
                    except Exception:
                        pass
                else:
                    ida_kernwin.warning(f"Warning: '{new_type}' could not be parsed by IDA's type library.")
            self.show_func(self.current_func_ea, preserve_cursor=True)
            return

        # 5. Local variable, live-in, or stack variable in the body
        curr_type = self.var_types.get(word, "qword")
        new_type = ida_kernwin.ask_str(curr_type, 0, f"Set Type for variable '{word}'")
        if new_type is None:
            return
        new_type = new_type.strip()
        if new_type and not self._validate_c_type(new_type):
            ida_kernwin.warning(f"Warning: '{new_type}' could not be parsed by IDA's type library. Applying override anyway.")

        db.set_var_type(self.current_func_ea, word, new_type if new_type else None)
        if new_type:
            self._set_frame_member_type(word, new_type)
        self.show_func(self.current_func_ea, preserve_cursor=True)

    def toggle_sync(self):
        """Toggle synchronization with IDA disassembly view."""
        self.sync_with_disasm = not self.sync_with_disasm
        db.set_sync_enabled(self.sync_with_disasm)
        state_str = "ENABLED" if self.sync_with_disasm else "DISABLED"
        print(f"spudec: Sync with Disassembly {state_str}")
        if self.sync_with_disasm:
            ea = ida_kernwin.get_screen_ea()
            pfn = ida_funcs.get_func(ea)
            if pfn and pfn.start_ea != self.current_func_ea:
                self.show_func(pfn.start_ea)

    def toggle_ir(self):
        """Toggle between C pseudocode and SSA IR views (Shift-I)."""
        self.mode = "ir" if self.mode == "c" else "c"
        if self.current_func_ea is not None:
            self.show_func(self.current_func_ea)

    def jump_disasm(self):
        """Click-through navigation: jump to callee function, label, symbol, or address."""
        word, lineno, col = self.get_word_under_cursor()
        qtok, _, _ = self.get_token_under_cursor()

        # 1. Callee function in call_eas (handles demangled C++ names too!)
        if qtok and qtok in self.call_eas:
            return self._navigate_to_func(self.call_eas[qtok], push_history=True)
        if word and word in self.call_eas:
            return self._navigate_to_func(self.call_eas[word], push_history=True)

        # 2. Global symbol in sym_eas
        if qtok and qtok in self.sym_eas:
            return _jumpto_disasm(self.sym_eas[qtok], push_history=True, activate=True)
        if word and word in self.sym_eas:
            return _jumpto_disasm(self.sym_eas[word], push_history=True, activate=True)

        if word:
            # 3. Named function or symbol in IDA
            try:
                import ida_name, ida_idaapi
                target_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, qtok or word)
                if target_ea == ida_idaapi.BADADDR and word != qtok:
                    target_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, word)
                if target_ea != ida_idaapi.BADADDR:
                    pfn = ida_funcs.get_func(target_ea)
                    if pfn and pfn.start_ea == target_ea:
                        return self._navigate_to_func(target_ea, push_history=True)
                    return _jumpto_disasm(target_ea, push_history=True, activate=True)
            except Exception:
                pass

            # 4. sub_XXXXXX or loc_XXXXXX
            m = _EA.search(word)
            if m:
                try:
                    target_ea = int(m.group(1), 16)
                    pfn = ida_funcs.get_func(target_ea)
                    if pfn and pfn.start_ea == target_ea and target_ea != self.current_func_ea:
                        return self._navigate_to_func(target_ea, push_history=True)
                    if target_ea in self.ea_to_line:
                        self.select_line(self.ea_to_line[target_ea], jump=True, update_asm=True, jump_asm=True)
                        return True
                    return _jumpto_disasm(target_ea, push_history=True, activate=False)
                except ValueError:
                    pass

            # 5. Hex address literal
            m = _ADDR_HEX.search(word)
            if m:
                try:
                    target_ea = int(m.group(1), 16)
                    pfn = ida_funcs.get_func(target_ea)
                    if pfn and pfn.start_ea == target_ea and target_ea != self.current_func_ea:
                        return self._navigate_to_func(target_ea, push_history=True)
                    return _jumpto_disasm(target_ea, push_history=True, activate=True)
                except ValueError:
                    pass

        # Fallback: sync disassembly to current line without flooding history
        target_ea = self._primary_ea_for_line(lineno)
        if target_ea is not None:
            _jumpto_disasm(target_ea, push_history=False, activate=False)
            return True
        return False

    def on_show_xrefs(self):
        """Open IDA Cross-References window for symbol/function/address under cursor (X)."""
        word, lineno, col = self.get_word_under_cursor()
        qtok, _, _ = self.get_token_under_cursor()
        target_ea = None

        if qtok == self.current_func_name or word == self.current_func_name or (self.sig_line is not None and lineno == self.sig_line):
            target_ea = self.current_func_ea
        else:
            callee_ea, _ = self._resolve_callee_under_cursor(word, qtok, lineno, col)
            if callee_ea is not None:
                target_ea = callee_ea
            else:
                sym_ea, _ = self._resolve_global_under_cursor(word, qtok)
                if sym_ea is not None:
                    target_ea = sym_ea
                else:
                    cinfo = self._get_const_under_cursor()
                    if cinfo and cinfo.get("is_addr"):
                        target_ea = cinfo.get("addr_val")
        if target_ea is None:
            target_ea = self._primary_ea_for_line(lineno)
        if target_ea is not None:
            try:
                ida_kernwin.open_xrefs_window(target_ea)
                return True
            except Exception:
                pass
        return False

    def on_invert_if(self):
        """Invert if-condition and swap then/else branches (Hex-Rays 'I' hotkey)."""
        pos = self.GetPos()
        if not pos or pos[0] >= len(self.raw_lines):
            return
        lineno = pos[0]
        ea = self.line_ea[lineno] if lineno < len(self.line_ea) else None
        if ea is None and lineno in self.line_to_eas and self.line_to_eas[lineno]:
            ea = self.line_to_eas[lineno][0]
        if ea is not None:
            db.toggle_iflag(self.current_func_ea, ea)
            self.show_func(self.current_func_ea, preserve_cursor=True)

    def on_edit_comment(self):
        """Add or edit statement comment attached to linear address (Hex-Rays '/' or ';' hotkey)."""
        pos = self.GetPos()
        if not pos or pos[0] >= len(self.raw_lines):
            return
        lineno = pos[0]
        ea = self.line_ea[lineno] if lineno < len(self.line_ea) else None
        if ea is None and lineno in self.line_to_eas and self.line_to_eas[lineno]:
            ea = self.line_to_eas[lineno][0]
        if ea is not None:
            existing = db.get_statement_cmt(self.current_func_ea, ea) or ""
            new_cmt = ida_kernwin.ask_str(existing, 0, f"Comment for statement at 0x{ea:X}")
            if new_cmt is not None:
                db.set_statement_cmt(self.current_func_ea, ea, new_cmt)
                self.show_func(self.current_func_ea, preserve_cursor=True)

    def on_set_numform(self, form_str):
        """Set immediate number format on the constant under cursor."""
        cinfo = self._get_const_under_cursor()
        if cinfo is not None and cinfo.get("ea") is not None:
            db.set_numform(self.current_func_ea, cinfo["ea"], cinfo["idx"], form_str)
            self.show_func(self.current_func_ea, preserve_cursor=True)
            return True
        pos = self.GetPos()
        if not pos or pos[0] >= len(self.raw_lines):
            return False
        lineno = pos[0]
        ea = self._primary_ea_for_line(lineno)
        if ea is not None:
            db.set_numform(self.current_func_ea, ea, 0, form_str)
            self.show_func(self.current_func_ea, preserve_cursor=True)
            return True
        return False

    def on_toggle_hex(self):
        """Toggle Hexadecimal <-> Decimal on constant under cursor (Hex-Rays 'H' hotkey)."""
        cinfo = self._get_const_under_cursor()
        if cinfo is None or cinfo.get("ea") is None:
            return False
        cur = (cinfo.get("form") or "hex").lower()
        if cur == "str":
            new_form = "nostr"
        elif cur in ("hex", "uhex", "shex", "nostr"):
            new_form = "dec"
        else:
            new_form = "hex"
        db.set_numform(self.current_func_ea, cinfo["ea"], cinfo["idx"], new_form)
        self.show_func(self.current_func_ea, preserve_cursor=True)
        return True

    def on_toggle_char(self):
        """Toggle Character constant representation on constant under cursor (Hex-Rays 'R' hotkey)."""
        cinfo = self._get_const_under_cursor()
        if cinfo is None or cinfo.get("ea") is None:
            return False
        cur = (cinfo.get("form") or "").lower()
        new_form = None if cur == "char" else "char"
        db.set_numform(self.current_func_ea, cinfo["ea"], cinfo["idx"], new_form)
        self.show_func(self.current_func_ea, preserve_cursor=True)
        return True

    def on_make_ascii(self):
        """Create/toggle ASCII string literal on address/symbol, or ASCII char on immediate ('A' hotkey)."""
        import spudec
        cinfo = self._get_const_under_cursor()
        if cinfo is not None and cinfo.get("ea") is not None:
            cur = (cinfo.get("form") or "").lower()
            if cur == "str":
                db.set_numform(self.current_func_ea, cinfo["ea"], cinfo["idx"], "nostr")
                self.show_func(self.current_func_ea, preserve_cursor=True)
                return True

            addr = cinfo.get("addr_val", cinfo.get("val", 0))
            is_mem_str = False
            try:
                import ida_bytes, ida_nalt
                if (cinfo.get("is_addr") or addr > 0xFF) and ida_bytes.is_loaded(addr):
                    b0 = ida_bytes.get_byte(addr)
                    if b0 in (0x09, 0x0A, 0x0D) or (0x20 <= b0 <= 0x7E):
                        ida_bytes.create_strlit(addr, 0, ida_nalt.STRTYPE_C)
                        spudec.clear_caches()
                        is_mem_str = True
            except Exception:
                pass

            if is_mem_str or cinfo.get("is_addr"):
                db.set_numform(self.current_func_ea, cinfo["ea"], cinfo["idx"], "str")
            else:
                new_form = None if cur == "char" else "char"
                db.set_numform(self.current_func_ea, cinfo["ea"], cinfo["idx"], new_form)
            self.show_func(self.current_func_ea, preserve_cursor=True)
            return True

        # Fallback: cursor on a global data symbol -> define ASCII string at its EA
        word, lineno, col = self.get_word_under_cursor()
        qtok, _, _ = self.get_token_under_cursor()
        sym_ea, _ = self._resolve_global_under_cursor(word, qtok)
        if sym_ea is not None:
            try:
                import ida_bytes, ida_nalt
                ida_bytes.create_strlit(sym_ea, 0, ida_nalt.STRTYPE_C)
                spudec.clear_caches()
                self.show_func(self.current_func_ea, preserve_cursor=True)
                return True
            except Exception:
                pass
        return False

    def on_toggle_bin(self):
        """Toggle Binary representation (0b...) on constant under cursor (Hex-Rays 'B' hotkey)."""
        cinfo = self._get_const_under_cursor()
        if cinfo is None or cinfo.get("ea") is None:
            return False
        cur = (cinfo.get("form") or "").lower()
        new_form = None if cur == "bin" else "bin"
        db.set_numform(self.current_func_ea, cinfo["ea"], cinfo["idx"], new_form)
        self.show_func(self.current_func_ea, preserve_cursor=True)
        return True

    def on_toggle_signed(self):
        """Toggle signed <-> unsigned representation on constant under cursor (Hex-Rays '_' hotkey)."""
        cinfo = self._get_const_under_cursor()
        if cinfo is None or cinfo.get("ea") is None:
            return False
        cur = (cinfo.get("form") or "hex").lower()
        if cur in ("shex", "signed"):
            new_form = "uhex"
        elif cur == "sdec":
            new_form = "udec"
        elif cur in ("dec", "udec"):
            new_form = "sdec"
        else:
            new_form = "shex"
        db.set_numform(self.current_func_ea, cinfo["ea"], cinfo["idx"], new_form)
        self.show_func(self.current_func_ea, preserve_cursor=True)
        return True

    def on_toggle_invert_bits(self):
        """Toggle bitwise-negated constant (~0x...) under cursor (Hex-Rays '~' hotkey)."""
        cinfo = self._get_const_under_cursor()
        if cinfo is None or cinfo.get("ea") is None:
            return False
        cur = (cinfo.get("form") or "").lower()
        new_form = None if cur == "inv" else "inv"
        db.set_numform(self.current_func_ea, cinfo["ea"], cinfo["idx"], new_form)
        self.show_func(self.current_func_ea, preserve_cursor=True)
        return True

    def on_toggle_offset(self):
        """Toggle offset/symbol representation (&sym) on constant under cursor (Hex-Rays 'O' hotkey)."""
        cinfo = self._get_const_under_cursor()
        if cinfo is None or cinfo.get("ea") is None:
            return False
        cur = (cinfo.get("form") or "").lower()
        if cur == "offset":
            new_form = "nostr"
        else:
            new_form = "offset"
        db.set_numform(self.current_func_ea, cinfo["ea"], cinfo["idx"], new_form)
        self.show_func(self.current_func_ea, preserve_cursor=True)
        return True

    def on_set_enum(self):
        """Apply an IDA enum symbolic constant to the number under cursor (Hex-Rays 'M' hotkey)."""
        cinfo = self._get_const_under_cursor()
        if cinfo is None or cinfo.get("ea") is None:
            return False
        val = cinfo.get("val", 0)
        cur = cinfo.get("form") or ""
        default_name = cur.split(":", 1)[1] if cur.lower().startswith("enum:") else ""
        matches = _find_ida_enum_matches(val)
        if not default_name and matches:
            default_name = matches[0]
        hint = f" (matches: {', '.join(matches[:5])})" if matches else ""
        chosen = ida_kernwin.ask_str(default_name, 0,
                                     f"Symbolic constant / Enum for 0x{val:X}{hint} (empty to clear)")
        if chosen is None:
            return False
        chosen = chosen.strip()
        new_form = ("enum:" + chosen) if chosen else None
        db.set_numform(self.current_func_ea, cinfo["ea"], cinfo["idx"], new_form)
        self.show_func(self.current_func_ea, preserve_cursor=True)
        return True

    def on_toggle_casts(self):
        """Toggle hiding/showing redundant scalar & pointer casts (Hex-Rays '\\' hotkey)."""
        db.set_hide_casts(not db.get_hide_casts())
        if self.current_func_ea is not None:
            self.show_func(self.current_func_ea, preserve_cursor=True)
        return True

    def on_reset_overrides(self):
        """Clear all saved user overrides (renames, types, numforms, comments) for current function."""
        if self.current_func_ea is None:
            return False
        ans = ida_kernwin.ask_yn(0, f"Reset all spudec overrides for {self.current_func_name}?")
        if ans == 1:
            db.clear_func_overrides(self.current_func_ea)
            self.show_func(self.current_func_ea, preserve_cursor=True)
            return True
        return False

    def OnDblClick(self, shift):
        return self.jump_disasm()

    def OnKeydown(self, vkey, shift):
        # Note: widget-scoped IDA actions handle shortcuts first in GUI mode;
        # OnKeydown remains as a fallback and for OEM virtual key codes on Windows.
        if vkey in (ord('N'), ord('n')):
            self.on_rename()
            return True
        if vkey in (ord('Y'), ord('y')):
            self.on_set_type()
            return True
        if vkey in (ord('H'), ord('h')):
            self.on_toggle_hex()
            return True
        if vkey in (ord('A'), ord('a')):
            self.on_make_ascii()
            return True
        if vkey in (ord('R'), ord('r')):
            self.on_toggle_char()
            return True
        if vkey in (ord('B'), ord('b')):
            self.on_toggle_bin()
            return True
        if vkey in (ord('O'), ord('o')):
            self.on_toggle_offset()
            return True
        if vkey in (ord('M'), ord('m')):
            self.on_set_enum()
            return True
        if vkey in (ord('X'), ord('x')):
            self.on_show_xrefs()
            return True
        if vkey in (ord('G'), ord('g')):
            self.on_jump_addr()
            return True
        if vkey in (ord('D'), ord('d')):
            self.on_set_numform('dec')
            return True
        if vkey in (ord('I'), ord('i')):
            if shift & 1:
                self.toggle_ir()
            else:
                self.on_invert_if()
            return True
        if vkey in (ord('/'), 0xBF, ord(';'), 0xBA):  # '/' (VK_OEM_2) or ';' (VK_OEM_1)
            self.on_edit_comment()
            return True
        if vkey in (ord('_'), 0xBD):  # '_' / VK_OEM_MINUS
            self.on_toggle_signed()
            return True
        if vkey in (ord('~'), 0xC0):  # '~' / VK_OEM_3
            self.on_toggle_invert_bits()
            return True
        if vkey in (ord('\\'), 0xDC):  # '\' / VK_OEM_5
            self.on_toggle_casts()
            return True
        if vkey == 116:  # F5
            if self.current_func_ea is not None:
                self.show_func(self.current_func_ea, preserve_cursor=True)
            return True
        if vkey == 13:  # Enter or Ctrl-Enter
            if shift & 2:
                return self.on_nav_forward()
            return self.jump_disasm()
        if vkey == 32:  # Space
            return self.jump_disasm()
        if vkey == 9:  # Tab
            return self.on_switch_to_disasm()
        if vkey == 27:  # Esc
            return self.on_nav_back()
        # Navigation keys: Up(38), Down(40), PageUp(33), PageDown(34), Home(36), End(35)
        if vkey in (38, 40, 33, 34, 36, 35):
            try:
                ida_kernwin.execute_ui_requests([self.on_cursor_changed])
            except Exception:
                pass
        return False


class _UiHooks(ida_kernwin.UI_Hooks):
    def __init__(self, view):
        super().__init__()
        self.view = view

    def create_desktop_widget(self, title, cfg):
        if title == _VIEW_TITLE:
            global _active_viewer, _view_hooks
            if _active_viewer is None or _active_viewer.GetWidget() is None:
                v = _DecompilerView()
                if v.Create(_VIEW_TITLE):
                    _active_viewer = v
                    _register_actions(_active_viewer)
                    self.view = _active_viewer
                    if _view_hooks is None:
                        _view_hooks = _CustViewHooks(_active_viewer)
                        _view_hooks.hook()
                    else:
                        _view_hooks.view = _active_viewer
                    return _active_viewer.GetWidget()
            else:
                return _active_viewer.GetWidget()
        return None

    def desktop_applied(self, name, from_idb, type):
        self._restore_from_state()

    def database_inited(self, is_new_database, idc_script=None):
        self._restore_from_state()

    def saving(self):
        self._record_current_state()

    def saved(self):
        self._record_current_state()

    def _record_current_state(self):
        global _active_viewer
        if _active_viewer is not None and _active_viewer.GetWidget() is not None:
            pos = _active_viewer.GetPos() or (0, 0)
            if _active_viewer.current_func_ea is not None:
                db.save_window_state(True, _active_viewer.current_func_ea,
                                     lineno=pos[0], col=pos[1], mode=_active_viewer.mode, persist=True)

    def screen_ea_changed(self, ea, prev_ea):
        """Automatically follow current function in disassembly and sync line selection."""
        if not self.view or self.view._sync_lock:
            return
        if _active_viewer is not self.view:
            return
        pfn = ida_funcs.get_func(ea)
        if pfn is None:
            return
        if pfn.start_ea != self.view.current_func_ea:
            if not self.view.sync_with_disasm:
                return
            # Keep internal nav stacks coherent with IDA's Back/Forward toolbar arrows
            cur_ea = self.view.current_func_ea
            cur_pos = self.view.GetPos() or (0, 0)
            if self.view._nav_history and self.view._nav_history[-1][0] == pfn.start_ea:
                self.view._nav_history.pop()
                if cur_ea is not None:
                    self.view._nav_forward.append((cur_ea, cur_pos[0], cur_pos[1]))
            elif self.view._nav_forward and self.view._nav_forward[-1][0] == pfn.start_ea:
                self.view._nav_forward.pop()
                if cur_ea is not None:
                    self.view._nav_history.append((cur_ea, cur_pos[0], cur_pos[1]))
            elif cur_ea is not None:
                if not self.view._nav_history or self.view._nav_history[-1][0] != cur_ea:
                    self.view._nav_history.append((cur_ea, cur_pos[0], cur_pos[1]))
                self.view._nav_forward.clear()
            self.view.show_func(pfn.start_ea)
        self.view.sync_from_disasm_ea(ea)

    def widget_invisible(self, widget):
        """Reset active viewer and persist closed state when the decompiler window is closed."""
        if self.view and widget == self.view.GetWidget():
            global _active_viewer
            self.view.clear_asm_highlights()
            if self.view.current_func_ea is not None:
                db.save_window_state(False, self.view.current_func_ea, mode=self.view.mode, persist=True)
            _active_viewer = None

    def finish_populating_widget_popup(self, widget, popup_handle):
        """Attach Hex-Rays-style decompiler context actions to the right-click popup menu."""
        wtype = ida_kernwin.get_widget_type(widget)
        if wtype == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_DECOMPILE)
            return

        if not self.view:
            return
        view_widget = self.view.GetWidget()
        if widget != view_widget:
            return

        attach = ida_kernwin.attach_action_to_popup
        sep_flag = getattr(ida_kernwin, "SETMENU_ENSURE_SEP", 0x8)
        # Editing
        attach(widget, popup_handle, ACTION_RENAME, "")
        attach(widget, popup_handle, ACTION_SET_TYPE, "")
        attach(widget, popup_handle, ACTION_EDIT_CMT, "")
        # Number & String formatting
        attach(widget, popup_handle, ACTION_TOGGLE_HEX, "", sep_flag)
        attach(widget, popup_handle, ACTION_TOGGLE_CHAR, "")
        attach(widget, popup_handle, ACTION_MAKE_ASCII, "")
        attach(widget, popup_handle, ACTION_TOGGLE_BIN, "Number format/")
        attach(widget, popup_handle, ACTION_TOGGLE_SIGNED, "Number format/")
        attach(widget, popup_handle, ACTION_TOGGLE_INV, "Number format/")
        attach(widget, popup_handle, ACTION_TOGGLE_OFFSET, "Number format/")
        attach(widget, popup_handle, ACTION_SET_ENUM, "Number format/")
        # Display transforms
        attach(widget, popup_handle, ACTION_INVERT_IF, "", sep_flag)
        attach(widget, popup_handle, ACTION_TOGGLE_CASTS, "")
        # Navigation
        attach(widget, popup_handle, ACTION_SHOW_XREFS, "", sep_flag)
        attach(widget, popup_handle, ACTION_JUMP_ADDR, "")
        attach(widget, popup_handle, ACTION_JUMP_DISASM, "")
        attach(widget, popup_handle, ACTION_SWITCH_DISASM, "")
        attach(widget, popup_handle, ACTION_NAV_BACK, "")
        attach(widget, popup_handle, ACTION_NAV_FORWARD, "")
        # View controls
        attach(widget, popup_handle, ACTION_TOGGLE_SYNC, "", sep_flag)
        attach(widget, popup_handle, ACTION_TOGGLE_IR, "")
        attach(widget, popup_handle, ACTION_REFRESH, "")
        attach(widget, popup_handle, ACTION_RESET_OVERRIDES, "")

    def _restore_from_state(self):
        global _active_viewer
        state = db.load_window_state()
        if not state.get("is_open") or not state.get("func_ea"):
            return
        func_ea = state["func_ea"]
        mode = state.get("mode", "c")
        lineno = state.get("lineno", 0)
        col = state.get("col", 0)
        if _active_viewer is not None and _active_viewer.GetWidget() is not None:
            if _active_viewer.current_func_ea != func_ea or not _active_viewer.raw_lines:
                _active_viewer.show_func(func_ea)
            if lineno:
                try:
                    _active_viewer.Jump(lineno, col)
                except Exception:
                    pass
        else:
            show(func_ea, mode=mode, auto_dock=False)
            if _active_viewer is not None and lineno:
                try:
                    _active_viewer.Jump(lineno, col)
                except Exception:
                    pass


class _CustViewHooks(ida_kernwin.View_Hooks):
    def __init__(self, view):
        super().__init__()
        self.view = view

    def view_curpos(self, view):
        """Called whenever cursor position changes in any view."""
        if self.view and view == self.view.GetWidget():
            self.view.on_cursor_changed()

    def view_click(self, view, event):
        """Called on mouse click in view."""
        if self.view and view == self.view.GetWidget():
            self.view.on_cursor_changed()

    def view_close(self, view):
        """Called when view is closed."""
        if self.view and view == self.view.GetWidget():
            self.view.clear_asm_highlights()


def _register_actions(view):
    """Register widget-scoped IDA actions with Hex-Rays shortcuts and popup menu entries."""
    actions = [
        (ACTION_RENAME, "Rename...", "N", "Rename variable, parameter, or function", view.on_rename),
        (ACTION_SET_TYPE, "Set type...", "Y", "Set type of variable, parameter, global, or function", view.on_set_type),
        (ACTION_EDIT_CMT, "Add/Edit comment...", "/", "Add or edit statement comment", view.on_edit_comment),
        (ACTION_EDIT_CMT_SEMI, "Add/Edit comment...", ";", "Add or edit statement comment", view.on_edit_comment),
        (ACTION_TOGGLE_HEX, "Hexadecimal / Decimal", "H", "Toggle hexadecimal and decimal representation", view.on_toggle_hex),
        (ACTION_TOGGLE_CHAR, "Character constant", "R", "Toggle character constant ('A')", view.on_toggle_char),
        (ACTION_MAKE_ASCII, "ASCII string / Char", "A", "Create/toggle ASCII string literal or character constant", view.on_make_ascii),
        (ACTION_TOGGLE_BIN, "Binary", "B", "Toggle binary representation (0b...)", view.on_toggle_bin),
        (ACTION_TOGGLE_SIGNED, "Invert sign", "_", "Toggle signed / unsigned representation", view.on_toggle_signed),
        (ACTION_TOGGLE_INV, "Bitwise negate", "~", "Toggle bitwise negated constant (~0x...)", view.on_toggle_invert_bits),
        (ACTION_TOGGLE_OFFSET, "Offset / Symbol", "O", "Toggle symbol/offset representation (&sym)", view.on_toggle_offset),
        (ACTION_SET_ENUM, "Use symbolic constant (Enum)...", "M", "Replace number with IDA enum constant", view.on_set_enum),
        (ACTION_INVERT_IF, "Invert if-statement", "I", "Invert if condition and swap then/else branches", view.on_invert_if),
        (ACTION_TOGGLE_CASTS, "Hide/Show casts", "\\", "Toggle hiding redundant C casts", view.on_toggle_casts),
        (ACTION_SHOW_XREFS, "Jump to xrefs...", "X", "Open cross-references window", view.on_show_xrefs),
        (ACTION_JUMP_ADDR, "Jump to address...", "G", "Jump to an address or function", view.on_jump_addr),
        (ACTION_JUMP_DISASM, "Jump to Callee / Symbol", None, "Jump to callee function or symbol under cursor (Enter)", view.jump_disasm),
        (ACTION_SWITCH_DISASM, "Switch to Disassembly", "Tab", "Focus disassembly view at current statement", view.on_switch_to_disasm),
        (ACTION_NAV_BACK, "Navigate Back", "Esc", "Navigate back to previous function", view.on_nav_back),
        (ACTION_NAV_FORWARD, "Navigate Forward", "Ctrl+Enter", "Navigate forward in history", view.on_nav_forward),
        (ACTION_TOGGLE_SYNC, "Synchronize with Disassembly", "Alt+S", "Toggle automatic synchronization with IDA View-A", view.toggle_sync),
        (ACTION_TOGGLE_IR, "Toggle Pseudocode / SSA IR", "Shift+I", "Switch between C pseudocode and SSA IR view", view.toggle_ir),
        (ACTION_REFRESH, "Refresh Decompilation (F5)", None, "Re-decompile current function",
         lambda: view.show_func(view.current_func_ea, preserve_cursor=True)),
        (ACTION_RESET_OVERRIDES, "Reset all overrides...", None, "Clear all saved overrides for this function", view.on_reset_overrides),
    ]
    for action_id, label, shortcut, tooltip, callback in actions:
        ida_kernwin.unregister_action(action_id)
        desc = ida_kernwin.action_desc_t(
            action_id,
            label,
            _ActionHandler(view, callback),
            shortcut,
            tooltip
        )
        ida_kernwin.register_action(desc)


def show(target, mode="c", auto_dock=True):
    """Open or refresh the dockable decompiler view for the specified function or EA."""
    global _active_viewer, _ui_hooks, _view_hooks
    first_create = False
    if _active_viewer is None or _active_viewer.GetWidget() is None:
        v = _DecompilerView()
        if not v.Create(_VIEW_TITLE):
            return None
        _active_viewer = v
        _register_actions(_active_viewer)
        first_create = True

        if _ui_hooks is None:
            _ui_hooks = _UiHooks(_active_viewer)
            _ui_hooks.hook()
        else:
            _ui_hooks.view = _active_viewer

        if _view_hooks is None:
            _view_hooks = _CustViewHooks(_active_viewer)
            _view_hooks.hook()
        else:
            _view_hooks.view = _active_viewer

    target_ea = target if isinstance(target, int) else getattr(target, "start_ea", None)
    same_func = (not first_create and target_ea is not None and _active_viewer.current_func_ea == target_ea)
    _active_viewer.build_or_refresh(target, mode=mode, preserve_cursor=same_func)
    _active_viewer.Show()

    if first_create and auto_dock:
        try:
            ida_kernwin.set_dock_pos(_VIEW_TITLE, "IDA View-A", ida_kernwin.DP_RIGHT)
        except Exception:
            pass

    if _active_viewer.current_func_ea is not None:
        pos = _active_viewer.GetPos() or (0, 0)
        db.save_window_state(True, _active_viewer.current_func_ea, lineno=pos[0], col=pos[1],
                             mode=_active_viewer.mode, persist=True)

    return _active_viewer


def init_hooks():
    """Initialize UI hooks early (at plugin load) to support desktop/docking persistence."""
    global _ui_hooks
    if _ui_hooks is None:
        _ui_hooks = _UiHooks(None)
        _ui_hooks.hook()


class ListingViewer(ida_kernwin.simplecustviewer_t):
    """
    A plain scrollable listing, for the whole-database decompilation.

    Double-click on a `// name @ 0xEA` header line jumps there.
    """

    def __init__(self):
        super(ListingViewer, self).__init__()
        self.line_ea = []

    def build(self, title, lines):
        if not self.Create(title):
            return False
        self.line_ea = []
        for ln in lines:
            ea = None
            m = re.search(r"@\s*0x([0-9A-Fa-f]+)", ln)
            if m:
                try:
                    ea = int(m.group(1), 16)
                except ValueError:
                    ea = None
            self.AddLine(highlight.colorize(ln))
            self.line_ea.append(ea)
        return True

    def OnDblClick(self, shift):
        n = self.GetLineNo()
        if n is None or n >= len(self.line_ea):
            return False
        ea = self.line_ea[n]
        if ea is None:
            return False
        idaapi.jumpto(ea)
        return True

    def OnKeydown(self, vkey, shift):
        if vkey == 27:
            self.Close()
            return True
        return False


def show_listing(title, lines):
    v = ListingViewer()
    if not v.build(title, lines):
        return None
    v.Show()
    return v


def cleanup():
    """Unregister hooks and actions on plugin unload."""
    global _active_viewer, _ui_hooks, _view_hooks
    if _active_viewer is not None:
        try:
            _active_viewer.clear_asm_highlights()
        except Exception:
            pass
    if _ui_hooks is not None:
        try:
            _ui_hooks.unhook()
        except Exception:
            pass
        _ui_hooks = None
    if _view_hooks is not None:
        try:
            _view_hooks.unhook()
        except Exception:
            pass
        _view_hooks = None
    for action_id in (ACTION_DECOMPILE,) + _ALL_VIEW_ACTIONS:
        try:
            ida_kernwin.unregister_action(action_id)
        except Exception:
            pass
    _active_viewer = None
