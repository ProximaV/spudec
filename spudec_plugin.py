"""
IDA plugin entry point for the SPU decompiler front end.

Install by copying this file *and* the ``spudec`` package directory next to
each other into IDA's user plugin directory:

    %APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\

    F5             decompile the function under the cursor (or refresh)
    Ctrl-Shift-S   legacy decompile shortcut
    Ctrl-F5        decompile everything in the database

The patched ``spu.py`` belongs in %APPDATA%\\Hex-Rays\\IDA Pro\\procs\\ .
"""

import os
import sys
import time
import traceback

import ida_idaapi
import ida_idp
import ida_kernwin
import ida_funcs
import idaapi

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


HOTKEY_DECOMPILE = "F5"
HOTKEY_LEGACY = "Ctrl-Shift-S"
HOTKEY_ALL = "Ctrl-F5"

ACTION_DECOMPILE = "spudec:decompile"
MENU_PSEUDOCODE_PATH = "View/Open subviews/Generate pseudocode"
MENU_PLUGIN_PATH = "Edit/Plugins/SPU decompiler (spudec)"

# Viewers must outlive run(); IDA does not hold a reference for us.
_views = []
_hotkeys = []


def _check_spu():
    if ida_idp.ph_get_id() != ida_idp.PLFM_SPU:
        ida_kernwin.warning(
            "spudec: this database is not SPU "
            "(processor id %d, expected %d)."
            % (ida_idp.ph_get_id(), ida_idp.PLFM_SPU))
        return False
    return True


def _name_of(ea):
    """
    The name a call site should print.

    Delegates to the package's shared resolver so C++ symbols are demangled
    here too; returning a bare `get_name()` would override the default and
    silently undo the demangling for the whole listing.
    """
    import spudec
    return spudec.names()(ea)


# ---------------------------------------------------------------------------
# one function
# ---------------------------------------------------------------------------


def _run_one():
    import spudec
    from spudec import view

    if not _check_spu():
        return

    ea = ida_kernwin.get_screen_ea()
    f = ida_funcs.get_func(ea) if (ea is not None and ea != idaapi.BADADDR) else None

    # If the pseudocode viewer is active and focused, get_screen_ea() can be BADADDR
    if f is None and getattr(view, "_active_viewer", None) is not None and view._active_viewer.current_func_ea is not None:
        start_ea = view._active_viewer.current_func_ea
    elif f is not None:
        start_ea = f.start_ea
    else:
        ida_kernwin.warning("spudec: no function at 0x%X.\n"
                            "Create one with 'P' first." % (ea if ea is not None else 0))
        return

    try:
        func = spudec.decompile(start_ea, check=True)
    except Exception:
        ida_kernwin.warning("spudec failed:\n\n%s" % traceback.format_exc())
        return

    v = view.show(func)
    if v is not None and v not in _views:
        _views.append(v)

    n = sum(len(b.insns) for b in func.blocks)
    msg = "spudec: %s -> %d blocks, %d IR instructions" % (
        func.name or "sub_%X" % func.start_ea, len(func.blocks), n)
    info = getattr(func, "structure_info", None)
    if info:
        msg += ", %d loops, %d gotos" % (info.get("loops", 0),
                                         info.get("gotos", 0))
    if func.unhandled:
        msg += " (%d unmodelled mnemonics)" % len(func.unhandled)
    if func.problems:
        msg += " -- %d SSA problems, see the viewer" % len(func.problems)
    print(msg)


# ---------------------------------------------------------------------------
# everything
# ---------------------------------------------------------------------------

# Above this, the listing is offered as a file only: a custom viewer holding
# a few hundred thousand lines is painful to scroll and slow to build.
VIEWER_LINE_LIMIT = 60000


def _run_all():
    import spudec
    from spudec import view

    if not _check_spu():
        return

    total = ida_funcs.get_func_qty()
    if total == 0:
        ida_kernwin.warning("spudec: this database has no functions.")
        return

    state = {"t": 0.0}

    def progress(done, n, name):
        # Throttled: updating the wait box for every function costs more than
        # the decompilation does on small ones.
        now = time.time()
        if now - state["t"] > 0.1:
            state["t"] = now
            ida_kernwin.replace_wait_box(
                "Decompiling %d/%d\n%s" % (done + 1, n, name[:60]))
        return not ida_kernwin.user_cancelled()

    ida_kernwin.show_wait_box("Decompiling %d functions..." % total)
    t0 = time.time()
    try:
        lines, stats = spudec.decompile_all(name_of=_name_of,
                                            progress=progress)
    except Exception:
        ida_kernwin.hide_wait_box()
        ida_kernwin.warning("spudec: decompile all failed:\n\n%s"
                            % traceback.format_exc())
        return
    finally:
        try:
            ida_kernwin.hide_wait_box()
        except Exception:
            pass
    dt = time.time() - t0

    summary = ("spudec: %d functions in %.1fs (%d failed, %d SSA problems, "
               "%d loops, %d gotos)"
               % (stats["functions"], dt, stats["failed"], stats["problems"],
                  stats["loops"], stats["gotos"]))
    if stats["cancelled"]:
        summary += "  [CANCELLED -- partial output]"
    print(summary)

    # Offer to save, the way Hex-Rays' "Decompile all" does.
    import ida_nalt
    default = os.path.splitext(
        ida_nalt.get_input_file_path() or "spu")[0] + ".c"
    path = ida_kernwin.ask_file(True, default,
                                "Save the decompiled listing")
    if path:
        try:
            with open(path, "w", encoding="utf-8") as fp:
                fp.write("\n".join(lines))
                fp.write("\n")
            print("spudec: wrote %d lines to %s" % (len(lines), path))
        except Exception as exc:
            ida_kernwin.warning("spudec: could not write %s:\n%s"
                                % (path, exc))

    if len(lines) > VIEWER_LINE_LIMIT:
        ida_kernwin.info(
            "spudec: %d lines is too many for the viewer.\n"
            "%s" % (len(lines),
                    "Saved to %s" % path if path
                    else "Re-run and choose a file to save it."))
        return

    v = view.show_listing("SPU decompilation - all functions", lines)
    if v is not None:
        _views.append(v)


# ---------------------------------------------------------------------------
# UI action handler for F5 decompile
# ---------------------------------------------------------------------------


class _DecompileActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        _run_one()
        return 1

    def update(self, ctx):
        if ida_idp.ph_get_id() != ida_idp.PLFM_SPU:
            return ida_kernwin.AST_DISABLE_ALWAYS
        return ida_kernwin.AST_ENABLE_ALWAYS


def _register_actions():
    ida_kernwin.unregister_action(ACTION_DECOMPILE)
    desc = ida_kernwin.action_desc_t(
        ACTION_DECOMPILE,
        "SPU Pseudocode",
        _DecompileActionHandler(),
        HOTKEY_DECOMPILE,
        "Decompile current SPU function to pseudocode (F5)",
        -1
    )
    if ida_kernwin.register_action(desc):
        ida_kernwin.attach_action_to_menu(MENU_PSEUDOCODE_PATH, ACTION_DECOMPILE, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_menu(MENU_PLUGIN_PATH, ACTION_DECOMPILE, ida_kernwin.SETMENU_APP)


def _unregister_actions():
    try:
        ida_kernwin.detach_action_from_menu(MENU_PSEUDOCODE_PATH, ACTION_DECOMPILE)
    except Exception:
        pass
    try:
        ida_kernwin.detach_action_from_menu(MENU_PLUGIN_PATH, ACTION_DECOMPILE)
    except Exception:
        pass
    try:
        ida_kernwin.unregister_action(ACTION_DECOMPILE)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Plugin descriptor
# ---------------------------------------------------------------------------


class SpuDecPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC
    comment = "This is a decompilation plugin."
    help = ("%s decompiles the current function, %s decompiles everything."
            % (HOTKEY_DECOMPILE, HOTKEY_ALL))
    wanted_name = "SPU decompiler (spudec)"
    wanted_hotkey = HOTKEY_DECOMPILE

    def init(self):
        if ida_idp.ph_get_id() != ida_idp.PLFM_SPU:
            return ida_idaapi.PLUGIN_SKIP

        _register_actions()

        for hk, fn in [(HOTKEY_DECOMPILE, _run_one),
                       (HOTKEY_LEGACY, _run_one),
                       (HOTKEY_ALL, _run_all)]:
            ctx = ida_kernwin.add_hotkey(hk, fn)
            if ctx is not None:
                _hotkeys.append(ctx)

        try:
            from spudec import view
            view.init_hooks()
        except Exception:
            pass

        print("spudec: loaded -- %s = this function, %s = decompile all"
              % (HOTKEY_DECOMPILE, HOTKEY_ALL))
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        _run_one()

    def term(self):
        _unregister_actions()
        try:
            from spudec import view
            view.cleanup()
        except Exception:
            pass
        for ctx in _hotkeys:
            try:
                ida_kernwin.del_hotkey(ctx)
            except Exception:
                pass
        del _hotkeys[:]
        del _views[:]


def PLUGIN_ENTRY():
    return SpuDecPlugin()

