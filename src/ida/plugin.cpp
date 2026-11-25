#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <mergemod.hpp>

#include "plugin.hpp"
#include "api_dispatch.hpp"
#include "db.hpp"
#include "ida_provider.hpp"
#include "idc_funcs.hpp"
#include "merge.hpp"
#include "summary_cache.hpp"
#include "view.hpp"
#include "spudec/pipeline.hpp"

namespace spudec {

namespace {

SpuDecPlugmod *g_active_plugmod = nullptr;

void register_spudec_addon_info() {
    static bool registered = false;
    if (registered) return;
    addon_info_t addon;
    addon.id = "org.spudec.native";
    addon.name = "Cell SPU Native Decompiler (spudec)";
    addon.producer = "spudec";
    addon.version = SPUDEC_VERSION;
    addon.url = "";
    addon.freeform = "Compiled C++17 Cell Broadband Engine SPU Decompiler";
    register_addon(&addon);
    registered = true;
}

} // namespace

bool is_spu_database_active() {
    return g_active_plugmod != nullptr && g_active_plugmod->active_on_spu && PH.id == PLFM_SPU;
}

SpuDecPlugmod *active_spudec_plugmod() {
    return g_active_plugmod;
}

ssize_t idaapi SpuDecPlugmod::IdpListener::on_event(ssize_t code, va_list va) {
    return pm.on_idp_event(code, va);
}

SpuDecPlugmod::SpuDecPlugmod() {
    active_on_spu = (PH.id == PLFM_SPU);
    g_active_plugmod = this;
    set_module_data(&data_id, this);

    register_spudec_addon_info();
    hook_event_listener(HT_UI, this);
    hook_event_listener(HT_IDB, &global_summary_cache());
    hook_event_listener(HT_IDP, &idp_listener);

    register_all_spudec_actions(this);
    register_spudec_idc_funcs();
}

SpuDecPlugmod::~SpuDecPlugmod() {
    global_vdui().close_and_cleanup();
    clear_api_handles();
    global_summary_cache().clear_all();

    unregister_spudec_idc_funcs();
    unregister_all_spudec_actions();

    unhook_event_listener(HT_IDP, &idp_listener);
    unhook_event_listener(HT_IDB, &global_summary_cache());
    unhook_event_listener(HT_UI, this);

    clr_module_data(data_id);
    if (g_active_plugmod == this) {
        g_active_plugmod = nullptr;
    }
    active_on_spu = false;
}

bool idaapi SpuDecPlugmod::run(size_t arg) {
    if (!active_on_spu || PH.id != PLFM_SPU) return false;

    // arg == 1: Decompile all functions viewer; arg == 2: Clear caches; default: Decompile current function
    if (arg == 1) {
        return open_decompile_all_viewer();
    }
    if (arg == 2) {
        global_summary_cache().clear_all();
        clear_api_handles();
        if (global_vdui().is_open()) global_vdui().refresh_view(true);
        msg("[spudec] Cleared all caches.\n");
        return true;
    }

    SpuVdui &v = global_vdui();
    if (v.widget() && get_current_widget() == v.widget()) {
        return v.refresh_view(true);
    }

    ea_t ea = get_screen_ea();
    if (ea == BADADDR && v.current_func_ea().has_value()) {
        ea = static_cast<ea_t>(*v.current_func_ea());
    }
    if (ea == BADADDR) return false;
    return v.open_or_focus(static_cast<uint64_t>(ea), 1, true);
}

ssize_t SpuDecPlugmod::on_idp_event(ssize_t code, va_list va) {
    switch (code) {
        case processor_t::ev_create_merge_handlers: {
            merge_data_t *md = va_arg(va, merge_data_t *);
            if (md) {
                register_spudec_merge_handlers(*md, data_id);
            }
            break;
        }
        case processor_t::ev_ending_undo: {
            global_summary_cache().clear_all();
            if (global_vdui().is_open()) {
                global_vdui().refresh_view(true);
            }
            break;
        }
        default:
            break;
    }
    return 0;
}

ssize_t idaapi SpuDecPlugmod::on_event(ssize_t code, va_list va) {
    if (!active_on_spu) return 0;

    switch (code) {
        case ui_broadcast: {
            int magic = va_arg(va, int);
            if (magic == SPUDEC_BROADCAST_MAGIC) {
                auto *req = va_arg(va, SpudecBroadcastReq *);
                if (handle_spudec_broadcast(req)) {
                    return 1;
                }
            }
            break;
        }

        case ui_create_desktop_widget: {
            const char *ttl = va_arg(va, const char *);
            (void)va_arg(va, const void *);
            if (ttl && qstrcmp(ttl, SPUDEC_VIEW_TITLE) == 0) {
                TWidget *w = global_vdui().create_for_desktop();
                return reinterpret_cast<ssize_t>(w);
            }
            break;
        }

        case ui_ready_to_run: {
            update_action_shortcut(ACTION_DECOMPILE, "F5");
            update_action_shortcut(ACTION_DECOMPILE_ALL, "Ctrl-F5");
            if (!desktop_restored && is_idaq()) {
                desktop_restored = true;
                global_vdui().restore_saved_window();
            }
            break;
        }

        case ui_desktop_applied: {
            if (!desktop_restored && is_idaq()) {
                desktop_restored = true;
                global_vdui().restore_saved_window();
            }
            break;
        }

        case ui_database_inited: {
            ensure_spu_types();
            if (!desktop_restored && is_idaq()) {
                desktop_restored = true;
                global_vdui().restore_saved_window();
            }
            break;
        }

        case ui_saving: {
            global_vdui().persist_window_state(true);
            break;
        }

        case ui_screen_ea_changed: {
            ea_t ea = va_arg(va, ea_t);
            ea_t prev_ea = va_arg(va, ea_t);
            global_vdui().on_screen_ea_changed(ea, prev_ea);
            break;
        }

        case ui_widget_invisible: {
            TWidget *w = va_arg(va, TWidget *);
            global_vdui().on_widget_invisible(w);
            break;
        }

        case ui_finish_populating_widget_popup: {
            TWidget *w = va_arg(va, TWidget *);
            TPopupMenu *popup = va_arg(va, TPopupMenu *);
            global_vdui().populate_popup(w, popup);
            break;
        }

        case ui_get_custom_viewer_hint: {
            qstring *hint = va_arg(va, qstring *);
            TWidget *viewer = va_arg(va, TWidget *);
            place_t *place = va_arg(va, place_t *);
            int *important_lines = va_arg(va, int *);
            if (hint && global_vdui().get_hint(viewer, place, *hint, important_lines)) {
                return 1;
            }
            break;
        }

        case ui_get_lines_rendering_info: {
            auto *out = va_arg(va, lines_rendering_output_t *);
            const TWidget *viewer = va_arg(va, const TWidget *);
            const auto *info = va_arg(va, const lines_rendering_input_t *);
            global_vdui().get_lines_rendering_info(out, viewer, info);
            break;
        }

        default:
            break;
    }
    return 0;
}

} // namespace spudec

// ---------------------------------------------------------------------------
// IDA Plugin Entry Point
// ---------------------------------------------------------------------------

static plugmod_t *idaapi spudec_init() {
    if (PH.id != PLFM_SPU) {
        return nullptr; // Strictly inactive on non-SPU architectures!
    }
    return new spudec::SpuDecPlugmod();
}

static const char kSpudecComment[] = "This is a decompilation plugin.";
static const char kSpudecHelp[] =
    "Cell SPU Decompiler (spudec)\n"
    "Press F5 in any SPU function to open interactive C pseudocode.\n"
    "Press Ctrl+F5 to decompile all functions in the database.\n";
static const char kSpudecWantedName[] = "SPU decompiler (spudec)";
static const char kSpudecWantedHotkey[] = "F5";

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_PROC | PLUGIN_MULTI, // Auto-initializes when PLFM_SPU processor loads; zero effect on other arches
    spudec_init,
    nullptr,
    nullptr,
    kSpudecComment,
    kSpudecHelp,
    kSpudecWantedName,
    kSpudecWantedHotkey,
};