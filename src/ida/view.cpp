#include <ida.hpp>
#include <bytes.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <typeinf.hpp>

#ifdef strtoull
#undef strtoull
#endif

#include "view.hpp"
#include "db.hpp"
#include "ida_provider.hpp"
#include "plugin.hpp"
#include "summary_cache.hpp"

#include "spudec/abi.hpp"
#include "spudec/highlight.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace spudec {

namespace {

std::string trim_copy(const std::string &s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

bool is_valid_c_ident(const std::string &s) {
    if (s.empty()) return false;
    unsigned char c0 = static_cast<unsigned char>(s[0]);
    if (!(std::isalpha(c0) || c0 == '_')) return false;
    for (size_t i = 1; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (!(std::isalnum(c) || c == '_')) return false;
    }
    return true;
}

bool is_builtin_spudec_type(const std::string &raw) {
    std::string base = trim_copy(raw);
    while (!base.empty() && (base.back() == '*' || std::isspace(static_cast<unsigned char>(base.back())))) {
        base.pop_back();
    }
    if (base.rfind("const ", 0) == 0) base = trim_copy(base.substr(6));
    if (base.rfind("volatile ", 0) == 0) base = trim_copy(base.substr(9));
    static const std::unordered_set<std::string> kKnown = {
        "void", "bool", "char", "short", "int", "long", "float", "double",
        "u8", "u16", "u32", "u64", "u128",
        "i8", "i16", "i32", "i64", "i128",
        "s8", "s16", "s32", "s64", "s128",
        "f32", "f64", "qword", "__int128", "unsigned __int128",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "int8_t", "int16_t", "int32_t", "int64_t", "size_t", "ssize_t", "uintptr_t",
        "vec_uchar16", "vec_char16", "vec_ushort8", "vec_short8",
        "vec_uint4", "vec_int4", "vec_ullong2", "vec_llong2",
        "vec_float4", "vec_double2",
    };
    return kKnown.count(base) > 0;
}

bool line_contains_ident(const std::string &line, const std::string &ident) {
    if (ident.empty()) return false;
    size_t pos = 0;
    while ((pos = line.find(ident, pos)) != std::string::npos) {
        bool left_ok = (pos == 0) ||
            !(std::isalnum(static_cast<unsigned char>(line[pos - 1])) || line[pos - 1] == '_');
        size_t end = pos + ident.size();
        bool right_ok = (end >= line.size()) ||
            !(std::isalnum(static_cast<unsigned char>(line[end])) || line[end] == '_');
        if (left_ok && right_ok) return true;
        pos = end;
    }
    return false;
}

bool is_packed_ascii_constant(uint64_t val, uint64_t val_hi, int bits) {
    std::vector<uint8_t> raw;
    if (bits > 64 && (val_hi != 0 || val != 0)) {
        for (int i = 7; i >= 0; --i) raw.push_back(static_cast<uint8_t>((val_hi >> (i * 8)) & 0xFF));
        for (int i = 7; i >= 0; --i) raw.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
    } else {
        int nbytes = std::max(1, std::min(8, (bits + 7) / 8));
        for (int i = nbytes - 1; i >= 0; --i) raw.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
    }
    // Strip leading and trailing zero padding bytes
    size_t start = 0;
    while (start < raw.size() && raw[start] == 0) ++start;
    size_t end = raw.size();
    while (end > start && raw[end - 1] == 0) --end;
    if (end - start < 2) return false;
    for (size_t i = start; i < end; ++i) {
        uint8_t b = raw[i];
        if (b < 0x20 || b > 0x7E) return false;
    }
    return true;
}

// Modal chooser for local variable cross-references inside the current function
struct LocalXrefRow {
    int lineno = 0;
    uint64_t ea = 0;
    std::string text;
};

struct LocalXrefChooser : public chooser_t {
    static constexpr int kWidths[] = {6, 10, 64};
    static constexpr const char *const kHeaders[] = {"Line", "Address", "Statement"};
    std::vector<LocalXrefRow> rows;

    LocalXrefChooser(const char *title_str, std::vector<LocalXrefRow> r)
        : chooser_t(CH_MODAL | CH_KEEP, 3, kWidths, kHeaders, title_str),
          rows(std::move(r)) {}

    size_t idaapi get_count() const override { return rows.size(); }

    void idaapi get_row(qstrvec_t *cols, int *, chooser_item_attrs_t *, size_t n) const override {
        if (!cols || n >= rows.size()) return;
        (*cols)[0].sprnt("%d", rows[n].lineno + 1);
        if (rows[n].ea != UINT64_MAX && rows[n].ea != 0) {
            (*cols)[1].sprnt("0x%05llX", static_cast<unsigned long long>(rows[n].ea));
        } else {
            (*cols)[1] = "-";
        }
        (*cols)[2] = rows[n].text.c_str();
    }
};

// Modal chooser when multiple IDA enum members share the same constant value
struct EnumMatchChooser : public chooser_t {
    static constexpr int kWidths[] = {48};
    static constexpr const char *const kHeaders[] = {"Symbolic Constant"};
    std::vector<std::string> names;

    EnumMatchChooser(const char *title_str, std::vector<std::string> n)
        : chooser_t(CH_MODAL | CH_KEEP, 1, kWidths, kHeaders, title_str),
          names(std::move(n)) {}

    size_t idaapi get_count() const override { return names.size(); }

    void idaapi get_row(qstrvec_t *cols, int *, chooser_item_attrs_t *, size_t n) const override {
        if (cols && n < names.size()) (*cols)[0] = names[n].c_str();
    }
};

// Custom viewer static trampolines for SpuVdui
bool idaapi vdui_ct_keyboard(TWidget *, int key, int shift, void *ud) {
    auto *v = static_cast<SpuVdui *>(ud);
    return v ? v->handle_keyboard(key, shift) : false;
}

void idaapi vdui_ct_curpos(TWidget *, void *ud) {
    auto *v = static_cast<SpuVdui *>(ud);
    if (v) v->handle_curpos();
}

bool idaapi vdui_ct_click(TWidget *, int shift, void *ud) {
    auto *v = static_cast<SpuVdui *>(ud);
    if (v) v->handle_click(shift);
    return false;
}

bool idaapi vdui_ct_dblclick(TWidget *, int shift, void *ud) {
    auto *v = static_cast<SpuVdui *>(ud);
    return v ? v->handle_dblclick(shift) : false;
}

static const custom_viewer_handlers_t kVduiHandlers(
    vdui_ct_keyboard,
    nullptr, // popup handled via ui_finish_populating_widget_popup
    nullptr, // mouse_moved
    vdui_ct_click,
    vdui_ct_dblclick,
    vdui_ct_curpos,
    nullptr, // close handled via ui_widget_invisible
    nullptr,
    nullptr);

// Whole-binary listing viewer state (Ctrl+F5)
struct ListingViewState {
    TWidget *widget = nullptr;
    strvec_t lines;
    std::string raw_c_text;
};

ListingViewState &listing_state() {
    static ListingViewState st;
    return st;
}

bool idaapi listing_ct_dblclick(TWidget *v, int, void *) {
    const char *cur = get_custom_viewer_curline(v, false);
    if (!cur) return false;
    qstring clean;
    tag_remove(&clean, cur);
    const char *s = clean.c_str();
    const char *p = std::strstr(s, "sub_");
    if (!p) p = std::strstr(s, "0x");
    if (p) {
        p += (p[0] == 's') ? 4 : 2;
        char *endp = nullptr;
        unsigned long long val = std::strtoull(p, &endp, 16);
        if (endp > p && is_loaded(static_cast<ea_t>(val))) {
            global_vdui().open_or_focus(static_cast<uint64_t>(val), 1, true);
            return true;
        }
    }
    return false;
}

static const custom_viewer_handlers_t kListingHandlers(
    nullptr, nullptr, nullptr, nullptr, listing_ct_dblclick, nullptr, nullptr, nullptr, nullptr);

} // namespace

// ---------------------------------------------------------------------------
// Shared Decompilation Helpers
// ---------------------------------------------------------------------------

SpuVdui &global_vdui() {
    static SpuVdui instance;
    return instance;
}

SpuVdui *find_vdui_for_widget(TWidget *w) {
    if (!w) return nullptr;
    SpuVdui &v = global_vdui();
    if (v.widget() == w) return &v;
    qstring title;
    if (get_widget_title(&title, w) && title == SPUDEC_VIEW_TITLE) {
        return &v;
    }
    return nullptr;
}

TWidget *get_listing_widget() {
    return listing_state().widget;
}

cfuncptr_t decompile_or_get_cached(uint64_t ea, bool force_redecompile, std::string *out_error) {
    SummaryCache &cache = global_summary_cache();
    IdaDatabaseProvider prov(&cache);

    uint64_t func_ea = ea;
    prov.get_func_start(ea, &func_ea);

    const bool hide_casts = idadb::get_hide_casts();
    if (!force_redecompile) {
        cfuncptr_t cached = cache.get_cached_cfunc(func_ea);
        if (cached && cached->hide_casts == hide_casts) {
            if (cached->has_tree_mutations()) {
                cached->refresh_func_ctext();
            }
            return cached;
        }
    }

    ensure_spu_types();
    DecompileOptions opts;
    opts.hide_casts = hide_casts;
    opts.user_data = idadb::get_func_data(func_ea);

    DecompileOutput res = decompile_function(prov, func_ea, opts);
    if (!res.cfunc) {
        if (out_error) *out_error = res.error.empty() ? "Decompilation failed" : res.error;
        return nullptr;
    }
    cache.put_cached_cfunc(func_ea, res.cfunc);
    return res.cfunc;
}

std::string decompile_single_to_text(uint64_t ea, std::string *out_error) {
    cfuncptr_t cf = decompile_or_get_cached(ea, false, out_error);
    if (!cf) return {};
    return cf->print_func();
}

std::string dump_single_ir_to_text(uint64_t ea, std::string *out_error) {
    SummaryCache &cache = global_summary_cache();
    IdaDatabaseProvider prov(&cache);
    uint64_t func_ea = ea;
    prov.get_func_start(ea, &func_ea);

    DecompileOptions opts;
    opts.hide_casts = idadb::get_hide_casts();
    opts.user_data = idadb::get_func_data(func_ea);

    std::string err;
    std::unique_ptr<Function> fn = lift_and_optimize(prov, func_ea, opts, &err);
    if (!fn) {
        if (out_error) *out_error = err.empty() ? "IR lift failed" : err;
        return {};
    }
    return fn->dump();
}

std::string decompile_all_to_string(bool show_progress, int *out_ok, int *out_fail) {
    ensure_spu_types();
    const size_t total = get_func_qty();
    int ok_cnt = 0;
    int fail_cnt = 0;

    std::string out;
    out.reserve(total * 512 + 256);
    out += "/* Decompiled by spudec (native C++) */\n";
    out += "#include <stdint.h>\n";
    out += "#include <spu_intrinsics.h>\n\n";

    if (show_progress) {
        show_wait_box("spudec: decompiling 0/%u functions...", static_cast<unsigned>(total));
    }

    for (size_t i = 0; i < total; ++i) {
        if (show_progress && (i % 16 == 0)) {
            if (user_cancelled()) break;
            replace_wait_box("spudec: decompiling %u/%u functions...",
                             static_cast<unsigned>(i), static_cast<unsigned>(total));
        }
        func_t *pfn = getn_func(i);
        if (!pfn) continue;
        uint64_t fea = static_cast<uint64_t>(pfn->start_ea);
        std::string err;
        cfuncptr_t cf = decompile_or_get_cached(fea, false, &err);
        char hdr[128];
        std::snprintf(hdr, sizeof(hdr), "/* === 0x%05llX === */\n",
                      static_cast<unsigned long long>(fea));
        out += hdr;
        if (cf) {
            out += cf->print_func();
            out += "\n\n";
            ++ok_cnt;
        } else {
            out += "/* DECOMPILATION FAILED: " + err + " */\n\n";
            ++fail_cnt;
        }
    }

    if (show_progress) {
        hide_wait_box();
    }
    if (out_ok) *out_ok = ok_cnt;
    if (out_fail) *out_fail = fail_cnt;
    return out;
}

int act_save_listing_to_c_file() {
    ListingViewState &st = listing_state();
    if (st.raw_c_text.empty()) return 0;
    char *path = ask_file(true, "decompiled_spu.c", "C source files|*.c;*.h|All files|*.*");
    if (!path) return 0;
    FILE *fp = qfopen(path, "wb");
    if (!fp) {
        warning("spudec: failed to open '%s' for writing.", path);
        return 0;
    }
    qfwrite(fp, st.raw_c_text.data(), st.raw_c_text.size());
    qfclose(fp);
    msg("[spudec] Exported %u bytes to %s\n",
        static_cast<unsigned>(st.raw_c_text.size()), path);
    return 1;
}

bool open_decompile_all_viewer() {
    int ok_cnt = 0, fail_cnt = 0;
    std::string full_text = decompile_all_to_string(true, &ok_cnt, &fail_cnt);
    msg("[spudec] Decompiled %d functions (%d failed).\n", ok_cnt, fail_cnt);

    ListingViewState &st = listing_state();
    st.raw_c_text = std::move(full_text);
    st.lines.qclear();

    std::istringstream iss(st.raw_c_text);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string colored = highlight::colorize(line);
        st.lines.push_back(simpleline_t(colored.c_str()));
    }
    if (st.lines.empty()) {
        st.lines.push_back(simpleline_t("/* No functions found */"));
    }

    TWidget *existing = find_widget(SPUDEC_LISTING_TITLE);
    if (existing) {
        st.widget = existing;
        simpleline_place_t s1;
        simpleline_place_t s2(static_cast<int>(st.lines.size()) - 1);
        set_custom_viewer_range(st.widget, &s1, &s2);
        jumpto(st.widget, &s1, 0, 0);
        refresh_custom_viewer(st.widget);
        activate_widget(st.widget, true);
        return true;
    }

    simpleline_place_t s1;
    simpleline_place_t s2(static_cast<int>(st.lines.size()) - 1);
    st.widget = create_custom_viewer(
        SPUDEC_LISTING_TITLE, &s1, &s2, &s1, nullptr, &st.lines, &kListingHandlers, nullptr);
    if (!st.widget) return false;
    display_widget(st.widget, WOPN_DP_TAB | WOPN_RESTORE);
    attach_action_to_popup(st.widget, nullptr, ACTION_SAVE_LISTING_C);
    return true;
}

// ---------------------------------------------------------------------------
// SpuVdui Implementation
// ---------------------------------------------------------------------------

bool SpuVdui::ensure_widget_created(bool dock_right, bool activate) {
    if (widget_ != nullptr) {
        TWidget *found = find_widget(SPUDEC_VIEW_TITLE);
        if (found == widget_) {
            if (activate) activate_widget(widget_, true);
            return true;
        }
        widget_ = nullptr;
    }

    TWidget *existing = find_widget(SPUDEC_VIEW_TITLE);
    if (existing != nullptr) {
        widget_ = existing;
        set_custom_viewer_handlers(widget_, &kVduiHandlers, this);
        if (activate) activate_widget(widget_, true);
        return true;
    }

    if (lines_.empty()) {
        lines_.push_back(simpleline_t("/* Ready */"));
    }
    simpleline_place_t s1;
    simpleline_place_t s2(static_cast<int>(lines_.size()) - 1);
    widget_ = create_custom_viewer(
        SPUDEC_VIEW_TITLE, &s1, &s2, &s1, nullptr, &lines_, &kVduiHandlers, this);
    if (!widget_) return false;

    uint32 wopn = WOPN_DP_TAB | WOPN_RESTORE;
    display_widget(widget_, wopn);
    if (dock_right) {
        set_dock_pos(SPUDEC_VIEW_TITLE, "IDA View-A", DP_RIGHT);
    }
    if (activate) {
        activate_widget(widget_, true);
    }
    notify_event(spe_open_pseudocode, this);
    return true;
}

TWidget *SpuVdui::create_for_desktop() {
    sync_with_disasm_ = idadb::get_sync_enabled();
    WindowState st = idadb::load_window_state();
    mode_ = (st.mode == "ir") ? "ir" : "c";

    if (lines_.empty()) {
        lines_.push_back(simpleline_t("/* Loading SPU pseudocode... */"));
    }
    simpleline_place_t s1;
    simpleline_place_t s2(static_cast<int>(lines_.size()) - 1);
    widget_ = create_custom_viewer(
        SPUDEC_VIEW_TITLE, &s1, &s2, &s1, nullptr, &lines_, &kVduiHandlers, this);
    return widget_;
}

void SpuVdui::restore_saved_window() {
    sync_with_disasm_ = idadb::get_sync_enabled();
    WindowState st = idadb::load_window_state();
    mode_ = (st.mode == "ir") ? "ir" : "c";

    // Check if ui_create_desktop_widget already instantiated the custom viewer
    TWidget *existing = find_widget(SPUDEC_VIEW_TITLE);
    if (existing != nullptr) {
        widget_ = existing;
        set_custom_viewer_handlers(widget_, &kVduiHandlers, this);
    } else if (!st.is_open) {
        return;
    }

    uint64_t target_ea = 0;
    if (st.func_ea.has_value() && is_loaded(static_cast<ea_t>(*st.func_ea))) {
        target_ea = *st.func_ea;
    } else {
        ea_t scr = get_screen_ea();
        if (scr != BADADDR) target_ea = static_cast<uint64_t>(scr);
    }
    if (target_ea == 0 && !is_loaded(0)) return;

    if (!widget_) {
        if (!ensure_widget_created(true, false)) return;
    }
    render_function(target_ea, std::nullopt, st.lineno, st.col, false);
}

void SpuVdui::persist_window_state(bool force_open_state) {
    bool open_flag = force_open_state ? (widget_ != nullptr) : false;
    int lineno = selected_line_;
    int col = 0;
    if (widget_ != nullptr) {
        get_cursor_pos(&lineno, &col, false);
    }
    idadb::save_window_state(open_flag, current_func_ea_, lineno, col, mode_, true);
}

void SpuVdui::close_and_cleanup() {
    highlighted_asm_eas_.clear();
    if (widget_ != nullptr) {
        TWidget *w = widget_;
        widget_ = nullptr;
        close_widget(w, WCLS_SAVE);
    }
    cfunc_.reset();
    ir_func_.reset();
    lines_.qclear();
}

void SpuVdui::on_widget_invisible(TWidget *w) {
    if (w != nullptr && w == listing_state().widget) {
        listing_state().widget = nullptr;
        listing_state().lines.qclear();
        return;
    }
    if (w != nullptr && w == widget_) {
        notify_event(spe_close_pseudocode, this);
        highlighted_asm_eas_.clear();
        widget_ = nullptr;
        if (!errorexit) {
            idadb::save_window_state(false, current_func_ea_, selected_line_, 0, mode_, true);
            refresh_idaview_anyway();
        }
    }
}

bool SpuVdui::open_or_focus(uint64_t target_ea, int open_flags, bool push_history) {
    sync_with_disasm_ = idadb::get_sync_enabled();
    func_t *pfn = get_func(static_cast<ea_t>(target_ea));
    uint64_t func_ea = pfn ? static_cast<uint64_t>(pfn->start_ea) : target_ea;

    const bool was_open = (widget_ != nullptr && find_widget(SPUDEC_VIEW_TITLE) == widget_);
    const bool activate = (open_flags >= 0);

    if (push_history && was_open && current_func_ea_.has_value()) {
        push_current_nav();
        nav_forward_.clear();
    }

    if (!ensure_widget_created(!was_open, activate)) {
        return false;
    }

    bool ok = render_function(func_ea, target_ea, -1, 0, false);
    if (ok) {
        persist_window_state(true);
    }
    return ok;
}

bool SpuVdui::switch_to(uint64_t target_ea, bool push_history) {
    func_t *pfn = get_func(static_cast<ea_t>(target_ea));
    if (!pfn) {
        // Target is data or non-function code: jump in IDA disassembly view!
        if (push_history && current_func_ea_.has_value()) {
            push_current_nav();
            nav_forward_.clear();
        }
        jumpto(static_cast<ea_t>(target_ea), -1, UIJMP_IDAVIEW | UIJMP_ACTIVATE);
        return true;
    }
    uint64_t new_func_ea = static_cast<uint64_t>(pfn->start_ea);
    if (push_history && current_func_ea_.has_value()) {
        push_current_nav();
        nav_forward_.clear();
    }
    bool switched_func = (!current_func_ea_.has_value() || *current_func_ea_ != new_func_ea);
    bool ok = render_function(new_func_ea, target_ea, -1, 0, false);
    if (ok && switched_func) {
        notify_event(spe_switch_pseudocode, this);
    }
    return ok;
}

bool SpuVdui::refresh_view(bool force_redecompile) {
    if (!current_func_ea_.has_value()) return false;
    int lineno = selected_line_;
    int col = 0;
    get_cursor_pos(&lineno, &col, false);
    if (force_redecompile) {
        global_summary_cache().invalidate_func(*current_func_ea_);
    }
    bool ok = render_function(*current_func_ea_, std::nullopt, lineno, col, force_redecompile);
    if (ok) {
        notify_event(spe_refresh_pseudocode, this);
    }
    return ok;
}

bool SpuVdui::render_function(uint64_t func_ea,
                              std::optional<uint64_t> focus_ea,
                              int restore_line,
                              int restore_col,
                              bool force_redecompile) {
    SummaryCache &cache = global_summary_cache();
    IdaDatabaseProvider prov(&cache);
    prov.get_func_start(func_ea, &func_ea);

    ensure_spu_types();
    std::string err;

    if (mode_ == "ir") {
        DecompileOptions opts;
        opts.hide_casts = idadb::get_hide_casts();
        opts.user_data = idadb::get_func_data(func_ea);
        DecompileOutput out = decompile_function(prov, func_ea, opts);
        if (!out.ir_func || !out.cfunc) {
            warning("spudec: failed to lift 0x%llX: %s",
                    static_cast<unsigned long long>(func_ea),
                    out.error.empty() ? "unknown error" : out.error.c_str());
            return false;
        }
        ir_func_ = std::move(out.ir_func);
        cfunc_ = out.cfunc;
        cache.put_cached_cfunc(func_ea, cfunc_);
    } else {
        cfuncptr_t cf = decompile_or_get_cached(func_ea, force_redecompile, &err);
        if (!cf) {
            warning("spudec: failed to decompile 0x%llX: %s",
                    static_cast<unsigned long long>(func_ea),
                    err.empty() ? "unknown error" : err.c_str());
            return false;
        }
        cfunc_ = cf;
    }

    current_func_ea_ = func_ea;
    last_token_.clear();
    rebuild_strvec_from_current();

    int target_line = 0;
    if (restore_line >= 0 && restore_line < static_cast<int>(lines_.size())) {
        target_line = restore_line;
    } else if (focus_ea.has_value() && *focus_ea != func_ea && mode_ == "c" && cfunc_) {
        auto it = cfunc_->ea_to_line.find(*focus_ea);
        if (it != cfunc_->ea_to_line.end()) {
            target_line = it->second;
        } else {
            // Nearest preceding instruction EA in ea_to_line
            uint64_t best_ea = 0;
            int best_line = cfunc_->sig_line;
            for (const auto &kv : cfunc_->ea_to_line) {
                if (kv.first <= *focus_ea && kv.first >= best_ea) {
                    best_ea = kv.first;
                    best_line = kv.second;
                }
            }
            target_line = best_line;
        }
    } else if (mode_ == "c" && cfunc_) {
        target_line = cfunc_->sig_line;
    }

    target_line = std::max(0, std::min(target_line, static_cast<int>(lines_.size()) - 1));
    selected_line_ = target_line;

    highlighted_asm_eas_.clear();
    if (mode_ == "c" && cfunc_) {
        auto it = cfunc_->line_to_eas.find(selected_line_);
        if (it != cfunc_->line_to_eas.end()) {
            highlighted_asm_eas_.insert(it->second.begin(), it->second.end());
        }
    } else if (selected_line_ >= 0 && selected_line_ < static_cast<int>(view_line_eas_.size()) &&
               view_line_eas_[selected_line_].has_value()) {
        highlighted_asm_eas_.insert(*view_line_eas_[selected_line_]);
    }

    update_viewer_bounds_and_cursor(target_line, std::max(0, restore_col));
    refresh_idaview_anyway();
    return true;
}

void SpuVdui::rebuild_strvec_from_current() {
    lines_.qclear();
    plain_lines_.clear();
    view_line_eas_.clear();

    if (mode_ == "ir" && ir_func_) {
        std::string ir_text = ir_func_->dump();
        std::istringstream iss(ir_text);
        std::string ln;
        std::optional<uint64_t> cur_ea = ir_func_->start_ea;
        while (std::getline(iss, ln)) {
            if (!ln.empty() && ln.back() == '\r') ln.pop_back();
            // Extract `@0xXXXXX` or `[0xXXXXX..` EA annotations on IR lines
            size_t at_pos = ln.find("@0x");
            if (at_pos == std::string::npos) at_pos = ln.find("[0x");
            if (at_pos != std::string::npos) {
                char *endp = nullptr;
                unsigned long long v = std::strtoull(ln.c_str() + at_pos + 3, &endp, 16);
                if (endp > ln.c_str() + at_pos + 3) cur_ea = static_cast<uint64_t>(v);
            }
            plain_lines_.push_back(ln);
            view_line_eas_.push_back(cur_ea);
            std::string col = highlight::colorize(ln, last_token_);
            lines_.push_back(simpleline_t(col.c_str()));
        }
    } else if (cfunc_) {
        if (cfunc_->has_tree_mutations()) {
            cfunc_->refresh_func_ctext();
        }
        cfunc_->recolorize(last_token_);
        plain_lines_ = cfunc_->pseudocode_lines;
        view_line_eas_ = cfunc_->line_eas;
        lines_.reserve(cfunc_->sv.size());
        for (const auto &s : cfunc_->sv) {
            lines_.push_back(simpleline_t(s.c_str()));
        }
    }

    if (lines_.empty()) {
        plain_lines_.push_back("/* Empty */");
        view_line_eas_.push_back(std::nullopt);
        lines_.push_back(simpleline_t("/* Empty */"));
    }
}

void SpuVdui::update_viewer_bounds_and_cursor(int target_line, int target_col) {
    if (!widget_ || lines_.empty()) return;
    sync_lock_ = true;
    simpleline_place_t s1(0);
    simpleline_place_t s2(static_cast<int>(lines_.size()) - 1);
    set_custom_viewer_range(widget_, &s1, &s2);

    int clamped = std::max(0, std::min(target_line, static_cast<int>(lines_.size()) - 1));
    simpleline_place_t cur(clamped);
    jumpto(widget_, &cur, target_col, -1);
    refresh_custom_viewer(widget_);
    sync_lock_ = false;
}

bool SpuVdui::get_cursor_pos(int *out_lineno, int *out_col, bool mouse) const {
    if (!widget_) return false;
    int x = 0, y = 0;
    place_t *pl = get_custom_viewer_place(widget_, mouse, &x, &y);
    if (!pl) return false;
    auto *spl = static_cast<simpleline_place_t *>(pl);
    if (out_lineno) *out_lineno = static_cast<int>(spl->n);
    if (out_col) *out_col = std::max(0, x);
    return true;
}

std::string SpuVdui::get_current_word(bool mouse) const {
    int lineno = 0, col = 0;
    if (!get_cursor_pos(&lineno, &col, mouse)) return {};
    if (lineno < 0 || lineno >= static_cast<int>(plain_lines_.size())) return {};
    std::string w = highlight::extract_word_at(plain_lines_[lineno], col);
    // Strip structure member dot/arrow prefix when user clicks on identifier right after `.` or `->`
    size_t dot = w.rfind('.');
    if (dot != std::string::npos && dot + 1 < w.size()) {
        // Determine whether cursor is before or after the dot
        const std::string &ln = plain_lines_[lineno];
        size_t pos_in_line = ln.find(w);
        if (pos_in_line != std::string::npos && col > static_cast<int>(pos_in_line + dot)) {
            return w.substr(dot + 1);
        }
        return w.substr(0, dot);
    }
    return w;
}

citem_t *SpuVdui::get_current_citem(bool mouse) const {
    if (!cfunc_ || mode_ != "c") return nullptr;
    int lineno = 0, col = 0;
    if (!get_cursor_pos(&lineno, &col, mouse)) return nullptr;

    // 1. Check COLOR_ADDR anchor at exact column on tagged line
    if (lineno >= 0 && lineno < static_cast<int>(cfunc_->sv.size())) {
        auto anchor = highlight::extract_addr_anchor_at(cfunc_->sv[lineno], col);
        if (anchor.has_value()) {
            uint32_t idx = static_cast<uint32_t>(*anchor & 0xFFFFFFFFULL);
            if (citem_t *it = cfunc_->get_item(idx)) return it;
        }
    }
    // 2. Check constant span at cursor
    const LineConstSpan *sp = find_const_at_cursor(nullptr, mouse);
    if (sp && sp->citem_id < cfunc_->treeitems.size()) {
        return cfunc_->get_item(sp->citem_id);
    }
    // 3. Fallback to statement cinsn_t via line EA
    if (lineno >= 0 && lineno < static_cast<int>(cfunc_->line_eas.size()) &&
        cfunc_->line_eas[lineno].has_value()) {
        auto it = cfunc_->eamap.find(*cfunc_->line_eas[lineno]);
        if (it != cfunc_->eamap.end() && !it->second.empty()) {
            return it->second.front();
        }
    }
    return cfunc_->body;
}

std::optional<uint64_t> SpuVdui::get_current_line_ea(bool mouse) const {
    int lineno = 0, col = 0;
    if (!get_cursor_pos(&lineno, &col, mouse)) return current_func_ea_;
    if (lineno >= 0 && lineno < static_cast<int>(view_line_eas_.size()) &&
        view_line_eas_[lineno].has_value()) {
        return view_line_eas_[lineno];
    }
    return current_func_ea_;
}

const LineConstSpan *SpuVdui::find_const_at_cursor(int *out_lineno, bool mouse) const {
    if (!cfunc_ || mode_ != "c") return nullptr;
    int lineno = 0, col = 0;
    if (!get_cursor_pos(&lineno, &col, mouse)) return nullptr;
    if (out_lineno) *out_lineno = lineno;

    auto it = cfunc_->line_consts.find(lineno);
    if (it == cfunc_->line_consts.end() || it->second.empty()) return nullptr;

    const auto &vec = it->second;
    // Exact column hit
    for (const auto &sp : vec) {
        if (col >= sp.col_start && col <= sp.col_end) {
            return &sp;
        }
    }
    // Single constant on the line -> forgiving match anywhere on the line!
    if (vec.size() == 1) {
        return &vec.front();
    }
    // Nearest constant on the line
    const LineConstSpan *best = &vec.front();
    int best_dist = 1000000;
    for (const auto &sp : vec) {
        int dist = (col < sp.col_start) ? (sp.col_start - col) : (col - sp.col_end);
        if (dist < best_dist) {
            best_dist = dist;
            best = &sp;
        }
    }
    return best;
}

void SpuVdui::update_token_highlight(const std::string &word) {
    if (!widget_ || word == last_token_) return;
    last_token_ = word;
    if (mode_ == "c" && cfunc_) {
        cfunc_->recolorize(last_token_);
        const size_t n = std::min(lines_.size(), cfunc_->sv.size());
        for (size_t i = 0; i < n; ++i) {
            lines_[i].line = cfunc_->sv[i].c_str();
        }
    } else {
        const size_t n = std::min(lines_.size(), plain_lines_.size());
        for (size_t i = 0; i < n; ++i) {
            std::string col = highlight::colorize(plain_lines_[i], last_token_);
            lines_[i].line = col.c_str();
        }
    }
    refresh_custom_viewer(widget_);
}

void SpuVdui::sync_cursor_to_disasm(int lineno, bool push_history) {
    bool line_changed = (lineno != selected_line_);
    selected_line_ = lineno;

    std::unordered_set<uint64_t> next_eas;
    std::optional<uint64_t> primary_ea;

    if (mode_ == "c" && cfunc_) {
        auto it = cfunc_->line_to_eas.find(lineno);
        if (it != cfunc_->line_to_eas.end() && !it->second.empty()) {
            next_eas.insert(it->second.begin(), it->second.end());
            primary_ea = it->second.front();
        } else if (lineno >= 0 && lineno < static_cast<int>(cfunc_->line_eas.size())) {
            primary_ea = cfunc_->line_eas[lineno];
            if (primary_ea.has_value()) next_eas.insert(*primary_ea);
        }
    } else if (lineno >= 0 && lineno < static_cast<int>(view_line_eas_.size())) {
        primary_ea = view_line_eas_[lineno];
        if (primary_ea.has_value()) next_eas.insert(*primary_ea);
    }

    bool eas_changed = (next_eas != highlighted_asm_eas_);
    highlighted_asm_eas_ = std::move(next_eas);

    if (line_changed && widget_) {
        refresh_custom_viewer(widget_);
    }

    if (!sync_with_disasm_) return;

    if (primary_ea.has_value() && is_loaded(static_cast<ea_t>(*primary_ea))) {
        sync_lock_ = true;
        int flags = UIJMP_IDAVIEW;
        if (!push_history) flags |= UIJMP_DONTPUSH;
        jumpto(static_cast<ea_t>(*primary_ea), -1, flags);
        sync_lock_ = false;
    }
    if (eas_changed) {
        refresh_idaview_anyway();
    }
}

void SpuVdui::handle_curpos() {
    if (sync_lock_ || !widget_) return;
    int lineno = 0, col = 0;
    if (!get_cursor_pos(&lineno, &col, false)) return;
    std::string word = get_current_word(false);
    update_token_highlight(word);
    sync_cursor_to_disasm(lineno, false);
    notify_event(spe_curpos, this);
}

void SpuVdui::handle_click(int) {
    if (sync_lock_ || !widget_) return;
    std::string word = get_current_word(false);
    update_token_highlight(word);
}

bool SpuVdui::handle_dblclick(int) {
    if (!widget_) return false;
    notify_event(spe_double_click, this);

    std::string word = get_current_word(false);
    if (word.empty()) return false;

    if (cfunc_) {
        // 1. Direct callee jump
        auto cit = cfunc_->call_eas.find(word);
        if (cit != cfunc_->call_eas.end() && is_loaded(static_cast<ea_t>(cit->second))) {
            return switch_to(cit->second, true);
        }
        // 2. Global symbol jump
        auto sit = cfunc_->sym_eas.find(word);
        if (sit != cfunc_->sym_eas.end() && is_loaded(static_cast<ea_t>(sit->second))) {
            return switch_to(sit->second, true);
        }
    }

    // 3. Label jump (`loc_XXXX`) within current function
    if (word.rfind("loc_", 0) == 0 && word.size() > 4) {
        char *endp = nullptr;
        unsigned long long target = std::strtoull(word.c_str() + 4, &endp, 16);
        if (endp && *endp == '\0' && cfunc_) {
            std::string label_decl = word + ":";
            for (size_t i = 0; i < plain_lines_.size(); ++i) {
                if (trim_copy(plain_lines_[i]).rfind(label_decl, 0) == 0) {
                    push_current_nav();
                    nav_forward_.clear();
                    selected_line_ = static_cast<int>(i);
                    update_viewer_bounds_and_cursor(selected_line_, 0);
                    sync_cursor_to_disasm(selected_line_, false);
                    return true;
                }
            }
            if (is_loaded(static_cast<ea_t>(target))) {
                return switch_to(static_cast<uint64_t>(target), true);
            }
        }
    }

    // 4. sub_XXXX or 0xXXXX literal address jump
    if (word.rfind("sub_", 0) == 0 || word.rfind("0x", 0) == 0 || word.rfind("0X", 0) == 0) {
        const char *hex_start = (word[0] == 's') ? (word.c_str() + 4) : (word.c_str() + 2);
        char *endp = nullptr;
        unsigned long long target = std::strtoull(hex_start, &endp, 16);
        if (endp > hex_start && is_loaded(static_cast<ea_t>(target))) {
            return switch_to(static_cast<uint64_t>(target), true);
        }
    }

    // 5. Named IDA symbol fallback
    ea_t nea = get_name_ea(current_func_ea_.value_or(0), word.c_str());
    if (nea != BADADDR && is_loaded(nea)) {
        return switch_to(static_cast<uint64_t>(nea), true);
    }

    return false;
}

bool SpuVdui::handle_keyboard(int key, int shift) {
    notify_event(spe_keyboard, this, &key);
    // Esc -> Navigate Back (if history non-empty) or let Esc close/ignore cleanly without losing dock
    if (key == IK_ESCAPE && shift == 0) {
        if (!nav_history_.empty()) {
            act_nav_back();
            return true;
        }
    }
    return false;
}

void SpuVdui::on_screen_ea_changed(ea_t ea, ea_t) {
    if (sync_lock_ || in_nav_action_ || !sync_with_disasm_ || !widget_ || ea == BADADDR) return;
    // Ignore if our own pseudocode viewer currently holds focus
    if (get_current_widget() == widget_) return;

    func_t *pfn = get_func(ea);
    if (!pfn) return;
    uint64_t fea = static_cast<uint64_t>(pfn->start_ea);

    if (!current_func_ea_.has_value() || *current_func_ea_ != fea) {
        if (current_func_ea_.has_value()) {
            push_current_nav();
            nav_forward_.clear();
        }
        render_function(fea, static_cast<uint64_t>(ea), -1, 0, false);
        notify_event(spe_switch_pseudocode, this);
        return;
    }

    if (mode_ == "c" && cfunc_) {
        auto it = cfunc_->ea_to_line.find(static_cast<uint64_t>(ea));
        if (it != cfunc_->ea_to_line.end() && it->second != selected_line_) {
            selected_line_ = it->second;
            highlighted_asm_eas_.clear();
            auto eit = cfunc_->line_to_eas.find(selected_line_);
            if (eit != cfunc_->line_to_eas.end()) {
                highlighted_asm_eas_.insert(eit->second.begin(), eit->second.end());
            }
            update_viewer_bounds_and_cursor(selected_line_, 0);
            refresh_idaview_anyway();
        }
    }
}

void SpuVdui::push_current_nav() {
    if (!current_func_ea_.has_value()) return;
    int lineno = selected_line_;
    int col = 0;
    get_cursor_pos(&lineno, &col, false);
    NavEntry e;
    e.func_ea = *current_func_ea_;
    e.ea = get_current_line_ea(false).value_or(*current_func_ea_);
    e.lineno = lineno;
    e.col = col;
    if (nav_history_.empty() ||
        nav_history_.back().func_ea != e.func_ea ||
        nav_history_.back().lineno != e.lineno) {
        nav_history_.push_back(e);
        if (nav_history_.size() > 128) {
            nav_history_.erase(nav_history_.begin());
        }
    }
}

bool SpuVdui::get_hint(TWidget *viewer, place_t *place, qstring &out_hint, int *important_lines) {
    if (viewer != widget_ || !place || !cfunc_ || mode_ != "c") return false;
    auto *spl = static_cast<simpleline_place_t *>(place);
    int lineno = static_cast<int>(spl->n);
    if (lineno < 0 || lineno >= static_cast<int>(plain_lines_.size())) return false;

    int col = 0;
    int mouse_line = 0;
    if (get_cursor_pos(&mouse_line, &col, true) && mouse_line == lineno) {
        std::string word = highlight::extract_word_at(plain_lines_[lineno], col);
        if (!word.empty()) {
            for (const auto &lv : cfunc_->lvars) {
                if (lv.name == word) {
                    out_hint.cat_sprnt("%s %s  /* %s */\n",
                                       lv.type_str.c_str(),
                                       lv.name.c_str(),
                                       lv.location.to_key().c_str());
                    if (important_lines) *important_lines += 1;
                    return true;
                }
            }
            auto cit = cfunc_->call_eas.find(word);
            if (cit != cfunc_->call_eas.end()) {
                IdaDatabaseProvider prov(&global_summary_cache());
                auto p = prov.get_ida_func_proto(cit->second);
                out_hint.cat_sprnt("callee 0x%05llX: %s\n",
                                   static_cast<unsigned long long>(cit->second),
                                   p.has_value() ? p->c_str() : word.c_str());
                if (important_lines) *important_lines += 1;
                return true;
            }
            auto sit = cfunc_->sym_eas.find(word);
            if (sit != cfunc_->sym_eas.end()) {
                out_hint.cat_sprnt("symbol %s @ 0x%05llX\n",
                                   word.c_str(),
                                   static_cast<unsigned long long>(sit->second));
                if (important_lines) *important_lines += 1;
                return true;
            }
        }
        auto cit_consts = cfunc_->line_consts.find(lineno);
        if (cit_consts != cfunc_->line_consts.end()) {
            for (const auto &sp : cit_consts->second) {
                if (col >= sp.col_start && col <= sp.col_end) {
                    int64_t sval = static_cast<int64_t>(sp.val);
                    if (sp.bits == 32) sval = static_cast<int32_t>(static_cast<uint32_t>(sp.val));
                    else if (sp.bits == 16) sval = static_cast<int16_t>(static_cast<uint16_t>(sp.val));
                    else if (sp.bits == 8) sval = static_cast<int8_t>(static_cast<uint8_t>(sp.val));
                    out_hint.cat_sprnt("hex: 0x%llX | udec: %llu | sdec: %lld\n",
                                       static_cast<unsigned long long>(sp.val),
                                       static_cast<unsigned long long>(sp.val),
                                       static_cast<long long>(sval));
                    if (important_lines) *important_lines += 1;
                    return true;
                }
            }
        }
    }
    return false;
}

void SpuVdui::get_lines_rendering_info(lines_rendering_output_t *out,
                                       const TWidget *viewer,
                                       const lines_rendering_input_t *info) const {
    if (!out || !viewer || !info || !widget_) return;

    if (viewer == widget_) {
        for (const auto &sec : info->sections_lines) {
            for (const twinline_t *twl : sec) {
                if (!twl || !twl->at) continue;
                const auto *spl = static_cast<const simpleline_place_t *>(twl->at);
                if (static_cast<int>(spl->n) == selected_line_) {
                    out->entries.push_back(
                        new line_rendering_output_entry_t(twl, LROEF_FULL_LINE, CK_EXTRA1));
                }
            }
        }
        return;
    }

    if (sync_with_disasm_ && !highlighted_asm_eas_.empty() &&
        get_widget_type(const_cast<TWidget *>(viewer)) == BWN_DISASM) {
        for (const auto &sec : info->sections_lines) {
            for (const twinline_t *twl : sec) {
                if (!twl || !twl->at) continue;
                ea_t line_ea = twl->at->toea();
                if (line_ea != BADADDR &&
                    highlighted_asm_eas_.count(static_cast<uint64_t>(line_ea)) > 0) {
                    out->entries.push_back(
                        new line_rendering_output_entry_t(twl, LROEF_FULL_LINE, CK_EXTRA1));
                }
            }
        }
    }
}

void SpuVdui::populate_popup(TWidget *w, TPopupMenu *popup) {
    if (!w || !popup) return;
    if (w == widget_) {
        notify_event(spe_populating_popup, this, popup);
        // Group 1: Annotations (Rename, Set Type, Comments)
        attach_action_to_popup(w, popup, ACTION_RENAME, nullptr, SETMENU_APP);
        attach_action_to_popup(w, popup, ACTION_SET_TYPE, nullptr, SETMENU_APP);
        attach_action_to_popup(w, popup, ACTION_EDIT_CMT, nullptr, SETMENU_APP);

        // Group 2: Constant / Number representations (submenu)
        const char *num_sub = "Number format/";
        attach_action_to_popup(w, popup, ACTION_TOGGLE_HEX, num_sub, SETMENU_APP | SETMENU_ENSURE_SEP);
        attach_action_to_popup(w, popup, ACTION_TOGGLE_CHAR, num_sub, SETMENU_APP);
        attach_action_to_popup(w, popup, ACTION_MAKE_ASCII, num_sub, SETMENU_APP);
        attach_action_to_popup(w, popup, ACTION_TOGGLE_BIN, num_sub, SETMENU_APP);
        attach_action_to_popup(w, popup, ACTION_TOGGLE_SIGNED, num_sub, SETMENU_APP);
        attach_action_to_popup(w, popup, ACTION_TOGGLE_INV, num_sub, SETMENU_APP);
        attach_action_to_popup(w, popup, ACTION_TOGGLE_OFFSET, num_sub, SETMENU_APP);
        attach_action_to_popup(w, popup, ACTION_SET_ENUM, num_sub, SETMENU_APP);

        // Group 3: Structure & Cast presentation
        attach_action_to_popup(w, popup, ACTION_INVERT_IF, nullptr, SETMENU_APP | SETMENU_ENSURE_SEP);
        attach_action_to_popup(w, popup, ACTION_TOGGLE_CASTS, nullptr, SETMENU_APP);

        // Group 4: Navigation & Cross-references
        attach_action_to_popup(w, popup, ACTION_SHOW_XREFS, nullptr, SETMENU_APP | SETMENU_ENSURE_SEP);
        attach_action_to_popup(w, popup, ACTION_JUMP_ADDR, nullptr, SETMENU_APP);
        attach_action_to_popup(w, popup, ACTION_JUMP_DISASM, nullptr, SETMENU_APP);
        attach_action_to_popup(w, popup, ACTION_SWITCH_DISASM, nullptr, SETMENU_APP);
        attach_action_to_popup(w, popup, ACTION_NAV_BACK, nullptr, SETMENU_APP);
        attach_action_to_popup(w, popup, ACTION_NAV_FORWARD, nullptr, SETMENU_APP);

        // Group 5: View controls
        attach_action_to_popup(w, popup, ACTION_TOGGLE_SYNC, nullptr, SETMENU_APP | SETMENU_ENSURE_SEP);
        attach_action_to_popup(w, popup, ACTION_TOGGLE_IR, nullptr, SETMENU_APP);
        attach_action_to_popup(w, popup, ACTION_REFRESH, nullptr, SETMENU_APP);
        attach_action_to_popup(w, popup, ACTION_RESET_OVERRIDES, nullptr, SETMENU_APP);
        return;
    }

    if (get_widget_type(w) == BWN_DISASM) {
        attach_action_to_popup(w, popup, ACTION_DECOMPILE, nullptr, SETMENU_APP | SETMENU_ENSURE_SEP);
    }
}

// ---------------------------------------------------------------------------
// 24 Interactive Actions Implementation
// ---------------------------------------------------------------------------

int SpuVdui::act_rename() {
    if (!current_func_ea_.has_value() || !cfunc_ || mode_ != "c") return 0;
    const uint64_t fea = *current_func_ea_;
    int lineno = 0, col = 0;
    get_cursor_pos(&lineno, &col, false);

    std::string word = get_current_word(false);
    if (word.empty() && lineno == cfunc_->sig_line) {
        word = cfunc_->func_name;
    }
    if (word.empty()) return 0;

    // 1. Local variable rename
    for (const auto &lv : cfunc_->lvars) {
        if (lv.name == word || lv.canonical_name == word) {
            qstring new_qstr(lv.name.c_str());
            if (!ask_str(&new_qstr, HIST_IDENT2,
                         "Rename local variable '%s' (empty to restore default):",
                         lv.name.c_str())) {
                return 0;
            }
            std::string next = trim_copy(new_qstr.c_str());
            if (!next.empty() && !is_valid_c_ident(next)) {
                warning("'%s' is not a valid C identifier.", next.c_str());
                return 0;
            }
            idadb::set_var_rename(fea, lv.canonical_name, next);
            idadb::set_var_locator(fea, lv.location.to_key(), next, std::nullopt);
            refresh_view(true);
            return 1;
        }
    }

    // 2. Current function or callee rename
    std::optional<uint64_t> target_ea;
    if (word == cfunc_->func_name) {
        target_ea = fea;
    } else {
        auto cit = cfunc_->call_eas.find(word);
        if (cit != cfunc_->call_eas.end()) target_ea = cit->second;
    }
    if (!target_ea.has_value()) {
        auto sit = cfunc_->sym_eas.find(word);
        if (sit != cfunc_->sym_eas.end()) target_ea = sit->second;
    }
    if (!target_ea.has_value() && word.rfind("loc_", 0) == 0 && word.size() > 4) {
        char *endp = nullptr;
        unsigned long long v = std::strtoull(word.c_str() + 4, &endp, 16);
        if (endp && *endp == '\0') target_ea = static_cast<uint64_t>(v);
    }

    if (target_ea.has_value() && is_loaded(static_cast<ea_t>(*target_ea))) {
        qstring cur_name;
        get_name(&cur_name, static_cast<ea_t>(*target_ea));
        if (cur_name.empty()) cur_name = word.c_str();
        if (!ask_str(&cur_name, HIST_IDENT, "Rename symbol at 0x%05llX:",
                     static_cast<unsigned long long>(*target_ea))) {
            return 0;
        }
        int sn_flags = SN_CHECK | SN_NOWARN;
        if (word.rfind("loc_", 0) == 0) sn_flags |= SN_LOCAL;
        if (!set_name(static_cast<ea_t>(*target_ea), cur_name.c_str(), sn_flags)) {
            warning("IDA rejected symbol name '%s'.", cur_name.c_str());
            return 0;
        }
        global_summary_cache().invalidate_names_and_symbols();
        refresh_view(true);
        return 1;
    }

    return 0;
}

int SpuVdui::act_set_type() {
    if (!current_func_ea_.has_value() || !cfunc_ || mode_ != "c") return 0;
    const uint64_t fea = *current_func_ea_;
    int lineno = 0, col = 0;
    get_cursor_pos(&lineno, &col, false);
    std::string word = get_current_word(false);

    // 1. Local variable type override (takes priority even on sig_line if cursor is on a parameter name!)
    for (const auto &lv : cfunc_->lvars) {
        if (lv.name == word) {
            qstring type_qstr(lv.type_str.c_str());
            if (!ask_str(&type_qstr, HIST_TYPE,
                         "Set C type for variable '%s' (empty to restore inferred type):",
                         lv.name.c_str())) {
                return 0;
            }
            std::string next_type = trim_copy(type_qstr.c_str());
            while (!next_type.empty() && next_type.back() == ';') next_type.pop_back();
            next_type = trim_copy(next_type);

            if (!next_type.empty() && !is_builtin_spudec_type(next_type)) {
                tinfo_t tif;
                IdaDatabaseProvider prov(&global_summary_cache());
                if (!parse_c_type_tinfo(next_type, &tif) && !prov.get_udt_info(next_type).has_value()) {
                    warning("Could not parse C type '%s'. Ensure custom structs are defined in Local Types.",
                            next_type.c_str());
                    return 0;
                }
            }
            idadb::set_var_type(fea, lv.canonical_name, next_type);
            idadb::set_var_locator(fea, lv.location.to_key(), std::nullopt, next_type);
            refresh_view(true);
            return 1;
        }
    }

    // 2. Function prototype override (current function on signature line, or callee under cursor)
    std::optional<uint64_t> proto_ea;
    if (lineno == cfunc_->sig_line || word == cfunc_->func_name) {
        proto_ea = fea;
    } else if (!word.empty()) {
        auto cit = cfunc_->call_eas.find(word);
        if (cit != cfunc_->call_eas.end()) proto_ea = cit->second;
    }

    if (proto_ea.has_value()) {
        IdaDatabaseProvider prov(&global_summary_cache());
        FuncUserData ud = idadb::get_func_data(*proto_ea);
        std::string cur_proto;
        if (ud.proto.has_value() && !ud.proto->empty()) {
            cur_proto = *ud.proto;
        } else if (auto ip = prov.get_ida_func_proto(*proto_ea); ip.has_value()) {
            cur_proto = *ip;
        } else if (*proto_ea == fea) {
            cur_proto = cfunc_->signature_line + ";";
        } else {
            cur_proto = "int " + word + "(void);";
        }

        qstring proto_qstr(cur_proto.c_str());
        if (!ask_str(&proto_qstr, HIST_TYPE,
                     "Set C function prototype for 0x%05llX (empty to reset):",
                     static_cast<unsigned long long>(*proto_ea))) {
            return 0;
        }
        std::string next_proto = trim_copy(proto_qstr.c_str());
        if (next_proto.empty()) {
            idadb::set_func_proto(*proto_ea, "");
            del_tinfo(static_cast<ea_t>(*proto_ea));
            global_summary_cache().clear_arity_and_demand();
            global_summary_cache().invalidate_func(*proto_ea);
            refresh_view(true);
            return 1;
        }

        auto parsed = abi::parse_proto(next_proto);
        if (!parsed.has_value()) {
            warning("Invalid C function prototype:\n%s", next_proto.c_str());
            return 0;
        }
        idadb::set_func_proto(*proto_ea, next_proto);
        apply_proto_to_ida(static_cast<ea_t>(*proto_ea), next_proto);
        global_summary_cache().clear_arity_and_demand();
        global_summary_cache().invalidate_func(*proto_ea);
        refresh_view(true);
        return 1;
    }

    // 3. Global data symbol type override
    if (!word.empty()) {
        auto sit = cfunc_->sym_eas.find(word);
        if (sit != cfunc_->sym_eas.end()) {
            ea_t sea = static_cast<ea_t>(sit->second);
            tinfo_t cur_tif;
            qstring def_str;
            if (get_tinfo(&cur_tif, sea)) cur_tif.print(&def_str);
            if (!ask_str(&def_str, HIST_TYPE, "Set C type for global '%s' (0x%05llX):",
                         word.c_str(), static_cast<unsigned long long>(sit->second))) {
                return 0;
            }
            std::string next_t = trim_copy(def_str.c_str());
            if (next_t.empty()) {
                del_tinfo(sea);
            } else {
                tinfo_t new_tif;
                if (!parse_c_type_tinfo(next_t, &new_tif)) {
                    warning("IDA could not parse type '%s'.", next_t.c_str());
                    return 0;
                }
                apply_tinfo(sea, new_tif, TINFO_DEFINITE);
            }
            global_summary_cache().invalidate_types();
            refresh_view(true);
            return 1;
        }
    }

    return 0;
}

int SpuVdui::act_edit_comment() {
    if (!current_func_ea_.has_value() || mode_ != "c") return 0;
    const uint64_t fea = *current_func_ea_;
    uint64_t stmt_ea = get_current_line_ea(false).value_or(fea);

    std::string existing = idadb::get_statement_cmt(fea, stmt_ea).value_or("");
    qstring ans;
    if (!ask_text(&ans, 0, existing.c_str(),
                  "Enter pseudocode comment for 0x%05llX (empty to delete):",
                  static_cast<unsigned long long>(stmt_ea))) {
        return 0;
    }
    std::string trimmed = trim_copy(ans.c_str());
    idadb::set_statement_cmt(fea, stmt_ea, trimmed);
    refresh_view(true);
    return 1;
}

int SpuVdui::act_toggle_numform(const char *target_form) {
    if (!current_func_ea_.has_value() || !cfunc_ || mode_ != "c" || !target_form) return 0;
    const LineConstSpan *sp = find_const_at_cursor(nullptr, false);
    if (!sp) return 0;

    std::string cur_effective = sp->applied ? sp->form : sp->default_form;
    std::string next_form;
    if (std::strcmp(target_form, "hex") == 0) {
        next_form = (cur_effective == "hex") ? "dec" : "hex";
    } else {
        next_form = (cur_effective == target_form) ? "" : target_form;
    }

    idadb::set_numform(*current_func_ea_, sp->ea, sp->idx, next_form);
    refresh_view(true);
    return 1;
}

int SpuVdui::act_make_ascii() {
    if (!current_func_ea_.has_value() || !cfunc_ || mode_ != "c") return 0;
    const uint64_t fea = *current_func_ea_;
    const LineConstSpan *sp = find_const_at_cursor(nullptr, false);
    if (!sp) return 0;

    std::string cur_effective = sp->applied ? sp->form : sp->default_form;
    if (cur_effective == "str" || cur_effective == "chr_be" || cur_effective == "char") {
        idadb::set_numform(fea, sp->ea, sp->idx, "");
        refresh_view(true);
        return 1;
    }

    // 1. Check if constant is a Local Store pointer to printable ASCII bytes
    uint64_t cand_ea = sp->is_addr ? sp->addr_val : sp->val;
    if (cand_ea < 0x40000ULL && is_loaded(static_cast<ea_t>(cand_ea))) {
        uint8_t buf[128] = {};
        IdaDatabaseProvider prov(&global_summary_cache());
        size_t got = prov.read_bytes(cand_ea, buf, sizeof(buf));
        if (got >= 2 && looks_like_text_bytes(buf, got)) {
            create_strlit(static_cast<ea_t>(cand_ea), 0, STRTYPE_C);
            global_summary_cache().invalidate_names_and_symbols();
            idadb::set_numform(fea, sp->ea, sp->idx, "str");
            refresh_view(true);
            return 1;
        }
    }

    // 2. Check if constant packs big-endian printable ASCII characters (FourCC / 8B / 16B tag)
    if (is_packed_ascii_constant(sp->val, sp->val_hi, sp->bits)) {
        idadb::set_numform(fea, sp->ea, sp->idx, "chr_be");
        refresh_view(true);
        return 1;
    }

    // 3. Single printable byte -> char literal
    if (sp->val >= 0x20 && sp->val <= 0x7E) {
        idadb::set_numform(fea, sp->ea, sp->idx, "char");
        refresh_view(true);
        return 1;
    }

    msg("[spudec] Constant 0x%llX is neither a Local Store string address nor packed ASCII.\n",
        static_cast<unsigned long long>(sp->val));
    return 0;
}

int SpuVdui::act_toggle_offset() {
    if (!current_func_ea_.has_value() || !cfunc_ || mode_ != "c") return 0;
    const LineConstSpan *sp = find_const_at_cursor(nullptr, false);
    if (!sp) return 0;

    std::string cur_effective = sp->applied ? sp->form : sp->default_form;
    if (cur_effective == "off") {
        idadb::set_numform(*current_func_ea_, sp->ea, sp->idx, "");
    } else {
        uint64_t cand = sp->is_addr ? sp->addr_val : sp->val;
        if (!is_loaded(static_cast<ea_t>(cand))) {
            msg("[spudec] Value 0x%llX is not a loaded SPU Local Store address.\n",
                static_cast<unsigned long long>(cand));
            return 0;
        }
        idadb::set_numform(*current_func_ea_, sp->ea, sp->idx, "off");
    }
    refresh_view(true);
    return 1;
}

int SpuVdui::act_set_enum() {
    if (!current_func_ea_.has_value() || !cfunc_ || mode_ != "c") return 0;
    const LineConstSpan *sp = find_const_at_cursor(nullptr, false);
    if (!sp) return 0;

    std::string cur_effective = sp->applied ? sp->form : sp->default_form;
    if (cur_effective.rfind("enum:", 0) == 0) {
        idadb::set_numform(*current_func_ea_, sp->ea, sp->idx, "");
        refresh_view(true);
        return 1;
    }

    // Try IDA's built-in enum chooser first
    tinfo_t chosen_enum;
    uchar serial = 0;
    int nbytes = std::max(1, std::min(8, (sp->bits + 7) / 8));
    if (choose_enum_by_value(&chosen_enum, "Choose Symbolic Constant", 0, sp->val, nbytes, &serial)) {
        qstring mname;
        edm_t edm;
        ssize_t idx = chosen_enum.get_edm_by_value(&edm, sp->val, serial);
        if (idx >= 0 && !edm.name.empty()) {
            idadb::set_numform(*current_func_ea_, sp->ea, sp->idx, std::string("enum:") + edm.name.c_str());
            refresh_view(true);
            return 1;
        }
    }

    // Fallback: direct scan of all local enum types matching sp->val
    std::vector<std::string> matches = find_ida_enum_matches(sp->val);
    if (matches.empty()) {
        msg("[spudec] No enum constant matching 0x%llX found in Local Types.\n",
            static_cast<unsigned long long>(sp->val));
        return 0;
    }
    std::string selected = matches.front();
    if (matches.size() > 1) {
        EnumMatchChooser ch("Select Enum Member", matches);
        ssize_t sel = ch.choose(0);
        if (sel < 0 || static_cast<size_t>(sel) >= matches.size()) return 0;
        selected = matches[static_cast<size_t>(sel)];
    }
    idadb::set_numform(*current_func_ea_, sp->ea, sp->idx, "enum:" + selected);
    refresh_view(true);
    return 1;
}

std::optional<uint64_t> SpuVdui::find_enclosing_if_ea(int lineno) const {
    if (!cfunc_ || !cfunc_->body) return std::nullopt;
    // Check current line and scan upward a few lines if cursor is on `{` or `else`
    for (int probe = lineno; probe >= std::max(0, lineno - 4); --probe) {
        if (probe >= static_cast<int>(plain_lines_.size())) continue;
        std::string t = trim_copy(plain_lines_[probe]);
        bool looks_like_if_or_else =
            (t.rfind("if (", 0) == 0 || t.rfind("} else", 0) == 0 || t.rfind("else", 0) == 0 || probe == lineno);
        if (!looks_like_if_or_else) continue;

        if (probe < static_cast<int>(cfunc_->line_eas.size()) && cfunc_->line_eas[probe].has_value()) {
            uint64_t ea = *cfunc_->line_eas[probe];
            auto it = cfunc_->eamap.find(ea);
            if (it != cfunc_->eamap.end()) {
                for (cinsn_t *ins : it->second) {
                    if (ins && ins->op == cit_if && ins->ea != UINT64_MAX) {
                        return ins->ea;
                    }
                }
            }
        }
    }
    return std::nullopt;
}

int SpuVdui::act_invert_if() {
    if (!current_func_ea_.has_value() || !cfunc_ || mode_ != "c") return 0;
    int lineno = selected_line_;
    int col = 0;
    get_cursor_pos(&lineno, &col, false);

    auto if_ea = find_enclosing_if_ea(lineno);
    if (!if_ea.has_value()) {
        msg("[spudec] Place cursor on an 'if (...)' or 'else' statement to invert branches.\n");
        return 0;
    }
    idadb::toggle_iflag(*current_func_ea_, *if_ea);
    refresh_view(true);
    return 1;
}

int SpuVdui::act_toggle_casts() {
    bool next = !idadb::get_hide_casts();
    idadb::set_hide_casts(next);
    msg("[spudec] Scalar casts: %s\n", next ? "hidden" : "shown");
    refresh_view(true);
    return 1;
}

int SpuVdui::act_show_xrefs() {
    if (!current_func_ea_.has_value() || !cfunc_ || mode_ != "c") return 0;
    std::string word = get_current_word(false);
    int lineno = selected_line_;
    int col = 0;
    get_cursor_pos(&lineno, &col, false);
    if (word.empty() && lineno == cfunc_->sig_line) {
        word = cfunc_->func_name;
    }
    if (word.empty()) return 0;

    // 1. Local variable xrefs within current function
    for (const auto &lv : cfunc_->lvars) {
        if (lv.name == word) {
            std::vector<LocalXrefRow> rows;
            ssize_t def_sel = 0;
            for (size_t i = 0; i < plain_lines_.size(); ++i) {
                if (line_contains_ident(plain_lines_[i], word)) {
                    if (static_cast<int>(i) == lineno) def_sel = static_cast<ssize_t>(rows.size());
                    LocalXrefRow r;
                    r.lineno = static_cast<int>(i);
                    r.ea = (i < view_line_eas_.size() && view_line_eas_[i].has_value())
                               ? *view_line_eas_[i]
                               : UINT64_MAX;
                    r.text = trim_copy(plain_lines_[i]);
                    rows.push_back(std::move(r));
                }
            }
            if (rows.empty()) return 0;
            qstring title;
            title.sprnt("Local xrefs to '%s' in %s", word.c_str(), cfunc_->func_name.c_str());
            LocalXrefChooser ch(title.c_str(), std::move(rows));
            ssize_t sel = ch.choose(def_sel);
            if (sel >= 0 && static_cast<size_t>(sel) < ch.rows.size()) {
                int target_ln = ch.rows[static_cast<size_t>(sel)].lineno;
                selected_line_ = target_ln;
                update_viewer_bounds_and_cursor(target_ln, 0);
                sync_cursor_to_disasm(target_ln, false);
            }
            return 1;
        }
    }

    // 2. Global / Function / Callee xrefs in IDA
    std::optional<uint64_t> target_ea;
    if (word == cfunc_->func_name) {
        target_ea = *current_func_ea_;
    } else if (auto cit = cfunc_->call_eas.find(word); cit != cfunc_->call_eas.end()) {
        target_ea = cit->second;
    } else if (auto sit = cfunc_->sym_eas.find(word); sit != cfunc_->sym_eas.end()) {
        target_ea = sit->second;
    } else {
        ea_t nea = get_name_ea(*current_func_ea_, word.c_str());
        if (nea != BADADDR) target_ea = static_cast<uint64_t>(nea);
    }

    if (target_ea.has_value()) {
        ea_t xea = choose_xref(static_cast<ea_t>(*target_ea));
        if (xea != BADADDR) {
            switch_to(static_cast<uint64_t>(xea), true);
            return 1;
        }
    }
    return 0;
}

int SpuVdui::act_jump_addr() {
    ea_t dest = get_current_line_ea(false).value_or(current_func_ea_.value_or(0));
    if (!ask_addr(&dest, "Jump to function or address:")) return 0;
    if (dest == BADADDR || !is_loaded(dest)) return 0;
    switch_to(static_cast<uint64_t>(dest), true);
    return 1;
}

int SpuVdui::act_jump_disasm() {
    auto ea = get_current_line_ea(false);
    if (!ea.has_value()) return 0;
    jumpto(static_cast<ea_t>(*ea), -1, UIJMP_IDAVIEW | UIJMP_ACTIVATE);
    return 1;
}

int SpuVdui::act_switch_disasm() {
    auto ea = get_current_line_ea(false);
    if (ea.has_value() && is_loaded(static_cast<ea_t>(*ea))) {
        jumpto(static_cast<ea_t>(*ea), -1, UIJMP_IDAVIEW | UIJMP_ACTIVATE);
        return 1;
    }
    TWidget *dis = find_widget("IDA View-A");
    if (dis) {
        activate_widget(dis, true);
        return 1;
    }
    return 0;
}

int SpuVdui::act_nav_back() {
    if (nav_history_.empty()) return 0;
    in_nav_action_ = true;
    if (current_func_ea_.has_value()) {
        int ln = selected_line_, col = 0;
        get_cursor_pos(&ln, &col, false);
        nav_forward_.push_back({*current_func_ea_, get_current_line_ea(false).value_or(*current_func_ea_), ln, col});
    }
    NavEntry prev = nav_history_.back();
    nav_history_.pop_back();
    render_function(prev.func_ea, std::nullopt, prev.lineno, prev.col, false);
    sync_cursor_to_disasm(selected_line_, false);
    in_nav_action_ = false;
    return 1;
}

int SpuVdui::act_nav_forward() {
    if (nav_forward_.empty()) return 0;
    in_nav_action_ = true;
    push_current_nav();
    NavEntry next = nav_forward_.back();
    nav_forward_.pop_back();
    render_function(next.func_ea, std::nullopt, next.lineno, next.col, false);
    sync_cursor_to_disasm(selected_line_, false);
    in_nav_action_ = false;
    return 1;
}

int SpuVdui::act_toggle_sync() {
    sync_with_disasm_ = !sync_with_disasm_;
    idadb::set_sync_enabled(sync_with_disasm_);
    msg("[spudec] Cursor sync with disassembly: %s\n", sync_with_disasm_ ? "ON" : "OFF");
    refresh_idaview_anyway();
    return 1;
}

int SpuVdui::act_toggle_ir() {
    mode_ = (mode_ == "c") ? "ir" : "c";
    refresh_view(false);
    return 1;
}

int SpuVdui::act_refresh() {
    return refresh_view(true) ? 1 : 0;
}

int SpuVdui::act_reset_overrides() {
    if (!current_func_ea_.has_value()) return 0;
    if (ask_yn(ASKBTN_NO,
               "Reset all user variable names, types, comments, number formats, and branch inversions for 0x%05llX?",
               static_cast<unsigned long long>(*current_func_ea_)) != ASKBTN_YES) {
        return 0;
    }
    idadb::clear_func_overrides(*current_func_ea_);
    global_summary_cache().clear_arity_and_demand();
    refresh_view(true);
    return 1;
}

// ---------------------------------------------------------------------------
// Action Registration Table
// ---------------------------------------------------------------------------

namespace {

enum class ActId {
    Decompile,
    DecompileAll,
    ClearCaches,
    SaveListingC,
    Rename,
    SetType,
    EditCmt,
    EditCmtSemi,
    ToggleHex,
    ToggleChar,
    MakeAscii,
    ToggleBin,
    ToggleSigned,
    ToggleInv,
    ToggleOffset,
    SetEnum,
    InvertIf,
    ToggleCasts,
    ShowXrefs,
    JumpAddr,
    JumpDisasm,
    SwitchDisasm,
    NavBack,
    NavForward,
    ToggleSync,
    ToggleIr,
    Refresh,
    ResetOverrides,
};

struct SpudecActionHandler : public action_handler_t {
    ActId id;
    explicit SpudecActionHandler(ActId i) : id(i) {}

    int idaapi activate(action_activation_ctx_t *ctx) override {
        if (!is_spu_database_active()) return 0;
        SpuVdui &v = global_vdui();
        switch (id) {
            case ActId::Decompile: {
                if (v.widget() && ((ctx && ctx->widget == v.widget()) || get_current_widget() == v.widget())) {
                    return v.act_refresh();
                }
                ea_t ea = BADADDR;
                if (ctx && ctx->cur_ea != BADADDR) {
                    ea = ctx->cur_ea;
                }
                if (ea == BADADDR) {
                    ea = get_screen_ea();
                }
                if (ea == BADADDR && v.current_func_ea().has_value()) {
                    ea = static_cast<ea_t>(*v.current_func_ea());
                }
                if (ea == BADADDR) {
                    warning("spudec: place the cursor inside an SPU function before pressing F5.");
                    return 0;
                }
                return v.open_or_focus(static_cast<uint64_t>(ea), 1, true) ? 1 : 0;
            }
            case ActId::DecompileAll:
                return open_decompile_all_viewer() ? 1 : 0;
            case ActId::ClearCaches:
                global_summary_cache().clear_all();
                if (v.is_open()) v.refresh_view(true);
                msg("[spudec] Cleared all summary and pseudocode caches.\n");
                return 1;
            case ActId::SaveListingC:
                return act_save_listing_to_c_file();
            case ActId::Rename:        return v.act_rename();
            case ActId::SetType:       return v.act_set_type();
            case ActId::EditCmt:
            case ActId::EditCmtSemi:   return v.act_edit_comment();
            case ActId::ToggleHex:     return v.act_toggle_numform("hex");
            case ActId::ToggleChar:    return v.act_toggle_numform("char");
            case ActId::MakeAscii:     return v.act_make_ascii();
            case ActId::ToggleBin:     return v.act_toggle_numform("bin");
            case ActId::ToggleSigned:  return v.act_toggle_numform("sdec");
            case ActId::ToggleInv:     return v.act_toggle_numform("inv");
            case ActId::ToggleOffset:  return v.act_toggle_offset();
            case ActId::SetEnum:       return v.act_set_enum();
            case ActId::InvertIf:      return v.act_invert_if();
            case ActId::ToggleCasts:   return v.act_toggle_casts();
            case ActId::ShowXrefs:     return v.act_show_xrefs();
            case ActId::JumpAddr:      return v.act_jump_addr();
            case ActId::JumpDisasm:    return v.act_jump_disasm();
            case ActId::SwitchDisasm:  return v.act_switch_disasm();
            case ActId::NavBack:       return v.act_nav_back();
            case ActId::NavForward:    return v.act_nav_forward();
            case ActId::ToggleSync:    return v.act_toggle_sync();
            case ActId::ToggleIr:      return v.act_toggle_ir();
            case ActId::Refresh:       return v.act_refresh();
            case ActId::ResetOverrides:return v.act_reset_overrides();
        }
        return 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override {
        if (!ctx || !is_spu_database_active()) return AST_DISABLE_FOR_IDB;
        if (id == ActId::Decompile || id == ActId::DecompileAll || id == ActId::ClearCaches) {
            return AST_ENABLE_ALWAYS;
        }
        if (id == ActId::SaveListingC) {
            return (ctx->widget == listing_state().widget) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
        }
        return (ctx->widget == global_vdui().widget()) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
    }
};

struct ActionEntry {
    const char *name;
    const char *label;
    const char *shortcut;
    const char *tooltip;
    ActId id;
    SpudecActionHandler handler;

    ActionEntry(const char *n, const char *l, const char *sc, const char *tt, ActId i)
        : name(n), label(l), shortcut(sc), tooltip(tt), id(i), handler(i) {}
};

std::vector<ActionEntry> &action_table() {
    static std::vector<ActionEntry> tbl = {
        {ACTION_DECOMPILE,       "Decompile SPU function",         "F5",         "Generate Cell SPU C pseudocode", ActId::Decompile},
        {ACTION_DECOMPILE_ALL,   "Decompile all SPU functions",    "Ctrl-F5",    "Decompile all functions in binary", ActId::DecompileAll},
        {ACTION_CLEAR_CACHES,    "Clear spudec caches",            "Ctrl-Shift-S","Invalidate all cached summaries and pseudocode", ActId::ClearCaches},
        {ACTION_SAVE_LISTING_C,  "Save all pseudocode to .c file...", nullptr,   "Export all decompiled SPU C code", ActId::SaveListingC},

        {ACTION_RENAME,          "Rename variable / symbol...",    "N",          "Rename variable, function, or label", ActId::Rename},
        {ACTION_SET_TYPE,        "Set C type / prototype...",      "Y",          "Set variable C type or function prototype", ActId::SetType},
        {ACTION_EDIT_CMT,        "Edit comment...",                "/",          "Attach or edit pseudocode comment", ActId::EditCmt},
        {ACTION_EDIT_CMT_SEMI,   "Edit comment (;)",               ";",          "Attach or edit pseudocode comment", ActId::EditCmtSemi},

        {ACTION_TOGGLE_HEX,      "Hexadecimal / Decimal",          "H",          "Toggle hex / decimal representation", ActId::ToggleHex},
        {ACTION_TOGGLE_CHAR,     "Character constant",             "R",          "Toggle character literal representation", ActId::ToggleChar},
        {ACTION_MAKE_ASCII,      "ASCII string / FourCC",          "A",          "Create Local Store C string or packed ASCII tag", ActId::MakeAscii},
        {ACTION_TOGGLE_BIN,      "Binary literal",                 "B",          "Toggle binary literal representation", ActId::ToggleBin},
        {ACTION_TOGGLE_SIGNED,   "Signed / Unsigned decimal",      "Shift--",    "Toggle signed decimal representation", ActId::ToggleSigned},
        {ACTION_TOGGLE_INV,      "Bitwise negated (~x)",           "Shift-`",    "Toggle bitwise inverted constant", ActId::ToggleInv},
        {ACTION_TOGGLE_OFFSET,   "Local Store offset (&sym)",      "O",          "Toggle address/symbol offset representation", ActId::ToggleOffset},
        {ACTION_SET_ENUM,        "Symbolic constant (Enum)...",    "M",          "Format constant using an IDA enum member", ActId::SetEnum},

        {ACTION_INVERT_IF,       "Invert if/else branches",        "I",          "Negate condition and swap then/else blocks", ActId::InvertIf},
        {ACTION_TOGGLE_CASTS,    "Hide / Show scalar casts",       "\\",         "Toggle display of scalar casts", ActId::ToggleCasts},

        {ACTION_SHOW_XREFS,      "Jump to xrefs...",               "X",          "Show local or global cross-references", ActId::ShowXrefs},
        {ACTION_JUMP_ADDR,       "Jump to address...",             "G",          "Jump to SPU function or address", ActId::JumpAddr},
        {ACTION_JUMP_DISASM,     "Jump to disassembly",            nullptr,      "Focus matching instruction in IDA View", ActId::JumpDisasm},
        {ACTION_SWITCH_DISASM,   "Switch to disassembly",          "Tab",        "Toggle between pseudocode and IDA View", ActId::SwitchDisasm},
        {ACTION_NAV_BACK,        "Navigate backward",              "Escape",     "Return to previous pseudocode location", ActId::NavBack},
        {ACTION_NAV_FORWARD,     "Navigate forward",               "Ctrl-Return","Advance to next pseudocode location", ActId::NavForward},

        {ACTION_TOGGLE_SYNC,     "Sync cursor with disassembly",   "Alt-S",      "Toggle live disassembly synchronization", ActId::ToggleSync},
        {ACTION_TOGGLE_IR,       "Toggle C / SSA IR view",         "Shift-I",    "Switch between C pseudocode and lifted IR", ActId::ToggleIr},
        {ACTION_REFRESH,         "Refresh pseudocode",             nullptr,      "Re-run SPU decompilation pipeline", ActId::Refresh},
        {ACTION_RESET_OVERRIDES, "Reset function overrides",       nullptr,      "Clear all user overrides on current function", ActId::ResetOverrides},
    };
    return tbl;
}

} // namespace

void register_all_spudec_actions(plugmod_t *owner) {
    for (auto &entry : action_table()) {
        unregister_action(entry.name);
        action_desc_t desc = ACTION_DESC_LITERAL_PLUGMOD(
            entry.name,
            entry.label,
            &entry.handler,
            owner,
            entry.shortcut,
            entry.tooltip,
            -1);
        register_action(desc);
    }
    attach_action_to_menu("View/Open subviews/Generate pseudocode", ACTION_DECOMPILE, SETMENU_APP);
    attach_action_to_menu("View/Open subviews/", ACTION_DECOMPILE, SETMENU_APP);
    attach_action_to_menu("View/Open subviews/", ACTION_DECOMPILE_ALL, SETMENU_APP);
    update_action_shortcut(ACTION_DECOMPILE, "F5");
    update_action_shortcut(ACTION_DECOMPILE_ALL, "Ctrl-F5");
}

void unregister_all_spudec_actions() {
    detach_action_from_menu("View/Open subviews/Generate pseudocode", ACTION_DECOMPILE);
    detach_action_from_menu("View/Open subviews/", ACTION_DECOMPILE);
    detach_action_from_menu("View/Open subviews/", ACTION_DECOMPILE_ALL);
    for (const auto &entry : action_table()) {
        unregister_action(entry.name);
    }
}

} // namespace spudec