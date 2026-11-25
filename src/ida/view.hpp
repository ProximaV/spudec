#pragma once

#include <ida.hpp>
#include <kernwin.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include "spudec/ctree.hpp"
#include "spudec/ir.hpp"
#include "spudec/pipeline.hpp"

namespace spudec {

inline constexpr const char *SPUDEC_VIEW_TITLE = "spudec - Pseudocode";
inline constexpr const char *SPUDEC_LISTING_TITLE = "spudec - All Decompiled Functions";

// Action names (100% parity with legacy spudec + Hex-Rays shortcuts)
inline constexpr const char *ACTION_DECOMPILE       = "spudec:decompile";
inline constexpr const char *ACTION_DECOMPILE_ALL   = "spudec:decompile_all";
inline constexpr const char *ACTION_CLEAR_CACHES    = "spudec:clear_caches";
inline constexpr const char *ACTION_RENAME          = "spudec:rename_var";
inline constexpr const char *ACTION_SET_TYPE        = "spudec:set_type";
inline constexpr const char *ACTION_EDIT_CMT        = "spudec:edit_comment";
inline constexpr const char *ACTION_EDIT_CMT_SEMI   = "spudec:edit_comment_semi";
inline constexpr const char *ACTION_TOGGLE_HEX      = "spudec:toggle_hex";
inline constexpr const char *ACTION_TOGGLE_CHAR     = "spudec:toggle_char";
inline constexpr const char *ACTION_MAKE_ASCII      = "spudec:make_ascii";
inline constexpr const char *ACTION_TOGGLE_BIN      = "spudec:toggle_bin";
inline constexpr const char *ACTION_TOGGLE_SIGNED   = "spudec:toggle_signed";
inline constexpr const char *ACTION_TOGGLE_INV      = "spudec:toggle_inv";
inline constexpr const char *ACTION_TOGGLE_OFFSET   = "spudec:toggle_offset";
inline constexpr const char *ACTION_SET_ENUM        = "spudec:set_enum";
inline constexpr const char *ACTION_INVERT_IF       = "spudec:invert_if";
inline constexpr const char *ACTION_TOGGLE_CASTS    = "spudec:toggle_casts";
inline constexpr const char *ACTION_SHOW_XREFS      = "spudec:show_xrefs";
inline constexpr const char *ACTION_JUMP_ADDR       = "spudec:jump_addr";
inline constexpr const char *ACTION_JUMP_DISASM     = "spudec:jump_disasm";
inline constexpr const char *ACTION_SWITCH_DISASM   = "spudec:switch_disasm";
inline constexpr const char *ACTION_NAV_BACK        = "spudec:nav_back";
inline constexpr const char *ACTION_NAV_FORWARD     = "spudec:nav_forward";
inline constexpr const char *ACTION_TOGGLE_SYNC     = "spudec:toggle_sync";
inline constexpr const char *ACTION_TOGGLE_IR       = "spudec:toggle_ir";
inline constexpr const char *ACTION_REFRESH         = "spudec:refresh";
inline constexpr const char *ACTION_RESET_OVERRIDES = "spudec:reset_overrides";
inline constexpr const char *ACTION_SAVE_LISTING_C  = "spudec:save_listing_c";

struct NavEntry {
    uint64_t func_ea = 0;
    uint64_t ea = 0;
    int lineno = 0;
    int col = 0;
};

class SpuVdui {
public:
    SpuVdui() = default;
    ~SpuVdui() = default;

    TWidget *widget() const { return widget_; }
    bool is_open() const { return widget_ != nullptr; }
    std::optional<uint64_t> current_func_ea() const { return current_func_ea_; }
    cfuncptr_t cfunc() const { return cfunc_; }
    const Function *ir_func() const { return ir_func_.get(); }
    const std::string &mode() const { return mode_; }
    bool sync_enabled() const { return sync_with_disasm_; }
    int selected_line() const { return selected_line_; }
    const std::unordered_set<uint64_t> &highlighted_asm_eas() const { return highlighted_asm_eas_; }

    // Open or focus pseudocode viewer at `target_ea` (`flags`: 0 = reuse, 1 = new/focus, -1 = no activate)
    bool open_or_focus(uint64_t target_ea, int open_flags = 0, bool push_history = false);

    // Desktop layout hooks
    TWidget *create_for_desktop();
    void restore_saved_window();
    void persist_window_state(bool force_open_state = true);
    void close_and_cleanup();

    // Refresh current function (force_redecompile=true invalidates cached cfunc_t)
    bool refresh_view(bool force_redecompile = true);
    bool switch_to(uint64_t target_ea, bool push_history = true);

    // UI event callbacks forwarded from SpuDecPlugmod
    void on_screen_ea_changed(ea_t ea, ea_t prev_ea);
    void on_widget_invisible(TWidget *w);
    void populate_popup(TWidget *w, TPopupMenu *popup);
    bool get_hint(TWidget *viewer, place_t *place, qstring &out_hint, int *important_lines);
    void get_lines_rendering_info(lines_rendering_output_t *out,
                                  const TWidget *viewer,
                                  const lines_rendering_input_t *info) const;

    // Cursor & AST inspection helpers (shared with C++ / IDAPython vdui_t scripting)
    bool get_cursor_pos(int *out_lineno, int *out_col, bool mouse = false) const;
    std::string get_current_word(bool mouse = false) const;
    citem_t *get_current_citem(bool mouse = false) const;
    std::optional<uint64_t> get_current_line_ea(bool mouse = false) const;
    const LineConstSpan *find_const_at_cursor(int *out_lineno = nullptr, bool mouse = false) const;

    // 24 Interactive Hex-Rays Actions
    int act_rename();
    int act_set_type();
    int act_edit_comment();
    int act_toggle_numform(const char *target_form);
    int act_make_ascii();
    int act_toggle_offset();
    int act_set_enum();
    int act_invert_if();
    int act_toggle_casts();
    int act_show_xrefs();
    int act_jump_addr();
    int act_jump_disasm();
    int act_switch_disasm();
    int act_nav_back();
    int act_nav_forward();
    int act_toggle_sync();
    int act_toggle_ir();
    int act_refresh();
    int act_reset_overrides();

    // Custom viewer static trampoline handlers
    void handle_curpos();
    void handle_click(int shift);
    bool handle_dblclick(int shift);
    bool handle_keyboard(int key, int shift);

private:
    bool ensure_widget_created(bool dock_right, bool activate);
    bool render_function(uint64_t func_ea, std::optional<uint64_t> focus_ea = std::nullopt,
                         int restore_line = -1, int restore_col = 0, bool force_redecompile = false);
    void rebuild_strvec_from_current();
    void update_viewer_bounds_and_cursor(int target_line, int target_col);
    void update_token_highlight(const std::string &word);
    void sync_cursor_to_disasm(int lineno, bool push_history);
    void push_current_nav();
    std::optional<uint64_t> find_enclosing_if_ea(int lineno) const;

    TWidget *widget_ = nullptr;
    strvec_t lines_;
    std::vector<std::string> plain_lines_;
    std::vector<std::optional<uint64_t>> view_line_eas_;

    std::optional<uint64_t> current_func_ea_;
    cfuncptr_t cfunc_;
    std::unique_ptr<Function> ir_func_;
    std::string mode_ = "c"; // "c" or "ir"

    int selected_line_ = 0;
    std::string last_token_;
    std::unordered_set<uint64_t> highlighted_asm_eas_;

    bool sync_with_disasm_ = true;
    bool sync_lock_ = false;
    bool in_nav_action_ = false;
    std::vector<NavEntry> nav_history_;
    std::vector<NavEntry> nav_forward_;
};

// Whole-binary decompile helper & listing viewer (Ctrl+F5 & scripting)
std::string decompile_single_to_text(uint64_t ea, std::string *out_error = nullptr);
std::string dump_single_ir_to_text(uint64_t ea, std::string *out_error = nullptr);
cfuncptr_t decompile_or_get_cached(uint64_t ea, bool force_redecompile = false, std::string *out_error = nullptr);
std::string decompile_all_to_string(bool show_progress = false, int *out_ok = nullptr, int *out_fail = nullptr);
bool open_decompile_all_viewer();
int act_save_listing_to_c_file();
TWidget *get_listing_widget();

// Singleton viewer & action registration
SpuVdui &global_vdui();
SpuVdui *find_vdui_for_widget(TWidget *w);
void register_all_spudec_actions(plugmod_t *owner);
void unregister_all_spudec_actions();

} // namespace spudec