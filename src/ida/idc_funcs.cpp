#include <ida.hpp>
#include <expr.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>

#include "idc_funcs.hpp"
#include "db.hpp"
#include "ida_provider.hpp"
#include "plugin.hpp"
#include "summary_cache.hpp"
#include "view.hpp"
#include "spudec/abi.hpp"
#include "spudec/pipeline.hpp"

namespace spudec {

namespace {

uint64_t arg_to_ea(idc_value_t &v) {
    idcv_int64(&v);
    return static_cast<uint64_t>(v.i64);
}

int arg_to_int(idc_value_t &v) {
    idcv_long(&v);
    return static_cast<int>(v.num);
}

std::string arg_to_str(idc_value_t &v) {
    idcv_string(&v);
    return v.c_str() ? std::string(v.c_str()) : std::string();
}

error_t idaapi idc_spudec_version(idc_value_t *, idc_value_t *res) {
    res->set_string(SPUDEC_VERSION);
    return eOk;
}

error_t idaapi idc_spudec_decompile(idc_value_t *argv, idc_value_t *res) {
    if (!is_spu_database_active()) {
        res->set_string("");
        return eOk;
    }
    uint64_t ea = arg_to_ea(argv[0]);
    std::string err;
    std::string text = decompile_single_to_text(ea, &err);
    res->set_string(text.c_str(), text.size());
    return eOk;
}

error_t idaapi idc_spudec_dump_ir(idc_value_t *argv, idc_value_t *res) {
    if (!is_spu_database_active()) {
        res->set_string("");
        return eOk;
    }
    uint64_t ea = arg_to_ea(argv[0]);
    std::string err;
    std::string text = dump_single_ir_to_text(ea, &err);
    res->set_string(text.c_str(), text.size());
    return eOk;
}

error_t idaapi idc_spudec_decompile_all(idc_value_t *argv, idc_value_t *res) {
    if (!is_spu_database_active()) {
        res->set_long(0);
        return eOk;
    }
    std::string out_path = arg_to_str(argv[0]);
    int ok_cnt = 0, fail_cnt = 0;
    std::string full_text = decompile_all_to_string(false, &ok_cnt, &fail_cnt);
    if (!out_path.empty()) {
        FILE *fp = qfopen(out_path.c_str(), "wb");
        if (!fp) {
            res->set_long(-1);
            return eOk;
        }
        qfwrite(fp, full_text.data(), full_text.size());
        qfclose(fp);
    }
    res->set_long(ok_cnt);
    return eOk;
}

error_t idaapi idc_spudec_open_pseudocode(idc_value_t *argv, idc_value_t *res) {
    if (!is_spu_database_active()) {
        res->set_long(0);
        return eOk;
    }
    uint64_t ea = arg_to_ea(argv[0]);
    int flags = arg_to_int(argv[1]);
    bool ok = global_vdui().open_or_focus(ea, flags, true);
    res->set_long(ok ? 1 : 0);
    return eOk;
}

error_t idaapi idc_spudec_rename_lvar(idc_value_t *argv, idc_value_t *res) {
    if (!is_spu_database_active()) {
        res->set_long(0);
        return eOk;
    }
    uint64_t fea = arg_to_ea(argv[0]);
    if (func_t *pfn = get_func(static_cast<ea_t>(fea))) fea = static_cast<uint64_t>(pfn->start_ea);
    std::string old_name = arg_to_str(argv[1]);
    std::string new_name = arg_to_str(argv[2]);

    // Resolve canonical name if caller passed an already-renamed lvar display name
    cfuncptr_t cf = decompile_or_get_cached(fea, false);
    std::string canon = old_name;
    if (cf) {
        for (const auto &lv : cf->lvars) {
            if (lv.name == old_name || lv.canonical_name == old_name) {
                canon = lv.canonical_name;
                idadb::set_var_locator(fea, lv.location.to_key(), new_name, std::nullopt);
                break;
            }
        }
    }
    idadb::set_var_rename(fea, canon, new_name);
    global_summary_cache().invalidate_func(fea);
    if (global_vdui().is_open() && global_vdui().current_func_ea() == fea) {
        global_vdui().refresh_view(true);
    }
    res->set_long(1);
    return eOk;
}

error_t idaapi idc_spudec_set_lvar_type(idc_value_t *argv, idc_value_t *res) {
    if (!is_spu_database_active()) {
        res->set_long(0);
        return eOk;
    }
    uint64_t fea = arg_to_ea(argv[0]);
    if (func_t *pfn = get_func(static_cast<ea_t>(fea))) fea = static_cast<uint64_t>(pfn->start_ea);
    std::string var_name = arg_to_str(argv[1]);
    std::string type_str = arg_to_str(argv[2]);

    cfuncptr_t cf = decompile_or_get_cached(fea, false);
    std::string canon = var_name;
    if (cf) {
        for (const auto &lv : cf->lvars) {
            if (lv.name == var_name || lv.canonical_name == var_name) {
                canon = lv.canonical_name;
                idadb::set_var_locator(fea, lv.location.to_key(), std::nullopt, type_str);
                break;
            }
        }
    }
    idadb::set_var_type(fea, canon, type_str);
    global_summary_cache().invalidate_func(fea);
    if (global_vdui().is_open() && global_vdui().current_func_ea() == fea) {
        global_vdui().refresh_view(true);
    }
    res->set_long(1);
    return eOk;
}

error_t idaapi idc_spudec_set_proto(idc_value_t *argv, idc_value_t *res) {
    if (!is_spu_database_active()) {
        res->set_long(0);
        return eOk;
    }
    uint64_t fea = arg_to_ea(argv[0]);
    if (func_t *pfn = get_func(static_cast<ea_t>(fea))) fea = static_cast<uint64_t>(pfn->start_ea);
    std::string proto_str = arg_to_str(argv[1]);
    if (!proto_str.empty() && !abi::parse_proto(proto_str).has_value()) {
        res->set_long(0);
        return eOk;
    }
    idadb::set_func_proto(fea, proto_str);
    if (!proto_str.empty()) {
        apply_proto_to_ida(static_cast<ea_t>(fea), proto_str);
    }
    global_summary_cache().clear_arity_and_demand();
    global_summary_cache().invalidate_func(fea);
    if (global_vdui().is_open()) global_vdui().refresh_view(true);
    res->set_long(1);
    return eOk;
}

error_t idaapi idc_spudec_set_cmt(idc_value_t *argv, idc_value_t *res) {
    if (!is_spu_database_active()) {
        res->set_long(0);
        return eOk;
    }
    uint64_t fea = arg_to_ea(argv[0]);
    if (func_t *pfn = get_func(static_cast<ea_t>(fea))) fea = static_cast<uint64_t>(pfn->start_ea);
    uint64_t stmt_ea = arg_to_ea(argv[1]);
    std::string cmt = arg_to_str(argv[2]);
    idadb::set_statement_cmt(fea, stmt_ea, cmt);
    global_summary_cache().invalidate_func(fea);
    if (global_vdui().is_open() && global_vdui().current_func_ea() == fea) {
        global_vdui().refresh_view(true);
    }
    res->set_long(1);
    return eOk;
}

error_t idaapi idc_spudec_set_numform(idc_value_t *argv, idc_value_t *res) {
    if (!is_spu_database_active()) {
        res->set_long(0);
        return eOk;
    }
    uint64_t fea = arg_to_ea(argv[0]);
    if (func_t *pfn = get_func(static_cast<ea_t>(fea))) fea = static_cast<uint64_t>(pfn->start_ea);
    uint64_t stmt_ea = arg_to_ea(argv[1]);
    int op_idx = arg_to_int(argv[2]);
    std::string form = arg_to_str(argv[3]);
    idadb::set_numform(fea, stmt_ea, op_idx, form);
    global_summary_cache().invalidate_func(fea);
    if (global_vdui().is_open() && global_vdui().current_func_ea() == fea) {
        global_vdui().refresh_view(true);
    }
    res->set_long(1);
    return eOk;
}

error_t idaapi idc_spudec_invert_if(idc_value_t *argv, idc_value_t *res) {
    if (!is_spu_database_active()) {
        res->set_long(0);
        return eOk;
    }
    uint64_t fea = arg_to_ea(argv[0]);
    if (func_t *pfn = get_func(static_cast<ea_t>(fea))) fea = static_cast<uint64_t>(pfn->start_ea);
    uint64_t branch_ea = arg_to_ea(argv[1]);
    bool inv = idadb::toggle_iflag(fea, branch_ea);
    global_summary_cache().invalidate_func(fea);
    if (global_vdui().is_open() && global_vdui().current_func_ea() == fea) {
        global_vdui().refresh_view(true);
    }
    res->set_long(inv ? 1 : 0);
    return eOk;
}

error_t idaapi idc_spudec_mark_dirty(idc_value_t *argv, idc_value_t *res) {
    if (!is_spu_database_active()) {
        res->set_long(0);
        return eOk;
    }
    uint64_t fea = arg_to_ea(argv[0]);
    if (fea == BADADDR || fea == UINT64_MAX) {
        global_summary_cache().clear_all();
    } else {
        if (func_t *pfn = get_func(static_cast<ea_t>(fea))) fea = static_cast<uint64_t>(pfn->start_ea);
        global_summary_cache().invalidate_func(fea);
    }
    if (global_vdui().is_open()) {
        global_vdui().refresh_view(true);
    }
    res->set_long(1);
    return eOk;
}

static const char kArgsNone[]      = {0};
static const char kArgsEa[]        = {VT_INT64, 0};
static const char kArgsStr[]       = {VT_STR, 0};
static const char kArgsEaLong[]    = {VT_INT64, VT_LONG, 0};
static const char kArgsEaStr[]     = {VT_INT64, VT_STR, 0};
static const char kArgsEaStrStr[]  = {VT_INT64, VT_STR, VT_STR, 0};
static const char kArgsEaEa[]      = {VT_INT64, VT_INT64, 0};
static const char kArgsEaEaStr[]   = {VT_INT64, VT_INT64, VT_STR, 0};
static const char kArgsEaEaLongStr[] = {VT_INT64, VT_INT64, VT_LONG, VT_STR, 0};

static const idc_value_t kDefZero(static_cast<sval_t>(0));

static const ext_idcfunc_t kSpudecIdcFuncs[] = {
    {"spudec_version",         idc_spudec_version,         kArgsNone,        nullptr,   0, 0},
    {"spudec_decompile",       idc_spudec_decompile,       kArgsEa,          nullptr,   0, EXTFUN_BASE},
    {"spudec_dump_ir",         idc_spudec_dump_ir,         kArgsEa,          nullptr,   0, EXTFUN_BASE},
    {"spudec_decompile_all",   idc_spudec_decompile_all,   kArgsStr,         nullptr,   0, EXTFUN_BASE},
    {"spudec_open_pseudocode", idc_spudec_open_pseudocode, kArgsEaLong,      &kDefZero, 1, EXTFUN_BASE},
    {"spudec_rename_lvar",     idc_spudec_rename_lvar,     kArgsEaStrStr,    nullptr,   0, EXTFUN_BASE},
    {"spudec_set_lvar_type",   idc_spudec_set_lvar_type,   kArgsEaStrStr,    nullptr,   0, EXTFUN_BASE},
    {"spudec_set_proto",       idc_spudec_set_proto,       kArgsEaStr,       nullptr,   0, EXTFUN_BASE},
    {"spudec_set_cmt",         idc_spudec_set_cmt,         kArgsEaEaStr,     nullptr,   0, EXTFUN_BASE},
    {"spudec_set_numform",     idc_spudec_set_numform,     kArgsEaEaLongStr, nullptr,   0, EXTFUN_BASE},
    {"spudec_invert_if",       idc_spudec_invert_if,       kArgsEaEa,        nullptr,   0, EXTFUN_BASE},
    {"spudec_mark_dirty",      idc_spudec_mark_dirty,      kArgsEa,          nullptr,   0, EXTFUN_BASE},
};

} // namespace

void register_spudec_idc_funcs() {
    for (const auto &fn : kSpudecIdcFuncs) {
        add_idc_func(fn);
    }
}

void unregister_spudec_idc_funcs() {
    for (const auto &fn : kSpudecIdcFuncs) {
        del_idc_func(fn.name);
    }
}

} // namespace spudec