#define SPUDEC_BUILDING_DLL 1

#include <ida.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>

#include "api_dispatch.hpp"
#include "db.hpp"
#include "ida_provider.hpp"
#include "plugin.hpp"
#include "summary_cache.hpp"
#include "view.hpp"

#include "spudec/abi.hpp"
#include "spudec/ctree.hpp"
#include "spudec/opt.hpp"
#include "spudec/pipeline.hpp"
#include "spudec/spudec_c_api.h"
#include "spudec/user_data.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <unordered_map>

namespace spudec {

namespace {

// Owned cfunc_t handle table for FFI / scripting consumers
struct ApiState {
    uint64_t next_handle = 1;
    std::unordered_map<uint64_t, cfuncptr_t> handles;
    std::unordered_map<const cfunc_t *, uint64_t> ptr_to_handle;
    Function *active_opt_func = nullptr;
};

ApiState &api_state() {
    static ApiState st;
    return st;
}

uint64_t register_cfunc_handle(const cfuncptr_t &cf) {
    if (!cf) return 0;
    ApiState &st = api_state();
    auto it = st.ptr_to_handle.find(cf.get());
    if (it != st.ptr_to_handle.end()) {
        st.handles[it->second] = cf;
        return it->second;
    }
    uint64_t h = st.next_handle++;
    st.handles[h] = cf;
    st.ptr_to_handle[cf.get()] = h;
    return h;
}

cfuncptr_t lookup_cfunc_handle(uint64_t h) {
    if (h == 0) return nullptr;
    ApiState &st = api_state();
    auto it = st.handles.find(h);
    return (it != st.handles.end()) ? it->second : nullptr;
}

char *dup_cstr(const std::string &s) {
    char *buf = static_cast<char *>(std::malloc(s.size() + 1));
    if (!buf) return nullptr;
    std::memcpy(buf, s.data(), s.size());
    buf[s.size()] = '\0';
    return buf;
}

void append_json_escaped(std::string &out, const std::string &s) {
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned>(c));
                    out += hex;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    out.push_back('"');
}

void append_u64_or_null(std::string &out, uint64_t v) {
    if (v == UINT64_MAX) {
        out += "null";
    } else {
        out += std::to_string(v);
    }
}

std::string serialize_cfunc_to_json(const cfunc_t &cf, bool include_ctree) {
    std::string out;
    out.reserve(include_ctree ? (cf.treeitems.size() * 128 + 4096) : 4096);

    out += "{";
    out += "\"entry_ea\":" + std::to_string(cf.entry_ea);
    out += ",\"func_name\":"; append_json_escaped(out, cf.func_name);
    out += ",\"ret_type\":"; append_json_escaped(out, cf.ret_type);
    out += ",\"signature_line\":"; append_json_escaped(out, cf.signature_line);
    out += ",\"hdrlines\":" + std::to_string(cf.hdrlines);
    out += ",\"sig_line\":" + std::to_string(cf.sig_line);
    out += ",\"maturity\":" + std::to_string(cf.maturity);
    out += ",\"body_id\":" + (cf.body ? std::to_string(cf.body->obj_id) : std::string("-1"));

    // pseudocode_lines
    out += ",\"lines\":[";
    for (size_t i = 0; i < cf.pseudocode_lines.size(); ++i) {
        if (i) out.push_back(',');
        append_json_escaped(out, cf.pseudocode_lines[i]);
    }
    out += "]";

    // sv (IDA color-tagged lines)
    out += ",\"sv\":[";
    for (size_t i = 0; i < cf.sv.size(); ++i) {
        if (i) out.push_back(',');
        append_json_escaped(out, cf.sv[i]);
    }
    out += "]";

    // line_eas
    out += ",\"line_eas\":[";
    for (size_t i = 0; i < cf.line_eas.size(); ++i) {
        if (i) out.push_back(',');
        if (cf.line_eas[i].has_value()) out += std::to_string(*cf.line_eas[i]);
        else out += "null";
    }
    out += "]";

    // lvars
    out += ",\"lvars\":[";
    for (size_t i = 0; i < cf.lvars.size(); ++i) {
        if (i) out.push_back(',');
        const auto &lv = cf.lvars[i];
        out += "{\"idx\":" + std::to_string(lv.index);
        out += ",\"name\":"; append_json_escaped(out, lv.name);
        out += ",\"canon\":"; append_json_escaped(out, lv.canonical_name);
        out += ",\"type\":"; append_json_escaped(out, lv.type_str);
        out += ",\"cmt\":"; append_json_escaped(out, lv.cmt);
        out += ",\"width\":" + std::to_string(lv.width);
        out += ",\"defea\":"; append_u64_or_null(out, lv.defea);
        out += ",\"loc_stk\":" + std::string(lv.location.is_stk ? "true" : "false");
        out += ",\"loc_reg\":" + std::to_string(lv.location.reg);
        out += ",\"loc_off\":" + std::to_string(lv.location.stk_off);
        out += ",\"is_arg\":" + std::string(lv.is_arg_var ? "true" : "false");
        out += ",\"is_this\":" + std::string(lv.is_thisarg ? "true" : "false");
        out += ",\"is_res\":" + std::string(lv.is_result_var ? "true" : "false");
        out += ",\"is_stk\":" + std::string(lv.is_stk_var_flag ? "true" : "false");
        out += ",\"user_name\":" + std::string(lv.has_user_name ? "true" : "false");
        out += ",\"user_type\":" + std::string(lv.has_user_type ? "true" : "false");
        out += "}";
    }
    out += "]";

    // argidx
    out += ",\"argidx\":[";
    for (size_t i = 0; i < cf.argidx.size(); ++i) {
        if (i) out.push_back(',');
        out += std::to_string(cf.argidx[i]);
    }
    out += "]";

    // eamap: { "ea_dec": [obj_id, ...] }
    out += ",\"eamap\":{";
    bool first_ea = true;
    for (const auto &kv : cf.eamap) {
        if (kv.first == UINT64_MAX) continue;
        if (!first_ea) out.push_back(',');
        first_ea = false;
        out.push_back('"');
        out += std::to_string(kv.first);
        out += "\":[";
        for (size_t j = 0; j < kv.second.size(); ++j) {
            if (j) out.push_back(',');
            out += std::to_string(kv.second[j] ? static_cast<int>(kv.second[j]->obj_id) : -1);
        }
        out.push_back(']');
    }
    out += "}";

    if (include_ctree) {
        out += ",\"items\":[";
        for (size_t i = 0; i < cf.treeitems.size(); ++i) {
            if (i) out.push_back(',');
            const citem_t *it = cf.treeitems[i].get();
            if (!it) {
                out += "null";
                continue;
            }
            out += "{\"id\":" + std::to_string(it->obj_id);
            out += ",\"op\":" + std::to_string(static_cast<int>(it->op));
            out += ",\"ea\":"; append_u64_or_null(out, it->ea);
            out += ",\"lbl\":" + std::to_string(it->label_num);
            if (!it->label_name.empty()) {
                out += ",\"lbl_name\":"; append_json_escaped(out, it->label_name);
            }
            if (it->is_expr()) {
                const cexpr_t *e = it->cexpr();
                out += ",\"k\":\"e\"";
                out += ",\"ty\":"; append_json_escaped(out, e->type_str);
                if (e->ptrsize) out += ",\"ps\":" + std::to_string(e->ptrsize);
                if (e->x) out += ",\"x\":" + std::to_string(e->x->obj_id);
                if (e->y) out += ",\"y\":" + std::to_string(e->y->obj_id);
                if (e->z) out += ",\"z\":" + std::to_string(e->z->obj_id);
                if (!e->a.empty()) {
                    out += ",\"a\":[";
                    for (size_t k = 0; k < e->a.size(); ++k) {
                        if (k) out.push_back(',');
                        out += std::to_string(e->a[k] ? static_cast<int>(e->a[k]->obj_id) : -1);
                    }
                    out += "]";
                }
                if (e->op == cot_var) {
                    out += ",\"v\":" + std::to_string(e->v.idx);
                } else if (e->op == cot_num || e->op == cot_fnum) {
                    out += ",\"n\":" + std::to_string(e->n._value);
                    out += ",\"nb\":" + std::to_string(e->n.bits);
                    out += ",\"nr\":"; append_json_escaped(out, e->n.repr);
                } else if (e->op == cot_obj || e->obj_ea != UINT64_MAX) {
                    out += ",\"oea\":"; append_u64_or_null(out, e->obj_ea);
                }
                if (!e->string.empty()) {
                    out += ",\"s\":"; append_json_escaped(out, e->string);
                }
                if (!e->helper.empty()) {
                    out += ",\"h\":"; append_json_escaped(out, e->helper);
                }
                out += ",\"txt\":"; append_json_escaped(out, e->print1(&cf.lvars));
            } else {
                const cinsn_t *ins = it->cinsn();
                out += ",\"k\":\"i\"";
                if (ins->op == cit_block) {
                    out += ",\"blk\":[";
                    for (size_t k = 0; k < ins->cblock.statements.size(); ++k) {
                        if (k) out.push_back(',');
                        out += std::to_string(ins->cblock.statements[k]
                                                  ? static_cast<int>(ins->cblock.statements[k]->obj_id)
                                                  : -1);
                    }
                    out += "]";
                } else if (ins->op == cit_expr && ins->cexpr_node) {
                    out += ",\"e\":" + std::to_string(ins->cexpr_node->obj_id);
                } else if (ins->op == cit_if) {
                    out += ",\"ic\":" + std::to_string(ins->cif.expr ? static_cast<int>(ins->cif.expr->obj_id) : -1);
                    out += ",\"it\":" + std::to_string(ins->cif.ithen ? static_cast<int>(ins->cif.ithen->obj_id) : -1);
                    out += ",\"ie\":" + std::to_string(ins->cif.ielse ? static_cast<int>(ins->cif.ielse->obj_id) : -1);
                } else if (ins->op == cit_while || ins->op == cit_do || ins->op == cit_for) {
                    out += ",\"lc\":" + std::to_string(ins->cloop.expr ? static_cast<int>(ins->cloop.expr->obj_id) : -1);
                    out += ",\"lb\":" + std::to_string(ins->cloop.body ? static_cast<int>(ins->cloop.body->obj_id) : -1);
                } else if (ins->op == cit_return && ins->creturn.expr) {
                    out += ",\"re\":" + std::to_string(ins->creturn.expr->obj_id);
                } else if (ins->op == cit_goto) {
                    out += ",\"gl\":" + std::to_string(ins->cgoto.label_num);
                    out += ",\"gt\":"; append_json_escaped(out, ins->cgoto.target_name);
                }
                if (!ins->user_cmt.empty()) {
                    out += ",\"cmt\":"; append_json_escaped(out, ins->user_cmt);
                }
            }
            out += "}";
        }
        out += "]";
    }

    out += "}";
    return out;
}

uint64_t normalize_func_ea(uint64_t ea) {
    if (func_t *pfn = get_func(static_cast<ea_t>(ea))) {
        return static_cast<uint64_t>(pfn->start_ea);
    }
    return ea;
}

} // namespace

void clear_api_handles() {
    ApiState &st = api_state();
    st.handles.clear();
    st.ptr_to_handle.clear();
}

bool handle_spudec_broadcast(SpudecBroadcastReq *req) {
    if (!req || req->struct_size != sizeof(SpudecBroadcastReq)) return false;
    if (!is_spu_database_active()) {
        req->status = -1;
        return false;
    }

    req->status = 0;
    switch (req->op) {
        case SPUDEC_BCAST_PING:
            req->out_str = SPUDEC_VERSION;
            return true;

        case SPUDEC_BCAST_DECOMPILE_CFUNC: {
            std::string err;
            cfuncptr_t cf = decompile_or_get_cached(req->ea, (req->flags & 1) != 0, &err);
            if (!cf) {
                req->status = -2;
                req->out_str = err.c_str();
                return true;
            }
            if (req->ptr_arg) {
                *static_cast<cfuncptr_t *>(req->ptr_arg) = cf;
            }
            req->out_ptr = cf.get();
            return true;
        }

        case SPUDEC_BCAST_DECOMPILE_TEXT: {
            std::string err;
            std::string txt = decompile_single_to_text(req->ea, &err);
            if (txt.empty() && !err.empty()) {
                req->status = -2;
                req->out_str = err.c_str();
                return true;
            }
            req->out_str = txt.c_str();
            return true;
        }

        case SPUDEC_BCAST_DUMP_IR_TEXT: {
            std::string err;
            std::string txt = dump_single_ir_to_text(req->ea, &err);
            if (txt.empty() && !err.empty()) {
                req->status = -2;
                req->out_str = err.c_str();
                return true;
            }
            req->out_str = txt.c_str();
            return true;
        }

        case SPUDEC_BCAST_OPEN_PSEUDOCODE: {
            bool ok = global_vdui().open_or_focus(req->ea, req->flags, true);
            req->status = ok ? 0 : -1;
            req->out_ptr = ok ? &global_vdui() : nullptr;
            return true;
        }

        case SPUDEC_BCAST_MARK_DIRTY: {
            if (req->ea == BADADDR || req->ea == UINT64_MAX) {
                global_summary_cache().clear_all();
            } else {
                global_summary_cache().invalidate_func(normalize_func_ea(req->ea));
            }
            if (global_vdui().is_open()) global_vdui().refresh_view(true);
            return true;
        }

        case SPUDEC_BCAST_CLEAR_CACHES:
            global_summary_cache().clear_all();
            clear_api_handles();
            if (global_vdui().is_open()) global_vdui().refresh_view(true);
            return true;

        case SPUDEC_BCAST_RENAME_LVAR:
            req->status = spudec_abi_rename_lvar(
                req->ea, req->str_arg1 ? req->str_arg1 : "", req->str_arg2 ? req->str_arg2 : "") ? 0 : -1;
            return true;

        case SPUDEC_BCAST_SET_LVAR_TYPE:
            req->status = spudec_abi_set_lvar_type(
                req->ea, req->str_arg1 ? req->str_arg1 : "", req->str_arg2 ? req->str_arg2 : "") ? 0 : -1;
            return true;

        case SPUDEC_BCAST_SET_PROTO:
            req->status = spudec_abi_set_proto(
                req->ea, req->str_arg1 ? req->str_arg1 : "") ? 0 : -1;
            return true;

        case SPUDEC_BCAST_SET_CMT:
            req->status = spudec_abi_set_cmt(
                req->ea, req->ea2, req->str_arg1 ? req->str_arg1 : "") ? 0 : -1;
            return true;

        case SPUDEC_BCAST_SET_NUMFORM:
            req->status = spudec_abi_set_numform(
                req->ea, req->ea2, req->flags, req->str_arg1 ? req->str_arg1 : "") ? 0 : -1;
            return true;

        case SPUDEC_BCAST_INVERT_IF:
            req->status = spudec_abi_invert_if(req->ea, req->ea2);
            return true;

        case SPUDEC_BCAST_REG_EVENT_CB: {
            if (!req->ptr_arg) { req->status = -1; return true; }
            auto *cb_ptr = static_cast<SpudecEventCallback *>(req->ptr_arg);
            req->status = register_event_callback(*cb_ptr);
            return true;
        }

        case SPUDEC_BCAST_UNREG_EVENT_CB:
            req->status = unregister_event_callback(req->flags) ? 0 : -1;
            return true;

        default:
            req->status = -1;
            return false;
    }
}

} // namespace spudec

// ===========================================================================
// Exported C ABI for ctypes / external plugins
// ===========================================================================

extern "C" {

SPUDEC_API_EXPORT const char * __cdecl spudec_abi_version(void) {
    return spudec::SPUDEC_VERSION;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_is_spu_db(void) {
    return spudec::is_spu_database_active() ? 1 : 0;
}

SPUDEC_API_EXPORT void __cdecl spudec_abi_free_str(char *s) {
    if (s) std::free(s);
}

SPUDEC_API_EXPORT void __cdecl spudec_abi_clear_caches(void) {
    spudec::global_summary_cache().clear_all();
    spudec::clear_api_handles();
    if (spudec::global_vdui().is_open()) {
        spudec::global_vdui().refresh_view(true);
    }
}

SPUDEC_API_EXPORT void __cdecl spudec_abi_mark_dirty(uint64_t func_ea, int close_views) {
    if (func_ea == BADADDR || func_ea == UINT64_MAX) {
        spudec::global_summary_cache().clear_all();
    } else {
        uint64_t fea = spudec::normalize_func_ea(func_ea);
        spudec::global_summary_cache().invalidate_func(fea);
    }
    if (close_views) {
        spudec::global_vdui().close_and_cleanup();
    } else if (spudec::global_vdui().is_open()) {
        spudec::global_vdui().refresh_view(true);
    }
}

SPUDEC_API_EXPORT uint64_t __cdecl spudec_abi_decompile(uint64_t ea, int flags, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (!spudec::is_spu_database_active()) {
        if (out_err) *out_err = spudec::dup_cstr("Active IDA database is not PLFM_SPU");
        return 0;
    }
    bool force = (flags & 1) != 0; // DECOMP_NO_CACHE == 1
    std::string err;
    spudec::cfuncptr_t cf = spudec::decompile_or_get_cached(ea, force, &err);
    if (!cf) {
        if (out_err) *out_err = spudec::dup_cstr(err.empty() ? "Decompilation failed" : err);
        return 0;
    }
    return spudec::register_cfunc_handle(cf);
}

SPUDEC_API_EXPORT void __cdecl spudec_abi_release_cfunc(uint64_t handle) {
    auto &st = spudec::api_state();
    auto it = st.handles.find(handle);
    if (it != st.handles.end()) {
        st.ptr_to_handle.erase(it->second.get());
        st.handles.erase(it);
    }
}

SPUDEC_API_EXPORT char * __cdecl spudec_abi_cfunc_text(uint64_t handle) {
    spudec::cfuncptr_t cf = spudec::lookup_cfunc_handle(handle);
    if (!cf) return nullptr;
    return spudec::dup_cstr(cf->print_func());
}

SPUDEC_API_EXPORT char * __cdecl spudec_abi_cfunc_json(uint64_t handle, int include_ctree) {
    spudec::cfuncptr_t cf = spudec::lookup_cfunc_handle(handle);
    if (!cf) return nullptr;
    return spudec::dup_cstr(spudec::serialize_cfunc_to_json(*cf, include_ctree != 0));
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_cfunc_mutate_item(
    uint64_t handle,
    uint32_t obj_id,
    int new_op,
    uint64_t new_numval,
    int new_var_idx,
    const char *new_str,
    const char *new_helper) {
    spudec::cfuncptr_t cf = spudec::lookup_cfunc_handle(handle);
    if (!cf) return 0;
    spudec::citem_t *it = cf->get_item(obj_id);
    if (!it) return 0;

    if (new_op >= 0) {
        it->op = static_cast<spudec::ctype_t>(new_op);
    }
    if (it->is_expr()) {
        spudec::cexpr_t *e = it->cexpr();
        e->mark_mutated();
        if (e->op == spudec::cot_num) {
            e->n._value = new_numval;
            e->n.repr.clear();
        }
        if (e->op == spudec::cot_var && new_var_idx >= 0) {
            e->v.idx = new_var_idx;
        }
        if (new_str) {
            e->string = new_str;
        }
        if (new_helper) {
            e->helper = new_helper;
        }
    } else {
        it->cinsn()->mark_mutated();
    }
    return 1;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_cfunc_swap_if(uint64_t handle, uint32_t if_obj_id) {
    spudec::cfuncptr_t cf = spudec::lookup_cfunc_handle(handle);
    if (!cf) return 0;
    spudec::citem_t *it = cf->get_item(if_obj_id);
    if (!it || it->op != spudec::cit_if) return 0;
    spudec::cinsn_t *ins = it->cinsn();
    if (!ins->cif.expr || !ins->cif.ielse) return 0;

    spudec::ctype_t neg = spudec::negated_relation(ins->cif.expr->op);
    if (neg != spudec::cot_empty) {
        ins->cif.expr->op = neg;
        ins->cif.expr->mark_mutated();
    } else {
        spudec::cexpr_t *wrapped = cf->alloc_expr(spudec::cot_lnot, ins->cif.expr->ea);
        wrapped->x = ins->cif.expr;
        wrapped->mark_mutated();
        ins->cif.expr = wrapped;
    }
    std::swap(ins->cif.ithen, ins->cif.ielse);
    ins->mark_mutated();
    return 1;
}

SPUDEC_API_EXPORT char * __cdecl spudec_abi_cfunc_refresh_ctext(uint64_t handle) {
    spudec::cfuncptr_t cf = spudec::lookup_cfunc_handle(handle);
    if (!cf) return nullptr;
    cf->refresh_func_ctext();
    if (spudec::global_vdui().is_open() && spudec::global_vdui().cfunc() == cf) {
        spudec::global_vdui().refresh_view(false);
    }
    return spudec::dup_cstr(cf->print_func());
}

SPUDEC_API_EXPORT char * __cdecl spudec_abi_decompile_text(uint64_t ea, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (!spudec::is_spu_database_active()) {
        if (out_err) *out_err = spudec::dup_cstr("Active IDA database is not PLFM_SPU");
        return nullptr;
    }
    std::string err;
    std::string text = spudec::decompile_single_to_text(ea, &err);
    if (text.empty() && !err.empty()) {
        if (out_err) *out_err = spudec::dup_cstr(err);
        return nullptr;
    }
    return spudec::dup_cstr(text);
}

SPUDEC_API_EXPORT char * __cdecl spudec_abi_dump_ir(uint64_t ea, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (!spudec::is_spu_database_active()) {
        if (out_err) *out_err = spudec::dup_cstr("Active IDA database is not PLFM_SPU");
        return nullptr;
    }
    std::string err;
    std::string text = spudec::dump_single_ir_to_text(ea, &err);
    if (text.empty() && !err.empty()) {
        if (out_err) *out_err = spudec::dup_cstr(err);
        return nullptr;
    }
    return spudec::dup_cstr(text);
}

SPUDEC_API_EXPORT char * __cdecl spudec_abi_decompile_all(const char *out_path, int *out_ok, int *out_fail) {
    if (!spudec::is_spu_database_active()) return nullptr;
    int ok_cnt = 0, fail_cnt = 0;
    std::string text = spudec::decompile_all_to_string(false, &ok_cnt, &fail_cnt);
    if (out_ok) *out_ok = ok_cnt;
    if (out_fail) *out_fail = fail_cnt;
    if (out_path && *out_path) {
        FILE *fp = qfopen(out_path, "wb");
        if (!fp) return nullptr;
        qfwrite(fp, text.data(), text.size());
        qfclose(fp);
        return spudec::dup_cstr(out_path);
    }
    return spudec::dup_cstr(text);
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_open_pseudocode(uint64_t ea, int open_flags) {
    if (!spudec::is_spu_database_active()) return 0;
    return spudec::global_vdui().open_or_focus(ea, open_flags, true) ? 1 : 0;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_vdui_is_open(void) {
    return (spudec::is_spu_database_active() && spudec::global_vdui().is_open()) ? 1 : 0;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_vdui_refresh(int force_redecompile) {
    if (!spudec::is_spu_database_active() || !spudec::global_vdui().is_open()) return 0;
    return spudec::global_vdui().refresh_view(force_redecompile != 0) ? 1 : 0;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_vdui_switch_to(uint64_t ea, int push_history) {
    if (!spudec::is_spu_database_active() || !spudec::global_vdui().is_open()) return 0;
    return spudec::global_vdui().switch_to(ea, push_history != 0) ? 1 : 0;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_vdui_get_state(
    uint64_t *out_func_ea,
    uint64_t *out_cfunc_handle,
    int *out_lineno,
    int *out_col,
    uint32_t *out_citem_id) {
    if (!spudec::is_spu_database_active()) return 0;
    spudec::SpuVdui &v = spudec::global_vdui();
    if (!v.is_open() || !v.current_func_ea().has_value()) return 0;

    if (out_func_ea) *out_func_ea = *v.current_func_ea();
    if (out_cfunc_handle) *out_cfunc_handle = spudec::register_cfunc_handle(v.cfunc());
    int ln = v.selected_line(), col = 0;
    v.get_cursor_pos(&ln, &col, false);
    if (out_lineno) *out_lineno = ln;
    if (out_col) *out_col = col;
    if (out_citem_id) {
        spudec::citem_t *it = v.get_current_citem(false);
        *out_citem_id = it ? it->obj_id : UINT32_MAX;
    }
    return 1;
}

SPUDEC_API_EXPORT char * __cdecl spudec_abi_get_user_data_json(uint64_t func_ea) {
    if (!spudec::is_spu_database_active()) return nullptr;
    uint64_t fea = spudec::normalize_func_ea(func_ea);
    spudec::FuncUserData ud = spudec::idadb::get_func_data(fea);
    return spudec::dup_cstr(spudec::serialize_func_user_data_json(ud));
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_set_user_data_json(uint64_t func_ea, const char *json_str) {
    if (!spudec::is_spu_database_active() || !json_str) return 0;
    uint64_t fea = spudec::normalize_func_ea(func_ea);
    spudec::FuncUserData ud;
    if (!spudec::parse_func_user_data_json(json_str, ud)) return 0;
    spudec::idadb::set_func_data(fea, ud);
    spudec::global_summary_cache().invalidate_func(fea);
    if (spudec::global_vdui().is_open() && spudec::global_vdui().current_func_ea() == fea) {
        spudec::global_vdui().refresh_view(true);
    }
    return 1;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_rename_lvar(uint64_t func_ea, const char *old_name, const char *new_name) {
    if (!spudec::is_spu_database_active() || !old_name || !new_name) return 0;
    uint64_t fea = spudec::normalize_func_ea(func_ea);
    spudec::cfuncptr_t cf = spudec::decompile_or_get_cached(fea, false);
    std::string canon = old_name;
    if (cf) {
        for (const auto &lv : cf->lvars) {
            if (lv.name == old_name || lv.canonical_name == old_name) {
                canon = lv.canonical_name;
                spudec::idadb::set_var_locator(fea, lv.location.to_key(), std::string(new_name), std::nullopt);
                break;
            }
        }
    }
    spudec::idadb::set_var_rename(fea, canon, new_name);
    spudec::global_summary_cache().invalidate_func(fea);
    if (spudec::global_vdui().is_open() && spudec::global_vdui().current_func_ea() == fea) {
        spudec::global_vdui().refresh_view(true);
    }
    return 1;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_set_lvar_type(uint64_t func_ea, const char *var_name, const char *type_str) {
    if (!spudec::is_spu_database_active() || !var_name || !type_str) return 0;
    uint64_t fea = spudec::normalize_func_ea(func_ea);
    spudec::cfuncptr_t cf = spudec::decompile_or_get_cached(fea, false);
    std::string canon = var_name;
    if (cf) {
        for (const auto &lv : cf->lvars) {
            if (lv.name == var_name || lv.canonical_name == var_name) {
                canon = lv.canonical_name;
                spudec::idadb::set_var_locator(fea, lv.location.to_key(), std::nullopt, std::string(type_str));
                break;
            }
        }
    }
    spudec::idadb::set_var_type(fea, canon, type_str);
    spudec::global_summary_cache().invalidate_func(fea);
    if (spudec::global_vdui().is_open() && spudec::global_vdui().current_func_ea() == fea) {
        spudec::global_vdui().refresh_view(true);
    }
    return 1;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_set_proto(uint64_t func_ea, const char *proto_str) {
    if (!spudec::is_spu_database_active() || !proto_str) return 0;
    uint64_t fea = spudec::normalize_func_ea(func_ea);
    std::string s(proto_str);
    if (!s.empty() && !spudec::abi::parse_proto(s).has_value()) return 0;
    spudec::idadb::set_func_proto(fea, s);
    if (!s.empty()) {
        spudec::apply_proto_to_ida(static_cast<ea_t>(fea), s);
    } else {
        del_tinfo(static_cast<ea_t>(fea));
    }
    spudec::global_summary_cache().clear_arity_and_demand();
    spudec::global_summary_cache().invalidate_func(fea);
    if (spudec::global_vdui().is_open()) spudec::global_vdui().refresh_view(true);
    return 1;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_set_cmt(uint64_t func_ea, uint64_t stmt_ea, const char *cmt_str) {
    if (!spudec::is_spu_database_active() || !cmt_str) return 0;
    uint64_t fea = spudec::normalize_func_ea(func_ea);
    spudec::idadb::set_statement_cmt(fea, stmt_ea, cmt_str);
    spudec::global_summary_cache().invalidate_func(fea);
    if (spudec::global_vdui().is_open() && spudec::global_vdui().current_func_ea() == fea) {
        spudec::global_vdui().refresh_view(true);
    }
    return 1;
}

SPUDEC_API_EXPORT char * __cdecl spudec_abi_get_cmt(uint64_t func_ea, uint64_t stmt_ea) {
    if (!spudec::is_spu_database_active()) return nullptr;
    uint64_t fea = spudec::normalize_func_ea(func_ea);
    auto cmt = spudec::idadb::get_statement_cmt(fea, stmt_ea);
    return cmt.has_value() ? spudec::dup_cstr(*cmt) : nullptr;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_set_numform(uint64_t func_ea, uint64_t stmt_ea, int op_idx, const char *form_str) {
    if (!spudec::is_spu_database_active() || !form_str) return 0;
    uint64_t fea = spudec::normalize_func_ea(func_ea);
    spudec::idadb::set_numform(fea, stmt_ea, op_idx, form_str);
    spudec::global_summary_cache().invalidate_func(fea);
    if (spudec::global_vdui().is_open() && spudec::global_vdui().current_func_ea() == fea) {
        spudec::global_vdui().refresh_view(true);
    }
    return 1;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_invert_if(uint64_t func_ea, uint64_t branch_ea) {
    if (!spudec::is_spu_database_active()) return 0;
    uint64_t fea = spudec::normalize_func_ea(func_ea);
    bool inv = spudec::idadb::toggle_iflag(fea, branch_ea);
    spudec::global_summary_cache().invalidate_func(fea);
    if (spudec::global_vdui().is_open() && spudec::global_vdui().current_func_ea() == fea) {
        spudec::global_vdui().refresh_view(true);
    }
    return inv ? 1 : 0;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_get_hide_casts(void) {
    return spudec::idadb::get_hide_casts() ? 1 : 0;
}

SPUDEC_API_EXPORT void __cdecl spudec_abi_set_hide_casts(int hide) {
    spudec::idadb::set_hide_casts(hide != 0);
    if (spudec::global_vdui().is_open()) {
        spudec::global_vdui().refresh_view(true);
    }
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_reset_overrides(uint64_t func_ea) {
    if (!spudec::is_spu_database_active()) return 0;
    uint64_t fea = spudec::normalize_func_ea(func_ea);
    spudec::idadb::clear_func_overrides(fea);
    spudec::global_summary_cache().clear_arity_and_demand();
    spudec::global_summary_cache().invalidate_func(fea);
    if (spudec::global_vdui().is_open()) spudec::global_vdui().refresh_view(true);
    return 1;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_register_callback(spudec_abi_event_cb_t cb, void *ud) {
    if (!cb) return -1;
    return spudec::register_event_callback(
        [cb, ud](spudec::spudec_event_t ev, void *arg0, void *arg1) -> int {
            uint64_t cf_handle = 0;
            uint64_t aux = 0;
            if (ev == spudec::spe_maturity || ev == spudec::spe_func_printed) {
                auto *cf_raw = static_cast<spudec::cfunc_t *>(arg0);
                if (cf_raw) {
                    // Wrap non-owning alias shared_ptr so script can inspect/mutate cfunc_t during maturity!
                    spudec::cfuncptr_t alias(std::shared_ptr<spudec::cfunc_t>{}, cf_raw);
                    cf_handle = spudec::register_cfunc_handle(alias);
                }
                if (ev == spudec::spe_maturity) aux = 7; // CMAT_FINAL
            } else if (ev == spudec::spe_lifting_done || ev == spudec::spe_ssa_optimized) {
                auto *fn = static_cast<spudec::Function *>(arg0);
                if (fn) aux = fn->start_ea;
            } else if (ev >= spudec::spe_open_pseudocode && ev <= spudec::spe_populating_popup) {
                auto *v = static_cast<spudec::SpuVdui *>(arg0);
                if (v && v->cfunc()) {
                    cf_handle = spudec::register_cfunc_handle(v->cfunc());
                }
                if (ev == spudec::spe_keyboard && arg1) {
                    aux = static_cast<uint64_t>(*static_cast<int *>(arg1));
                }
            }
            return cb(static_cast<int>(ev), cf_handle, aux, ud);
        });
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_unregister_callback(int cb_handle) {
    return spudec::unregister_event_callback(cb_handle) ? 1 : 0;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_register_optinsn(spudec_abi_optinsn_cb_t cb, void *ud) {
    if (!cb) return -1;
    return spudec::opt::register_optinsn_hook(
        [cb, ud](spudec::Function &fn, spudec::Block &blk, spudec::Insn &ins) -> int {
            int insn_idx = -1;
            for (size_t i = 0; i < blk.insns.size(); ++i) {
                if (blk.insns[i].get() == &ins) {
                    insn_idx = static_cast<int>(i);
                    break;
                }
            }
            auto &st = spudec::api_state();
            spudec::Function *prev = st.active_opt_func;
            st.active_opt_func = &fn;
            int rc = cb(fn.start_ea, blk.id, insn_idx, static_cast<int>(ins.op), ins.ea, ud);
            st.active_opt_func = prev;
            return rc;
        });
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_unregister_optinsn(int hook_handle) {
    return spudec::opt::unregister_optinsn_hook(hook_handle) ? 1 : 0;
}

SPUDEC_API_EXPORT int __cdecl spudec_abi_optinsn_nop(uint64_t func_ea, int block_id, int insn_idx) {
    auto &st = spudec::api_state();
    if (!st.active_opt_func || st.active_opt_func->start_ea != func_ea) return 0;
    spudec::Block *blk = nullptr;
    for (const auto &b : st.active_opt_func->blocks) {
        if (b && b->id == block_id) {
            blk = b.get();
            break;
        }
    }
    if (!blk || insn_idx < 0 || insn_idx >= static_cast<int>(blk->insns.size())) return 0;
    spudec::Insn *ins = blk->insns[static_cast<size_t>(insn_idx)].get();
    if (!ins || ins->op == spudec::Op::NOP) return 0;
    ins->op = spudec::Op::NOP;
    ins->has_dst = false;
    ins->dst_reg = -1;
    ins->dst_ver = -1;
    ins->srcs.clear();
    return 1;
}

} // extern "C"