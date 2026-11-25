#include <ida.hpp>
#include <demangle.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include "summary_cache.hpp"
#include "ida_provider.hpp"
#include "db.hpp"
#include "spudec/abi.hpp"
#include "spudec/lanes.hpp"
#include "spudec/regs.hpp"

#include <cstdio>

namespace spudec {

SummaryCache &global_summary_cache() {
    static SummaryCache s_cache;
    return s_cache;
}

void SummaryCache::clear_all() {
    shared_names_ready_ = false;
    shared_names_.clear();
    func_names_.clear();
    demangled_count_ = 0;

    classes_ready_ = false;
    classes_.clear();
    member_classes_.clear();

    strings_.clear();
    symbols_.clear();
    frame_members_.clear();
    insn_slots_.clear();

    clear_arity_and_demand();
    cfunc_cache_.clear();
}

void SummaryCache::clear_arity_and_demand() {
    arities_.clear();
    arity_active_.clear();
    variadics_.clear();
    variadic_active_.clear();
    param_demands_.clear();
    demand_active_.clear();
}

void SummaryCache::invalidate_func(uint64_t func_ea) {
    cfunc_cache_.erase(func_ea);
    arities_.erase(func_ea);
    variadics_.erase(func_ea);
    param_demands_.erase(func_ea);
    frame_members_.erase(func_ea);
    insn_slots_.clear();
}

void SummaryCache::invalidate_names_and_symbols() {
    shared_names_ready_ = false;
    shared_names_.clear();
    func_names_.clear();
    demangled_count_ = 0;
    classes_ready_ = false;
    classes_.clear();
    member_classes_.clear();
    symbols_.clear();
    cfunc_cache_.clear();
}

void SummaryCache::invalidate_types() {
    clear_arity_and_demand();
    frame_members_.clear();
    insn_slots_.clear();
    cfunc_cache_.clear();
}

ssize_t idaapi SummaryCache::on_event(ssize_t code, va_list va) {
    switch (code) {
        case idb_event::renamed: {
            ea_t ea = va_arg(va, ea_t);
            invalidate_names_and_symbols();
            if (func_t *pfn = get_func(ea)) {
                invalidate_func(static_cast<uint64_t>(pfn->start_ea));
            }
            break;
        }
        case idb_event::ti_changed: {
            ea_t ea = va_arg(va, ea_t);
            invalidate_types();
            if (func_t *pfn = get_func(ea)) {
                invalidate_func(static_cast<uint64_t>(pfn->start_ea));
            }
            break;
        }
        case idb_event::lt_udm_created:
        case idb_event::lt_udm_deleted:
        case idb_event::lt_udm_renamed:
        case idb_event::lt_udm_changed:
        case idb_event::lt_udt_expanded:
        case idb_event::local_types_changed:
        case idb_event::frame_expanded: {
            invalidate_types();
            break;
        }
        case idb_event::make_data:
        case idb_event::destroyed_items: {
            strings_.clear();
            symbols_.clear();
            cfunc_cache_.clear();
            break;
        }
        case idb_event::func_added:
        case idb_event::func_updated:
        case idb_event::deleting_func: {
            func_t *pfn = va_arg(va, func_t *);
            if (pfn) {
                invalidate_func(static_cast<uint64_t>(pfn->start_ea));
            } else {
                clear_all();
            }
            break;
        }
        default:
            break;
    }
    return 0;
}

cfuncptr_t SummaryCache::get_cached_cfunc(uint64_t func_ea) const {
    auto it = cfunc_cache_.find(func_ea);
    return (it != cfunc_cache_.end()) ? it->second : nullptr;
}

void SummaryCache::put_cached_cfunc(uint64_t func_ea, cfuncptr_t cf) {
    cfunc_cache_[func_ea] = std::move(cf);
}

void SummaryCache::ensure_shared_names() {
    if (shared_names_ready_) return;
    shared_names_ready_ = true;
    shared_names_.clear();

    std::unordered_map<std::string, int> counts;
    const size_t nfn = get_func_qty();
    for (size_t i = 0; i < nfn; ++i) {
        func_t *f = getn_func(i);
        if (!f) continue;
        qstring qnm;
        if (get_name(&qnm, f->start_ea) <= 0 || qnm.empty()) continue;
        if (auto d = demangle_spu_name(std::string(qnm.c_str(), qnm.length())); d.has_value()) {
            ++counts[*d];
        }
    }
    for (const auto &[nm, cnt] : counts) {
        if (cnt > 1) shared_names_.insert(nm);
    }
}

std::string SummaryCache::get_func_name(uint64_t ea) {
    auto it = func_names_.find(ea);
    if (it != func_names_.end()) return it->second;

    ensure_shared_names();
    qstring qraw;
    get_name(&qraw, static_cast<ea_t>(ea));
    std::string raw(qraw.c_str(), qraw.length());
    std::string out;

    if (auto d = demangle_spu_name(raw); d.has_value()) {
        ++demangled_count_;
        if (shared_names_.find(*d) != shared_names_.end()) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "_%llX", static_cast<unsigned long long>(ea));
            out = *d + buf;
        } else {
            out = *d;
        }
    } else if (!raw.empty()) {
        out = raw;
    } else {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "sub_%llX", static_cast<unsigned long long>(ea));
        out = buf;
    }

    func_names_[ea] = out;
    return out;
}

void SummaryCache::ensure_class_set() {
    if (classes_ready_) return;
    classes_ready_ = true;
    classes_.clear();

    const size_t nnames = get_nlist_size();
    for (size_t i = 0; i < nnames; ++i) {
        const char *cname = get_nlist_name(i);
        if (!cname || !*cname) continue;
        std::string raw(cname);
        if (raw.rfind("_ZTV", 0) == 0) {
            qstring qd;
            if (demangle_name(&qd, raw.c_str(), MNG_NODEFINIT) > 0 && !qd.empty()) {
                std::string ds(qd.c_str(), qd.length());
                auto fp = ds.find("for'");
                if (fp != std::string::npos) {
                    std::string cls = ds.substr(fp + 4);
                    while (!cls.empty() && (cls.back() == ' ' || cls.back() == '>')) cls.pop_back();
                    size_t b = 0;
                    while (b < cls.size() && cls[b] == ' ') ++b;
                    classes_.insert(cls.substr(b));
                }
            }
            continue;
        }

        auto d = demangle_spu_name(raw);
        if (!d.has_value()) continue;
        auto sep = d->rfind("::");
        if (sep == std::string::npos) continue;
        std::string scope = d->substr(0, sep);
        std::string last = d->substr(sep + 2);
        auto sep2 = scope.rfind("::");
        std::string cls = (sep2 == std::string::npos) ? scope : scope.substr(sep2 + 2);
        if (last == cls || last == ("~" + cls)) {
            classes_.insert(scope);
        }
    }
}

std::optional<std::string> SummaryCache::get_member_class(uint64_t func_ea) {
    auto it = member_classes_.find(func_ea);
    if (it != member_classes_.end()) return it->second;

    ensure_class_set();
    std::optional<std::string> res;
    qstring qraw;
    if (get_name(&qraw, static_cast<ea_t>(func_ea)) > 0 && !qraw.empty()) {
        if (auto d = demangle_spu_name(std::string(qraw.c_str(), qraw.length())); d.has_value()) {
            auto sep = d->rfind("::");
            if (sep != std::string::npos) {
                std::string scope = d->substr(0, sep);
                if (classes_.find(scope) != classes_.end()) {
                    res = scope;
                }
            }
        }
    }
    member_classes_[func_ea] = res;
    return res;
}

std::optional<std::string> SummaryCache::get_string_literal(const IdaDatabaseProvider &prov, uint64_t ea) {
    auto it = strings_.find(ea);
    if (it != strings_.end()) return it->second;
    auto res = prov.lookup_string_uncached(ea);
    strings_[ea] = res;
    return res;
}

std::optional<std::string> SummaryCache::get_symbol_name(const IdaDatabaseProvider &prov, uint64_t ea) {
    auto it = symbols_.find(ea);
    if (it != symbols_.end()) return it->second;
    auto res = prov.lookup_symbol_uncached(ea);
    symbols_[ea] = res;
    return res;
}

const std::unordered_map<uint64_t, StackSlotHit> &SummaryCache::ensure_frame_members(uint64_t func_start_ea) {
    auto it = frame_members_.find(func_start_ea);
    if (it != frame_members_.end()) return it->second;

    auto &out = frame_members_[func_start_ea];
    func_t *pfn = get_func(static_cast<ea_t>(func_start_ea));
    if (!pfn) return out;

    tinfo_t ftif;
    if (get_func_frame(&ftif, pfn)) {
        udt_type_data_t udt;
        if (ftif.get_udt_details(&udt)) {
            for (const auto &m : udt) {
                if (!m.name.empty()) {
                    out[static_cast<uint64_t>(m.offset / 8)] =
                        StackSlotHit{std::string(m.name.c_str(), m.name.length()),
                                     static_cast<int>(m.size / 8)};
                }
            }
        }
    }
    return out;
}

std::optional<StackSlotHit> SummaryCache::get_stack_slot(uint64_t insn_ea) {
    auto it = insn_slots_.find(insn_ea);
    if (it != insn_slots_.end()) return it->second;

    std::optional<StackSlotHit> res;
    func_t *pfn = get_func(static_cast<ea_t>(insn_ea));
    if (pfn) {
        insn_t insn;
        if (decode_insn(&insn, static_cast<ea_t>(insn_ea)) > 0) {
            const auto &members = ensure_frame_members(static_cast<uint64_t>(pfn->start_ea));
            for (int n = 0; n < UA_MAXOP; ++n) {
                const op_t &op = insn.ops[n];
                if (op.type == o_void) break;
                if (op.type != o_displ && op.type != o_imm) continue;
                ea_t soff = calc_stkvar_struc_offset(pfn, insn, n);
                if (soff == BADADDR) continue;
                auto mit = members.find(static_cast<uint64_t>(soff));
                if (mit != members.end() && !mit->second.name.empty()) {
                    res = mit->second;
                    break;
                }
                qstring qnm;
                if (build_stkvar_name(&qnm, pfn, static_cast<sval_t>(soff)) > 0 && !qnm.empty()) {
                    res = StackSlotHit{std::string(qnm.c_str(), qnm.length()), 0};
                    break;
                }
            }
        }
    }
    insn_slots_[insn_ea] = res;
    return res;
}

std::optional<uint64_t> SummaryCache::resolve_thunk_target(uint64_t ea) const {
    func_t *pfn = get_func(static_cast<ea_t>(ea));
    if (!pfn || pfn->start_ea != static_cast<ea_t>(ea)) return std::nullopt;
    if (pfn->end_ea - pfn->start_ea != 4) return std::nullopt;

    uint8_t b[4];
    if (get_bytes(b, 4, static_cast<ea_t>(ea)) != 4) return std::nullopt;
    uint32_t word = (static_cast<uint32_t>(b[0]) << 24) |
                    (static_cast<uint32_t>(b[1]) << 16) |
                    (static_cast<uint32_t>(b[2]) << 8) |
                    static_cast<uint32_t>(b[3]);
    uint32_t op9 = (word >> 23) & 0x1FFu;
    // `br` (op9 = 0x064) or `bra` (op9 = 0x060)
    if (op9 != 0x064u && op9 != 0x060u) return std::nullopt;

    xrefblk_t xb;
    for (bool ok = xb.first_from(static_cast<ea_t>(ea), XREF_FAR); ok; ok = xb.next_from()) {
        if (!xb.iscode) continue;
        func_t *tf = get_func(xb.to);
        if (tf && tf->start_ea != static_cast<ea_t>(ea)) {
            return static_cast<uint64_t>(tf->start_ea);
        }
    }
    return std::nullopt;
}

std::optional<int> SummaryCache::get_callee_arity(IdaDatabaseProvider &prov, uint64_t callee_ea) {
    auto it = arities_.find(callee_ea);
    if (it != arities_.end()) return it->second;
    if (!arity_active_.insert(callee_ea).second) return std::nullopt;

    std::optional<int> n;
    // 1. User prototype override in "$ spudec" netnode
    auto udata = idadb::get_func_data(callee_ea);
    if (udata.proto.has_value() && !udata.proto->empty()) {
        if (auto sig = abi::parse_proto(*udata.proto, "fn"); sig.has_value()) {
            n = static_cast<int>(sig->params.size());
        }
    }

    // 2. IDA tinfo_t prototype
    if (!n.has_value()) {
        tinfo_t tif;
        if (get_tinfo(&tif, static_cast<ea_t>(callee_ea)) && tif.is_func()) {
            int nargs = tif.get_nargs();
            if (nargs >= 0) n = nargs;
        }
    }

    // 3. Thunk / trampoline resolution
    if (!n.has_value()) {
        if (auto tgt = resolve_thunk_target(callee_ea); tgt.has_value() && *tgt != callee_ea) {
            n = get_callee_arity(prov, *tgt);
        }
    }

    // 4. Shallow IR recovery on callee body
    if (!n.has_value()) {
        func_t *pfn = get_func(static_cast<ea_t>(callee_ea));
        if (pfn && static_cast<uint64_t>(pfn->start_ea) == callee_ea) {
            n = analyze_callee_arity(prov, callee_ea);
        }
    }

    arity_active_.erase(callee_ea);
    arities_[callee_ea] = n;
    return n;
}

bool SummaryCache::is_callee_variadic(IdaDatabaseProvider &prov, uint64_t callee_ea) {
    auto it = variadics_.find(callee_ea);
    if (it != variadics_.end()) return it->second;
    if (!variadic_active_.insert(callee_ea).second) return false;

    bool res = false;
    func_t *pfn = get_func(static_cast<ea_t>(callee_ea));
    if (pfn && static_cast<uint64_t>(pfn->start_ea) == callee_ea) {
        res = analyze_is_variadic(prov, callee_ea);
    }
    variadic_active_.erase(callee_ea);
    variadics_[callee_ea] = res;
    return res;
}

std::optional<std::unordered_map<int, uint16_t>> SummaryCache::get_callee_param_demand(
    IdaDatabaseProvider &prov, uint64_t callee_ea) {
    auto it = param_demands_.find(callee_ea);
    if (it != param_demands_.end()) return it->second;

    std::unordered_map<int, uint16_t> wide;
    for (int r = regs::ARG_FIRST; r <= regs::ARG_LAST; ++r) wide[r] = lanes::ALL;

    if (!demand_active_.insert(callee_ea).second) {
        return wide;
    }

    func_t *pfn = get_func(static_cast<ea_t>(callee_ea));
    if (!pfn || static_cast<uint64_t>(pfn->start_ea) != callee_ea) {
        demand_active_.erase(callee_ea);
        return wide;
    }

    auto out = analyze_param_demand(prov, callee_ea);
    demand_active_.erase(callee_ea);
    param_demands_[callee_ea] = out;
    return out;
}

} // namespace spudec
