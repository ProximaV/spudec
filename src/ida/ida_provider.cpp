#include <ida.hpp>
#include <bytes.hpp>
#include <demangle.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <ua.hpp>

#include "ida_provider.hpp"
#include "summary_cache.hpp"
#include "spudec/abi.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <unordered_set>

namespace spudec {

namespace {

constexpr size_t STR_MIN_LEN = 4;
constexpr size_t STR_MAX_LEN = 96;
constexpr size_t STR_WINDOW  = 4096;

bool is_name_ok_char(char c) {
    unsigned char u = static_cast<unsigned char>(c);
    return std::isalnum(u) || c == '_' || c == ':' || c == '~' || c == '<' || c == '>' || c == ',';
}

std::string sanitise_demangled(const std::string &name) {
    bool all_ok = true;
    for (char c : name) {
        if (!is_name_ok_char(c)) { all_ok = false; break; }
    }
    if (all_ok) return name;

    std::string out;
    out.reserve(name.size());
    for (char c : name) {
        char mapped = is_name_ok_char(c) ? c : '_';
        if (mapped == '_' && !out.empty() && out.back() == '_') continue;
        out.push_back(mapped);
    }
    while (!out.empty() && out.front() == '_') out.erase(out.begin());
    while (!out.empty() && out.back() == '_') out.pop_back();
    return out.empty() ? name : out;
}

bool has_cpp_operator_token(const std::string &s) {
    size_t pos = 0;
    while ((pos = s.find("operator", pos)) != std::string::npos) {
        bool anchored = (pos == 0) || (pos >= 2 && s[pos - 1] == ':' && s[pos - 2] == ':');
        size_t after = pos + 8;
        bool non_ident_after = (after >= s.size()) ||
                               !(std::isalnum(static_cast<unsigned char>(s[after])) || s[after] == '_');
        if (anchored && non_ident_after) return true;
        pos += 8;
    }
    return false;
}

bool is_arithmetic_progression(const uint8_t *body, size_t len) {
    if (len < 4) return false;
    int stride = static_cast<int>(body[1]) - static_cast<int>(body[0]);
    if (stride == 1) return false;
    for (size_t i = 0; i + 1 < len; ++i) {
        if (static_cast<int>(body[i + 1]) - static_cast<int>(body[i]) != stride) return false;
    }
    return stride != 0 || len >= 8;
}

std::string trim_s(const std::string &s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

} // namespace

std::optional<std::string> demangle_spu_name(const std::string &raw) {
    if (raw.empty()) return std::nullopt;
    qstring qdem;
    if (demangle_name(&qdem, raw.c_str(), MNG_NODEFINIT) <= 0 || qdem.empty()) {
        return std::nullopt;
    }
    std::string d(qdem.c_str(), qdem.length());
    if (d == raw) return std::nullopt;
    if (has_cpp_operator_token(d)) return d;
    auto lp = d.find('(');
    if (lp != std::string::npos) {
        d.erase(lp);
        while (!d.empty() && std::isspace(static_cast<unsigned char>(d.back()))) d.pop_back();
    }
    return sanitise_demangled(d);
}

std::string escape_c_string_literal(const std::string &text, size_t max_len) {
    bool elided = text.size() > max_len;
    size_t lim = elided ? max_len : text.size();
    std::string out = "\"";
    out.reserve(lim + 8);
    for (size_t i = 0; i < lim; ++i) {
        unsigned char c = static_cast<unsigned char>(text[i]);
        switch (c) {
            case '\t': out += "\\t"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            default:   out.push_back(static_cast<char>(c)); break;
        }
    }
    if (elided) out += "...";
    out.push_back('"');
    return out;
}

bool looks_like_text_bytes(const uint8_t *buf, size_t len) {
    if (len < STR_MIN_LEN) return false;
    bool has_alnum = false;
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = buf[i];
        bool ok = (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D;
        if (!ok) return false;
        if (std::isalnum(b)) has_alnum = true;
    }
    if (!has_alnum) return false;
    if (is_arithmetic_progression(buf, len)) return false;
    return true;
}

void ensure_spu_types() {
    static bool s_registered = false;
    if (s_registered) return;
    static const char *const kHeader =
        "typedef unsigned char u8;\n"
        "typedef unsigned short u16;\n"
        "typedef unsigned int u32;\n"
        "typedef unsigned long long u64;\n"
        "typedef signed char s8;\n"
        "typedef signed short s16;\n"
        "typedef signed int s32;\n"
        "typedef signed long long s64;\n"
        "typedef struct { unsigned char b[16]; } qword;\n"
        "typedef struct { unsigned char b[16]; } vec_uchar16;\n"
        "typedef struct { signed char b[16]; } vec_char16;\n"
        "typedef struct { unsigned short h[8]; } vec_ushort8;\n"
        "typedef struct { signed short h[8]; } vec_short8;\n"
        "typedef struct { unsigned int w[4]; } vec_uint4;\n"
        "typedef struct { signed int w[4]; } vec_int4;\n"
        "typedef struct { unsigned long long d[2]; } vec_ullong2;\n"
        "typedef struct { signed long long d[2]; } vec_llong2;\n"
        "typedef struct { float f[4]; } vec_float4;\n"
        "typedef struct { double d[2]; } vec_double2;\n"
        "typedef struct { unsigned char b[16]; } qword_unaligned;\n";
    parse_decls(nullptr, kHeader, nullptr, HTI_DCL);
    s_registered = true;
}

bool parse_c_type_tinfo(const std::string &type_str, tinfo_t *out_tif) {
    if (!out_tif) return false;
    ensure_spu_types();
    std::string clean = trim_s(type_str);
    while (!clean.empty() && clean.back() == ';') clean.pop_back();
    clean = trim_s(clean);
    if (clean.empty()) return false;

    tinfo_t tif;
    qstring qname;
    if (parse_decl(&tif, &qname, nullptr, (clean + ";").c_str(), PT_TYP | PT_SIL)) {
        *out_tif = tif;
        return true;
    }
    if (parse_decl(&tif, &qname, nullptr, (clean + " _spudec_var;").c_str(), PT_SIL)) {
        *out_tif = tif;
        return true;
    }

    int stars = 0;
    std::string bare = clean;
    while (!bare.empty() && bare.back() == '*') {
        ++stars;
        bare.pop_back();
        bare = trim_s(bare);
    }
    static const char *const pfxs[] = {"const ", "volatile ", "struct ", "union ", "enum "};
    for (const char *pfx : pfxs) {
        size_t plen = std::strlen(pfx);
        if (bare.size() >= plen && bare.compare(0, plen, pfx) == 0) {
            bare = trim_s(bare.substr(plen));
        }
    }
    if (!bare.empty() && tif.get_named_type(nullptr, bare.c_str())) {
        for (int i = 0; i < stars; ++i) {
            tinfo_t ptif;
            ptif.create_ptr(tif);
            tif = ptif;
        }
        *out_tif = tif;
        return true;
    }
    return false;
}

bool apply_proto_to_ida(ea_t ea, const std::string &proto_str) {
    ensure_spu_types();
    std::string clean = trim_s(proto_str);
    while (!clean.empty() && clean.back() == ';') clean.pop_back();
    if (clean.empty()) return false;

    const std::string cands[4] = {
        clean + ";",
        abi::sanitize_decl_for_ida(proto_str, false, false),
        abi::sanitize_decl_for_ida(proto_str, true, false),
        abi::sanitize_decl_for_ida(proto_str, true, true),
    };
    std::unordered_set<std::string> seen;
    for (const auto &decl : cands) {
        if (decl.empty() || !seen.insert(decl).second) continue;
        tinfo_t tif;
        qstring qname;
        if (parse_decl(&tif, &qname, nullptr, decl.c_str(), PT_SIL) && tif.is_func()) {
            apply_tinfo(ea, tif, TINFO_DEFINITE);
            return true;
        }
    }
    return false;
}

std::vector<std::string> find_ida_enum_matches(uint64_t val) {
    std::vector<std::string> matches;
    std::unordered_set<std::string> seen;
    const til_t *til = get_idati();
    if (!til) return matches;

    const uint32 limit = get_ordinal_limit(til);
    for (uint32 ord = 1; ord < limit; ++ord) {
        tinfo_t tif;
        if (!tif.get_numbered_type(til, ord) || !tif.is_enum()) continue;
        enum_type_data_t etd;
        if (!tif.get_enum_details(&etd)) continue;
        for (const auto &edm : etd) {
            if (edm.value == val && !edm.name.empty()) {
                std::string nm(edm.name.c_str(), edm.name.length());
                if (seen.insert(nm).second) {
                    matches.push_back(std::move(nm));
                }
            }
        }
    }
    return matches;
}

bool IdaDatabaseProvider::is_loaded(uint64_t ea) const {
    return ::is_loaded(static_cast<ea_t>(ea));
}

bool IdaDatabaseProvider::read_u32_be(uint64_t ea, uint32_t *out_word) const {
    uint8_t b[4];
    if (get_bytes(b, 4, static_cast<ea_t>(ea)) != 4) return false;
    *out_word = (static_cast<uint32_t>(b[0]) << 24) |
                (static_cast<uint32_t>(b[1]) << 16) |
                (static_cast<uint32_t>(b[2]) << 8) |
                static_cast<uint32_t>(b[3]);
    return true;
}

size_t IdaDatabaseProvider::read_bytes(uint64_t ea, uint8_t *buf, size_t max_len) const {
    ssize_t n = get_bytes(buf, static_cast<ssize_t>(max_len), static_cast<ea_t>(ea), GMB_READALL);
    if (n > 0) return static_cast<size_t>(n);
    // Fallback byte-by-byte near segment end
    size_t got = 0;
    for (; got < max_len; ++got) {
        ea_t cur = static_cast<ea_t>(ea + got);
        if (!::is_loaded(cur)) break;
        buf[got] = static_cast<uint8_t>(get_byte(cur));
    }
    return got;
}

bool IdaDatabaseProvider::get_func_start(uint64_t ea, uint64_t *out_start_ea) const {
    func_t *pfn = get_func(static_cast<ea_t>(ea));
    if (!pfn) return false;
    *out_start_ea = static_cast<uint64_t>(pfn->start_ea);
    return true;
}

bool IdaDatabaseProvider::get_flowchart(uint64_t func_ea,
                                        uint64_t *out_func_start,
                                        std::vector<FlowBlockRange> *out_blocks) const {
    func_t *pfn = get_func(static_cast<ea_t>(func_ea));
    if (!pfn) return false;
    *out_func_start = static_cast<uint64_t>(pfn->start_ea);
    out_blocks->clear();

    qflow_chart_t fc("", pfn, pfn->start_ea, pfn->end_ea, 0);
    const int count = fc.size();
    out_blocks->reserve(static_cast<size_t>(count));
    for (int i = 0; i < count; ++i) {
        const qbasic_block_t &bb = fc.blocks[i];
        // Exclude external 1-instruction blocks outside the function that qflow_chart_t may append
        if (i >= fc.nproper && !func_contains(pfn, bb.start_ea)) {
            continue;
        }
        FlowBlockRange r;
        r.id = i;
        r.start_ea = static_cast<uint64_t>(bb.start_ea);
        r.end_ea = static_cast<uint64_t>(bb.end_ea);
        for (int s : bb.succ) r.succs.push_back(s);
        for (int p : bb.pred) r.preds.push_back(p);
        out_blocks->push_back(std::move(r));
    }

    // Remap block IDs densely if any external block was skipped
    if (static_cast<int>(out_blocks->size()) != count) {
        std::unordered_map<int, int> old_to_new;
        for (int ni = 0; ni < static_cast<int>(out_blocks->size()); ++ni) {
            old_to_new[(*out_blocks)[ni].id] = ni;
            (*out_blocks)[ni].id = ni;
        }
        for (auto &blk : *out_blocks) {
            std::vector<int> ns, np;
            for (int s : blk.succs) {
                if (auto it = old_to_new.find(s); it != old_to_new.end()) ns.push_back(it->second);
            }
            for (int p : blk.preds) {
                if (auto it = old_to_new.find(p); it != old_to_new.end()) np.push_back(it->second);
            }
            blk.succs = std::move(ns);
            blk.preds = std::move(np);
        }
    }
    return !out_blocks->empty();
}

std::vector<uint64_t> IdaDatabaseProvider::get_func_items(uint64_t func_ea) const {
    std::vector<uint64_t> out;
    func_t *pfn = get_func(static_cast<ea_t>(func_ea));
    if (!pfn) return out;
    func_item_iterator_t fii;
    for (bool ok = fii.set(pfn); ok; ok = fii.next_addr()) {
        out.push_back(static_cast<uint64_t>(fii.current()));
    }
    return out;
}

std::string IdaDatabaseProvider::get_func_name(uint64_t ea) const {
    if (cache_) return cache_->get_func_name(ea);
    qstring qnm;
    if (get_name(&qnm, static_cast<ea_t>(ea)) > 0 && !qnm.empty()) {
        std::string raw(qnm.c_str(), qnm.length());
        if (auto d = demangle_spu_name(raw); d.has_value()) return *d;
        return raw;
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "sub_%llX", static_cast<unsigned long long>(ea));
    return buf;
}

std::optional<std::string> IdaDatabaseProvider::lookup_string_uncached(uint64_t ea) const {
    if (ea == 0 || !::is_loaded(static_cast<ea_t>(ea))) return std::nullopt;

    // 1. Defined IDA string literal at or covering `ea`
    ea_t head = get_item_head(static_cast<ea_t>(ea));
    if (is_strlit(get_flags(head))) {
        qstring qbuf;
        if (get_strlit_contents(&qbuf, static_cast<ea_t>(ea), -1, STRTYPE_C) > 0 && !qbuf.empty()) {
            return escape_c_string_literal(std::string(qbuf.c_str(), qbuf.length()), STR_MAX_LEN);
        }
    }

    // 2. Strict printable ASCII sniffer (with arithmetic progression rejection)
    std::vector<uint8_t> buf(STR_WINDOW);
    ssize_t got = get_bytes(buf.data(), static_cast<ssize_t>(STR_WINDOW), static_cast<ea_t>(ea));
    if (got <= 0) {
        got = get_bytes(buf.data(), static_cast<ssize_t>(STR_MAX_LEN + 1), static_cast<ea_t>(ea));
    }
    if (got <= 0) return std::nullopt;

    ssize_t nul_pos = -1;
    for (ssize_t i = 0; i < got; ++i) {
        if (buf[static_cast<size_t>(i)] == 0) {
            nul_pos = i;
            break;
        }
    }
    if (nul_pos < 0) return std::nullopt;
    if (!looks_like_text_bytes(buf.data(), static_cast<size_t>(nul_pos))) {
        return std::nullopt;
    }
    std::string raw(reinterpret_cast<const char *>(buf.data()), static_cast<size_t>(nul_pos));
    return escape_c_string_literal(raw, STR_MAX_LEN);
}

std::optional<std::string> IdaDatabaseProvider::get_string_literal(uint64_t ea) const {
    if (cache_) return cache_->get_string_literal(*this, ea);
    return lookup_string_uncached(ea);
}

std::optional<std::string> IdaDatabaseProvider::get_relaxed_cstr(uint64_t ea) const {
    ea_t a = static_cast<ea_t>(ea);
    qstring qbuf;
    if (get_strlit_contents(&qbuf, a, -1, STRTYPE_C) > 0 && !qbuf.empty()) {
        return escape_c_string_literal(std::string(qbuf.c_str(), qbuf.length()), 256);
    }
    if (!::is_loaded(a)) return std::nullopt;
    std::string raw;
    for (size_t off = 0; off < 256; ++off) {
        if (!::is_loaded(a + off)) return std::nullopt;
        uint8_t b = static_cast<uint8_t>(get_byte(a + off));
        if (b == 0) break;
        if (b == 0x09 || b == 0x0A || b == 0x0D || (b >= 0x20 && b <= 0x7E)) {
            raw.push_back(static_cast<char>(b));
        } else {
            return std::nullopt;
        }
    }
    if (raw.empty()) return std::nullopt;
    return escape_c_string_literal(raw, 256);
}

std::optional<std::string> IdaDatabaseProvider::lookup_symbol_uncached(uint64_t ea) const {
    if (ea == 0) return std::nullopt;
    ea_t a = static_cast<ea_t>(ea);
    if (getseg(a) == nullptr && !::is_loaded(a)) return std::nullopt;

    qstring qraw;
    get_name(&qraw, a);
    if (qraw.empty()) {
        ea_t head = get_item_head(a);
        if (head != a && (getseg(head) != nullptr || ::is_loaded(head))) {
            qstring qhead;
            if (get_name(&qhead, head) > 0 && !qhead.empty() && strncmp(qhead.c_str(), "loc_", 4) != 0) {
                std::string hraw(qhead.c_str(), qhead.length());
                std::string base = demangle_spu_name(hraw).value_or(hraw);
                char buf[64];
                std::snprintf(buf, sizeof(buf), " + 0x%llX", static_cast<unsigned long long>(a - head));
                return base + buf;
            }
        }
        return std::nullopt;
    }

    std::string raw(qraw.c_str(), qraw.length());
    if (raw.rfind("loc_", 0) == 0) return std::nullopt;
    if (raw.rfind("_ZTV", 0) == 0) {
        qstring qd;
        if (demangle_name(&qd, raw.c_str(), MNG_NODEFINIT) > 0 && !qd.empty()) {
            std::string ds(qd.c_str(), qd.length());
            auto fp = ds.find("for'");
            if (fp != std::string::npos) {
                return sanitise_demangled(trim_s(ds.substr(fp + 4))) + "::vtable";
            }
        }
        return sanitise_demangled(raw);
    }
    return demangle_spu_name(raw).value_or(raw);
}

std::optional<std::string> IdaDatabaseProvider::get_symbol_name(uint64_t ea) const {
    if (cache_) return cache_->get_symbol_name(*this, ea);
    return lookup_symbol_uncached(ea);
}

std::optional<std::string> IdaDatabaseProvider::get_member_class(uint64_t func_ea) const {
    if (cache_) return cache_->get_member_class(func_ea);
    return std::nullopt;
}

std::optional<StackSlotHit> IdaDatabaseProvider::get_stack_slot(uint64_t insn_ea) const {
    if (cache_) return cache_->get_stack_slot(insn_ea);

    func_t *pfn = get_func(static_cast<ea_t>(insn_ea));
    if (!pfn) return std::nullopt;
    insn_t insn;
    if (decode_insn(&insn, static_cast<ea_t>(insn_ea)) <= 0) return std::nullopt;

    tinfo_t ftif;
    udt_type_data_t udt;
    bool has_frame = get_func_frame(&ftif, pfn) && ftif.get_udt_details(&udt);

    for (int n = 0; n < UA_MAXOP; ++n) {
        const op_t &op = insn.ops[n];
        if (op.type == o_void) break;
        if (op.type != o_displ && op.type != o_imm) continue;
        ea_t soff = calc_stkvar_struc_offset(pfn, insn, n);
        if (soff == BADADDR) continue;
        if (has_frame) {
            for (const auto &m : udt) {
                if ((m.offset / 8) == soff && !m.name.empty()) {
                    return StackSlotHit{std::string(m.name.c_str(), m.name.length()),
                                        static_cast<int>(m.size / 8)};
                }
            }
        }
        qstring qnm;
        if (build_stkvar_name(&qnm, pfn, static_cast<sval_t>(soff)) > 0 && !qnm.empty()) {
            return StackSlotHit{std::string(qnm.c_str(), qnm.length()), 0};
        }
    }
    return std::nullopt;
}

std::optional<UdtInfo> IdaDatabaseProvider::get_udt_info(const std::string &type_name) const {
    if (type_name.empty() || type_name == "void") return std::nullopt;
    tinfo_t tif;
    bool ok = tif.get_named_type(nullptr, type_name.c_str());
    if (!ok) {
        qstring qn;
        ok = parse_decl(&tif, &qn, nullptr, (type_name + ";").c_str(), PT_TYP | PT_SIL);
    }
    if (!ok || !tif.is_udt()) return std::nullopt;

    size_t sz = tif.get_size();
    if (sz == 0 || sz == BADSIZE) return std::nullopt;

    udt_type_data_t udt;
    if (!tif.get_udt_details(&udt)) return std::nullopt;

    UdtInfo out;
    out.size = static_cast<int>(sz);
    for (const auto &m : udt) {
        int m_off = static_cast<int>(m.offset / 8);
        int m_sz = static_cast<int>(m.size / 8);
        if (m_sz <= 0) {
            size_t tsz = m.type.get_size();
            m_sz = (tsz != 0 && tsz != BADSIZE) ? static_cast<int>(tsz) : 0;
        }
        if (m_sz <= 0 || m.name.empty()) continue;

        UdtFieldInfo fi;
        fi.byte_offset = m_off;
        fi.byte_size = m_sz;
        fi.name = std::string(m.name.c_str(), m.name.length());

        qstring qmt;
        m.type.print(&qmt);
        fi.type_str = std::string(qmt.c_str(), qmt.length());

        if (m.type.is_array()) {
            tinfo_t etif = m.type.get_array_element();
            size_t esz = etif.get_size();
            if (esz != 0 && esz != BADSIZE) {
                fi.array_elem_size = static_cast<int>(esz);
                qstring qet;
                etif.print(&qet);
                fi.type_str = std::string(qet.c_str(), qet.length());
            }
        }
        out.fields.push_back(std::move(fi));
    }
    return out;
}

std::optional<std::string> IdaDatabaseProvider::get_ida_func_proto(uint64_t func_ea) const {
    tinfo_t tif;
    if (!get_tinfo(&tif, static_cast<ea_t>(func_ea)) || !tif.is_func()) {
        return std::nullopt;
    }
    std::string fn_name = get_func_name(func_ea);
    func_type_data_t ftd;
    if (tif.get_func_details(&ftd)) {
        qstring qret;
        ftd.rettype.print(&qret);
        std::string ret_s = qret.empty() ? "void" : std::string(qret.c_str(), qret.length());
        std::string pjoin;
        for (size_t i = 0; i < ftd.size(); ++i) {
            if (i > 0) pjoin += ", ";
            qstring qat;
            ftd[i].type.print(&qat);
            std::string at = qat.empty() ? "qword" : std::string(qat.c_str(), qat.length());
            std::string an = ftd[i].name.empty()
                                 ? ("a" + std::to_string(i + 1))
                                 : std::string(ftd[i].name.c_str(), ftd[i].name.length());
            std::string sep = (!at.empty() && at.back() == '*') ? "" : " ";
            pjoin += at + sep + an;
        }
        if (pjoin.empty()) pjoin = "void";
        std::string rsep = (!ret_s.empty() && ret_s.back() == '*') ? "" : " ";
        return ret_s + rsep + fn_name + "(" + pjoin + ")";
    }
    qstring qd;
    tif.print(&qd);
    std::string d(qd.c_str(), qd.length());
    auto lp = d.find('(');
    if (lp != std::string::npos) {
        return trim_s(d.substr(0, lp)) + " " + fn_name + d.substr(lp);
    }
    return std::nullopt;
}

std::optional<int> IdaDatabaseProvider::get_callee_arity(uint64_t callee_ea) {
    if (cache_) return cache_->get_callee_arity(*this, callee_ea);
    return std::nullopt;
}

bool IdaDatabaseProvider::is_callee_variadic(uint64_t callee_ea) {
    if (cache_) return cache_->is_callee_variadic(*this, callee_ea);
    return false;
}

std::optional<std::unordered_map<int, uint16_t>> IdaDatabaseProvider::get_callee_param_demand(uint64_t callee_ea) {
    if (cache_) return cache_->get_callee_param_demand(*this, callee_ea);
    return std::nullopt;
}

} // namespace spudec
