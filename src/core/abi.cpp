#include "spudec/abi.hpp"
#include "spudec/regs.hpp"
#include <algorithm>
#include <cctype>
#include <set>
#include <unordered_set>

namespace spudec {
namespace abi {

namespace {

const std::unordered_set<std::string> kCallConvs = {
    "__cdecl", "__stdcall", "__fastcall", "__thiscall", "_cdecl",
    "__spucall", "__usercall", "__userpurge", "__spoils"
};

const std::unordered_set<std::string> kCTypeWords = {
    "void", "char", "short", "int", "long", "unsigned", "signed",
    "float", "double", "bool", "_Bool", "const", "volatile", "restrict",
    "struct", "union", "enum", "class",
    "qword", "qword_unaligned", "qword2", "vec_ullong4", "u8", "u16", "u32", "u64",
    "s8", "s16", "s32", "s64", "size_t", "ssize_t", "ptrdiff_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "uintptr_t", "intptr_t", "__int8", "__int16", "__int32", "__int64",
    "BYTE", "WORD", "DWORD", "QWORD", "BOOL"
};

std::string trim_str(const std::string &s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

bool is_ident_start(char c) {
    return std::isalpha(static_cast<unsigned char>(c)) || c == '_' || c == '~';
}

bool is_qident_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) ||
           c == '_' || c == ':' || c == '~' || c == '<' || c == '>';
}

bool is_plain_c_ident(const std::string &s) {
    if (s.empty()) return false;
    if (!(std::isalpha(static_cast<unsigned char>(s[0])) || s[0] == '_')) return false;
    for (char c : s) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_')) return false;
    }
    return true;
}

std::vector<std::string> lex_decl_tokens(const std::string &s) {
    std::vector<std::string> out;
    size_t i = 0, n = s.size();
    while (i < n) {
        if (std::isspace(static_cast<unsigned char>(s[i]))) { ++i; continue; }
        if (s[i] == '*') { out.emplace_back("*"); ++i; continue; }
        if (is_ident_start(s[i])) {
            size_t j = i + 1;
            while (j < n && is_qident_char(s[j])) ++j;
            std::string tok = s.substr(i, j - i);
            if (kCallConvs.find(tok) == kCallConvs.end()) out.push_back(std::move(tok));
            i = j;
            continue;
        }
        ++i;
    }
    return out;
}

bool looks_like_type_token(const std::string &tok) {
    if (tok.empty()) return false;
    if (kCTypeWords.count(tok)) return true;
    if (tok.rfind("vec_", 0) == 0) return true;
    if (tok.size() > 2 && tok.substr(tok.size() - 2) == "_t") return true;
    if (tok.find("::") != std::string::npos) return true;
    if (std::isupper(static_cast<unsigned char>(tok[0])) && tok.find('_') != std::string::npos) return true;
    return false;
}

std::string normalize_type_stars(const std::vector<std::string> &parts, int nstars) {
    std::string base;
    for (const auto &p : parts) {
        if (p.empty()) continue;
        if (!base.empty()) base += ' ';
        base += p;
    }
    if (nstars <= 0) return base.empty() ? "qword" : base;
    if (base.empty()) base = "void";
    return base + " " + std::string(static_cast<size_t>(nstars), '*');
}

bool parse_one_param(const std::string &arg_raw, int idx, std::string &out_type, std::string &out_name) {
    std::string s = trim_str(arg_raw);
    if (s.empty() || s == "...") return false;

    int arr_dims = 0;
    while (!s.empty() && s.back() == ']') {
        auto lb = s.rfind('[');
        if (lb == std::string::npos) break;
        ++arr_dims;
        s = trim_str(s.substr(0, lb));
    }

    auto toks = lex_decl_tokens(s);
    if (toks.empty()) return false;

    if (toks.back() == "*") {
        int stars = arr_dims;
        while (!toks.empty() && toks.back() == "*") { ++stars; toks.pop_back(); }
        out_type = normalize_type_stars(toks, stars);
        out_name = "a" + std::to_string(idx + 1);
        return true;
    }

    if (toks.size() == 1) {
        if (looks_like_type_token(toks[0])) {
            out_type = normalize_type_stars(toks, arr_dims);
            out_name = "a" + std::to_string(idx + 1);
        } else {
            out_type = normalize_type_stars({"qword"}, arr_dims);
            out_name = toks[0];
        }
        return true;
    }

    const std::string last = toks.back();
    std::vector<std::string> prev(toks.begin(), toks.end() - 1);

    if (kCTypeWords.count(last) ||
        (!prev.empty() && (prev.back() == "struct" || prev.back() == "union" ||
                           prev.back() == "enum" || prev.back() == "class"))) {
        out_type = normalize_type_stars(toks, arr_dims);
        out_name = "a" + std::to_string(idx + 1);
        return true;
    }

    out_name = last;
    int stars = arr_dims;
    while (!prev.empty() && prev.back() == "*") { ++stars; prev.pop_back(); }

    std::vector<std::string> post_quals;
    while (!prev.empty() &&
           (prev.back() == "const" || prev.back() == "volatile" || prev.back() == "restrict") &&
           std::find(prev.begin(), prev.end(), "*") != prev.end()) {
        post_quals.insert(post_quals.begin(), prev.back());
        prev.pop_back();
        while (!prev.empty() && prev.back() == "*") { ++stars; prev.pop_back(); }
    }
    out_type = normalize_type_stars(prev, stars);
    for (const auto &pq : post_quals) out_type += " " + pq;
    return true;
}

} // namespace

std::string format_proto(const std::string &ret_type,
                         const std::string &name,
                         const std::vector<Param> &params) {
    std::string pstr;
    if (params.empty()) {
        pstr = "void";
    } else {
        for (size_t i = 0; i < params.size(); ++i) {
            if (i > 0) pstr += ", ";
            pstr += params[i].type_str;
            if (!params[i].type_str.empty() && params[i].type_str.back() != '*') pstr += ' ';
            pstr += params[i].name;
        }
    }
    std::string rsep = (!ret_type.empty() && ret_type.back() == '*') ? "" : " ";
    return ret_type + rsep + name + "(" + pstr + ")";
}

std::string FunctionSig::format_signature(const std::string &override_name) const {
    const std::string &nm = !override_name.empty() ? override_name : (name.empty() ? "sub_unknown" : name);
    return format_proto(ret_type, nm, params);
}

std::optional<FunctionSig> parse_proto(const std::string &proto_str,
                                       const std::string &default_name) {
    std::string clean = trim_str(proto_str);
    while (!clean.empty() && clean.back() == ';') clean.pop_back();
    clean = trim_str(clean);

    auto lp = clean.find('(');
    auto rp = clean.rfind(')');
    if (lp == std::string::npos || rp == std::string::npos || rp < lp) return std::nullopt;

    std::string head = trim_str(clean.substr(0, lp));
    std::string args_part = trim_str(clean.substr(lp + 1, rp - lp - 1));

    auto head_toks = lex_decl_tokens(head);
    if (head_toks.empty()) return std::nullopt;

    std::string fn_name;
    std::vector<std::string> ret_toks;
    if (head_toks.back() == "*" || (head_toks.size() == 1 && kCTypeWords.count(head_toks[0]))) {
        fn_name = default_name;
        ret_toks = head_toks;
    } else {
        fn_name = head_toks.back().empty() ? default_name : head_toks.back();
        ret_toks.assign(head_toks.begin(), head_toks.end() - 1);
    }

    int ret_stars = 0;
    while (!ret_toks.empty() && ret_toks.back() == "*") {
        ++ret_stars;
        ret_toks.pop_back();
    }
    std::string ret_type = ret_toks.empty()
        ? (ret_stars > 0 ? ("void " + std::string(static_cast<size_t>(ret_stars), '*')) : "void")
        : normalize_type_stars(ret_toks, ret_stars);

    FunctionSig sig;
    sig.name = fn_name;
    sig.ret_type = ret_type;
    if (ret_type != "void") sig.ret_expr = regs::reg_name(regs::ARG_FIRST);

    if (!args_part.empty() && args_part != "void") {
        size_t start = 0;
        int raw_idx = 0;
        while (start <= args_part.size()) {
            auto comma = args_part.find(',', start);
            std::string piece = (comma == std::string::npos)
                ? args_part.substr(start)
                : args_part.substr(start, comma - start);
            std::string ptype, pname;
            if (parse_one_param(piece, raw_idx, ptype, pname)) {
                int loc_reg = regs::ARG_FIRST + static_cast<int>(sig.params.size());
                std::string loc = (loc_reg <= regs::ARG_LAST)
                    ? regs::reg_name(loc_reg)
                    : ("arg_" + std::to_string(sig.params.size() + 1));
                sig.params.push_back(Param{pname, ptype, loc});
            }
            ++raw_idx;
            if (comma == std::string::npos) break;
            start = comma + 1;
        }
    }
    return sig;
}

std::string sanitize_decl_for_ida(const std::string &proto_str,
                                  bool replace_this,
                                  bool replace_qualified_types) {
    std::string clean = trim_str(proto_str);
    while (!clean.empty() && clean.back() == ';') clean.pop_back();
    auto sig = parse_proto(clean);
    if (!sig.has_value()) return clean + ";";

    std::string fn_name = is_plain_c_ident(sig->name) ? sig->name : "_spudec_fn";
    std::string ret_type = sig->ret_type;
    if (replace_qualified_types && ret_type.find("::") != std::string::npos) {
        size_t stars = static_cast<size_t>(std::count(ret_type.begin(), ret_type.end(), '*'));
        ret_type = stars > 0 ? ("void " + std::string(stars, '*')) : "qword";
    }

    std::vector<Param> san_params;
    for (size_t i = 0; i < sig->params.size(); ++i) {
        Param p = sig->params[i];
        if (replace_this && p.name == "this") p.name = "_this_ptr";
        if (!is_plain_c_ident(p.name)) p.name = "a" + std::to_string(i + 1);
        if (replace_qualified_types && p.type_str.find("::") != std::string::npos) {
            size_t stars = static_cast<size_t>(std::count(p.type_str.begin(), p.type_str.end(), '*'));
            p.type_str = stars > 0 ? ("void " + std::string(stars, '*')) : "qword";
        }
        san_params.push_back(std::move(p));
    }
    return format_proto(ret_type, fn_name, san_params) + ";";
}

int insert_call_clobbers(Function &func) {
    std::set<int> vol;
    for (const auto &b : func.blocks) {
        for (const auto &ins : b->insns) {
            if (ins->has_dst && regs::is_gpr(ins->dst_reg) && regs::is_volatile(ins->dst_reg)) {
                vol.insert(ins->dst_reg);
            }
        }
    }
    if (vol.empty()) return 0;

    int count = 0;
    for (auto &b : func.blocks) {
        std::vector<std::unique_ptr<Insn>> out;
        out.reserve(b->insns.size());
        for (auto &ins : b->insns) {
            Op op = ins->op;
            uint64_t call_ea = ins->ea;
            out.push_back(std::move(ins));
            if (op == Op::CALL || op == Op::ICALL) {
                for (int r : vol) {
                    auto c = func.make_insn(Op::UNDEF, EW::W, call_ea);
                    c->has_dst = true;
                    c->dst_reg = r;
                    c->block_id = b->id;
                    c->comment = "clobbered by call";
                    out.push_back(std::move(c));
                    ++count;
                }
            }
        }
        b->insns = std::move(out);
    }
    return count;
}

} // namespace abi
} // namespace spudec
