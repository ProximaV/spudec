#include "spudec/cgen.hpp"
#include "spudec/abi.hpp"
#include "spudec/channels.hpp"
#include "spudec/frame.hpp"
#include "spudec/highlight.hpp"
#include "spudec/lanes.hpp"
#include "spudec/outssa.hpp"
#include "spudec/regs.hpp"
#include "spudec/scalarize.hpp"
#include "spudec/sem.hpp"
#include "spudec/types.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace spudec {
namespace cgen {

namespace {

constexpr int MAX_INLINE_DEPTH = 4;

const char *ew_ctype(EW ew) {
    switch (ew) {
        case EW::B: return "u8";
        case EW::H: return "u16";
        case EW::W: return "u32";
        case EW::D: return "u64";
        default:    return "qword";
    }
}

bool is_c_ident(const std::string &s) {
    if (s.empty()) return false;
    unsigned char c0 = static_cast<unsigned char>(s[0]);
    if (!std::isalpha(c0) && s[0] != '_') return false;
    for (size_t i = 1; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (!std::isalnum(c) && s[i] != '_') return false;
    }
    return true;
}

std::string trim_str(const std::string &s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string to_lower_str(std::string s) {
    for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool starts_with(const std::string &s, const char *pfx) {
    size_t n = std::strlen(pfx);
    return s.size() >= n && s.compare(0, n, pfx) == 0;
}

bool ends_with(const std::string &s, const char *sfx) {
    size_t n = std::strlen(sfx);
    return s.size() >= n && s.compare(s.size() - n, n, sfx) == 0;
}

std::string strip_type_quals(const std::string &type_str) {
    std::string s;
    bool prev_space = true;
    for (char c : type_str) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!prev_space) { s.push_back(' '); prev_space = true; }
        } else {
            s.push_back(c);
            prev_space = false;
        }
    }
    s = trim_str(s);
    bool changed = true;
    static const char *const kws[] = {"const ", "volatile ", "restrict ", "struct ", "union "};
    while (changed) {
        changed = false;
        for (const char *kw : kws) {
            if (starts_with(s, kw)) {
                s = trim_str(s.substr(std::strlen(kw)));
                changed = true;
            }
        }
    }
    return s;
}

std::optional<int> prim_type_size(const std::string &clean) {
    static const std::unordered_map<std::string, int> m = {
        {"char", 1}, {"signed char", 1}, {"unsigned char", 1}, {"u8", 1}, {"s8", 1},
        {"uint8_t", 1}, {"int8_t", 1}, {"bool", 1}, {"_Bool", 1}, {"BYTE", 1}, {"__int8", 1},
        {"short", 2}, {"signed short", 2}, {"unsigned short", 2}, {"u16", 2}, {"s16", 2},
        {"uint16_t", 2}, {"int16_t", 2}, {"WORD", 2}, {"__int16", 2},
        {"int", 4}, {"signed int", 4}, {"unsigned int", 4}, {"signed", 4}, {"unsigned", 4},
        {"long", 4}, {"unsigned long", 4}, {"float", 4}, {"u32", 4}, {"s32", 4},
        {"uint32_t", 4}, {"int32_t", 4}, {"size_t", 4}, {"ssize_t", 4},
        {"uintptr_t", 4}, {"intptr_t", 4}, {"DWORD", 4}, {"__int32", 4},
        {"long long", 8}, {"unsigned long long", 8}, {"double", 8}, {"u64", 8}, {"s64", 8},
        {"uint64_t", 8}, {"int64_t", 8}, {"QWORD", 8}, {"__int64", 8},
        {"qword", 16}, {"qword_unaligned", 16},
        {"vec_uchar16", 16}, {"vec_char16", 16}, {"vec_ushort8", 16}, {"vec_short8", 16},
        {"vec_uint4", 16}, {"vec_int4", 16}, {"vec_ullong2", 16}, {"vec_llong2", 16},
        {"vec_float4", 16}, {"vec_double2", 16},
    };
    auto it = m.find(clean);
    if (it != m.end()) return it->second;
    return std::nullopt;
}

std::string format_char_const(uint64_t uval, int bits) {
    int nbytes = std::max(1, std::min(8, (bits + 7) / 8));
    std::vector<uint8_t> raw;
    raw.reserve(static_cast<size_t>(nbytes));
    for (int i = 0; i < nbytes; ++i) {
        int sh = 8 * (nbytes - 1 - i);
        uint8_t b = (sh >= 64) ? 0 : static_cast<uint8_t>((uval >> sh) & 0xFFULL);
        raw.push_back(b);
    }
    while (raw.size() > 1 && raw.front() == 0) {
        raw.erase(raw.begin());
    }
    std::string out = "'";
    for (uint8_t b : raw) {
        switch (b) {
            case 0x00: out += "\\0"; break;
            case 0x07: out += "\\a"; break;
            case 0x08: out += "\\b"; break;
            case 0x09: out += "\\t"; break;
            case 0x0A: out += "\\n"; break;
            case 0x0B: out += "\\v"; break;
            case 0x0C: out += "\\f"; break;
            case 0x0D: out += "\\r"; break;
            case 0x27: out += "\\'"; break;
            case 0x5C: out += "\\\\"; break;
            default:
                if (b >= 0x20 && b <= 0x7E) {
                    out.push_back(static_cast<char>(b));
                } else {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\x%02X", static_cast<unsigned>(b));
                    out += buf;
                }
                break;
        }
    }
    out.push_back('\'');
    return out;
}

std::optional<std::vector<Operand>> call_arguments(const Insn &insn, int n) {
    std::unordered_map<int, Operand> by_reg;
    for (const auto &s : insn.srcs) {
        if (s.is_var() && s.reg >= regs::ARG_FIRST && s.reg <= regs::ARG_LAST) {
            by_reg.emplace(s.reg, s);
        }
    }
    std::vector<Operand> out;
    out.reserve(static_cast<size_t>(std::max(0, n)));
    for (int i = 0; i < n; ++i) {
        auto it = by_reg.find(regs::ARG_FIRST + i);
        if (it == by_reg.end()) return std::nullopt;
        out.push_back(it->second);
    }
    return out;
}

std::unordered_set<VarKey> returned_keys(const Function &func) {
    std::unordered_set<VarKey> out;
    for (const auto &b : func.blocks) {
        for (const auto &insn : b->insns) {
            if (insn->op != Op::RET) continue;
            for (const auto &s : insn->srcs) {
                if (s.is_var() && s.reg == regs::ARG_FIRST && s.ver != 0 &&
                    func.store_idiom_roots.find(s.key()) == func.store_idiom_roots.end()) {
                    out.insert(s.key());
                    break;
                }
            }
        }
    }
    return out;
}

std::unordered_set<VarKey> real_uses(const Function &func, const std::unordered_set<VarKey> &seed = {}) {
    std::unordered_set<VarKey> real = seed;
    for (const auto &b : func.blocks) {
        for (const auto &insn : b->insns) {
            if (op_is_abi(insn->op)) continue;
            if (insn->op == Op::MOV && insn->comment == "merge") continue;
            if (insn->op == Op::PHI) continue;
            for (const auto &u : insn->srcs) {
                if (u.is_var()) real.insert(u.key());
            }
        }
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto &b : func.blocks) {
            for (const auto &insn : b->insns) {
                if (insn->op == Op::PHI || (insn->op == Op::MOV && insn->comment == "merge")) {
                    if (!insn->defines() || real.find(insn->dst_key()) == real.end()) continue;
                    for (const auto &u : insn->srcs) {
                        if (u.is_var() && real.insert(u.key()).second) {
                            changed = true;
                        }
                    }
                }
            }
        }
    }
    return real;
}

std::unordered_set<VarKey> muted_clobbers(const Function &func, const std::unordered_set<VarKey> &keep) {
    std::unordered_set<VarKey> seed = keep;
    auto ret_k = returned_keys(func);
    seed.insert(ret_k.begin(), ret_k.end());
    auto ruse = real_uses(func, seed);

    std::unordered_set<VarKey> out;
    for (const auto &b : func.blocks) {
        for (const auto &i : b->insns) {
            if (i->op == Op::UNDEF && i->defines() && ruse.find(i->dst_key()) == ruse.end()) {
                out.insert(i->dst_key());
            }
        }
    }
    return out;
}

bool is_active_arg(const Operand &v,
                   const std::unordered_map<VarKey, Insn *> &defs,
                   const std::unordered_set<int> &param_set,
                   std::unordered_set<VarKey> &visited) {
    if (v.ver == 0) return param_set.find(v.reg) != param_set.end();
    auto it = defs.find(v.key());
    if (it == defs.end() || it->second->op == Op::UNDEF) return false;
    Insn *d = it->second;
    if (d->op == Op::PHI) {
        if (!visited.insert(v.key()).second) return false;
        for (const auto &s : d->srcs) {
            if (s.is_var() && is_active_arg(s, defs, param_set, visited)) return true;
        }
        return false;
    }
    return true;
}

std::optional<uint32_t> get_const_addr16(const Operand &v, const std::unordered_map<VarKey, Insn *> &defs, int depth = 0) {
    if (depth > 16) return std::nullopt;
    if (v.is_const) {
        uint32_t w0 = v.val.word0();
        if (w0 > 0) return w0 & 0xFFFFu;
        return static_cast<uint32_t>(v.val.lo & 0xFFFFULL);
    }
    if (v.is_var()) {
        auto it = defs.find(v.key());
        if (it == defs.end()) return std::nullopt;
        const Insn *d = it->second;
        if ((d->op == Op::CONST || d->op == Op::MOV) && !d->srcs.empty()) {
            return get_const_addr16(d->srcs[0], defs, depth + 1);
        }
        if ((d->op == Op::LOAD || d->op == Op::LOADQ) && d->srcs.size() >= 2) {
            return get_const_addr16(d->srcs[1], defs, depth + 1);
        }
    }
    return std::nullopt;
}

std::vector<std::string> format_decl_lines(const std::string &ctype,
                                           const std::vector<std::string> &names,
                                           const std::string &suffix = "") {
    std::string base = ctype;
    std::vector<std::string> items = names;
    if (!base.empty() && base.back() == '*') {
        base.pop_back();
        while (!base.empty() && std::isspace(static_cast<unsigned char>(base.back()))) base.pop_back();
        for (auto &n : items) n = "*" + n;
    }
    std::vector<std::string> out;
    for (size_t i = 0; i < items.size(); i += 8) {
        size_t lim = std::min<size_t>(items.size(), i + 8);
        std::string joined;
        for (size_t j = i; j < lim; ++j) {
            if (j > i) joined += ", ";
            joined += items[j];
        }
        out.push_back("    " + base + " " + joined + ";" + suffix);
    }
    return out;
}

std::string lbl_name(const Block &b) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "loc_%llX", static_cast<unsigned long long>(b.start_ea));
    return buf;
}

struct Namer {
    std::unordered_map<VarKey, std::string> name_map;
    std::vector<std::vector<VarKey>> colours_list;
    std::unordered_map<std::string, VarKey> first_key_of_name;

    Namer(const Function &func,
          const std::unordered_map<VarKey, std::string> &param_names,
          const outssa::CallArgsMap &call_args) {
        std::unordered_map<VarKey, VarKey> parent;
        auto find_root = [&](VarKey k) -> VarKey {
            VarKey r = k;
            while (parent[r] != r) r = parent[r];
            while (parent[k] != k) {
                VarKey nxt = parent[k];
                parent[k] = r;
                k = nxt;
            }
            return r;
        };

        for (const auto &b : func.blocks) {
            for (const auto &insn : b->insns) {
                if (insn->defines()) parent.emplace(insn->dst_key(), insn->dst_key());
                for (const auto &u : insn->srcs) {
                    if (u.is_var()) parent.emplace(u.key(), u.key());
                }
            }
        }
        for (const auto &b : func.blocks) {
            for (const auto &insn : b->insns) {
                if (insn->op != Op::PHI || !insn->defines()) continue;
                for (const auto &s : insn->srcs) {
                    if (s.is_var()) {
                        VarKey ra = find_root(insn->dst_key());
                        VarKey rb = find_root(s.key());
                        if (ra != rb) parent[rb] = ra;
                    }
                }
            }
        }

        std::vector<VarKey> all_keys;
        all_keys.reserve(parent.size());
        for (const auto &[k, _] : parent) all_keys.push_back(k);
        auto key_less = [](VarKey a, VarKey b) {
            int ra = key_reg(a), rb = key_reg(b);
            return (ra != rb) ? (ra < rb) : (key_ver(a) < key_ver(b));
        };
        std::sort(all_keys.begin(), all_keys.end(), key_less);

        std::unordered_map<VarKey, std::vector<VarKey>> webs;
        std::vector<VarKey> roots;
        for (VarKey k : all_keys) {
            VarKey r = find_root(k);
            auto &vec = webs[r];
            if (vec.empty()) roots.push_back(r);
            vec.push_back(k);
        }
        std::sort(roots.begin(), roots.end(), key_less);

        auto col = outssa::colours(func, &call_args);
        std::unordered_map<std::string, int> seen;

        for (VarKey root : roots) {
            std::unordered_map<int, std::vector<VarKey>> by_col;
            std::vector<int> col_order;
            for (VarKey k : webs[root]) {
                auto cit = col.key_to_colour.find(k);
                int cid = (cit != col.key_to_colour.end()) ? cit->second : -1;
                auto &cv = by_col[cid];
                if (cv.empty()) col_order.push_back(cid);
                cv.push_back(k);
            }
            // Sort colour IDs lexicographically by string representation to match Python `sorted(by_colour, key=str)`.
            std::sort(col_order.begin(), col_order.end(), [](int a, int b) {
                return std::to_string(a) < std::to_string(b);
            });

            for (int cid : col_order) {
                auto members = std::move(by_col[cid]);
                std::sort(members.begin(), members.end(), key_less);
                std::string fixed;
                for (VarKey k : members) {
                    auto pit = param_names.find(k);
                    if (pit != param_names.end()) {
                        fixed = pit->second;
                        break;
                    }
                }
                std::string nm;
                if (!fixed.empty()) {
                    nm = fixed;
                } else {
                    std::string base = regs::reg_name(key_reg(root));
                    int n = ++seen[base];
                    nm = (n == 1) ? base : (base + "_" + std::to_string(n));
                }
                for (VarKey k : members) {
                    name_map[k] = nm;
                }
                first_key_of_name.emplace(nm, members.front());
                colours_list.push_back(std::move(members));
            }
        }
    }

    std::string name(const Operand &v) const {
        auto it = name_map.find(v.key());
        return (it != name_map.end()) ? it->second : v.str();
    }

    std::string name_key(VarKey k) const {
        auto it = name_map.find(k);
        if (it != name_map.end()) return it->second;
        return Operand::make_var(key_reg(k), key_ver(k)).str();
    }
};

struct SboxTree {
    Operand inp_var;
    bool is_inv = false;
    std::vector<Insn *> tree_insns;
    Insn *mask_insn = nullptr;
};

struct SlotHitInfo {
    std::string name;
    std::string ctype;
    EW ew = EW::Q;
};

struct FieldResolution {
    std::string path;
    int matched_size = 0;
    int rem = 0;
};

class CGenEngine {
public:
    Function &func;
    const CGenOptions &opts;
    cfuncptr_t cfunc;

    std::unordered_map<std::string, std::string> user_renames;
    std::unordered_map<std::string, std::string> user_types;
    std::optional<std::string> user_proto;
    std::unordered_map<std::string, std::string> user_cmts;
    std::unordered_set<uint64_t> user_iflags;
    std::unordered_map<std::string, std::string> user_numforms;
    bool hide_casts = false;

    std::unordered_map<VarKey, Insn *> defs;
    std::vector<int> params;
    outssa::CallArgsMap call_args;
    std::unordered_map<uint32_t, Operand> call_return;
    std::unordered_map<uint32_t, Operand> call_return2;
    bool two_reg_return = false;
    std::unordered_set<uint32_t> suppressed_uids;
    std::optional<std::string> member_class;
    std::optional<int> this_reg;
    std::unordered_map<int, std::string> raw_param_name;
    std::unordered_map<int, std::string> param_name;
    std::unordered_map<int, std::string> param_proto_types;
    std::unique_ptr<Namer> namer;
    std::unordered_map<uint64_t, Insn *> call_at;
    std::unordered_map<VarKey, SboxTree> sbox_trees;
    std::unordered_set<VarKey> debris;
    std::unordered_set<VarKey> inlinable;
    std::unordered_set<VarKey> mute;
    frame::FrameInfo frame_info;
    std::unordered_set<std::string> printed;
    std::unordered_set<std::string> assigned;
    std::unordered_set<std::string> visible;
    types::TypeMap types_map;
    types::TypeStats type_stats;

    bool slots_ready = false;
    std::unordered_map<uint32_t, SlotHitInfo> sp_slots; // keyed by uint32_t offset from sp#0
    std::unordered_map<std::string, std::string> stack_decls;
    int stack_unresolved = 0;
    std::unordered_map<std::string, std::optional<UdtInfo>> udt_cache;

    std::unordered_map<std::string, std::string> all_var_types;
    std::vector<std::pair<std::string, std::string>> sig_params;
    std::string ret_type = "void";
    std::unordered_map<std::string, int> lvar_idx_by_name;

    // Statement / line tracking
    std::optional<uint64_t> cur_stmt_ea;
    std::optional<uint64_t> cur_expr_ea;
    int cur_const_idx = 0;
    std::vector<LineConstSpan> cur_line_consts;
    std::vector<uint64_t> current_inlined_eas;

    std::vector<std::optional<uint64_t>> body_eas;
    std::unordered_map<int, std::vector<uint64_t>> body_line_to_eas;
    std::unordered_map<int, std::vector<LineConstSpan>> body_line_consts;
    std::unordered_map<std::string, uint64_t> call_eas;
    std::unordered_map<std::string, uint64_t> sym_eas;

    CGenEngine(Function &fn, const CGenOptions &o)
        : func(fn), opts(o), cfunc(std::make_shared<cfunc_t>()) {
        cfunc->entry_ea = func.start_ea;
        cfunc->hide_casts = opts.hide_casts;
        hide_casts = opts.hide_casts;

        user_renames = opts.user_data.renames;
        user_types = opts.user_data.types;
        user_proto = opts.user_data.proto;
        user_cmts = opts.user_data.cmts;
        user_numforms = opts.user_data.numforms;
        for (uint64_t flg : opts.user_data.iflags) user_iflags.insert(flg);

        if (!user_proto.has_value() && opts.db) {
            user_proto = opts.db->get_ida_func_proto(func.start_ea);
        }

        // Fold locator-keyed lvars into renames/types fallback maps (matching cgen.py lines 532-545)
        for (const auto &[loc_key, linfo] : opts.user_data.lvars) {
            std::string base_name = loc_key;
            auto at_pos = base_name.find('@');
            if (at_pos != std::string::npos) base_name = base_name.substr(0, at_pos);
            auto col_pos = base_name.find(':');
            if (col_pos != std::string::npos) base_name = base_name.substr(col_pos + 1);
            if (!linfo.name.empty()) {
                user_renames.emplace(base_name, linfo.name);
                if (!linfo.type.empty()) user_types.emplace(linfo.name, linfo.type);
            } else if (!linfo.type.empty()) {
                user_types.emplace(base_name, linfo.type);
            }
        }

        for (auto &b : func.blocks) {
            for (auto &i : b->insns) {
                if (i->defines()) defs[i->dst_key()] = i.get();
            }
        }

        auto arity_fn = [&](uint64_t ea) -> std::optional<int> { return query_arity(ea); };
        auto variadic_fn = [&](uint64_t ea) -> bool { return query_variadic(ea); };
        params = recover_params(func, arity_fn, variadic_fn);

        // Compute real call argument operands per call site
        std::unordered_set<int> param_set(params.begin(), params.end());
        for (auto &b : func.blocks) {
            for (size_t idx = 0; idx < b->insns.size(); ++idx) {
                Insn *insn = b->insns[idx].get();
                if (insn->op == Op::CALL || insn->op == Op::ICALL || insn->op == Op::TCALL) {
                    auto args = compute_call_args(*insn, param_set);
                    if (!args.empty()) {
                        call_args[insn->uid] = std::move(args);
                    }
                    call_at[insn->ea] = insn;
                }
                if (insn->op == Op::CALL || insn->op == Op::ICALL) {
                    for (size_t j = idx + 1; j < b->insns.size(); ++j) {
                        Insn *other = b->insns[j].get();
                        if (other->ea != insn->ea) break;
                        if (other->op == Op::UNDEF && other->defines()) {
                            if (other->dst_reg == regs::ARG_FIRST && !call_return.count(insn->uid)) {
                                call_return[insn->uid] = other->dst_as_var();
                                suppressed_uids.insert(other->uid);
                            } else if (other->dst_reg == regs::ARG_FIRST + 1 && !call_return2.count(insn->uid)) {
                                // Only capture secondary r4 return if r4 is genuinely read in a non-PHI/non-ABI op.
                                bool r4_used = false;
                                VarKey rk4 = other->dst_key();
                                for (const auto &ub : func.blocks) {
                                    for (const auto &ui : ub->insns) {
                                        if (ui->op == Op::PHI) continue;
                                        if (op_is_abi(ui->op) && ui->op != Op::RET) continue;
                                        for (const auto &us : ui->srcs) {
                                            if (us.is_var() && us.key() == rk4) {
                                                r4_used = true;
                                                break;
                                            }
                                        }
                                        if (r4_used) break;
                                    }
                                    if (r4_used) break;
                                }
                                if (r4_used) {
                                    call_return2[insn->uid] = other->dst_as_var();
                                    suppressed_uids.insert(other->uid);
                                }
                            }
                        }
                    }
                }
            }
        }

        member_class = query_this_class(func.start_ea);
        if (member_class.has_value() && !member_class->empty()) {
            this_reg = regs::ARG_FIRST;
        }
        if (this_reg.has_value() && params.empty()) {
            params.push_back(*this_reg);
        }

        std::unordered_map<VarKey, std::string> pnames;
        if (user_proto.has_value() && !user_proto->empty()) {
            std::string fb = func.name.empty() ? default_sub_name(func.start_ea) : func.name;
            auto parsed = abi::parse_proto(*user_proto, fb);
            if (parsed.has_value() && !parsed->params.empty()) {
                for (size_t idx = 0; idx < parsed->params.size(); ++idx) {
                    int r = regs::ARG_FIRST + static_cast<int>(idx);
                    if (std::find(params.begin(), params.end(), r) == params.end()) {
                        params.push_back(r);
                    }
                    const auto &p = parsed->params[idx];
                    raw_param_name[r] = p.name;
                    std::string eff = lookup_rename(p.name);
                    param_name[r] = eff;
                    pnames[make_var_key(r, 0)] = eff;
                    param_proto_types[r] = p.type_str;
                }
            }
        }
        int ai = 0;
        for (int r : params) {
            if (param_name.find(r) != param_name.end()) continue;
            std::string nm = (this_reg.has_value() && r == *this_reg) ? "this" : ("a" + std::to_string(++ai));
            raw_param_name[r] = nm;
            std::string eff = lookup_rename(nm);
            param_name[r] = eff;
            pnames[make_var_key(r, 0)] = eff;
        }

        namer = std::make_unique<Namer>(func, pnames, call_args);
        if (func.demand.empty()) {
            lanes::CalleeDemandFn callee_dem;
            if (opts.db) {
                callee_dem = [&](uint64_t ea) { return opts.db->get_callee_param_demand(ea); };
            }
            func.demand = lanes::compute_demand(func, callee_dem);
        }
        two_reg_return = detect_two_reg_return();
        debris = compute_debris();
        inlinable = compute_inlinable();
        mute = muted_clobbers(func, rendered_keys());
        frame_info = frame::analyse(func);

        for (const auto &b : func.blocks) {
            for (const auto &insn : b->insns) {
                if (!insn->defines() || regs::is_pseudo(insn->dst_reg)) continue;
                if (!is_suppressed(*insn)) {
                    visible.insert(namer->name_key(insn->dst_key()));
                }
            }
        }

        auto [tm, tstats] = types::infer(
            func, func.demand, namer->colours_list,
            [&](const u128_t &val) { return query_str(val.word0()).has_value(); });
        types_map = std::move(tm);
        type_stats = std::move(tstats);
    }

    const Insn *peel_mov_def(Operand op) const {
        std::unordered_set<VarKey> seen;
        while (op.is_var() && seen.insert(op.key()).second) {
            auto it = defs.find(op.key());
            if (it == defs.end()) return nullptr;
            const Insn *d = it->second;
            if (d->op == Op::MOV && d->srcs.size() == 1 && d->srcs[0].is_var()) {
                op = d->srcs[0];
                continue;
            }
            return d;
        }
        return nullptr;
    }

    static bool is_vector16_producer_op(Op op, bool scalar_flag) {
        switch (op) {
        case Op::SHUFB:
        case Op::LOADQ:
        case Op::LOADU:
        case Op::QROTBY:
        case Op::QROTBI:
        case Op::QROTMBY:
        case Op::QROTMBI:
        case Op::QSHLBY:
        case Op::QSHLBI:
            return true;
        case Op::SELB:
            return !scalar_flag;
        default:
            return false;
        }
    }

    bool is_clean_vector_ret_val(const Operand &op, const std::unordered_map<VarKey, int> *non_ret_uses = nullptr) const {
        if (non_ret_uses && non_ret_uses->count(op.key())) return false;
        const Insn *d = peel_mov_def(op);
        if (!d) return false;
        if (d->op == Op::PHI) {
            bool any_src = false;
            for (const auto &s : d->srcs) {
                if (!s.is_var() || s.ver == 0) return false;
                if (d->has_dst && s.key() == d->dst_key()) continue;
                any_src = true;
                const Insn *sd = peel_mov_def(s);
                if (!sd || sd->op == Op::UNDEF || sd->op == Op::CONST) return false;
            }
            return any_src;
        }
        return d->op != Op::UNDEF && d->op != Op::CONST;
    }

    bool detect_two_reg_return() const {
        if (user_proto.has_value() && !user_proto->empty()) return false;
        std::unordered_map<VarKey, int> non_ret_uses;
        for (const auto &b : func.blocks) {
            for (const auto &i : b->insns) {
                if (i->op == Op::RET) continue;
                for (const auto &s : i->srcs) {
                    if (s.is_var()) ++non_ret_uses[s.key()];
                }
            }
        }
        int ret_count = 0;
        for (const auto &b : func.blocks) {
            for (const auto &i : b->insns) {
                if (i->op != Op::RET) continue;
                ++ret_count;
                std::optional<Operand> r3_op, r4_op;
                for (const auto &s : i->srcs) {
                    if (!s.is_var() || s.ver == 0) continue;
                    if (s.reg == regs::ARG_FIRST) r3_op = s;
                    else if (s.reg == regs::ARG_FIRST + 1) r4_op = s;
                }
                if (!r3_op.has_value() || !r4_op.has_value()) return false;
                if (func.store_idiom_roots.count(r3_op->key()) ||
                    func.store_idiom_roots.count(r4_op->key())) {
                    return false;
                }
                if (!is_clean_vector_ret_val(*r4_op, &non_ret_uses)) return false;
                const Insn *d3 = peel_mov_def(*r3_op);
                if (!d3) return false;
                if (d3->op == Op::PHI) {
                    if (!is_clean_vector_ret_val(*r3_op)) return false;
                    bool has_vec_src = false;
                    for (const auto &s : d3->srcs) {
                        if (!s.is_var() || (d3->has_dst && s.key() == d3->dst_key())) continue;
                        const Insn *sd = peel_mov_def(s);
                        if (sd && is_vector16_producer_op(sd->op, sd->scalar)) has_vec_src = true;
                    }
                    if (!has_vec_src) return false;
                } else if (!is_vector16_producer_op(d3->op, d3->scalar)) {
                    return false;
                }
            }
        }
        return ret_count > 0;
    }

    // --- Provider query helpers ---
    static std::string default_sub_name(uint64_t ea) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "sub_%llX", static_cast<unsigned long long>(ea));
        return buf;
    }

    std::string lookup_rename(const std::string &nm) const {
        auto it = user_renames.find(nm);
        return (it != user_renames.end()) ? it->second : nm;
    }

    std::string query_name(uint64_t ea) const {
        if (opts.name_of) return opts.name_of(ea);
        if (opts.db) return opts.db->get_func_name(ea);
        return default_sub_name(ea);
    }

    std::optional<int> query_arity(uint64_t ea) const {
        if (opts.arity_of) return opts.arity_of(ea);
        if (opts.db) return opts.db->get_callee_arity(ea);
        return std::nullopt;
    }

    bool query_variadic(uint64_t ea) const {
        if (opts.is_variadic_of) return opts.is_variadic_of(ea);
        if (opts.db) return opts.db->is_callee_variadic(ea);
        return false;
    }

    std::optional<std::string> query_str(uint64_t ea) const {
        if (opts.str_of) return opts.str_of(ea);
        if (opts.db) return opts.db->get_string_literal(ea);
        return std::nullopt;
    }

    std::optional<std::string> query_relaxed_str(uint64_t ea) const {
        if (opts.relaxed_str_of) return opts.relaxed_str_of(ea);
        if (opts.db) return opts.db->get_relaxed_cstr(ea);
        return std::nullopt;
    }

    std::optional<StackSlotHit> query_stk(uint64_t ea) const {
        if (opts.stk_of) return opts.stk_of(ea);
        if (opts.db) return opts.db->get_stack_slot(ea);
        return std::nullopt;
    }

    std::optional<std::string> query_this_class(uint64_t ea) const {
        if (opts.this_of) return opts.this_of(ea);
        if (opts.db) return opts.db->get_member_class(ea);
        return std::nullopt;
    }

    std::optional<std::string> query_sym(uint64_t ea) const {
        if (opts.sym_of) return opts.sym_of(ea);
        if (opts.db) return opts.db->get_symbol_name(ea);
        return std::nullopt;
    }

    const UdtInfo *query_udt(const std::string &type_name) {
        std::string key = strip_type_quals(type_name);
        if (key.empty() || key == "void" || prim_type_size(key).has_value()) return nullptr;
        auto it = udt_cache.find(key);
        if (it != udt_cache.end()) {
            return it->second.has_value() ? &(*it->second) : nullptr;
        }
        std::optional<UdtInfo> res;
        if (opts.struct_resolver) res = opts.struct_resolver(key);
        if (!res.has_value() && opts.db) res = opts.db->get_udt_info(key);
        auto [ins_it, _] = udt_cache.emplace(key, std::move(res));
        return ins_it->second.has_value() ? &(*ins_it->second) : nullptr;
    }

    std::vector<Operand> compute_call_args(const Insn &insn, const std::unordered_set<int> &param_set) const {
        std::unordered_map<int, Operand> by_reg;
        for (const auto &s : insn.srcs) {
            if (s.is_var() && s.reg >= regs::ARG_FIRST && s.reg <= regs::ARG_LAST) {
                by_reg[s.reg] = s;
            }
        }
        if (by_reg.empty()) return {};

        bool callee_var = false;
        std::optional<int> n;
        if ((insn.op == Op::CALL || insn.op == Op::TCALL) && insn.has_aux) {
            callee_var = query_variadic(insn.aux_ea);
            n = query_arity(insn.aux_ea);
        }

        if (!callee_var && n.has_value() && *n > 0 && *n <= static_cast<int>(by_reg.size())) {
            std::vector<Operand> out;
            for (int i = 0; i < *n; ++i) {
                auto it = by_reg.find(regs::ARG_FIRST + i);
                if (it == by_reg.end()) break;
                out.push_back(it->second);
            }
            return out;
        }
        if (n.has_value() && *n == 0) return {};
        if (insn.op == Op::ICALL && !insn.srcs.empty() && insn.srcs[0].is_var() &&
            insn.srcs[0].reg == regs::ARG_FIRST) {
            return {};
        }

        std::vector<Operand> out;
        for (int i = 0; i < static_cast<int>(by_reg.size()); ++i) {
            auto it = by_reg.find(regs::ARG_FIRST + i);
            if (it == by_reg.end()) break;
            std::unordered_set<VarKey> vis;
            if (is_active_arg(it->second, defs, param_set, vis)) {
                out.push_back(it->second);
            } else {
                break;
            }
        }
        return out;
    }

    std::unordered_set<VarKey> rendered_keys() const {
        std::unordered_set<VarKey> keys;
        for (const auto &[_, args] : call_args) {
            for (const auto &a : args) {
                if (a.is_var()) keys.insert(a.key());
            }
        }
        return keys;
    }

    std::unordered_set<VarKey> find_sbox_trees() {
        std::unordered_set<VarKey> deb;
        for (auto &b : func.blocks) {
            for (auto &insn_ptr : b->insns) {
                Insn *insn = insn_ptr.get();
                if (insn->op != Op::SELB || insn->srcs.size() < 3 || !insn->defines()) continue;

                std::vector<Insn *> l2;
                bool ok = true;
                for (int i = 0; i < 2; ++i) {
                    const auto &s = insn->srcs[i];
                    if (!s.is_var()) { ok = false; break; }
                    auto it = defs.find(s.key());
                    if (it == defs.end() || it->second->op != Op::SELB || it->second->srcs.size() < 3) {
                        ok = false; break;
                    }
                    l2.push_back(it->second);
                }
                if (!ok || l2.size() != 2) continue;

                std::vector<Insn *> l1;
                for (Insn *n : l2) {
                    for (int i = 0; i < 2; ++i) {
                        const auto &s = n->srcs[i];
                        if (!s.is_var()) { ok = false; break; }
                        auto it = defs.find(s.key());
                        if (it == defs.end() || it->second->op != Op::SELB || it->second->srcs.size() < 3) {
                            ok = false; break;
                        }
                        l1.push_back(it->second);
                    }
                    if (!ok) break;
                }
                if (!ok || l1.size() != 4) continue;

                std::vector<Insn *> shufs;
                for (Insn *n : l1) {
                    for (int i = 0; i < 2; ++i) {
                        const auto &s = n->srcs[i];
                        if (!s.is_var()) { ok = false; break; }
                        auto it = defs.find(s.key());
                        if (it == defs.end() || it->second->op != Op::SHUFB || it->second->srcs.size() < 3) {
                            ok = false; break;
                        }
                        shufs.push_back(it->second);
                    }
                    if (!ok) break;
                }
                if (!ok || shufs.size() != 8) continue;

                std::unordered_set<VarKey> mask_keys;
                for (Insn *sh : shufs) {
                    if (sh->srcs[2].is_var()) mask_keys.insert(sh->srcs[2].key());
                }
                if (mask_keys.size() != 1) continue;
                auto mit = defs.find(*mask_keys.begin());
                if (mit == defs.end() || mit->second->op != Op::AND || mit->second->srcs.size() < 2) continue;
                Insn *mask_insn = mit->second;

                bool is_inv = false;
                for (Insn *sh : shufs) {
                    for (int i = 0; i < 2; ++i) {
                        const auto &src = sh->srcs[i];
                        if (!src.is_var()) continue;
                        auto sit = defs.find(src.key());
                        if (sit != defs.end() && (sit->second->op == Op::LOAD || sit->second->op == Op::LOADQ) &&
                            sit->second->srcs.size() >= 2) {
                            auto ca = get_const_addr16(sit->second->srcs[1], defs);
                            if (ca.has_value() && *ca >= 0xCB30u && *ca <= 0xCC20u) {
                                is_inv = true;
                            }
                        }
                    }
                }

                SboxTree tree;
                tree.inp_var = mask_insn->srcs[0];
                tree.is_inv = is_inv;
                tree.tree_insns.push_back(insn);
                tree.tree_insns.insert(tree.tree_insns.end(), l2.begin(), l2.end());
                tree.tree_insns.insert(tree.tree_insns.end(), l1.begin(), l1.end());
                tree.tree_insns.insert(tree.tree_insns.end(), shufs.begin(), shufs.end());
                tree.mask_insn = mask_insn;

                for (size_t k = 1; k < tree.tree_insns.size(); ++k) {
                    if (tree.tree_insns[k]->defines()) deb.insert(tree.tree_insns[k]->dst_key());
                }
                if (mask_insn->defines()) deb.insert(mask_insn->dst_key());
                sbox_trees[insn->dst_key()] = std::move(tree);
            }
        }
        return deb;
    }

    std::unordered_set<VarKey> compute_debris() {
        auto sbox_deb = find_sbox_trees();
        std::unordered_set<VarKey> roots = func.store_idiom_roots;
        roots.insert(sbox_deb.begin(), sbox_deb.end());

        std::unordered_set<VarKey> kept;
        auto keeping = [&](const Insn &insn, std::vector<Operand> &out) {
            out.clear();
            if (insn.defines()) {
                auto sit = sbox_trees.find(insn.dst_key());
                if (sit != sbox_trees.end()) {
                    if (sit->second.inp_var.is_var()) out.push_back(sit->second.inp_var);
                    return;
                }
            }
            int leading = 0;
            if (op_is_abi(insn.op, &leading)) {
                for (int i = 0; i < leading && i < static_cast<int>(insn.srcs.size()); ++i) {
                    out.push_back(insn.srcs[i]);
                }
                if (insn.op == Op::CALL || insn.op == Op::TCALL) {
                    std::optional<int> n = insn.has_aux ? query_arity(insn.aux_ea) : std::nullopt;
                    if (n.has_value()) {
                        auto cargs = call_arguments(insn, *n);
                        if (cargs.has_value()) {
                            for (const auto &a : *cargs) out.push_back(a);
                        }
                    } else {
                        for (const auto &s : insn.srcs) {
                            if (s.is_var() && roots.find(s.key()) == roots.end()) out.push_back(s);
                        }
                    }
                } else if (insn.op == Op::ICALL || insn.op == Op::IJMP) {
                    for (const auto &s : insn.srcs) {
                        if (s.is_var() && roots.find(s.key()) == roots.end()) out.push_back(s);
                    }
                } else if (insn.op == Op::RET) {
                    for (const auto &s : insn.srcs) {
                        bool is_ret_reg = (s.reg == regs::ARG_FIRST) ||
                                          (two_reg_return && s.reg == regs::ARG_FIRST + 1);
                        if (s.is_var() && is_ret_reg && s.ver != 0 &&
                            roots.find(s.key()) == roots.end()) {
                            out.push_back(s);
                        }
                    }
                }
                return;
            }
            if (op_has_side_effects(insn.op) || insn.is_terminator()) {
                out = insn.srcs;
                return;
            }
            if (insn.defines() && kept.find(insn.dst_key()) != kept.end()) {
                out = insn.srcs;
            }
        };

        std::vector<Operand> kbuf;
        bool changed = true;
        while (changed) {
            changed = false;
            for (const auto &b : func.blocks) {
                for (const auto &insn : b->insns) {
                    keeping(*insn, kbuf);
                    for (const auto &u : kbuf) {
                        if (u.is_var() && defs.find(u.key()) != defs.end() && kept.insert(u.key()).second) {
                            changed = true;
                        }
                    }
                }
            }
        }

        std::unordered_set<VarKey> dead;
        for (const auto &[k, insn] : defs) {
            if (kept.find(k) == kept.end() && !op_has_side_effects(insn->op) &&
                !insn->is_terminator() && insn->op != Op::PHI && insn->op != Op::UNDEF) {
                dead.insert(k);
            }
        }

        std::unordered_set<VarKey> cone;
        std::vector<VarKey> frontier;
        for (VarKey r : roots) {
            if (dead.find(r) != dead.end()) {
                cone.insert(r);
                frontier.push_back(r);
            }
        }
        while (!frontier.empty()) {
            VarKey cur = frontier.back();
            frontier.pop_back();
            auto dit = defs.find(cur);
            if (dit == defs.end()) continue;
            for (const auto &u : dit->second->srcs) {
                if (u.is_var() && dead.find(u.key()) != dead.end() && cone.insert(u.key()).second) {
                    frontier.push_back(u.key());
                }
            }
        }

        for (VarKey k : dead) {
            const Insn *d = defs.at(k);
            if (d->op == Op::CONST || d->op == Op::ADD || d->op == Op::MOV) {
                cone.insert(k);
            } else if ((d->op == Op::LOAD || d->op == Op::LOADQ) && d->srcs.size() >= 2 &&
                       get_const_addr16(d->srcs[1], defs).has_value()) {
                cone.insert(k);
            }
        }
        cone.insert(sbox_deb.begin(), sbox_deb.end());

        // 64-bit ADDX/SUBX carry/borrow debris
        std::unordered_map<VarKey, std::vector<Insn *>> uses_of;
        for (auto &b : func.blocks) {
            for (auto &insn : b->insns) {
                for (const auto &u : insn->srcs) {
                    if (u.is_var()) uses_of[u.key()].push_back(insn.get());
                }
            }
        }
        std::unordered_set<uint32_t> all_carry_uids;
        std::vector<std::vector<Insn *>> cand_groups;
        for (auto &b : func.blocks) {
            for (auto &insn : b->insns) {
                if ((insn->op == Op::ADDX || insn->op == Op::SUBX) && insn->srcs.size() >= 3) {
                    const Operand &c_var = insn->srcs[2];
                    if (!c_var.is_var()) continue;
                    auto cit = defs.find(c_var.key());
                    if (cit == defs.end()) continue;
                    Insn *c_def = cit->second;
                    std::vector<Insn *> cands;
                    if (c_def->op == Op::SHUFB) {
                        cands.push_back(c_def);
                        for (size_t si = 0; si < 2 && si < c_def->srcs.size(); ++si) {
                            if (c_def->srcs[si].is_var()) {
                                auto sit = defs.find(c_def->srcs[si].key());
                                if (sit != defs.end()) {
                                    Op sop = sit->second->op;
                                    if (sop == Op::CG || sop == Op::BG || sop == Op::CGX || sop == Op::BGX) {
                                        cands.push_back(sit->second);
                                    }
                                }
                            }
                        }
                        if (c_def->srcs.size() > 2 && c_def->srcs[2].is_var()) {
                            auto mit = defs.find(c_def->srcs[2].key());
                            if (mit != defs.end()) {
                                Op mop = mit->second->op;
                                if (mop == Op::LOAD || mop == Op::LOADQ || mop == Op::CONST) {
                                    cands.push_back(mit->second);
                                }
                            }
                        }
                    } else if (c_def->op == Op::CG || c_def->op == Op::BG ||
                               c_def->op == Op::CGX || c_def->op == Op::BGX) {
                        cands.push_back(c_def);
                    }
                    for (Insn *c : cands) all_carry_uids.insert(c->uid);
                    all_carry_uids.insert(insn->uid);
                    cand_groups.push_back(std::move(cands));
                }
            }
        }
        for (const auto &cands : cand_groups) {
            for (Insn *cand : cands) {
                if (!cand->defines()) continue;
                bool ok = true;
                auto uit = uses_of.find(cand->dst_key());
                if (uit != uses_of.end()) {
                    for (Insn *u : uit->second) {
                        if (op_is_abi(u->op) || u->op == Op::PHI) continue;
                        if (all_carry_uids.find(u->uid) == all_carry_uids.end()) {
                            ok = false;
                            break;
                        }
                    }
                }
                if (ok) cone.insert(cand->dst_key());
            }
        }

        // Condition chains feeding CJMP / CIJMP
        for (const auto &b : func.blocks) {
            for (const auto &insn : b->insns) {
                if ((insn->op != Op::CJMP && insn->op != Op::CIJMP) || insn->srcs.empty()) continue;
                Operand cur = insn->srcs[0];
                std::vector<Insn *> chain;
                int guard = 0;
                while (cur.is_var() && guard++ < 32) {
                    auto dit = defs.find(cur.key());
                    if (dit == defs.end()) break;
                    Insn *d = dit->second;
                    if ((d->op == Op::MOV || d->op == Op::EXTS) && !d->srcs.empty()) {
                        chain.push_back(d);
                        cur = d->srcs[0];
                    } else if ((d->op == Op::CMPGT || d->op == Op::CMPGTU) && d->srcs.size() == 2 &&
                               d->srcs[1].is_const &&
                               (d->srcs[1].val.word0() == 0xBu || d->srcs[1].val.word0() == 0xFu)) {
                        chain.push_back(d);
                        cur = d->srcs[0];
                    } else if (d->op == Op::GB && d->srcs.size() == 1) {
                        chain.push_back(d);
                        cur = d->srcs[0];
                    } else if (d->op == Op::CMPEQ || d->op == Op::FCMPEQ ||
                               d->op == Op::CMPGT || d->op == Op::CMPGTU) {
                        chain.push_back(d);
                        for (Insn *x : chain) {
                            if (x->defines() && dead.find(x->dst_key()) != dead.end()) {
                                cone.insert(x->dst_key());
                            }
                        }
                        break;
                    } else {
                        break;
                    }
                }
            }
        }
        // Suppress Op::GENCTL masks whose only non-dead users are SHUFB mask inputs (srcs[2]),
        // along with any single-use address calculation insns feeding only those GENCTLs.
        for (const auto &b : func.blocks) {
            for (const auto &insn : b->insns) {
                if (insn->op != Op::GENCTL || !insn->defines()) continue;
                VarKey gk = insn->dst_key();
                bool only_shufb_mask = true;
                auto uit = uses_of.find(gk);
                if (uit != uses_of.end()) {
                    for (Insn *u : uit->second) {
                        if (u->op == Op::PHI) continue;
                        if (u->defines() && (cone.count(u->dst_key()) || dead.count(u->dst_key()))) continue;
                        if (u->op == Op::SHUFB && u->srcs.size() >= 3 &&
                            u->srcs[2].is_var() && u->srcs[2].key() == gk &&
                            !(u->srcs[0].is_var() && u->srcs[0].key() == gk) &&
                            !(u->srcs[1].is_var() && u->srcs[1].key() == gk)) {
                            continue;
                        }
                        only_shufb_mask = false;
                        break;
                    }
                }
                if (only_shufb_mask) {
                    cone.insert(gk);
                    if (!insn->srcs.empty() && insn->srcs[0].is_var()) {
                        std::vector<VarKey> bw = {insn->srcs[0].key()};
                        while (!bw.empty()) {
                            VarKey ak = bw.back();
                            bw.pop_back();
                            if (cone.count(ak)) continue;
                            auto adit = defs.find(ak);
                            if (adit == defs.end()) continue;
                            Insn *ad = adit->second;
                            if (ad->op != Op::ADD && ad->op != Op::AND &&
                                ad->op != Op::MOV && ad->op != Op::CONST) {
                                continue;
                            }
                            bool all_dead = true;
                            auto auit = uses_of.find(ak);
                            if (auit != uses_of.end()) {
                                for (Insn *au : auit->second) {
                                    if (!au->defines() || (!cone.count(au->dst_key()) && !dead.count(au->dst_key()))) {
                                        all_dead = false;
                                        break;
                                    }
                                }
                            }
                            if (all_dead) {
                                cone.insert(ak);
                                for (const auto &as : ad->srcs) {
                                    if (as.is_var()) bw.push_back(as.key());
                                }
                            }
                        }
                    }
                }
            }
        }
        return cone;
    }

    struct GenctlChain {
        EW ew = EW::None;
        int n_lanes = 0;
        bool full_coverage = false;
        bool zero_base = false;
        std::vector<std::optional<Operand>> lanes;
    };

    bool is_zero_operand(const Operand &op) const {
        if (op.is_const) return op.val.is_zero();
        auto it = defs.find(op.key());
        return it != defs.end() && it->second->op == Op::CONST &&
               !it->second->srcs.empty() && it->second->srcs[0].is_const &&
               it->second->srcs[0].val.is_zero();
    }

    std::optional<uint32_t> genctl_const_slot(const Operand &mask_op, EW *out_ew = nullptr) const {
        if (!mask_op.is_var()) return std::nullopt;
        auto cit = defs.find(mask_op.key());
        if (cit == defs.end() || cit->second->op != Op::GENCTL || cit->second->srcs.empty()) {
            return std::nullopt;
        }
        Insn *c_insn = cit->second;
        if (out_ew) *out_ew = c_insn->ew;
        auto ca = scalarize::addr_expr(c_insn->srcs[0], defs);
        if (!ca.has_base || key_reg(ca.base) == regs::SP || ca.aligned) {
            return ca.offset & 0xFu;
        }
        return std::nullopt;
    }

    std::optional<GenctlChain> try_unpack_genctl_chain(const Insn &shuf) const {
        GenctlChain ch;
        const Insn *cur = &shuf;
        for (int step = 0; step < 16; ++step) {
            if (!cur || cur->op != Op::SHUFB || cur->srcs.size() != 3) break;
            EW c_ew = EW::None;
            auto slot = genctl_const_slot(cur->srcs[2], &c_ew);
            if (!slot.has_value() || c_ew == EW::None || c_ew == EW::Q) return std::nullopt;
            if (ch.ew == EW::None) {
                ch.ew = c_ew;
                ch.n_lanes = 16 / static_cast<int>(c_ew);
                ch.lanes.assign(static_cast<size_t>(ch.n_lanes), std::nullopt);
            } else if (c_ew != ch.ew) {
                return std::nullopt;
            }
            int idx = static_cast<int>(*slot / static_cast<uint32_t>(c_ew));
            if (idx < 0 || idx >= ch.n_lanes) return std::nullopt;
            if (!ch.lanes[static_cast<size_t>(idx)].has_value()) {
                ch.lanes[static_cast<size_t>(idx)] = cur->srcs[0];
            }
            const Operand &old = cur->srcs[1];
            if (is_zero_operand(old)) {
                ch.zero_base = true;
                break;
            }
            if (!old.is_var()) break;
            auto oit = defs.find(old.key());
            if (oit == defs.end() || oit->second->op != Op::SHUFB) break;
            cur = oit->second;
        }
        if (ch.lanes.empty()) return std::nullopt;
        ch.full_coverage = true;
        for (const auto &ln : ch.lanes) {
            if (!ln.has_value()) { ch.full_coverage = false; break; }
        }
        if (!ch.full_coverage && !ch.zero_base) return std::nullopt;
        return ch;
    }

    std::unordered_set<VarKey> compute_inlinable() const {
        std::unordered_map<VarKey, std::unordered_set<uint32_t>> rendered;
        for (const auto &[uid, args] : call_args) {
            for (const auto &a : args) {
                if (a.is_var()) rendered[a.key()].insert(uid);
            }
        }

        std::unordered_map<VarKey, int> use_count;
        std::unordered_map<VarKey, Insn *> use_site;
        std::unordered_map<VarKey, std::vector<Insn *>> use_sites;

        for (auto &b : func.blocks) {
            for (auto &insn_ptr : b->insns) {
                Insn *insn = insn_ptr.get();
                if (insn->defines() && debris.find(insn->dst_key()) != debris.end()) continue;

                std::vector<Operand> real_srcs;
                if (insn->op == Op::RET) {
                    for (const auto &s : insn->srcs) {
                        bool is_ret_reg = (s.reg == regs::ARG_FIRST) ||
                                          (two_reg_return && s.reg == regs::ARG_FIRST + 1);
                        if (s.is_var() && is_ret_reg && s.ver != 0) real_srcs.push_back(s);
                    }
                } else if (insn->op == Op::CALL || insn->op == Op::ICALL || insn->op == Op::TCALL) {
                    int n_real = 0;
                    op_is_abi(insn->op, &n_real);
                    for (int i = 0; i < n_real && i < static_cast<int>(insn->srcs.size()); ++i) {
                        if (insn->srcs[i].is_var()) real_srcs.push_back(insn->srcs[i]);
                    }
                    auto cit = call_args.find(insn->uid);
                    if (cit != call_args.end()) {
                        for (const auto &a : cit->second) real_srcs.push_back(a);
                    }
                } else {
                    for (const auto &s : insn->srcs) {
                        if (s.is_var()) real_srcs.push_back(s);
                    }
                }

                for (const auto &u : real_srcs) {
                    if (!u.is_var()) continue;
                    VarKey k = u.key();
                    ++use_count[k];
                    use_site[k] = insn;
                    use_sites[k].push_back(insn);
                }
            }
        }

        std::unordered_set<VarKey> ok;
        for (const auto &[key, insn] : defs) {
            bool is_arg = rendered.find(key) != rendered.end();
            if (insn->op == Op::PHI || insn->op == Op::UNDEF || op_has_side_effects(insn->op)) continue;
            if (insn->op == Op::CONST) {
                if (is_arg) {
                    const auto &rcalls = rendered.at(key);
                    bool all_in_calls = true;
                    auto sit = use_sites.find(key);
                    if (sit != use_sites.end()) {
                        for (Insn *s : sit->second) {
                            if (rcalls.find(s->uid) == rcalls.end()) {
                                all_in_calls = false;
                                break;
                            }
                        }
                    }
                    if (all_in_calls) ok.insert(key);
                }
                continue;
            }
            auto ucit = use_count.find(key);
            if (ucit == use_count.end() || ucit->second != 1) continue;
            Insn *site = use_site.at(key);
            if (site->op == Op::PHI) continue;
            const bool ret_shuf_chain =
                site->op == Op::RET && two_reg_return &&
                insn->op == Op::SHUFB && try_unpack_genctl_chain(*insn).has_value();
            if (op_is_abi(site->op) &&
                !(is_arg && (site->op == Op::CALL || site->op == Op::ICALL || site->op == Op::TCALL)) &&
                !ret_shuf_chain) {
                continue;
            }
            if (site->block_id != insn->block_id) continue;
            if (insn->op == Op::SHUFB && site->op == Op::SHUFB &&
                genctl_const_slot(site->srcs.size() >= 3 ? site->srcs[2] : Operand{}).has_value() &&
                !try_unpack_genctl_chain(*site).has_value()) {
                continue;
            }
            ok.insert(key);
        }

        // Precompute per-block instruction indices for O(1) hazard checks.
        std::unordered_map<const Insn *, size_t> insn_pos;
        for (const auto &b : func.blocks) {
            for (size_t j = 0; j < b->insns.size(); ++j) {
                insn_pos[b->insns[j].get()] = j;
            }
        }

        // Post-OutSSA anti-aliasing & memory-hazard pruning fixpoint:
        // Never sink an expression past an intervening write to any C variable name it reads
        // (nor sink a memory read past an intervening memory write / side effect) up to its
        // final transitive evaluation site.
        while (true) {
            std::vector<VarKey> unsafe;
            for (VarKey key : ok) {
                auto dit = defs.find(key);
                if (dit == defs.end()) continue;
                Insn *insn = dit->second;
                if (insn->op == Op::CONST) continue;
                auto sit = use_site.find(key);
                if (sit == use_site.end()) continue;

                // Follow transitive inlining chain to the actual emission site in C.
                Insn *eval_site = sit->second;
                int hop = 0;
                while (eval_site && eval_site->defines() &&
                       ok.find(eval_site->dst_key()) != ok.end() && hop++ < 32) {
                    auto nsit = use_site.find(eval_site->dst_key());
                    if (nsit == use_site.end() || nsit->second->block_id != insn->block_id) break;
                    eval_site = nsit->second;
                }
                if (!eval_site || eval_site->block_id != insn->block_id) {
                    unsafe.push_back(key);
                    continue;
                }

                auto p0 = insn_pos.find(insn);
                auto p1 = insn_pos.find(eval_site);
                if (p0 == insn_pos.end() || p1 == insn_pos.end() || p0->second >= p1->second) {
                    continue;
                }
                size_t i0 = p0->second;
                size_t i1 = p1->second;

                std::unordered_set<std::string> read_cnames;
                for (const auto &s : insn->srcs) {
                    if (s.is_var() && !regs::is_pseudo(s.reg) && ok.find(s.key()) == ok.end()) {
                        read_cnames.insert(namer->name(s));
                    }
                }
                bool is_mread = op_is_mem_read(insn->op);

                const Block &blk = *func.blocks[insn->block_id];
                bool hazard = false;
                for (size_t j = i0 + 1; j < i1; ++j) {
                    const Insn *mid = blk.insns[j].get();
                    if (mid->op == Op::PHI || mid->op == Op::UNDEF) continue;
                    if (mid->defines() && debris.find(mid->dst_key()) != debris.end()) continue;
                    if (is_mread && (op_is_mem_write(mid->op) || op_has_side_effects(mid->op))) {
                        hazard = true;
                        break;
                    }
                    if (!read_cnames.empty() && mid->defines() && !regs::is_pseudo(mid->dst_reg)) {
                        if (ok.find(mid->dst_key()) == ok.end()) {
                            if (read_cnames.find(namer->name_key(mid->dst_key())) != read_cnames.end()) {
                                hazard = true;
                                break;
                            }
                        }
                    }
                }
                if (hazard) unsafe.push_back(key);
            }
            if (unsafe.empty()) break;
            for (VarKey k : unsafe) ok.erase(k);
        }

        // Depth-cap pruning fixpoint
        while (true) {
            std::unordered_map<VarKey, int> pos;
            auto walk = [&](auto &self, VarKey k, std::unordered_set<VarKey> &seen) -> int {
                auto pit = pos.find(k);
                if (pit != pos.end()) return pit->second;
                auto sit = use_site.find(k);
                Insn *site = (sit != use_site.end()) ? sit->second : nullptr;
                int d = 0;
                if (site && site->defines()) {
                    VarKey sk = site->dst_key();
                    if (ok.find(sk) != ok.end() && seen.find(sk) == seen.end()) {
                        seen.insert(k);
                        d = self(self, sk, seen) + 1;
                    }
                }
                pos[k] = d;
                return d;
            };

            std::vector<VarKey> too_deep;
            for (VarKey k : ok) {
                std::unordered_set<VarKey> seen = {k};
                if (walk(walk, k, seen) >= MAX_INLINE_DEPTH) {
                    too_deep.push_back(k);
                }
            }
            if (too_deep.empty()) break;
            for (VarKey k : too_deep) ok.erase(k);
        }
        return ok;
    }

    // --- Name & Type helpers ---
    std::string nm(const Operand &v) {
        std::string name = namer->name(v);
        printed.insert(name);
        return lookup_rename(name);
    }

    std::string nma(const Operand &v) {
        std::string name = namer->name(v);
        printed.insert(name);
        assigned.insert(name);
        return lookup_rename(name);
    }

    const types::Ty *type_of(const Operand &v) const {
        return types_map.of_var(v);
    }

    const types::Ty *type_of_key(VarKey k) const {
        return types_map.of(k);
    }

    std::string ctype_str(const types::Ty *ty, const std::string &fallback = "qword") const {
        if (!ty) return fallback;
        if (ty->kind == types::TyKind::UNK &&
            ty->width != 1 && ty->width != 2 && ty->width != 4 && ty->width != 8) {
            return fallback;
        }
        return ty->str();
    }

    std::string access_type(const Insn &insn) const {
        if (insn.op == Op::LOADQ || insn.op == Op::STOREQ) return "qword";
        if (insn.op == Op::LOADU) return "qword_unaligned";
        const types::Ty *ty = nullptr;
        if (insn.op == Op::LOAD) {
            if (insn.defines()) ty = type_of_key(insn.dst_key());
        } else if (insn.srcs.size() >= 3) {
            ty = type_of(insn.srcs[2]);
        }
        if (ty && (ty->kind == types::TyKind::INT || ty->kind == types::TyKind::FLT) &&
            ty->width == static_cast<int>(insn.ew)) {
            return ty->str();
        }
        return ew_ctype(insn.ew);
    }

    bool scalarish(const Insn &insn) const {
        if (insn.scalar) return true;
        if (!insn.defines()) return false;
        const types::Ty *t = type_of_key(insn.dst_key());
        return t && (t->kind == types::TyKind::INT || t->kind == types::TyKind::PTR || t->kind == types::TyKind::UNK) &&
               t->width > 0 && t->width <= 8;
    }

    std::string byte_ptr(const Operand &v, const std::string &text) const {
        if (hide_casts) return text;
        const types::Ty *t = type_of(v);
        if (!t || t->kind != types::TyKind::PTR) return text;
        if (t->pointee && t->pointee->width == 1) return text;
        if (starts_with(text, "(char *)")) return text;
        return is_c_ident(text) ? ("(char *)" + text) : ("(char *)(" + text + ")");
    }

    std::string cast_expr(const std::string &tstr, const std::string &expr) const {
        if (hide_casts) return expr;
        return "(" + tstr + ")" + expr;
    }

    // --- Constant & Numform formatting ---
    void reset_stmt_consts(std::optional<uint64_t> primary_ea) {
        cur_stmt_ea = primary_ea;
        cur_expr_ea = primary_ea;
        cur_const_idx = 0;
        cur_line_consts.clear();
    }

    std::pair<std::string, std::optional<uint64_t>> lookup_numform(int idx) const {
        if (user_numforms.empty()) return {"", cur_stmt_ea};
        std::vector<std::pair<uint64_t, int>> cands;
        if (cur_stmt_ea.has_value()) cands.push_back({*cur_stmt_ea, idx});
        if (cur_expr_ea.has_value() && cur_expr_ea != cur_stmt_ea) cands.push_back({*cur_expr_ea, 0});
        if (idx == 0) {
            for (uint64_t iea : current_inlined_eas) cands.push_back({iea, 0});
        }
        for (const auto &[ea, i] : cands) {
            char k_hex[48];
            std::snprintf(k_hex, sizeof(k_hex), "0x%llx:%d", static_cast<unsigned long long>(ea), i);
            auto it = user_numforms.find(k_hex);
            if (it == user_numforms.end()) {
                std::string k_dec = std::to_string(ea) + ":" + std::to_string(i);
                it = user_numforms.find(k_dec);
            }
            if (it != user_numforms.end() && !it->second.empty()) {
                return {it->second, cur_stmt_ea.has_value() ? cur_stmt_ea : std::optional<uint64_t>(ea)};
            }
        }
        return {"", cur_stmt_ea};
    }

    std::string record_const(int idx, std::optional<uint64_t> ea, uint64_t uval, uint64_t uval_hi,
                             int bits, const std::string &text, const std::string &default_form,
                             const std::string &applied_form = "", bool is_addr = false,
                             std::optional<uint64_t> addr_val = std::nullopt) {
        LineConstSpan sp;
        sp.idx = idx;
        sp.ea = ea.has_value() ? *ea : (cur_stmt_ea.has_value() ? *cur_stmt_ea : 0);
        sp.val = uval;
        sp.val_hi = uval_hi;
        sp.bits = bits;
        sp.text = text;
        sp.default_form = default_form;
        sp.form = applied_form.empty() ? default_form : applied_form;
        sp.applied = !applied_form.empty();
        sp.is_addr = is_addr;
        sp.addr_val = addr_val.has_value() ? *addr_val : uval;
        cur_line_consts.push_back(std::move(sp));
        return text;
    }

    std::string apply_numform(uint64_t uval, int bits, const std::string &form,
                              std::optional<uint64_t> addr_val = std::nullopt, bool is_addr = false) {
        uint64_t mask = (bits >= 64 || bits <= 0) ? ~uint64_t(0) : ((1ULL << bits) - 1ULL);
        uint64_t uv = uval & mask;
        int64_t sv = 0;
        if (bits >= 64) {
            sv = static_cast<int64_t>(uv);
        } else if (bits > 0 && uv >= (1ULL << (bits - 1))) {
            sv = static_cast<int64_t>(uv) - static_cast<int64_t>(1ULL << bits);
        } else {
            sv = static_cast<int64_t>(uv);
        }
        uint64_t av = addr_val.has_value() ? *addr_val : uv;
        std::string fl = to_lower_str(form);

        char buf[80];
        if (starts_with(fl, "enum:")) {
            std::string ename = trim_str(form.substr(5));
            if (!ename.empty()) return ename;
            std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(uv));
            return buf;
        }
        if (fl == "hex" || fl == "uhex") {
            std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(uv));
            return buf;
        }
        if (fl == "shex") {
            if (sv < 0) {
                uint64_t mag = static_cast<uint64_t>(-sv);
                std::snprintf(buf, sizeof(buf), "-0x%llX", static_cast<unsigned long long>(mag));
            } else {
                std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(uv));
            }
            return buf;
        }
        if (fl == "dec") {
            if (sv < 0 && static_cast<uint64_t>(-sv) <= 0xFFFFULL && bits >= 16) {
                std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(sv));
                return buf;
            }
            std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(uv));
            return buf;
        }
        if (fl == "udec") {
            std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(uv));
            return buf;
        }
        if (fl == "sdec" || fl == "signed") {
            std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(sv));
            return buf;
        }
        if (fl == "char") {
            return format_char_const(uv, bits);
        }
        if (fl == "bin") {
            if (uv == 0) return "0b0";
            std::string b;
            uint64_t t = uv;
            while (t > 0) {
                b.push_back((t & 1ULL) ? '1' : '0');
                t >>= 1;
            }
            std::reverse(b.begin(), b.end());
            return "0b" + b;
        }
        if (fl == "oct") {
            if (uv == 0) return "0";
            std::snprintf(buf, sizeof(buf), "0%llo", static_cast<unsigned long long>(uv));
            return buf;
        }
        if (fl == "inv") {
            std::snprintf(buf, sizeof(buf), "~0x%llX", static_cast<unsigned long long>((~uv) & mask));
            return buf;
        }
        if (fl == "str") {
            if (auto lit = query_str(av); lit.has_value()) return *lit;
            if (auto lit2 = query_relaxed_str(av); lit2.has_value()) return *lit2;
            return format_char_const(uv, bits);
        }
        if (fl == "nostr") {
            std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(is_addr ? av : uv));
            return buf;
        }
        if (fl == "offset") {
            if (auto sym = query_sym(av); sym.has_value()) {
                return format_sym_ref(*sym, av);
            }
            std::string fn_nm = query_name(av);
            if (!fn_nm.empty()) {
                sym_eas[fn_nm] = av;
                return "&" + fn_nm;
            }
            std::snprintf(buf, sizeof(buf), "&unk_%llX", static_cast<unsigned long long>(av));
            return buf;
        }
        std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(uv));
        return buf;
    }

    std::string format_sym_ref(const std::string &sym, uint64_t av) {
        auto pos = sym.find(" + ");
        if (pos != std::string::npos) {
            std::string base = sym.substr(0, pos);
            std::string off = sym.substr(pos + 3);
            std::string eff_base = lookup_rename(base);
            sym_eas[eff_base] = av;
            return "&" + eff_base + " + " + off;
        }
        std::string eff_sym = lookup_rename(sym);
        sym_eas[eff_sym] = av;
        return "&" + eff_sym;
    }

    std::string fmt_imm(int64_t val, int bits = 32, const std::string &default_form = "dec") {
        int idx = cur_const_idx++;
        uint64_t mask = (bits >= 64) ? ~uint64_t(0) : ((1ULL << bits) - 1ULL);
        uint64_t uval = static_cast<uint64_t>(val) & mask;
        auto [form, form_ea] = lookup_numform(idx);
        if (!form.empty()) {
            std::string txt = apply_numform(uval, bits, form, uval, false);
            return record_const(idx, form_ea, uval, 0, bits, txt, default_form, form);
        }
        char buf[48];
        if (default_form == "dec") {
            std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(val));
        } else {
            std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(uval));
        }
        return record_const(idx, cur_stmt_ea, uval, 0, bits, buf, default_form);
    }

    std::string fmt_const_op(const Operand &c, bool scalar, bool strings = true, EW ew = EW::None) {
        int idx = cur_const_idx++;
        uint64_t addr_val = c.val.word0();
        EW eff_ew = (ew != EW::None) ? ew : c.ew;
        int bits = 32;
        uint64_t uval = addr_val;
        uint64_t uval_hi = 0;

        bool has_rep = false;
        EW rep_ew = EW::W;
        uint64_t rep_lane = 0;

        if (c.val.is_zero()) {
            bits = (eff_ew == EW::B || eff_ew == EW::H || eff_ew == EW::W || eff_ew == EW::D)
                       ? (static_cast<int>(eff_ew) * 8)
                       : 32;
            uval = 0;
        } else if (c.val.is_all_ones()) {
            bits = (eff_ew == EW::B || eff_ew == EW::H || eff_ew == EW::W || eff_ew == EW::D)
                       ? (static_cast<int>(eff_ew) * 8)
                       : 32;
            uval = (bits >= 64) ? ~uint64_t(0) : ((1ULL << bits) - 1ULL);
        } else {
            EW cands[5];
            int nc = 0;
            if (eff_ew != EW::None && eff_ew != EW::Q) cands[nc++] = eff_ew;
            for (EW cand : {EW::B, EW::H, EW::W, EW::D}) {
                bool dup = false;
                for (int i = 0; i < nc; ++i) if (cands[i] == cand) dup = true;
                if (!dup) cands[nc++] = cand;
            }
            for (int i = 0; i < nc; ++i) {
                uint64_t ln = 0;
                if (c.val.is_replicated(cands[i], &ln)) {
                    has_rep = true;
                    rep_ew = cands[i];
                    rep_lane = ln;
                    bits = static_cast<int>(rep_ew) * 8;
                    uval = ln;
                    break;
                }
            }
            if (!has_rep && !scalar && !c.val.low96_zero()) {
                bits = 128;
                uval = c.val.lo;
                uval_hi = c.val.hi;
            }
        }

        auto [form, form_ea] = lookup_numform(idx);
        if (!form.empty()) {
            std::string fl = to_lower_str(form);
            bool is_addr_hint = (fl == "str" || fl == "nostr" || fl == "offset");
            std::string txt = apply_numform(uval, bits == 128 ? 64 : bits, form, addr_val, is_addr_hint);
            return record_const(idx, form_ea, uval, uval_hi, bits, txt, "hex", form, is_addr_hint, addr_val);
        }

        if (strings) {
            if (auto lit = query_str(addr_val); lit.has_value()) {
                return record_const(idx, cur_stmt_ea, addr_val, 0, 32, *lit, "str", "", true, addr_val);
            }
        }
        if (auto sym = query_sym(addr_val); sym.has_value()) {
            std::string txt = format_sym_ref(*sym, addr_val);
            return record_const(idx, cur_stmt_ea, addr_val, 0, 32, txt, "offset", "", true, addr_val);
        }
        if (c.val.is_zero()) {
            return record_const(idx, cur_stmt_ea, 0, 0, bits, "0", "dec", "", false, 0);
        }
        if (c.val.is_all_ones()) {
            if (eff_ew == EW::B) {
                return record_const(idx, cur_stmt_ea, 0xFF, 0, 8, "0xFF", "hex");
            }
            return record_const(idx, cur_stmt_ea, uval, 0, bits, "-0x1", "shex");
        }

        char buf[64];
        if (has_rep) {
            if (rep_ew == EW::W) {
                if (rep_lane >= 0x80000000ULL && (0x100000000ULL - rep_lane) <= 0xFFFFULL) {
                    std::snprintf(buf, sizeof(buf), "-0x%llX",
                                  static_cast<unsigned long long>(0x100000000ULL - rep_lane));
                    return record_const(idx, cur_stmt_ea, rep_lane, 0, 32, buf, "shex", "", false, addr_val);
                }
                std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(rep_lane));
                return record_const(idx, cur_stmt_ea, rep_lane, 0, 32, buf, "hex", "", false, addr_val);
            }
            if (rep_ew == EW::D) {
                if (rep_lane >= 0x8000000000000000ULL && (uint64_t(0) - rep_lane) <= 0xFFFFULL) {
                    std::snprintf(buf, sizeof(buf), "-0x%llX",
                                  static_cast<unsigned long long>(uint64_t(0) - rep_lane));
                    return record_const(idx, cur_stmt_ea, rep_lane, 0, 64, buf, "shex", "", false, addr_val);
                }
                std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(rep_lane));
                return record_const(idx, cur_stmt_ea, rep_lane, 0, 64, buf, "hex", "", false, addr_val);
            }
            if (rep_ew == EW::H) {
                if (rep_lane >= 0x8000ULL && (0x10000ULL - rep_lane) <= 0xFFULL) {
                    std::snprintf(buf, sizeof(buf), "-0x%llX",
                                  static_cast<unsigned long long>(0x10000ULL - rep_lane));
                    return record_const(idx, cur_stmt_ea, rep_lane, 0, 16, buf, "shex", "", false, addr_val);
                }
                std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(rep_lane));
                return record_const(idx, cur_stmt_ea, rep_lane, 0, 16, buf, "hex", "", false, addr_val);
            }
            std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(rep_lane));
            return record_const(idx, cur_stmt_ea, rep_lane, 0, 8, buf, "hex", "", false, addr_val);
        }

        if (scalar || c.val.low96_zero()) {
            std::string txt = c.scalar_str();
            std::string df = starts_with(txt, "-0x") ? "shex" : (starts_with(txt, "0x") ? "hex" : "dec");
            return record_const(idx, cur_stmt_ea, addr_val, 0, 32, txt, df, "", false, addr_val);
        }
        std::string txt = "0x" + c.val.hex32_upper();
        return record_const(idx, cur_stmt_ea, c.val.lo, c.val.hi, 128, txt, "hex", "", false, addr_val);
    }

    // --- Stack slots & UDT resolution ---
    void ensure_slots() {
        if (slots_ready) return;
        slots_ready = true;
        const VarKey sp_in = make_var_key(regs::SP, 0);

        std::unordered_set<VarKey> tainted = {sp_in};
        bool changed = true;
        while (changed) {
            changed = false;
            for (const auto &b : func.blocks) {
                for (const auto &insn : b->insns) {
                    if (!insn->defines() || regs::is_pseudo(insn->dst_reg)) continue;
                    if (tainted.find(insn->dst_key()) != tainted.end()) continue;
                    for (const auto &s : insn->srcs) {
                        if (s.is_var() && !regs::is_pseudo(s.reg) && tainted.find(s.key()) != tainted.end()) {
                            tainted.insert(insn->dst_key());
                            changed = true;
                            break;
                        }
                    }
                }
            }
        }

        struct RawSlotGroup {
            bool has_ew = false;
            EW ew = EW::Q;
            std::unordered_map<EW, std::unordered_set<std::string>> types_by_ew;
            std::string name;
        };
        std::unordered_map<uint32_t, RawSlotGroup> groups;

        for (const auto &b : func.blocks) {
            for (const auto &insn : b->insns) {
                if (insn->defines() && debris.find(insn->dst_key()) != debris.end()) continue;
                if (op_is_mem_read(insn->op) || op_is_mem_write(insn->op)) {
                    if (insn->srcs.size() < 2) continue;
                    auto ae = scalarize::addr_expr(insn->srcs[1], defs);
                    if (!ae.has_base || ae.base != sp_in) {
                        if (ae.has_base && tainted.find(ae.base) != tainted.end()) {
                            ++stack_unresolved;
                        }
                        continue;
                    }
                    auto &g = groups[ae.offset];
                    if (!g.has_ew || static_cast<int>(insn->ew) > static_cast<int>(g.ew)) {
                        g.ew = insn->ew;
                        g.has_ew = true;
                    }
                    g.types_by_ew[insn->ew].insert(access_type(*insn));
                    if (g.name.empty() && insn->ea != 0) {
                        if (auto hit = query_stk(insn->ea); hit.has_value() && !hit->name.empty()) {
                            g.name = hit->name;
                        }
                    }
                } else if (insn->op == Op::ADD && insn->defines()) {
                    auto ae = scalarize::addr_expr(insn->dst_as_var(), defs);
                    if (ae.has_base && ae.base == sp_in) {
                        int64_t soff = frame::signed_offset(ae.offset);
                        if (soff != 0 && soff >= -0x4000 && soff <= 0x200) {
                            auto &g = groups[ae.offset];
                            if (!g.has_ew) {
                                g.ew = EW::Q;
                                g.has_ew = true;
                            }
                            g.types_by_ew[EW::Q].insert("qword");
                            if (g.name.empty() && insn->ea != 0) {
                                if (auto hit = query_stk(insn->ea); hit.has_value() && !hit->name.empty()) {
                                    g.name = hit->name;
                                }
                            }
                            if (g.name.empty()) {
                                char nbuf[32];
                                uint64_t mag = static_cast<uint64_t>(soff < 0 ? -soff : soff);
                                std::snprintf(nbuf, sizeof(nbuf), "%s_%llX",
                                              (soff < 0 ? "var" : "arg"),
                                              static_cast<unsigned long long>(mag));
                                g.name = nbuf;
                            }
                        }
                    }
                }
            }
        }

        std::unordered_set<int64_t> reserved;
        for (const auto &[off, _] : frame_info.saves) reserved.insert(off);
        if (frame_info.back_chain.has_value()) reserved.insert(*frame_info.back_chain);

        for (auto &[off, g] : groups) {
            if (g.name.empty() || reserved.find(frame::signed_offset(off)) != reserved.end()) continue;
            const auto &widest = g.types_by_ew[g.ew];
            std::string ct = (widest.size() == 1) ? *widest.begin() : ew_ctype(g.ew);
            sp_slots[off] = SlotHitInfo{g.name, ct, g.ew};
        }
    }

    std::optional<std::string> addr_of_slot(const Insn &insn) {
        ensure_slots();
        if (sp_slots.empty() || !insn.defines()) return std::nullopt;
        const VarKey sp_in = make_var_key(regs::SP, 0);
        auto ae = scalarize::addr_expr(insn.dst_as_var(), defs);
        if (!ae.has_base || ae.base != sp_in) return std::nullopt;

        uint32_t slot_base = ae.offset & ~0xFu;
        uint32_t byte_off = ae.offset & 0xFu;
        auto it = sp_slots.find(slot_base);
        if (it == sp_slots.end()) {
            it = sp_slots.find(ae.offset);
            if (it == sp_slots.end()) return std::nullopt;
            byte_off = 0;
        }
        stack_decls[it->second.name] = it->second.ctype;
        std::string eff_hit = lookup_rename(it->second.name);
        if (byte_off == 0) return "&" + eff_hit;
        return "(char *)&" + eff_hit + " + " + std::to_string(byte_off);
    }

    std::optional<std::string> stack_indexed_addr(const Operand &v, int depth) {
        ensure_slots();
        if (sp_slots.empty()) return std::nullopt;

        Operand cur = v;
        if (cur.is_var()) {
            auto dit = defs.find(cur.key());
            if (dit != defs.end() && dit->second->op == Op::AND && dit->second->srcs.size() == 2 &&
                dit->second->srcs[1].is_const) {
                uint32_t m = dit->second->srcs[1].val.word0();
                if (m == 0x3FFF0u || m == 0x3FFFFu) cur = dit->second->srcs[0];
            }
        }
        if (!cur.is_var()) return std::nullopt;
        auto dit = defs.find(cur.key());
        if (dit == defs.end() || dit->second->op != Op::ADD || dit->second->ew != EW::W ||
            dit->second->srcs.size() != 2) {
            return std::nullopt;
        }
        const VarKey sp_in = make_var_key(regs::SP, 0);
        for (int p = 0; p < 2; ++p) {
            const Operand &sp_term = dit->second->srcs[p];
            const Operand &idx_term = dit->second->srcs[1 - p];
            auto a_sp = scalarize::addr_expr(sp_term, defs);
            if (a_sp.has_base && a_sp.base == sp_in) {
                auto a_idx = scalarize::addr_expr(idx_term, defs);
                if (a_idx.has_base && a_idx.base != sp_in) {
                    uint32_t tot_off = a_sp.offset + a_idx.offset;
                    uint32_t slot_base = tot_off & ~0xFu;
                    uint32_t byte_off = tot_off & 0xFu;
                    auto hit = sp_slots.find(slot_base);
                    if (hit == sp_slots.end()) {
                        hit = sp_slots.find(tot_off);
                        byte_off = 0;
                    }
                    if (hit == sp_slots.end()) {
                        int64_t soff = frame::signed_offset(slot_base);
                        if (soff != 0 && soff >= -0x4000 && soff <= 0x200) {
                            char nbuf[32];
                            uint64_t mag = static_cast<uint64_t>(soff < 0 ? -soff : soff);
                            std::snprintf(nbuf, sizeof(nbuf), "%s_%llX",
                                          (soff < 0 ? "var" : "arg"),
                                          static_cast<unsigned long long>(mag));
                            sp_slots[slot_base] = SlotHitInfo{nbuf, "qword", EW::Q};
                            hit = sp_slots.find(slot_base);
                        }
                    }
                    if (hit != sp_slots.end()) {
                        stack_decls[hit->second.name] = hit->second.ctype;
                        std::string slot_name = lookup_rename(hit->second.name);
                        Operand idx_var = Operand::make_var(key_reg(a_idx.base), key_ver(a_idx.base));
                        std::string idx_str = render_operand(idx_var, depth, true, false, true);
                        if (byte_off == 0) {
                            return "(char *)&" + slot_name + " + " + idx_str;
                        }
                        char obuf[32];
                        std::snprintf(obuf, sizeof(obuf), "0x%X", byte_off);
                        return "(char *)&" + slot_name + " + " + idx_str + " + " + obuf;
                    }
                }
            }
        }
        return std::nullopt;
    }

    std::optional<FieldResolution> resolve_field_path(const std::string &type_name, int byte_off,
                                                      int access_size, int depth = 0) {
        if (depth > 4 || byte_off < 0) return std::nullopt;
        const UdtInfo *udt = query_udt(type_name);
        if (!udt) return std::nullopt;
        for (const auto &f : udt->fields) {
            if (byte_off >= f.byte_offset && byte_off < f.byte_offset + f.byte_size) {
                int rem = byte_off - f.byte_offset;
                if (f.array_elem_size > 0) {
                    int arr_idx = rem / f.array_elem_size;
                    int sub_rem = rem % f.array_elem_size;
                    std::string idx_p = f.name + "[" + std::to_string(arr_idx) + "]";
                    if (sub_rem == 0 && f.array_elem_size == access_size) {
                        return FieldResolution{idx_p, access_size, 0};
                    }
                    if (auto sub = resolve_field_path(f.type_str, sub_rem, access_size, depth + 1); sub.has_value()) {
                        return FieldResolution{idx_p + "." + sub->path, sub->matched_size, sub->rem};
                    }
                    return FieldResolution{idx_p, f.array_elem_size, sub_rem};
                }
                if (rem == 0 && f.byte_size == access_size) {
                    return FieldResolution{f.name, f.byte_size, 0};
                }
                if (auto sub = resolve_field_path(f.type_str, rem, access_size, depth + 1); sub.has_value()) {
                    return FieldResolution{f.name + "." + sub->path, sub->matched_size, sub->rem};
                }
                return FieldResolution{f.name, f.byte_size, rem};
            }
        }
        return std::nullopt;
    }

    std::optional<std::string> user_type_of_var(VarKey base_key) const {
        int reg = key_reg(base_key);
        int ver = key_ver(base_key);
        std::string raw_nm = namer->name_key(base_key);
        std::string eff_nm = lookup_rename(raw_nm);
        if (auto it = user_types.find(raw_nm); it != user_types.end()) return it->second;
        if (auto it = user_types.find(eff_nm); it != user_types.end()) return it->second;
        if (ver == 0) {
            if (auto it = param_proto_types.find(reg); it != param_proto_types.end()) return it->second;
            if (this_reg.has_value() && reg == *this_reg && member_class.has_value()) {
                return *member_class + " *";
            }
        }
        return std::nullopt;
    }

    std::string format_member_access(const std::string &base_expr, const char *op_str,
                                     const FieldResolution &fr, const std::string &acc_ctype,
                                     int acc_size) const {
        std::string expr = base_expr + op_str + fr.path;
        if (fr.rem == 0 && fr.matched_size == acc_size) return expr;
        if (fr.rem == 0) return "*(" + acc_ctype + " *)&" + expr;
        char rbuf[32];
        std::snprintf(rbuf, sizeof(rbuf), "0x%X", static_cast<unsigned>(fr.rem));
        if (hide_casts) {
            return "*(" + acc_ctype + " *)(&" + expr + " + " + rbuf + ")";
        }
        return "*(" + acc_ctype + " *)((char *)&" + expr + " + " + rbuf + ")";
    }

    std::optional<std::string> resolve_typed_deref(const Insn &insn, int depth) {
        if (insn.srcs.size() < 2) return std::nullopt;
        const Operand &addr = insn.srcs[1];
        const int acc_size = static_cast<int>(insn.ew);
        const std::string acc_ctype = access_type(insn);
        const VarKey sp_in = make_var_key(regs::SP, 0);

        auto ae = scalarize::addr_expr(addr, defs);
        if (ae.has_base && ae.base != sp_in) {
            auto ut = user_type_of_var(ae.base);
            if (!ut.has_value()) {
                const types::Ty *bty = type_of_key(ae.base);
                if (bty && bty->kind == types::TyKind::PTR && bty->pointee &&
                    (bty->pointee->kind == types::TyKind::INT || bty->pointee->kind == types::TyKind::FLT ||
                     (bty->pointee->kind == types::TyKind::UNK &&
                      (bty->pointee->width == 1 || bty->pointee->width == 2 ||
                       bty->pointee->width == 4 || bty->pointee->width == 8)))) {
                    ut = bty->str();
                }
            }
            if (ut.has_value() && ut->find('*') != std::string::npos) {
                std::string stripped = trim_str(*ut);
                if (!stripped.empty() && stripped.back() == '*') {
                    std::string pointee_clean = strip_type_quals(stripped.substr(0, stripped.size() - 1));
                    if (!pointee_clean.empty() && pointee_clean != "void" &&
                        pointee_clean.find('*') == std::string::npos) {
                        int64_t soff = frame::signed_offset(ae.offset);
                        if (soff >= 0 && soff < 0x100000) {
                            Operand base_var = Operand::make_var(key_reg(ae.base), key_ver(ae.base));
                            if (const UdtInfo *udt = query_udt(pointee_clean)) {
                                if (soff < udt->size) {
                                    if (auto res = resolve_field_path(pointee_clean, static_cast<int>(soff), acc_size)) {
                                        return format_member_access(nm(base_var), "->", *res, acc_ctype, acc_size);
                                    }
                                } else if (udt->size > 0) {
                                    int arr_idx = static_cast<int>(soff) / udt->size;
                                    int rem = static_cast<int>(soff) % udt->size;
                                    if (auto res = resolve_field_path(pointee_clean, rem, acc_size)) {
                                        std::string bidx = nm(base_var) + "[" + std::to_string(arr_idx) + "]";
                                        return format_member_access(bidx, ".", *res, acc_ctype, acc_size);
                                    }
                                }
                            }
                            if (auto psz = prim_type_size(pointee_clean); psz.has_value() && *psz == acc_size &&
                                                                          (soff % *psz) == 0) {
                                std::string bname = nm(base_var);
                                if (soff == 0) return "*" + bname;
                                return bname + "[" + std::to_string(soff / *psz) + "]";
                            }
                        }
                    }
                }
            }
        }

        // Dynamic indexed address `base + idx` / `base + (idx << sh)` / `base + idx * elem_sz`
        if (addr.is_var()) {
            auto dit = defs.find(addr.key());
            if (dit != defs.end() && dit->second->op == Op::ADD && dit->second->ew == EW::W &&
                dit->second->srcs.size() == 2) {
                for (int p = 0; p < 2; ++p) {
                    const Operand &base_op = dit->second->srcs[p];
                    const Operand &idx_op = dit->second->srcs[1 - p];
                    if (!base_op.is_var() || base_op.key() == sp_in) continue;
                    auto ut = user_type_of_var(base_op.key());
                    if (!ut.has_value()) {
                        const types::Ty *bty = type_of_key(base_op.key());
                        if (bty && bty->kind == types::TyKind::PTR && bty->pointee &&
                            (bty->pointee->kind == types::TyKind::INT || bty->pointee->kind == types::TyKind::FLT ||
                             (bty->pointee->kind == types::TyKind::UNK &&
                              (bty->pointee->width == 1 || bty->pointee->width == 2 ||
                               bty->pointee->width == 4 || bty->pointee->width == 8)))) {
                            ut = bty->str();
                        }
                    }
                    if (!ut.has_value()) continue;
                    std::string stripped = trim_str(*ut);
                    if (stripped.empty() || stripped.back() != '*') continue;
                    std::string pointee_clean = strip_type_quals(stripped.substr(0, stripped.size() - 1));
                    if (pointee_clean.empty() || pointee_clean == "void" ||
                        pointee_clean.find('*') != std::string::npos) {
                        continue;
                    }
                    auto psz = prim_type_size(pointee_clean);
                    if (!psz.has_value() || *psz != acc_size) continue;
                    if (*psz == 1) {
                        return nm(base_op) + "[" + render_operand(idx_op, depth, true, false, true) + "]";
                    }
                    if (idx_op.is_var()) {
                        auto iit = defs.find(idx_op.key());
                        if (iit != defs.end() && iit->second->srcs.size() == 2 && iit->second->srcs[1].is_const) {
                            Insn *id_def = iit->second;
                            uint32_t c = id_def->srcs[1].val.word0();
                            if (id_def->op == Op::SHL && c < 16 && (1 << c) == *psz) {
                                return nm(base_op) + "[" + render_operand(id_def->srcs[0], depth, true, false, true) + "]";
                            }
                            if ((id_def->op == Op::MUL || id_def->op == Op::MPY) && static_cast<int>(c) == *psz) {
                                return nm(base_op) + "[" + render_operand(id_def->srcs[0], depth, true, false, true) + "]";
                            }
                        }
                    }
                }
            }
        }
        return std::nullopt;
    }

    std::optional<std::string> stack_name(const Insn &insn) {
        ensure_slots();
        if (sp_slots.empty() || insn.srcs.size() < 2) return std::nullopt;
        const VarKey sp_in = make_var_key(regs::SP, 0);
        auto ae = scalarize::addr_expr(insn.srcs[1], defs);
        if (!ae.has_base || ae.base != sp_in) return std::nullopt;

        int64_t soff = frame::signed_offset(ae.offset);
        int acc_size = static_cast<int>(insn.ew);
        std::string t = access_type(insn);

        if (!user_types.empty()) {
            for (const auto &[slot_off, sinfo] : sp_slots) {
                std::string eff_sname = lookup_rename(sinfo.name);
                std::string ut;
                if (auto it = user_types.find(sinfo.name); it != user_types.end()) ut = it->second;
                else if (auto it2 = user_types.find(eff_sname); it2 != user_types.end()) ut = it2->second;
                if (ut.empty() || ut.find('*') != std::string::npos) continue;
                int64_t rel = soff - frame::signed_offset(slot_off);
                if (rel < 0) continue;
                std::string clean_ut = strip_type_quals(ut);
                if (const UdtInfo *udt = query_udt(clean_ut); udt && rel < udt->size) {
                    if (auto res = resolve_field_path(clean_ut, static_cast<int>(rel), acc_size)) {
                        stack_decls[sinfo.name] = sinfo.ctype;
                        return format_member_access(eff_sname, ".", *res, t, acc_size);
                    }
                }
            }
        }

        uint32_t slot_base = ae.offset & ~0xFu;
        uint32_t byte_off = ae.offset & 0xFu;
        auto hit = sp_slots.find(slot_base);
        if (hit == sp_slots.end()) {
            hit = sp_slots.find(ae.offset);
            if (hit == sp_slots.end()) return std::nullopt;
            byte_off = 0;
        }
        stack_decls[hit->second.name] = hit->second.ctype;
        std::string eff_name = lookup_rename(hit->second.name);

        std::string ut;
        if (auto it = user_types.find(hit->second.name); it != user_types.end()) ut = it->second;
        else if (auto it2 = user_types.find(eff_name); it2 != user_types.end()) ut = it2->second;
        if (!ut.empty() && ut.find('*') == std::string::npos) {
            std::string clean_ut = strip_type_quals(ut);
            if (const UdtInfo *udt = query_udt(clean_ut); udt && static_cast<int>(byte_off) < udt->size) {
                if (auto res = resolve_field_path(clean_ut, static_cast<int>(byte_off), acc_size)) {
                    return format_member_access(eff_name, ".", *res, t, acc_size);
                }
            }
        }

        if (byte_off == 0) {
            if (insn.ew == hit->second.ew) return eff_name;
            return "*(" + t + " *)&" + eff_name;
        }
        return "*(((" + t + " *)&" + eff_name + ") + " + std::to_string(byte_off) + ")";
    }

    // --- Core expression & statement rendering ---
    std::string render_addr(const Operand &v, int depth = 0, bool strings = true) {
        if (auto stk_idx = stack_indexed_addr(v, depth); stk_idx.has_value()) {
            return *stk_idx;
        }
        if (v.is_const) {
            int idx = cur_const_idx++;
            uint64_t av = v.val.word0();
            auto [form, form_ea] = lookup_numform(idx);
            if (!form.empty()) {
                std::string txt = apply_numform(av, 32, form, av, true);
                return record_const(idx, form_ea, av, 0, 32, txt, "hex", form, true, av);
            }
            if (strings) {
                if (auto lit = query_str(av); lit.has_value()) {
                    return record_const(idx, cur_stmt_ea, av, 0, 32, *lit, "str", "", true, av);
                }
            }
            if (auto sym = query_sym(av); sym.has_value()) {
                std::string txt = format_sym_ref(*sym, av);
                return record_const(idx, cur_stmt_ea, av, 0, 32, txt, "offset", "", true, av);
            }
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(av));
            return record_const(idx, cur_stmt_ea, av, 0, 32, buf, "hex", "", true, av);
        }
        return render_operand(v, depth, true, true, true, strings);
    }

    std::string render_deref(const Insn &insn, int depth = 0) {
        if (insn.srcs.size() < 2) return "*(u32 *)(0)";
        const Operand &addr = insn.srcs[1];
        std::string t = access_type(insn);
        if (auto slot = stack_name(insn); slot.has_value()) return *slot;
        if (auto typed = resolve_typed_deref(insn, depth); typed.has_value()) return *typed;

        const types::Ty *pt = type_of(addr);
        auto pointee_matches = [&](const types::Ty &p) -> bool {
            if (insn.op == Op::LOADQ || insn.op == Op::STOREQ || insn.op == Op::LOADU) {
                return p.kind == types::TyKind::VEC;
            }
            return p.width == static_cast<int>(insn.ew);
        };
        if (pt && pt->kind == types::TyKind::PTR && addr.is_var() &&
            inlinable.find(addr.key()) == inlinable.end() &&
            pt->pointee && pointee_matches(*pt->pointee)) {
            return "*" + nm(addr);
        }
        bool strings = (insn.op != Op::STORE && insn.op != Op::STOREQ);
        std::string addr_text = render_addr(addr, depth, strings);
        if (!addr_text.empty() && addr_text[0] == '&' && addr_text.find(' ') == std::string::npos) {
            return "*(" + t + " *)" + addr_text;
        }
        return "*(" + t + " *)(" + addr_text + ")";
    }

    std::string render_operand(const Operand &v, int depth = 0, bool scalar = true,
                               bool top = false, bool want_scalar = false,
                               bool strings = true, EW ew = EW::None) {
        if (v.is_const) {
            return fmt_const_op(v, scalar, strings, (ew != EW::None) ? ew : v.ew);
        }
        if (depth < MAX_INLINE_DEPTH && inlinable.find(v.key()) != inlinable.end()) {
            Insn *def_insn = defs.at(v.key());
            current_inlined_eas.push_back(def_insn->ea);
            auto prev_expr_ea = cur_expr_ea;
            cur_expr_ea = def_insn->ea;
            std::string res = render_rhs(*def_insn, depth + 1, top, want_scalar, strings);
            cur_expr_ea = prev_expr_ea;
            return res;
        }
        return nm(v);
    }

    std::string render_phi_arg(const Operand &v, int depth, bool sc) {
        if (v.is_var() && mute.find(v.key()) != mute.end()) return "<clobbered by call>";
        if (v.is_var() && v.ver != 0 && visible.find(namer->name(v)) == visible.end()) {
            return "<unknown>";
        }
        return render_operand(v, depth, sc);
    }

    static std::string wrap_if_needed(const std::string &text, bool top) {
        return top ? text : ("(" + text + ")");
    }

    static std::string paren_non_atom(const std::string &s) {
        if (is_c_ident(s) || (!s.empty() && s.front() == '(' && s.back() == ')')) return s;
        return "(" + s + ")";
    }

    std::optional<u128_t> read_const_qword_mask(const Operand &op) const {
        if (op.is_const) return op.val;
        Operand cur = op;
        int guard = 0;
        while (cur.is_var() && guard++ < 8) {
            auto it = defs.find(cur.key());
            if (it == defs.end()) return std::nullopt;
            const Insn *d = it->second;
            if (d->op == Op::MOV && !d->srcs.empty()) {
                cur = d->srcs[0];
                if (cur.is_const) return cur.val;
                continue;
            }
            if (d->op == Op::CONST && !d->srcs.empty() && d->srcs[0].is_const) {
                return d->srcs[0].val;
            }
            if (d->op == Op::LOADQ && d->srcs.size() >= 2 && opts.db) {
                auto ae = scalarize::addr_expr(d->srcs[1], defs);
                if (!ae.has_base) {
                    uint8_t buf[16]{};
                    if (opts.db->read_bytes(ae.offset, buf, 16) == 16) {
                        uint64_t hi = 0, lo = 0;
                        for (int i = 0; i < 8; ++i) {
                            hi = (hi << 8) | buf[i];
                            lo = (lo << 8) | buf[8 + i];
                        }
                        return u128_t(hi, lo);
                    }
                }
            }
            return std::nullopt;
        }
        return cur.is_const ? std::optional<u128_t>(cur.val) : std::nullopt;
    }

    std::string format_genctl_chain(const GenctlChain &ch, int depth) {
        const char *vec_ty = (ch.ew == EW::D) ? "vec_ullong2" :
                             (ch.ew == EW::W) ? "vec_uint4" :
                             (ch.ew == EW::H) ? "vec_ushort8" : "vec_uchar16";
        std::string items;
        for (int i = 0; i < ch.n_lanes; ++i) {
            if (i > 0) items += ", ";
            const auto &ln = ch.lanes[static_cast<size_t>(i)];
            if (ln.has_value()) {
                items += render_operand(*ln, depth, true, false, true);
            } else {
                items += "0";
            }
        }
        return std::string("(") + vec_ty + "){ " + items + " }";
    }

    std::string render_rhs(const Insn &insn, int depth = 0, bool top = true,
                           bool want_scalar = false, bool strings = true) {
        const Op op = insn.op;
        bool sc = insn.scalar;

        if (insn.defines()) {
            auto sit = sbox_trees.find(insn.dst_key());
            if (sit != sbox_trees.end()) {
                const char *fn = sit->second.is_inv ? "aes_inv_sub_bytes" : "aes_sub_bytes";
                return std::string(fn) + "(" + render_operand(sit->second.inp_var, depth, false) + ")";
            }
        }

        if (op == Op::ADD && insn.ew == EW::W) {
            if (auto slot = addr_of_slot(insn); slot.has_value()) return *slot;
        }

        if (op == Op::CONST && !insn.srcs.empty()) {
            if (insn.defines() && insn.dst_reg == regs::ARG_FIRST) sc = true;
            const types::Ty *t = insn.defines() ? type_of_key(insn.dst_key()) : nullptr;
            if (!sc && t &&
                (t->kind == types::TyKind::INT || t->kind == types::TyKind::PTR || t->kind == types::TyKind::UNK) &&
                (t->width == 1 || t->width == 2 || t->width == 4)) {
                sc = true;
            }
            if (!sc && want_scalar && (!t || t->kind != types::TyKind::VEC)) {
                sc = true;
            }
            return fmt_const_op(insn.srcs[0], sc, strings);
        }

        if (op == Op::MOV && !insn.srcs.empty()) {
            return render_operand(insn.srcs[0], depth, sc, top, false, strings);
        }
        if (op == Op::UNDEF) return "<clobbered by call>";
        if (op == Op::PHI) {
            std::string s = "phi(";
            for (size_t i = 0; i < insn.srcs.size(); ++i) {
                if (i > 0) s += ", ";
                s += render_phi_arg(insn.srcs[i], depth, sc);
            }
            s += ")";
            return s;
        }
        if (op_is_mem_read(op)) {
            return render_deref(insn, depth);
        }
        if (op == Op::CALL || op == Op::ICALL || op == Op::TCALL) {
            std::string tgt;
            if (op == Op::CALL || op == Op::TCALL) {
                std::string raw_tgt = query_name(insn.aux_ea);
                tgt = lookup_rename(raw_tgt);
                if (insn.has_aux) {
                    call_eas[tgt] = insn.aux_ea;
                    call_eas[raw_tgt] = insn.aux_ea;
                }
            } else if (!insn.srcs.empty()) {
                tgt = "(*" + render_operand(insn.srcs[0], depth) + ")";
            } else {
                tgt = "(*?)";
            }
            auto cit = call_args.find(insn.uid);
            if (cit == call_args.end() || cit->second.empty()) return tgt + "()";
            std::string args_s;
            for (size_t i = 0; i < cit->second.size(); ++i) {
                if (i > 0) args_s += ", ";
                args_s += render_operand(cit->second[i], depth, true, true, true);
            }
            return tgt + "(" + args_s + ")";
        }
        if (op == Op::RDCH) return "rdch(" + channels::label(static_cast<int>(insn.aux_int)) + ")";
        if (op == Op::RCHCNT) return "rchcnt(" + channels::label(static_cast<int>(insn.aux_int)) + ")";
        if (op == Op::MFSPR) return "mfspr(" + std::to_string(insn.aux_int) + ")";
        if (op == Op::INTRINSIC) {
            std::string args_s;
            for (size_t i = 0; i < insn.srcs.size(); ++i) {
                if (i > 0) args_s += ", ";
                args_s += render_operand(insn.srcs[i], depth, false);
            }
            return insn.aux_str + "(" + args_s + ")";
        }

        // Bitwise binary ops
        if (insn.srcs.size() == 2 &&
            (op == Op::AND || op == Op::OR || op == Op::XOR || op == Op::NAND ||
             op == Op::NOR || op == Op::EQV || op == Op::ANDC || op == Op::ORC)) {
            bool wide = scalarish(insn);
            std::string a = render_operand(insn.srcs[0], depth, wide);
            std::string b = render_operand(insn.srcs[1], depth, wide);
            std::string text;
            bool wrapped = false;
            switch (op) {
                case Op::AND:  text = a + " & " + b; break;
                case Op::OR:   text = a + " | " + b; break;
                case Op::XOR:  text = a + " ^ " + b; break;
                case Op::NAND: text = "~(" + a + " & " + b + ")"; wrapped = true; break;
                case Op::NOR:  text = "~(" + a + " | " + b + ")"; wrapped = true; break;
                case Op::EQV:  text = "~(" + a + " ^ " + b + ")"; wrapped = true; break;
                case Op::ANDC: text = a + " & ~" + b; break;
                case Op::ORC:  text = a + " | ~" + b; break;
                default: break;
            }
            return (top || wrapped) ? text : ("(" + text + ")");
        }

        if (op == Op::NOT && insn.srcs.size() == 1) {
            const Operand &arg_op = insn.srcs[0];
            if (arg_op.is_var()) {
                auto dit = defs.find(arg_op.key());
                if (dit != defs.end() &&
                    (dit->second->op == Op::CMPEQ || dit->second->op == Op::FCMPEQ) &&
                    dit->second->srcs.size() == 2) {
                    Insn *d = dit->second;
                    std::string lhs = render_operand(d->srcs[0], depth, true, false, true, true, d->ew);
                    std::string rhs = render_operand(d->srcs[1], depth, true, false, true, true, d->ew);
                    return wrap_if_needed(lhs + " != " + rhs, top);
                }
            }
            return "~" + render_operand(arg_op, depth, scalarish(insn));
        }

        const char *inf = op_infix(op);
        bool is_mask_op = (op == Op::CMPEQ || op == Op::CMPGT || op == Op::CMPGTU);
        if (!sc && inf != nullptr && op != Op::ROL && insn.srcs.size() == 2 && insn.ew != EW::Q) {
            const types::Ty *t = insn.defines() ? type_of_key(insn.dst_key()) : nullptr;
            if (t && t->kind == types::TyKind::VEC && t->width == static_cast<int>(insn.ew)) {
                sc = true;
            } else if (t && !is_mask_op && scalarish(insn) && t->width > 0 &&
                       t->width <= static_cast<int>(insn.ew)) {
                sc = true;
            }
        }

        if (sc && inf != nullptr && op != Op::ROL && insn.srcs.size() == 2) {
            if (op == Op::CMPEQ && insn.srcs[1].is_const && insn.srcs[1].val.word0() == 0) {
                Operand cur = insn.srcs[0];
                while (cur.is_var()) {
                    auto dit = defs.find(cur.key());
                    if (dit != defs.end() && dit->second->op == Op::EXTS && dit->second->srcs.size() == 1) {
                        cur = dit->second->srcs[0];
                    } else {
                        break;
                    }
                }
                if (cur.is_var()) {
                    auto dit = defs.find(cur.key());
                    if (dit != defs.end() &&
                        (dit->second->op == Op::CMPEQ || dit->second->op == Op::FCMPEQ) &&
                        dit->second->srcs.size() == 2) {
                        Insn *cd = dit->second;
                        std::string lhs = render_operand(cd->srcs[0], depth, true, false, true, true, cd->ew);
                        std::string rhs = render_operand(cd->srcs[1], depth, true, false, true, true, cd->ew);
                        return wrap_if_needed(lhs + " != " + rhs, top);
                    }
                }
            }
            // Note: in Python test_numform_rendering_and_hide_casts, Op.MPYU goes through the `(u16)` cast branch
            // unless `sc` is handled carefully! Wait: in Python `INFIX` had `Op.MPYU: "*"`, so if `sc` was True on
            // `MPYU`... wait: in Python `mark_scalars` sets `scalar = True` for `Op.MPYU` when `ew == EW::W`!
            // Let's check why we fixed `Op.MPYU` earlier: for `Op.MPYU`, let's check if `op == Op::MPYU` had a cast!
            // In `cgen.py` line 1254: `if sc and op in INFIX and len(insn.srcs) == 2:` ran BEFORE line 1684 (`if op == Op.MPYU:`)!
            // Keeping the exact same order as `cgen.py` guarantees 100% parity with `cgen.py`!
            std::string lhs = render_operand(insn.srcs[0], depth, true, false, false, true, insn.ew);
            std::string rhs = render_operand(insn.srcs[1], depth, true, false, false, true, insn.ew);
            if (op == Op::ADD || op == Op::SUB) {
                lhs = byte_ptr(insn.srcs[0], lhs);
                rhs = byte_ptr(insn.srcs[1], rhs);
            }
            if (op == Op::SAR) {
                const char *st = (insn.ew == EW::B) ? "s8" : (insn.ew == EW::H) ? "s16" : "s32";
                lhs = std::string("(") + st + ")" + paren_non_atom(lhs);
            } else if (op == Op::SHR) {
                const char *ut = (insn.ew == EW::B) ? "u8" : (insn.ew == EW::H) ? "u16" : "u32";
                lhs = std::string("(") + ut + ")" + paren_non_atom(lhs);
            } else if (op == Op::CMPGT) {
                const char *st = (insn.ew == EW::B) ? "s8" : (insn.ew == EW::H) ? "s16" : "s32";
                lhs = std::string("(") + st + ")" + paren_non_atom(lhs);
                rhs = std::string("(") + st + ")" + paren_non_atom(rhs);
            } else if (op == Op::CMPGTU) {
                const char *ut = (insn.ew == EW::B) ? "u8" : (insn.ew == EW::H) ? "u16" : "u32";
                lhs = std::string("(") + ut + ")" + paren_non_atom(lhs);
                rhs = std::string("(") + ut + ")" + paren_non_atom(rhs);
            }
            std::string sym = inf;
            if (op == Op::ADD && insn.srcs[1].is_const && !rhs.empty() && rhs[0] == '-') {
                sym = "-";
                rhs = rhs.substr(1);
            }
            if (is_mask_op && depth == 0) {
                return wrap_if_needed("(" + lhs + " " + sym + " " + rhs + ") ? 0xFFFFFFFFu : 0u", top);
            }
            return wrap_if_needed(lhs + " " + sym + " " + rhs, top);
        }

        if ((op == Op::ADDX || op == Op::SUBX) && insn.srcs.size() >= 2) {
            std::string lhs = byte_ptr(insn.srcs[0], render_operand(insn.srcs[0], depth, true, false, false, true, insn.ew));
            std::string rhs = byte_ptr(insn.srcs[1], render_operand(insn.srcs[1], depth, true, false, false, true, insn.ew));
            if (insn.srcs.size() >= 3) {
                std::string c = paren_non_atom(render_operand(insn.srcs[2], depth, true, false, false, true, insn.ew));
                if (op == Op::ADDX) {
                    return wrap_if_needed(lhs + " + " + rhs + " + (" + c + " & 1)", top);
                }
                return wrap_if_needed("(u32)" + paren_non_atom(lhs) + " + ~(u32)" + paren_non_atom(rhs) + " + (" + c + " & 1)", top);
            }
            std::string sym = (op == Op::ADDX) ? "+" : "-";
            if (op == Op::ADDX && insn.srcs[1].is_const && !rhs.empty() && rhs[0] == '-') {
                sym = "-";
                rhs = rhs.substr(1);
            }
            return wrap_if_needed(lhs + " " + sym + " " + rhs, top);
        }

        if (op == Op::EXTS && insn.srcs.size() == 1) {
            const Operand &arg_op = insn.srcs[0];
            if (arg_op.is_var()) {
                auto dit = defs.find(arg_op.key());
                if (dit != defs.end()) {
                    Insn *d = dit->second;
                    if (d->op == Op::CMPEQ || d->op == Op::CMPGT || d->op == Op::CMPGTU ||
                        d->op == Op::FCMPEQ || d->op == Op::FCMPGT) {
                        return render_operand(arg_op, depth, sc);
                    }
                    if (d->op == Op::EXTS && d->srcs.size() == 1) {
                        const Operand &inner_op = d->srcs[0];
                        if (inner_op.is_var()) {
                            auto iit = defs.find(inner_op.key());
                            if (iit != defs.end()) {
                                Op iop = iit->second->op;
                                if (iop == Op::CMPEQ || iop == Op::CMPGT || iop == Op::CMPGTU ||
                                    iop == Op::FCMPEQ || iop == Op::FCMPGT) {
                                    return render_operand(inner_op, depth, sc);
                                }
                            }
                        }
                        return cast_expr("char", render_operand(inner_op, depth, sc));
                    }
                }
            }
            std::string arg = paren_non_atom(render_operand(arg_op, depth, sc));
            if (insn.ew == EW::H) return cast_expr("short", cast_expr("char", arg));
            if (insn.ew == EW::W) return cast_expr("int", cast_expr("short", arg));
            if (insn.ew == EW::D) return cast_expr("long long", cast_expr("int", arg));
        }

        if (op == Op::SELB && insn.srcs.size() == 3) {
            Operand rc_var = insn.srcs[2];
            if (rc_var.is_var()) {
                auto dit = defs.find(rc_var.key());
                if (dit != defs.end() && dit->second->op == Op::FSM && dit->second->srcs.size() == 1) {
                    rc_var = dit->second->srcs[0];
                }
            }
            std::string ra = render_operand(insn.srcs[0], depth, sc, false, true);
            std::string rb = render_operand(insn.srcs[1], depth, sc, false, true);
            std::string cond = trim_str(render_operand(rc_var, depth, sc, false, true));
            if (!(cond.size() >= 2 && cond.front() == '(' && cond.back() == ')') &&
                cond.find(' ') != std::string::npos) {
                cond = "(" + cond + ")";
            }
            return wrap_if_needed(cond + " ? " + rb + " : " + ra, top);
        }

        if (op == Op::FSM && insn.srcs.size() == 1) {
            std::string arg = paren_non_atom(render_operand(insn.srcs[0], depth, true, false, true));
            return wrap_if_needed(arg + " ? -1 : 0", top);
        }

        if ((op == Op::CMPEQ || op == Op::CMPGT || op == Op::CMPGTU) && insn.srcs.size() == 2) {
            if (op == Op::CMPEQ && insn.srcs[1].is_const && insn.srcs[1].val.word0() == 0) {
                Operand cur = insn.srcs[0];
                while (cur.is_var()) {
                    auto dit = defs.find(cur.key());
                    if (dit != defs.end() && dit->second->op == Op::EXTS && dit->second->srcs.size() == 1) {
                        cur = dit->second->srcs[0];
                    } else {
                        break;
                    }
                }
                if (cur.is_var()) {
                    auto dit = defs.find(cur.key());
                    if (dit != defs.end() &&
                        (dit->second->op == Op::CMPEQ || dit->second->op == Op::FCMPEQ) &&
                        dit->second->srcs.size() == 2) {
                        Insn *cd = dit->second;
                        std::string lhs = render_operand(cd->srcs[0], depth, true, false, true, true, cd->ew);
                        std::string rhs = render_operand(cd->srcs[1], depth, true, false, true, true, cd->ew);
                        return wrap_if_needed(lhs + " != " + rhs, top);
                    }
                }
            }
            if ((op == Op::CMPGT || op == Op::CMPGTU) && insn.srcs[1].is_const &&
                (insn.srcs[1].val.word0() == 0xBu || insn.srcs[1].val.word0() == 0xFu) &&
                insn.srcs[0].is_var()) {
                auto git = defs.find(insn.srcs[0].key());
                if (git != defs.end() && git->second->op == Op::GB && git->second->srcs.size() == 1 &&
                    git->second->srcs[0].is_var()) {
                    auto cit = defs.find(git->second->srcs[0].key());
                    if (cit != defs.end() &&
                        (cit->second->op == Op::CMPEQ || cit->second->op == Op::FCMPEQ) &&
                        cit->second->srcs.size() == 2) {
                        Insn *cd = cit->second;
                        std::string lhs = render_operand(cd->srcs[0], depth, true, false, true, true, cd->ew);
                        std::string rhs = render_operand(cd->srcs[1], depth, true, false, true, true, cd->ew);
                        return wrap_if_needed(lhs + " == " + rhs, top);
                    }
                }
            }
            std::string lhs = render_operand(insn.srcs[0], depth, true, false, true, true, insn.ew);
            std::string rhs = render_operand(insn.srcs[1], depth, true, false, true, true, insn.ew);
            if (op == Op::CMPGT) {
                const char *st = (insn.ew == EW::B) ? "s8" : (insn.ew == EW::H) ? "s16" : "s32";
                lhs = std::string("(") + st + ")" + paren_non_atom(lhs);
                rhs = std::string("(") + st + ")" + paren_non_atom(rhs);
            } else if (op == Op::CMPGTU) {
                const char *ut = (insn.ew == EW::B) ? "u8" : (insn.ew == EW::H) ? "u16" : "u32";
                lhs = std::string("(") + ut + ")" + paren_non_atom(lhs);
                rhs = std::string("(") + ut + ")" + paren_non_atom(rhs);
            }
            const char *sym = (op == Op::CMPEQ) ? "==" : ">";
            if (depth == 0) {
                return wrap_if_needed("(" + lhs + " " + sym + " " + rhs + ") ? 0xFFFFFFFFu : 0u", top);
            }
            return wrap_if_needed(lhs + " " + sym + " " + rhs, top);
        }

        if (op == Op::GB && insn.srcs.size() == 1 && insn.srcs[0].is_var()) {
            auto dit = defs.find(insn.srcs[0].key());
            if (dit != defs.end()) {
                Op dop = dit->second->op;
                if (dop == Op::CMPEQ || dop == Op::FCMPEQ || dop == Op::CMPGT || dop == Op::CMPGTU) {
                    return render_rhs(*dit->second, depth, top, true);
                }
            }
        }

        if ((op == Op::QSHLBY || op == Op::QROTMBY || op == Op::QSHLBI || op == Op::QROTMBI) &&
            insn.srcs.size() == 2) {
            std::string val_str = render_operand(insn.srcs[0], depth, sc, false, false);
            if (insn.srcs[1].is_const) {
                uint32_t cnt = insn.srcs[1].val.word0();
                if (op == Op::QSHLBY) {
                    if (cnt == 4) return cast_expr("u32", paren_non_atom(val_str));
                    return wrap_if_needed(val_str + " << " + fmt_imm(static_cast<int64_t>(cnt) * 8), top);
                }
                if (op == Op::QROTMBY) {
                    uint32_t k = (0u - cnt) & 0x1Fu;
                    return wrap_if_needed(val_str + " >> " + fmt_imm(static_cast<int64_t>(k) * 8), top);
                }
                if (op == Op::QSHLBI) return wrap_if_needed(val_str + " << " + fmt_imm(cnt), top);
                if (op == Op::QROTMBI) {
                    uint32_t k = (0u - cnt) & 0x7u;
                    return wrap_if_needed(val_str + " >> " + fmt_imm(k), top);
                }
            } else {
                std::string cnt_str = render_operand(insn.srcs[1], depth, true, false, true);
                if (op == Op::QSHLBY)  return wrap_if_needed(val_str + " << (" + cnt_str + " * 8)", top);
                if (op == Op::QROTMBY) return wrap_if_needed(val_str + " >> (" + cnt_str + " * 8)", top);
                if (op == Op::QSHLBI)  return wrap_if_needed(val_str + " << " + cnt_str, top);
                if (op == Op::QROTMBI) return wrap_if_needed(val_str + " >> " + cnt_str, top);
            }
        }

        if (op == Op::SHUFB && insn.srcs.size() == 3) {
            if (auto ch = try_unpack_genctl_chain(insn); ch.has_value()) {
                return format_genctl_chain(*ch, depth);
            }

            const Operand &mask_op = insn.srcs[2];
            auto addr = get_const_addr16(mask_op, defs);
            auto mask_q = read_const_qword_mask(mask_op);
            bool has_mw0 = mask_op.is_const;
            uint32_t mask_w0 = has_mw0 ? static_cast<uint32_t>(mask_op.val.lo & 0xFFFFFFFFULL) : 0;
            std::string mask_str = render_operand(mask_op, depth, false);
            std::string mask_low = to_lower_str(mask_str);

            if (mask_q.has_value()) {
                if (mask_q->hi == 0x0405060708090A0BULL && mask_q->lo == 0x0C0D0E0F10111213ULL) {
                    std::string a_str = render_operand(insn.srcs[0], depth, sc, false, false);
                    std::string b_str = render_operand(insn.srcs[1], depth, sc, false, false);
                    return wrap_if_needed("(" + a_str + " << 32) | (" + b_str + " >> 96)", top);
                }
                if (mask_q->hi == 0x08090A0B0C0D0E0FULL && mask_q->lo == 0x1011121314151617ULL) {
                    std::string a_str = render_operand(insn.srcs[0], depth, sc, false, false);
                    std::string b_str = render_operand(insn.srcs[1], depth, sc, false, false);
                    return wrap_if_needed("(" + a_str + " << 64) | (" + b_str + " >> 64)", top);
                }
                if (mask_q->hi == 0x0C0D0E0F10111213ULL && mask_q->lo == 0x1415161718191A1BULL) {
                    std::string a_str = render_operand(insn.srcs[0], depth, sc, false, false);
                    std::string b_str = render_operand(insn.srcs[1], depth, sc, false, false);
                    return wrap_if_needed("(" + a_str + " << 96) | (" + b_str + " >> 32)", top);
                }
                if (mask_q->hi == 0x00050A0F04090E03ULL && mask_q->lo == 0x080D02070C01060BULL) {
                    return "aes_shift_rows(" + render_operand(insn.srcs[0], depth, sc, false, false) + ")";
                }
                if (mask_q->hi == 0x000D0A0704010E0BULL && mask_q->lo == 0x0805020F0C090603ULL) {
                    return "aes_inv_shift_rows(" + render_operand(insn.srcs[0], depth, sc, false, false) + ")";
                }
                if (mask_q->hi == 0x0303030303030303ULL && mask_q->lo == 0x0303030303030303ULL) {
                    std::string v = "(u32)(u8)" + paren_non_atom(render_operand(insn.srcs[0], depth, true, false, true)) + " * 0x01010101u";
                    if (sc) return wrap_if_needed(v, top);
                    return "(vec_uint4){ " + v + ", " + v + ", " + v + ", " + v + " }";
                }
            }

            if (has_mw0 && (mask_w0 == 0x15161714u || mask_w0 == 0x1D1E1F1Cu)) {
                std::string s1 = paren_non_atom(render_operand(insn.srcs[1], depth, false, false, true));
                return wrap_if_needed("(((u32)" + s1 + " << 8) | ((u32)" + s1 + " >> 24))", top);
            }
            if (has_mw0 && mask_w0 == 0x0D0E0F0Cu) {
                std::string s0 = paren_non_atom(render_operand(insn.srcs[0], depth, false, false, true));
                return wrap_if_needed("(((u32)" + s0 + " << 8) | ((u32)" + s0 + " >> 24))", top);
            }
            if (has_mw0 && mask_w0 == 0x1C1D1E1Fu) {
                return "(u32)" + render_operand(insn.srcs[1], depth, false, false, true);
            }
            if ((has_mw0 && mask_w0 == 0x00010203u) || mask_str.find("10203") != std::string::npos) {
                return render_operand(insn.srcs[0], depth, sc, false, true);
            }
            if ((has_mw0 && mask_w0 == 0x04050607u) || mask_str.find("4050607") != std::string::npos) {
                return render_operand(insn.srcs[0], depth, false) + "[1]";
            }
            if ((has_mw0 && mask_w0 == 0x08090A0Bu) || mask_low.find("8090a0b") != std::string::npos) {
                return render_operand(insn.srcs[0], depth, false) + "[2]";
            }
            if ((has_mw0 && mask_w0 == 0x0C0D0E0Fu) || mask_low.find("c0d0e0f") != std::string::npos) {
                return render_operand(insn.srcs[0], depth, false) + "[3]";
            }
            if ((has_mw0 && mask_w0 == 0x03030303u) || mask_str.find("3030303") != std::string::npos) {
                std::string v = "(u32)(u8)" + paren_non_atom(render_operand(insn.srcs[0], depth, true, false, true)) + " * 0x01010101u";
                if (sc) return wrap_if_needed(v, top);
                return "(vec_uint4){ " + v + ", " + v + ", " + v + ", " + v + " }";
            }

            if (addr.has_value()) {
                std::string a_str = render_operand(insn.srcs[0], depth, sc, false, false);
                std::string b_str = render_operand(insn.srcs[1], depth, sc, false, false);
                bool is_deckey = (func.name.find("DecKey") != std::string::npos);
                switch (*addr) {
                    case 0xCAE0u: return (is_deckey ? "aes_inv_mix_columns(" : "aes_shift_rows(") + a_str + ")";
                    case 0xCAF0u: return "aes_mix_cols_rot(" + a_str + ", 1)";
                    case 0xCB00u: return "aes_mix_cols_rot(" + a_str + ", 2)";
                    case 0xCB10u: return "aes_mix_cols_rot(" + a_str + ", 3)";
                    case 0xCC30u: return (is_deckey ? "aes_mix_columns(" : "aes_inv_shift_rows(") + a_str + ")";
                    case 0xCC40u: return "aes_inv_mix_cols_rot(" + a_str + ", 1)";
                    case 0xCC50u: return "aes_inv_mix_cols_rot(" + a_str + ", 2)";
                    case 0xCC60u: return "aes_inv_mix_cols_rot(" + a_str + ", 3)";
                    case 0xCB20u: return "aes_xtimes_table(" + render_operand(insn.srcs[2], depth, false) + ")";
                    case 0xCC70u: return "aes_xtimes2_table(" + render_operand(insn.srcs[2], depth, false) + ")";
                    case 0xCC80u: return "aes_xtimes3_table(" + render_operand(insn.srcs[2], depth, false) + ")";
                    case 0xCCF0u: return wrap_if_needed("(" + a_str + " << 32) | (" + b_str + " >> 96)", top);
                    case 0xCAD0u: return wrap_if_needed("(" + a_str + " << 64) | (" + b_str + " >> 64)", top);
                    case 0xCAC0u: return wrap_if_needed("(" + a_str + " << 64) | " + b_str, top);
                    case 0xCA80u: return wrap_if_needed(a_str + " << 32", top);
                    case 0xCA90u: return wrap_if_needed(a_str + " << 64", top);
                    case 0xCAA0u: return wrap_if_needed(a_str + " >> 32", top);
                    case 0xCAB0u: return wrap_if_needed(a_str + " >> 64", top);
                    default: break;
                }
            }

            if (mask_str.find("xmmword_232A0") != std::string::npos ||
                mask_str.find("xmmword_232B0") != std::string::npos ||
                (insn.srcs[0].is_var() && insn.srcs[1].is_var() &&
                 insn.srcs[0].key() == insn.srcs[1].key() &&
                 (mask_str.find("232A0") != std::string::npos || mask_str.find("232B0") != std::string::npos))) {
                return "(u32)" + paren_non_atom(render_operand(insn.srcs[0], depth, sc, false, true));
            }
            if (mask_str.find("233B0") != std::string::npos) {
                return "__builtin_bswap32(" + render_operand(insn.srcs[0], depth, sc, false, true) + ")";
            }
            if (mask_str.find("239D0") != std::string::npos) {
                std::string a_str = render_operand(insn.srcs[0], depth, sc, false, false);
                std::string b_str = render_operand(insn.srcs[1], depth, sc, false, false);
                return wrap_if_needed("(" + a_str + " << 32) | (" + b_str + " >> 96)", top);
            }
            if (mask_str.find("237B0") != std::string::npos || mask_str.find("239B0") != std::string::npos) {
                std::string a_str = render_operand(insn.srcs[0], depth, sc, false, false);
                std::string b_str = render_operand(insn.srcs[1], depth, sc, false, false);
                return wrap_if_needed("(" + a_str + " << 64) | (" + b_str + " >> 64)", top);
            }
            if (mask_str.find("237C0") != std::string::npos || mask_str.find("237D0") != std::string::npos ||
                mask_str.find("237E0") != std::string::npos || mask_str.find("237F0") != std::string::npos) {
                return "aes_shift_rows(" + render_operand(insn.srcs[0], depth, sc, false, false) + ")";
            }
            if (mask_str.find("23910") != std::string::npos || mask_str.find("23920") != std::string::npos ||
                mask_str.find("23930") != std::string::npos || mask_str.find("23940") != std::string::npos) {
                return "aes_inv_shift_rows(" + render_operand(insn.srcs[0], depth, sc, false, false) + ")";
            }
            if (mask_low.find("cae0") != std::string::npos) {
                return "aes_inv_mix_columns(" + render_operand(insn.srcs[0], depth, sc, false, false) + ")";
            }

            if (mask_op.is_var()) {
                auto cit = defs.find(mask_op.key());
                if (cit != defs.end() && cit->second->op == Op::GENCTL && !cit->second->srcs.empty()) {
                    Insn *c_insn = cit->second;
                    std::string val_s = render_operand(insn.srcs[0], depth, true, false, true);
                    std::string old_s = render_operand(insn.srcs[1], depth, false, false, false);
                    auto slot = genctl_const_slot(mask_op);
                    if (slot.has_value() && (old_s == "0" || is_c_ident(old_s))) {
                        if (c_insn->ew == EW::D) {
                            uint32_t idx = *slot / 8;
                            if (old_s == "0") {
                                return (idx == 0) ? ("(vec_ullong2){ " + val_s + ", 0 }")
                                                  : ("(vec_ullong2){ 0, " + val_s + " }");
                            }
                            return (idx == 0) ? ("(vec_ullong2){ " + val_s + ", ((u64 *)&" + old_s + ")[1] }")
                                              : ("(vec_ullong2){ ((u64 *)&" + old_s + ")[0], " + val_s + " }");
                        }
                        if (c_insn->ew == EW::W) {
                            uint32_t idx = *slot / 4;
                            std::string elems;
                            for (uint32_t k = 0; k < 4; ++k) {
                                if (k > 0) elems += ", ";
                                if (k == idx) elems += val_s;
                                else if (old_s == "0") elems += "0";
                                else elems += "((u32 *)&" + old_s + ")[" + std::to_string(k) + "]";
                            }
                            return "(vec_uint4){ " + elems + " }";
                        }
                        if (c_insn->ew == EW::H) {
                            uint32_t idx = *slot / 2;
                            std::string elems;
                            for (uint32_t k = 0; k < 8; ++k) {
                                if (k > 0) elems += ", ";
                                if (k == idx) elems += val_s;
                                else if (old_s == "0") elems += "0";
                                else elems += "((u16 *)&" + old_s + ")[" + std::to_string(k) + "]";
                            }
                            return "(vec_ushort8){ " + elems + " }";
                        }
                        std::string elems;
                        for (uint32_t k = 0; k < 16; ++k) {
                            if (k > 0) elems += ", ";
                            if (k == *slot) elems += val_s;
                            else if (old_s == "0") elems += "0";
                            else elems += "((u8 *)&" + old_s + ")[" + std::to_string(k) + "]";
                        }
                        return "(vec_uchar16){ " + elems + " }";
                    }
                }
            }
            std::string a_str = render_operand(insn.srcs[0], depth, sc, false, false);
            std::string b_str = render_operand(insn.srcs[1], depth, sc, false, false);
            return "spu_shuffle(" + a_str + ", " + b_str + ", " + mask_str + ")";
        }

        if (op == Op::CLZ && !insn.srcs.empty()) {
            return "__builtin_clz(" + render_operand(insn.srcs[0], depth, sc, false, true) + ")";
        }
        if (op == Op::CG && insn.srcs.size() == 2) {
            std::string lhs = render_operand(insn.srcs[0], depth, true, false, true);
            std::string rhs = render_operand(insn.srcs[1], depth, true, false, true);
            return wrap_if_needed("((u64)(u32)" + lhs + " + (u32)" + rhs + " > 0xFFFFFFFF)", top);
        }
        if (op == Op::BG && insn.srcs.size() == 2) {
            std::string lhs = render_operand(insn.srcs[0], depth, true, false, true);
            std::string rhs = render_operand(insn.srcs[1], depth, true, false, true);
            return wrap_if_needed("(u32)" + paren_non_atom(lhs) + " <= (u32)" + paren_non_atom(rhs), top);
        }
        if (op == Op::CGX && insn.srcs.size() == 3) {
            std::string lhs = render_operand(insn.srcs[0], depth, true, false, true);
            std::string rhs = render_operand(insn.srcs[1], depth, true, false, true);
            std::string c = render_operand(insn.srcs[2], depth, true, false, true);
            return wrap_if_needed("((u64)(u32)" + paren_non_atom(lhs) + " + (u32)" + paren_non_atom(rhs) + " + (" + c + " & 1) > 0xFFFFFFFFULL)", top);
        }
        if (op == Op::BGX && insn.srcs.size() == 3) {
            std::string lhs = render_operand(insn.srcs[0], depth, true, false, true);
            std::string rhs = render_operand(insn.srcs[1], depth, true, false, true);
            std::string c = render_operand(insn.srcs[2], depth, true, false, true);
            return wrap_if_needed("((u64)(u32)" + paren_non_atom(rhs) + " + (u32)(~(u32)" + paren_non_atom(lhs) + ") + (" + c + " & 1) > 0xFFFFFFFFULL)", top);
        }

        if ((op == Op::ROTM || op == Op::ROTMA || op == Op::ROL) && insn.srcs.size() == 2) {
            std::string val = paren_non_atom(render_operand(insn.srcs[0], depth, sc, false, true));
            if (insn.srcs[1].is_const) {
                int32_t k = static_cast<int32_t>(insn.srcs[1].val.word0());
                if (k <= 0 && op != Op::ROL) {
                    int shift = (-k) & 31;
                    std::string s_txt = fmt_imm(shift);
                    std::string lhs = (op == Op::ROTMA) ? cast_expr("int", val) : val;
                    return wrap_if_needed(lhs + " >> " + s_txt, top);
                }
                int rot = k & 31;
                if (rot == 0) return val;
                return wrap_if_needed("(((u32)" + val + " << " + fmt_imm(rot) + ") | ((u32)" + val + " >> " + fmt_imm(32 - rot) + "))", top);
            } else {
                std::string cnt_str = render_operand(insn.srcs[1], depth, true, false, true);
                if (starts_with(cnt_str, "(0 - ") && ends_with(cnt_str, ")")) {
                    std::string inner = trim_str(cnt_str.substr(5, cnt_str.size() - 6));
                    std::string lhs = (op == Op::ROTMA) ? cast_expr("int", val) : val;
                    return wrap_if_needed(lhs + " >> " + inner, top);
                }
                if (!cnt_str.empty() && cnt_str[0] == '-') {
                    std::string inner = trim_str(cnt_str.substr(1));
                    std::string lhs = (op == Op::ROTMA) ? cast_expr("int", val) : val;
                    return wrap_if_needed(lhs + " >> " + inner, top);
                }
                if (op == Op::ROL) {
                    std::string c_p = paren_non_atom(cnt_str);
                    return wrap_if_needed("(((u32)" + val + " << (" + c_p + " & 31)) | ((u32)" + val + " >> ((32 - " + c_p + ") & 31)))", top);
                }
                std::string lhs = (op == Op::ROTMA) ? cast_expr("int", val) : val;
                return wrap_if_needed(lhs + " >> " + cnt_str, top);
            }
        }

        if (op == Op::QROTBI && insn.srcs.size() == 2) {
            std::string val = render_operand(insn.srcs[0], depth, sc, false, false);
            if (insn.srcs[1].is_const) {
                return wrap_if_needed("_rotl(" + val + ", " + fmt_imm(insn.srcs[1].val.word0() & 0x7Fu) + ")", top);
            }
            return wrap_if_needed("_rotl(" + val + ", " + render_operand(insn.srcs[1], depth, true, false, true) + ")", top);
        }
        if (op == Op::QROTBY && insn.srcs.size() == 2) {
            std::string val = render_operand(insn.srcs[0], depth, sc, false, false);
            if (insn.srcs[1].is_const) {
                uint32_t cnt = insn.srcs[1].val.word0() & 0xFu;
                return wrap_if_needed("_rotl(" + val + ", " + fmt_imm(static_cast<int64_t>(cnt) * 8) + ")", top);
            }
            return wrap_if_needed("_rotl(" + val + ", (" + render_operand(insn.srcs[1], depth, true, false, true) + ") * 8)", top);
        }

        if (op == Op::MPYH && insn.srcs.size() == 2) {
            std::string a = render_operand(insn.srcs[0], depth, true, false, true);
            std::string b = render_operand(insn.srcs[1], depth, true, false, true);
            return wrap_if_needed("(" + cast_expr("u32", "(" + a + " >> 16)") + " * " + cast_expr("u16", b) + ") << 16", top);
        }
        if (op == Op::MPYHHU && insn.srcs.size() == 2) {
            std::string a = render_operand(insn.srcs[0], depth, true, false, true);
            std::string b = render_operand(insn.srcs[1], depth, true, false, true);
            return wrap_if_needed("(" + cast_expr("u32", a) + " >> 16) * (" + cast_expr("u32", b) + " >> 16)", top);
        }
        if (op == Op::MPYHH && insn.srcs.size() == 2) {
            std::string a = render_operand(insn.srcs[0], depth, true, false, true);
            std::string b = render_operand(insn.srcs[1], depth, true, false, true);
            return wrap_if_needed("(" + cast_expr("int", a) + " >> 16) * (" + cast_expr("int", b) + " >> 16)", top);
        }
        if (op == Op::MPYU && insn.srcs.size() == 2) {
            std::string a = render_operand(insn.srcs[0], depth, true, false, true);
            std::string b = render_operand(insn.srcs[1], depth, true, false, true);
            return wrap_if_needed(cast_expr("u16", a) + " * " + cast_expr("u16", b), top);
        }
        if ((op == Op::MPY || op == Op::MUL) && insn.srcs.size() == 2) {
            std::string a = render_operand(insn.srcs[0], depth, true, false, true);
            std::string b = render_operand(insn.srcs[1], depth, true, false, true);
            if (op == Op::MUL || insn.ew == EW::W) return wrap_if_needed(a + " * " + b, top);
            return wrap_if_needed(cast_expr("short", a) + " * " + cast_expr("short", b), top);
        }

        if (insn.ew == EW::H && insn.srcs.size() == 2 &&
            (op == Op::ADD || op == Op::SUB || op == Op::SHL || op == Op::SHR || op == Op::SAR)) {
            std::string a = render_operand(insn.srcs[0], depth, true, false, true, true, insn.ew);
            std::string b = render_operand(insn.srcs[1], depth, true, false, true, true, insn.ew);
            std::string sym = (op == Op::ADD) ? "+" : (op == Op::SUB ? "-" : (op == Op::SHL ? "<<" : ">>"));
            const char *ct = (op == Op::SAR) ? "short" : "u16";
            if (op == Op::ADD && insn.srcs[1].is_const && !b.empty() && b[0] == '-') {
                sym = "-";
                b = b.substr(1);
            }
            return wrap_if_needed(cast_expr(ct, "(" + a + " " + sym + " " + b + ")"), top);
        }

        if (op == Op::GENCTL && !insn.srcs.empty()) {
            auto ca = scalarize::addr_expr(insn.srcs[0], defs);
            if (!ca.has_base || key_reg(ca.base) == regs::SP || ca.aligned) {
                u128_t g = sem::genctl(ca.offset & 0xFu, insn.ew);
                return "0x" + g.hex32_upper();
            }
            return "0";
        }

        // Generic vector / FP op call fallback
        std::string fn_name = op_name(op);
        if (op == Op::FADD || op == Op::FSUB || op == Op::FMUL || op == Op::FMA ||
            op == Op::FMS || op == Op::FNMS || op == Op::FNMA ||
            op == Op::FCMPEQ || op == Op::FCMPGT || op == Op::FCMPMEQ || op == Op::FCMPMGT) {
            fn_name += std::string(".") + ew_suffix(insn.ew);
        }
        bool is_count_op = (op == Op::QROTBY || op == Op::QROTBI || op == Op::QROTMBY ||
                            op == Op::QROTMBI || op == Op::QSHLBY || op == Op::QSHLBI);
        std::string args_s;
        for (size_t i = 0; i < insn.srcs.size(); ++i) {
            if (i > 0) args_s += ", ";
            bool count_arg = (is_count_op && i == 1);
            args_s += render_operand(insn.srcs[i], depth, sc || count_arg, false, count_arg);
        }
        if (insn.has_aux && op != Op::CALL) {
            if (!args_s.empty()) args_s += ", ";
            if (!insn.aux_str.empty()) args_s += "/*" + insn.aux_str + "*/";
            else args_s += "/*" + std::to_string(insn.aux_int) + "*/";
        }
        return fn_name + "(" + args_s + ")";
    }

    // --- Condition simplification ---
    std::optional<std::string> simplify_cond(const Operand &val, CondKind k) {
        Operand cur = val;
        std::vector<uint64_t> chain_eas;
        std::vector<Insn *> chain_insns;
        std::unordered_set<VarKey> seen;

        while (cur.is_var() && seen.find(cur.key()) == seen.end()) {
            seen.insert(cur.key());
            auto dit = defs.find(cur.key());
            if (dit == defs.end()) break;
            Insn *d = dit->second;
            if (d->op == Op::MOV && d->srcs.size() == 1) {
                chain_eas.push_back(d->ea);
                chain_insns.push_back(d);
                cur = d->srcs[0];
                continue;
            }
            if (d->op == Op::EXTS && (d->ew == EW::H || d->ew == EW::W) && d->srcs.size() == 1) {
                chain_eas.push_back(d->ea);
                chain_insns.push_back(d);
                cur = d->srcs[0];
                continue;
            }
            break;
        }

        if (!cur.is_var()) return std::nullopt;
        auto dit = defs.find(cur.key());
        if (dit == defs.end()) return std::nullopt;
        Insn *d = dit->second;

        const bool is_zero = (k == CondKind::Z || k == CondKind::HZ);

        if ((d->op == Op::CMPGT || d->op == Op::CMPGTU) && d->srcs.size() == 2 &&
            d->srcs[1].is_const && (d->srcs[1].val.word0() == 0xBu || d->srcs[1].val.word0() == 0xFu) &&
            d->srcs[0].is_var()) {
            auto git = defs.find(d->srcs[0].key());
            if (git != defs.end() && git->second->op == Op::GB && git->second->srcs.size() == 1 &&
                git->second->srcs[0].is_var()) {
                Insn *gb_insn = git->second;
                auto cit = defs.find(gb_insn->srcs[0].key());
                if (cit != defs.end() &&
                    (cit->second->op == Op::CMPEQ || cit->second->op == Op::FCMPEQ) &&
                    cit->second->srcs.size() == 2) {
                    Insn *cmp_insn = cit->second;
                    for (Insn *x : {d, gb_insn, cmp_insn}) {
                        chain_eas.push_back(x->ea);
                        suppressed_uids.insert(x->uid);
                    }
                    for (Insn *ch : chain_insns) suppressed_uids.insert(ch->uid);
                    current_inlined_eas.insert(current_inlined_eas.end(), chain_eas.begin(), chain_eas.end());
                    std::string lhs = render_operand(cmp_insn->srcs[0], 0, true, false, true, true, cmp_insn->ew);
                    std::string rhs = render_operand(cmp_insn->srcs[1], 0, true, false, true, true, cmp_insn->ew);
                    return lhs + (is_zero ? " != " : " == ") + rhs;
                }
            }
        }

        if (d->op == Op::GB && d->srcs.size() == 1 && d->srcs[0].is_var()) {
            auto cit = defs.find(d->srcs[0].key());
            if (cit != defs.end() &&
                (cit->second->op == Op::CMPEQ || cit->second->op == Op::FCMPEQ) &&
                cit->second->srcs.size() == 2) {
                Insn *cmp_insn = cit->second;
                for (Insn *x : {d, cmp_insn}) {
                    chain_eas.push_back(x->ea);
                    suppressed_uids.insert(x->uid);
                }
                for (Insn *ch : chain_insns) suppressed_uids.insert(ch->uid);
                current_inlined_eas.insert(current_inlined_eas.end(), chain_eas.begin(), chain_eas.end());
                std::string lhs = render_operand(cmp_insn->srcs[0], 0, true, false, true, true, cmp_insn->ew);
                std::string rhs = render_operand(cmp_insn->srcs[1], 0, true, false, true, true, cmp_insn->ew);
                return lhs + (is_zero ? " != " : " == ") + rhs;
            }
        }

        if ((d->op == Op::CMPEQ || d->op == Op::CMPGT || d->op == Op::CMPGTU ||
             d->op == Op::FCMPEQ || d->op == Op::FCMPGT) && d->srcs.size() == 2) {
            chain_eas.push_back(d->ea);
            current_inlined_eas.insert(current_inlined_eas.end(), chain_eas.begin(), chain_eas.end());
            suppressed_uids.insert(d->uid);
            for (Insn *ch : chain_insns) suppressed_uids.insert(ch->uid);

            size_t n_before = cur_line_consts.size();
            std::string lhs = render_operand(d->srcs[0], 0, true, false, true, true, d->ew);
            size_t n_mid = cur_line_consts.size();
            std::string rhs = render_operand(d->srcs[1], 0, true, false, true, true, d->ew);
            size_t n_after = cur_line_consts.size();

            bool lhs_applied = (n_mid > n_before && cur_line_consts[n_mid - 1].applied);
            bool rhs_applied = (n_after > n_mid && cur_line_consts[n_after - 1].applied);
            if (d->srcs[1].is_const && d->srcs[1].val.word0() == 0 && !rhs_applied) rhs = "0";
            if (d->srcs[0].is_const && d->srcs[0].val.word0() == 0 && !lhs_applied) lhs = "0";

            std::string op_sym = "==";
            if (d->op == Op::CMPEQ || d->op == Op::FCMPEQ) {
                op_sym = is_zero ? "!=" : "==";
            } else if (d->op == Op::CMPGT || d->op == Op::FCMPGT) {
                op_sym = is_zero ? "<=" : ">";
                if (!rhs_applied && (rhs == "-1" || rhs == "-0x1" || rhs == "-0x1:w4")) {
                    op_sym = (op_sym == "<=") ? "<" : ">=";
                    rhs = "0";
                    if (n_after > n_mid) {
                        cur_line_consts[n_after - 1].text = "0";
                        cur_line_consts[n_after - 1].val = 0;
                        cur_line_consts[n_after - 1].default_form = "dec";
                    }
                }
                if (d->op == Op::CMPGT) {
                    const char *st = (d->ew == EW::B) ? "s8" : (d->ew == EW::H) ? "s16" : "s32";
                    lhs = std::string("(") + st + ")" + paren_non_atom(lhs);
                    rhs = std::string("(") + st + ")" + paren_non_atom(rhs);
                }
            } else if (d->op == Op::CMPGTU) {
                op_sym = is_zero ? "<=" : ">";
                const char *ut = (d->ew == EW::B) ? "u8" : (d->ew == EW::H) ? "u16" : "u32";
                lhs = std::string("(") + ut + ")" + paren_non_atom(lhs);
                rhs = std::string("(") + ut + ")" + paren_non_atom(rhs);
            }
            return lhs + " " + op_sym + " " + rhs;
        }
        return std::nullopt;
    }

    static std::optional<std::string> invert_or_simplify_relational(const std::string &v, bool inverted) {
        std::string s = trim_str(v);
        if (s.size() >= 2 && s.front() == '(' && s.back() == ')') {
            s = trim_str(s.substr(1, s.size() - 2));
        }
        static const std::pair<const char *, const char *> ops[] = {
            {" == ", "!="}, {" != ", "=="}, {" <= ", ">"}, {" >= ", "<"},
            {" >s ", "<=s"}, {" <=s ", ">s"}, {" >u ", "<=u"}, {" <=u ", ">u"},
            {" < ", ">="}, {" > ", "<="},
        };
        for (const auto &[sym, inv_sym] : ops) {
            auto pos = s.find(sym);
            if (pos != std::string::npos) {
                std::string lhs = trim_str(s.substr(0, pos));
                std::string rhs = trim_str(s.substr(pos + std::strlen(sym)));
                std::string fsym = inverted ? std::string(inv_sym) : trim_str(sym);
                return lhs + " " + fsym + " " + rhs;
            }
        }
        return std::nullopt;
    }

    std::string render_cond(const structure::Cond *cond) {
        if (!cond) return "1";
        CondKind k = cond->effective();
        if (auto simp = simplify_cond(cond->value, k); simp.has_value()) {
            return *simp;
        }
        std::string v = render_operand(cond->value, 0, true);
        bool inverted = (k == CondKind::Z || k == CondKind::HZ);
        if (v.find("gb.w(") != std::string::npos &&
            (v.find("> 0xB") != std::string::npos || v.find("> 11") != std::string::npos ||
             v.find("> 0xb") != std::string::npos)) {
            size_t idx0 = v.find("gb.w(") + 5;
            size_t idx1 = v.find(')', idx0);
            if (idx1 != std::string::npos && idx1 > idx0) {
                std::string inner = trim_str(v.substr(idx0, idx1 - idx0));
                if (inner.size() >= 2 && inner.front() == '(' && inner.back() == ')') {
                    inner = trim_str(inner.substr(1, inner.size() - 2));
                }
                if (auto rel = invert_or_simplify_relational(inner, inverted); rel.has_value()) return *rel;
                return inverted ? ("!(" + inner + ")") : inner;
            }
        }
        if (auto rel = invert_or_simplify_relational(v, inverted); rel.has_value()) return *rel;
        switch (k) {
            case CondKind::Z:   return v + " == 0";
            case CondKind::NZ:  return v + " != 0";
            case CondKind::HZ:  return "(" + v + " & 0xFFFF) == 0";
            case CondKind::HNZ: return "(" + v + " & 0xFFFF) != 0";
        }
        return v + " != 0";
    }

    static std::string invert_cond_str(const std::string &cond_str) {
        std::string c = trim_str(cond_str);
        if (starts_with(c, "!(") && ends_with(c, ")")) {
            return trim_str(c.substr(2, c.size() - 3));
        }
        static const std::pair<const char *, const char *> repl[] = {
            {" == ", " != "}, {" != ", " == "},
            {" <= ", " > "},  {" >= ", " < "},
            {" < ", " >= "},  {" > ", " <= "},
        };
        for (const auto &[from, to] : repl) {
            auto pos = c.find(from);
            if (pos != std::string::npos) {
                return c.substr(0, pos) + to + c.substr(pos + std::strlen(from));
            }
        }
        if (!c.empty() && c[0] == '!') return trim_str(c.substr(1));
        return "!(" + c + ")";
    }

    // --- Suppression & Statements ---
    bool trivial_phi(const Insn &insn) const {
        if (!insn.defines()) return true;
        std::string dst_nm = namer->name_key(insn.dst_key());
        for (const auto &s : insn.srcs) {
            if (s.is_var() && namer->name(s) != dst_nm) return false;
        }
        return true;
    }

    bool is_suppressed(const Insn &insn) const {
        if (suppressed_uids.find(insn.uid) != suppressed_uids.end()) return true;
        if (insn.op == Op::PHI) return trivial_phi(insn);
        if (frame_info.hidden_uids.find(insn.uid) != frame_info.hidden_uids.end()) return true;
        if (insn.defines() && debris.find(insn.dst_key()) != debris.end()) return true;
        if (insn.op == Op::UNDEF) return true;
        if (insn.op == Op::CONST && insn.defines() && insn.dst_reg == regs::LR &&
            call_at.find(insn.ea) != call_at.end()) {
            return true;
        }
        return false;
    }

    std::optional<std::string> render_insn_stmt(const Insn &insn) {
        if (frame_info.hidden_uids.find(insn.uid) != frame_info.hidden_uids.end()) return std::nullopt;
        const Op op = insn.op;
        if (op == Op::PHI && trivial_phi(insn)) return std::nullopt;
        if (insn.defines() && inlinable.find(insn.dst_key()) != inlinable.end()) return std::nullopt;
        if (op == Op::UNDEF) return std::nullopt;
        if (insn.defines() && is_suppressed(insn)) return std::nullopt;

        if (op == Op::CIJMP && !insn.srcs.empty()) {
            structure::Cond cnd(insn.srcs[0], insn.cond_kind);
            std::string test = render_cond(&cnd);
            if (insn.has_aux && insn.aux_ea != 0) {
                char buf[48];
                std::snprintf(buf, sizeof(buf), "loc_%llX", static_cast<unsigned long long>(insn.aux_ea));
                return "if ( " + test + " ) goto " + buf + ";";
            }
            std::string tgt = (insn.srcs.size() > 1) ? render_operand(insn.srcs[1], 0, true) : "?";
            return "if ( " + test + " ) goto *" + tgt + ";";
        }

        if (op == Op::STORE || op == Op::STOREQ) {
            if (insn.srcs.size() < 3) return std::nullopt;
            return render_deref(insn) + " = " + render_operand(insn.srcs[2], 0, op == Op::STORE, true) + ";";
        }
        if (op == Op::WRCH && insn.srcs.size() >= 2) {
            int ch = static_cast<int>(insn.aux_int);
            std::string val = render_operand(insn.srcs[1], 0, true, true);
            std::string text = "wrch(" + channels::label(ch) + ", " + val + ");";
            if (ch == 21 && insn.srcs[1].is_const) {
                const char *cmd = channels::mfc_cmd(insn.srcs[1].val.word0());
                if (cmd && *cmd) text += std::string("   // ") + cmd;
            }
            return text;
        }
        if (op == Op::MTSPR && insn.srcs.size() >= 2) {
            return "mtspr(" + std::to_string(insn.aux_int) + ", " + render_operand(insn.srcs[1], 0, false) + ");";
        }
        if (op == Op::SYNC) {
            if (starts_with(insn.aux_str, "after")) return std::nullopt;
            return std::string("sync();");
        }
        if (op == Op::STOP) {
            char buf[48];
            std::snprintf(buf, sizeof(buf), "stop(0x%llX);", static_cast<unsigned long long>(insn.aux_int));
            return std::string(buf);
        }
        if (op == Op::HALT && insn.srcs.size() >= 2) {
            std::string cmp_sym = insn.aux_str;
            if (cmp_sym == "eq") cmp_sym = "==";
            else if (cmp_sym == "gt" || cmp_sym == "lgt") cmp_sym = ">";
            else if (cmp_sym == "ge") cmp_sym = ">=";
            else if (cmp_sym == "lt") cmp_sym = "<";
            else if (cmp_sym == "le") cmp_sym = "<=";
            else if (cmp_sym == "ne") cmp_sym = "!=";
            std::string lhs = render_operand(insn.srcs[0], 0, true, false, true);
            std::string rhs = render_operand(insn.srcs[1], 0, true, false, true);
            return "if ( " + lhs + " " + cmp_sym + " " + rhs + " ) abort();";
        }
        if (op == Op::SHUFB && insn.srcs.size() == 3 && insn.defines() && !regs::is_pseudo(insn.dst_reg)) {
            const Operand &mask_op = insn.srcs[2];
            if (mask_op.is_var()) {
                auto cit = defs.find(mask_op.key());
                if (cit != defs.end() && cit->second->op == Op::GENCTL && !cit->second->srcs.empty() &&
                    !try_unpack_genctl_chain(insn).has_value()) {
                    Insn *c_insn = cit->second;
                    std::string elem_ty = (c_insn->ew == EW::D) ? "u64" :
                                          (c_insn->ew == EW::W) ? "u32" :
                                          (c_insn->ew == EW::H) ? "u16" : "u8";
                    std::string idx_s;
                    if (auto slot = genctl_const_slot(mask_op); slot.has_value()) {
                        idx_s = std::to_string(*slot / static_cast<uint32_t>(c_insn->ew));
                    } else {
                        std::string c_addr = paren_non_atom(render_operand(c_insn->srcs[0], 0, true, false, true));
                        if (c_insn->ew == EW::D) idx_s = "(" + c_addr + " & 0xF) / 8";
                        else if (c_insn->ew == EW::W) idx_s = "(" + c_addr + " & 0xF) / 4";
                        else if (c_insn->ew == EW::H) idx_s = "(" + c_addr + " & 0xF) / 2";
                        else idx_s = c_addr + " & 0xF";
                    }
                    std::string dst_s = nma(insn.dst_as_var());
                    std::string val_s = render_operand(insn.srcs[0], 0, true, false, true);
                    std::string old_s = render_operand(insn.srcs[1], 0, false, false, false);
                    std::string lane_assign = "((" + elem_ty + " *)&" + dst_s + ")[" + idx_s + "] = " + val_s + ";";
                    if (old_s == dst_s) return lane_assign;
                    return dst_s + " = " + old_s + ";\n" + lane_assign;
                }
            }
        }
        if (op == Op::CALL || op == Op::ICALL) {
            std::string text = render_rhs(insn);
            auto rit = call_return.find(insn.uid);
            auto r2it = call_return2.find(insn.uid);
            if (rit != call_return.end() && r2it != call_return2.end()) {
                std::string t3 = ctype_str(type_of(rit->second));
                std::string t4 = ctype_str(type_of(r2it->second));
                return "{ vec_ullong4 _ret_pair = " + text + "; " +
                       nma(rit->second) + " = *(" + t3 + " *)&_ret_pair; " +
                       nma(r2it->second) + " = *(" + t4 + " *)((char *)&_ret_pair + 16); }";
            }
            if (rit != call_return.end()) {
                return nma(rit->second) + " = " + text + ";";
            }
            if (insn.defines() && !regs::is_pseudo(insn.dst_reg)) {
                return nma(insn.dst_as_var()) + " = " + text + ";";
            }
            return text + ";";
        }
        if (op == Op::NOP) return std::nullopt;

        if (!insn.defines()) return render_rhs(insn) + ";";
        if (regs::is_pseudo(insn.dst_reg)) return std::nullopt;
        return nma(insn.dst_as_var()) + " = " + render_rhs(insn) + ";";
    }

    std::pair<std::string, std::optional<Operand>> render_return(const Insn &insn) {
        if (insn.op == Op::STOP) {
            char buf[48];
            std::snprintf(buf, sizeof(buf), "stop(0x%llX);", static_cast<unsigned long long>(insn.aux_int));
            return {buf, std::nullopt};
        }
        if (two_reg_return) {
            std::optional<Operand> r3_op, r4_op;
            for (const auto &s : insn.srcs) {
                if (!s.is_var() || s.ver == 0) continue;
                if (s.reg == regs::ARG_FIRST) r3_op = s;
                else if (s.reg == regs::ARG_FIRST + 1) r4_op = s;
            }
            if (r3_op.has_value() && r4_op.has_value()) {
                auto try_d2 = [&](const Operand &opnd) -> std::optional<std::pair<std::string, std::string>> {
                    auto dit = defs.find(opnd.key());
                    if (dit == defs.end()) return std::nullopt;
                    auto ch = try_unpack_genctl_chain(*dit->second);
                    if (!ch.has_value() || ch->ew != EW::D || !ch->full_coverage || ch->lanes.size() != 2) {
                        return std::nullopt;
                    }
                    std::string s0 = render_operand(*ch->lanes[0], 0, true, false, true);
                    std::string s1 = render_operand(*ch->lanes[1], 0, true, false, true);
                    return std::make_pair(s0, s1);
                };
                auto p3 = try_d2(*r3_op);
                auto p4 = try_d2(*r4_op);
                if (p3.has_value() && p4.has_value() && ret_type == "vec_ullong4") {
                    return {"return (vec_ullong4){ " + p3->first + ", " + p3->second + ", " +
                            p4->first + ", " + p4->second + " };", r3_op};
                }
                std::string s3 = render_operand(*r3_op, 0, false);
                std::string s4 = render_operand(*r4_op, 0, false);
                return {"return (" + ret_type + "){ " + s3 + ", " + s4 + " };", r3_op};
            }
        }
        for (const auto &s : insn.srcs) {
            if (s.is_var() && s.reg == regs::ARG_FIRST && s.ver != 0) {
                if (debris.find(s.key()) != debris.end() ||
                    func.store_idiom_roots.find(s.key()) != func.store_idiom_roots.end()) {
                    continue;
                }
                return {"return " + render_operand(s, 0, false) + ";", s};
            }
        }
        return {"return;", std::nullopt};
    }

    // --- ctree AST synthesis helpers ---
    int ensure_lvar_placeholder(const std::string &eff_name) {
        auto it = lvar_idx_by_name.find(eff_name);
        if (it != lvar_idx_by_name.end()) return it->second;
        int idx = static_cast<int>(cfunc->lvars.size());
        lvar_t lv;
        lv.index = idx;
        lv.name = eff_name;
        lv.canonical_name = eff_name;
        cfunc->lvars.push_back(std::move(lv));
        lvar_idx_by_name[eff_name] = idx;
        return idx;
    }

    cexpr_t *build_ast_for_operand(const Operand &opnd, uint64_t ea, const std::string &rendered_txt) {
        if (opnd.is_const) {
            uint64_t av = opnd.val.word0();
            if (!rendered_txt.empty() && rendered_txt.front() == '"') {
                cexpr_t *e = cfunc->alloc_expr(cot_str, ea);
                e->string = rendered_txt;
                e->obj_ea = av;
                e->type_str = "const char *";
                e->text_cache = rendered_txt;
                return e;
            }
            if (!rendered_txt.empty() && rendered_txt.front() == '&') {
                cexpr_t *e = cfunc->alloc_expr(cot_obj, ea);
                e->obj_ea = av;
                e->helper = rendered_txt;
                e->text_cache = rendered_txt;
                return e;
            }
            cexpr_t *e = cfunc->alloc_expr(cot_num, ea);
            e->n._value = opnd.val.low96_zero() ? static_cast<uint64_t>(av) : opnd.val.lo;
            e->n.ea = ea;
            e->n.repr = rendered_txt;
            e->n.addr_val = av;
            e->text_cache = rendered_txt;
            return e;
        }
        if (inlinable.find(opnd.key()) != inlinable.end()) {
            auto dit = defs.find(opnd.key());
            if (dit != defs.end()) {
                return build_ast_for_rhs(*dit->second, rendered_txt);
            }
        }
        cexpr_t *e = cfunc->alloc_expr(cot_var, ea);
        std::string vname = lookup_rename(namer->name(opnd));
        e->v.idx = ensure_lvar_placeholder(vname);
        e->helper = vname;
        e->text_cache = rendered_txt;
        return e;
    }

    cexpr_t *build_ast_for_rhs(const Insn &insn, const std::string &rendered_rhs) {
        const uint64_t ea = insn.ea;
        const Op op = insn.op;

        if (op == Op::CONST && !insn.srcs.empty()) {
            return build_ast_for_operand(insn.srcs[0], ea, rendered_rhs);
        }
        if (op == Op::MOV && !insn.srcs.empty()) {
            return build_ast_for_operand(insn.srcs[0], ea, rendered_rhs);
        }
        if (op == Op::CALL || op == Op::ICALL || op == Op::TCALL) {
            cexpr_t *call_e = cfunc->alloc_expr(cot_call, ea);
            if (op == Op::CALL || op == Op::TCALL) {
                cexpr_t *callee = cfunc->alloc_expr(cot_obj, ea);
                callee->obj_ea = insn.aux_ea;
                callee->helper = lookup_rename(query_name(insn.aux_ea));
                callee->text_cache = callee->helper;
                call_e->x = callee;
                call_e->obj_ea = insn.aux_ea;
                call_e->helper = callee->helper;
            } else if (!insn.srcs.empty()) {
                call_e->x = build_ast_for_operand(insn.srcs[0], ea, "");
            }
            if (auto cit = call_args.find(insn.uid); cit != call_args.end()) {
                for (const auto &arg : cit->second) {
                    call_e->a.push_back(build_ast_for_operand(arg, ea, ""));
                }
            }
            call_e->text_cache = rendered_rhs;
            return call_e;
        }
        if (op_is_mem_read(op) && insn.srcs.size() >= 2) {
            if (rendered_rhs.find("->") != std::string::npos) {
                cexpr_t *e = cfunc->alloc_expr(cot_memptr, ea);
                e->ptrsize = static_cast<int>(insn.ew);
                e->x = build_ast_for_operand(insn.srcs[1], ea, "");
                auto p = rendered_rhs.find("->");
                e->string = rendered_rhs.substr(p + 2);
                e->type_str = access_type(insn);
                e->text_cache = rendered_rhs;
                return e;
            }
            cexpr_t *e = cfunc->alloc_expr(cot_ptr, ea);
            e->ptrsize = static_cast<int>(insn.ew);
            e->type_str = access_type(insn);
            e->x = build_ast_for_operand(insn.srcs[1], ea, "");
            e->text_cache = rendered_rhs;
            return e;
        }

        // Map standard binary IR operations to ctype_t
        ctype_t cop = cot_empty;
        switch (op) {
            case Op::ADD: case Op::ADDX: cop = cot_add; break;
            case Op::SUB: case Op::SUBX: cop = cot_sub; break;
            case Op::MUL: case Op::MPY: case Op::MPYU: cop = cot_mul; break;
            case Op::AND: cop = cot_band; break;
            case Op::OR:  cop = cot_bor; break;
            case Op::XOR: cop = cot_xor; break;
            case Op::SHL: cop = cot_shl; break;
            case Op::SHR: cop = cot_ushr; break;
            case Op::SAR: cop = cot_sshr; break;
            case Op::CMPEQ: case Op::FCMPEQ: cop = cot_eq; break;
            case Op::CMPGT: case Op::FCMPGT: cop = cot_sgt; break;
            case Op::CMPGTU: cop = cot_ugt; break;
            case Op::FADD: cop = cot_fadd; break;
            case Op::FSUB: cop = cot_fsub; break;
            case Op::FMUL: cop = cot_fmul; break;
            default: break;
        }
        if (cop != cot_empty && insn.srcs.size() >= 2 && rendered_rhs.find('(') != 0) {
            cexpr_t *e = cfunc->alloc_expr(cop, ea);
            e->x = build_ast_for_operand(insn.srcs[0], ea, "");
            e->y = build_ast_for_operand(insn.srcs[1], ea, "");
            e->text_cache = rendered_rhs;
            return e;
        }
        if (op == Op::NOT && insn.srcs.size() == 1) {
            cexpr_t *e = cfunc->alloc_expr(cot_bnot, ea);
            e->x = build_ast_for_operand(insn.srcs[0], ea, "");
            e->text_cache = rendered_rhs;
            return e;
        }

        // Helper / intrinsic call representation (e.g. spu_shuffle, aes_sub_bytes, rdch, _rotl)
        auto lp = rendered_rhs.find('(');
        if (lp != std::string::npos && lp > 0 && rendered_rhs.back() == ')') {
            std::string hname = rendered_rhs.substr(0, lp);
            if (is_c_ident(hname) || hname.find('.') != std::string::npos) {
                cexpr_t *call_e = cfunc->alloc_expr(cot_call, ea);
                cexpr_t *hlp = cfunc->alloc_expr(cot_helper, ea);
                hlp->helper = hname;
                hlp->text_cache = hname;
                call_e->x = hlp;
                call_e->helper = hname;
                for (const auto &s : insn.srcs) {
                    call_e->a.push_back(build_ast_for_operand(s, ea, ""));
                }
                call_e->text_cache = rendered_rhs;
                return call_e;
            }
        }

        cexpr_t *e = cfunc->alloc_expr(cot_helper, ea);
        e->helper = rendered_rhs;
        e->text_cache = rendered_rhs;
        return e;
    }

    cexpr_t *build_ast_for_insn_stmt(const Insn &insn, const std::string &stmt_txt) {
        std::string no_semi = (!stmt_txt.empty() && stmt_txt.back() == ';')
                                  ? stmt_txt.substr(0, stmt_txt.size() - 1)
                                  : stmt_txt;
        if (insn.op == Op::STORE || insn.op == Op::STOREQ) {
            auto eq = no_semi.find(" = ");
            std::string lhs_txt = (eq != std::string::npos) ? no_semi.substr(0, eq) : "";
            std::string rhs_txt = (eq != std::string::npos) ? no_semi.substr(eq + 3) : "";
            cexpr_t *asg = cfunc->alloc_expr(cot_asg, insn.ea);
            cexpr_t *lhs = cfunc->alloc_expr(cot_ptr, insn.ea);
            lhs->ptrsize = static_cast<int>(insn.ew);
            lhs->type_str = access_type(insn);
            if (insn.srcs.size() >= 2) lhs->x = build_ast_for_operand(insn.srcs[1], insn.ea, lhs_txt);
            lhs->text_cache = lhs_txt;
            asg->x = lhs;
            if (insn.srcs.size() >= 3) asg->y = build_ast_for_operand(insn.srcs[2], insn.ea, rhs_txt);
            asg->text_cache = no_semi;
            return asg;
        }
        if (insn.op == Op::CALL || insn.op == Op::ICALL) {
            auto rit = call_return.find(insn.uid);
            if (rit != call_return.end()) {
                auto eq = no_semi.find(" = ");
                std::string rhs_txt = (eq != std::string::npos) ? no_semi.substr(eq + 3) : no_semi;
                cexpr_t *asg = cfunc->alloc_expr(cot_asg, insn.ea);
                asg->x = build_ast_for_operand(rit->second, insn.ea, lookup_rename(namer->name(rit->second)));
                asg->y = build_ast_for_rhs(insn, rhs_txt);
                asg->text_cache = no_semi;
                return asg;
            }
            return build_ast_for_rhs(insn, no_semi);
        }
        if (insn.defines() && !regs::is_pseudo(insn.dst_reg)) {
            auto eq = no_semi.find(" = ");
            std::string lhs_txt = (eq != std::string::npos) ? no_semi.substr(0, eq) : lookup_rename(namer->name(insn.dst_as_var()));
            std::string rhs_txt = (eq != std::string::npos) ? no_semi.substr(eq + 3) : no_semi;
            cexpr_t *asg = cfunc->alloc_expr(cot_asg, insn.ea);
            asg->x = build_ast_for_operand(insn.dst_as_var(), insn.ea, lhs_txt);
            asg->y = build_ast_for_rhs(insn, rhs_txt);
            asg->text_cache = no_semi;
            return asg;
        }
        return build_ast_for_rhs(insn, no_semi);
    }

    cexpr_t *build_ast_for_cond(const structure::Cond *cond, uint64_t ea, const std::string &cond_str) {
        cexpr_t *e = cfunc->alloc_expr(cot_ne, ea);
        if (cond) {
            e->x = build_ast_for_operand(cond->value, ea, "");
            cexpr_t *zero = cfunc->alloc_expr(cot_num, ea);
            zero->n._value = 0;
            zero->n.repr = "0";
            zero->text_cache = "0";
            e->y = zero;
        }
        e->text_cache = cond_str;
        return e;
    }

    // --- Line emitter ---
    std::unordered_set<uint64_t> emitted_cmt_eas;

    std::optional<std::string> find_user_cmt(std::optional<uint64_t> primary_ea,
                                             const std::vector<uint64_t> &inlined_eas) {
        if (user_cmts.empty()) return std::nullopt;
        std::vector<uint64_t> check;
        if (primary_ea.has_value()) check.push_back(*primary_ea);
        check.insert(check.end(), inlined_eas.begin(), inlined_eas.end());
        for (uint64_t ea : check) {
            if (emitted_cmt_eas.count(ea)) continue;
            char hex_k[32];
            std::snprintf(hex_k, sizeof(hex_k), "0x%llx", static_cast<unsigned long long>(ea));
            auto it = user_cmts.find(hex_k);
            if (it != user_cmts.end() && !it->second.empty()) {
                emitted_cmt_eas.insert(ea);
                return it->second;
            }
            auto it2 = user_cmts.find(std::to_string(ea));
            if (it2 != user_cmts.end() && !it2->second.empty()) {
                emitted_cmt_eas.insert(ea);
                return it2->second;
            }
        }
        return std::nullopt;
    }

    void add_body_line(std::vector<std::string> &out, std::string text,
                       std::optional<uint64_t> primary_ea = std::nullopt,
                       const std::vector<uint64_t> &inlined_eas = {},
                       cinsn_t *stmt_node = nullptr) {
        int lineno = static_cast<int>(out.size());
        if (auto cmt = find_user_cmt(primary_ea, inlined_eas); cmt.has_value()) {
            text += "   // " + *cmt;
            if (stmt_node) stmt_node->user_cmt = *cmt;
        }
        out.push_back(text);
        body_eas.push_back(primary_ea);

        std::vector<uint64_t> unique_eas;
        auto push_uniq = [&](uint64_t e) {
            if (std::find(unique_eas.begin(), unique_eas.end(), e) == unique_eas.end()) {
                unique_eas.push_back(e);
            }
        };
        if (primary_ea.has_value()) push_uniq(*primary_ea);
        for (uint64_t e : inlined_eas) push_uniq(e);
        body_line_to_eas[lineno] = unique_eas;

        if (!cur_line_consts.empty()) {
            size_t search_pos = 0;
            std::vector<LineConstSpan> resolved;
            resolved.reserve(cur_line_consts.size());
            for (auto cinfo : cur_line_consts) {
                size_t pos = text.find(cinfo.text, search_pos);
                size_t matched_len = cinfo.text.size();
                if (pos == std::string::npos && !cinfo.text.empty() && cinfo.text[0] == '-') {
                    std::string stripped = cinfo.text.substr(1);
                    pos = text.find(stripped, search_pos);
                    matched_len = stripped.size();
                }
                if (pos == std::string::npos) {
                    pos = text.find(cinfo.text);
                    matched_len = cinfo.text.size();
                }
                if (cinfo.ea == 0 && !primary_ea.has_value() && !unique_eas.empty()) {
                    cinfo.ea = unique_eas[0];
                }
                if (pos != std::string::npos) {
                    cinfo.col_start = static_cast<int>(pos);
                    cinfo.col_end = static_cast<int>(pos + matched_len);
                    search_pos = pos + matched_len;
                } else {
                    cinfo.col_start = 0;
                    cinfo.col_end = static_cast<int>(text.size());
                }
                if (stmt_node) cinfo.citem_id = stmt_node->obj_id;
                resolved.push_back(std::move(cinfo));
            }
            body_line_consts[lineno] = std::move(resolved);
            cur_line_consts.clear();
            cur_const_idx = 0;
        }
    }

    void emit_stmts(const std::vector<std::unique_ptr<structure::Stmt>> &stmts,
                    std::vector<std::string> &out, int indent,
                    const structure::StructureInfo &info,
                    cinsn_t *parent_block) {
        using namespace structure;
        std::string pad(static_cast<size_t>(indent) * 4, ' ');
        int pending_label_blk = -1;

        auto attach_pending_label = [&](cinsn_t *node) {
            if (pending_label_blk >= 0 && node) {
                node->label_num = pending_label_blk;
                node->label_name = lbl_name(*func.blocks[pending_label_blk]);
                pending_label_blk = -1;
            }
        };

        for (const auto &st_ptr : stmts) {
            const Stmt &st = *st_ptr;
            switch (st.kind) {
                case StmtKind::Basic: {
                    for (const Insn *insn : st.insns) {
                        current_inlined_eas.clear();
                        reset_stmt_consts(insn->ea);
                        auto text = render_insn_stmt(*insn);
                        if (text.has_value()) {
                            std::istringstream liss(*text);
                            std::string subline;
                            bool first_sub = true;
                            while (std::getline(liss, subline)) {
                                if (subline.empty()) continue;
                                cinsn_t *cins = cfunc->alloc_insn(cit_expr, insn->ea);
                                cins->cexpr_node = first_sub ? build_ast_for_insn_stmt(*insn, subline) : nullptr;
                                cins->text_cache = subline;
                                attach_pending_label(cins);
                                if (parent_block) parent_block->cblock.push_back(cins);
                                add_body_line(out, pad + subline, insn->ea, first_sub ? current_inlined_eas : std::vector<uint64_t>{}, cins);
                                first_sub = false;
                            }
                        } else {
                            cur_line_consts.clear();
                        }
                    }
                    break;
                }
                case StmtKind::If: {
                    current_inlined_eas.clear();
                    std::optional<uint64_t> ea = st.has_ea ? std::optional<uint64_t>(st.ea) : std::nullopt;
                    reset_stmt_consts(ea);
                    std::string cond_str = render_cond(&st.cond);
                    bool invert = ea.has_value() && user_iflags.find(*ea) != user_iflags.end();

                    cinsn_t *cif_node = cfunc->alloc_insn(cit_if, ea.value_or(UINT64_MAX));
                    attach_pending_label(cif_node);
                    if (parent_block) parent_block->cblock.push_back(cif_node);

                    if (invert && !st.els_body.empty()) {
                        cond_str = invert_cond_str(cond_str);
                        cif_node->cif.expr = build_ast_for_cond(&st.cond, ea.value_or(UINT64_MAX), cond_str);
                        add_body_line(out, pad + "if ( " + cond_str + " )", ea, current_inlined_eas, cif_node);

                        cinsn_t *b_then = cfunc->alloc_insn(cit_block);
                        cif_node->cif.ithen = b_then;
                        add_body_line(out, pad + "{");
                        emit_stmts(st.els_body, out, indent + 1, info, b_then);
                        add_body_line(out, pad + "}");

                        cinsn_t *b_else = cfunc->alloc_insn(cit_block);
                        cif_node->cif.ielse = b_else;
                        add_body_line(out, pad + "else");
                        add_body_line(out, pad + "{");
                        emit_stmts(st.then_body, out, indent + 1, info, b_else);
                        add_body_line(out, pad + "}");
                    } else {
                        cif_node->cif.expr = build_ast_for_cond(&st.cond, ea.value_or(UINT64_MAX), cond_str);
                        add_body_line(out, pad + "if ( " + cond_str + " )", ea, current_inlined_eas, cif_node);

                        cinsn_t *b_then = cfunc->alloc_insn(cit_block);
                        cif_node->cif.ithen = b_then;
                        add_body_line(out, pad + "{");
                        emit_stmts(st.then_body, out, indent + 1, info, b_then);
                        add_body_line(out, pad + "}");

                        if (!st.els_body.empty()) {
                            cinsn_t *b_else = cfunc->alloc_insn(cit_block);
                            cif_node->cif.ielse = b_else;
                            add_body_line(out, pad + "else");
                            add_body_line(out, pad + "{");
                            emit_stmts(st.els_body, out, indent + 1, info, b_else);
                            add_body_line(out, pad + "}");
                        }
                    }
                    break;
                }
                case StmtKind::Loop: {
                    std::optional<uint64_t> hdr_ea;
                    if (st.block_id >= 0 && st.block_id < static_cast<int>(func.blocks.size())) {
                        hdr_ea = func.blocks[st.block_id]->start_ea;
                    }
                    ctype_t lop = (st.loop_kind == LoopKind::While)   ? cit_while :
                                  (st.loop_kind == LoopKind::DoWhile) ? cit_do    : cit_for;
                    cinsn_t *lnode = cfunc->alloc_insn(lop, hdr_ea.value_or(UINT64_MAX));
                    attach_pending_label(lnode);
                    if (parent_block) parent_block->cblock.push_back(lnode);
                    cinsn_t *lbody = cfunc->alloc_insn(cit_block);
                    lnode->cloop.body = lbody;

                    if (st.loop_kind == LoopKind::While) {
                        current_inlined_eas.clear();
                        reset_stmt_consts(hdr_ea);
                        std::string cond_str = render_cond(st.has_cond ? &st.cond : nullptr);
                        lnode->cloop.expr = build_ast_for_cond(st.has_cond ? &st.cond : nullptr,
                                                               hdr_ea.value_or(UINT64_MAX), cond_str);
                        add_body_line(out, pad + "while ( " + cond_str + " )", hdr_ea, current_inlined_eas, lnode);
                        add_body_line(out, pad + "{");
                        emit_stmts(st.body, out, indent + 1, info, lbody);
                        add_body_line(out, pad + "}");
                    } else if (st.loop_kind == LoopKind::DoWhile) {
                        add_body_line(out, pad + "do", hdr_ea, {}, lnode);
                        add_body_line(out, pad + "{");
                        emit_stmts(st.body, out, indent + 1, info, lbody);
                        current_inlined_eas.clear();
                        reset_stmt_consts(hdr_ea);
                        std::string cond_str = render_cond(st.has_cond ? &st.cond : nullptr);
                        lnode->cloop.expr = build_ast_for_cond(st.has_cond ? &st.cond : nullptr,
                                                               hdr_ea.value_or(UINT64_MAX), cond_str);
                        add_body_line(out, pad + "} while ( " + cond_str + " );", hdr_ea, current_inlined_eas, lnode);
                    } else {
                        add_body_line(out, pad + "for ( ;; )", hdr_ea, {}, lnode);
                        add_body_line(out, pad + "{");
                        emit_stmts(st.body, out, indent + 1, info, lbody);
                        add_body_line(out, pad + "}");
                    }
                    break;
                }
                case StmtKind::Break: {
                    cinsn_t *bn = cfunc->alloc_insn(cit_break);
                    attach_pending_label(bn);
                    if (parent_block) parent_block->cblock.push_back(bn);
                    add_body_line(out, pad + "break;", std::nullopt, {}, bn);
                    break;
                }
                case StmtKind::Continue: {
                    cinsn_t *cn = cfunc->alloc_insn(cit_continue);
                    attach_pending_label(cn);
                    if (parent_block) parent_block->cblock.push_back(cn);
                    add_body_line(out, pad + "continue;", std::nullopt, {}, cn);
                    break;
                }
                case StmtKind::Goto: {
                    const Block &tgt_blk = *func.blocks[st.block_id];
                    std::string lname = lbl_name(tgt_blk);
                    cinsn_t *gn = cfunc->alloc_insn(cit_goto, tgt_blk.start_ea);
                    gn->cgoto.label_num = st.block_id;
                    gn->cgoto.target_name = lname;
                    gn->text_cache = "goto " + lname + ";";
                    attach_pending_label(gn);
                    if (parent_block) parent_block->cblock.push_back(gn);
                    add_body_line(out, pad + gn->text_cache, tgt_blk.start_ea, {}, gn);
                    break;
                }
                case StmtKind::Label: {
                    if (info.labels.find(st.block_id) != info.labels.end()) {
                        const Block &lbl_blk = *func.blocks[st.block_id];
                        std::string lpad(static_cast<size_t>(indent > 0 ? indent - 1 : 0) * 4, ' ');
                        add_body_line(out, lpad + lbl_name(lbl_blk) + ":", lbl_blk.start_ea);
                        pending_label_blk = st.block_id;
                    }
                    break;
                }
                case StmtKind::Return: {
                    current_inlined_eas.clear();
                    uint64_t ea = st.insn ? st.insn->ea : 0;
                    reset_stmt_consts(ea);
                    auto [ret_str, ret_opnd] = render_return(*st.insn);
                    cinsn_t *rn = cfunc->alloc_insn(cit_return, ea);
                    rn->text_cache = ret_str;
                    if (ret_opnd.has_value()) {
                        rn->creturn.expr = build_ast_for_operand(*ret_opnd, ea, lookup_rename(namer->name(*ret_opnd)));
                    }
                    attach_pending_label(rn);
                    if (parent_block) parent_block->cblock.push_back(rn);
                    add_body_line(out, pad + ret_str, ea, current_inlined_eas, rn);
                    break;
                }
                case StmtKind::Tail: {
                    current_inlined_eas.clear();
                    const Insn &ti = *st.insn;
                    reset_stmt_consts(ti.ea);
                    if (ti.op == Op::IJMP) {
                        const Block &blk = *func.blocks[ti.block_id];
                        const char *kstr = (blk.succs.size() > 1) ? "jump table" : "indirect / tail call";
                        std::string op_s = ti.srcs.empty() ? "?" : render_operand(ti.srcs[0], 0, true);
                        std::string line_s = "goto *" + op_s + ";   // " + kstr;
                        cinsn_t *gn = cfunc->alloc_insn(cit_goto, ti.ea);
                        gn->text_cache = line_s;
                        attach_pending_label(gn);
                        if (parent_block) parent_block->cblock.push_back(gn);
                        add_body_line(out, pad + line_s, ti.ea, current_inlined_eas, gn);
                    } else if (ti.op == Op::TCALL) {
                        std::string call_str = render_rhs(ti);
                        std::string line_s = (ret_type != "void") ? ("return " + call_str + ";") : (call_str + ";");
                        cinsn_t *tn = cfunc->alloc_insn(ret_type != "void" ? cit_return : cit_expr, ti.ea);
                        cexpr_t *ce = build_ast_for_rhs(ti, call_str);
                        if (ret_type != "void") tn->creturn.expr = ce;
                        else tn->cexpr_node = ce;
                        tn->text_cache = line_s;
                        attach_pending_label(tn);
                        if (parent_block) parent_block->cblock.push_back(tn);
                        add_body_line(out, pad + line_s, ti.ea, current_inlined_eas, tn);
                    } else if (ti.op == Op::JMP) {
                        std::string tgt_nm = query_name(ti.aux_ea);
                        if (tgt_nm.empty()) {
                            char buf[32];
                            std::snprintf(buf, sizeof(buf), "loc_%llX", static_cast<unsigned long long>(ti.aux_ea));
                            tgt_nm = buf;
                        } else {
                            tgt_nm = lookup_rename(tgt_nm);
                            if (ti.has_aux) call_eas[tgt_nm] = ti.aux_ea;
                        }
                        std::string line_s = "goto " + tgt_nm + ";   // outside this function";
                        cinsn_t *gn = cfunc->alloc_insn(cit_goto, ti.ea);
                        gn->cgoto.target_name = tgt_nm;
                        gn->text_cache = line_s;
                        attach_pending_label(gn);
                        if (parent_block) parent_block->cblock.push_back(gn);
                        add_body_line(out, pad + line_s, ti.ea, {}, gn);
                    } else {
                        std::string line_s = render_rhs(ti) + ";";
                        cinsn_t *en = cfunc->alloc_insn(cit_expr, ti.ea);
                        en->cexpr_node = build_ast_for_rhs(ti, line_s);
                        en->text_cache = line_s;
                        attach_pending_label(en);
                        if (parent_block) parent_block->cblock.push_back(en);
                        add_body_line(out, pad + line_s, ti.ea, current_inlined_eas, en);
                    }
                    break;
                }
            }
        }
    }

    std::pair<std::string, std::string> build_signature() {
        sig_params.clear();
        if (user_proto.has_value() && !user_proto->empty()) {
            std::string fb = func.name.empty() ? default_sub_name(func.start_ea) : func.name;
            auto parsed = abi::parse_proto(*user_proto, fb);
            if (parsed.has_value()) {
                ret_type = parsed->ret_type;
                all_var_types["__return__"] = ret_type;
                if (!parsed->params.empty()) {
                    std::string plist;
                    for (size_t i = 0; i < parsed->params.size(); ++i) {
                        const auto &p = parsed->params[i];
                        std::string eff_name = lookup_rename(p.name);
                        std::string eff_type = p.type_str;
                        if (auto it = user_types.find(p.name); it != user_types.end()) eff_type = it->second;
                        if (auto it = user_types.find(eff_name); it != user_types.end()) eff_type = it->second;
                        if (i > 0) plist += ", ";
                        plist += eff_type + ((!eff_type.empty() && eff_type.back() == '*') ? "" : " ") + eff_name;
                        sig_params.push_back({eff_name, eff_type});
                        all_var_types[eff_name] = eff_type;
                        all_var_types[p.name] = eff_type;
                    }
                    return {ret_type, plist};
                }
                return {ret_type, "void"};
            }
        }

        std::string plist;
        for (size_t i = 0; i < params.size(); ++i) {
            int r = params[i];
            std::string raw_nm = raw_param_name[r];
            std::string pnm = param_name[r];
            std::string p_type;
            if (this_reg.has_value() && r == *this_reg && member_class.has_value()) {
                p_type = *member_class + " *";
            } else {
                p_type = ctype_str(types_map.of(make_var_key(r, 0)));
                if (auto it = user_types.find(raw_nm); it != user_types.end()) p_type = it->second;
                if (auto it = user_types.find(pnm); it != user_types.end()) p_type = it->second;
            }
            if (i > 0) plist += ", ";
            plist += p_type + ((!p_type.empty() && p_type.back() == '*') ? "" : " ") + pnm;
            sig_params.push_back({pnm, p_type});
            all_var_types[pnm] = p_type;
            all_var_types[raw_nm] = p_type;
        }

        if (auto it = user_types.find("__return__"); it != user_types.end()) {
            ret_type = it->second;
        } else if (two_reg_return) {
            bool all_d2 = true;
            for (const auto &b : func.blocks) {
                for (const auto &insn : b->insns) {
                    if (insn->op != Op::RET) continue;
                    for (const auto &s : insn->srcs) {
                        if (!s.is_var() || s.ver == 0) continue;
                        if (s.reg != regs::ARG_FIRST && s.reg != regs::ARG_FIRST + 1) continue;
                        auto dit = defs.find(s.key());
                        auto ch = (dit != defs.end()) ? try_unpack_genctl_chain(*dit->second) : std::nullopt;
                        if (!ch.has_value() || ch->ew != EW::D || !ch->full_coverage) {
                            all_d2 = false;
                            break;
                        }
                    }
                    if (!all_d2) break;
                }
                if (!all_d2) break;
            }
            ret_type = all_d2 ? "vec_ullong4" : "qword2";
        } else {
            ret_type = "void";
            for (const auto &b : func.blocks) {
                for (const auto &insn : b->insns) {
                    if (insn->op != Op::RET) continue;
                    for (const auto &s : insn->srcs) {
                        if (s.is_var() && s.reg == regs::ARG_FIRST && s.ver != 0) {
                            ret_type = ctype_str(type_of(s), "qword");
                            break;
                        }
                    }
                }
            }
        }
        all_var_types["__return__"] = ret_type;
        return {ret_type, plist.empty() ? "void" : plist};
    }

    std::vector<std::string> build_declarations_and_lvars() {
        std::unordered_set<std::string> pnames;
        for (const auto &[r, pnm] : param_name) {
            pnames.insert(pnm);
            pnames.insert(lookup_rename(pnm));
            if (auto it = raw_param_name.find(r); it != raw_param_name.end()) pnames.insert(it->second);
        }

        // Finalize lvar metadata for parameters first
        cfunc->argidx.clear();
        for (size_t idx = 0; idx < params.size() && idx < sig_params.size(); ++idx) {
            int r = params[idx];
            const auto &[pnm, pty] = sig_params[idx];
            int lidx = ensure_lvar_placeholder(pnm);
            lvar_t &lv = cfunc->lvars[static_cast<size_t>(lidx)];
            lv.canonical_name = raw_param_name[r];
            lv.type_str = pty;
            lv.defea = func.start_ea;
            lv.location = lvar_locator_t{false, r, 0, func.start_ea};
            lv.is_arg_var = true;
            lv.is_thisarg = (this_reg.has_value() && r == *this_reg);
            lv.has_user_name = (pnm != lv.canonical_name);
            lv.has_user_type = (user_types.count(lv.canonical_name) > 0 || user_types.count(pnm) > 0);
            cfunc->argidx.push_back(lidx);
        }

        struct LocalMeta {
            std::string canonical;
            std::string ctype;
            int reg = -1;
            int64_t stk_off = 0;
            uint64_t defea = UINT64_MAX;
            bool is_stk = false;
        };
        std::unordered_map<std::string, LocalMeta> by_name;

        auto is_vec_ctype = [](const std::string &ct) -> bool {
            if (ct.find('*') != std::string::npos) return false;
            return ct == "qword" || starts_with(ct, "vec_");
        };
        auto is_true_vector_op = [](Op op) -> bool {
            switch (op) {
                case Op::LOADQ: case Op::LOADU: case Op::STOREQ:
                case Op::SHUFB: case Op::GENCTL:
                case Op::QROTBY: case Op::QROTBI: case Op::QROTMBY:
                case Op::QROTMBI: case Op::QSHLBY: case Op::QSHLBI:
                    return true;
                default:
                    return false;
            }
        };
        // Track which local variable names genuinely participate in 128-bit vector operations
        // (excluding instructions that were suppressed/inlined/constant-folded away).
        std::unordered_set<std::string> true_vec_names;
        std::unordered_set<std::string> qword_assigned_names;
        for (const auto &b : func.blocks) {
            for (const auto &insn : b->insns) {
                if (is_suppressed(*insn)) continue;
                if ((insn->op == Op::LOADQ || insn->op == Op::LOADU) &&
                    insn->defines() && !regs::is_pseudo(insn->dst_reg)) {
                    qword_assigned_names.insert(namer->name_key(insn->dst_key()));
                }
                if (!is_true_vector_op(insn->op)) continue;
                if (insn->defines() && !regs::is_pseudo(insn->dst_reg)) {
                    true_vec_names.insert(namer->name_key(insn->dst_key()));
                }
                for (const auto &u : insn->srcs) {
                    if (u.is_var() && !regs::is_pseudo(u.reg)) {
                        true_vec_names.insert(namer->name(u));
                    }
                }
            }
        }
        // Also propagate vectorness from any vector-typed parameters.
        for (const auto &[pnm, pty] : sig_params) {
            if (is_vec_ctype(pty)) true_vec_names.insert(pnm);
        }

        for (const auto &b : func.blocks) {
            for (const auto &insn : b->insns) {
                if (!insn->defines() || regs::is_pseudo(insn->dst_reg)) continue;
                std::string raw_nm = namer->name_key(insn->dst_key());
                if (assigned.find(raw_nm) == assigned.end()) continue;
                std::string eff_nm = lookup_rename(raw_nm);
                if (by_name.count(eff_nm) || pnames.count(eff_nm) || pnames.count(raw_nm)) continue;

                std::string ct = ctype_str(type_of_key(insn->dst_key()));
                bool has_ut = false;
                if (auto it = user_types.find(raw_nm); it != user_types.end()) { ct = it->second; has_ut = true; }
                if (auto it = user_types.find(eff_nm); it != user_types.end()) { ct = it->second; has_ut = true; }
                if (!has_ut && ct == "vec_uchar16" && qword_assigned_names.count(raw_nm)) {
                    ct = "qword";
                } else if (!has_ut && is_vec_ctype(ct) && true_vec_names.find(raw_nm) == true_vec_names.end()) {
                    auto dit = func.demand.find(insn->dst_key());
                    if (dit != func.demand.end() && (dit->second & ~lanes::W0) != 0 && (dit->second & ~0x00FFu) == 0) {
                        ct = "unsigned long long";
                    } else {
                        ct = "unsigned int";
                    }
                }
                by_name[eff_nm] = LocalMeta{raw_nm, ct, insn->dst_reg, 0, insn->ea, false};
            }
        }

        auto reg_call_ret = [&](const std::unordered_map<uint32_t, Operand> &cret) {
            for (const auto &[uid, ret_var] : cret) {
                std::string raw_nm = namer->name(ret_var);
                if (assigned.find(raw_nm) == assigned.end()) continue;
                std::string eff_nm = lookup_rename(raw_nm);
                if (by_name.count(eff_nm) || pnames.count(eff_nm) || pnames.count(raw_nm)) continue;

                std::string ct = ctype_str(type_of(ret_var));
                if (auto it = user_types.find(raw_nm); it != user_types.end()) ct = it->second;
                if (auto it = user_types.find(eff_nm); it != user_types.end()) ct = it->second;
                uint64_t def_ea = ret_var.def_insn ? ret_var.def_insn->ea : func.start_ea;
                by_name[eff_nm] = LocalMeta{raw_nm, ct, ret_var.reg, 0, def_ea, false};
            }
        };
        reg_call_ret(call_return);
        reg_call_ret(call_return2);

        std::unordered_map<std::string, LocalMeta> live_in;
        for (const auto &b : func.blocks) {
            for (const auto &insn : b->insns) {
                int n_real = 0;
                bool is_abi = op_is_abi(insn->op, &n_real);
                size_t lim = is_abi ? static_cast<size_t>(n_real) : insn->srcs.size();
                for (size_t i = 0; i < lim && i < insn->srcs.size(); ++i) {
                    const Operand &u = insn->srcs[i];
                    if (!u.is_var() || u.ver != 0 || regs::is_pseudo(u.reg)) continue;
                    std::string raw_nm = namer->name(u);
                    if (printed.find(raw_nm) == printed.end()) continue;
                    std::string eff_nm = lookup_rename(raw_nm);
                    if (pnames.count(eff_nm) || by_name.count(eff_nm) || live_in.count(eff_nm) || pnames.count(raw_nm)) {
                        continue;
                    }
                    std::string ct = ctype_str(type_of(u));
                    if (auto it = user_types.find(raw_nm); it != user_types.end()) ct = it->second;
                    if (auto it = user_types.find(eff_nm); it != user_types.end()) ct = it->second;
                    live_in[eff_nm] = LocalMeta{raw_nm, ct, u.reg, 0, func.start_ea, false};
                }
            }
        }

        std::unordered_map<std::string, LocalMeta> stack_map;
        for (const auto &[raw_nm, raw_ct] : stack_decls) {
            std::string eff_nm = lookup_rename(raw_nm);
            if (pnames.count(eff_nm) || by_name.count(eff_nm) || live_in.count(eff_nm) || pnames.count(raw_nm)) {
                continue;
            }
            std::string ct = raw_ct;
            if (auto it = user_types.find(raw_nm); it != user_types.end()) ct = it->second;
            if (auto it = user_types.find(eff_nm); it != user_types.end()) ct = it->second;
            int64_t soff = 0;
            for (const auto &[off, sinfo] : sp_slots) {
                if (sinfo.name == raw_nm) { soff = frame::signed_offset(off); break; }
            }
            stack_map[eff_nm] = LocalMeta{raw_nm, ct, -1, soff, func.start_ea, true};
        }

        auto reg_lvars = [&](const std::unordered_map<std::string, LocalMeta> &mp) {
            for (const auto &[eff_nm, m] : mp) {
                all_var_types[eff_nm] = m.ctype;
                all_var_types[m.canonical] = m.ctype;
                int lidx = ensure_lvar_placeholder(eff_nm);
                lvar_t &lv = cfunc->lvars[static_cast<size_t>(lidx)];
                lv.canonical_name = m.canonical;
                lv.type_str = m.ctype;
                lv.defea = m.defea;
                lv.is_stk_var_flag = m.is_stk;
                lv.location = lvar_locator_t{m.is_stk, m.reg, m.stk_off, m.defea};
                lv.has_user_name = (eff_nm != m.canonical);
                lv.has_user_type = (user_types.count(m.canonical) > 0 || user_types.count(eff_nm) > 0);
            }
        };
        reg_lvars(live_in);
        reg_lvars(by_name);
        reg_lvars(stack_map);

        if (by_name.empty() && live_in.empty() && stack_map.empty()) return {};

        auto emit_section = [](const std::unordered_map<std::string, LocalMeta> &mp,
                               const std::string &suffix,
                               std::vector<std::string> &out) {
            if (mp.empty()) return;
            std::unordered_map<std::string, std::vector<std::string>> grp;
            std::vector<std::string> ctypes;
            for (const auto &[nm, meta] : mp) {
                auto &v = grp[meta.ctype];
                if (v.empty()) ctypes.push_back(meta.ctype);
                v.push_back(nm);
            }
            std::sort(ctypes.begin(), ctypes.end());
            for (const auto &ct : ctypes) {
                auto &names = grp[ct];
                std::sort(names.begin(), names.end());
                auto lines = format_decl_lines(ct, names, suffix);
                out.insert(out.end(), lines.begin(), lines.end());
            }
        };

        std::vector<std::string> out;
        emit_section(live_in, "   // live in", out);
        emit_section(by_name, "", out);
        emit_section(stack_map, "   // stack", out);
        return out;
    }
};

} // namespace

std::vector<int> recover_params(const Function &func,
                                const std::function<std::optional<int>(uint64_t)> &arity_of,
                                const std::function<bool(uint64_t)> &is_variadic_of) {
    int var_spills = 0;
    for (const auto &b : func.blocks) {
        for (const auto &i : b->insns) {
            if (i->op == Op::STOREQ && i->srcs.size() >= 3 &&
                i->srcs[2].is_var() && i->srcs[2].ver == 0 &&
                i->srcs[2].reg >= 4 && i->srcs[2].reg <= 79) {
                ++var_spills;
            }
        }
    }
    if (var_spills >= 16) {
        int hi = regs::ARG_FIRST;
        for (const auto &b : func.blocks) {
            for (const auto &insn : b->insns) {
                if (insn->op == Op::PHI || insn->op == Op::STOREQ || op_is_abi(insn->op)) continue;
                for (const auto &u : insn->srcs) {
                    if (u.is_var() && u.ver == 0 && u.reg >= regs::ARG_FIRST && u.reg <= regs::ARG_LAST) {
                        hi = std::max(hi, u.reg);
                    }
                }
            }
        }
        std::vector<int> out;
        for (int r = regs::ARG_FIRST; r <= hi; ++r) out.push_back(r);
        return out;
    }

    int hi = -1;
    auto real = real_uses(func);
    for (const auto &b : func.blocks) {
        for (const auto &insn : b->insns) {
            if (insn->op == Op::PHI) continue;
            if (op_is_abi(insn->op)) {
                if (!arity_of || (insn->op != Op::CALL && insn->op != Op::ICALL && insn->op != Op::TCALL)) {
                    continue;
                }
                if ((insn->op == Op::CALL || insn->op == Op::TCALL) && insn->has_aux) {
                    if (is_variadic_of && is_variadic_of(insn->aux_ea)) continue;
                }
                std::optional<int> n = ((insn->op == Op::CALL || insn->op == Op::TCALL) && insn->has_aux)
                                           ? arity_of(insn->aux_ea)
                                           : std::nullopt;
                if (!n.has_value() || *n <= 0) continue;
                auto args = call_arguments(*insn, *n);
                if (!args.has_value()) continue;
                for (const auto &u : *args) {
                    if (u.is_var() && u.ver == 0 && u.reg >= regs::ARG_FIRST && u.reg <= regs::ARG_LAST) {
                        hi = std::max(hi, u.reg);
                    }
                }
                continue;
            }
            for (const auto &u : insn->srcs) {
                if (!u.is_var() || u.ver != 0 || real.find(u.key()) == real.end()) continue;
                if (u.reg >= regs::ARG_FIRST && u.reg <= regs::ARG_LAST) {
                    hi = std::max(hi, u.reg);
                }
            }
        }
    }
    if (hi < 0) return {};
    if (hi > regs::ARG_FIRST + 7) hi = regs::ARG_FIRST + 7;
    std::vector<int> out;
    for (int r = regs::ARG_FIRST; r <= hi; ++r) out.push_back(r);
    return out;
}

cfuncptr_t generate(Function &func,
                    const std::vector<std::unique_ptr<structure::Stmt>> &stmts,
                    const structure::StructureInfo &info,
                    const CGenOptions &opts) {
    CGenEngine g(func, opts);

    std::string raw_name = func.name.empty() ? CGenEngine::default_sub_name(func.start_ea) : func.name;
    if (g.user_proto.has_value() && !g.user_proto->empty()) {
        auto parsed = abi::parse_proto(*g.user_proto, raw_name);
        if (parsed.has_value() && !parsed->name.empty() && parsed->name != "sub_unknown") {
            raw_name = parsed->name;
        }
    }
    std::string fn_name = g.lookup_rename(raw_name);
    auto [ret, params_str] = g.build_signature();

    std::vector<std::string> out;
    {
        char hbuf[256];
        std::snprintf(hbuf, sizeof(hbuf), "// %s  @ 0x%llX",
                      fn_name.c_str(), static_cast<unsigned long long>(func.start_ea));
        out.emplace_back(hbuf);
    }

    if (!func.scalar_stats.empty()) {
        auto get_sc = [&](const char *k) -> int {
            auto it = func.scalar_stats.find(k);
            return (it != func.scalar_stats.end()) ? it->second : 0;
        };
        char sbuf[128];
        std::snprintf(sbuf, sizeof(sbuf), "// scalarised: %d stores, %d loads, %d scalar ops",
                      get_sc("stores"), get_sc("loads") + get_sc("aligned_loads"), get_sc("scalars"));
        out.emplace_back(sbuf);
    }

    {
        std::string lline = "// " + std::to_string(info.loops) + " loops, " + std::to_string(info.gotos) + " gotos";
        if (!info.unreached.empty()) {
            lline += ", " + std::to_string(info.unreached.size()) + " block(s) not reached";
        }
        out.push_back(std::move(lline));
    }

    if (!g.type_stats.kinds.empty()) {
        std::vector<std::string> kkeys;
        for (const auto &[k, _] : g.type_stats.kinds) kkeys.push_back(k);
        std::sort(kkeys.begin(), kkeys.end());
        std::string tline = "// types: ";
        for (size_t i = 0; i < kkeys.size(); ++i) {
            if (i > 0) tline += ", ";
            tline += kkeys[i] + " " + std::to_string(g.type_stats.kinds.at(kkeys[i]));
        }
        if (g.type_stats.ambiguous > 0) {
            tline += "  (" + std::to_string(g.type_stats.ambiguous) + " read both signed and unsigned)";
        }
        if (g.type_stats.contradictions > 0) {
            tline += "  (" + std::to_string(g.type_stats.contradictions) + " contradictory -- suspect)";
        }
        out.push_back(std::move(tline));
    }

    if (g.type_stats.strings > 0) {
        out.push_back("// " + std::to_string(g.type_stats.strings) + " constant(s) resolved to string literals");
    }

    if (auto fr_desc = g.frame_info.describe(); fr_desc.has_value()) {
        out.push_back("// " + *fr_desc);
    }

    const size_t stack_note_at = out.size();
    if (!g.params.empty()) {
        std::string pline = "// parameters: ";
        for (size_t i = 0; i < g.params.size(); ++i) {
            if (i > 0) pline += "  ";
            int r = g.params[i];
            pline += g.param_name[r] + " = " + regs::reg_name(r);
        }
        out.push_back(std::move(pline));
    }

    int proto_lineno = static_cast<int>(out.size());
    std::string sep = (!ret.empty() && ret.back() == '*') ? "" : " ";
    std::string sig_line_txt = ret + sep + fn_name + "(" + params_str + ")";
    out.push_back(sig_line_txt);
    out.push_back("{");

    // Emit structured body & build ctree root block
    g.cfunc->body = g.cfunc->alloc_insn(cit_block, func.start_ea);
    std::vector<std::string> body_lines;
    g.emit_stmts(stmts, body_lines, 1, info, g.cfunc->body);

    // Emit function-level user comment above signature if func.start_ea comment wasn't attached to a body line
    if (auto fn_cmt = g.find_user_cmt(func.start_ea, {}); fn_cmt.has_value()) {
        std::istringstream ciss(*fn_cmt);
        std::string cln;
        while (std::getline(ciss, cln)) {
            if (!cln.empty() && cln.back() == '\r') cln.pop_back();
            out.insert(out.begin() + static_cast<std::ptrdiff_t>(proto_lineno), "// " + cln);
            ++proto_lineno;
        }
    }

    if (!g.stack_decls.empty() || g.stack_unresolved > 0) {
        std::string note = "// stack: " + std::to_string(g.stack_decls.size()) + " slot(s) named from the frame";
        if (g.stack_unresolved > 0) {
            note += "; " + std::to_string(g.stack_unresolved) +
                    " stack address(es) did not resolve to a slot and are assumed not to alias one";
        }
        out.insert(out.begin() + static_cast<std::ptrdiff_t>(stack_note_at), std::move(note));
        ++proto_lineno;
    }

    auto decls = g.build_declarations_and_lvars();
    if (!decls.empty()) {
        out.insert(out.end(), decls.begin(), decls.end());
        out.emplace_back("");
    }

    const int header_count = static_cast<int>(out.size());
    out.insert(out.end(), body_lines.begin(), body_lines.end());
    out.emplace_back("}");

    // Populate cfunc_t metadata & bidirectional EA maps
    cfunc_t &cf = *g.cfunc;
    cf.func_name = fn_name;
    cf.ret_type = ret;
    cf.signature_line = sig_line_txt;
    cf.hdrlines = header_count;
    cf.sig_line = proto_lineno;
    cf.pseudocode_lines = std::move(out);

    cf.line_eas.assign(static_cast<size_t>(header_count), std::nullopt);
    cf.line_eas.insert(cf.line_eas.end(), g.body_eas.begin(), g.body_eas.end());
    cf.line_eas.push_back(std::nullopt);

    for (const auto &[k, v] : g.body_line_to_eas) {
        cf.line_to_eas[header_count + k] = v;
    }
    for (const auto &[k, v] : g.body_line_consts) {
        cf.line_consts[header_count + k] = v;
    }
    cf.call_eas = std::move(g.call_eas);
    cf.sym_eas = std::move(g.sym_eas);
    cf.var_types = std::move(g.all_var_types);
    for (const auto &[pnm, pty] : g.sig_params) {
        cf.arg_names.push_back(pnm);
        cf.param_types[pnm] = pty;
    }

    for (const auto &[lineno, eas] : cf.line_to_eas) {
        for (uint64_t ea : eas) {
            cf.ea_to_line.emplace(ea, lineno);
        }
    }
    if (cf.ea_to_line.find(func.start_ea) == cf.ea_to_line.end()) {
        cf.ea_to_line[func.start_ea] = proto_lineno;
    }
    for (int hl = proto_lineno; hl < header_count; ++hl) {
        auto &vec = cf.line_to_eas[hl];
        if (std::find(vec.begin(), vec.end(), func.start_ea) == vec.end()) {
            vec.push_back(func.start_ea);
        }
        if (hl >= 0 && static_cast<size_t>(hl) < cf.line_eas.size() && !cf.line_eas[static_cast<size_t>(hl)].has_value()) {
            cf.line_eas[static_cast<size_t>(hl)] = func.start_ea;
        }
    }

    // Dense instruction completion across all basic blocks
    std::vector<const Block *> sorted_blocks;
    sorted_blocks.reserve(func.blocks.size());
    for (const auto &b : func.blocks) sorted_blocks.push_back(b.get());
    std::sort(sorted_blocks.begin(), sorted_blocks.end(),
              [](const Block *a, const Block *b) { return a->start_ea < b->start_ea; });

    for (const Block *b : sorted_blocks) {
        std::vector<std::pair<uint64_t, int>> b_lines;
        for (const auto &ins : b->insns) {
            auto it = cf.ea_to_line.find(ins->ea);
            if (it != cf.ea_to_line.end()) b_lines.push_back({ins->ea, it->second});
        }
        for (const auto &ins : b->insns) {
            if (cf.ea_to_line.find(ins->ea) != cf.ea_to_line.end()) continue;
            int chosen = proto_lineno;
            if (!b_lines.empty()) {
                uint64_t best_dist = UINT64_MAX;
                for (const auto &[ea, ln] : b_lines) {
                    uint64_t dist = (ea > ins->ea) ? (ea - ins->ea) : (ins->ea - ea);
                    if (dist < best_dist) { best_dist = dist; chosen = ln; }
                }
            } else if (auto bit = cf.ea_to_line.find(b->start_ea); bit != cf.ea_to_line.end()) {
                chosen = bit->second;
            }
            cf.ea_to_line[ins->ea] = chosen;
            auto &vec = cf.line_to_eas[chosen];
            if (std::find(vec.begin(), vec.end(), ins->ea) == vec.end()) vec.push_back(ins->ea);
        }
    }

    if (opts.db) {
        for (uint64_t item_ea : opts.db->get_func_items(func.start_ea)) {
            if (cf.ea_to_line.find(item_ea) != cf.ea_to_line.end()) continue;
            if (!cf.ea_to_line.empty()) {
                uint64_t best_dist = UINT64_MAX;
                int chosen = proto_lineno;
                for (const auto &[ea, ln] : cf.ea_to_line) {
                    uint64_t dist = (ea > item_ea) ? (ea - item_ea) : (item_ea - ea);
                    if (dist < best_dist) { best_dist = dist; chosen = ln; }
                }
                cf.ea_to_line[item_ea] = chosen;
                cf.line_to_eas[chosen].push_back(item_ea);
            }
        }
    }

    cf.recolorize();
    return g.cfunc;
}

} // namespace cgen
} // namespace spudec
