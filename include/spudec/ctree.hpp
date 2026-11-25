#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace spudec {

// Exact numeric parity with IDA 9.5 <hexrays.hpp> enum ctype_t!
enum ctype_t : int {
    cot_empty    = 0,
    cot_comma    = 1,   // x, y
    cot_asg      = 2,   // x = y
    cot_asgbor   = 3,   // x |= y
    cot_asgxor   = 4,   // x ^= y
    cot_asgband  = 5,   // x &= y
    cot_asgadd   = 6,   // x += y
    cot_asgsub   = 7,   // x -= y
    cot_asgmul   = 8,   // x *= y
    cot_asgsshr  = 9,   // x >>= y signed
    cot_asgushr  = 10,  // x >>= y unsigned
    cot_asgshl   = 11,  // x <<= y
    cot_asgsdiv  = 12,  // x /= y signed
    cot_asgudiv  = 13,  // x /= y unsigned
    cot_asgsmod  = 14,  // x %= y signed
    cot_asgumod  = 15,  // x %= y unsigned
    cot_tern     = 16,  // x ? y : z
    cot_lor      = 17,  // x || y
    cot_land     = 18,  // x && y
    cot_bor      = 19,  // x | y
    cot_xor      = 20,  // x ^ y
    cot_band     = 21,  // x & y
    cot_eq       = 22,  // x == y
    cot_ne       = 23,  // x != y
    cot_sge      = 24,  // x >= y signed
    cot_uge      = 25,  // x >= y unsigned
    cot_sle      = 26,  // x <= y signed
    cot_ule      = 27,  // x <= y unsigned
    cot_sgt      = 28,  // x >  y signed
    cot_ugt      = 29,  // x >  y unsigned
    cot_slt      = 30,  // x <  y signed
    cot_ult      = 31,  // x <  y unsigned
    cot_sshr     = 32,  // x >> y signed
    cot_ushr     = 33,  // x >> y unsigned
    cot_shl      = 34,  // x << y
    cot_add      = 35,  // x + y
    cot_sub      = 36,  // x - y
    cot_mul      = 37,  // x * y
    cot_sdiv     = 38,  // x / y signed
    cot_udiv     = 39,  // x / y unsigned
    cot_smod     = 40,  // x % y signed
    cot_umod     = 41,  // x % y unsigned
    cot_fadd     = 42,  // x + y fp
    cot_fsub     = 43,  // x - y fp
    cot_fmul     = 44,  // x * y fp
    cot_fdiv     = 45,  // x / y fp
    cot_fneg     = 46,  // -x fp
    cot_neg      = 47,  // -x
    cot_cast     = 48,  // (type)x
    cot_lnot     = 49,  // !x
    cot_bnot     = 50,  // ~x
    cot_ptr      = 51,  // *x
    cot_ref      = 52,  // &x
    cot_postinc  = 53,  // x++
    cot_postdec  = 54,  // x--
    cot_preinc   = 55,  // ++x
    cot_predec   = 56,  // --x
    cot_call     = 57,  // x(...)
    cot_idx      = 58,  // x[y]
    cot_memref   = 59,  // x.m
    cot_memptr   = 60,  // x->m
    cot_num      = 61,  // n
    cot_fnum     = 62,  // fpc
    cot_str      = 63,  // string literal
    cot_obj      = 64,  // obj_ea
    cot_var      = 65,  // v (lvar ref)
    cot_insn     = 66,  // embedded insn
    cot_sizeof   = 67,  // sizeof(x)
    cot_helper   = 68,  // helper / intrinsic identifier
    cot_type     = 69,  // type node
    cot_last     = cot_type,

    cit_empty    = 70,
    cit_block    = 71,  // { ... }
    cit_expr     = 72,  // expr;
    cit_if       = 73,  // if (expr) iif [else ielse]
    cit_for      = 74,  // for (;;) body
    cit_while    = 75,  // while (expr) body
    cit_do       = 76,  // do body while (expr);
    cit_switch   = 77,  // switch
    cit_break    = 78,  // break;
    cit_continue = 79,  // continue;
    cit_return   = 80,  // return [expr];
    cit_goto     = 81,  // goto label;
    cit_asm      = 82,  // asm
    cit_try      = 83,
    cit_throw    = 84,
    cit_end      = 85,
};

const char *ctype_name(ctype_t op);
ctype_t negated_relation(ctype_t op);

constexpr inline bool ctype_is_expr(ctype_t op) { return op >= cot_empty && op <= cot_last; }
constexpr inline bool ctype_is_insn(ctype_t op) { return op >= cit_empty && op < cit_end; }
constexpr inline bool ctype_uses_x(ctype_t op)  { return (op >= cot_comma && op <= cot_memptr) || op == cot_sizeof; }
constexpr inline bool ctype_uses_y(ctype_t op)  { return (op >= cot_comma && op <= cot_fdiv) || op == cot_idx; }
constexpr inline bool ctype_uses_z(ctype_t op)  { return op == cot_tern; }

// Hex-Rays visitor flags (exact bit parity with <hexrays.hpp>).
enum CtreeVisitorFlags : int {
    SPU_CV_FAST    = 0x0000,
    SPU_CV_PRUNE   = 0x0001,
    SPU_CV_PARENTS = 0x0002,
    SPU_CV_POST    = 0x0004,
    SPU_CV_RESTART = 0x0008,
    SPU_CV_INSNS   = 0x0010,
};

struct lvar_locator_t {
    bool is_stk = false;
    int reg = -1;
    int64_t stk_off = 0;
    uint64_t defea = UINT64_MAX;

    std::string to_key() const;
};

struct lvar_t {
    int index = 0;
    std::string name;
    std::string canonical_name;
    std::string type_str = "qword";
    std::string cmt;
    int width = 16;
    uint64_t defea = UINT64_MAX;
    lvar_locator_t location;
    bool is_arg_var = false;
    bool is_thisarg = false;
    bool is_result_var = false;
    bool is_stk_var_flag = false;
    bool has_user_name = false;
    bool has_user_type = false;

    bool is_stk_var() const { return is_stk_var_flag; }
    bool is_reg_var() const { return !is_stk_var_flag; }
};

struct var_ref_t {
    int idx = -1; // index into cfunc_t::lvars
};

struct cnumber_t {
    uint64_t _value = 0;
    int bits = 32;
    int opnum = 0;
    uint64_t ea = UINT64_MAX;
    std::string repr;         // formatted literal text
    std::string default_form = "hex";
    std::string applied_form;
    bool is_addr = false;
    uint64_t addr_val = 0;

    uint64_t value() const { return _value; }
};

struct cexpr_t;
struct cinsn_t;

struct citem_t {
    uint32_t obj_id = 0;     // index in cfunc_t::treeitems
    ctype_t op = cot_empty;
    uint64_t ea = UINT64_MAX;
    int label_num = -1;      // >= 0 if labelled block target (`loc_%X`)
    std::string label_name;
    bool mutated = false;    // set true when script modifies node fields

    virtual ~citem_t() = default;
    bool is_expr() const { return ctype_is_expr(op); }
    cexpr_t *cexpr();
    const cexpr_t *cexpr() const;
    cinsn_t *cinsn();
    const cinsn_t *cinsn() const;
};

struct carg_t;

struct cexpr_t : public citem_t {
    std::string type_str;    // C type representation (e.g. "u32", "char *", "qword")
    int ptrsize = 0;         // access size for cot_ptr / cot_memptr
    cexpr_t *x = nullptr;
    cexpr_t *y = nullptr;
    cexpr_t *z = nullptr;
    std::vector<cexpr_t *> a; // call arguments for cot_call
    var_ref_t v;             // cot_var
    cnumber_t n;             // cot_num
    uint64_t obj_ea = UINT64_MAX; // cot_obj / direct cot_call target
    std::string string;      // cot_str or member field name (cot_memref / cot_memptr)
    std::string helper;      // cot_helper / intrinsic / function name
    std::string text_cache;  // exact initial text emitted by CGen (used unless mutated)

    uint64_t numval() const { return n._value; }
    void mark_mutated() { mutated = true; text_cache.clear(); }
    std::string print1(const std::vector<lvar_t> *lvars = nullptr) const;
};

struct cblock_t {
    std::vector<cinsn_t *> statements;
    size_t size() const { return statements.size(); }
    bool empty() const { return statements.empty(); }
    auto begin() { return statements.begin(); }
    auto end() { return statements.end(); }
    auto begin() const { return statements.begin(); }
    auto end() const { return statements.end(); }
    void push_back(cinsn_t *s) { statements.push_back(s); }
};

struct cif_t {
    cexpr_t *expr = nullptr;
    cinsn_t *ithen = nullptr;
    cinsn_t *ielse = nullptr;
};

struct cloop_t {
    cexpr_t *expr = nullptr; // condition for while / do-while (nullptr for endless for(;;))
    cinsn_t *body = nullptr;
};

struct creturn_t {
    cexpr_t *expr = nullptr;
};

struct cgoto_t {
    int label_num = -1;
    std::string target_name;
};

struct cinsn_t : public citem_t {
    cblock_t cblock;
    cexpr_t *cexpr_node = nullptr; // cit_expr
    cif_t cif;                     // cit_if
    cloop_t cloop;                 // cit_while / cit_do / cit_for
    creturn_t creturn;             // cit_return
    cgoto_t cgoto;                 // cit_goto
    std::string user_cmt;
    std::string text_cache;        // exact initial statement line (without indentation)

    void mark_mutated() { mutated = true; text_cache.clear(); }
};

class ctree_visitor_t {
public:
    int cv_flags = SPU_CV_FAST;
    std::vector<citem_t *> parents;

    explicit ctree_visitor_t(int flags = SPU_CV_FAST) : cv_flags(flags) {}
    virtual ~ctree_visitor_t() = default;

    bool maintain_parents() const { return (cv_flags & SPU_CV_PARENTS) != 0; }
    bool must_prune()       const { return (cv_flags & SPU_CV_PRUNE) != 0; }
    bool must_restart()     const { return (cv_flags & SPU_CV_RESTART) != 0; }
    bool is_postorder()     const { return (cv_flags & SPU_CV_POST) != 0; }
    bool only_insns()       const { return (cv_flags & SPU_CV_INSNS) != 0; }

    void prune_now()   { cv_flags |= SPU_CV_PRUNE; }
    void clr_prune()   { cv_flags &= ~SPU_CV_PRUNE; }
    void set_restart() { cv_flags |= SPU_CV_RESTART; }
    void clr_restart() { cv_flags &= ~SPU_CV_RESTART; }

    citem_t *parent_item() { return parents.empty() ? nullptr : parents.back(); }
    cexpr_t *parent_expr() {
        citem_t *p = parent_item();
        return (p && p->is_expr()) ? p->cexpr() : nullptr;
    }
    cinsn_t *parent_insn() {
        citem_t *p = parent_item();
        return (p && !p->is_expr()) ? p->cinsn() : nullptr;
    }

    virtual int visit_insn(cinsn_t *)  { return 0; }
    virtual int visit_expr(cexpr_t *)  { return 0; }
    virtual int leave_insn(cinsn_t *)  { return 0; }
    virtual int leave_expr(cexpr_t *)  { return 0; }

    int apply_to(citem_t *item, citem_t *parent = nullptr);
    int apply_to_exprs(citem_t *item, citem_t *parent = nullptr);

private:
    int walk_item(citem_t *item, bool exprs_only);
};

// Rendered constant span on a pseudocode line (for interactive H/R/_/~/M/A/O/B actions).
struct LineConstSpan {
    int idx = 0;
    uint64_t ea = 0;
    uint64_t val = 0;
    uint64_t val_hi = 0; // upper 64 bits when bits == 128
    int bits = 32;
    std::string text;
    std::string default_form = "hex";
    std::string form = "hex";
    bool applied = false;
    bool is_addr = false;
    uint64_t addr_val = 0;
    int col_start = 0;
    int col_end = 0;
    uint32_t citem_id = 0;
};

struct cfunc_t {
    uint64_t entry_ea = 0;
    std::string func_name;
    std::string ret_type = "void";
    std::string signature_line;
    int hdrlines = 0;
    int sig_line = 0;
    bool hide_casts = false;
    int maturity = 7; // CMAT_FINAL

    // Arena owning all citem_t nodes; node->obj_id == index in treeitems!
    std::vector<std::unique_ptr<citem_t>> treeitems;
    cinsn_t *body = nullptr; // root cit_block
    std::vector<lvar_t> lvars;
    std::unordered_map<uint64_t, std::vector<cinsn_t *>> eamap;

    // Plain & colored pseudocode lines + rich bidirectional navigation maps
    std::vector<std::string> pseudocode_lines; // plain C lines
    std::vector<std::string> sv;               // IDA SCOLOR_* + COLOR_ADDR tagged lines
    std::vector<std::optional<uint64_t>> line_eas;
    std::unordered_map<int, std::vector<uint64_t>> line_to_eas;
    std::unordered_map<uint64_t, int> ea_to_line;
    std::unordered_map<int, std::vector<LineConstSpan>> line_consts;
    std::unordered_map<std::string, uint64_t> call_eas;
    std::unordered_map<std::string, uint64_t> sym_eas;
    std::unordered_map<std::string, std::string> var_types;
    std::vector<std::string> arg_names;
    std::unordered_map<std::string, std::string> param_types;
    std::vector<int> argidx;

    cexpr_t *alloc_expr(ctype_t op, uint64_t ea = UINT64_MAX);
    cinsn_t *alloc_insn(ctype_t op, uint64_t ea = UINT64_MAX);
    citem_t *get_item(uint32_t obj_id) const {
        return (obj_id < treeitems.size()) ? treeitems[obj_id].get() : nullptr;
    }

    // Re-colorize `sv` with an optional occurrence highlight token (instant < 0.2 ms!).
    void recolorize(const std::string &highlight_ident = "");

    // Re-synthesize body lines from `body` AST if a script mutated any `citem_t` in `treeitems`.
    bool has_tree_mutations() const;
    void refresh_func_ctext();
    std::string print_func() const;
};

using cfuncptr_t = std::shared_ptr<cfunc_t>;

} // namespace spudec
