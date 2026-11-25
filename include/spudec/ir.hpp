#pragma once

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "u128.hpp"
#include "regs.hpp"

namespace spudec {

// Compact 64-bit SSA variable key: upper 32 bits = reg, lower 32 bits = ver (uint32_t(ver)).
using VarKey = uint64_t;

constexpr inline VarKey make_var_key(int reg, int ver) {
    return (static_cast<uint64_t>(static_cast<uint32_t>(reg)) << 32) |
           static_cast<uint64_t>(static_cast<uint32_t>(ver));
}
constexpr inline int key_reg(VarKey k) { return static_cast<int>(static_cast<int32_t>(k >> 32)); }
constexpr inline int key_ver(VarKey k) { return static_cast<int>(static_cast<int32_t>(k & 0xFFFFFFFFULL)); }

// Dense 64-bit word bitset for SSA dominance frontiers, liveness, and interference.
class BitVec {
public:
    BitVec() = default;
    explicit BitVec(size_t nbits) : words_((nbits + 63) / 64, 0) {}

    void resize(size_t nbits) { words_.resize((nbits + 63) / 64, 0); }
    void clear_all() { std::fill(words_.begin(), words_.end(), 0ULL); }

    void set(size_t bit) {
        size_t w = bit >> 6;
        if (w >= words_.size()) words_.resize(w + 1, 0ULL);
        words_[w] |= (1ULL << (bit & 63));
    }

    void reset(size_t bit) {
        size_t w = bit >> 6;
        if (w < words_.size()) words_[w] &= ~(1ULL << (bit & 63));
    }

    bool test(size_t bit) const {
        size_t w = bit >> 6;
        return w < words_.size() && ((words_[w] >> (bit & 63)) & 1ULL) != 0;
    }

    bool empty() const {
        for (uint64_t w : words_) if (w != 0) return false;
        return true;
    }

    bool or_with(const BitVec &o) {
        if (o.words_.size() > words_.size()) words_.resize(o.words_.size(), 0ULL);
        bool changed = false;
        for (size_t i = 0; i < o.words_.size(); ++i) {
            uint64_t nw = words_[i] | o.words_[i];
            if (nw != words_[i]) { words_[i] = nw; changed = true; }
        }
        return changed;
    }

    void and_not(const BitVec &o) {
        size_t n = std::min(words_.size(), o.words_.size());
        for (size_t i = 0; i < n; ++i) words_[i] &= ~o.words_[i];
    }

    bool operator==(const BitVec &o) const {
        size_t n = std::min(words_.size(), o.words_.size());
        for (size_t i = 0; i < n; ++i) if (words_[i] != o.words_[i]) return false;
        for (size_t i = n; i < words_.size(); ++i) if (words_[i] != 0) return false;
        for (size_t i = n; i < o.words_.size(); ++i) if (o.words_[i] != 0) return false;
        return true;
    }
    bool operator!=(const BitVec &o) const { return !(*this == o); }

    template <typename Fn>
    void for_each_set(Fn &&fn) const {
        for (size_t wi = 0; wi < words_.size(); ++wi) {
            uint64_t w = words_[wi];
            while (w != 0) {
#if defined(_MSC_VER)
                unsigned long bit = 0;
                _BitScanForward64(&bit, w);
                fn((wi << 6) + static_cast<size_t>(bit));
#else
                fn((wi << 6) + static_cast<size_t>(__builtin_ctzll(w)));
#endif
                w &= (w - 1);
            }
        }
    }

private:
    std::vector<uint64_t> words_;
};

enum class Op : uint8_t {
    // Pseudo
    PHI = 0,
    MOV = 1,
    CONST = 2,
    INTRINSIC = 3,
    UNDEF = 4,

    // Integer arithmetic
    ADD = 10,
    SUB = 11,
    MUL = 12,
    CG = 13,
    BG = 14,
    ADDX = 15,
    SUBX = 16,
    CGX = 17,
    BGX = 18,
    ABSDB = 19,
    AVGB = 20,
    SUMB = 21,

    // Multiply family
    MPY = 30,
    MPYU = 31,
    MPYH = 32,
    MPYS = 33,
    MPYHH = 34,
    MPYHHU = 35,
    MPYHHA = 36,
    MPYHHAU = 37,
    MPYA = 38,

    // Bitwise
    AND = 40,
    OR = 41,
    XOR = 42,
    NAND = 43,
    NOR = 44,
    ANDC = 45,
    ORC = 46,
    EQV = 47,
    NOT = 48,

    // Element shifts / rotates
    SHL = 50,
    SHR = 51,
    SAR = 52,
    ROL = 53,
    ROTM = 54,
    ROTMA = 55,

    // Quadword shifts / rotates
    QROTBY = 60,
    QROTBI = 61,
    QROTMBY = 62,
    QROTMBI = 63,
    QSHLBY = 64,
    QSHLBI = 65,

    // Permute / select
    SHUFB = 70,
    SELB = 71,
    GENCTL = 72,
    GB = 73,
    FSM = 74,

    // Misc unary
    CLZ = 80,
    CNTB = 81,
    ORX = 82,
    EXTS = 83,

    // Compares
    CMPEQ = 90,
    CMPGT = 91,
    CMPGTU = 92,

    // Floating point
    FADD = 100,
    FSUB = 101,
    FMUL = 102,
    FMA = 103,
    FMS = 104,
    FNMS = 105,
    FNMA = 106,
    FCMPEQ = 107,
    FCMPGT = 108,
    FCMPMEQ = 109,
    FCMPMGT = 110,
    FI = 111,
    FREST = 112,
    FRSQEST = 113,
    FESD = 114,
    FRDS = 115,
    CSFLT = 116,
    CUFLT = 117,
    CFLTS = 118,
    CFLTU = 119,
    DFTSV = 120,

    // Memory
    LOADQ = 130,
    STOREQ = 131,
    LOAD = 132,
    STORE = 133,
    LOADU = 134,

    // Control flow
    JMP = 140,
    CJMP = 141,
    CALL = 142,
    ICALL = 143,
    IJMP = 144,
    RET = 145,
    CIJMP = 146,
    TCALL = 147,

    // Side-effecting / system
    RDCH = 150,
    WRCH = 151,
    RCHCNT = 152,
    MFSPR = 153,
    MTSPR = 154,
    STOP = 155,
    SYNC = 156,
    NOP = 157,
    HALT = 158,
};

enum class CondKind : uint8_t {
    Z = 0,
    NZ = 1,
    HZ = 2,
    HNZ = 3,
};

constexpr inline CondKind flip_cond(CondKind k) {
    switch (k) {
        case CondKind::Z:   return CondKind::NZ;
        case CondKind::NZ:  return CondKind::Z;
        case CondKind::HZ:  return CondKind::HNZ;
        case CondKind::HNZ: return CondKind::HZ;
    }
    return CondKind::NZ;
}

constexpr inline const char *cond_kind_str(CondKind k) {
    switch (k) {
        case CondKind::Z:   return "z";
        case CondKind::NZ:  return "nz";
        case CondKind::HZ:  return "hz";
        case CondKind::HNZ: return "hnz";
    }
    return "z";
}

bool op_is_terminator(Op op);
bool op_has_side_effects(Op op);
bool op_is_mem_read(Op op);
bool op_is_mem_write(Op op);
bool op_is_abi(Op op, int *out_leading_real = nullptr);
bool op_ew_significant(Op op);
const char *op_name(Op op);
const char *op_infix(Op op);

struct Insn;

struct Operand {
    bool is_const = false;
    EW ew = EW::None;       // optional element-width hint for constants
    int reg = -1;
    int ver = -1;
    u128_t val{};
    Insn *def_insn = nullptr;

    static Operand make_var(int r, int v = -1, Insn *def = nullptr) {
        Operand o;
        o.is_const = false;
        o.reg = r;
        o.ver = v;
        o.def_insn = def;
        return o;
    }

    static Operand make_const(const u128_t &c, EW cew = EW::None) {
        Operand o;
        o.is_const = true;
        o.val = c;
        o.ew = cew;
        return o;
    }

    constexpr bool is_var() const { return !is_const; }
    constexpr VarKey key() const { return make_var_key(reg, ver); }

    std::string fmt_const(EW ctx_ew = EW::None) const;
    std::string addr_str() const;
    std::string scalar_str() const;
    std::string str() const;
};

struct Insn {
    uint32_t uid = 0;       // unique instruction ID within Function
    Op op = Op::NOP;
    EW ew = EW::W;
    bool has_dst = false;
    bool scalar = false;
    bool has_aux = false;
    CondKind cond_kind = CondKind::Z;
    int dst_reg = -1;
    int dst_ver = -1;
    int block_id = -1;
    uint64_t ea = 0;
    uint64_t aux_ea = 0;
    int64_t aux_int = 0;
    std::string aux_str;
    std::string comment;
    std::vector<Operand> srcs;
    std::vector<int> phi_preds; // block IDs recorded when PHI was inserted

    bool is_terminator() const { return op_is_terminator(op); }
    bool defines() const { return has_dst; }
    VarKey dst_key() const { return make_var_key(dst_reg, dst_ver); }
    Operand dst_as_var() const { return Operand::make_var(dst_reg, dst_ver, const_cast<Insn *>(this)); }

    std::string to_string() const;
};

struct Block {
    int id = 0;
    uint64_t start_ea = 0;
    uint64_t end_ea = 0;
    std::vector<std::unique_ptr<Insn>> insns;
    std::vector<int> preds;
    std::vector<int> succs;

    int idom = -1;
    std::vector<int> domfront;
    std::vector<int> dom_children;

    Insn *add(std::unique_ptr<Insn> ins);
    Insn *terminator() const {
        if (!insns.empty() && insns.back()->is_terminator()) return insns.back().get();
        return nullptr;
    }
};

struct Function {
    uint64_t start_ea = 0;
    std::string name;
    std::vector<std::unique_ptr<Block>> blocks;
    int entry_id = -1;
    bool ssa = false;
    uint32_t next_insn_uid = 1;
    int clobbers = 0;
    int phi_copies = 0;
    int scal_tmp = 0;

    std::unordered_map<std::string, int> unhandled;
    std::vector<std::pair<uint64_t, uint64_t>> unreachable;
    std::vector<std::string> problems;
    std::unordered_map<std::string, int> stats;
    std::unordered_map<std::string, int> scalar_stats;
    std::unordered_set<VarKey> store_idiom_roots;
    std::unordered_map<VarKey, uint16_t> demand;

    Function() = default;
    Function(uint64_t ea, std::string nm = "") : start_ea(ea), name(std::move(nm)) {}

    Block *new_block(uint64_t s_ea, uint64_t e_ea);
    Block *entry() { return (entry_id >= 0 && entry_id < static_cast<int>(blocks.size())) ? blocks[entry_id].get() : nullptr; }
    const Block *entry() const { return (entry_id >= 0 && entry_id < static_cast<int>(blocks.size())) ? blocks[entry_id].get() : nullptr; }

    std::unique_ptr<Insn> make_insn(Op op, EW ew = EW::W, uint64_t ea = 0);
    std::string dump() const;
};

} // namespace spudec
