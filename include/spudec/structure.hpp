#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include "ir.hpp"

namespace spudec {
namespace structure {

constexpr int MAX_DEPTH     = 200;
constexpr int DUP_MAX_INSNS = 16;
constexpr int DUP_PER_BLOCK = 3;
constexpr int DUP_BUDGET    = 120;

struct Cond {
    Operand value;
    CondKind kind = CondKind::Z;
    bool neg = false;

    Cond() = default;
    Cond(Operand v, CondKind k, bool n = false) : value(std::move(v)), kind(k), neg(n) {}

    Cond negate() const { return Cond(value, kind, !neg); }
    CondKind effective() const { return neg ? flip_cond(kind) : kind; }
    std::string to_string() const;
};

Cond cond_of(const Insn &insn);

enum class StmtKind : uint8_t {
    Basic = 0,
    If = 1,
    Loop = 2,
    Break = 3,
    Continue = 4,
    Goto = 5,
    Label = 6,
    Return = 7,
    Tail = 8,
};

enum class LoopKind : uint8_t {
    Endless = 0,
    While = 1,
    DoWhile = 2,
};

struct Stmt {
    StmtKind kind = StmtKind::Basic;
    int block_id = -1;                  // Basic, Label, Goto (target block_id), Loop (header block_id)
    uint64_t ea = 0;
    bool has_ea = false;
    bool has_cond = false;
    Cond cond;
    LoopKind loop_kind = LoopKind::Endless;
    Insn *insn = nullptr;               // Return, Tail
    std::vector<Insn *> insns;          // Basic
    std::vector<std::unique_ptr<Stmt>> then_body;
    std::vector<std::unique_ptr<Stmt>> els_body;
    std::vector<std::unique_ptr<Stmt>> body; // Loop

    static std::unique_ptr<Stmt> make_basic(int blk_id, std::vector<Insn *> list);
    static std::unique_ptr<Stmt> make_if(Cond c, std::vector<std::unique_ptr<Stmt>> th,
                                         std::vector<std::unique_ptr<Stmt>> el, uint64_t branch_ea);
    static std::unique_ptr<Stmt> make_loop(std::vector<std::unique_ptr<Stmt>> bd, int header_id,
                                           LoopKind lk = LoopKind::Endless, const Cond *c = nullptr);
    static std::unique_ptr<Stmt> make_break();
    static std::unique_ptr<Stmt> make_continue();
    static std::unique_ptr<Stmt> make_goto(int target_blk_id);
    static std::unique_ptr<Stmt> make_label(int blk_id);
    static std::unique_ptr<Stmt> make_return(Insn *ret_insn);
    static std::unique_ptr<Stmt> make_tail(Insn *tail_insn);
};

struct LoopInfo {
    int header_id = -1;
    std::vector<int> latches;
    std::unordered_set<int> body;
    int follow_id = -1;
    LoopKind kind = LoopKind::Endless;
};

struct StructureInfo {
    std::unordered_set<int> labels;
    int gotos = 0;
    std::unordered_map<std::string, int> goto_why;
    int duplicated = 0;
    int loops = 0;
    std::vector<int> unreached; // block IDs
};

std::unordered_map<int, LoopInfo> find_loops(const Function &func, const std::unordered_map<int, int> &rpo_index);
std::pair<std::vector<std::unique_ptr<Stmt>>, StructureInfo> structure(Function &func);

} // namespace structure
} // namespace spudec
