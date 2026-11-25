#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace spudec {
namespace regs {

constexpr int NGPR = 128;
constexpr int R_MEM = 128;  // local-store memory ordering chain
constexpr int R_CH  = 129;  // channel ordering chain (rdch/wrch/rchcnt)
constexpr int R_SPR = 130;  // special-purpose register / FPSCR chain
constexpr int NREG  = 131;

constexpr int LR  = 0;      // $0 link register
constexpr int SP  = 1;      // $1 stack pointer (16-byte aligned)
constexpr int ENV = 2;      // $2 environment pointer / scratch

// SPU ABI v1.9 register ranges
constexpr int ARG_FIRST          = 3;
constexpr int ARG_LAST           = 74;
constexpr int VOLATILE_LAST      = 79;
constexpr int CALLEE_SAVED_FIRST = 80;

constexpr inline bool is_pseudo(int r) {
    return r == R_MEM || r == R_CH || r == R_SPR;
}

constexpr inline bool is_temp(int r) {
    return r >= NREG;
}

constexpr inline bool is_gpr(int r) {
    return r >= 0 && r < NGPR;
}

constexpr inline bool is_callee_saved(int r) {
    return r >= CALLEE_SAVED_FIRST && r < NGPR;
}

constexpr inline bool is_volatile(int r) {
    return r == LR || r == ENV || (r >= ARG_FIRST && r <= VOLATILE_LAST);
}

inline std::string reg_name(int r) {
    if (r == LR) return "lr";
    if (r == SP) return "sp";
    if (r >= 2 && r < NGPR) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "r%d", r);
        return buf;
    }
    if (r == R_MEM) return "mem";
    if (r == R_CH)  return "ch";
    if (r == R_SPR) return "spr";
    if (r >= NREG) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "t%d", r - NREG);
        return buf;
    }
    char buf[24];
    std::snprintf(buf, sizeof(buf), "?reg%d", r);
    return buf;
}

inline std::vector<int> arg_regs(int n) {
    std::vector<int> out;
    const int hi = (ARG_FIRST + n <= ARG_LAST + 1) ? (ARG_FIRST + n) : (ARG_LAST + 1);
    for (int r = ARG_FIRST; r < hi; ++r) out.push_back(r);
    return out;
}

} // namespace regs
} // namespace spudec
