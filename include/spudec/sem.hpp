#pragma once

#include <cstdint>
#include <optional>
#include <vector>
#include "u128.hpp"
#include "ir.hpp"

namespace spudec {
namespace sem {

u128_t shufb(const u128_t &a, const u128_t &b, const u128_t &ctl);
u128_t genctl(uint32_t addr, EW ew);
u128_t fsm(const u128_t &v, EW ew);
u128_t gb(const u128_t &v, EW ew);

u128_t qrotby(const u128_t &v, uint32_t n);
u128_t qrotbi(const u128_t &v, uint32_t n);
u128_t qrotmby(const u128_t &v, uint32_t n);
u128_t qrotmbi(const u128_t &v, uint32_t n);
u128_t qshlby(const u128_t &v, uint32_t n);
u128_t qshlbi(const u128_t &v, uint32_t n);

// Evaluate `op` over known 128-bit constant operands; returns std::nullopt if unmodelled.
std::optional<u128_t> evaluate(Op op, EW ew, const u128_t *args, size_t nargs);

} // namespace sem
} // namespace spudec
