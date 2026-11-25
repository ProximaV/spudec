#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <unordered_map>
#include "ir.hpp"

namespace spudec {
namespace lanes {

constexpr uint16_t ALL  = 0xFFFFu; // every byte
constexpr uint16_t NONE = 0x0000u;
constexpr uint16_t W0   = 0x000Fu; // preferred slot: bytes 0..3
constexpr uint16_t H0   = 0x000Cu; // bytes 2..3 (brhz/brhnz)
constexpr uint16_t B0   = 0x0008u; // byte 3 (scalar char in slot 0)

constexpr inline uint16_t slot_low_mask(EW ew) {
    switch (ew) {
        case EW::B: return 0x0008u;
        case EW::H: return 0x000Cu;
        case EW::W: return 0x000Fu;
        case EW::D: return 0x00FFu;
        default:    return ALL;
    }
}

constexpr inline uint16_t lead_mask(EW ew) {
    switch (ew) {
        case EW::B: return 0x0001u;
        case EW::H: return 0x0003u;
        case EW::W: return 0x000Fu;
        case EW::D: return 0x00FFu;
        default:    return ALL;
    }
}

uint16_t expand_mask(uint16_t mask, EW ew);
uint16_t rotl_mask(uint16_t mask, uint32_t n);

using CalleeDemandFn = std::function<std::optional<std::unordered_map<int, uint16_t>>(uint64_t callee_ea)>;

std::unordered_map<VarKey, uint16_t> compute_demand(const Function &func, const CalleeDemandFn &callee = nullptr);

constexpr inline bool is_scalar(uint16_t mask) {
    return mask != NONE && (mask & ~W0) == 0;
}

constexpr inline bool fits_lead(uint16_t mask, EW ew) {
    return mask != NONE && (mask & ~lead_mask(ew)) == 0;
}

constexpr inline bool fits_slot_low(uint16_t mask, EW ew) {
    return mask != NONE && (mask & ~slot_low_mask(ew)) == 0;
}

// Narrowest element width whose LEAD (falling back to SLOT_LOW) contains `mask`, or EW::None.
EW narrowest_lead(uint16_t mask);
// Narrowest element width whose SLOT_LOW contains `mask`, or EW::None.
EW narrowest_slot_low(uint16_t mask);

} // namespace lanes
} // namespace spudec
