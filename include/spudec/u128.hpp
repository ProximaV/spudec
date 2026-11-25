#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <array>

namespace spudec {

// Element width in bytes (matches SPU preferred/vector element widths)
enum class EW : uint8_t {
    None = 0,
    B = 1,
    H = 2,
    W = 4,
    D = 8,
    Q = 16,
};

constexpr inline int ew_bytes(EW ew) { return static_cast<int>(ew); }
constexpr inline int ew_bits(EW ew)  { return static_cast<int>(ew) * 8; }
constexpr inline int ew_count(EW ew) { return ew == EW::None ? 0 : (16 / static_cast<int>(ew)); }

constexpr inline const char *ew_suffix(EW ew) {
    switch (ew) {
        case EW::B: return "b";
        case EW::H: return "h";
        case EW::W: return "w";
        case EW::D: return "d";
        case EW::Q: return "q";
        default:    return "?";
    }
}

inline int64_t sext64(uint64_t v, int bits) {
    if (bits >= 64) return static_cast<int64_t>(v);
    const uint64_t m = 1ULL << (bits - 1);
    const uint64_t mask = (1ULL << bits) - 1ULL;
    v &= mask;
    return static_cast<int64_t>((v ^ m) - m);
}

// 128-bit big-endian SPU register value.
// Byte 0 is the most significant byte (bits 63..56 of `hi`).
// Word 0 (bytes 0..3, bits 63..32 of `hi`) is the SPU preferred slot.
struct alignas(16) u128_t {
    uint64_t hi = 0;
    uint64_t lo = 0;

    constexpr u128_t() = default;
    constexpr u128_t(uint64_t hi_, uint64_t lo_) : hi(hi_), lo(lo_) {}

    static constexpr u128_t zero() { return u128_t(0, 0); }
    static constexpr u128_t all_ones() { return u128_t(~uint64_t(0), ~uint64_t(0)); }

    static constexpr u128_t from_word0(uint32_t w0) {
        return u128_t(static_cast<uint64_t>(w0) << 32, 0);
    }

    static constexpr u128_t from_u64_low(uint64_t v) {
        return u128_t(0, v);
    }

    static u128_t from_bytes(const uint8_t b[16]) {
        uint64_t h = 0, l = 0;
        for (int i = 0; i < 8; ++i) h = (h << 8) | b[i];
        for (int i = 8; i < 16; ++i) l = (l << 8) | b[i];
        return u128_t(h, l);
    }

    void to_bytes(uint8_t out[16]) const {
        for (int i = 0; i < 8; ++i) out[i] = static_cast<uint8_t>((hi >> (56 - 8 * i)) & 0xFF);
        for (int i = 0; i < 8; ++i) out[8 + i] = static_cast<uint8_t>((lo >> (56 - 8 * i)) & 0xFF);
    }

    static u128_t repl(uint64_t val, EW ew) {
        switch (ew) {
            case EW::B: {
                uint64_t b = val & 0xFFULL;
                uint64_t rep = b * 0x0101010101010101ULL;
                return u128_t(rep, rep);
            }
            case EW::H: {
                uint64_t h = val & 0xFFFFULL;
                uint64_t rep = h | (h << 16);
                rep |= (rep << 32);
                return u128_t(rep, rep);
            }
            case EW::W: {
                uint64_t w = val & 0xFFFFFFFFULL;
                uint64_t rep = w | (w << 32);
                return u128_t(rep, rep);
            }
            case EW::D:
                return u128_t(val, val);
            default:
                return u128_t(0, val);
        }
    }

    static u128_t fsmbi(uint16_t imm16) {
        uint8_t b[16];
        for (int i = 0; i < 16; ++i) {
            b[i] = ((imm16 >> (15 - i)) & 1) ? 0xFF : 0x00;
        }
        return from_bytes(b);
    }

    constexpr bool is_zero() const { return hi == 0 && lo == 0; }
    constexpr bool is_all_ones() const { return hi == ~uint64_t(0) && lo == ~uint64_t(0); }
    constexpr bool low96_zero() const { return (hi & 0xFFFFFFFFULL) == 0 && lo == 0; }

    constexpr uint32_t word0() const { return static_cast<uint32_t>(hi >> 32); }
    constexpr uint32_t low_u32() const { return static_cast<uint32_t>(lo & 0xFFFFFFFFULL); }

    uint8_t byte_lane(int idx) const {
        if (idx < 8) return static_cast<uint8_t>((hi >> (56 - 8 * idx)) & 0xFF);
        return static_cast<uint8_t>((lo >> (56 - 8 * (idx - 8))) & 0xFF);
    }

    uint64_t get_lane(EW ew, int idx) const {
        switch (ew) {
            case EW::B:
                return byte_lane(idx);
            case EW::H:
                if (idx < 4) return (hi >> (48 - 16 * idx)) & 0xFFFFULL;
                return (lo >> (48 - 16 * (idx - 4))) & 0xFFFFULL;
            case EW::W:
                switch (idx & 3) {
                    case 0: return (hi >> 32) & 0xFFFFFFFFULL;
                    case 1: return hi & 0xFFFFFFFFULL;
                    case 2: return (lo >> 32) & 0xFFFFFFFFULL;
                    default: return lo & 0xFFFFFFFFULL;
                }
            case EW::D:
                return (idx == 0) ? hi : lo;
            default:
                return lo;
        }
    }

    void set_lane(EW ew, int idx, uint64_t val) {
        switch (ew) {
            case EW::B: {
                uint64_t v = val & 0xFFULL;
                if (idx < 8) {
                    int sh = 56 - 8 * idx;
                    hi = (hi & ~(0xFFULL << sh)) | (v << sh);
                } else {
                    int sh = 56 - 8 * (idx - 8);
                    lo = (lo & ~(0xFFULL << sh)) | (v << sh);
                }
                break;
            }
            case EW::H: {
                uint64_t v = val & 0xFFFFULL;
                if (idx < 4) {
                    int sh = 48 - 16 * idx;
                    hi = (hi & ~(0xFFFFULL << sh)) | (v << sh);
                } else {
                    int sh = 48 - 16 * (idx - 4);
                    lo = (lo & ~(0xFFFFULL << sh)) | (v << sh);
                }
                break;
            }
            case EW::W: {
                uint64_t v = val & 0xFFFFFFFFULL;
                switch (idx & 3) {
                    case 0: hi = (hi & 0x00000000FFFFFFFFULL) | (v << 32); break;
                    case 1: hi = (hi & 0xFFFFFFFF00000000ULL) | v; break;
                    case 2: lo = (lo & 0x00000000FFFFFFFFULL) | (v << 32); break;
                    default: lo = (lo & 0xFFFFFFFF00000000ULL) | v; break;
                }
                break;
            }
            case EW::D:
                if (idx == 0) hi = val;
                else lo = val;
                break;
            default:
                break;
        }
    }

    bool is_replicated(EW ew, uint64_t *out_lane = nullptr) const {
        if (ew == EW::None || ew == EW::Q) return false;
        const int n = ew_count(ew);
        const uint64_t first = get_lane(ew, 0);
        for (int i = 1; i < n; ++i) {
            if (get_lane(ew, i) != first) return false;
        }
        if (out_lane) *out_lane = first;
        return true;
    }

    constexpr bool operator==(const u128_t &o) const { return hi == o.hi && lo == o.lo; }
    constexpr bool operator!=(const u128_t &o) const { return hi != o.hi || lo != o.lo; }
    constexpr bool operator<(const u128_t &o) const { return hi != o.hi ? (hi < o.hi) : (lo < o.lo); }

    constexpr u128_t operator&(const u128_t &o) const { return u128_t(hi & o.hi, lo & o.lo); }
    constexpr u128_t operator|(const u128_t &o) const { return u128_t(hi | o.hi, lo | o.lo); }
    constexpr u128_t operator^(const u128_t &o) const { return u128_t(hi ^ o.hi, lo ^ o.lo); }
    constexpr u128_t operator~() const { return u128_t(~hi, ~lo); }

    u128_t shl_bits(int n) const {
        if (n <= 0) return *this;
        if (n >= 128) return zero();
        if (n >= 64) return u128_t(lo << (n - 64), 0);
        return u128_t((hi << n) | (lo >> (64 - n)), lo << n);
    }

    u128_t shr_bits(int n) const {
        if (n <= 0) return *this;
        if (n >= 128) return zero();
        if (n >= 64) return u128_t(0, hi >> (n - 64));
        return u128_t(hi >> n, (lo >> n) | (hi << (64 - n)));
    }

    u128_t rotl_bits(int n) const {
        n &= 127;
        if (n == 0) return *this;
        return shl_bits(n) | shr_bits(128 - n);
    }

    std::string hex32_lower() const {
        char buf[40];
        std::snprintf(buf, sizeof(buf), "%016llx%016llx",
                      static_cast<unsigned long long>(hi),
                      static_cast<unsigned long long>(lo));
        return buf;
    }

    std::string hex32_upper() const {
        char buf[40];
        std::snprintf(buf, sizeof(buf), "%016llX%016llX",
                      static_cast<unsigned long long>(hi),
                      static_cast<unsigned long long>(lo));
        return buf;
    }
};

struct U128Hash {
    size_t operator()(const u128_t &v) const noexcept {
        return static_cast<size_t>(v.hi ^ (v.lo * 0x9E3779B97F4A7C15ULL));
    }
};

} // namespace spudec
