#include "spudec/sem.hpp"

namespace spudec {
namespace sem {

u128_t shufb(const u128_t &a, const u128_t &b, const u128_t &ctl) {
    uint8_t sa[16], sb[16], sc[16], out[16];
    a.to_bytes(sa);
    b.to_bytes(sb);
    ctl.to_bytes(sc);
    for (int i = 0; i < 16; ++i) {
        uint8_t cb = sc[i];
        if ((cb & 0xC0u) == 0x80u)      out[i] = 0x00u;
        else if ((cb & 0xE0u) == 0xC0u) out[i] = 0xFFu;
        else if ((cb & 0xE0u) == 0xE0u) out[i] = 0x80u;
        else {
            uint8_t idx = cb & 0x1Fu;
            out[i] = (idx < 16) ? sa[idx] : sb[idx - 16];
        }
    }
    return u128_t::from_bytes(out);
}

u128_t genctl(uint32_t addr, EW ew) {
    const int n = ew_bytes(ew);
    const int t = static_cast<int>(addr & 0xFu);
    const int j = t & ~(n - 1);
    uint8_t out[16];
    for (int i = 0; i < 16; ++i) out[i] = static_cast<uint8_t>(0x10 + i);
    const int first = (n <= 4) ? (4 - n) : 0;
    for (int k = 0; k < n && (j + k) < 16; ++k) {
        out[j + k] = static_cast<uint8_t>(first + k);
    }
    return u128_t::from_bytes(out);
}

u128_t fsm(const u128_t &v, EW ew) {
    const int n = ew_count(ew);
    const uint32_t w = v.word0();
    const int bits = ew_bits(ew);
    const uint64_t full = (bits == 64) ? ~uint64_t(0) : ((1ULL << bits) - 1ULL);
    u128_t res;
    for (int j = 0; j < n; ++j) {
        uint64_t lane = ((w >> (n - 1 - j)) & 1u) ? full : 0ULL;
        res.set_lane(ew, j, lane);
    }
    return res;
}

u128_t gb(const u128_t &v, EW ew) {
    const int n = ew_count(ew);
    uint32_t out = 0;
    for (int j = 0; j < n; ++j) {
        if (v.get_lane(ew, j) & 1ULL) {
            out |= (1u << (n - 1 - j));
        }
    }
    return u128_t::from_word0(out);
}

u128_t qrotby(const u128_t &v, uint32_t n) {
    return v.rotl_bits(static_cast<int>((n & 0xFu) * 8u));
}

u128_t qrotbi(const u128_t &v, uint32_t n) {
    return v.rotl_bits(static_cast<int>(n & 0x7u));
}

u128_t qrotmby(const u128_t &v, uint32_t n) {
    uint32_t k = (0u - n) & 0x1Fu;
    if (k >= 16u) return u128_t::zero();
    return v.shr_bits(static_cast<int>(k * 8u));
}

u128_t qrotmbi(const u128_t &v, uint32_t n) {
    uint32_t k = (0u - n) & 0x7u;
    return v.shr_bits(static_cast<int>(k));
}

u128_t qshlby(const u128_t &v, uint32_t n) {
    uint32_t k = n & 0x1Fu;
    if (k >= 16u) return u128_t::zero();
    return v.shl_bits(static_cast<int>(k * 8u));
}

u128_t qshlbi(const u128_t &v, uint32_t n) {
    return v.shl_bits(static_cast<int>(n & 0x7u));
}

static uint32_t clz32(uint32_t x) {
    if (x == 0) return 32;
    uint32_t n = 0;
    for (int i = 31; i >= 0; --i) {
        if ((x >> i) & 1u) break;
        ++n;
    }
    return n;
}

static uint8_t popcnt8(uint8_t x) {
    uint8_t c = 0;
    while (x) { c += (x & 1u); x >>= 1; }
    return c;
}

static uint64_t lane_shl(uint64_t x, uint64_t c, int bits, uint64_t full) {
    uint64_t m = (bits == 32) ? 0x3FULL : 0x1FULL;
    c &= m;
    return (c >= static_cast<uint64_t>(bits)) ? 0ULL : ((x << c) & full);
}

static uint64_t lane_shr(uint64_t x, uint64_t c, int bits) {
    uint64_t m = (bits == 32) ? 0x3FULL : 0x1FULL;
    c &= m;
    return (c >= static_cast<uint64_t>(bits)) ? 0ULL : (x >> c);
}

static uint64_t lane_sar(uint64_t x, uint64_t c, int bits, uint64_t full) {
    uint64_t m = (bits == 32) ? 0x3FULL : 0x1FULL;
    c &= m;
    if (c >= static_cast<uint64_t>(bits)) c = static_cast<uint64_t>(bits - 1);
    return static_cast<uint64_t>(sext64(x, bits) >> c) & full;
}

static uint64_t lane_rol(uint64_t x, uint64_t c, int bits, uint64_t full) {
    c &= static_cast<uint64_t>(bits - 1);
    if (c == 0) return x & full;
    return ((x << c) | (x >> (bits - c))) & full;
}

std::optional<u128_t> evaluate(Op op, EW ew, const u128_t *args, size_t nargs) {
    if (op == Op::MOV || op == Op::CONST) {
        if (nargs < 1) return std::nullopt;
        return args[0];
    }

    // Bitwise
    if (op == Op::NOT) {
        if (nargs < 1) return std::nullopt;
        return ~args[0];
    }
    if (op == Op::AND || op == Op::OR || op == Op::XOR ||
        op == Op::NAND || op == Op::NOR || op == Op::ANDC ||
        op == Op::ORC || op == Op::EQV) {
        if (nargs < 2) return std::nullopt;
        switch (op) {
            case Op::AND:  return args[0] & args[1];
            case Op::OR:   return args[0] | args[1];
            case Op::XOR:  return args[0] ^ args[1];
            case Op::NAND: return ~(args[0] & args[1]);
            case Op::NOR:  return ~(args[0] | args[1]);
            case Op::ANDC: return args[0] & ~args[1];
            case Op::ORC:  return args[0] | ~args[1];
            case Op::EQV:  return ~(args[0] ^ args[1]);
            default: break;
        }
    }

    // Permute / select / quadword shifts
    if (op == Op::SELB) {
        if (nargs < 3) return std::nullopt;
        return (args[0] & ~args[2]) | (args[1] & args[2]);
    }
    if (op == Op::SHUFB) {
        if (nargs < 3) return std::nullopt;
        return shufb(args[0], args[1], args[2]);
    }
    if (op == Op::GENCTL) {
        if (nargs < 1 || ew == EW::None || ew == EW::Q) return std::nullopt;
        return genctl(args[0].word0(), ew);
    }
    if (op == Op::FSM) {
        if (nargs < 1 || ew == EW::None || ew == EW::Q) return std::nullopt;
        return fsm(args[0], ew);
    }
    if (op == Op::GB) {
        if (nargs < 1 || ew == EW::None || ew == EW::Q) return std::nullopt;
        return gb(args[0], ew);
    }
    if (op == Op::QROTBY || op == Op::QROTBI || op == Op::QROTMBY ||
        op == Op::QROTMBI || op == Op::QSHLBY || op == Op::QSHLBI) {
        if (nargs < 2) return std::nullopt;
        uint32_t cnt = args[1].word0();
        switch (op) {
            case Op::QROTBY:  return qrotby(args[0], cnt);
            case Op::QROTBI:  return qrotbi(args[0], cnt);
            case Op::QROTMBY: return qrotmby(args[0], cnt);
            case Op::QROTMBI: return qrotmbi(args[0], cnt);
            case Op::QSHLBY:  return qshlby(args[0], cnt);
            case Op::QSHLBI:  return qshlbi(args[0], cnt);
            default: break;
        }
    }

    // Unary word/byte ops
    if (op == Op::CLZ) {
        if (nargs < 1) return std::nullopt;
        u128_t r;
        for (int i = 0; i < 4; ++i)
            r.set_lane(EW::W, i, clz32(static_cast<uint32_t>(args[0].get_lane(EW::W, i))));
        return r;
    }
    if (op == Op::CNTB) {
        if (nargs < 1) return std::nullopt;
        u128_t r;
        for (int i = 0; i < 16; ++i)
            r.set_lane(EW::B, i, popcnt8(args[0].byte_lane(i)));
        return r;
    }
    if (op == Op::ORX) {
        if (nargs < 1) return std::nullopt;
        uint32_t w = 0;
        for (int i = 0; i < 4; ++i) w |= static_cast<uint32_t>(args[0].get_lane(EW::W, i));
        return u128_t::from_word0(w);
    }

    // Multiply family (always EW::W lanes)
    if (op == Op::MPY || op == Op::MPYU || op == Op::MPYH ||
        op == Op::MPYHH || op == Op::MPYHHU || op == Op::MPYS) {
        if (nargs < 2) return std::nullopt;
        u128_t r;
        for (int i = 0; i < 4; ++i) {
            uint32_t x = static_cast<uint32_t>(args[0].get_lane(EW::W, i));
            uint32_t y = static_cast<uint32_t>(args[1].get_lane(EW::W, i));
            uint32_t out = 0;
            switch (op) {
                case Op::MPY:
                    out = static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(x & 0xFFFFu)) *
                                                static_cast<int32_t>(static_cast<int16_t>(y & 0xFFFFu)));
                    break;
                case Op::MPYU:
                    out = (x & 0xFFFFu) * (y & 0xFFFFu);
                    break;
                case Op::MPYH:
                    out = static_cast<uint32_t>((static_cast<int32_t>(static_cast<int16_t>(x >> 16)) *
                                                 static_cast<int32_t>(y & 0xFFFFu)) << 16);
                    break;
                case Op::MPYHH:
                    out = static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(x >> 16)) *
                                                static_cast<int32_t>(static_cast<int16_t>(y >> 16)));
                    break;
                case Op::MPYHHU:
                    out = (x >> 16) * (y >> 16);
                    break;
                case Op::MPYS:
                    out = static_cast<uint32_t>((static_cast<int32_t>(static_cast<int16_t>(x & 0xFFFFu)) *
                                                 static_cast<int32_t>(static_cast<int16_t>(y & 0xFFFFu))) >> 16);
                    break;
                default: break;
            }
            r.set_lane(EW::W, i, out);
        }
        return r;
    }

    if (ew == EW::None || ew == EW::Q) return std::nullopt;
    const int n = ew_count(ew);
    const int bits = ew_bits(ew);
    const uint64_t full = (bits == 64) ? ~uint64_t(0) : ((1ULL << bits) - 1ULL);

    if (op == Op::EXTS) {
        if (nargs < 1) return std::nullopt;
        const int half = bits / 2;
        const uint64_t hmask = (1ULL << half) - 1ULL;
        u128_t r;
        for (int i = 0; i < n; ++i) {
            uint64_t x = args[0].get_lane(ew, i) & hmask;
            r.set_lane(ew, i, static_cast<uint64_t>(sext64(x, half)) & full);
        }
        return r;
    }

    if (op == Op::ADD || op == Op::SUB || op == Op::CG || op == Op::BG ||
        op == Op::SHL || op == Op::SHR || op == Op::SAR || op == Op::ROL ||
        op == Op::ROTM || op == Op::ROTMA ||
        op == Op::CMPEQ || op == Op::CMPGT || op == Op::CMPGTU) {
        if (nargs < 2 || (bits == 64 && (op == Op::CG || op == Op::BG || op == Op::SHL ||
                                         op == Op::SHR || op == Op::SAR || op == Op::ROL ||
                                         op == Op::ROTM || op == Op::ROTMA))) {
            // Note: SPU integer arithmetic/shifts/compares operate on B/H/W (<=32b); handle 64b ADD/SUB/CMP cleanly too.
            if (nargs < 2) return std::nullopt;
        }
        u128_t r;
        for (int i = 0; i < n; ++i) {
            uint64_t x = args[0].get_lane(ew, i);
            uint64_t y = args[1].get_lane(ew, i);
            uint64_t out = 0;
            switch (op) {
                case Op::ADD:   out = (x + y) & full; break;
                case Op::SUB:   out = (x - y) & full; break;
                case Op::CG:    out = ((x + y) > full) ? 1ULL : 0ULL; break;
                case Op::BG:    out = (y >= x) ? 1ULL : 0ULL; break;
                case Op::SHL:   out = lane_shl(x, y, bits, full); break;
                case Op::SHR:   out = lane_shr(x, y, bits); break;
                case Op::SAR:   out = lane_sar(x, y, bits, full); break;
                case Op::ROL:   out = lane_rol(x, y, bits, full); break;
                case Op::ROTM:  out = lane_shr(x, 0ULL - y, bits); break;
                case Op::ROTMA: out = lane_sar(x, 0ULL - y, bits, full); break;
                case Op::CMPEQ: out = (x == y) ? full : 0ULL; break;
                case Op::CMPGT: out = (sext64(x, bits) > sext64(y, bits)) ? full : 0ULL; break;
                case Op::CMPGTU: out = (x > y) ? full : 0ULL; break;
                default: return std::nullopt;
            }
            r.set_lane(ew, i, out);
        }
        return r;
    }

    if (op == Op::ADDX || op == Op::SUBX || op == Op::CGX || op == Op::BGX) {
        if (nargs < 3 || bits > 32) return std::nullopt;
        u128_t r;
        for (int i = 0; i < n; ++i) {
            uint64_t x = args[0].get_lane(ew, i);
            uint64_t y = args[1].get_lane(ew, i);
            uint64_t c = args[2].get_lane(ew, i) & 1ULL;
            uint64_t out = 0;
            switch (op) {
                case Op::ADDX: out = (x + y + c) & full; break;
                case Op::SUBX: out = (x + (~y & full) + c) & full; break;
                case Op::CGX:  out = ((x + y + c) > full) ? 1ULL : 0ULL; break;
                case Op::BGX:  out = ((y + (~x & full) + c) > full) ? 1ULL : 0ULL; break;
                default: break;
            }
            r.set_lane(ew, i, out);
        }
        return r;
    }

    return std::nullopt;
}

} // namespace sem
} // namespace spudec
