#include "spudec/lifter.hpp"
#include <array>
#include <cstdio>
#include <cstring>

namespace spudec {

namespace {

constexpr inline uint32_t ibits(uint32_t word, int hi, int lo) {
    const int shift = 31 - lo;
    const int width = lo - hi + 1;
    return (word >> shift) & ((1u << width) - 1u);
}

constexpr inline int32_t sign_ext32(uint32_t val, int bits) {
    const uint32_t m = 1u << (bits - 1);
    val &= (1u << bits) - 1u;
    return static_cast<int32_t>((val ^ m) - m);
}

enum class SpuInsnId : uint16_t {
    Invalid = 0,
    // RRR (4-bit)
    selb, shufb, mpya, fnms, fma, fms,
    // 7-bit
    hbra, hbrr, ila,
    // 8-bit RI10
    ori, orhi, orbi, sfi, sfhi, andi, andhi, andbi, ai, ahi,
    stqd, lqd, xori, xorhi, xorbi, cgti, cgthi, cgtbi, hgti,
    clgti, clgthi, clgtbi, hlgti, mpyi, mpyui, ceqi, ceqhi, ceqbi, heqi,
    // 9-bit RI16
    brz, stqa, brnz, brhz, brhnz, stqr, bra, lqa, brasl, br, fsmbi, brsl, lqr,
    il, ilhu, ilh, iohl,
    // 10-bit RI8 float converts
    cflts, cfltu, csflt, cuflt,
    // 11-bit RR / RI7 / Control / Channel
    stop, lnop, sync, dsync, mfspr, rdch, rchcnt,
    sf, or_, bg, sfh, nor, absdb,
    rot, rotm, rotma, shl, roth, rothm, rotmah, shlh,
    roti, rotmi, rotmai, shli, rothi, rothmi, rotmahi, shlhi,
    a, and_, cg, ah, nand, avgb,
    mtspr, wrch,
    biz, binz, bihz, bihnz,
    stopd, stqx,
    bi, bisl, iret, bisled, hbr,
    gb, gbh, gbb, fsm, fsmh, fsmb, frest, frsqest,
    lqx, rotqbybi, rotqmbybi, shlqbybi,
    cbx, chx, cwx, cdx,
    rotqbi, rotqmbi, shlqbi, rotqby, rotqmby, shlqby,
    orx, cbd, chd, cwd, cdd,
    rotqbii, rotqmbii, shlqbii, rotqbyi, rotqmbyi, shlqbyi,
    nop, cgt, xor_, cgth, eqv, cgtb, sumb, hgt,
    clz, xswd, xshw, cntb, xsbh,
    clgt, andc, fcgt, dfcgt, fa, fs, fm,
    clgth, orc, fcmgt, dfcmgt, dfa, dfs, dfm, clgtb, hlgt,
    addx, sfx, cgx, bgx, mpyhha, mpyhhau, dfma, dfms, dfnms, dfnma,
    fscrrd, fesd, frds, fscrwr, dftsv,
    ceq, fceq, dfceq, mpy, mpyh, mpyhh, mpys,
    ceqh, fcmeq, dfcmeq, mpyu, mpyhhu, ceqb, fi, heq,
    COUNT
};

struct OpcodeEntry {
    SpuInsnId id = SpuInsnId::Invalid;
    const char *mnem = nullptr;
};

struct OpcodeTable {
    std::array<OpcodeEntry, 2048> tab{};

    void fill(uint32_t opcode, int opbits, SpuInsnId id, const char *mnem) {
        const int shift = 11 - opbits;
        const uint32_t count = 1u << shift;
        const uint32_t base = opcode << shift;
        for (uint32_t i = 0; i < count; ++i) {
            tab[base + i] = OpcodeEntry{id, mnem};
        }
    }

    OpcodeTable() {
        // 4-bit RRR
        fill(0x8, 4, SpuInsnId::selb,  "selb");
        fill(0xB, 4, SpuInsnId::shufb, "shufb");
        fill(0xC, 4, SpuInsnId::mpya,  "mpya");
        fill(0xD, 4, SpuInsnId::fnms,  "fnms");
        fill(0xE, 4, SpuInsnId::fma,   "fma");
        fill(0xF, 4, SpuInsnId::fms,   "fms");

        // 7-bit
        fill(0x08, 7, SpuInsnId::hbra, "hbra");
        fill(0x09, 7, SpuInsnId::hbrr, "hbrr");
        fill(0x21, 7, SpuInsnId::ila,  "ila");

        // 8-bit RI10
        fill(0x04, 8, SpuInsnId::ori,    "ori");
        fill(0x05, 8, SpuInsnId::orhi,   "orhi");
        fill(0x06, 8, SpuInsnId::orbi,   "orbi");
        fill(0x0C, 8, SpuInsnId::sfi,    "sfi");
        fill(0x0D, 8, SpuInsnId::sfhi,   "sfhi");
        fill(0x14, 8, SpuInsnId::andi,   "andi");
        fill(0x15, 8, SpuInsnId::andhi,  "andhi");
        fill(0x16, 8, SpuInsnId::andbi,  "andbi");
        fill(0x1C, 8, SpuInsnId::ai,     "ai");
        fill(0x1D, 8, SpuInsnId::ahi,    "ahi");
        fill(0x24, 8, SpuInsnId::stqd,   "stqd");
        fill(0x34, 8, SpuInsnId::lqd,    "lqd");
        fill(0x44, 8, SpuInsnId::xori,   "xori");
        fill(0x45, 8, SpuInsnId::xorhi,  "xorhi");
        fill(0x46, 8, SpuInsnId::xorbi,  "xorbi");
        fill(0x4C, 8, SpuInsnId::cgti,   "cgti");
        fill(0x4D, 8, SpuInsnId::cgthi,  "cgthi");
        fill(0x4E, 8, SpuInsnId::cgtbi,  "cgtbi");
        fill(0x4F, 8, SpuInsnId::hgti,   "hgti");
        fill(0x5C, 8, SpuInsnId::clgti,  "clgti");
        fill(0x5D, 8, SpuInsnId::clgthi, "clgthi");
        fill(0x5E, 8, SpuInsnId::clgtbi, "clgtbi");
        fill(0x5F, 8, SpuInsnId::hlgti,  "hlgti");
        fill(0x74, 8, SpuInsnId::mpyi,   "mpyi");
        fill(0x75, 8, SpuInsnId::mpyui,  "mpyui");
        fill(0x7C, 8, SpuInsnId::ceqi,   "ceqi");
        fill(0x7D, 8, SpuInsnId::ceqhi,  "ceqhi");
        fill(0x7E, 8, SpuInsnId::ceqbi,  "ceqbi");
        fill(0x7F, 8, SpuInsnId::heqi,   "heqi");

        // 9-bit RI16
        fill(0x040, 9, SpuInsnId::brz,   "brz");
        fill(0x041, 9, SpuInsnId::stqa,  "stqa");
        fill(0x042, 9, SpuInsnId::brnz,  "brnz");
        fill(0x044, 9, SpuInsnId::brhz,  "brhz");
        fill(0x046, 9, SpuInsnId::brhnz, "brhnz");
        fill(0x047, 9, SpuInsnId::stqr,  "stqr");
        fill(0x060, 9, SpuInsnId::bra,   "bra");
        fill(0x061, 9, SpuInsnId::lqa,   "lqa");
        fill(0x062, 9, SpuInsnId::brasl, "brasl");
        fill(0x064, 9, SpuInsnId::br,    "br");
        fill(0x065, 9, SpuInsnId::fsmbi, "fsmbi");
        fill(0x066, 9, SpuInsnId::brsl,  "brsl");
        fill(0x067, 9, SpuInsnId::lqr,   "lqr");
        fill(0x081, 9, SpuInsnId::il,    "il");
        fill(0x082, 9, SpuInsnId::ilhu,  "ilhu");
        fill(0x083, 9, SpuInsnId::ilh,   "ilh");
        fill(0x0C1, 9, SpuInsnId::iohl,  "iohl");

        // 10-bit RI8
        fill(0x1D8, 10, SpuInsnId::cflts, "cflts");
        fill(0x1D9, 10, SpuInsnId::cfltu, "cfltu");
        fill(0x1DA, 10, SpuInsnId::csflt, "csflt");
        fill(0x1DB, 10, SpuInsnId::cuflt, "cuflt");

        // 11-bit
        fill(0x000, 11, SpuInsnId::stop,      "stop");
        fill(0x001, 11, SpuInsnId::lnop,      "lnop");
        fill(0x002, 11, SpuInsnId::sync,      "sync");
        fill(0x003, 11, SpuInsnId::dsync,     "dsync");
        fill(0x00C, 11, SpuInsnId::mfspr,     "mfspr");
        fill(0x00D, 11, SpuInsnId::rdch,      "rdch");
        fill(0x00F, 11, SpuInsnId::rchcnt,    "rchcnt");
        fill(0x040, 11, SpuInsnId::sf,        "sf");
        fill(0x041, 11, SpuInsnId::or_,       "or");
        fill(0x042, 11, SpuInsnId::bg,        "bg");
        fill(0x048, 11, SpuInsnId::sfh,       "sfh");
        fill(0x049, 11, SpuInsnId::nor,       "nor");
        fill(0x053, 11, SpuInsnId::absdb,     "absdb");
        fill(0x058, 11, SpuInsnId::rot,       "rot");
        fill(0x059, 11, SpuInsnId::rotm,      "rotm");
        fill(0x05A, 11, SpuInsnId::rotma,     "rotma");
        fill(0x05B, 11, SpuInsnId::shl,       "shl");
        fill(0x05C, 11, SpuInsnId::roth,      "roth");
        fill(0x05D, 11, SpuInsnId::rothm,     "rothm");
        fill(0x05E, 11, SpuInsnId::rotmah,    "rotmah");
        fill(0x05F, 11, SpuInsnId::shlh,      "shlh");
        fill(0x078, 11, SpuInsnId::roti,      "roti");
        fill(0x079, 11, SpuInsnId::rotmi,     "rotmi");
        fill(0x07A, 11, SpuInsnId::rotmai,    "rotmai");
        fill(0x07B, 11, SpuInsnId::shli,      "shli");
        fill(0x07C, 11, SpuInsnId::rothi,     "rothi");
        fill(0x07D, 11, SpuInsnId::rothmi,    "rothmi");
        fill(0x07E, 11, SpuInsnId::rotmahi,   "rotmahi");
        fill(0x07F, 11, SpuInsnId::shlhi,     "shlhi");
        fill(0x0C0, 11, SpuInsnId::a,         "a");
        fill(0x0C1, 11, SpuInsnId::and_,      "and");
        fill(0x0C2, 11, SpuInsnId::cg,        "cg");
        fill(0x0C8, 11, SpuInsnId::ah,        "ah");
        fill(0x0C9, 11, SpuInsnId::nand,      "nand");
        fill(0x0D3, 11, SpuInsnId::avgb,      "avgb");
        fill(0x10C, 11, SpuInsnId::mtspr,     "mtspr");
        fill(0x10D, 11, SpuInsnId::wrch,      "wrch");
        fill(0x128, 11, SpuInsnId::biz,       "biz");
        fill(0x129, 11, SpuInsnId::binz,      "binz");
        fill(0x12A, 11, SpuInsnId::bihz,      "bihz");
        fill(0x12B, 11, SpuInsnId::bihnz,     "bihnz");
        fill(0x140, 11, SpuInsnId::stopd,     "stopd");
        fill(0x144, 11, SpuInsnId::stqx,      "stqx");
        fill(0x1A8, 11, SpuInsnId::bi,        "bi");
        fill(0x1A9, 11, SpuInsnId::bisl,      "bisl");
        fill(0x1AA, 11, SpuInsnId::iret,      "iret");
        fill(0x1AB, 11, SpuInsnId::bisled,    "bisled");
        fill(0x1AC, 11, SpuInsnId::hbr,       "hbr");
        fill(0x1B0, 11, SpuInsnId::gb,        "gb");
        fill(0x1B1, 11, SpuInsnId::gbh,       "gbh");
        fill(0x1B2, 11, SpuInsnId::gbb,       "gbb");
        fill(0x1B4, 11, SpuInsnId::fsm,       "fsm");
        fill(0x1B5, 11, SpuInsnId::fsmh,      "fsmh");
        fill(0x1B6, 11, SpuInsnId::fsmb,      "fsmb");
        fill(0x1B8, 11, SpuInsnId::frest,     "frest");
        fill(0x1B9, 11, SpuInsnId::frsqest,   "frsqest");
        fill(0x1C4, 11, SpuInsnId::lqx,       "lqx");
        fill(0x1CC, 11, SpuInsnId::rotqbybi,  "rotqbybi");
        fill(0x1CD, 11, SpuInsnId::rotqmbybi, "rotqmbybi");
        fill(0x1CF, 11, SpuInsnId::shlqbybi,  "shlqbybi");
        fill(0x1D4, 11, SpuInsnId::cbx,       "cbx");
        fill(0x1D5, 11, SpuInsnId::chx,       "chx");
        fill(0x1D6, 11, SpuInsnId::cwx,       "cwx");
        fill(0x1D7, 11, SpuInsnId::cdx,       "cdx");
        fill(0x1D8, 11, SpuInsnId::rotqbi,    "rotqbi");
        fill(0x1D9, 11, SpuInsnId::rotqmbi,   "rotqmbi");
        fill(0x1DB, 11, SpuInsnId::shlqbi,    "shlqbi");
        fill(0x1DC, 11, SpuInsnId::rotqby,    "rotqby");
        fill(0x1DD, 11, SpuInsnId::rotqmby,   "rotqmby");
        fill(0x1DF, 11, SpuInsnId::shlqby,    "shlqby");
        fill(0x1F0, 11, SpuInsnId::orx,       "orx");
        fill(0x1F4, 11, SpuInsnId::cbd,       "cbd");
        fill(0x1F5, 11, SpuInsnId::chd,       "chd");
        fill(0x1F6, 11, SpuInsnId::cwd,       "cwd");
        fill(0x1F7, 11, SpuInsnId::cdd,       "cdd");
        fill(0x1F8, 11, SpuInsnId::rotqbii,   "rotqbii");
        fill(0x1F9, 11, SpuInsnId::rotqmbii,  "rotqmbii");
        fill(0x1FB, 11, SpuInsnId::shlqbii,   "shlqbii");
        fill(0x1FC, 11, SpuInsnId::rotqbyi,   "rotqbyi");
        fill(0x1FD, 11, SpuInsnId::rotqmbyi,  "rotqmbyi");
        fill(0x1FF, 11, SpuInsnId::shlqbyi,   "shlqbyi");
        fill(0x201, 11, SpuInsnId::nop,       "nop");
        fill(0x240, 11, SpuInsnId::cgt,       "cgt");
        fill(0x241, 11, SpuInsnId::xor_,      "xor");
        fill(0x248, 11, SpuInsnId::cgth,      "cgth");
        fill(0x249, 11, SpuInsnId::eqv,       "eqv");
        fill(0x250, 11, SpuInsnId::cgtb,      "cgtb");
        fill(0x253, 11, SpuInsnId::sumb,      "sumb");
        fill(0x258, 11, SpuInsnId::hgt,       "hgt");
        fill(0x2A5, 11, SpuInsnId::clz,       "clz");
        fill(0x2A6, 11, SpuInsnId::xswd,      "xswd");
        fill(0x2AE, 11, SpuInsnId::xshw,      "xshw");
        fill(0x2B4, 11, SpuInsnId::cntb,      "cntb");
        fill(0x2B6, 11, SpuInsnId::xsbh,      "xsbh");
        fill(0x2C0, 11, SpuInsnId::clgt,      "clgt");
        fill(0x2C1, 11, SpuInsnId::andc,      "andc");
        fill(0x2C2, 11, SpuInsnId::fcgt,      "fcgt");
        fill(0x2C3, 11, SpuInsnId::dfcgt,     "dfcgt");
        fill(0x2C4, 11, SpuInsnId::fa,        "fa");
        fill(0x2C5, 11, SpuInsnId::fs,        "fs");
        fill(0x2C6, 11, SpuInsnId::fm,        "fm");
        fill(0x2C8, 11, SpuInsnId::clgth,     "clgth");
        fill(0x2C9, 11, SpuInsnId::orc,       "orc");
        fill(0x2CA, 11, SpuInsnId::fcmgt,     "fcmgt");
        fill(0x2CB, 11, SpuInsnId::dfcmgt,    "dfcmgt");
        fill(0x2CC, 11, SpuInsnId::dfa,       "dfa");
        fill(0x2CD, 11, SpuInsnId::dfs,       "dfs");
        fill(0x2CE, 11, SpuInsnId::dfm,       "dfm");
        fill(0x2D0, 11, SpuInsnId::clgtb,     "clgtb");
        fill(0x2D8, 11, SpuInsnId::hlgt,      "hlgt");
        fill(0x340, 11, SpuInsnId::addx,      "addx");
        fill(0x341, 11, SpuInsnId::sfx,       "sfx");
        fill(0x342, 11, SpuInsnId::cgx,       "cgx");
        fill(0x343, 11, SpuInsnId::bgx,       "bgx");
        fill(0x346, 11, SpuInsnId::mpyhha,    "mpyhha");
        fill(0x34E, 11, SpuInsnId::mpyhhau,   "mpyhhau");
        fill(0x35C, 11, SpuInsnId::dfma,      "dfma");
        fill(0x35D, 11, SpuInsnId::dfms,      "dfms");
        fill(0x35E, 11, SpuInsnId::dfnms,     "dfnms");
        fill(0x35F, 11, SpuInsnId::dfnma,     "dfnma");
        fill(0x398, 11, SpuInsnId::fscrrd,    "fscrrd");
        fill(0x3B8, 11, SpuInsnId::fesd,      "fesd");
        fill(0x3B9, 11, SpuInsnId::frds,      "frds");
        fill(0x3BA, 11, SpuInsnId::fscrwr,    "fscrwr");
        fill(0x3BF, 11, SpuInsnId::dftsv,     "dftsv");
        fill(0x3C0, 11, SpuInsnId::ceq,       "ceq");
        fill(0x3C2, 11, SpuInsnId::fceq,      "fceq");
        fill(0x3C3, 11, SpuInsnId::dfceq,     "dfceq");
        fill(0x3C4, 11, SpuInsnId::mpy,       "mpy");
        fill(0x3C5, 11, SpuInsnId::mpyh,      "mpyh");
        fill(0x3C6, 11, SpuInsnId::mpyhh,     "mpyhh");
        fill(0x3C7, 11, SpuInsnId::mpys,      "mpys");
        fill(0x3C8, 11, SpuInsnId::ceqh,      "ceqh");
        fill(0x3CA, 11, SpuInsnId::fcmeq,     "fcmeq");
        fill(0x3CB, 11, SpuInsnId::dfcmeq,    "dfcmeq");
        fill(0x3CC, 11, SpuInsnId::mpyu,      "mpyu");
        fill(0x3CE, 11, SpuInsnId::mpyhhu,    "mpyhhu");
        fill(0x3D0, 11, SpuInsnId::ceqb,      "ceqb");
        fill(0x3D4, 11, SpuInsnId::fi,        "fi");
        fill(0x3D8, 11, SpuInsnId::heq,       "heq");
    }
};

const OpcodeTable &opcode_table() {
    static const OpcodeTable kTable;
    return kTable;
}

std::string dftsv_classes(uint32_t sel) {
    static const char *const kNames[7] = {
        "nan", "+inf", "-inf", "+0", "-0", "+denorm", "-denorm"
    };
    std::string out;
    for (int i = 0; i < 7; ++i) {
        if (sel & (0x40u >> i)) {
            if (!out.empty()) out += "|";
            out += kNames[i];
        }
    }
    return out.empty() ? "none" : out;
}

} // namespace

int Lifter::modelled_mnemonic_count() {
    // 199 hardware mnemonics + simplified `lr` alias = 200 modelled mnemonics
    return static_cast<int>(SpuInsnId::COUNT) - 1 + 1;
}

Lifter::Lifter(bool drop_hints, int n_arg_regs, int n_ret_regs, uint32_t lslr)
    : drop_hints_(drop_hints),
      lslr_(lslr ? lslr : kDefaultLslr),
      abi_args_(regs::arg_regs(n_arg_regs)),
      ret_regs_(regs::arg_regs(n_ret_regs)) {}

uint64_t Lifter::wrap_ls(uint64_t base_ea, int64_t target, bool quad_align) const {
    uint64_t overlay = (base_ea > lslr_) ? (base_ea & ~static_cast<uint64_t>(lslr_)) : 0ULL;
    uint32_t wrapped = static_cast<uint32_t>(target) & lslr_;
    wrapped &= quad_align ? ~0xFu : ~0x3u;
    return overlay | wrapped;
}

std::vector<Operand> Lifter::make_abi_call_srcs() const {
    std::vector<Operand> out;
    out.reserve(3 + abi_args_.size());
    out.push_back(Operand::make_var(regs::R_MEM));
    out.push_back(Operand::make_var(regs::R_CH));
    out.push_back(Operand::make_var(regs::LR));
    for (int r : abi_args_) out.push_back(Operand::make_var(r));
    return out;
}

std::vector<Operand> Lifter::make_abi_ret_srcs() const {
    std::vector<Operand> out;
    out.reserve(2 + ret_regs_.size());
    out.push_back(Operand::make_var(regs::R_MEM));
    out.push_back(Operand::make_var(regs::R_CH));
    for (int r : ret_regs_) out.push_back(Operand::make_var(r));
    return out;
}

void Lifter::lift_word(Function &func, Block &blk, uint64_t ea, uint32_t word) {
    auto emit = [&](Op op, int dst, std::vector<Operand> srcs, EW ew = EW::W,
                    const char *cmt = nullptr) -> Insn * {
        auto ins = func.make_insn(op, ew, ea);
        if (dst >= 0) {
            ins->has_dst = true;
            ins->dst_reg = dst;
        }
        ins->srcs = std::move(srcs);
        if (cmt) ins->comment = cmt;
        return blk.add(std::move(ins));
    };

    auto mat_const = [&](const u128_t &val, EW cew = EW::None, const char *cmt = nullptr) -> Operand {
        int t = alloc_tmp();
        emit(Op::CONST, t, {Operand::make_const(val, cew)}, (cew != EW::None) ? cew : EW::W, cmt);
        return Operand::make_var(t);
    };

    const OpcodeEntry &ent = opcode_table().tab[ibits(word, 0, 10)];
    if (ent.id == SpuInsnId::Invalid) {
        unhandled_["undecodable"]++;
        auto ins = emit(Op::INTRINSIC, -1, {}, EW::Q);
        ins->has_aux = true;
        ins->aux_str = "undecodable";
        return;
    }

    const int rb = static_cast<int>(ibits(word, 11, 17));
    const int ra = static_cast<int>(ibits(word, 18, 24));
    const int rt = static_cast<int>(ibits(word, 25, 31));

    auto emit_rr = [&](Op op, EW ew) {
        emit(op, rt, {Operand::make_var(ra), Operand::make_var(rb)}, ew);
    };
    auto emit_rr_acc = [&](Op op, EW ew) {
        emit(op, rt, {Operand::make_var(ra), Operand::make_var(rb), Operand::make_var(rt)}, ew);
    };
    auto emit_unary = [&](Op op, EW ew) {
        emit(op, rt, {Operand::make_var(ra)}, ew);
    };
    auto emit_ri10 = [&](Op op, EW ew, bool byte_unsigned = false, bool byte_signed = false) {
        int64_t imm = 0;
        if (byte_unsigned) imm = static_cast<int64_t>(ibits(word, 8, 17) & 0xFFu);
        else if (byte_signed) imm = static_cast<int64_t>(sign_ext32(ibits(word, 8, 17) & 0xFFu, 8));
        else imm = static_cast<int64_t>(sign_ext32(ibits(word, 8, 17), 10));
        Operand c = mat_const(u128_t::repl(static_cast<uint64_t>(imm), ew), ew);
        emit(op, rt, {Operand::make_var(ra), c}, ew);
    };
    auto emit_rrr = [&](Op op, EW ew) {
        const int rrr_rt = static_cast<int>(ibits(word, 4, 10));
        const int rrr_rb = static_cast<int>(ibits(word, 11, 17));
        const int rrr_ra = static_cast<int>(ibits(word, 18, 24));
        const int rrr_rc = static_cast<int>(ibits(word, 25, 31));
        emit(op, rrr_rt, {Operand::make_var(rrr_ra), Operand::make_var(rrr_rb), Operand::make_var(rrr_rc)}, ew);
    };
    auto emit_shift_imm = [&](EW ew, int mode /*0=shl,1=rol,2=shr,3=sar*/) {
        const int bits = ew_bits(ew);
        const int32_t raw = sign_ext32(ibits(word, 11, 17), 7);
        const int mask = (ew == EW::W) ? 0x3F : 0x1F;
        if (mode == 0) {
            int n = raw & mask;
            if (n >= bits) {
                emit(Op::CONST, rt, {Operand::make_const(u128_t::zero())}, EW::W, "shl count >= bits");
                return;
            }
            emit(Op::SHL, rt, {Operand::make_var(ra), mat_const(u128_t::repl(static_cast<uint64_t>(n), ew))}, ew);
        } else if (mode == 1) {
            int n = raw & (bits - 1);
            if (n == 0) {
                emit(Op::MOV, rt, {Operand::make_var(ra)}, ew);
                return;
            }
            emit(Op::ROL, rt, {Operand::make_var(ra), mat_const(u128_t::repl(static_cast<uint64_t>(n), ew))}, ew);
        } else {
            int n = (-raw) & mask;
            if (n >= bits) {
                if (mode == 2) {
                    emit(Op::CONST, rt, {Operand::make_const(u128_t::zero())}, EW::W, "shr count >= bits");
                    return;
                }
                n = bits - 1;
            }
            emit(mode == 2 ? Op::SHR : Op::SAR, rt,
                 {Operand::make_var(ra), mat_const(u128_t::repl(static_cast<uint64_t>(n), ew))}, ew);
        }
    };
    auto emit_quad_imm = [&](Op op, bool is_bytes, bool negated, bool check_zero) {
        const int32_t raw = sign_ext32(ibits(word, 11, 17), 7);
        int n = 0;
        if (negated) {
            int k = (-raw) & (is_bytes ? 0x1F : 0x7);
            if (is_bytes && k >= 16) {
                emit(Op::CONST, rt, {Operand::make_const(u128_t::zero())}, EW::W, "shift right >= 16 bytes");
                return;
            }
            if (k == 0) {
                emit(Op::MOV, rt, {Operand::make_var(ra)}, EW::Q);
                return;
            }
            // Preserve the raw SPU ISA shift-count convention (hardware shifts right by (0 - count) & mask)
            // so immediate and register forms of QROTMBY/QROTMBI agree across sem.cpp, lanes.cpp, and cgen.cpp.
            n = raw;
        } else if (op == Op::QSHLBY || op == Op::QSHLBI) {
            n = raw & (is_bytes ? 0x1F : 0x7);
            if (is_bytes && n >= 16) {
                emit(Op::CONST, rt, {Operand::make_const(u128_t::zero())}, EW::W, "shift left >= 16 bytes");
                return;
            }
            if (n == 0) {
                emit(Op::MOV, rt, {Operand::make_var(ra)}, EW::Q);
                return;
            }
        } else {
            n = raw & (is_bytes ? 0xF : 0x7);
            if (check_zero && n == 0) {
                emit(Op::MOV, rt, {Operand::make_var(ra)}, EW::Q);
                return;
            }
        }
        emit(op, rt, {Operand::make_var(ra), mat_const(u128_t::from_word0(static_cast<uint32_t>(n)))}, EW::Q);
    };
    auto emit_bybi = [&](Op op) {
        int t = alloc_tmp();
        Operand c = mat_const(u128_t::repl(3, EW::W));
        emit(Op::SHR, t, {Operand::make_var(rb), c}, EW::W, "byte count from bits 3:6");
        emit(op, rt, {Operand::make_var(ra), Operand::make_var(t)}, EW::Q);
    };
    auto ea_displ = [&](int32_t off_bytes) -> Operand {
        Operand base = Operand::make_var(ra);
        if (off_bytes != 0) {
            int t = alloc_tmp();
            emit(Op::ADD, t, {base, mat_const(u128_t::repl(static_cast<uint64_t>(off_bytes), EW::W))}, EW::W);
            base = Operand::make_var(t);
        }
        int t2 = alloc_tmp();
        uint32_t ls_mask = (lslr_ & ~0xFu);
        emit(Op::AND, t2, {base, mat_const(u128_t::repl(ls_mask, EW::W))}, EW::W,
             "local store, quadword aligned");
        return Operand::make_var(t2);
    };
    auto ea_index = [&]() -> Operand {
        int t = alloc_tmp();
        emit(Op::ADD, t, {Operand::make_var(ra), Operand::make_var(rb)}, EW::W);
        int t2 = alloc_tmp();
        uint32_t ls_mask = (lslr_ & ~0xFu);
        emit(Op::AND, t2, {Operand::make_var(t), mat_const(u128_t::repl(ls_mask, EW::W))}, EW::W,
             "local store, quadword aligned");
        return Operand::make_var(t2);
    };
    auto emit_genctl_d = [&](EW ew) {
        int32_t off = sign_ext32(ibits(word, 11, 17), 7);
        Operand addr = Operand::make_var(ra);
        if (off != 0) {
            int t = alloc_tmp();
            emit(Op::ADD, t, {addr, mat_const(u128_t::repl(static_cast<uint64_t>(off), EW::W))}, EW::W);
            addr = Operand::make_var(t);
        }
        emit(Op::GENCTL, rt, {addr}, ew);
    };
    auto emit_genctl_x = [&](EW ew) {
        int t = alloc_tmp();
        emit(Op::ADD, t, {Operand::make_var(ra), Operand::make_var(rb)}, EW::W);
        emit(Op::GENCTL, rt, {Operand::make_var(t)}, ew);
    };
    auto emit_link = [&](int link_reg) {
        uint32_t ret_addr = static_cast<uint32_t>(wrap_ls(ea, static_cast<int64_t>(ea + 4), false));
        emit(Op::CONST, link_reg, {Operand::make_const(u128_t::from_word0(ret_addr))}, EW::W, "link register");
    };

    switch (ent.id) {
        // RRR
        case SpuInsnId::selb:  emit_rrr(Op::SELB, EW::Q); return;
        case SpuInsnId::shufb: emit_rrr(Op::SHUFB, EW::Q); return;
        case SpuInsnId::mpya:  emit_rrr(Op::MPYA, EW::W); return;
        case SpuInsnId::fma:   emit_rrr(Op::FMA, EW::W); return;
        case SpuInsnId::fms:   emit_rrr(Op::FMS, EW::W); return;
        case SpuInsnId::fnms:  emit_rrr(Op::FNMS, EW::W); return;

        // Hints & NOPs
        case SpuInsnId::hbr:
        case SpuInsnId::hbra:
        case SpuInsnId::hbrr:
            if (!drop_hints_) {
                auto *ins = emit(Op::NOP, -1, {}, EW::W, "branch hint");
                ins->has_aux = true;
                ins->aux_str = ent.mnem;
            }
            return;
        case SpuInsnId::nop:
        case SpuInsnId::lnop:
            return;

        // Immediates & moves
        case SpuInsnId::ila: {
            uint32_t imm18 = ibits(word, 7, 24) & 0x3FFFFu;
            emit(Op::CONST, rt, {Operand::make_const(u128_t::repl(imm18, EW::W))});
            return;
        }
        case SpuInsnId::il: {
            int32_t imm16 = sign_ext32(ibits(word, 9, 24), 16);
            emit(Op::CONST, rt, {Operand::make_const(u128_t::repl(static_cast<uint64_t>(imm16), EW::W))});
            return;
        }
        case SpuInsnId::ilh: {
            uint32_t imm16 = ibits(word, 9, 24) & 0xFFFFu;
            emit(Op::CONST, rt, {Operand::make_const(u128_t::repl(imm16, EW::H))});
            return;
        }
        case SpuInsnId::ilhu: {
            uint32_t imm16 = (ibits(word, 9, 24) & 0xFFFFu) << 16;
            emit(Op::CONST, rt, {Operand::make_const(u128_t::repl(imm16, EW::W))});
            return;
        }
        case SpuInsnId::iohl: {
            uint32_t imm16 = ibits(word, 9, 24) & 0xFFFFu;
            Operand c = mat_const(u128_t::repl(imm16, EW::W));
            emit(Op::OR, rt, {Operand::make_var(rt), c}, EW::W);
            return;
        }
        case SpuInsnId::fsmbi: {
            uint16_t imm16 = static_cast<uint16_t>(ibits(word, 9, 24) & 0xFFFFu);
            emit(Op::CONST, rt, {Operand::make_const(u128_t::fsmbi(imm16))}, EW::W, "fsmbi");
            return;
        }

        // RI10 (`ori rt, ra, 0` is architectural `lr rt, ra`!)
        case SpuInsnId::ori:
            if (ibits(word, 8, 17) == 0) emit(Op::MOV, rt, {Operand::make_var(ra)}, EW::Q);
            else emit_ri10(Op::OR, EW::W);
            return;
        case SpuInsnId::orhi:   emit_ri10(Op::OR, EW::H); return;
        case SpuInsnId::orbi:   emit_ri10(Op::OR, EW::B, true, false); return;
        case SpuInsnId::andi:   emit_ri10(Op::AND, EW::W); return;
        case SpuInsnId::andhi:  emit_ri10(Op::AND, EW::H); return;
        case SpuInsnId::andbi:  emit_ri10(Op::AND, EW::B, true, false); return;
        case SpuInsnId::xori:   emit_ri10(Op::XOR, EW::W); return;
        case SpuInsnId::xorhi:  emit_ri10(Op::XOR, EW::H); return;
        case SpuInsnId::xorbi:  emit_ri10(Op::XOR, EW::B, true, false); return;
        case SpuInsnId::ai:     emit_ri10(Op::ADD, EW::W); return;
        case SpuInsnId::ahi:    emit_ri10(Op::ADD, EW::H); return;
        case SpuInsnId::ceqi:   emit_ri10(Op::CMPEQ, EW::W); return;
        case SpuInsnId::ceqhi:  emit_ri10(Op::CMPEQ, EW::H); return;
        case SpuInsnId::ceqbi:  emit_ri10(Op::CMPEQ, EW::B, true, false); return;
        case SpuInsnId::cgti:   emit_ri10(Op::CMPGT, EW::W); return;
        case SpuInsnId::cgthi:  emit_ri10(Op::CMPGT, EW::H); return;
        case SpuInsnId::cgtbi:  emit_ri10(Op::CMPGT, EW::B, false, true); return;
        case SpuInsnId::clgti:  emit_ri10(Op::CMPGTU, EW::W); return;
        case SpuInsnId::clgthi: emit_ri10(Op::CMPGTU, EW::H); return;
        case SpuInsnId::clgtbi: emit_ri10(Op::CMPGTU, EW::B, true, false); return;
        case SpuInsnId::mpyi:   emit_ri10(Op::MPY, EW::W); return;
        case SpuInsnId::mpyui:  emit_ri10(Op::MPYU, EW::W); return;
        case SpuInsnId::sfi: {
            int32_t i10 = sign_ext32(ibits(word, 8, 17), 10);
            emit(Op::SUB, rt, {mat_const(u128_t::repl(static_cast<uint64_t>(i10), EW::W)), Operand::make_var(ra)}, EW::W);
            return;
        }
        case SpuInsnId::sfhi: {
            int32_t i10 = sign_ext32(ibits(word, 8, 17), 10);
            emit(Op::SUB, rt, {mat_const(u128_t::repl(static_cast<uint64_t>(i10), EW::H)), Operand::make_var(ra)}, EW::H);
            return;
        }

        // Subtracts (reversed operands: rb - ra)
        case SpuInsnId::sf:  emit(Op::SUB, rt, {Operand::make_var(rb), Operand::make_var(ra)}, EW::W); return;
        case SpuInsnId::sfh: emit(Op::SUB, rt, {Operand::make_var(rb), Operand::make_var(ra)}, EW::H); return;
        case SpuInsnId::sfx: emit(Op::SUBX, rt, {Operand::make_var(rb), Operand::make_var(ra), Operand::make_var(rt)}, EW::W); return;

        // RR binary
        case SpuInsnId::a:       emit_rr(Op::ADD, EW::W); return;
        case SpuInsnId::ah:      emit_rr(Op::ADD, EW::H); return;
        case SpuInsnId::and_:    emit_rr(Op::AND, EW::W); return;
        case SpuInsnId::or_:     emit_rr(Op::OR, EW::W); return;
        case SpuInsnId::xor_:    emit_rr(Op::XOR, EW::W); return;
        case SpuInsnId::nand:    emit_rr(Op::NAND, EW::W); return;
        case SpuInsnId::nor:     emit_rr(Op::NOR, EW::W); return;
        case SpuInsnId::eqv:     emit_rr(Op::EQV, EW::W); return;
        case SpuInsnId::andc:    emit_rr(Op::ANDC, EW::W); return;
        case SpuInsnId::orc:     emit_rr(Op::ORC, EW::W); return;
        case SpuInsnId::cg:      emit_rr(Op::CG, EW::W); return;
        case SpuInsnId::bg:      emit_rr(Op::BG, EW::W); return;
        case SpuInsnId::absdb:   emit_rr(Op::ABSDB, EW::B); return;
        case SpuInsnId::avgb:    emit_rr(Op::AVGB, EW::B); return;
        case SpuInsnId::sumb:    emit_rr(Op::SUMB, EW::B); return;
        case SpuInsnId::ceq:     emit_rr(Op::CMPEQ, EW::W); return;
        case SpuInsnId::ceqh:    emit_rr(Op::CMPEQ, EW::H); return;
        case SpuInsnId::ceqb:    emit_rr(Op::CMPEQ, EW::B); return;
        case SpuInsnId::cgt:     emit_rr(Op::CMPGT, EW::W); return;
        case SpuInsnId::cgth:    emit_rr(Op::CMPGT, EW::H); return;
        case SpuInsnId::cgtb:    emit_rr(Op::CMPGT, EW::B); return;
        case SpuInsnId::clgt:    emit_rr(Op::CMPGTU, EW::W); return;
        case SpuInsnId::clgth:   emit_rr(Op::CMPGTU, EW::H); return;
        case SpuInsnId::clgtb:   emit_rr(Op::CMPGTU, EW::B); return;
        case SpuInsnId::rot:     emit_rr(Op::ROL, EW::W); return;
        case SpuInsnId::roth:    emit_rr(Op::ROL, EW::H); return;
        case SpuInsnId::rotm:    emit_rr(Op::ROTM, EW::W); return;
        case SpuInsnId::rothm:   emit_rr(Op::ROTM, EW::H); return;
        case SpuInsnId::rotma:   emit_rr(Op::ROTMA, EW::W); return;
        case SpuInsnId::rotmah:  emit_rr(Op::ROTMA, EW::H); return;
        case SpuInsnId::shl:     emit_rr(Op::SHL, EW::W); return;
        case SpuInsnId::shlh:    emit_rr(Op::SHL, EW::H); return;
        case SpuInsnId::mpy:     emit_rr(Op::MPY, EW::W); return;
        case SpuInsnId::mpyu:    emit_rr(Op::MPYU, EW::W); return;
        case SpuInsnId::mpyh:    emit_rr(Op::MPYH, EW::W); return;
        case SpuInsnId::mpys:    emit_rr(Op::MPYS, EW::W); return;
        case SpuInsnId::mpyhh:   emit_rr(Op::MPYHH, EW::W); return;
        case SpuInsnId::mpyhhu:  emit_rr(Op::MPYHHU, EW::W); return;
        case SpuInsnId::fa:      emit_rr(Op::FADD, EW::W); return;
        case SpuInsnId::fs:      emit_rr(Op::FSUB, EW::W); return;
        case SpuInsnId::fm:      emit_rr(Op::FMUL, EW::W); return;
        case SpuInsnId::dfa:     emit_rr(Op::FADD, EW::D); return;
        case SpuInsnId::dfs:     emit_rr(Op::FSUB, EW::D); return;
        case SpuInsnId::dfm:     emit_rr(Op::FMUL, EW::D); return;
        case SpuInsnId::fceq:    emit_rr(Op::FCMPEQ, EW::W); return;
        case SpuInsnId::fcgt:    emit_rr(Op::FCMPGT, EW::W); return;
        case SpuInsnId::fcmeq:   emit_rr(Op::FCMPMEQ, EW::W); return;
        case SpuInsnId::fcmgt:   emit_rr(Op::FCMPMGT, EW::W); return;
        case SpuInsnId::dfceq:   emit_rr(Op::FCMPEQ, EW::D); return;
        case SpuInsnId::dfcgt:   emit_rr(Op::FCMPGT, EW::D); return;
        case SpuInsnId::dfcmeq:  emit_rr(Op::FCMPMEQ, EW::D); return;
        case SpuInsnId::dfcmgt:  emit_rr(Op::FCMPMGT, EW::D); return;
        case SpuInsnId::fi:      emit_rr(Op::FI, EW::W); return;
        case SpuInsnId::rotqbi:  emit_rr(Op::QROTBI, EW::Q); return;
        case SpuInsnId::rotqmbi: emit_rr(Op::QROTMBI, EW::Q); return;
        case SpuInsnId::shlqbi:  emit_rr(Op::QSHLBI, EW::Q); return;
        case SpuInsnId::rotqby:  emit_rr(Op::QROTBY, EW::Q); return;
        case SpuInsnId::rotqmby: emit_rr(Op::QROTMBY, EW::Q); return;
        case SpuInsnId::shlqby:  emit_rr(Op::QSHLBY, EW::Q); return;

        // RR accumulator (reads RT)
        case SpuInsnId::addx:    emit_rr_acc(Op::ADDX, EW::W); return;
        case SpuInsnId::cgx:     emit_rr_acc(Op::CGX, EW::W); return;
        case SpuInsnId::bgx:     emit_rr_acc(Op::BGX, EW::W); return;
        case SpuInsnId::mpyhha:  emit_rr_acc(Op::MPYHHA, EW::W); return;
        case SpuInsnId::mpyhhau: emit_rr_acc(Op::MPYHHAU, EW::W); return;
        case SpuInsnId::dfma:    emit_rr_acc(Op::FMA, EW::D); return;
        case SpuInsnId::dfms:    emit_rr_acc(Op::FMS, EW::D); return;
        case SpuInsnId::dfnms:   emit_rr_acc(Op::FNMS, EW::D); return;
        case SpuInsnId::dfnma:   emit_rr_acc(Op::FNMA, EW::D); return;

        // bybi
        case SpuInsnId::rotqbybi:  emit_bybi(Op::QROTBY); return;
        case SpuInsnId::rotqmbybi: emit_bybi(Op::QROTMBY); return;
        case SpuInsnId::shlqbybi:  emit_bybi(Op::QSHLBY); return;

        // Unary
        case SpuInsnId::clz:     emit_unary(Op::CLZ, EW::W); return;
        case SpuInsnId::cntb:    emit_unary(Op::CNTB, EW::B); return;
        case SpuInsnId::orx:     emit_unary(Op::ORX, EW::W); return;
        case SpuInsnId::xsbh:    emit_unary(Op::EXTS, EW::H); return;
        case SpuInsnId::xshw:    emit_unary(Op::EXTS, EW::W); return;
        case SpuInsnId::xswd:    emit_unary(Op::EXTS, EW::D); return;
        case SpuInsnId::gb:      emit_unary(Op::GB, EW::W); return;
        case SpuInsnId::gbh:     emit_unary(Op::GB, EW::H); return;
        case SpuInsnId::gbb:     emit_unary(Op::GB, EW::B); return;
        case SpuInsnId::fsm:     emit_unary(Op::FSM, EW::W); return;
        case SpuInsnId::fsmh:    emit_unary(Op::FSM, EW::H); return;
        case SpuInsnId::fsmb:    emit_unary(Op::FSM, EW::B); return;
        case SpuInsnId::frest:   emit_unary(Op::FREST, EW::W); return;
        case SpuInsnId::frsqest: emit_unary(Op::FRSQEST, EW::W); return;
        case SpuInsnId::fesd:    emit_unary(Op::FESD, EW::D); return;
        case SpuInsnId::frds:    emit_unary(Op::FRDS, EW::W); return;

        // RI7 shifts & quadword shifts
        case SpuInsnId::roti:     emit_shift_imm(EW::W, 1); return;
        case SpuInsnId::rothi:    emit_shift_imm(EW::H, 1); return;
        case SpuInsnId::rotmi:    emit_shift_imm(EW::W, 2); return;
        case SpuInsnId::rothmi:   emit_shift_imm(EW::H, 2); return;
        case SpuInsnId::rotmai:   emit_shift_imm(EW::W, 3); return;
        case SpuInsnId::rotmahi:  emit_shift_imm(EW::H, 3); return;
        case SpuInsnId::shli:     emit_shift_imm(EW::W, 0); return;
        case SpuInsnId::shlhi:    emit_shift_imm(EW::H, 0); return;
        case SpuInsnId::rotqbyi:  emit_quad_imm(Op::QROTBY,  true,  false, true); return;
        case SpuInsnId::rotqmbyi: emit_quad_imm(Op::QROTMBY, true,  true,  false); return;
        case SpuInsnId::shlqbyi:  emit_quad_imm(Op::QSHLBY,  true,  false, false); return;
        case SpuInsnId::rotqbii:  emit_quad_imm(Op::QROTBI,  false, false, true); return;
        case SpuInsnId::rotqmbii: emit_quad_imm(Op::QROTMBI, false, true,  false); return;
        case SpuInsnId::shlqbii:  emit_quad_imm(Op::QSHLBI,  false, false, false); return;

        // Shuffle control generators
        case SpuInsnId::cbd: emit_genctl_d(EW::B); return;
        case SpuInsnId::chd: emit_genctl_d(EW::H); return;
        case SpuInsnId::cwd: emit_genctl_d(EW::W); return;
        case SpuInsnId::cdd: emit_genctl_d(EW::D); return;
        case SpuInsnId::cbx: emit_genctl_x(EW::B); return;
        case SpuInsnId::chx: emit_genctl_x(EW::H); return;
        case SpuInsnId::cwx: emit_genctl_x(EW::W); return;
        case SpuInsnId::cdx: emit_genctl_x(EW::D); return;

        // Float-int conversions (RI8)
        case SpuInsnId::cflts:
        case SpuInsnId::cfltu:
        case SpuInsnId::csflt:
        case SpuInsnId::cuflt: {
            int bias = (ent.id == SpuInsnId::cflts || ent.id == SpuInsnId::cfltu) ? 173 : 155;
            int scale = bias - static_cast<int>(ibits(word, 10, 17));
            Op cop = (ent.id == SpuInsnId::cflts) ? Op::CFLTS :
                     (ent.id == SpuInsnId::cfltu) ? Op::CFLTU :
                     (ent.id == SpuInsnId::csflt) ? Op::CSFLT : Op::CUFLT;
            auto *ins = emit(cop, rt, {Operand::make_var(ra)}, EW::W);
            ins->has_aux = true;
            char sbuf[32];
            std::snprintf(sbuf, sizeof(sbuf), "scale=%d", scale);
            ins->aux_str = sbuf;
            return;
        }

        // Memory loads & stores
        case SpuInsnId::lqd: {
            int32_t off = sign_ext32(ibits(word, 8, 17), 10) << 4;
            emit(Op::LOADQ, rt, {Operand::make_var(regs::R_MEM), ea_displ(off)}, EW::Q);
            return;
        }
        case SpuInsnId::stqd: {
            int32_t off = sign_ext32(ibits(word, 8, 17), 10) << 4;
            emit(Op::STOREQ, regs::R_MEM, {Operand::make_var(regs::R_MEM), ea_displ(off), Operand::make_var(rt)}, EW::Q);
            return;
        }
        case SpuInsnId::lqx:
            emit(Op::LOADQ, rt, {Operand::make_var(regs::R_MEM), ea_index()}, EW::Q);
            return;
        case SpuInsnId::stqx:
            emit(Op::STOREQ, regs::R_MEM, {Operand::make_var(regs::R_MEM), ea_index(), Operand::make_var(rt)}, EW::Q);
            return;
        case SpuInsnId::lqa: {
            int32_t a16 = sign_ext32(ibits(word, 9, 24), 16) << 2;
            uint32_t tgt = static_cast<uint32_t>(wrap_ls(ea, a16, true));
            emit(Op::LOADQ, rt, {Operand::make_var(regs::R_MEM), mat_const(u128_t::from_word0(tgt))}, EW::Q);
            return;
        }
        case SpuInsnId::lqr: {
            int32_t r16 = sign_ext32(ibits(word, 9, 24), 16) << 2;
            uint32_t tgt = static_cast<uint32_t>(wrap_ls(ea, static_cast<int64_t>(ea) + r16, true));
            emit(Op::LOADQ, rt, {Operand::make_var(regs::R_MEM), mat_const(u128_t::from_word0(tgt))}, EW::Q);
            return;
        }
        case SpuInsnId::stqa: {
            int32_t a16 = sign_ext32(ibits(word, 9, 24), 16) << 2;
            uint32_t tgt = static_cast<uint32_t>(wrap_ls(ea, a16, true));
            emit(Op::STOREQ, regs::R_MEM,
                 {Operand::make_var(regs::R_MEM), mat_const(u128_t::from_word0(tgt)), Operand::make_var(rt)}, EW::Q);
            return;
        }
        case SpuInsnId::stqr: {
            int32_t r16 = sign_ext32(ibits(word, 9, 24), 16) << 2;
            uint32_t tgt = static_cast<uint32_t>(wrap_ls(ea, static_cast<int64_t>(ea) + r16, true));
            emit(Op::STOREQ, regs::R_MEM,
                 {Operand::make_var(regs::R_MEM), mat_const(u128_t::from_word0(tgt)), Operand::make_var(rt)}, EW::Q);
            return;
        }

        // Branches & calls
        case SpuInsnId::br: {
            int32_t r16 = sign_ext32(ibits(word, 9, 24), 16) << 2;
            auto *ins = emit(Op::JMP, -1, {}, EW::W);
            ins->has_aux = true;
            ins->aux_ea = wrap_ls(ea, static_cast<int64_t>(ea) + r16, false);
            return;
        }
        case SpuInsnId::bra: {
            int32_t a16 = sign_ext32(ibits(word, 9, 24), 16) << 2;
            auto *ins = emit(Op::JMP, -1, {}, EW::W);
            ins->has_aux = true;
            ins->aux_ea = wrap_ls(ea, a16, false);
            return;
        }
        case SpuInsnId::brsl: {
            int32_t r16 = sign_ext32(ibits(word, 9, 24), 16) << 2;
            emit_link(rt);
            auto *ins = emit(Op::CALL, regs::R_MEM, make_abi_call_srcs(), EW::W);
            ins->has_aux = true;
            ins->aux_ea = wrap_ls(ea, static_cast<int64_t>(ea) + r16, false);
            return;
        }
        case SpuInsnId::brasl: {
            int32_t a16 = sign_ext32(ibits(word, 9, 24), 16) << 2;
            emit_link(rt);
            auto *ins = emit(Op::CALL, regs::R_MEM, make_abi_call_srcs(), EW::W);
            ins->has_aux = true;
            ins->aux_ea = wrap_ls(ea, a16, false);
            return;
        }
        case SpuInsnId::bi: {
            if (ra == regs::LR) {
                emit(Op::RET, -1, make_abi_ret_srcs(), EW::W);
            } else {
                auto srcs = make_abi_call_srcs();
                srcs.insert(srcs.begin(), Operand::make_var(ra));
                emit(Op::IJMP, -1, std::move(srcs), EW::W);
            }
            return;
        }
        case SpuInsnId::iret:
            emit(Op::RET, -1, make_abi_ret_srcs(), EW::W, "interrupt return");
            return;
        case SpuInsnId::bisl: {
            emit_link(rt);
            auto srcs = make_abi_call_srcs();
            srcs.insert(srcs.begin(), Operand::make_var(ra));
            emit(Op::ICALL, regs::R_MEM, std::move(srcs), EW::W);
            return;
        }
        case SpuInsnId::brz:
        case SpuInsnId::brnz:
        case SpuInsnId::brhz:
        case SpuInsnId::brhnz: {
            int32_t r16 = sign_ext32(ibits(word, 9, 24), 16) << 2;
            auto *ins = emit(Op::CJMP, -1, {Operand::make_var(rt)}, EW::W);
            ins->has_aux = true;
            ins->aux_ea = wrap_ls(ea, static_cast<int64_t>(ea) + r16, false);
            ins->cond_kind = (ent.id == SpuInsnId::brz)  ? CondKind::Z :
                             (ent.id == SpuInsnId::brnz) ? CondKind::NZ :
                             (ent.id == SpuInsnId::brhz) ? CondKind::HZ : CondKind::HNZ;
            return;
        }
        case SpuInsnId::biz:
        case SpuInsnId::binz:
        case SpuInsnId::bihz:
        case SpuInsnId::bihnz: {
            auto *ins = emit(Op::CIJMP, -1, {Operand::make_var(rt), Operand::make_var(ra)}, EW::W);
            ins->has_aux = true;
            ins->cond_kind = (ent.id == SpuInsnId::biz)  ? CondKind::Z :
                             (ent.id == SpuInsnId::binz) ? CondKind::NZ :
                             (ent.id == SpuInsnId::bihz) ? CondKind::HZ : CondKind::HNZ;
            return;
        }
        case SpuInsnId::bisled: {
            emit_link(rt);
            int c = alloc_tmp();
            auto *ev = emit(Op::INTRINSIC, c, {Operand::make_var(regs::R_CH)}, EW::W, "pending external-data event");
            ev->has_aux = true;
            ev->aux_str = "external_event";
            auto *br = emit(Op::CIJMP, -1, {Operand::make_var(c), Operand::make_var(ra)}, EW::W,
                            "branch if the external condition holds");
            br->has_aux = true;
            br->cond_kind = CondKind::NZ;
            return;
        }

        // Halts (RT is false target; operands are RA and RB / I10)
        case SpuInsnId::heq:
        case SpuInsnId::hgt:
        case SpuInsnId::hlgt: {
            auto *ins = emit(Op::HALT, -1, {Operand::make_var(ra), Operand::make_var(rb)}, EW::W);
            ins->has_aux = true;
            ins->aux_str = (ent.id == SpuInsnId::heq) ? "eq" : (ent.id == SpuInsnId::hgt) ? "gt" : "lgt";
            return;
        }
        case SpuInsnId::heqi:
        case SpuInsnId::hgti:
        case SpuInsnId::hlgti: {
            int32_t i10 = sign_ext32(ibits(word, 8, 17), 10);
            Operand c = mat_const(u128_t::repl(static_cast<uint64_t>(i10), EW::W));
            auto *ins = emit(Op::HALT, -1, {Operand::make_var(ra), c}, EW::W);
            ins->has_aux = true;
            ins->aux_str = (ent.id == SpuInsnId::heqi) ? "eq" : (ent.id == SpuInsnId::hgti) ? "gt" : "lgt";
            return;
        }

        // Channels, SPRs, system
        case SpuInsnId::stop: {
            if (ibits(word, 11, 17) != 0) {
                unhandled_["undecodable"]++;
                auto *ins = emit(Op::INTRINSIC, -1, {}, EW::Q);
                ins->has_aux = true;
                ins->aux_str = "undecodable";
                return;
            }
            uint32_t code = ibits(word, 18, 31);
            auto *ins = emit(Op::STOP, -1, make_abi_ret_srcs(), EW::W);
            ins->has_aux = true;
            char sbuf[32];
            std::snprintf(sbuf, sizeof(sbuf), "0x%X", code);
            ins->aux_str = sbuf;
            return;
        }
        case SpuInsnId::stopd: {
            auto *ins = emit(Op::STOP, -1, make_abi_ret_srcs(), EW::W);
            ins->has_aux = true;
            ins->aux_str = "stopd";
            return;
        }
        case SpuInsnId::sync:
        case SpuInsnId::dsync: {
            auto *ins = emit(Op::SYNC, regs::R_MEM, {Operand::make_var(regs::R_MEM)}, EW::W);
            ins->has_aux = true;
            ins->aux_str = (ent.id == SpuInsnId::dsync) ? "dsync" : "sync";
            return;
        }
        case SpuInsnId::rdch: {
            auto *ins = emit(Op::RDCH, rt, {Operand::make_var(regs::R_CH)}, EW::Q);
            ins->has_aux = true;
            ins->aux_int = ra;
            auto *syn = emit(Op::SYNC, regs::R_CH, {Operand::make_var(regs::R_CH)}, EW::W);
            syn->has_aux = true;
            syn->aux_str = "after rdch " + std::to_string(ra);
            return;
        }
        case SpuInsnId::rchcnt: {
            auto *ins = emit(Op::RCHCNT, rt, {Operand::make_var(regs::R_CH)}, EW::Q);
            ins->has_aux = true;
            ins->aux_int = ra;
            return;
        }
        case SpuInsnId::wrch: {
            auto *ins = emit(Op::WRCH, regs::R_CH, {Operand::make_var(regs::R_CH), Operand::make_var(rt)}, EW::Q);
            ins->has_aux = true;
            ins->aux_int = ra;
            return;
        }
        case SpuInsnId::mfspr: {
            auto *ins = emit(Op::MFSPR, rt, {Operand::make_var(regs::R_SPR)}, EW::Q);
            ins->has_aux = true;
            ins->aux_int = ra;
            return;
        }
        case SpuInsnId::mtspr: {
            auto *ins = emit(Op::MTSPR, regs::R_SPR, {Operand::make_var(regs::R_SPR), Operand::make_var(rt)}, EW::Q);
            ins->has_aux = true;
            ins->aux_int = ra;
            return;
        }
        case SpuInsnId::fscrrd: {
            auto *ins = emit(Op::INTRINSIC, rt, {Operand::make_var(regs::R_SPR)}, EW::Q);
            ins->has_aux = true;
            ins->aux_str = "fscrrd";
            return;
        }
        case SpuInsnId::fscrwr: {
            auto *ins = emit(Op::INTRINSIC, regs::R_SPR,
                             {Operand::make_var(regs::R_SPR), Operand::make_var(ra)}, EW::Q);
            ins->has_aux = true;
            ins->aux_str = "fscrwr";
            return;
        }
        case SpuInsnId::dftsv: {
            uint32_t sel = ibits(word, 11, 17) & 0x7Fu;
            auto *ins = emit(Op::DFTSV, rt, {Operand::make_var(ra)}, EW::D);
            ins->has_aux = true;
            ins->aux_str = dftsv_classes(sel);
            return;
        }
        default:
            break;
    }

    const char *nm = ent.mnem ? ent.mnem : "unknown";
    unhandled_[nm]++;
    auto *ins = emit(Op::INTRINSIC, -1, {}, EW::Q);
    ins->has_aux = true;
    ins->aux_str = nm;
}

std::vector<Block *> Lifter::lift_ranges(const IDatabaseProvider &db,
                                         Function &func,
                                         const std::vector<std::pair<uint64_t, uint64_t>> &ranges) {
    std::vector<Block *> out;
    out.reserve(ranges.size());
    for (const auto &rng : ranges) {
        Block *b = func.new_block(rng.first, rng.second);
        out.push_back(b);
        for (uint64_t ea = rng.first; ea < rng.second; ea += 4) {
            uint32_t word = 0;
            if (!db.read_u32_be(ea, &word)) {
                auto ins = func.make_insn(Op::INTRINSIC, EW::Q, ea);
                ins->has_aux = true;
                ins->aux_str = "undecodable";
                b->add(std::move(ins));
                continue;
            }
            lift_word(func, *b, ea, word);
        }
    }
    return out;
}

} // namespace spudec
