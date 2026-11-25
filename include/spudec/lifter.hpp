#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "ir.hpp"
#include "database.hpp"

namespace spudec {

constexpr uint32_t kDefaultLslr = 0x3FFFFu;
constexpr uint32_t kLsQuadMask  = 0x3FFF0u;

class Lifter {
public:
    explicit Lifter(bool drop_hints = true, int n_arg_regs = 8, int n_ret_regs = 8, uint32_t lslr = kDefaultLslr);

    // Lift a single 32-bit big-endian SPU instruction word at `ea` into `blk`.
    void lift_word(Function &func, Block &blk, uint64_t ea, uint32_t word);

    // Lift a list of (start_ea, end_ea) block ranges from `db` into `func`.
    std::vector<Block *> lift_ranges(const IDatabaseProvider &db,
                                     Function &func,
                                     const std::vector<std::pair<uint64_t, uint64_t>> &ranges);

    std::vector<Operand> make_abi_call_srcs() const;
    std::vector<Operand> make_abi_ret_srcs() const;

    const std::vector<int> &abi_args() const { return abi_args_; }
    const std::vector<int> &ret_regs() const { return ret_regs_; }
    const std::unordered_map<std::string, int> &unhandled() const { return unhandled_; }

    // Total number of distinct architectural SPU mnemonics modelled in the opcode table.
    static int modelled_mnemonic_count();

private:
    bool drop_hints_ = true;
    uint32_t lslr_ = kDefaultLslr;
    int ntmp_ = 0;
    std::vector<int> abi_args_;
    std::vector<int> ret_regs_;
    std::unordered_map<std::string, int> unhandled_;

    int alloc_tmp() { return regs::NREG + (ntmp_++); }
    uint64_t wrap_ls(uint64_t base_ea, int64_t target, bool quad_align) const;
};

namespace cfg {

// Build a pre-SSA CFG Function from `db` at `func_ea`. Returns nullptr on failure.
std::unique_ptr<Function> build(const IDatabaseProvider &db,
                                uint64_t func_ea,
                                bool drop_hints = true,
                                std::string *out_err = nullptr);

} // namespace cfg
} // namespace spudec
