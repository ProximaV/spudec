#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include "ir.hpp"

namespace spudec {
namespace types {

enum class TyKind : uint8_t {
    UNK = 0,
    INT = 1,
    FLT = 2,
    PTR = 3,
    VEC = 4,
};

const char *kind_name(TyKind k);

struct Ty {
    TyKind kind = TyKind::UNK;
    int width = 0; // bytes: 0, 1, 2, 4, 8, 16
    std::optional<bool> is_signed;
    std::shared_ptr<const Ty> pointee;
    bool ambiguous = false;

    Ty() = default;
    Ty(TyKind k, int w = 0, std::optional<bool> s = std::nullopt,
       std::shared_ptr<const Ty> pt = nullptr, bool amb = false)
        : kind(k), width(w), is_signed(s), pointee(std::move(pt)), ambiguous(amb) {}

    bool same_key(const Ty &o) const;
    bool operator==(const Ty &o) const { return same_key(o); }
    bool operator!=(const Ty &o) const { return !same_key(o); }

    std::string str() const;
};

inline Ty scalar_ty(int width, std::optional<bool> is_signed = std::nullopt) {
    return Ty(TyKind::INT, width, is_signed);
}

inline Ty ptr_to(const Ty &pt) {
    return Ty(TyKind::PTR, 4, false, std::make_shared<Ty>(pt));
}

Ty join(const Ty &a, const Ty &b, int *contradictions = nullptr);
int width_from_demand(uint16_t mask);

struct TypeStats {
    int contradictions = 0;
    int ambiguous = 0;
    int strings = 0;
    std::unordered_map<std::string, int> kinds;
};

class TypeMap {
public:
    TypeMap() = default;
    TypeMap(std::unordered_map<VarKey, Ty> tys, std::unordered_map<VarKey, VarKey> rep)
        : tys_(std::move(tys)), rep_(std::move(rep)) {}

    const Ty *of(VarKey key) const {
        auto rit = rep_.find(key);
        VarKey rk = (rit != rep_.end()) ? rit->second : key;
        auto it = tys_.find(rk);
        return (it != tys_.end()) ? &it->second : nullptr;
    }

    const Ty *of_var(const Operand &v) const {
        return v.is_var() ? of(v.key()) : nullptr;
    }

    size_t size() const { return tys_.size(); }
    std::unordered_map<std::string, int> counts() const;

private:
    std::unordered_map<VarKey, Ty> tys_;
    std::unordered_map<VarKey, VarKey> rep_;
};

std::pair<TypeMap, TypeStats> infer(
    const Function &func,
    const std::unordered_map<VarKey, uint16_t> &demand,
    const std::vector<std::vector<VarKey>> &groups = {},
    const std::function<bool(const u128_t &)> &is_string = nullptr);

} // namespace types
} // namespace spudec
