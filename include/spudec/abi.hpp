#pragma once

#include <optional>
#include <string>
#include <vector>
#include "ir.hpp"

namespace spudec {
namespace abi {

struct Param {
    std::string name;
    std::string type_str = "qword";
    std::string location = "r3";
};

struct FunctionSig {
    std::string name;
    std::string ret_type = "void";
    std::string ret_expr;
    std::vector<Param> params;

    std::string format_signature(const std::string &override_name = "") const;
};

std::optional<FunctionSig> parse_proto(const std::string &proto_str,
                                       const std::string &default_name = "sub_unknown");

std::string format_proto(const std::string &ret_type,
                         const std::string &name,
                         const std::vector<Param> &params);

std::string sanitize_decl_for_ida(const std::string &proto_str,
                                  bool replace_this = false,
                                  bool replace_qualified_types = false);

// Insert UNDEF clobbers for volatile registers written by `func` after every CALL/ICALL.
int insert_call_clobbers(Function &func);

} // namespace abi
} // namespace spudec
