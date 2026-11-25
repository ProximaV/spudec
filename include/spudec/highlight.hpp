#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace spudec {
namespace highlight {

// Exact IDA 9.5 color escape & tag constants from <lines.hpp> so spudec_core
// produces native IDA tagged strings without requiring ida.lib in standalone tests.
constexpr char K_COLOR_ON       = '\x01';
constexpr char K_COLOR_OFF      = '\x02';
constexpr char K_COLOR_ESC      = '\x03';
constexpr char K_COLOR_INV      = '\x04';

constexpr char TAG_DEFAULT      = '\x01';
constexpr char TAG_REGCMT       = '\x02';
constexpr char TAG_AUTOCMT      = '\x04';
constexpr char TAG_SYMBOL       = '\x09';
constexpr char TAG_CHAR         = '\x0A';
constexpr char TAG_STRING       = '\x0B';
constexpr char TAG_NUMBER       = '\x0C';
constexpr char TAG_CREFTAIL     = '\x10';
constexpr char TAG_ERROR        = '\x12';
constexpr char TAG_EXTRA        = '\x15';
constexpr char TAG_TYPE         = '\x17'; // SCOLOR_HIDNAME == SCOLOR_TYPE
constexpr char TAG_LOCNAME      = '\x19';
constexpr char TAG_MACRO        = '\x1C';
constexpr char TAG_KEYWORD      = '\x20';
constexpr char TAG_REG          = '\x21';
constexpr char TAG_CNAME        = '\x25';
constexpr char TAG_ADDR         = '\x28'; // COLOR_ADDR (16 hex digits, no COLOR_OFF)

std::string colstr(const std::string &text, char tag);
std::string make_addr_tag(uint64_t anchor_val);
std::string strip_tags(const std::string &colored);

// Extract identifier or dotted token under visible column `col` on a plain (uncolored) line.
std::string extract_word_at(const std::string &plain_line, int col);

// Extract the nearest preceding COLOR_ADDR 64-bit anchor at visible column `col` on a colored line.
std::optional<uint64_t> extract_addr_anchor_at(const std::string &colored_line, int visible_col);

// Token-level C syntax highlighter matching highlight.py.
std::string colorize(const std::string &line, const std::string &highlight_ident = "");
std::vector<std::string> colorize_all(const std::vector<std::string> &lines,
                                      const std::string &highlight_ident = "");

} // namespace highlight
} // namespace spudec
