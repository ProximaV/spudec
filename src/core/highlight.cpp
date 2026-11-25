#include "spudec/highlight.hpp"
#include <cctype>
#include <cstdio>
#include <unordered_set>

namespace spudec {
namespace highlight {

namespace {

bool is_ident_start(char c) {
    unsigned char u = static_cast<unsigned char>(c);
    return std::isalpha(u) || c == '_' || c == '$';
}

bool is_ident_cont(char c) {
    unsigned char u = static_cast<unsigned char>(c);
    return std::isalnum(u) || c == '_' || c == '$';
}

bool is_word_char(char c) {
    unsigned char u = static_cast<unsigned char>(c);
    return std::isalnum(u) || c == '_';
}

bool is_hex_digit(char c) {
    unsigned char u = static_cast<unsigned char>(c);
    return std::isxdigit(u) != 0;
}

bool is_int_suffix(char c) {
    return c == 'u' || c == 'U' || c == 'l' || c == 'L';
}

const std::unordered_set<std::string> &c_keywords() {
    static const std::unordered_set<std::string> s = {
        "if", "else", "while", "do", "for", "return", "break", "continue",
        "goto", "switch", "case", "default", "sizeof",
    };
    return s;
}

const std::unordered_set<std::string> &c_types() {
    static const std::unordered_set<std::string> s = {
        "void", "char", "short", "int", "long", "unsigned", "signed",
        "float", "double", "bool", "_Bool", "const", "volatile", "struct", "union", "enum",
        "qword", "qword_unaligned", "qword2", "vec_ullong4", "u8", "u16", "u32", "u64",
        "s8", "s16", "s32", "s64", "size_t", "ssize_t",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "int8_t", "int16_t", "int32_t", "int64_t", "uintptr_t", "intptr_t",
        "__int8", "__int16", "__int32", "__int64",
        "BYTE", "WORD", "DWORD", "QWORD", "BOOL",
    };
    return s;
}

bool starts_with(const std::string &s, const char *pfx) {
    size_t n = std::strlen(pfx);
    return s.size() >= n && s.compare(0, n, pfx) == 0;
}

char ident_color(const std::string &text, const std::string &line, size_t after) {
    size_t dot = text.find('.');
    std::string base = (dot == std::string::npos) ? text : text.substr(0, dot);
    if (c_keywords().count(base) > 0) return TAG_KEYWORD;
    if (c_types().count(base) > 0 || starts_with(base, "vec_")) return TAG_TYPE;
    if (starts_with(base, "loc_") || starts_with(base, "def_") ||
        starts_with(base, "jpt_") || starts_with(base, "sub_")) {
        return TAG_CREFTAIL;
    }
    size_t p = after;
    while (p < line.size() && std::isspace(static_cast<unsigned char>(line[p]))) ++p;
    if (p < line.size() && line[p] == '(') return TAG_CNAME;
    return TAG_REG;
}

// Try to match binary, hex, or decimal literal starting at `pos`. Returns end pos or 0 on failure.
size_t match_number(const std::string &line, size_t pos) {
    const size_t n = line.size();
    size_t p = pos;
    if (p < n && line[p] == '-') {
        ++p;
    } else if (p > 0 && is_word_char(line[p - 1])) {
        return 0;
    }
    if (p >= n || !std::isdigit(static_cast<unsigned char>(line[p]))) {
        return 0;
    }

    // Binary: 0[bB][01]+[uUlL]{0,3}\b
    if (line[p] == '0' && p + 2 < n && (line[p + 1] == 'b' || line[p + 1] == 'B') &&
        (line[p + 2] == '0' || line[p + 2] == '1')) {
        size_t q = p + 2;
        while (q < n && (line[q] == '0' || line[q] == '1')) ++q;
        int suf = 0;
        while (q < n && suf < 3 && is_int_suffix(line[q])) { ++q; ++suf; }
        if (q == n || !is_word_char(line[q])) return q;
    }

    // Hex: 0[xX][0-9A-Fa-f]+[uUlL]{0,3}
    if (line[p] == '0' && p + 2 < n && (line[p + 1] == 'x' || line[p + 1] == 'X') &&
        is_hex_digit(line[p + 2])) {
        size_t q = p + 2;
        while (q < n && is_hex_digit(line[q])) ++q;
        int suf = 0;
        while (q < n && suf < 3 && is_int_suffix(line[q])) { ++q; ++suf; }
        return q;
    }

    // Decimal: \d+[uUlL]{0,3}\b
    size_t q = p;
    while (q < n && std::isdigit(static_cast<unsigned char>(line[q]))) ++q;
    int suf = 0;
    while (q < n && suf < 3 && is_int_suffix(line[q])) { ++q; ++suf; }
    if (q == n || !is_word_char(line[q])) return q;
    return 0;
}

} // namespace

std::string colstr(const std::string &text, char tag) {
    std::string out;
    out.reserve(text.size() + 4);
    out.push_back(K_COLOR_ON);
    out.push_back(tag);
    for (char c : text) {
        if (c >= K_COLOR_ON && c <= K_COLOR_INV) {
            out.push_back(K_COLOR_ESC);
        }
        out.push_back(c);
    }
    out.push_back(K_COLOR_OFF);
    out.push_back(tag);
    return out;
}

std::string make_addr_tag(uint64_t anchor_val) {
    char buf[20];
    buf[0] = K_COLOR_ON;
    buf[1] = TAG_ADDR;
    std::snprintf(buf + 2, sizeof(buf) - 2, "%016llX",
                  static_cast<unsigned long long>(anchor_val));
    return std::string(buf, 18);
}

std::string strip_tags(const std::string &colored) {
    std::string out;
    out.reserve(colored.size());
    const size_t n = colored.size();
    size_t i = 0;
    while (i < n) {
        char c = colored[i];
        if (c == K_COLOR_ON) {
            if (i + 1 < n) {
                char tag = colored[i + 1];
                if (tag == TAG_ADDR && i + 18 <= n) {
                    i += 18;
                    continue;
                }
                i += 2;
                continue;
            }
            ++i;
        } else if (c == K_COLOR_OFF) {
            i += (i + 1 < n) ? 2 : 1;
        } else if (c == K_COLOR_ESC) {
            if (i + 1 < n) {
                out.push_back(colored[i + 1]);
                i += 2;
            } else {
                ++i;
            }
        } else if (c == K_COLOR_INV) {
            ++i;
        } else {
            out.push_back(c);
            ++i;
        }
    }
    return out;
}

std::string extract_word_at(const std::string &plain_line, int col) {
    if (plain_line.empty() || col < 0 || col >= static_cast<int>(plain_line.size())) {
        return "";
    }
    auto is_tok = [](char c) -> bool {
        unsigned char u = static_cast<unsigned char>(c);
        return std::isalnum(u) || c == '_' || c == '$';
    };
    int pos = col;
    if (!is_tok(plain_line[pos])) {
        if (pos > 0 && is_tok(plain_line[pos - 1])) {
            --pos;
        } else {
            return "";
        }
    }
    int b = pos, e = pos;
    while (b > 0 && is_tok(plain_line[b - 1])) --b;
    while (e + 1 < static_cast<int>(plain_line.size()) && is_tok(plain_line[e + 1])) ++e;
    return plain_line.substr(static_cast<size_t>(b), static_cast<size_t>(e - b + 1));
}

std::optional<uint64_t> extract_addr_anchor_at(const std::string &colored_line, int visible_col) {
    std::optional<uint64_t> cur_anchor;
    int vis = 0;
    const size_t n = colored_line.size();
    size_t i = 0;
    while (i < n) {
        char c = colored_line[i];
        if (c == K_COLOR_ON && i + 1 < n) {
            char tag = colored_line[i + 1];
            if (tag == TAG_ADDR && i + 18 <= n) {
                std::string hex16 = colored_line.substr(i + 2, 16);
                cur_anchor = std::strtoull(hex16.c_str(), nullptr, 16);
                i += 18;
                continue;
            }
            i += 2;
            continue;
        }
        if (c == K_COLOR_OFF) {
            i += (i + 1 < n) ? 2 : 1;
            continue;
        }
        if (c == K_COLOR_ESC) {
            if (vis == visible_col) return cur_anchor;
            ++vis;
            i += (i + 1 < n) ? 2 : 1;
            continue;
        }
        if (c == K_COLOR_INV) {
            ++i;
            continue;
        }
        if (vis == visible_col) return cur_anchor;
        ++vis;
        ++i;
    }
    return cur_anchor;
}

std::string colorize(const std::string &line, const std::string &highlight_ident) {
    if (line.empty()) return line;

    size_t first_non_ws = 0;
    while (first_non_ws < line.size() && std::isspace(static_cast<unsigned char>(line[first_non_ws]))) {
        ++first_non_ws;
    }
    if (highlight_ident.empty() && first_non_ws + 1 < line.size() &&
        line[first_non_ws] == '/' && line[first_non_ws + 1] == '/') {
        return colstr(line, TAG_AUTOCMT);
    }

    std::string out;
    out.reserve(line.size() * 2 + 16);
    const size_t n = line.size();
    size_t pos = 0;

    while (pos < n) {
        char c = line[pos];

        // 1. Whitespace
        if (std::isspace(static_cast<unsigned char>(c))) {
            size_t start = pos++;
            while (pos < n && std::isspace(static_cast<unsigned char>(line[pos]))) ++pos;
            out.append(line, start, pos - start);
            continue;
        }

        // 2. Line comment //.*
        if (c == '/' && pos + 1 < n && line[pos + 1] == '/') {
            out += colstr(line.substr(pos), TAG_AUTOCMT);
            break;
        }

        // 3. Placeholder <[A-Za-z][^<>]*>
        if (c == '<' && pos + 1 < n && std::isalpha(static_cast<unsigned char>(line[pos + 1]))) {
            size_t q = pos + 2;
            while (q < n && line[q] != '<' && line[q] != '>') ++q;
            if (q < n && line[q] == '>') {
                out += colstr(line.substr(pos, q - pos + 1), TAG_MACRO);
                pos = q + 1;
                continue;
            }
        }

        // 4. String literal "(?:[^"\\]|\\.)*"
        if (c == '"') {
            size_t q = pos + 1;
            bool closed = false;
            while (q < n) {
                if (line[q] == '\\' && q + 1 < n) {
                    q += 2;
                    continue;
                }
                if (line[q] == '"') {
                    ++q;
                    closed = true;
                    break;
                }
                ++q;
            }
            if (closed) {
                out += colstr(line.substr(pos, q - pos), TAG_STRING);
                pos = q;
                continue;
            }
        }

        // 5. Char literal '(?:[^'\\]|\\.)+'
        if (c == '\'') {
            size_t q = pos + 1;
            bool closed = false;
            size_t inner = 0;
            while (q < n) {
                if (line[q] == '\\' && q + 1 < n) {
                    q += 2;
                    ++inner;
                    continue;
                }
                if (line[q] == '\'') {
                    ++q;
                    closed = (inner > 0);
                    break;
                }
                ++q;
                ++inner;
            }
            if (closed) {
                out += colstr(line.substr(pos, q - pos), TAG_CHAR);
                pos = q;
                continue;
            }
        }

        // 6. Number literal (bin / hex / dec)
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) {
            size_t num_end = match_number(line, pos);
            if (num_end > pos) {
                out += colstr(line.substr(pos, num_end - pos), TAG_NUMBER);
                pos = num_end;
                continue;
            }
        }

        // 7. Identifier [A-Za-z_$][A-Za-z_0-9$]*(?:\.[A-Za-z0-9]+)?
        if (is_ident_start(c)) {
            size_t q = pos + 1;
            while (q < n && is_ident_cont(line[q])) ++q;
            if (q + 1 < n && line[q] == '.' && std::isalnum(static_cast<unsigned char>(line[q + 1]))) {
                // Only treat `.suffix` as an op-width suffix (like `add.w(` or `gb.w(`) if followed by '('
                // or if it's a dotted opcode! Wait: in highlight.py, _TOK matched `(?:\.[A-Za-z0-9]+)?`
                // unconditionally, so let's check: in highlight.py `s.field` matched as `s.field`!
                size_t r = q + 1;
                while (r < n && std::isalnum(static_cast<unsigned char>(line[r]))) ++r;
                q = r;
            }
            std::string tok = line.substr(pos, q - pos);
            pos = q;
            size_t dot = tok.find('.');
            std::string base = (dot == std::string::npos) ? tok : tok.substr(0, dot);
            if (!highlight_ident.empty() && (tok == highlight_ident || base == highlight_ident)) {
                out += colstr(tok, TAG_EXTRA);
            } else {
                out += colstr(tok, ident_color(tok, line, pos));
            }
            continue;
        }

        // 8. Punctuation / operator
        out += colstr(std::string(1, c), TAG_SYMBOL);
        ++pos;
    }

    return out;
}

std::vector<std::string> colorize_all(const std::vector<std::string> &lines,
                                      const std::string &highlight_ident) {
    std::vector<std::string> out;
    out.reserve(lines.size());
    for (const auto &ln : lines) {
        out.push_back(colorize(ln, highlight_ident));
    }
    return out;
}

} // namespace highlight
} // namespace spudec
