#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

namespace spudec {
namespace channels {

inline const char *name(int ch) {
    switch (ch) {
        case 0:  return "SPU_RdEventStat";
        case 1:  return "SPU_WrEventMask";
        case 2:  return "SPU_WrEventAck";
        case 3:  return "SPU_RdSigNotify1";
        case 4:  return "SPU_RdSigNotify2";
        case 7:  return "SPU_WrDec";
        case 8:  return "SPU_RdDec";
        case 9:  return "MFC_WrMSSyncReq";
        case 11: return "SPU_RdEventMask";
        case 12: return "MFC_RdTagMask";
        case 13: return "SPU_RdMachStat";
        case 14: return "SPU_WrSRR0";
        case 15: return "SPU_RdSRR0";
        case 16: return "MFC_LSA";
        case 17: return "MFC_EAH";
        case 18: return "MFC_EAL";
        case 19: return "MFC_Size";
        case 20: return "MFC_TagID";
        case 21: return "MFC_Cmd";
        case 22: return "MFC_WrTagMask";
        case 23: return "MFC_WrTagUpdate";
        case 24: return "MFC_RdTagStat";
        case 25: return "MFC_RdListStallStat";
        case 26: return "MFC_WrListStallAck";
        case 27: return "MFC_RdAtomicStat";
        case 28: return "SPU_WrOutMbox";
        case 29: return "SPU_RdInMbox";
        case 30: return "SPU_WrOutIntrMbox";
        // PS3 isolation-mode channels
        case 64: return "SPU_IsoCntl";
        case 65: return "SPU_IsoStat";
        case 66: return "SPU_IsoRootKey";
        case 67: return "SPU_IsoKey";
        case 68: return "SPU_IsoIdent";
        default: return nullptr;
    }
}

inline std::string label(int ch) {
    const char *nm = name(ch);
    if (nm) return nm;
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%d", ch);
    return buf;
}

constexpr inline bool is_iso(int ch) {
    return ch >= 64 && ch <= 68;
}

inline const char *mfc_cmd(uint32_t val) {
    switch (val & 0xFFu) {
        case 0x20: return "PUT";
        case 0x21: return "PUTS";
        case 0x22: return "PUTR";
        case 0x24: return "PUTB";
        case 0x25: return "PUTBS";
        case 0x26: return "PUTRB";
        case 0x28: return "PUTF";
        case 0x29: return "PUTFS";
        case 0x2A: return "PUTRF";
        case 0x40: return "GET";
        case 0x41: return "GETS";
        case 0x44: return "GETB";
        case 0x45: return "GETBS";
        case 0x48: return "GETF";
        case 0x49: return "GETFS";
        case 0x50: return "PUTL";
        case 0x54: return "PUTLB";
        case 0x58: return "PUTLF";
        case 0x60: return "GETL";
        case 0x64: return "GETLB";
        case 0x68: return "GETLF";
        case 0xA0: return "SNDSIG";
        case 0xA4: return "SNDSIGB";
        case 0xA8: return "SNDSIGF";
        case 0xB0: return "GETLLAR";
        case 0xB4: return "PUTLLC";
        case 0xB8: return "PUTLLUC";
        case 0xBC: return "PUTQLLUC";
        case 0xC0: return "MFCEIEIO";
        case 0xC8: return "MFCSYNC";
        case 0xCC: return "BARRIER";
        default:   return nullptr;
    }
}

} // namespace channels
} // namespace spudec
