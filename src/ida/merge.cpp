#include <ida.hpp>
#include <idp.hpp>
#include <mergemod.hpp>

#include "merge.hpp"
#include "db.hpp"

namespace spudec {

namespace {

static const idbattr_info_t kSpudecIdbAttrs[] = {
    IDI_ALTENTRY(0, atag, sizeof(uval_t), 0, nullptr, "Sync with disassembly"),
    IDI_ALTENTRY(1, atag, sizeof(uval_t), 0, nullptr, "Hide scalar casts"),
};

SIMPLE_MODDATA_DIFF_HELPER(
    g_spudec_modmerger_helper,
    "SPU Decompiler options",
    idadb::SPUDEC_NODE_NAME,
    kSpudecIdbAttrs);

static const merge_node_info_t kSpudecMergeNodes[] = {
    {"Function annotations", stag, NDS_IS_STR, nullptr},
};

} // namespace

void register_spudec_merge_handlers(merge_data_t &md, int moddata_id) {
    if (moddata_id < 0) return;
    DEFINE_PLUGIN_MH_PARAMS("SPU Decompiler (spudec)", MH_UI_COLONNAME);
    create_std_modmerge_handlers(mhp, moddata_id, g_spudec_modmerger_helper);

    mhp.mh_flags = MH_UI_COMMANAME | MH_UI_NODETAILS;
    create_nodeval_merge_handlers(
        nullptr,
        mhp,
        moddata_id,
        idadb::SPUDEC_NODE_NAME,
        kSpudecMergeNodes,
        qnumber(kSpudecMergeNodes));
}

} // namespace spudec
