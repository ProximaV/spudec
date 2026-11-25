#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>

#include "summary_cache.hpp"
#include "view.hpp"

namespace spudec {

struct SpuDecPlugmod : public plugmod_t, public event_listener_t {
    int data_id = 0;
    bool active_on_spu = false;
    bool desktop_restored = false;

    DECLARE_LISTENER(IdpListener, SpuDecPlugmod, pm);
    IdpListener idp_listener = IdpListener(*this);

    SpuDecPlugmod();
    ~SpuDecPlugmod() override;

    bool idaapi run(size_t arg) override;
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
    ssize_t on_idp_event(ssize_t code, va_list va);
};

// Returns true if an IDA database is currently loaded and its processor is Cell SPU (PLFM_SPU).
bool is_spu_database_active();

// Access current active SpuDecPlugmod instance for this database (or nullptr if non-SPU).
SpuDecPlugmod *active_spudec_plugmod();

} // namespace spudec