#include "spudec/pipeline.hpp"
#include "spudec/abi.hpp"
#include "spudec/lanes.hpp"
#include "spudec/lifter.hpp"
#include "spudec/opt.hpp"
#include "spudec/outssa.hpp"
#include "spudec/regs.hpp"
#include "spudec/scalarize.hpp"
#include "spudec/ssa.hpp"

#include <algorithm>
#include <mutex>

namespace spudec {

namespace {

struct EventCbEntry {
    int id;
    SpudecEventCallback cb;
};

std::mutex g_ev_mu;
int g_next_ev_id = 1;
std::vector<EventCbEntry> g_ev_cbs;

} // namespace

int register_event_callback(SpudecEventCallback cb) {
    std::lock_guard<std::mutex> lk(g_ev_mu);
    int id = g_next_ev_id++;
    g_ev_cbs.push_back({id, std::move(cb)});
    return id;
}

bool unregister_event_callback(int handle) {
    std::lock_guard<std::mutex> lk(g_ev_mu);
    auto it = std::remove_if(g_ev_cbs.begin(), g_ev_cbs.end(),
                             [handle](const EventCbEntry &e) { return e.id == handle; });
    if (it == g_ev_cbs.end()) return false;
    g_ev_cbs.erase(it, g_ev_cbs.end());
    return true;
}

void notify_event(spudec_event_t ev, void *arg0, void *arg1) {
    std::vector<EventCbEntry> snapshot;
    {
        std::lock_guard<std::mutex> lk(g_ev_mu);
        if (g_ev_cbs.empty()) return;
        snapshot = g_ev_cbs;
    }
    for (const auto &ent : snapshot) {
        ent.cb(ev, arg0, arg1);
    }
}

std::unique_ptr<Function> lift_and_optimize(IDatabaseProvider &db,
                                            uint64_t ea,
                                            const DecompileOptions &opts,
                                            std::string *out_error) {
    auto func = cfg::build(db, ea, opts.drop_hints, out_error);
    if (!func) return nullptr;

    notify_event(spe_lifting_done, func.get(), nullptr);

    ssa::to_ssa(*func);
    if (opts.optimize_ir) {
        auto st = opt::optimize(*func);
        func->stats["rounds"] = st.rounds;
        func->stats["removed"] = st.removed;
    }

    if (opts.run_scalarize) {
        lanes::CalleeDemandFn callee_cb = [&](uint64_t callee_ea) {
            return db.get_callee_param_demand(callee_ea);
        };
        auto sc = scalarize::scalarize(*func, callee_cb, false, &db);
        func->scalar_stats["stores"] = sc.stores;
        func->scalar_stats["loads"] = sc.loads;
        func->scalar_stats["aligned_loads"] = sc.aligned_loads;
        func->scalar_stats["scalars"] = sc.scalars;
        func->scalar_stats["assumed_noalias"] = sc.assumed_noalias;

        if (opts.optimize_ir) {
            auto st2 = opt::optimize(*func);
            func->stats["rounds"] += st2.rounds;
            func->stats["removed"] += st2.removed;
            func->demand = lanes::compute_demand(*func, callee_cb);
            func->scalar_stats["scalars"] = scalarize::mark_scalars(*func, func->demand);
        }
    }

    func->phi_copies = outssa::lower_phis(*func);
    if (opts.verify_ssa) {
        func->problems = ssa::verify(*func);
    }

    notify_event(spe_ssa_optimized, func.get(), nullptr);
    return func;
}

DecompileOutput decompile_function(IDatabaseProvider &db,
                                   uint64_t ea,
                                   const DecompileOptions &opts) {
    DecompileOutput res;
    res.ir_func = lift_and_optimize(db, ea, opts, &res.error);
    if (!res.ir_func) return res;

    auto [stmts, sinfo] = structure::structure(*res.ir_func);
    res.struct_info = std::move(sinfo);

    cgen::CGenOptions cg_opts;
    cg_opts.db = &db;
    cg_opts.user_data = opts.user_data;
    cg_opts.hide_casts = opts.hide_casts;

    res.cfunc = cgen::generate(*res.ir_func, stmts, res.struct_info, cg_opts);

    // Fire CMAT_FINAL maturity callback; if a script mutated the ctree AST, refresh printed lines!
    notify_event(spe_maturity, res.cfunc.get(), nullptr);
    if (res.cfunc && res.cfunc->has_tree_mutations()) {
        res.cfunc->refresh_func_ctext();
    }
    notify_event(spe_func_printed, res.cfunc.get(), nullptr);
    return res;
}

bool analyze_is_variadic(IDatabaseProvider &db, uint64_t func_ea) {
    DecompileOptions opts;
    opts.run_scalarize = false;
    auto fn = lift_and_optimize(db, func_ea, opts);
    if (!fn) return false;
    int count = 0;
    for (const auto &b : fn->blocks) {
        for (const auto &i : b->insns) {
            if (i->op == Op::STOREQ && i->srcs.size() >= 3 &&
                i->srcs[2].is_var() && i->srcs[2].ver == 0 &&
                i->srcs[2].reg >= 4 && i->srcs[2].reg <= 79) {
                ++count;
            }
        }
    }
    return count >= 16;
}

std::optional<int> analyze_callee_arity(IDatabaseProvider &db, uint64_t func_ea,
                                        const std::optional<std::string> &user_proto) {
    if (user_proto.has_value() && !user_proto->empty()) {
        auto sig = abi::parse_proto(*user_proto, "fn");
        if (sig.has_value()) return static_cast<int>(sig->params.size());
    }
    if (auto ida_proto = db.get_ida_func_proto(func_ea); ida_proto.has_value()) {
        auto sig = abi::parse_proto(*ida_proto, "fn");
        if (sig.has_value()) return static_cast<int>(sig->params.size());
    }
    uint64_t start = 0;
    if (!db.get_func_start(func_ea, &start) || start != func_ea) {
        return std::nullopt;
    }
    DecompileOptions opts;
    opts.run_scalarize = false;
    auto fn = lift_and_optimize(db, func_ea, opts);
    if (!fn) return std::nullopt;
    auto params = cgen::recover_params(*fn);
    return static_cast<int>(params.size());
}

std::unordered_map<int, uint16_t> analyze_param_demand(IDatabaseProvider &db, uint64_t func_ea) {
    std::unordered_map<int, uint16_t> wide;
    for (int r = regs::ARG_FIRST; r <= regs::ARG_LAST; ++r) wide[r] = lanes::ALL;

    uint64_t start = 0;
    if (!db.get_func_start(func_ea, &start) || start != func_ea) return wide;

    DecompileOptions opts;
    opts.run_scalarize = false;
    auto fn = lift_and_optimize(db, func_ea, opts);
    if (!fn) return wide;

    auto dem = lanes::compute_demand(*fn);
    std::unordered_map<int, uint16_t> out;
    for (int r = regs::ARG_FIRST; r <= regs::ARG_LAST; ++r) {
        auto it = dem.find(make_var_key(r, 0));
        out[r] = (it != dem.end()) ? it->second : lanes::NONE;
    }
    return out;
}

} // namespace spudec
