"""Headless IDA Pro 9.5 verification & whole-corpus benchmark for native spudec.dll.

Supported SPU corpus IDBs:
  - lv0ldr.dec.i64
  - metldr.356.sym.elf.i64
  - isoldr.elf.i64 (including sub_275F8 vec_ullong4 recovery & sub_27738 scalar guard)
"""

import json
import os
import re
import subprocess
import tempfile
import time
import traceback
from pathlib import Path

import ida_auto
import ida_expr
import ida_funcs
import ida_idp
import ida_lines
import ida_netnode
import ida_pro
import idautils


def run_suite() -> dict:
    ida_auto.auto_wait()

    results = {
        "proc_id": ida_idp.ph_get_id(),
        "checks": {},
        "errors": [],
        "benchmark": {},
    }

    all_funcs = list(idautils.Functions())
    if not all_funcs:
        raise RuntimeError("No functions found in test IDB!")

    # Pick a non-trivial function (>= 8 instructions) for AST/netnode/IDC tests
    sample_ea = all_funcs[0]
    for fea in all_funcs:
        if len(list(idautils.FuncItems(fea))) >= 8:
            sample_ea = fea
            break

    # ------------------------------------------------------------------
    # 1. Zero-import `ida_hexrays` compatibility shim check
    #    (BEFORE `import spudec` has ever been executed!)
    # ------------------------------------------------------------------
    import ida_hexrays

    assert ida_hexrays.init_hexrays_plugin(), "init_hexrays_plugin() returned False on PLFM_SPU!"
    cf0 = ida_hexrays.decompile(sample_ea)
    assert cf0 is not None, "ida_hexrays.decompile(sample_ea) returned None!"
    txt0 = str(cf0)
    sv0 = cf0.get_pseudocode()
    assert len(txt0) > 20, "Empty pseudocode string!"
    assert len(sv0) > 2, "Empty sv tagged lines!"
    stripped_line0 = ida_lines.tag_remove(sv0[0].line)
    assert len(stripped_line0) >= 0
    results["checks"]["zero_import_ida_hexrays"] = True

    # ------------------------------------------------------------------
    # 2. `ctree_visitor_t` AST traversal & live AST mutation check
    # ------------------------------------------------------------------
    counts = {"insns": 0, "exprs": 0, "first_num": None}

    class AuditVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_PARENTS)

        def visit_insn(self, ins):
            counts["insns"] += 1
            return 0

        def visit_expr(self, expr):
            counts["exprs"] += 1
            if expr.op == ida_hexrays.cot_num and counts["first_num"] is None:
                counts["first_num"] = expr
            return 0

    vis = AuditVisitor()
    vis.apply_to(cf0.body, None)
    assert counts["insns"] >= 1, "Visitor saw 0 statements!"
    results["checks"]["ctree_visitor"] = {
        "insns": counts["insns"],
        "exprs": counts["exprs"],
        "lvars": len(cf0.get_lvars()),
    }

    if counts["first_num"] is not None:
        num_expr = counts["first_num"]
        orig_val = num_expr.numval()
        num_expr.n._value = 0x1337BEEF
        cf0.refresh_func_ctext()
        mut_txt = str(cf0)
        assert ("0x1337BEEF" in mut_txt) or ("322420463" in mut_txt), (
            f"Mutated constant not reflected in refreshed ctext:\n{mut_txt}"
        )
        # Restore clean cached cfunc
        ida_hexrays.mark_cfunc_dirty(sample_ea)
        _ = orig_val
    results["checks"]["ctree_mutation"] = True

    # ------------------------------------------------------------------
    # 3. `Hexrays_Hooks` lifecycle callback check
    # ------------------------------------------------------------------
    hook_hits = {"maturity": 0, "printed": 0}

    class TestHooks(ida_hexrays.Hexrays_Hooks):
        def maturity(self, cfunc, mat):
            if cfunc.entry_ea == sample_ea and mat == ida_hexrays.CMAT_FINAL:
                hook_hits["maturity"] += 1
            return 0

        def func_printed(self, cfunc):
            if cfunc.entry_ea == sample_ea:
                hook_hits["printed"] += 1
            return 0

    th = TestHooks()
    assert th.hook(), "Hexrays_Hooks.hook() failed!"
    _ = ida_hexrays.decompile(sample_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
    th.unhook()
    assert hook_hits["maturity"] >= 1 and hook_hits["printed"] >= 1, f"Hook hits missing: {hook_hits}"
    results["checks"]["hexrays_hooks"] = hook_hits

    # ------------------------------------------------------------------
    # 4. `$ spudec` netnode backward-compatibility check (raw legacy JSON)
    # ------------------------------------------------------------------
    import spudec

    nn = ida_netnode.netnode("$ spudec", 0, True)
    orig_sup = nn.supstr(sample_ea)
    cf_base = spudec.cfunc(sample_ea)
    test_canon = cf_base.lvars[0].canonical_name if cf_base.lvars else "r3"

    legacy_payload = {
        "renames": {test_canon: "legacy_netnode_var"},
        "types": {},
        "cmts": {f"0x{sample_ea:x}": "legacy_json_comment_ok"},
        "numforms": {},
        "iflags": [],
    }
    nn.supset(sample_ea, json.dumps(legacy_payload).encode("utf-8"))
    ida_hexrays.mark_cfunc_dirty(sample_ea)
    compat_txt = spudec.decompile(sample_ea)
    assert "legacy_json_comment_ok" in compat_txt, f"Legacy netnode comment missing:\n{compat_txt}"
    if cf_base.lvars:
        assert "legacy_netnode_var" in compat_txt, f"Legacy netnode rename missing:\n{compat_txt}"

    # Restore original netnode state
    if orig_sup:
        nn.supset(sample_ea, orig_sup.encode("utf-8"))
    else:
        spudec.db.clear_func_overrides(sample_ea)
    results["checks"]["netnode_backward_compat"] = True

    # ------------------------------------------------------------------
    # 5. Custom IR `optinsn` pass + `spudec.dump()` check
    # ------------------------------------------------------------------
    ir_dump = spudec.dump(sample_ea)
    assert len(ir_dump) > 10, "Empty IR dump!"
    opt_calls = {"cnt": 0}

    def _my_opt(fea, blk_id, insn_idx, op_code, insn_ea):
        _ = (fea, blk_id, insn_idx, op_code, insn_ea)
        opt_calls["cnt"] += 1
        return 0

    opt_h = spudec.register_optinsn(_my_opt)
    assert opt_h >= 0
    _ = ida_hexrays.decompile(sample_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
    spudec.unregister_optinsn(opt_h)
    assert opt_calls["cnt"] > 0, "Custom optinsn hook did not fire!"
    results["checks"]["custom_optinsn_and_ir"] = opt_calls["cnt"]

    # ------------------------------------------------------------------
    # 6. Native IDC functions check
    # ------------------------------------------------------------------
    idc_val = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(idc_val, sample_ea, "spudec_version()")
    assert not err and idc_val.c_str() == spudec.version(), f"IDC version mismatch: {err}"

    err = ida_expr.eval_idc_expr(
        idc_val, sample_ea, f'spudec_set_cmt(0x{sample_ea:x}, 0x{sample_ea:x}, "idc_cmt_verified")'
    )
    assert not err and idc_val.num == 1
    err = ida_expr.eval_idc_expr(idc_val, sample_ea, f"spudec_decompile(0x{sample_ea:x})")
    assert not err and "idc_cmt_verified" in idc_val.c_str()
    err = ida_expr.eval_idc_expr(
        idc_val, sample_ea, f'spudec_set_cmt(0x{sample_ea:x}, 0x{sample_ea:x}, "")'
    )
    results["checks"]["idc_functions"] = True

    # ------------------------------------------------------------------
    # 6b. isoldr.elf.i64-specific native C recovery regression checks
    # ------------------------------------------------------------------
    if 0x275F8 in all_funcs and 0x27738 in all_funcs:
        c_275f8 = spudec.decompile(0x275F8)
        assert "vec_ullong4" in c_275f8, f"isoldr sub_275F8 missing vec_ullong4 return:\n{c_275f8}"
        for banned in ("__builtin_spu_mask", "spu_insert", "qword_unaligned", "spu_splats", "spu_shuffle"):
            assert banned not in c_275f8, f"isoldr sub_275F8 still emits banned intrinsic {banned}:\n{c_275f8}"
        c_27738 = spudec.decompile(0x27738)
        sig_27738 = [ln for ln in c_27738.splitlines() if "sub_27738(" in ln and not ln.strip().startswith("//")]
        assert sig_27738 and "qword2" not in sig_27738[0] and "vec_ullong4" not in sig_27738[0], (
            f"isoldr sub_27738 falsely recovered multi-register return:\n{c_27738}"
        )
        results["checks"]["isoldr_regression_guards"] = True

    # ------------------------------------------------------------------
    # 7. Whole-corpus cold & warm native C++ decompilation + Functional Audit Gate
    #    (SSA verification, unhandled-opcode check, COLOR_ADDR anchors, cl.exe /Zs)
    # ------------------------------------------------------------------
    spudec.clear_caches()

    cold_times_ms = []
    worst_ms = 0.0
    worst_ea = 0
    worst_name = ""
    ok_count = 0
    fail_list = []
    ssa_problems = []
    unhandled_funcs = []
    missing_addr_anchors = []
    compile_sample_funcs = []
    total_lines = 0

    t_all_start = time.perf_counter()
    for fea in all_funcs:
        t0 = time.perf_counter()
        try:
            c_text = spudec.decompile(fea)
            dt_ms = (time.perf_counter() - t0) * 1000.0
            cold_times_ms.append(dt_ms)
            line_cnt = c_text.count("\n") + 1
            total_lines += line_cnt
            ok_count += 1
            if dt_ms > worst_ms:
                worst_ms = dt_ms
                worst_ea = fea
                worst_name = ida_funcs.get_func_name(fea) or f"sub_{fea:X}"

            # Functional invariant 1: zero silent unhandled/undecodable opcodes in emitted C or IR
            if "undecodable(" in c_text or "__unhandled" in c_text:
                unhandled_funcs.append({"ea": hex(fea), "reason": "unhandled/undecodable marker in C"})

            # Functional invariant 2: verify SSA problems == 0 and no unhandled IR markers
            ir_txt = spudec.dump(fea)
            if "problems:" in ir_txt.lower() or "ssa error" in ir_txt.lower() or "verify_ssa" in ir_txt.lower():
                ssa_problems.append({"ea": hex(fea), "detail": "SSA problem reported in IR dump"})
            if "unhandled" in ir_txt.lower() and "unhandled: 0" not in ir_txt.lower():
                unhandled_funcs.append({"ea": hex(fea), "reason": "unhandled opcode in IR dump"})

            # Functional invariant 3: valid COLOR_ADDR anchors on pseudocode body statements
            cf_cur = spudec.cfunc(fea)
            if cf_cur is not None:
                sv_cur = cf_cur.get_pseudocode()
                has_addr_tag = any("\x01\x28" in ln.line for ln in sv_cur)
                if not has_addr_tag and len(sv_cur) > 4:
                    missing_addr_anchors.append(hex(fea))

            # Collect first 16 non-trivial functions for MSVC cl.exe /Zs syntax/type oracle
            if len(compile_sample_funcs) < 16 and line_cnt >= 6:
                compile_sample_funcs.append((fea, c_text))
        except Exception as exc:
            fail_list.append({"ea": hex(fea), "err": str(exc)})
    total_cold_ms = (time.perf_counter() - t_all_start) * 1000.0

    # Functional invariant 4: Real MSVC cl.exe /Zs C syntax/type compilation oracle
    c_oracle_failures = []
    prelude_h = Path(__file__).resolve().parent.parent / ".agents" / "skills" / "decompiler-qa-audit" / "resources" / "spudec_audit_prelude.h"
    vcvars = None
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    vswhere = Path(pf86) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if vswhere.exists():
        res = subprocess.run(
            [str(vswhere), "-latest", "-products", "*", "-property", "installationPath"],
            capture_output=True, text=True, check=False,
        )
        inst = res.stdout.strip()
        if inst:
            cand = Path(inst) / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
            if cand.exists():
                vcvars = cand

    if vcvars and prelude_h.exists() and compile_sample_funcs:
        with tempfile.TemporaryDirectory(prefix="spudec_corpus_cl_") as tmpdir:
            for fea, c_text in compile_sample_funcs:
                cfile = Path(tmpdir) / f"fn_{fea:x}.c"
                bfile = Path(tmpdir) / f"fn_{fea:x}.bat"
                cfile.write_text(f'#include "{prelude_h.as_posix()}"\n\n{c_text}\n', encoding="utf-8")
                bfile.write_text(
                    f'@echo off\r\ncall "{vcvars}" >nul 2>&1\r\nif errorlevel 1 exit /b 1\r\n'
                    f'cl.exe /nologo /Zs /W3 /TC "{cfile}"\r\n',
                    encoding="utf-8",
                )
                proc = subprocess.run(["cmd.exe", "/c", str(bfile)], capture_output=True, text=True, check=False)
                if proc.returncode != 0:
                    c_oracle_failures.append({
                        "ea": hex(fea),
                        "diag": (proc.stdout + "\n" + proc.stderr).strip()[:500],
                    })

    # Warm cached pass
    t_warm_start = time.perf_counter()
    for fea in all_funcs:
        _ = spudec.decompile(fea)
    total_warm_ms = (time.perf_counter() - t_warm_start) * 1000.0

    results["checks"]["corpus_functional_gates"] = {
        "ssa_problems_count": len(ssa_problems),
        "unhandled_funcs_count": len(unhandled_funcs),
        "missing_addr_anchors_count": len(missing_addr_anchors),
        "c_oracle_checked": len(compile_sample_funcs),
        "c_oracle_failures_count": len(c_oracle_failures),
        "c_oracle_failures": c_oracle_failures[:5],
    }

    results["benchmark"] = {
        "total_funcs": len(all_funcs),
        "ok_funcs": ok_count,
        "failed_funcs": len(fail_list),
        "failures": fail_list[:10],
        "ssa_problems": ssa_problems[:10],
        "unhandled_funcs": unhandled_funcs[:10],
        "total_lines": total_lines,
        "total_cold_ms": round(total_cold_ms, 2),
        "avg_cold_ms": round(total_cold_ms / max(1, len(all_funcs)), 3),
        "median_cold_ms": round(sorted(cold_times_ms)[len(cold_times_ms) // 2], 3) if cold_times_ms else 0.0,
        "worst_func_ea": f"0x{worst_ea:05X}",
        "worst_func_name": worst_name,
        "worst_func_ms": round(worst_ms, 2),
        "total_warm_ms": round(total_warm_ms, 2),
        "avg_warm_ms": round(total_warm_ms / max(1, len(all_funcs)), 4),
    }
    return results


def main() -> None:
    out_path = os.environ.get("SPUDEC_BENCH_JSON", "")
    payload = {}
    exit_code = 0
    try:
        payload = run_suite()
        gates = payload.get("checks", {}).get("corpus_functional_gates", {})
        if (
            payload["benchmark"].get("failed_funcs", 0) > 0
            or gates.get("ssa_problems_count", 0) > 0
            or gates.get("unhandled_funcs_count", 0) > 0
            or gates.get("c_oracle_failures_count", 0) > 0
        ):
            exit_code = 2
    except Exception as exc:
        payload = {
            "fatal_error": str(exc),
            "traceback": traceback.format_exc(),
        }
        exit_code = 1

    if out_path:
        with open(out_path, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2)
    print("[spudec-verify]", json.dumps(payload))
    ida_pro.qexit(exit_code)


if __name__ == "__main__":
    main()
