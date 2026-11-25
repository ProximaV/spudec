#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "spudec/u128.hpp"
#include "spudec/regs.hpp"
#include "spudec/channels.hpp"
#include "spudec/ir.hpp"
#include "spudec/sem.hpp"
#include "spudec/abi.hpp"
#include "spudec/lifter.hpp"
#include "spudec/ssa.hpp"
#include "spudec/opt.hpp"
#include "spudec/lanes.hpp"
#include "spudec/scalarize.hpp"
#include "spudec/outssa.hpp"
#include "spudec/structure.hpp"
#include "spudec/frame.hpp"
#include "spudec/types.hpp"
#include "spudec/user_data.hpp"
#include "spudec/highlight.hpp"
#include "spudec/ctree.hpp"
#include "spudec/cgen.hpp"
#include "spudec/pipeline.hpp"

using namespace spudec;

static void test_u128_and_sem() {
    u128_t rep_b = u128_t::repl(0x7F, EW::B);
    assert(rep_b.hi == 0x7F7F7F7F7F7F7F7FULL && rep_b.lo == 0x7F7F7F7F7F7F7F7FULL);
    uint64_t lane = 0;
    assert(rep_b.is_replicated(EW::B, &lane) && lane == 0x7F);

    u128_t w0 = u128_t::from_word0(0xDEADBEEFu);
    assert(w0.word0() == 0xDEADBEEFu);
    assert(w0.low96_zero());

    u128_t val = u128_t::from_word0(0x11223344u);
    u128_t old_q(0xAABBCCDDEEFF0011ULL, 0x2233445566778899ULL);
    u128_t ctl = sem::genctl(4, EW::W);
    u128_t res = sem::shufb(val, old_q, ctl);
    assert(res.get_lane(EW::W, 0) == 0xAABBCCDDu);
    assert(res.get_lane(EW::W, 1) == 0x11223344u);
    assert(res.get_lane(EW::W, 2) == 0x22334455u);
    assert(res.get_lane(EW::W, 3) == 0x66778899u);

    u128_t bval = u128_t::from_word0(0x000000ABu);
    u128_t bctl = sem::genctl(13, EW::B);
    u128_t bres = sem::shufb(bval, old_q, bctl);
    assert(bres.byte_lane(13) == 0xABu);
    assert(bres.byte_lane(12) == old_q.byte_lane(12));
    assert(bres.byte_lane(14) == old_q.byte_lane(14));

    u128_t args[2] = { u128_t::repl(10, EW::W), u128_t::repl(20, EW::W) };
    auto sum = sem::evaluate(Op::ADD, EW::W, args, 2);
    assert(sum.has_value() && sum->get_lane(EW::W, 0) == 30);

    auto gt = sem::evaluate(Op::CMPGT, EW::W, args, 2);
    assert(gt.has_value() && gt->is_zero());
    u128_t args_rev[2] = { args[1], args[0] };
    auto gt2 = sem::evaluate(Op::CMPGT, EW::W, args_rev, 2);
    assert(gt2.has_value() && gt2->is_all_ones());

    auto g = sem::gb(*gt2, EW::B);
    assert(g.word0() == 0xFFFFu);

    std::printf("ok  test_u128_and_sem\n");
}

static void test_abi_proto_parser() {
    auto sig = abi::parse_proto("int *calculate(int a, void *buf, unsigned int size)");
    assert(sig.has_value());
    assert(sig->name == "calculate");
    assert(sig->ret_type == "int *");
    assert(sig->params.size() == 3);
    assert(sig->params[0].name == "a" && sig->params[0].type_str == "int" && sig->params[0].location == "r3");
    assert(sig->params[1].name == "buf" && sig->params[1].type_str == "void *" && sig->params[1].location == "r4");
    assert(sig->params[2].name == "size" && sig->params[2].type_str == "unsigned int" && sig->params[2].location == "r5");
    assert(sig->format_signature() == "int *calculate(int a, void *buf, unsigned int size)");

    auto sig2 = abi::parse_proto("int __cdecl check_hdr(unsigned int, const char **, struct Elf32_Ehdr *)");
    assert(sig2.has_value() && sig2->params.size() == 3);
    assert(sig2->params[0].type_str == "unsigned int" && sig2->params[0].name == "a1");
    assert(sig2->params[1].type_str == "const char **" && sig2->params[1].name == "a2");
    assert(sig2->params[2].type_str == "struct Elf32_Ehdr *" && sig2->params[2].name == "a3");

    std::string san = abi::sanitize_decl_for_ida(
        "int lv0::elf_access::set_elf(lv0::elf_access *this, const u8 *buf, u32 sz)", true, true);
    assert(san.find("::") == std::string::npos);
    assert(san.find("_spudec_fn(") != std::string::npos);
    assert(san.find("void *_this_ptr") != std::string::npos);

    std::printf("ok  test_abi_proto_parser\n");
}

static void test_lifter_and_cfg() {
    assert(Lifter::modelled_mnemonic_count() == 200);

    MockDatabaseProvider db;
    auto enc_rr = [](uint32_t op11, int rt, int ra, int rb) -> uint32_t {
        return (op11 << 21) | (static_cast<uint32_t>(rb) << 14) |
               (static_cast<uint32_t>(ra) << 7) | static_cast<uint32_t>(rt);
    };
    db.write_u32_be(0x100, enc_rr(0x0C0, 3, 3, 4));
    db.write_u32_be(0x104, enc_rr(0x07F, 3, 3, 8));
    db.write_u32_be(0x108, enc_rr(0x1A8, 0, 0, 0));
    db.func_names[0x100] = "add_and_shift";
    db.flowcharts[0x100] = { FlowBlockRange{0, 0x100, 0x10C, {}, {}} };

    std::string err;
    auto fn = cfg::build(db, 0x100, true, &err);
    assert(fn != nullptr);
    assert(fn->unhandled.empty());
    assert(fn->blocks.size() == 1);
    std::string ir_txt = fn->dump();
    assert(ir_txt.find("add.w") != std::string::npos);
    assert(ir_txt.find("shl.h") != std::string::npos);
    assert(ir_txt.find("ret") != std::string::npos);

    std::printf("ok  test_lifter_and_cfg\n");
}

static void add_edge(Function &f, int a, int b) {
    f.blocks[a]->succs.push_back(b);
    f.blocks[b]->preds.push_back(a);
}

static void test_ssa_opt_and_outssa() {
    // 1. Both arms of a PHI assigning distinct constants must survive opt::optimize
    const int R3 = regs::ARG_FIRST;
    const int R4 = regs::ARG_FIRST + 1;
    const int R5 = regs::ARG_FIRST + 2;

    {
        Function f(0x100, "pick");
        Block *b0 = f.new_block(0x100, 0x104);
        Block *b1 = f.new_block(0x104, 0x10C);
        Block *b2 = f.new_block(0x120, 0x128);
        Block *b3 = f.new_block(0x130, 0x134);

        auto br = f.make_insn(Op::CJMP, EW::W, 0x100);
        br->srcs = {Operand::make_var(R4)};
        br->has_aux = true;
        br->aux_ea = 0x120;
        br->cond_kind = CondKind::Z;
        b0->add(std::move(br));

        auto c1 = f.make_insn(Op::CONST, EW::W, 0x104);
        c1->has_dst = true; c1->dst_reg = R3; c1->scalar = true;
        c1->srcs = {Operand::make_const(u128_t::from_word0(1))};
        b1->add(std::move(c1));
        auto j1 = f.make_insn(Op::JMP, EW::W, 0x108);
        j1->has_aux = true; j1->aux_ea = 0x130;
        b1->add(std::move(j1));

        auto c2 = f.make_insn(Op::CONST, EW::W, 0x120);
        c2->has_dst = true; c2->dst_reg = R3; c2->scalar = true;
        c2->srcs = {Operand::make_const(u128_t::from_word0(2))};
        b2->add(std::move(c2));
        auto j2 = f.make_insn(Op::JMP, EW::W, 0x124);
        j2->has_aux = true; j2->aux_ea = 0x130;
        b2->add(std::move(j2));

        auto ret = f.make_insn(Op::RET, EW::W, 0x130);
        ret->srcs = {Operand::make_var(regs::R_MEM), Operand::make_var(regs::R_CH), Operand::make_var(R3)};
        b3->add(std::move(ret));

        add_edge(f, 0, 1); add_edge(f, 0, 2); add_edge(f, 1, 3); add_edge(f, 2, 3);

        ssa::to_ssa(f);
        assert(ssa::verify(f).empty());
        opt::optimize(f);
        assert(ssa::verify(f).empty());
        // Both CONST assignments in b1 and b2 must still exist!
        assert(b1->insns.size() == 2 && b1->insns[0]->op == Op::CONST);
        assert(b2->insns.size() == 2 && b2->insns[0]->op == Op::CONST);

        auto ipdom = ssa::compute_postdominators(f);
        assert(ipdom[0] == 3);
        assert(ipdom[3] == ssa::IPDOM_EXIT);
    }

    // 2. Interfering PHI web splitting + critical edge split (from test_pipeline.py::test_interfering_web_is_split)
    {
        Function f(0x100, "split");
        Block *b0 = f.new_block(0x100, 0x104);
        Block *b1 = f.new_block(0x104, 0x108);
        Block *b2 = f.new_block(0x108, 0x10C);
        Block *b3 = f.new_block(0x10C, 0x114);

        auto mv = f.make_insn(Op::MOV, EW::Q, 0x100);
        mv->has_dst = true; mv->dst_reg = R5;
        mv->srcs = {Operand::make_var(R3)};
        b0->add(std::move(mv));

        auto cj = f.make_insn(Op::CJMP, EW::W, 0x102);
        cj->srcs = {Operand::make_var(R4)};
        cj->has_aux = true; cj->aux_ea = 0x108; cj->cond_kind = CondKind::Z;
        b0->add(std::move(cj));

        auto j1 = f.make_insn(Op::JMP, EW::W, 0x104);
        j1->has_aux = true; j1->aux_ea = 0x10C;
        b1->add(std::move(j1));

        auto c2 = f.make_insn(Op::CONST, EW::W, 0x108);
        c2->has_dst = true; c2->dst_reg = R3; c2->scalar = true;
        c2->srcs = {Operand::make_const(u128_t::from_word0(2))};
        b2->add(std::move(c2));
        auto j2 = f.make_insn(Op::JMP, EW::W, 0x10A);
        j2->has_aux = true; j2->aux_ea = 0x10C;
        b2->add(std::move(j2));

        auto st = f.make_insn(Op::STOREQ, EW::Q, 0x10C);
        st->has_dst = true; st->dst_reg = regs::R_MEM;
        st->srcs = {Operand::make_var(regs::R_MEM), Operand::make_var(R5), Operand::make_var(R3)};
        b3->add(std::move(st));

        auto ret = f.make_insn(Op::RET, EW::W, 0x110);
        ret->srcs = {Operand::make_var(regs::R_MEM), Operand::make_var(regs::R_CH)};
        b3->add(std::move(ret));

        add_edge(f, 0, 1); add_edge(f, 0, 2); add_edge(f, 1, 3); add_edge(f, 2, 3);

        ssa::to_ssa(f);
        opt::optimize(f);
        assert(ssa::verify(f).empty());

        auto col_before = outssa::colours(f);
        // Incoming r3#0 must NOT share a colour with the merged r3#phi because r3#0 is still live as store addr!
        Insn *phi = b3->insns[0].get();
        assert(phi->op == Op::PHI);
        assert(col_before.key_to_colour.at(make_var_key(R3, 0)) != col_before.key_to_colour.at(phi->dst_key()));

        int copies = outssa::lower_phis(f);
        assert(copies >= 1);
        assert(ssa::verify(f).empty());
    }

    // 3. Custom optinsn hook registration & execution
    {
        Function f(0x200, "custom_hook");
        Block *b0 = f.new_block(0x200, 0x208);
        auto intr = f.make_insn(Op::INTRINSIC, EW::W, 0x200);
        intr->has_dst = true; intr->dst_reg = R3;
        intr->has_aux = true; intr->aux_str = "magic_zero";
        b0->add(std::move(intr));
        auto ret = f.make_insn(Op::RET, EW::W, 0x204);
        ret->srcs = {Operand::make_var(regs::R_MEM), Operand::make_var(regs::R_CH), Operand::make_var(R3)};
        b0->add(std::move(ret));

        ssa::to_ssa(f);
        int hid = opt::register_optinsn_hook([](Function &, Block &, Insn &insn) -> int {
            if (insn.op == Op::INTRINSIC && insn.aux_str == "magic_zero") {
                insn.op = Op::CONST;
                insn.srcs = {Operand::make_const(u128_t::from_word0(42))};
                insn.has_aux = false;
                insn.aux_str.clear();
                return 1;
            }
            return 0;
        });
        auto st = opt::optimize(f);
        opt::unregister_optinsn_hook(hid);
        assert(st.custom_changes == 1);
        assert(b0->insns[0]->op == Op::CONST && b0->insns[0]->srcs[0].val.word0() == 42);
    }

    std::printf("ok  test_ssa_opt_and_outssa\n");
}

static void test_lanes_and_scalarize() {
    // 1. Cross-procedural demand narrowing
    {
        const int R3 = regs::ARG_FIRST;
        Function f(0x100, "caller");
        Block *b0 = f.new_block(0x100, 0x110);

        auto add = f.make_insn(Op::ADD, EW::W, 0x100);
        add->has_dst = true; add->dst_reg = R3;
        add->srcs = {Operand::make_var(80), Operand::make_const(u128_t::from_word0(0x20))};
        Insn *add_ptr = b0->add(std::move(add));

        auto call = f.make_insn(Op::CALL, EW::W, 0x108);
        call->has_dst = true; call->dst_reg = regs::R_MEM;
        call->has_aux = true; call->aux_ea = 0x2000;
        call->srcs = {Operand::make_var(regs::R_MEM), Operand::make_var(regs::R_CH),
                      Operand::make_var(regs::LR), Operand::make_var(R3)};
        b0->add(std::move(call));

        auto ret = f.make_insn(Op::RET, EW::W, 0x10C);
        ret->srcs = {Operand::make_var(regs::R_MEM), Operand::make_var(regs::R_CH)};
        b0->add(std::move(ret));

        ssa::to_ssa(f);
        auto wide = lanes::compute_demand(f);
        assert(wide.at(add_ptr->dst_key()) == lanes::ALL);
        assert(wide.at(make_var_key(regs::LR, 0)) == lanes::W0);

        auto narrow = lanes::compute_demand(f, [R3](uint64_t ea) -> std::optional<std::unordered_map<int, uint16_t>> {
            assert(ea == 0x2000);
            return std::unordered_map<int, uint16_t>{{R3, lanes::W0}};
        });
        assert(narrow.at(add_ptr->dst_key()) == lanes::W0);
    }

    // 2. Lift a real SPU scalar word store + scalar halfword load from machine bytes and verify scalarize!
    //   0x200: cwd    r6, 4(r3)         ; op11=0x1F6 (RI7), i7=4, ra=3, rt=6
    //   0x204: lqd    r7, 0(r3)         ; op8=0x34 (RI10), i10=0, ra=3, rt=7
    //   0x208: shufb  r8, r4, r7, r6    ; op4=0xB (RRR: op4 bits 0..3, rt bits 4..10, rb bits 11..17, ra bits 18..24, rc bits 25..31)
    //   0x20C: stqd   r8, 0(r3)         ; op8=0x24 (RI10), i10=0, ra=3, rt=8
    //   0x210: lqd    r9, 0x10(r3)      ; op8=0x34 (RI10), i10=1, ra=3, rt=9
    //   0x214: rotqbyi r3, r9, 6        ; op11=0x1FC (RI7), i7=6, ra=9, rt=3
    //   0x218: andi   r3, r3, 0xFF      ; op8=0x14 (RI10), i10=0xFF, ra=3, rt=3 -> wait: let's branch on brhz r3 so demand is H0!
    //   0x218: brhz   r3, 0x220         ; op9=0x044 (RI16), i16=2, rt=3
    //   0x21C: bi     lr
    //   0x220: bi     lr
    {
        MockDatabaseProvider db;
        auto enc_ri7 = [](uint32_t op11, int rt, int ra, int i7) -> uint32_t {
            return (op11 << 21) | (static_cast<uint32_t>(i7 & 0x7F) << 14) |
                   (static_cast<uint32_t>(ra) << 7) | static_cast<uint32_t>(rt);
        };
        auto enc_ri10 = [](uint32_t op8, int rt, int ra, int i10) -> uint32_t {
            return (op8 << 24) | (static_cast<uint32_t>(i10 & 0x3FF) << 14) |
                   (static_cast<uint32_t>(ra) << 7) | static_cast<uint32_t>(rt);
        };
        auto enc_rrr = [](uint32_t op4, int rt, int ra, int rb, int rc) -> uint32_t {
            return (op4 << 28) | (static_cast<uint32_t>(rt) << 21) |
                   (static_cast<uint32_t>(rb) << 14) | (static_cast<uint32_t>(ra) << 7) |
                   static_cast<uint32_t>(rc);
        };
        auto enc_ri16 = [](uint32_t op9, int rt, int i16) -> uint32_t {
            return (op9 << 23) | (static_cast<uint32_t>(i16 & 0xFFFF) << 7) | static_cast<uint32_t>(rt);
        };

        db.write_u32_be(0x200, enc_ri7(0x1F6, 6, 3, 4));         // cwd r6, 4(r3)
        db.write_u32_be(0x204, enc_ri10(0x34, 7, 3, 0));         // lqd r7, 0(r3)
        db.write_u32_be(0x208, enc_rrr(0xB, 8, 4, 7, 6));        // shufb r8, r4, r7, r6
        db.write_u32_be(0x20C, enc_ri10(0x24, 8, 3, 0));         // stqd r8, 0(r3)
        db.write_u32_be(0x210, enc_ri10(0x34, 9, 3, 1));         // lqd r9, 0x10(r3)
        db.write_u32_be(0x214, enc_ri7(0x1FC, 10, 9, 6));        // rotqbyi r10, r9, 6
        db.write_u32_be(0x218, enc_ri16(0x044, 10, 2));          // brhz r10, +8 -> 0x220
        db.write_u32_be(0x21C, (0x1A8u << 21));                  // bi lr
        db.write_u32_be(0x220, (0x1A8u << 21));                  // bi lr

        db.func_names[0x200] = "scalar_mem_idioms";
        db.flowcharts[0x200] = {
            FlowBlockRange{0, 0x200, 0x21C, {}, {1, 2}},
            FlowBlockRange{1, 0x21C, 0x220, {0}, {}},
            FlowBlockRange{2, 0x220, 0x224, {0}, {}},
        };

        auto fn = cfg::build(db, 0x200);
        assert(fn != nullptr && fn->unhandled.empty());
        ssa::to_ssa(*fn);
        opt::optimize(*fn);
        auto sstats = scalarize::scalarize(*fn);
        opt::optimize(*fn);
        assert(ssa::verify(*fn).empty());

        assert(sstats.stores == 1);
        assert(sstats.loads == 1);
        std::string ir_after = fn->dump();
        assert(ir_after.find("store.w") != std::string::npos);
        assert(ir_after.find("load.h") != std::string::npos);
        assert(ir_after.find("shufb") == std::string::npos);
    }

    std::printf("ok  test_lanes_and_scalarize\n");
}

static void test_user_data_json_and_highlight() {
    FuncUserData ud;
    ud.set_var_rename("r3_2", "status");
    ud.set_var_type("a1", "Elf32_Ehdr *");
    ud.set_var_locator("reg:3@0x2548", std::string("ctx"), std::string("SpuCtx *"), 1);
    ud.set_statement_cmt(0x108, "validate magic header");
    ud.set_numform(0x104, 0, "enum:ELF_MAGIC");
    ud.toggle_iflag(0x100);
    ud.set_func_proto("int check_elf(Elf32_Ehdr *hdr, u32 len)");

    std::string js = serialize_func_user_data_json(ud);
    FuncUserData parsed;
    assert(parse_func_user_data_json(js, parsed));
    assert(parsed.renames.at("r3_2") == "status");
    assert(parsed.types.at("a1") == "Elf32_Ehdr *");
    assert(parsed.lvars.at("reg:3@0x2548").name == "ctx");
    assert(parsed.lvars.at("reg:3@0x2548").type == "SpuCtx *");
    assert(parsed.get_statement_cmt(0x108).value() == "validate magic header");
    assert(parsed.get_numform(0x104, 0).value() == "enum:ELF_MAGIC");
    assert(parsed.is_iflag_inverted(0x100));
    assert(parsed.proto.value() == "int check_elf(Elf32_Ehdr *hdr, u32 len)");

    WindowState ws{true, 0x2548, 42, 8, "c"};
    WindowState ws_out;
    assert(parse_window_state_json(serialize_window_state_json(ws), ws_out));
    assert(ws_out.is_open && ws_out.func_ea.value() == 0x2548 && ws_out.lineno == 42 && ws_out.col == 8);

    // Highlight & COLOR_ADDR round-trip
    std::string line = "    r4 = *(unsigned int *)(a1 + 0x10);   // was lqd/rotqby";
    std::string col = highlight::make_addr_tag(0x1234ULL) + highlight::colorize(line, "a1");
    assert(highlight::strip_tags(col) == line);
    auto anc = highlight::extract_addr_anchor_at(col, 6);
    assert(anc.has_value() && *anc == 0x1234ULL);
    assert(highlight::extract_word_at(line, 5) == "r4");

    std::printf("ok  test_user_data_json_and_highlight\n");
}

static void test_structure_cgen_udt_and_ctree() {
    const int R3 = regs::ARG_FIRST;
    const int R4 = regs::ARG_FIRST + 1;
    const int R5 = regs::ARG_FIRST + 2;

    // 1. Prologue hiding + stack frame naming + UDT pointer dereference + numforms + hide_casts
    {
        Function f(0x100, "process_pkt");
        Block *b0 = f.new_block(0x100, 0x130);
        int t = regs::NREG;
        auto emit_slot = [&](int tmp, int32_t off, uint64_t ea) {
            auto a = f.make_insn(Op::ADD, EW::W, ea);
            a->has_dst = true; a->dst_reg = tmp;
            a->srcs = {Operand::make_var(regs::SP), Operand::make_const(u128_t::from_word0(static_cast<uint32_t>(off)))};
            b0->add(std::move(a));
            auto m = f.make_insn(Op::AND, EW::W, ea);
            m->has_dst = true; m->dst_reg = tmp + 1;
            m->srcs = {Operand::make_var(tmp), Operand::make_const(u128_t::from_word0(0x3FFF0u))};
            b0->add(std::move(m));
        };

        // Prologue saves lr at sp+0x10 and r80 at sp-0x10
        emit_slot(t, -0x10, 0x100);
        {
            auto s = f.make_insn(Op::STOREQ, EW::Q, 0x104);
            s->has_dst = true; s->dst_reg = regs::R_MEM;
            s->srcs = {Operand::make_var(regs::R_MEM), Operand::make_var(t + 1), Operand::make_var(80)};
            b0->add(std::move(s));
        }
        emit_slot(t + 2, 0x10, 0x108);
        {
            auto s = f.make_insn(Op::STOREQ, EW::Q, 0x10C);
            s->has_dst = true; s->dst_reg = regs::R_MEM;
            s->srcs = {Operand::make_var(regs::R_MEM), Operand::make_var(t + 3), Operand::make_var(regs::LR)};
            b0->add(std::move(s));
        }

        // Load u32 field at a1 + 8 (`hdr->size`)
        {
            auto a = f.make_insn(Op::ADD, EW::W, 0x110);
            a->has_dst = true; a->dst_reg = t + 4;
            a->srcs = {Operand::make_var(R3), Operand::make_const(u128_t::from_word0(8))};
            b0->add(std::move(a));
            auto ld = f.make_insn(Op::LOAD, EW::W, 0x114);
            ld->has_dst = true; ld->dst_reg = R4;
            ld->srcs = {Operand::make_var(regs::R_MEM), Operand::make_var(t + 4)};
            b0->add(std::move(ld));
        }

        // Add magic constant 0x41424344 ('ABCD') to R4 into R3 and return
        {
            auto add = f.make_insn(Op::ADD, EW::W, 0x118);
            add->has_dst = true; add->dst_reg = R3; add->scalar = true;
            add->srcs = {Operand::make_var(R4), Operand::make_const(u128_t::from_word0(0x41424344u))};
            b0->add(std::move(add));
            auto ret = f.make_insn(Op::RET, EW::W, 0x11C);
            ret->srcs = {Operand::make_var(regs::R_MEM), Operand::make_var(regs::R_CH), Operand::make_var(R3)};
            b0->add(std::move(ret));
        }

        ssa::to_ssa(f);
        opt::optimize(f);
        outssa::lower_phis(f);
        auto [stmts, sinfo] = structure::structure(f);

        cgen::CGenOptions opts;
        opts.user_data.set_func_proto("u32 process_pkt(PktHdr *hdr)");
        opts.user_data.set_numform(0x118, 0, "char");
        opts.user_data.set_statement_cmt(0x118, "add magic tag");
        opts.struct_resolver = [](const std::string &nm) -> std::optional<UdtInfo> {
            if (nm == "PktHdr") {
                UdtInfo u;
                u.size = 16;
                u.fields.push_back({0, 4, "magic", "u32", 0});
                u.fields.push_back({4, 4, "flags", "u32", 0});
                u.fields.push_back({8, 4, "size", "u32", 0});
                u.fields.push_back({12, 4, "crc", "u32", 0});
                return u;
            }
            return std::nullopt;
        };

        auto cf = cgen::generate(f, stmts, sinfo, opts);
        std::string txt = cf->print_func();
        assert(txt.find("// prologue: saves lr at sp+0x10, r80 at sp-0x10") != std::string::npos);
        assert(txt.find("u32 process_pkt(PktHdr *hdr)") != std::string::npos);
        assert(txt.find("hdr->size") != std::string::npos);
        assert(txt.find("'ABCD'") != std::string::npos);
        assert(txt.find("// add magic tag") != std::string::npos);
        assert(cf->lvars.size() >= 1 && cf->lvars[0].name == "hdr" && cf->lvars[0].is_arg_var);
    }

    // 2. ctree_visitor_t traversal & AST mutation refreshing printed pseudocode!
    {
        MockDatabaseProvider db;
        auto enc_rr = [](uint32_t op11, int rt, int ra, int rb) -> uint32_t {
            return (op11 << 21) | (static_cast<uint32_t>(rb) << 14) |
                   (static_cast<uint32_t>(ra) << 7) | static_cast<uint32_t>(rt);
        };
        auto enc_ri16 = [](uint32_t op9, int rt, int i16) -> uint32_t {
            return (op9 << 23) | (static_cast<uint32_t>(i16 & 0xFFFF) << 7) | static_cast<uint32_t>(rt);
        };
        // 0x300: il  r3, 0x1234  (op9=0x081, rt=3, i16=0x1234)
        // 0x304: bi  lr          (op11=0x1A8)
        db.write_u32_be(0x300, enc_ri16(0x081, R3, 0x1234));
        db.write_u32_be(0x304, enc_rr(0x1A8, 0, 0, 0));
        db.func_names[0x300] = "ret_const";
        db.flowcharts[0x300] = { FlowBlockRange{0, 0x300, 0x308, {}, {}} };

        int cbid = register_event_callback([](spudec_event_t ev, void *arg0, void *) -> int {
            if (ev != spe_maturity) return 0;
            auto *cf = static_cast<cfunc_t *>(arg0);
            struct NumRewriter : public ctree_visitor_t {
                int visited_exprs = 0;
                NumRewriter() : ctree_visitor_t(SPU_CV_PARENTS | SPU_CV_POST) {}
                int visit_expr(cexpr_t *e) override {
                    ++visited_exprs;
                    if (e->op == cot_num && e->numval() == 0x1234) {
                        e->n._value = 0x7777;
                        e->mark_mutated();
                        for (citem_t *p : parents) p->mutated = true;
                    }
                    return 0;
                }
            } v;
            v.apply_to(cf->body);
            assert(v.visited_exprs >= 2);
            return 0;
        });

        DecompileOptions dopts;
        dopts.verify_ssa = true;
        auto out = decompile_function(db, 0x300, dopts);
        unregister_event_callback(cbid);

        assert(out.cfunc != nullptr && out.ir_func->problems.empty());
        std::string ptxt = out.cfunc->print_func();
        assert(ptxt.find("0x7777") != std::string::npos);
        (void)R5;
    }

    std::printf("ok  test_structure_cgen_udt_and_ctree\n");
}

// ============================================================================
// Adversarial 5-Tier External QA Audit Suite (Raw SPU ISA v1.2 Machine Bytes,
// Independent SPU Reference Evaluator, MSVC cl.exe /Zs Syntax/Type Oracle, and
// Differential Execution Oracle)
// ============================================================================

namespace qa {

static int g_failures = 0;

static void record_failure(const char *test_name, const std::string &msg) {
    ++g_failures;
    std::fprintf(stderr, "FAIL [%s]: %s\n", test_name, msg.c_str());
}

// --- Cell SPU ISA v1.2 Big-Endian 32-bit Machine Word Encoders ---
constexpr uint32_t enc_rr(uint32_t op11, int rt, int ra, int rb) {
    return (op11 << 21) | (static_cast<uint32_t>(rb & 0x7F) << 14) |
           (static_cast<uint32_t>(ra & 0x7F) << 7) | static_cast<uint32_t>(rt & 0x7F);
}
constexpr uint32_t enc_ri7(uint32_t op11, int rt, int ra, int i7) {
    return (op11 << 21) | (static_cast<uint32_t>(i7 & 0x7F) << 14) |
           (static_cast<uint32_t>(ra & 0x7F) << 7) | static_cast<uint32_t>(rt & 0x7F);
}
constexpr uint32_t enc_ri10(uint32_t op8, int rt, int ra, int i10) {
    return (op8 << 24) | (static_cast<uint32_t>(i10 & 0x3FF) << 14) |
           (static_cast<uint32_t>(ra & 0x7F) << 7) | static_cast<uint32_t>(rt & 0x7F);
}
constexpr uint32_t enc_ri16(uint32_t op9, int rt, int i16) {
    return (op9 << 23) | (static_cast<uint32_t>(i16 & 0xFFFF) << 7) | static_cast<uint32_t>(rt & 0x7F);
}
constexpr uint32_t enc_ri18(uint32_t op7, int rt, uint32_t i18) {
    return (op7 << 25) | ((i18 & 0x3FFFFu) << 7) | static_cast<uint32_t>(rt & 0x7F);
}
constexpr uint32_t enc_rrr(uint32_t op4, int rt, int ra, int rb, int rc) {
    return (op4 << 28) | (static_cast<uint32_t>(rt & 0x7F) << 21) |
           (static_cast<uint32_t>(rb & 0x7F) << 14) | (static_cast<uint32_t>(ra & 0x7F) << 7) |
           static_cast<uint32_t>(rc & 0x7F);
}

// Specific SPU ISA v1.2 instructions
constexpr uint32_t insn_a(int rt, int ra, int rb)       { return enc_rr(0x0C0, rt, ra, rb); }
constexpr uint32_t insn_sf(int rt, int ra, int rb)      { return enc_rr(0x040, rt, ra, rb); }
constexpr uint32_t insn_cg(int rt, int ra, int rb)      { return enc_rr(0x0C2, rt, ra, rb); }
constexpr uint32_t insn_bg(int rt, int ra, int rb)      { return enc_rr(0x042, rt, ra, rb); }
constexpr uint32_t insn_addx(int rt, int ra, int rb)    { return enc_rr(0x340, rt, ra, rb); }
constexpr uint32_t insn_sfx(int rt, int ra, int rb)     { return enc_rr(0x341, rt, ra, rb); }
constexpr uint32_t insn_and(int rt, int ra, int rb)     { return enc_rr(0x0C1, rt, ra, rb); }
constexpr uint32_t insn_or(int rt, int ra, int rb)      { return enc_rr(0x041, rt, ra, rb); }
constexpr uint32_t insn_xor(int rt, int ra, int rb)     { return enc_rr(0x241, rt, ra, rb); }
constexpr uint32_t insn_cgt(int rt, int ra, int rb)     { return enc_rr(0x240, rt, ra, rb); }
constexpr uint32_t insn_clgt(int rt, int ra, int rb)    { return enc_rr(0x2C0, rt, ra, rb); }
constexpr uint32_t insn_ceq(int rt, int ra, int rb)     { return enc_rr(0x3C0, rt, ra, rb); }
constexpr uint32_t insn_bi(int ra)                      { return enc_rr(0x1A8, 0, ra, 0); }
constexpr uint32_t insn_wrch(int ch, int rt)            { return enc_rr(0x10D, rt, ch, 0); }
constexpr uint32_t insn_rdch(int rt, int ch)            { return enc_rr(0x00D, rt, ch, 0); }
constexpr uint32_t insn_ai(int rt, int ra, int i10)     { return enc_ri10(0x1C, rt, ra, i10); }
constexpr uint32_t insn_ori(int rt, int ra, int i10)    { return enc_ri10(0x04, rt, ra, i10); }
constexpr uint32_t insn_lr(int rt, int ra)              { return enc_ri10(0x04, rt, ra, 0); }
constexpr uint32_t insn_andi(int rt, int ra, int i10)   { return enc_ri10(0x14, rt, ra, i10); }
constexpr uint32_t insn_ceqi(int rt, int ra, int i10)   { return enc_ri10(0x7C, rt, ra, i10); }
constexpr uint32_t insn_cgti(int rt, int ra, int i10)   { return enc_ri10(0x4C, rt, ra, i10); }
constexpr uint32_t insn_clgti(int rt, int ra, int i10)  { return enc_ri10(0x5C, rt, ra, i10); }
constexpr uint32_t insn_lqd(int rt, int ra, int i10)    { return enc_ri10(0x34, rt, ra, i10); }
constexpr uint32_t insn_stqd(int rt, int ra, int i10)   { return enc_ri10(0x24, rt, ra, i10); }
constexpr uint32_t insn_cwd(int rt, int ra, int i7)     { return enc_ri7(0x1F6, rt, ra, i7); }
constexpr uint32_t insn_cdd(int rt, int ra, int i7)     { return enc_ri7(0x1F7, rt, ra, i7); }
constexpr uint32_t insn_rot(int rt, int ra, int rb)     { return enc_rr(0x058, rt, ra, rb); }
constexpr uint32_t insn_roti(int rt, int ra, int i7)    { return enc_ri7(0x078, rt, ra, i7); }
constexpr uint32_t insn_rotmi(int rt, int ra, int i7)   { return enc_ri7(0x079, rt, ra, i7); }
constexpr uint32_t insn_rotmai(int rt, int ra, int i7)  { return enc_ri7(0x07A, rt, ra, i7); }
constexpr uint32_t insn_shli(int rt, int ra, int i7)    { return enc_ri7(0x07B, rt, ra, i7); }
constexpr uint32_t insn_rotqby(int rt, int ra, int rb)  { return enc_rr(0x1DC, rt, ra, rb); }
constexpr uint32_t insn_rotqbyi(int rt, int ra, int i7) { return enc_ri7(0x1FC, rt, ra, i7); }
constexpr uint32_t insn_rotqmbyi(int rt, int ra, int i7){ return enc_ri7(0x1FD, rt, ra, i7); }
constexpr uint32_t insn_rotqmbii(int rt, int ra, int i7){ return enc_ri7(0x1F9, rt, ra, i7); }
constexpr uint32_t insn_il(int rt, int i16)             { return enc_ri16(0x081, rt, i16); }
constexpr uint32_t insn_ilhu(int rt, uint16_t i16)      { return enc_ri16(0x082, rt, static_cast<int>(i16)); }
constexpr uint32_t insn_iohl(int rt, uint16_t i16)      { return enc_ri16(0x0C1, rt, static_cast<int>(i16)); }
constexpr uint32_t insn_fsmbi(int rt, uint16_t i16)     { return enc_ri16(0x065, rt, static_cast<int>(i16)); }
constexpr uint32_t insn_ila(int rt, uint32_t i18)       { return enc_ri18(0x21, rt, i18); }
constexpr uint32_t insn_br(int rel_words)               { return enc_ri16(0x064, 0, rel_words); }
constexpr uint32_t insn_brz(int rt, int rel_words)      { return enc_ri16(0x040, rt, rel_words); }
constexpr uint32_t insn_brnz(int rt, int rel_words)     { return enc_ri16(0x042, rt, rel_words); }
constexpr uint32_t insn_lqa(int rt, int abs_words)      { return enc_ri16(0x061, rt, abs_words); }
constexpr uint32_t insn_selb(int rt, int ra, int rb, int rc)  { return enc_rrr(0x8, rt, ra, rb, rc); }
constexpr uint32_t insn_shufb(int rt, int ra, int rb, int rc) { return enc_rrr(0xB, rt, ra, rb, rc); }

// --- Independent Cell SPU ISA v1.2 Reference Interpreter (Zero Dependency on spudec::sem) ---
struct SpuRefMachine {
    std::array<std::array<uint8_t, 16>, 128> r{};
    std::vector<uint8_t> ls;
    static constexpr uint32_t LSLR = 0x3FFFFu;

    SpuRefMachine() : ls(0x40000, 0) {}

    static int32_t sext(uint32_t v, int bits) {
        uint32_t m = 1u << (bits - 1);
        v &= (1u << bits) - 1u;
        return static_cast<int32_t>((v ^ m) - m);
    }
    static uint32_t bits(uint32_t w, int hi, int lo) {
        return (w >> (31 - lo)) & ((1u << (lo - hi + 1)) - 1u);
    }
    uint32_t get_w(int reg, int slot = 0) const {
        const auto &b = r[reg];
        int o = slot * 4;
        return (static_cast<uint32_t>(b[o]) << 24) | (static_cast<uint32_t>(b[o + 1]) << 16) |
               (static_cast<uint32_t>(b[o + 2]) << 8) | static_cast<uint32_t>(b[o + 3]);
    }
    void set_w(int reg, int slot, uint32_t val) {
        auto &b = r[reg];
        int o = slot * 4;
        b[o]     = static_cast<uint8_t>((val >> 24) & 0xFFu);
        b[o + 1] = static_cast<uint8_t>((val >> 16) & 0xFFu);
        b[o + 2] = static_cast<uint8_t>((val >> 8) & 0xFFu);
        b[o + 3] = static_cast<uint8_t>(val & 0xFFu);
    }
    void set_w0(int reg, uint32_t val) {
        r[reg].fill(0);
        set_w(reg, 0, val);
    }
    void set_repl_w(int reg, uint32_t val) {
        for (int i = 0; i < 4; ++i) set_w(reg, i, val);
    }
    void load_program(uint32_t ea, const std::vector<uint32_t> &words) {
        for (size_t i = 0; i < words.size(); ++i) {
            uint32_t a = (ea + static_cast<uint32_t>(i * 4)) & LSLR;
            uint32_t w = words[i];
            ls[a]     = static_cast<uint8_t>((w >> 24) & 0xFFu);
            ls[a + 1] = static_cast<uint8_t>((w >> 16) & 0xFFu);
            ls[a + 2] = static_cast<uint8_t>((w >> 8) & 0xFFu);
            ls[a + 3] = static_cast<uint8_t>(w & 0xFFu);
        }
    }
    uint32_t fetch(uint32_t pc) const {
        uint32_t a = pc & (LSLR & ~3u);
        return (static_cast<uint32_t>(ls[a]) << 24) | (static_cast<uint32_t>(ls[a + 1]) << 16) |
               (static_cast<uint32_t>(ls[a + 2]) << 8) | static_cast<uint32_t>(ls[a + 3]);
    }
    uint32_t read_ls_u32_be(uint32_t addr) const {
        uint32_t a = addr & LSLR;
        return (static_cast<uint32_t>(ls[a]) << 24) | (static_cast<uint32_t>(ls[(a + 1) & LSLR]) << 16) |
               (static_cast<uint32_t>(ls[(a + 2) & LSLR]) << 8) | static_cast<uint32_t>(ls[(a + 3) & LSLR]);
    }

    // Execute until `bi $lr` (returns to sentinel PC 0x3FFFC) or max_steps exceeded.
    bool run(uint32_t start_pc, int max_steps = 10000) {
        constexpr uint32_t RET_SENTINEL = 0x3FFFCu;
        set_w0(0, RET_SENTINEL);
        uint32_t pc = start_pc;
        for (int step = 0; step < max_steps; ++step) {
            if (pc == RET_SENTINEL) return true;
            uint32_t w = fetch(pc);
            uint32_t op4 = bits(w, 0, 3);
            uint32_t op7 = bits(w, 0, 6);
            uint32_t op8 = bits(w, 0, 7);
            uint32_t op9 = bits(w, 0, 8);
            uint32_t op11 = bits(w, 0, 10);
            int rb = static_cast<int>(bits(w, 11, 17));
            int ra = static_cast<int>(bits(w, 18, 24));
            int rt = static_cast<int>(bits(w, 25, 31));
            uint32_t next_pc = (pc + 4) & LSLR;

            if (op4 == 0x8) { // selb
                int rrt = static_cast<int>(bits(w, 4, 10));
                int rrb = static_cast<int>(bits(w, 11, 17));
                int rra = static_cast<int>(bits(w, 18, 24));
                int rrc = static_cast<int>(bits(w, 25, 31));
                std::array<uint8_t, 16> out{};
                for (int i = 0; i < 16; ++i)
                    out[i] = static_cast<uint8_t>((r[rra][i] & ~r[rrc][i]) | (r[rrb][i] & r[rrc][i]));
                r[rrt] = out;
            } else if (op4 == 0xB) { // shufb
                int rrt = static_cast<int>(bits(w, 4, 10));
                int rrb = static_cast<int>(bits(w, 11, 17));
                int rra = static_cast<int>(bits(w, 18, 24));
                int rrc = static_cast<int>(bits(w, 25, 31));
                std::array<uint8_t, 16> out{};
                for (int i = 0; i < 16; ++i) {
                    uint8_t c = r[rrc][i];
                    if ((c & 0xC0u) == 0x80u) out[i] = 0x00u;
                    else if ((c & 0xE0u) == 0xC0u) out[i] = 0xFFu;
                    else if ((c & 0xE0u) == 0xE0u) out[i] = 0x80u;
                    else {
                        uint8_t idx = c & 0x1Fu;
                        out[i] = (idx < 16) ? r[rra][idx] : r[rrb][idx - 16];
                    }
                }
                r[rrt] = out;
            } else if (op7 == 0x21) { // ila
                set_repl_w(rt, bits(w, 7, 24) & 0x3FFFFu);
            } else if (op8 == 0x1C) { // ai
                uint32_t imm = static_cast<uint32_t>(sext(bits(w, 8, 17), 10));
                for (int i = 0; i < 4; ++i) set_w(rt, i, get_w(ra, i) + imm);
            } else if (op8 == 0x04) { // ori
                uint32_t imm = static_cast<uint32_t>(sext(bits(w, 8, 17), 10));
                for (int i = 0; i < 4; ++i) set_w(rt, i, get_w(ra, i) | imm);
            } else if (op8 == 0x14) { // andi
                uint32_t imm = static_cast<uint32_t>(sext(bits(w, 8, 17), 10));
                for (int i = 0; i < 4; ++i) set_w(rt, i, get_w(ra, i) & imm);
            } else if (op8 == 0x7C) { // ceqi
                uint32_t imm = static_cast<uint32_t>(sext(bits(w, 8, 17), 10));
                for (int i = 0; i < 4; ++i) set_w(rt, i, (get_w(ra, i) == imm) ? 0xFFFFFFFFu : 0u);
            } else if (op8 == 0x4C) { // cgti
                int32_t imm = sext(bits(w, 8, 17), 10);
                for (int i = 0; i < 4; ++i) set_w(rt, i, (static_cast<int32_t>(get_w(ra, i)) > imm) ? 0xFFFFFFFFu : 0u);
            } else if (op8 == 0x5C) { // clgti
                uint32_t imm = static_cast<uint32_t>(sext(bits(w, 8, 17), 10));
                for (int i = 0; i < 4; ++i) set_w(rt, i, (get_w(ra, i) > imm) ? 0xFFFFFFFFu : 0u);
            } else if (op8 == 0x34) { // lqd
                uint32_t off = static_cast<uint32_t>(sext(bits(w, 8, 17), 10) << 4);
                uint32_t ea = (get_w(ra, 0) + off) & (LSLR & ~0xFu);
                for (int i = 0; i < 16; ++i) r[rt][i] = ls[(ea + i) & LSLR];
            } else if (op8 == 0x24) { // stqd
                uint32_t off = static_cast<uint32_t>(sext(bits(w, 8, 17), 10) << 4);
                uint32_t ea = (get_w(ra, 0) + off) & (LSLR & ~0xFu);
                for (int i = 0; i < 16; ++i) ls[(ea + i) & LSLR] = r[rt][i];
            } else if (op9 == 0x081) { // il
                set_repl_w(rt, static_cast<uint32_t>(sext(bits(w, 9, 24), 16)));
            } else if (op9 == 0x082) { // ilhu
                set_repl_w(rt, (bits(w, 9, 24) & 0xFFFFu) << 16);
            } else if (op9 == 0x0C1) { // iohl
                uint32_t imm = bits(w, 9, 24) & 0xFFFFu;
                for (int i = 0; i < 4; ++i) set_w(rt, i, get_w(rt, i) | imm);
            } else if (op9 == 0x065) { // fsmbi
                uint32_t imm = bits(w, 9, 24) & 0xFFFFu;
                for (int i = 0; i < 16; ++i) r[rt][i] = ((imm >> (15 - i)) & 1u) ? 0xFFu : 0x00u;
            } else if (op9 == 0x061) { // lqa
                uint32_t ea = static_cast<uint32_t>(sext(bits(w, 9, 24), 16) << 2) & (LSLR & ~0xFu);
                for (int i = 0; i < 16; ++i) r[rt][i] = ls[(ea + i) & LSLR];
            } else if (op9 == 0x064) { // br
                int32_t off = sext(bits(w, 9, 24), 16) << 2;
                next_pc = static_cast<uint32_t>(static_cast<int64_t>(pc) + off) & (LSLR & ~3u);
            } else if (op9 == 0x040) { // brz
                if (get_w(rt, 0) == 0) {
                    int32_t off = sext(bits(w, 9, 24), 16) << 2;
                    next_pc = static_cast<uint32_t>(static_cast<int64_t>(pc) + off) & (LSLR & ~3u);
                }
            } else if (op9 == 0x042) { // brnz
                if (get_w(rt, 0) != 0) {
                    int32_t off = sext(bits(w, 9, 24), 16) << 2;
                    next_pc = static_cast<uint32_t>(static_cast<int64_t>(pc) + off) & (LSLR & ~3u);
                }
            } else if (op11 == 0x0C0) { // a
                for (int i = 0; i < 4; ++i) set_w(rt, i, get_w(ra, i) + get_w(rb, i));
            } else if (op11 == 0x040) { // sf (rb - ra)
                for (int i = 0; i < 4; ++i) set_w(rt, i, get_w(rb, i) - get_w(ra, i));
            } else if (op11 == 0x0C2) { // cg
                for (int i = 0; i < 4; ++i) {
                    uint64_t s = static_cast<uint64_t>(get_w(ra, i)) + static_cast<uint64_t>(get_w(rb, i));
                    set_w(rt, i, (s > 0xFFFFFFFFULL) ? 1u : 0u);
                }
            } else if (op11 == 0x042) { // bg (rb >= ra ? 1 : 0)
                for (int i = 0; i < 4; ++i) set_w(rt, i, (get_w(rb, i) >= get_w(ra, i)) ? 1u : 0u);
            } else if (op11 == 0x340) { // addx
                for (int i = 0; i < 4; ++i) set_w(rt, i, get_w(ra, i) + get_w(rb, i) + (get_w(rt, i) & 1u));
            } else if (op11 == 0x341) { // sfx
                for (int i = 0; i < 4; ++i) set_w(rt, i, get_w(rb, i) + (~get_w(ra, i)) + (get_w(rt, i) & 1u));
            } else if (op11 == 0x0C1) { // and
                for (int i = 0; i < 4; ++i) set_w(rt, i, get_w(ra, i) & get_w(rb, i));
            } else if (op11 == 0x041) { // or
                for (int i = 0; i < 4; ++i) set_w(rt, i, get_w(ra, i) | get_w(rb, i));
            } else if (op11 == 0x241) { // xor
                for (int i = 0; i < 4; ++i) set_w(rt, i, get_w(ra, i) ^ get_w(rb, i));
            } else if (op11 == 0x240) { // cgt
                for (int i = 0; i < 4; ++i)
                    set_w(rt, i, (static_cast<int32_t>(get_w(ra, i)) > static_cast<int32_t>(get_w(rb, i))) ? 0xFFFFFFFFu : 0u);
            } else if (op11 == 0x2C0) { // clgt
                for (int i = 0; i < 4; ++i)
                    set_w(rt, i, (get_w(ra, i) > get_w(rb, i)) ? 0xFFFFFFFFu : 0u);
            } else if (op11 == 0x3C0) { // ceq
                for (int i = 0; i < 4; ++i)
                    set_w(rt, i, (get_w(ra, i) == get_w(rb, i)) ? 0xFFFFFFFFu : 0u);
            } else if (op11 == 0x058) { // rot
                for (int i = 0; i < 4; ++i) {
                    uint32_t s = get_w(rb, i) & 31u;
                    uint32_t v = get_w(ra, i);
                    set_w(rt, i, s == 0 ? v : ((v << s) | (v >> (32u - s))));
                }
            } else if (op11 == 0x078) { // roti
                uint32_t s = static_cast<uint32_t>(sext(bits(w, 11, 17), 7)) & 31u;
                for (int i = 0; i < 4; ++i) {
                    uint32_t v = get_w(ra, i);
                    set_w(rt, i, s == 0 ? v : ((v << s) | (v >> (32u - s))));
                }
            } else if (op11 == 0x079) { // rotmi
                uint32_t s = static_cast<uint32_t>(-sext(bits(w, 11, 17), 7)) & 0x3Fu;
                for (int i = 0; i < 4; ++i) set_w(rt, i, (s >= 32u) ? 0u : (get_w(ra, i) >> s));
            } else if (op11 == 0x07A) { // rotmai
                uint32_t s = static_cast<uint32_t>(-sext(bits(w, 11, 17), 7)) & 0x3Fu;
                if (s >= 32u) s = 31u;
                for (int i = 0; i < 4; ++i) set_w(rt, i, static_cast<uint32_t>(static_cast<int32_t>(get_w(ra, i)) >> s));
            } else if (op11 == 0x07B) { // shli
                uint32_t s = static_cast<uint32_t>(sext(bits(w, 11, 17), 7)) & 0x3Fu;
                for (int i = 0; i < 4; ++i) set_w(rt, i, (s >= 32u) ? 0u : (get_w(ra, i) << s));
            } else if (op11 == 0x1FD) { // rotqmbyi
                uint32_t s = static_cast<uint32_t>(-sext(bits(w, 11, 17), 7)) & 0x1Fu;
                std::array<uint8_t, 16> out{};
                if (s < 16u) {
                    for (uint32_t i = s; i < 16u; ++i) out[i] = r[ra][i - s];
                }
                r[rt] = out;
            } else if (op11 == 0x1F9) { // rotqmbii
                uint32_t s = static_cast<uint32_t>(-sext(bits(w, 11, 17), 7)) & 0x7u;
                std::array<uint8_t, 16> out{};
                if (s == 0) {
                    out = r[ra];
                } else {
                    uint8_t carry = 0;
                    for (int i = 0; i < 16; ++i) {
                        uint8_t cur = r[ra][i];
                        out[i] = static_cast<uint8_t>((cur >> s) | (carry << (8u - s)));
                        carry = cur;
                    }
                }
                r[rt] = out;
            } else if (op11 == 0x1DC) { // rotqby
                uint32_t s = get_w(rb, 0) & 0xFu;
                std::array<uint8_t, 16> out{};
                for (int i = 0; i < 16; ++i) out[i] = r[ra][(i + s) & 0xFu];
                r[rt] = out;
            } else if (op11 == 0x1F6) { // cwd
                int32_t off = sext(bits(w, 11, 17), 7);
                uint32_t j = (get_w(ra, 0) + static_cast<uint32_t>(off)) & 0xCu;
                std::array<uint8_t, 16> out{};
                for (int i = 0; i < 16; ++i) out[i] = static_cast<uint8_t>(0x10 + i);
                for (uint32_t k = 0; k < 4; ++k) out[j + k] = static_cast<uint8_t>(k);
                r[rt] = out;
            } else if (op11 == 0x1F7) { // cdd
                int32_t off = sext(bits(w, 11, 17), 7);
                uint32_t j = (get_w(ra, 0) + static_cast<uint32_t>(off)) & 0x8u;
                std::array<uint8_t, 16> out{};
                for (int i = 0; i < 16; ++i) out[i] = static_cast<uint8_t>(0x10 + i);
                for (uint32_t k = 0; k < 8; ++k) out[j + k] = static_cast<uint8_t>(k);
                r[rt] = out;
            } else if (op11 == 0x1A8) { // bi
                next_pc = get_w(ra, 0) & (LSLR & ~3u);
            } else if (op11 == 0x1AC || op11 == 0x001 || op11 == 0x201) { // hbr / lnop / nop
                // branch hint / no-op
            } else {
                return false;
            }
            pc = next_pc;
        }
        return false;
    }
};

// --- Real MSVC cl.exe Syntax/Type Oracle & Differential Execution Runner ---
static std::string find_vcvars64() {
    static std::string cached;
    static bool searched = false;
    if (searched) return cached;
    searched = true;

    const char *candidates[] = {
        "C:\\Program Files\\Microsoft Visual Studio\\18\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files\\Microsoft Visual Studio\\18\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Auxiliary\\Build\\vcvars64.bat",
    };
    for (const char *p : candidates) {
        if (std::filesystem::exists(p)) {
            cached = p;
            return cached;
        }
    }
    // Fallback via vswhere.exe
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "spudec_vswhere.txt";
    std::string cmd = "\"%ProgramFiles(x86)%\\Microsoft Visual Studio\\Installer\\vswhere.exe\" "
                      "-latest -products * -property installationPath > \"" + tmp.string() + "\" 2>nul";
    if (std::system(cmd.c_str()) == 0 && std::filesystem::exists(tmp)) {
        std::ifstream ifs(tmp);
        std::string line;
        if (std::getline(ifs, line) && !line.empty()) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
                line.pop_back();
            std::filesystem::path cand = std::filesystem::path(line) / "VC" / "Auxiliary" / "Build" / "vcvars64.bat";
            if (std::filesystem::exists(cand)) cached = cand.string();
        }
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
    }
    return cached;
}

static std::string prelude_header_path() {
    auto p = std::filesystem::current_path() / ".agents" / "skills" / "decompiler-qa-audit" / "resources" / "spudec_audit_prelude.h";
    if (std::filesystem::exists(p)) return p.generic_string();
    return "";
}

static bool msvc_syntax_check_c(const std::string &tag, const std::string &c_code, std::string *out_diag = nullptr) {
    std::string vc = find_vcvars64();
    std::string pre = prelude_header_path();
    if (vc.empty() || pre.empty()) {
        if (out_diag) *out_diag = "MSVC vcvars64.bat or spudec_audit_prelude.h not found";
        return false;
    }
    auto dir = std::filesystem::temp_directory_path() / ("spudec_zs_" + tag);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    auto cpath = dir / "unit.c";
    auto bpath = dir / "run.bat";
    auto lpath = dir / "cl.log";
    {
        std::ofstream ofs(cpath);
        ofs << "#include \"" << pre << "\"\n\n" << c_code << "\n";
    }
    {
        std::ofstream ofs(bpath);
        ofs << "@echo off\r\n"
            << "call \"" << vc << "\" >nul 2>&1\r\n"
            << "if errorlevel 1 exit /b 1\r\n"
            << "cl.exe /nologo /Zs /W3 /TC \"" << cpath.string() << "\" > \"" << lpath.string() << "\" 2>&1\r\n";
    }
    std::string cmd = "cmd.exe /c \"" + bpath.string() + "\"";
    int rc = std::system(cmd.c_str());
    if (out_diag && std::filesystem::exists(lpath)) {
        std::ifstream ifs(lpath);
        std::ostringstream ss;
        ss << ifs.rdbuf();
        *out_diag = ss.str();
    }
    std::filesystem::remove_all(dir, ec);
    return rc == 0;
}

// Compile decompiled C + driver main() and run it, returning stdout and exit code.
static bool msvc_compile_and_run_c(const std::string &tag,
                                   const std::string &c_code,
                                   const std::string &driver_c,
                                   std::string *out_stdout,
                                   std::string *out_diag) {
    std::string vc = find_vcvars64();
    std::string pre = prelude_header_path();
    if (vc.empty() || pre.empty()) {
        if (out_diag) *out_diag = "MSVC vcvars64.bat or spudec_audit_prelude.h not found";
        return false;
    }
    auto dir = std::filesystem::temp_directory_path() / ("spudec_diff_" + tag);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    auto cpath = dir / "harness.c";
    auto epath = dir / "harness.exe";
    auto bpath = dir / "build.bat";
    auto lpath = dir / "build.log";
    auto opath = dir / "run.out";
    {
        std::ofstream ofs(cpath);
        ofs << "#include <stdio.h>\n"
            << "#include <string.h>\n"
            << "#include \"" << pre << "\"\n"
            << "uint8_t g_spu_ls[0x40000];\n\n"
            << c_code << "\n\n"
            << driver_c << "\n";
    }
    {
        std::ofstream ofs(bpath);
        ofs << "@echo off\r\n"
            << "call \"" << vc << "\" >nul 2>&1\r\n"
            << "if errorlevel 1 exit /b 1\r\n"
            << "cl.exe /nologo /TC /Fo:\"" << (dir / "harness.obj").string() << "\" /Fe:\"" << epath.string() << "\" \"" << cpath.string() << "\" > \"" << lpath.string() << "\" 2>&1\r\n";
    }
    std::string bcmd = "cmd.exe /c \"" + bpath.string() + "\"";
    int brc = std::system(bcmd.c_str());
    if (brc != 0) {
        if (out_diag && std::filesystem::exists(lpath)) {
            std::ifstream ifs(lpath);
            std::ostringstream ss;
            ss << ifs.rdbuf();
            *out_diag = ss.str();
        }
        std::filesystem::remove_all(dir, ec);
        return false;
    }
    // Run compiled harness with a 3-second timeout so infinite-looping miscompiled C fails fast!
    std::string rcmd = "powershell -NoProfile -Command \""
                       "$p = Start-Process -FilePath '" + epath.string() + "' "
                       "-RedirectStandardOutput '" + opath.string() + "' -NoNewWindow -PassThru; "
                       "if (-not $p.WaitForExit(3000)) { try { $p.Kill() } catch {}; exit 124 }; "
                       "exit $p.ExitCode\"";
    int rrc = std::system(rcmd.c_str());
    if (rrc == 124) {
        if (out_diag) *out_diag = "TIMEOUT (>3s): compiled decompiled C entered an infinite loop!";
        std::filesystem::remove_all(dir, ec);
        return false;
    }
    if (out_stdout && std::filesystem::exists(opath)) {
        std::ifstream ifs(opath);
        std::ostringstream ss;
        ss << ifs.rdbuf();
        *out_stdout = ss.str();
    }
    std::filesystem::remove_all(dir, ec);
    return rrc == 0;
}

static DecompileOptions make_audit_opts(const std::string &proto = "") {
    DecompileOptions dopts;
    dopts.verify_ssa = true;
    if (!proto.empty()) dopts.user_data.set_func_proto(proto);
    return dopts;
}

// ---------------------------------------------------------------------------
// E2E Test 1 (Differential): Signed `cgt` vs Unsigned `clgt` + Arithmetic `rotmai` vs Logical `rotmi`
// ---------------------------------------------------------------------------
static void test_e2e_arith_signed_unsigned_compare() {
    const char *T = "test_e2e_arith_signed_unsigned_compare";
    // Function 1A: signed_gt(u32 a, u32 b) -> cgt r3, r3, r4; bi lr
    // Function 1B: arith_shr4(u32 a) -> rotmai r3, r3, -4; bi lr
    {
        MockDatabaseProvider db;
        std::vector<uint32_t> prog = {
            insn_cgt(3, 3, 4),
            insn_bi(0),
        };
        for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1000 + i * 4, prog[i]);
        db.func_names[0x1000] = "spu_cgt";
        db.flowcharts[0x1000] = { FlowBlockRange{0, 0x1000, 0x1008, {}, {}} };

        auto out = decompile_function(db, 0x1000, make_audit_opts("u32 spu_cgt(u32 a1, u32 a2)"));
        if (!out.cfunc || !out.ir_func->problems.empty()) {
            record_failure(T, "spu_cgt failed decompile or SSA verify");
            return;
        }
        std::string ctxt = out.cfunc->print_func();
        std::string diag;
        if (!msvc_syntax_check_c("cgt", ctxt, &diag)) {
            record_failure(T, "spu_cgt failed MSVC /Zs:\n" + diag + "\n" + ctxt);
            return;
        }
        // Differential execution across signed/unsigned boundaries
        const uint32_t pairs[][2] = {
            {0xFFFFFFFFu, 1u},          // -1 > 1: signed FALSE (0), unsigned TRUE!
            {1u, 0xFFFFFFFFu},          // 1 > -1: signed TRUE (0xFFFFFFFF), unsigned FALSE!
            {0x80000000u, 0x7FFFFFFFu}, // INT_MIN > INT_MAX: signed FALSE (0)
            {0x7FFFFFFFu, 0x80000000u}, // INT_MAX > INT_MIN: signed TRUE (0xFFFFFFFF)
            {0u, 0u},
        };
        std::ostringstream drv;
        drv << "int main(void) {\n"
            << "  const u32 a[] = {0xFFFFFFFFu, 1u, 0x80000000u, 0x7FFFFFFFu, 0u};\n"
            << "  const u32 b[] = {1u, 0xFFFFFFFFu, 0x7FFFFFFFu, 0x80000000u, 0u};\n"
            << "  for (int i = 0; i < 5; ++i) printf(\"%08X\\n\", spu_cgt(a[i], b[i]));\n"
            << "  return 0;\n}\n";
        std::string run_out;
        if (!msvc_compile_and_run_c("cgt", ctxt, drv.str(), &run_out, &diag)) {
            record_failure(T, "spu_cgt failed compile/run:\n" + diag + "\n" + ctxt);
        } else {
            std::istringstream iss(run_out);
            for (int i = 0; i < 5; ++i) {
                SpuRefMachine m;
                m.load_program(0x1000, prog);
                m.set_w0(3, pairs[i][0]);
                m.set_w0(4, pairs[i][1]);
                if (!m.run(0x1000)) { record_failure(T, "SpuRefMachine::run failed"); break; }
                uint32_t expected = m.get_w(3, 0);
                uint32_t actual = 0;
                iss >> std::hex >> actual;
                if (actual != expected) {
                    char buf[256];
                    std::snprintf(buf, sizeof(buf),
                                  "cgt(0x%08X, 0x%08X) mismatch: ISA ref=0x%08X vs compiled C=0x%08X\nEmitted C:\n%s",
                                  pairs[i][0], pairs[i][1], expected, actual, ctxt.c_str());
                    record_failure(T, buf);
                    break;
                }
            }
        }
    }

    // Function 1B: rotmai (arithmetic right shift by 4) on 0x80000000 must sign-extend to 0xF8000000!
    {
        MockDatabaseProvider db;
        std::vector<uint32_t> prog = {
            insn_rotmai(3, 3, -4),
            insn_bi(0),
        };
        for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1040 + i * 4, prog[i]);
        db.func_names[0x1040] = "spu_rotmai4";
        db.flowcharts[0x1040] = { FlowBlockRange{0, 0x1040, 0x1048, {}, {}} };

        auto out = decompile_function(db, 0x1040, make_audit_opts("u32 spu_rotmai4(u32 a1)"));
        if (!out.cfunc || !out.ir_func->problems.empty()) {
            record_failure(T, "spu_rotmai4 failed decompile or SSA verify");
            return;
        }
        std::string ctxt = out.cfunc->print_func();
        std::string diag, run_out;
        const uint32_t inputs[] = {0x80000000u, 0xFFFFFFFFu, 0x7FFFFFFFu, 0x00000100u};
        std::string drv =
            "int main(void) {\n"
            "  const u32 a[] = {0x80000000u, 0xFFFFFFFFu, 0x7FFFFFFFu, 0x00000100u};\n"
            "  for (int i = 0; i < 4; ++i) printf(\"%08X\\n\", spu_rotmai4(a[i]));\n"
            "  return 0;\n}\n";
        if (!msvc_compile_and_run_c("rotmai4", ctxt, drv, &run_out, &diag)) {
            record_failure(T, "spu_rotmai4 failed compile/run:\n" + diag + "\n" + ctxt);
        } else {
            std::istringstream iss(run_out);
            for (int i = 0; i < 4; ++i) {
                SpuRefMachine m;
                m.load_program(0x1040, prog);
                m.set_w0(3, inputs[i]);
                if (!m.run(0x1040)) { record_failure(T, "SpuRefMachine::run failed"); break; }
                uint32_t expected = m.get_w(3, 0);
                uint32_t actual = 0;
                iss >> std::hex >> actual;
                if (actual != expected) {
                    char buf[256];
                    std::snprintf(buf, sizeof(buf),
                                  "rotmai4(0x%08X) mismatch: ISA ref=0x%08X vs compiled C=0x%08X\nEmitted C:\n%s",
                                  inputs[i], expected, actual, ctxt.c_str());
                    record_failure(T, buf);
                    break;
                }
            }
        }
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 2 (Differential): Quadword Right Shifts `rotqmbyi` & `rotqmbii` (Double-Negation Probe)
// ---------------------------------------------------------------------------
static void test_e2e_quadword_rotqmbyi_rotqmbii() {
    const char *T = "test_e2e_quadword_rotqmbyi_rotqmbii";
    // Constant-folded rotqmbyi:
    //   ilhu r4, 0x1122
    //   iohl r4, 0x3344
    //   rotqmbyi r4, r4, -4   ; shifts word 0 (0x11223344) into word 1, word 0 becomes 0
    //   rotqbyi r3, r4, 4     ; rotates word 1 back into word 0 -> MUST BE 0x11223344!
    //   bi lr
    MockDatabaseProvider db;
    std::vector<uint32_t> prog = {
        insn_ilhu(4, 0x1122),
        insn_iohl(4, 0x3344),
        insn_rotqmbyi(4, 4, -4),
        insn_rotqbyi(3, 4, 4),
        insn_bi(0),
    };
    for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1100 + i * 4, prog[i]);
    db.func_names[0x1100] = "spu_rotqmbyi_const";
    db.flowcharts[0x1100] = { FlowBlockRange{0, 0x1100, 0x1114, {}, {}} };

    SpuRefMachine m;
    m.load_program(0x1100, prog);
    // Note: rotqbyi is not in our tiny ref loop above; compute ISA v1.2 exact result:
    // r4 = [11223344, 11223344, 11223344, 11223344]
    // rotqmbyi -4 -> [00000000, 11223344, 11223344, 11223344]
    // rotqbyi +4  -> [11223344, 11223344, 11223344, 00000000] -> word 0 = 0x11223344!
    const uint32_t expected = 0x11223344u;

    auto out = decompile_function(db, 0x1100, make_audit_opts("u32 spu_rotqmbyi_const(void)"));
    if (!out.cfunc || !out.ir_func->problems.empty()) {
        record_failure(T, "spu_rotqmbyi_const failed decompile or SSA verify");
        return;
    }
    std::string ctxt = out.cfunc->print_func();
    std::string diag, run_out;
    std::string drv = "int main(void) { printf(\"%08X\\n\", spu_rotqmbyi_const()); return 0; }\n";
    if (!msvc_compile_and_run_c("rotqmbyi_const", ctxt, drv, &run_out, &diag)) {
        record_failure(T, "spu_rotqmbyi_const failed compile/run:\n" + diag + "\n" + ctxt);
    } else {
        uint32_t actual = 0;
        std::istringstream(run_out) >> std::hex >> actual;
        if (actual != expected) {
            char buf[256];
            std::snprintf(buf, sizeof(buf),
                          "rotqmbyi_const mismatch: ISA ref=0x%08X vs compiled C=0x%08X (double-negation bug!)\nEmitted C:\n%s",
                          expected, actual, ctxt.c_str());
            record_failure(T, buf);
        }
    }

    // Also test rotqmbii constant-folded: 0x00000080 shifted right by 3 bits (-3) -> 0x00000010
    {
        MockDatabaseProvider db2;
        std::vector<uint32_t> prog2 = {
            insn_il(4, 0x80),
            insn_rotqmbii(3, 4, -3),
            insn_bi(0),
        };
        for (size_t i = 0; i < prog2.size(); ++i) db2.write_u32_be(0x1140 + i * 4, prog2[i]);
        db2.func_names[0x1140] = "spu_rotqmbii_const";
        db2.flowcharts[0x1140] = { FlowBlockRange{0, 0x1140, 0x114C, {}, {}} };

        SpuRefMachine m2;
        m2.load_program(0x1140, prog2);
        if (!m2.run(0x1140)) { record_failure(T, "SpuRefMachine::run failed"); return; }
        uint32_t exp2 = m2.get_w(3, 0); // 0x00000010

        auto out2 = decompile_function(db2, 0x1140, make_audit_opts("u32 spu_rotqmbii_const(void)"));
        std::string ctxt2 = out2.cfunc->print_func();
        std::string diag2, run_out2;
        std::string drv2 = "int main(void) { printf(\"%08X\\n\", spu_rotqmbii_const()); return 0; }\n";
        if (!msvc_compile_and_run_c("rotqmbii_const", ctxt2, drv2, &run_out2, &diag2)) {
            record_failure(T, "spu_rotqmbii_const failed compile/run:\n" + diag2 + "\n" + ctxt2);
        } else {
            uint32_t act2 = 0;
            std::istringstream(run_out2) >> std::hex >> act2;
            if (act2 != exp2) {
                char buf[256];
                std::snprintf(buf, sizeof(buf),
                              "rotqmbii_const mismatch: ISA ref=0x%08X vs compiled C=0x%08X\nEmitted C:\n%s",
                              exp2, act2, ctxt2.c_str());
                record_failure(T, buf);
            }
        }
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 3 (Differential): Extended Carry/Borrow Arithmetic (`cg` + `addx`, `bg` + `sfx`)
// ---------------------------------------------------------------------------
static void test_e2e_extended_carry_borrow() {
    const char *T = "test_e2e_extended_carry_borrow";
    // 3A: bg r3, r3, r4; bi lr  -> ISA: (r4 >= r3) ? 1 : 0 (note equality r3 == r4 MUST be 1!)
    {
        MockDatabaseProvider db;
        std::vector<uint32_t> prog = { insn_bg(3, 3, 4), insn_bi(0) };
        for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1200 + i * 4, prog[i]);
        db.func_names[0x1200] = "spu_bg";
        db.flowcharts[0x1200] = { FlowBlockRange{0, 0x1200, 0x1208, {}, {}} };

        auto out = decompile_function(db, 0x1200, make_audit_opts("u32 spu_bg(u32 a1, u32 a2)"));
        std::string ctxt = out.cfunc->print_func();
        std::string diag, run_out;
        const uint32_t pairs[][2] = {{5u, 5u}, {5u, 6u}, {6u, 5u}, {0u, 0u}, {0xFFFFFFFFu, 0xFFFFFFFFu}};
        std::string drv =
            "int main(void) {\n"
            "  const u32 a[] = {5u, 5u, 6u, 0u, 0xFFFFFFFFu};\n"
            "  const u32 b[] = {5u, 6u, 5u, 0u, 0xFFFFFFFFu};\n"
            "  for (int i = 0; i < 5; ++i) printf(\"%08X\\n\", spu_bg(a[i], b[i]));\n"
            "  return 0;\n}\n";
        if (!msvc_compile_and_run_c("bg", ctxt, drv, &run_out, &diag)) {
            record_failure(T, "spu_bg failed compile/run:\n" + diag + "\n" + ctxt);
        } else {
            std::istringstream iss(run_out);
            for (int i = 0; i < 5; ++i) {
                SpuRefMachine m;
                m.load_program(0x1200, prog);
                m.set_w0(3, pairs[i][0]);
                m.set_w0(4, pairs[i][1]);
                if (!m.run(0x1200)) { record_failure(T, "SpuRefMachine::run failed"); break; }
                uint32_t exp = m.get_w(3, 0);
                uint32_t act = 0;
                iss >> std::hex >> act;
                if (act != exp) {
                    char buf[256];
                    std::snprintf(buf, sizeof(buf),
                                  "bg(ra=0x%X, rb=0x%X) mismatch: ISA ref=%u vs compiled C=%u\nEmitted C:\n%s",
                                  pairs[i][0], pairs[i][1], exp, act, ctxt.c_str());
                    record_failure(T, buf);
                    break;
                }
            }
        }
    }

    // 3B: addx r5, r3, r4; lr r3, r5; bi lr  -> ISA: r3 + r4 + (r5 & 1)
    {
        MockDatabaseProvider db;
        std::vector<uint32_t> prog = {
            insn_addx(5, 3, 4),
            insn_lr(3, 5),
            insn_bi(0),
        };
        for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1240 + i * 4, prog[i]);
        db.func_names[0x1240] = "spu_addx";
        db.flowcharts[0x1240] = { FlowBlockRange{0, 0x1240, 0x124C, {}, {}} };

        auto out = decompile_function(db, 0x1240, make_audit_opts("u32 spu_addx(u32 a1, u32 a2, u32 a3)"));
        std::string ctxt = out.cfunc->print_func();
        std::string diag, run_out;
        std::string drv =
            "int main(void) {\n"
            "  printf(\"%08X\\n\", spu_addx(10u, 20u, 1u));\n"
            "  printf(\"%08X\\n\", spu_addx(0xFFFFFFFFu, 0u, 1u));\n"
            "  printf(\"%08X\\n\", spu_addx(10u, 20u, 0u));\n"
            "  return 0;\n}\n";
        if (!msvc_compile_and_run_c("addx", ctxt, drv, &run_out, &diag)) {
            record_failure(T, "spu_addx failed compile/run:\n" + diag + "\n" + ctxt);
        } else {
            const uint32_t cases[][3] = {{10u, 20u, 1u}, {0xFFFFFFFFu, 0u, 1u}, {10u, 20u, 0u}};
            std::istringstream iss(run_out);
            for (int i = 0; i < 3; ++i) {
                SpuRefMachine m;
                m.load_program(0x1240, prog);
                m.set_w0(3, cases[i][0]);
                m.set_w0(4, cases[i][1]);
                m.set_w0(5, cases[i][2]);
                if (!m.run(0x1240)) { record_failure(T, "SpuRefMachine::run failed"); break; }
                uint32_t exp = m.get_w(3, 0);
                uint32_t act = 0;
                iss >> std::hex >> act;
                if (act != exp) {
                    char buf[256];
                    std::snprintf(buf, sizeof(buf),
                                  "addx(%u, %u, carry=%u) mismatch: ISA ref=0x%08X vs compiled C=0x%08X\nEmitted C:\n%s",
                                  cases[i][0], cases[i][1], cases[i][2], exp, act, ctxt.c_str());
                    record_failure(T, buf);
                    break;
                }
            }
        }
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 4 (Differential): Preferred-Slot Immediates (`ila`, `il`, `ilhu`+`iohl`) & `selb` Direction
// ---------------------------------------------------------------------------
static void test_e2e_preferred_slot_and_immediates() {
    const char *T = "test_e2e_preferred_slot_and_immediates";
    // Compute: if (a1 > a2 unsigned) pick 0x0003FFFF (ila) else pick 0x11223344 (ilhu+iohl) via selb!
    //   0x1300: clgt r5, r3, r4       ; mask = (a1 > a2) ? 0xFFFFFFFF : 0
    //   0x1304: ila  r6, 0x3FFFF      ; zero-extended 18-bit (NOT sign-extended!)
    //   0x1308: ilhu r7, 0x1122
    //   0x130C: iohl r7, 0x3344       ; 0x11223344
    //   0x1310: selb r3, r7, r6, r5   ; (r7 & ~r5) | (r6 & r5) -> r5 ? r6 : r7
    //   0x1314: bi   lr
    MockDatabaseProvider db;
    std::vector<uint32_t> prog = {
        insn_clgt(5, 3, 4),
        insn_ila(6, 0x3FFFFu),
        insn_ilhu(7, 0x1122u),
        insn_iohl(7, 0x3344u),
        insn_selb(3, 7, 6, 5),
        insn_bi(0),
    };
    for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1300 + i * 4, prog[i]);
    db.func_names[0x1300] = "spu_selb_imm";
    db.flowcharts[0x1300] = { FlowBlockRange{0, 0x1300, 0x1318, {}, {}} };

    auto out = decompile_function(db, 0x1300, make_audit_opts("u32 spu_selb_imm(u32 a1, u32 a2)"));
    if (!out.cfunc || !out.ir_func->problems.empty()) {
        record_failure(T, "spu_selb_imm failed decompile or SSA verify");
        return;
    }
    std::string ctxt = out.cfunc->print_func();
    std::string diag, run_out;
    const uint32_t pairs[][2] = {{10u, 5u}, {5u, 10u}, {0xFFFFFFFFu, 1u}, {1u, 0xFFFFFFFFu}};
    std::string drv =
        "int main(void) {\n"
        "  const u32 a[] = {10u, 5u, 0xFFFFFFFFu, 1u};\n"
        "  const u32 b[] = {5u, 10u, 1u, 0xFFFFFFFFu};\n"
        "  for (int i = 0; i < 4; ++i) printf(\"%08X\\n\", spu_selb_imm(a[i], b[i]));\n"
        "  return 0;\n}\n";
    if (!msvc_compile_and_run_c("selb_imm", ctxt, drv, &run_out, &diag)) {
        record_failure(T, "spu_selb_imm failed compile/run:\n" + diag + "\n" + ctxt);
    } else {
        std::istringstream iss(run_out);
        for (int i = 0; i < 4; ++i) {
            SpuRefMachine m;
            m.load_program(0x1300, prog);
            m.set_w0(3, pairs[i][0]);
            m.set_w0(4, pairs[i][1]);
            if (!m.run(0x1300)) { record_failure(T, "SpuRefMachine::run failed"); break; }
            uint32_t exp = m.get_w(3, 0);
            uint32_t act = 0;
            iss >> std::hex >> act;
            if (act != exp) {
                char buf[256];
                std::snprintf(buf, sizeof(buf),
                              "selb_imm(0x%08X, 0x%08X) mismatch: ISA ref=0x%08X vs compiled C=0x%08X\nEmitted C:\n%s",
                              pairs[i][0], pairs[i][1], exp, act, ctxt.c_str());
                record_failure(T, buf);
                break;
            }
        }
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 5 (Negative / Aliasing Hazard): RMW Store Canary & Intervening Aliasing Store
// ---------------------------------------------------------------------------
static void test_e2e_rmw_store_canary_and_alias_hazard() {
    const char *T = "test_e2e_rmw_store_canary_and_alias_hazard";
    // Negative hazard: lqd r7, 0(r3) -> stqd r5, 0(r4) [MAY ALIAS r3!] -> cwd r6, 4(r3) -> shufb r8, r4, r7, r6 -> stqd r8, 0(r3)
    // In SPU hardware, if r4 == r3, the final stqd overwrites word 0/2/3 with the STALE values from lqd (BEFORE stqd r5)!
    // Scalarizing to `*(u32*)(r3 + 4) = ...` silently drops the stale-quadword overwrite!
    MockDatabaseProvider db;
    std::vector<uint32_t> prog = {
        insn_lqd(7, 3, 0),
        insn_stqd(5, 4, 0),       // intervening potentially-aliasing store!
        insn_cwd(6, 3, 4),
        insn_shufb(8, 4, 7, 6),
        insn_stqd(8, 3, 0),
        insn_bi(0),
    };
    for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1400 + i * 4, prog[i]);
    db.func_names[0x1400] = "spu_rmw_alias_hazard";
    db.flowcharts[0x1400] = { FlowBlockRange{0, 0x1400, 0x1418, {}, {}} };

    auto out = decompile_function(db, 0x1400, make_audit_opts());
    if (!out.cfunc || !out.ir_func->problems.empty()) {
        record_failure(T, "spu_rmw_alias_hazard failed decompile or SSA verify");
        return;
    }
    int assumed = out.ir_func->scalar_stats["assumed_noalias"];
    if (assumed > 0) {
        record_failure(T, "scalarize silently assumed no-alias across intervening potentially-aliasing stqd (assumed_noalias=" +
                          std::to_string(assumed) + ")! When r4==r3, this miscompiles SPU RMW semantics.");
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 6 (Structuring + Differential): Multi-block `if / else if / else` Chain
// ---------------------------------------------------------------------------
static void test_e2e_struct_if_else_chain() {
    const char *T = "test_e2e_struct_if_else_chain";
    //   0x1500 (b0): ceqi r5, r3, 1; brz r5, +3 (0x1510)
    //   0x1508 (b1): il r3, 100; br +6 (0x1524)
    //   0x1510 (b2): ceqi r5, r3, 2; brz r5, +3 (0x1520)
    //   0x1518 (b3): il r3, 200; br +2 (0x1524)
    //   0x1520 (b4): il r3, 300
    //   0x1524 (b5): bi lr
    MockDatabaseProvider db;
    std::vector<uint32_t> prog = {
        insn_ceqi(5, 3, 1), insn_brz(5, 3),  // 0x1500, 0x1504 -> taken 0x1510
        insn_il(3, 100),    insn_br(6),      // 0x1508, 0x150C -> 0x1524
        insn_ceqi(5, 3, 2), insn_brz(5, 3),  // 0x1510, 0x1514 -> taken 0x1520
        insn_il(3, 200),    insn_br(2),      // 0x1518, 0x151C -> 0x1524
        insn_il(3, 300),                     // 0x1520
        insn_bi(0),                          // 0x1524
    };
    for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1500 + i * 4, prog[i]);
    db.func_names[0x1500] = "spu_if_else_chain";
    db.flowcharts[0x1500] = {
        FlowBlockRange{0, 0x1500, 0x1508, {1, 2}, {}},
        FlowBlockRange{1, 0x1508, 0x1510, {5}, {0}},
        FlowBlockRange{2, 0x1510, 0x1518, {3, 4}, {0}},
        FlowBlockRange{3, 0x1518, 0x1520, {5}, {2}},
        FlowBlockRange{4, 0x1520, 0x1524, {5}, {2}},
        FlowBlockRange{5, 0x1524, 0x1528, {}, {1, 3, 4}},
    };

    auto out = decompile_function(db, 0x1500, make_audit_opts("u32 spu_if_else_chain(u32 a1)"));
    if (!out.cfunc || !out.ir_func->problems.empty()) {
        record_failure(T, "spu_if_else_chain failed decompile or SSA verify");
        return;
    }
    std::string ctxt = out.cfunc->print_func();
    std::string diag, run_out;
    const uint32_t inputs[] = {0u, 1u, 2u, 3u, 0xFFFFFFFFu};
    std::string drv =
        "int main(void) {\n"
        "  const u32 a[] = {0u, 1u, 2u, 3u, 0xFFFFFFFFu};\n"
        "  for (int i = 0; i < 5; ++i) printf(\"%08X\\n\", spu_if_else_chain(a[i]));\n"
        "  return 0;\n}\n";
    if (!msvc_compile_and_run_c("if_else_chain", ctxt, drv, &run_out, &diag)) {
        record_failure(T, "spu_if_else_chain failed compile/run:\n" + diag + "\n" + ctxt);
    } else {
        std::istringstream iss(run_out);
        for (int i = 0; i < 5; ++i) {
            SpuRefMachine m;
            m.load_program(0x1500, prog);
            m.set_w0(3, inputs[i]);
            if (!m.run(0x1500)) { record_failure(T, "SpuRefMachine::run failed"); break; }
            uint32_t exp = m.get_w(3, 0);
            uint32_t act = 0;
            iss >> std::hex >> act;
            if (act != exp) {
                record_failure(T, "if_else_chain mismatch for input " + std::to_string(inputs[i]) +
                                  ": expected " + std::to_string(exp) + " got " + std::to_string(act));
                break;
            }
        }
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 7 (Structuring + Differential): Pre-tested `while` Loop (Sum 1..n)
// ---------------------------------------------------------------------------
static void test_e2e_struct_while_loop_sum() {
    const char *T = "test_e2e_struct_while_loop_sum";
    //   0x1600 (b0): il r4, 0                 ; sum = 0
    //   0x1604 (b1): brz r3, +4 (0x1614)      ; while (n != 0)
    //   0x1608 (b2): a r4, r4, r3; ai r3, r3, -1; br -3 (0x1604)
    //   0x1614 (b3): lr r3, r4; bi lr
    MockDatabaseProvider db;
    std::vector<uint32_t> prog = {
        insn_il(4, 0),            // 0x1600
        insn_brz(3, 4),           // 0x1604 -> 0x1614
        insn_a(4, 4, 3),          // 0x1608
        insn_ai(3, 3, -1),        // 0x160C
        insn_br(-3),              // 0x1610 -> 0x1604
        insn_lr(3, 4),            // 0x1614
        insn_bi(0),               // 0x1618
    };
    for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1600 + i * 4, prog[i]);
    db.func_names[0x1600] = "spu_while_sum";
    db.flowcharts[0x1600] = {
        FlowBlockRange{0, 0x1600, 0x1604, {1}, {}},
        FlowBlockRange{1, 0x1604, 0x1608, {2, 3}, {0, 2}},
        FlowBlockRange{2, 0x1608, 0x1614, {1}, {1}},
        FlowBlockRange{3, 0x1614, 0x161C, {}, {1}},
    };

    auto out = decompile_function(db, 0x1600, make_audit_opts("u32 spu_while_sum(u32 a1)"));
    if (!out.cfunc || !out.ir_func->problems.empty()) {
        record_failure(T, "spu_while_sum failed decompile or SSA verify");
        return;
    }
    std::string ctxt = out.cfunc->print_func();
    if (ctxt.find("while") == std::string::npos) {
        record_failure(T, "spu_while_sum did not structure as while loop:\n" + ctxt);
    }
    std::string diag, run_out;
    const uint32_t inputs[] = {0u, 1u, 5u, 10u, 100u};
    std::string drv =
        "int main(void) {\n"
        "  const u32 a[] = {0u, 1u, 5u, 10u, 100u};\n"
        "  for (int i = 0; i < 5; ++i) printf(\"%08X\\n\", spu_while_sum(a[i]));\n"
        "  return 0;\n}\n";
    if (!msvc_compile_and_run_c("while_sum", ctxt, drv, &run_out, &diag)) {
        record_failure(T, "spu_while_sum failed compile/run:\n" + diag + "\n" + ctxt);
    } else {
        std::istringstream iss(run_out);
        for (int i = 0; i < 5; ++i) {
            SpuRefMachine m;
            m.load_program(0x1600, prog);
            m.set_w0(3, inputs[i]);
            if (!m.run(0x1600)) { record_failure(T, "SpuRefMachine::run failed"); break; }
            uint32_t exp = m.get_w(3, 0);
            uint32_t act = 0;
            iss >> std::hex >> act;
            if (act != exp) {
                record_failure(T, "while_sum mismatch for n=" + std::to_string(inputs[i]) +
                                  ": expected " + std::to_string(exp) + " got " + std::to_string(act));
                break;
            }
        }
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 8 (Structuring + Differential): Post-tested `do { ... } while (...)` Loop
// ---------------------------------------------------------------------------
static void test_e2e_struct_do_while_loop() {
    const char *T = "test_e2e_struct_do_while_loop";
    //   0x1700 (b0): il r4, 1
    //   0x1704 (b1): a r4, r4, r4; ai r3, r3, -1; brnz r3, -2 (0x1704)
    //   0x1710 (b2): lr r3, r4; bi lr
    MockDatabaseProvider db;
    std::vector<uint32_t> prog = {
        insn_il(4, 1),            // 0x1700
        insn_a(4, 4, 4),          // 0x1704
        insn_ai(3, 3, -1),        // 0x1708
        insn_brnz(3, -2),         // 0x170C -> 0x1704
        insn_lr(3, 4),            // 0x1710
        insn_bi(0),               // 0x1714
    };
    for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1700 + i * 4, prog[i]);
    db.func_names[0x1700] = "spu_do_while";
    db.flowcharts[0x1700] = {
        FlowBlockRange{0, 0x1700, 0x1704, {1}, {}},
        FlowBlockRange{1, 0x1704, 0x1710, {1, 2}, {0, 1}},
        FlowBlockRange{2, 0x1710, 0x1718, {}, {1}},
    };

    auto out = decompile_function(db, 0x1700, make_audit_opts("u32 spu_do_while(u32 a1)"));
    if (!out.cfunc || !out.ir_func->problems.empty()) {
        record_failure(T, "spu_do_while failed decompile or SSA verify");
        return;
    }
    std::string ctxt = out.cfunc->print_func();
    if (ctxt.find("do") == std::string::npos) {
        record_failure(T, "spu_do_while did not structure as do-while:\n" + ctxt);
    }
    std::string diag, run_out;
    const uint32_t inputs[] = {1u, 2u, 4u, 10u};
    std::string drv =
        "int main(void) {\n"
        "  const u32 a[] = {1u, 2u, 4u, 10u};\n"
        "  for (int i = 0; i < 4; ++i) printf(\"%08X\\n\", spu_do_while(a[i]));\n"
        "  return 0;\n}\n";
    if (!msvc_compile_and_run_c("do_while", ctxt, drv, &run_out, &diag)) {
        record_failure(T, "spu_do_while failed compile/run:\n" + diag + "\n" + ctxt);
    } else {
        std::istringstream iss(run_out);
        for (int i = 0; i < 4; ++i) {
            SpuRefMachine m;
            m.load_program(0x1700, prog);
            m.set_w0(3, inputs[i]);
            if (!m.run(0x1700)) { record_failure(T, "SpuRefMachine::run failed"); break; }
            uint32_t exp = m.get_w(3, 0);
            uint32_t act = 0;
            iss >> std::hex >> act;
            if (act != exp) {
                record_failure(T, "do_while mismatch for n=" + std::to_string(inputs[i]));
                break;
            }
        }
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 9 (Structuring + Differential): Loop with Early `break` & `continue`
// ---------------------------------------------------------------------------
static void test_e2e_struct_loop_break_continue() {
    const char *T = "test_e2e_struct_loop_break_continue";
    // Sum odd numbers from n down to 1, stopping early if sum > 20!
    //   0x1800 (b0): il r4, 0                 ; sum = 0
    //   0x1804 (b1): brz r3, +9 (0x1828)      ; if (n == 0) break
    //   0x1808 (b2): andi r5, r3, 1; brz r5, +4 (0x181C) ; if ((n & 1) == 0) continue-latch
    //   0x1810 (b3): a r4, r4, r3; cgti r6, r4, 20; brnz r6, +4 (0x1828) ; if (sum > 20) break
    //   0x181C (b4): ai r3, r3, -1; br -7 (0x1804)
    //   0x1828 (b5): lr r3, r4; bi lr
    MockDatabaseProvider db;
    std::vector<uint32_t> prog = {
        insn_il(4, 0),            // 0x1800
        insn_brz(3, 9),           // 0x1804 -> 0x1828
        insn_andi(5, 3, 1),       // 0x1808
        insn_brz(5, 4),           // 0x180C -> 0x181C
        insn_a(4, 4, 3),          // 0x1810
        insn_cgti(6, 4, 20),      // 0x1814
        insn_brnz(6, 4),          // 0x1818 -> 0x1828
        insn_ai(3, 3, -1),        // 0x181C
        insn_br(-7),              // 0x1820 -> 0x1804
        insn_lr(3, 4),            // 0x1824 (padding nop? wait: 0x1824 is +8 from 0x1804, let's align exact!)
    };
    // Exact offsets:
    // 0x1800: il r4, 0
    // 0x1804: brz r3, +8  -> 0x1824
    // 0x1808: andi r5, r3, 1
    // 0x180C: brz r5, +4  -> 0x181C
    // 0x1810: a r4, r4, r3
    // 0x1814: cgti r6, r4, 20
    // 0x1818: brnz r6, +3 -> 0x1824
    // 0x181C: ai r3, r3, -1
    // 0x1820: br -7       -> 0x1804
    // 0x1824: lr r3, r4
    // 0x1828: bi lr
    prog = {
        insn_il(4, 0),            // 0x1800
        insn_brz(3, 8),           // 0x1804 -> 0x1824
        insn_andi(5, 3, 1),       // 0x1808
        insn_brz(5, 4),           // 0x180C -> 0x181C
        insn_a(4, 4, 3),          // 0x1810
        insn_cgti(6, 4, 20),      // 0x1814
        insn_brnz(6, 3),          // 0x1818 -> 0x1824
        insn_ai(3, 3, -1),        // 0x181C
        insn_br(-7),              // 0x1820 -> 0x1804
        insn_lr(3, 4),            // 0x1824
        insn_bi(0),               // 0x1828
    };
    for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1800 + i * 4, prog[i]);
    db.func_names[0x1800] = "spu_loop_break_cont";
    db.flowcharts[0x1800] = {
        FlowBlockRange{0, 0x1800, 0x1804, {1}, {}},
        FlowBlockRange{1, 0x1804, 0x1808, {2, 5}, {0, 4}},
        FlowBlockRange{2, 0x1808, 0x1810, {3, 4}, {1}},
        FlowBlockRange{3, 0x1810, 0x181C, {4, 5}, {2}},
        FlowBlockRange{4, 0x181C, 0x1824, {1}, {2, 3}},
        FlowBlockRange{5, 0x1824, 0x182C, {}, {1, 3}},
    };

    auto out = decompile_function(db, 0x1800, make_audit_opts("u32 spu_loop_break_cont(u32 a1)"));
    if (!out.cfunc || !out.ir_func->problems.empty()) {
        record_failure(T, "spu_loop_break_cont failed decompile or SSA verify");
        return;
    }
    std::string ctxt = out.cfunc->print_func();
    std::string diag, run_out;
    const uint32_t inputs[] = {0u, 3u, 6u, 15u};
    std::string drv =
        "int main(void) {\n"
        "  const u32 a[] = {0u, 3u, 6u, 15u};\n"
        "  for (int i = 0; i < 4; ++i) printf(\"%08X\\n\", spu_loop_break_cont(a[i]));\n"
        "  return 0;\n}\n";
    if (!msvc_compile_and_run_c("loop_bc", ctxt, drv, &run_out, &diag)) {
        record_failure(T, "spu_loop_break_cont failed compile/run:\n" + diag + "\n" + ctxt);
    } else {
        std::istringstream iss(run_out);
        for (int i = 0; i < 4; ++i) {
            SpuRefMachine m;
            m.load_program(0x1800, prog);
            m.set_w0(3, inputs[i]);
            if (!m.run(0x1800)) { record_failure(T, "SpuRefMachine::run failed"); break; }
            uint32_t exp = m.get_w(3, 0);
            uint32_t act = 0;
            iss >> std::hex >> act;
            if (act != exp) {
                record_failure(T, "loop_break_cont mismatch for n=" + std::to_string(inputs[i]) +
                                  ": expected " + std::to_string(exp) + " got " + std::to_string(act));
                break;
            }
        }
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 10 (Structuring + Syntax Oracle): Nested Branch with Early Return Inside Loop
// ---------------------------------------------------------------------------
static void test_e2e_struct_nested_branches_early_return() {
    const char *T = "test_e2e_struct_nested_branches_early_return";
    //   0x1900 (b0): brz r3, +6 (0x1918)
    //   0x1904 (b1): ceqi r5, r3, 7; brz r5, +3 (0x1914)
    //   0x190C (b2): il r3, 99; bi lr           ; early return!
    //   0x1914 (b3): ai r3, r3, -1; br -6 (0x1900)
    //   0x191C (b4): il r3, 0; bi lr
    MockDatabaseProvider db;
    std::vector<uint32_t> prog = {
        insn_brz(3, 7),      // 0x1900 -> 0x191C
        insn_ceqi(5, 3, 7),  // 0x1904
        insn_brz(5, 3),      // 0x1908 -> 0x1914
        insn_il(3, 99),      // 0x190C
        insn_bi(0),          // 0x1910
        insn_ai(3, 3, -1),   // 0x1914
        insn_br(-6),         // 0x1918 -> 0x1900
        insn_il(3, 0),       // 0x191C
        insn_bi(0),          // 0x1920
    };
    for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1900 + i * 4, prog[i]);
    db.func_names[0x1900] = "spu_early_ret_loop";
    db.flowcharts[0x1900] = {
        FlowBlockRange{0, 0x1900, 0x1904, {1, 4}, {3}},
        FlowBlockRange{1, 0x1904, 0x190C, {2, 3}, {0}},
        FlowBlockRange{2, 0x190C, 0x1914, {}, {1}},
        FlowBlockRange{3, 0x1914, 0x191C, {0}, {1}},
        FlowBlockRange{4, 0x191C, 0x1924, {}, {0}},
    };

    auto out = decompile_function(db, 0x1900, make_audit_opts("u32 spu_early_ret_loop(u32 a1)"));
    if (!out.cfunc || !out.ir_func->problems.empty()) {
        record_failure(T, "spu_early_ret_loop failed decompile or SSA verify");
        return;
    }
    std::string ctxt = out.cfunc->print_func();
    std::string diag;
    if (!msvc_syntax_check_c("early_ret_loop", ctxt, &diag)) {
        record_failure(T, "spu_early_ret_loop failed MSVC /Zs:\n" + diag + "\n" + ctxt);
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 11 (Out-of-SSA Swap Problem + Differential): Parallel PHI Swap Loop!
// ---------------------------------------------------------------------------
static void test_e2e_critical_edge_phi_swap_loop() {
    const char *T = "test_e2e_critical_edge_phi_swap_loop";
    // Swap (r3, r4) r5 times:
    //   0x1A00 (b0): brz r5, +5 (0x1A14)      ; while (r5 != 0)
    //   0x1A04 (b1): lr r6, r3                ; tmp = r3
    //   0x1A08     : lr r3, r4                ; r3 = r4
    //   0x1A0C     : lr r4, r6                ; r4 = tmp
    //   0x1A10     : ai r5, r5, -1; br -5 (0x1A00)
    //   0x1A18 (b2): bi lr                    ; returns r3 (after 1 swap -> orig r4, after 2 swaps -> orig r3!)
    // After copy-propagation in SSA, b0 has parallel PHIs:
    //   r3#1 = phi(r3#0, r4#1)
    //   r4#1 = phi(r4#0, r3#1)
    // If outssa::lower_phis inserts sequential copies `r3 = r4; r4 = r3;` without a temp, 2 swaps returns r4 instead of r3!
    MockDatabaseProvider db;
    std::vector<uint32_t> prog = {
        insn_brz(5, 6),      // 0x1A00 -> 0x1A18
        insn_lr(6, 3),       // 0x1A04
        insn_lr(3, 4),       // 0x1A08
        insn_lr(4, 6),       // 0x1A0C
        insn_ai(5, 5, -1),   // 0x1A10
        insn_br(-5),         // 0x1A14 -> 0x1A00
        insn_bi(0),          // 0x1A18
    };
    for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1A00 + i * 4, prog[i]);
    db.func_names[0x1A00] = "spu_phi_swap";
    db.flowcharts[0x1A00] = {
        FlowBlockRange{0, 0x1A00, 0x1A04, {1, 2}, {1}},
        FlowBlockRange{1, 0x1A04, 0x1A18, {0}, {0}},
        FlowBlockRange{2, 0x1A18, 0x1A1C, {}, {0}},
    };

    auto out = decompile_function(db, 0x1A00, make_audit_opts("u32 spu_phi_swap(u32 a1, u32 a2, u32 a3)"));
    if (!out.cfunc || !out.ir_func->problems.empty()) {
        record_failure(T, "spu_phi_swap failed decompile or SSA verify");
        return;
    }
    std::string ctxt = out.cfunc->print_func();
    std::string diag, run_out;
    const uint32_t counts[] = {0u, 1u, 2u, 3u, 4u};
    std::string drv =
        "int main(void) {\n"
        "  for (u32 n = 0; n < 5; ++n) printf(\"%08X\\n\", spu_phi_swap(0x11111111u, 0x22222222u, n));\n"
        "  return 0;\n}\n";
    if (!msvc_compile_and_run_c("phi_swap", ctxt, drv, &run_out, &diag)) {
        record_failure(T, "spu_phi_swap failed compile/run:\n" + diag + "\n" + ctxt);
    } else {
        std::istringstream iss(run_out);
        for (int i = 0; i < 5; ++i) {
            SpuRefMachine m;
            m.load_program(0x1A00, prog);
            m.set_w0(3, 0x11111111u);
            m.set_w0(4, 0x22222222u);
            m.set_w0(5, counts[i]);
            if (!m.run(0x1A00)) { record_failure(T, "SpuRefMachine::run failed"); break; }
            uint32_t exp = m.get_w(3, 0);
            uint32_t act = 0;
            iss >> std::hex >> act;
            if (act != exp) {
                char buf[512];
                std::snprintf(buf, sizeof(buf),
                              "phi_swap(0x11111111, 0x22222222, n=%u) mismatch: ISA ref=0x%08X vs compiled C=0x%08X (Out-of-SSA swap problem!)\nEmitted C:\n%s",
                              counts[i], exp, act, ctxt.c_str());
                record_failure(T, buf);
                break;
            }
        }
    }
    // Also test with an explicit preheader (b0 -> b1 loop header) to isolate Out-of-SSA parallel PHI swap!
    {
        MockDatabaseProvider db2;
        std::vector<uint32_t> prog2 = {
            insn_ai(5, 5, 0),    // 0x1A40 (b0 preheader)
            insn_brz(5, 6),      // 0x1A44 (b1 header) -> 0x1A5C
            insn_lr(6, 3),       // 0x1A48 (b2 body)
            insn_lr(3, 4),       // 0x1A4C
            insn_lr(4, 6),       // 0x1A50
            insn_ai(5, 5, -1),   // 0x1A54
            insn_br(-5),         // 0x1A58 -> 0x1A44
            insn_bi(0),          // 0x1A5C (b3 exit)
        };
        for (size_t i = 0; i < prog2.size(); ++i) db2.write_u32_be(0x1A40 + i * 4, prog2[i]);
        db2.func_names[0x1A40] = "spu_phi_swap_prehdr";
        db2.flowcharts[0x1A40] = {
            FlowBlockRange{0, 0x1A40, 0x1A44, {1}, {}},
            FlowBlockRange{1, 0x1A44, 0x1A48, {2, 3}, {0, 2}},
            FlowBlockRange{2, 0x1A48, 0x1A5C, {1}, {1}},
            FlowBlockRange{3, 0x1A5C, 0x1A60, {}, {1}},
        };

        auto out2 = decompile_function(db2, 0x1A40, make_audit_opts("u32 spu_phi_swap_prehdr(u32 a1, u32 a2, u32 a3)"));
        if (!out2.cfunc || !out2.ir_func->problems.empty()) {
            record_failure(T, "spu_phi_swap_prehdr failed decompile or SSA verify");
        } else {
            std::string ctxt2 = out2.cfunc->print_func();
            std::string diag2, run_out2;
            std::string drv2 =
                "int main(void) {\n"
                "  for (u32 n = 0; n < 5; ++n) printf(\"%08X\\n\", spu_phi_swap_prehdr(0x11111111u, 0x22222222u, n));\n"
                "  return 0;\n}\n";
            if (!msvc_compile_and_run_c("phi_swap_prehdr", ctxt2, drv2, &run_out2, &diag2)) {
                record_failure(T, "spu_phi_swap_prehdr failed compile/run:\n" + diag2 + "\n" + ctxt2);
            } else {
                std::istringstream iss(run_out2);
                for (int i = 0; i < 5; ++i) {
                    SpuRefMachine m;
                    m.load_program(0x1A40, prog2);
                    m.set_w0(3, 0x11111111u);
                    m.set_w0(4, 0x22222222u);
                    m.set_w0(5, counts[i]);
                    if (!m.run(0x1A40)) { record_failure(T, "SpuRefMachine::run failed"); break; }
                    uint32_t exp = m.get_w(3, 0);
                    uint32_t act = 0;
                    iss >> std::hex >> act;
                    if (act != exp) {
                        char buf[512];
                        std::snprintf(buf, sizeof(buf),
                                      "phi_swap_prehdr(0x11111111, 0x22222222, n=%u) mismatch: ISA ref=0x%08X vs compiled C=0x%08X (Out-of-SSA swap problem!)\nEmitted C:\n%s",
                                      counts[i], exp, act, ctxt2.c_str());
                        record_failure(T, buf);
                        break;
                    }
                }
            }
        }
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 12 (Negative / Side Effects / Wrap): Unhandled Opcode, MFC DMA Channel Conservation, 18-bit LS Wrap
// ---------------------------------------------------------------------------
static void test_e2e_negative_unhandled_channels_wrap() {
    const char *T = "test_e2e_negative_unhandled_channels_wrap";
    // 12A: Invalid stop (non-zero bits 11..17) MUST be recorded in unhandled AND visible in C output
    {
        MockDatabaseProvider db;
        db.write_u32_be(0x1B00, 0x001FC000u); // op11=0x000 (stop), bits 11..17 = 0x7F (invalid!)
        db.write_u32_be(0x1B04, insn_bi(0));
        db.func_names[0x1B00] = "spu_bad_opcode";
        db.flowcharts[0x1B00] = { FlowBlockRange{0, 0x1B00, 0x1B08, {}, {}} };

        auto out = decompile_function(db, 0x1B00, make_audit_opts());
        if (!out.ir_func || out.ir_func->unhandled.empty()) {
            record_failure(T, "Invalid opcode was NOT recorded in ir_func->unhandled!");
        }
        std::string ctxt = out.cfunc ? out.cfunc->print_func() : "";
        if (ctxt.find("undecodable") == std::string::npos) {
            record_failure(T, "Invalid opcode silently vanished from emitted C:\n" + ctxt);
        }
    }

    // 12B: Consecutive MFC DMA wrch writes to same/different channels + rdch MUST NOT be DCE'd!
    {
        MockDatabaseProvider db;
        std::vector<uint32_t> prog = {
            insn_wrch(16, 3), // MFC_LSA
            insn_wrch(17, 4), // MFC_EAH
            insn_wrch(18, 5), // MFC_EAL
            insn_wrch(19, 6), // MFC_Size
            insn_wrch(20, 7), // MFC_TagID
            insn_wrch(21, 8), // MFC_Cmd
            insn_rdch(3, 24), // MFC_RdTagStat
            insn_bi(0),
        };
        for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1B40 + i * 4, prog[i]);
        db.func_names[0x1B40] = "spu_mfc_dma";
        db.flowcharts[0x1B40] = { FlowBlockRange{0, 0x1B40, 0x1B60, {}, {}} };

        auto out = decompile_function(db, 0x1B40, make_audit_opts());
        if (!out.cfunc || !out.ir_func->problems.empty()) {
            record_failure(T, "spu_mfc_dma failed decompile or SSA verify");
        } else {
            int wrch_cnt = 0, rdch_cnt = 0;
            for (const auto &b : out.ir_func->blocks) {
                for (const auto &ins : b->insns) {
                    if (ins->op == Op::WRCH) ++wrch_cnt;
                    if (ins->op == Op::RDCH) ++rdch_cnt;
                }
            }
            if (wrch_cnt != 6 || rdch_cnt != 1) {
                record_failure(T, "Channel side-effect conservation failed: expected 6 WRCH + 1 RDCH, got " +
                                  std::to_string(wrch_cnt) + " WRCH + " + std::to_string(rdch_cnt) + " RDCH");
            }
        }
    }

    // 12C: 18-bit Local Store wrap-around on lqa (0x40000 -> 0x00000)
    {
        MockDatabaseProvider db;
        // lqa r3, 0x40000 -> i16 = 0x10000? Wait: i16 is 16-bit signed << 2, range [-0x20000, +0x1FFFC].
        // Negative i16 = -4 (-16 bytes) wraps in 18-bit LS to 0x3FFF0!
        db.write_u32_be(0x1B80, insn_lqa(3, -4));
        db.write_u32_be(0x1B84, insn_bi(0));
        db.func_names[0x1B80] = "spu_ls_wrap";
        db.flowcharts[0x1B80] = { FlowBlockRange{0, 0x1B80, 0x1B88, {}, {}} };

        auto out = decompile_function(db, 0x1B80, make_audit_opts());
        if (!out.cfunc || !out.ir_func->problems.empty()) {
            record_failure(T, "spu_ls_wrap failed decompile or SSA verify");
        } else {
            std::string ir_dump = out.ir_func->dump();
            if (ir_dump.find("3fff0") == std::string::npos && ir_dump.find("3FFF0") == std::string::npos) {
                record_failure(T, "18-bit Local Store wrap-around failed for lqa -16 (expected 0x3FFF0):\n" + ir_dump);
            }
        }
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 13 (Negative Vector Hazard): `propagate_scalar_slots` Must Not Drop `shufb` Used by Full-Vector `a`!
// ---------------------------------------------------------------------------
static void test_e2e_vector_shufb_propagate_hazard() {
    const char *T = "test_e2e_vector_shufb_propagate_hazard";
    //   0x1C00: cwd   r6, 4(r1)         ; constant slot=4 (since r1 is SP, slot_of == 4!)
    //   0x1C04: shufb r8, r4, r3, r6    ; inserts r4.w0 into word 1 of r3!
    //   0x1C08: a     r9, r8, r5        ; full 128-bit vector wordwise add!
    //   0x1C0C: stqd  r9, 0(r1)         ; stores ALL 4 words of r9!
    //   0x1C10: bi    lr
    // Because r9 is stored via stqd (ALL 16 bytes live), r8's word 1 IS live!
    // If propagate_scalar_slots replaces r8 with r3 in `a r9, r8, r5`, the shufb is DCE'd and word 1 is corrupted!
    MockDatabaseProvider db;
    std::vector<uint32_t> prog = {
        insn_cwd(6, 1, 4),
        insn_shufb(8, 4, 3, 6),
        insn_a(9, 8, 5),
        insn_stqd(9, 1, 0),
        insn_bi(0),
    };
    for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x1C00 + i * 4, prog[i]);
    db.func_names[0x1C00] = "spu_vec_shufb_hazard";
    db.flowcharts[0x1C00] = { FlowBlockRange{0, 0x1C00, 0x1C14, {}, {}} };

    auto out = decompile_function(db, 0x1C00, make_audit_opts());
    if (!out.cfunc || !out.ir_func->problems.empty()) {
        record_failure(T, "spu_vec_shufb_hazard failed decompile or SSA verify");
        return;
    }
    bool has_shufb = false;
    for (const auto &b : out.ir_func->blocks) {
        for (const auto &ins : b->insns) {
            if (ins->op == Op::SHUFB) has_shufb = true;
        }
    }
    if (!has_shufb) {
        record_failure(T, "propagate_scalar_slots illegally dropped shufb feeding a full 128-bit vector ADD!\nIR:\n" +
                          out.ir_func->dump());
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 14 (Real isoldr.elf.i64 sub_275F8 + Differential): 32-Byte vec_ullong4 Return & Zero Intrinsics
// ---------------------------------------------------------------------------
static void test_e2e_sub_275F8_pattern_vec_ullong4_return() {
    const char *T = "test_e2e_sub_275F8_pattern_vec_ullong4_return";
    // Exact 38 big-endian SPU machine words from isoldr.elf.i64::sub_275F8 (0x275F8..0x27690)
    const std::vector<uint32_t> prog = {
        0x1C06019Du, 0x35800024u, 0x1C06020Du, 0x340001A1u, 0x1C020191u, 0x34000E9Cu,
        0x1C020210u, 0x3400069Bu, 0x04000189u, 0x34000897u, 0x34000816u, 0x34000220u,
        0x34004199u, 0x34004218u, 0x24FE8081u, 0x1CE80081u, 0x3B874E1Au, 0x3400C095u,
        0x34008094u, 0x3B834D8Cu, 0x3B844B86u, 0x3B840B08u, 0x3EE20092u, 0x3B81101Fu,
        0x18230D05u, 0x3B80D09Eu, 0x18220302u, 0x3B824C87u, 0x3B810C0Bu, 0x3EE00093u,
        0x1827CF03u, 0xB1C54292u, 0x1C180081u, 0xB1E50112u, 0x1822C384u, 0xB0838213u,
        0xB063C193u, 0x35000000u,
    };
    MockDatabaseProvider db;
    for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x275F8 + i * 4, prog[i]);
    db.func_names[0x275F8] = "sub_275F8";
    db.flowcharts[0x275F8] = { FlowBlockRange{0, 0x275F8, 0x27690, {}, {}} };

    auto out = decompile_function(db, 0x275F8, make_audit_opts());
    if (!out.cfunc || !out.ir_func->problems.empty()) {
        record_failure(T, "sub_275F8 failed decompile or SSA verify");
        return;
    }
    std::string ctxt = out.cfunc->print_func();
    const char *banned[] = {"__builtin_spu_mask", "spu_insert", "qword_unaligned", "spu_splats", "spu_shuffle", "_rotl("};
    for (const char *b : banned) {
        if (ctxt.find(b) != std::string::npos) {
            record_failure(T, std::string("sub_275F8 emitted banned intrinsic `") + b + "`:\n" + ctxt);
        }
    }
    if (ctxt.find("vec_ullong4") == std::string::npos) {
        record_failure(T, "sub_275F8 did not recover vec_ullong4 32-byte return:\n" + ctxt);
    }
    std::string diag;
    if (!msvc_syntax_check_c("sub_275F8", ctxt, &diag)) {
        record_failure(T, "sub_275F8 failed MSVC /Zs /TC:\n" + diag + "\n" + ctxt);
        return;
    }

    // Differential semantic execution: compare SpuRefMachine (big-endian Local Store) vs compiled C!
    const uint64_t A[4] = {0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL, 0xAA55DEADBEEFCAFEULL, 0x800000007FFFFFFFULL};
    const uint64_t B[4] = {0x0F0F0F0FF0F0F0F0ULL, 0x55555555AAAAAAAAULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFFFFFFFFFFULL};

    SpuRefMachine m;
    m.load_program(0x275F8, prog);
    m.set_w0(1, 0x3F000u); // SP
    m.set_w0(3, 0x10000u); // a1
    m.set_w0(4, 0x10100u); // a2
    auto write_be64 = [&](uint32_t addr, uint64_t v) {
        for (int b = 0; b < 8; ++b) m.ls[(addr + b) & SpuRefMachine::LSLR] = static_cast<uint8_t>((v >> (56 - b * 8)) & 0xFFu);
    };
    for (int i = 0; i < 4; ++i) {
        write_be64(0x10000u + i * 8, A[i]);
        write_be64(0x10100u + i * 8, B[i]);
    }
    if (!m.run(0x275F8)) {
        record_failure(T, "SpuRefMachine::run failed on sub_275F8");
        return;
    }
    auto get_u64 = [&](int reg, int idx) -> uint64_t {
        uint64_t hi = m.get_w(reg, idx * 2);
        uint64_t lo = m.get_w(reg, idx * 2 + 1);
        return (hi << 32) | lo;
    };
    uint64_t exp[4] = {get_u64(3, 0), get_u64(3, 1), get_u64(4, 0), get_u64(4, 1)};

    std::string drv =
        "int main(void) {\n"
        "  unsigned long long a[4] = {0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL, 0xAA55DEADBEEFCAFEULL, 0x800000007FFFFFFFULL};\n"
        "  unsigned long long b[4] = {0x0F0F0F0FF0F0F0F0ULL, 0x55555555AAAAAAAAULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFFFFFFFFFFULL};\n"
        "  vec_ullong4 r = sub_275F8(a, b);\n"
        "  printf(\"%016llX %016llX %016llX %016llX\\n\", r.d[0], r.d[1], r.d[2], r.d[3]);\n"
        "  return 0;\n}\n";
    std::string run_out;
    if (!msvc_compile_and_run_c("sub_275F8", ctxt, drv, &run_out, &diag)) {
        record_failure(T, "sub_275F8 failed compile/run:\n" + diag + "\n" + ctxt);
    } else {
        std::istringstream iss(run_out);
        for (int i = 0; i < 4; ++i) {
            uint64_t act = 0;
            iss >> std::hex >> act;
            if (act != exp[i]) {
                char buf[256];
                std::snprintf(buf, sizeof(buf),
                              "sub_275F8 lane %d mismatch: ISA ref=0x%016llX vs compiled C=0x%016llX\nEmitted C:\n%s",
                              i, static_cast<unsigned long long>(exp[i]), static_cast<unsigned long long>(act), ctxt.c_str());
                record_failure(T, buf);
                break;
            }
        }
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 15 (Differential): 64-bit Doubleword Arithmetic (`cg+shufb+addx`, `bg+shufb+sfx`) + Negative Mask Hazard
// ---------------------------------------------------------------------------
static void test_e2e_u64_arith_cg_addx_and_bg_sfx() {
    const char *T = "test_e2e_u64_arith_cg_addx_and_bg_sfx";
    // 15A: 64-bit add via cg + lqa(carry_mask) + shufb + addx
    {
        MockDatabaseProvider db;
        // Carry shift mask at 0x2000: word1 -> word0, zero -> word1, word3 -> word2, zero -> word3
        db.write_u32_be(0x2000, 0x04050607u);
        db.write_u32_be(0x2004, 0x80808080u);
        db.write_u32_be(0x2008, 0x0C0D0E0Fu);
        db.write_u32_be(0x200C, 0x80808080u);

        std::vector<uint32_t> prog = {
            insn_cg(5, 3, 4),
            insn_lqa(6, 0x2000 >> 2),
            insn_shufb(5, 5, 5, 6),
            insn_addx(5, 3, 4),
            insn_lr(3, 5),
            insn_bi(0),
        };
        for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x2100 + i * 4, prog[i]);
        db.func_names[0x2100] = "spu_add64";
        db.flowcharts[0x2100] = { FlowBlockRange{0, 0x2100, 0x2118, {}, {}} };

        auto out = decompile_function(db, 0x2100, make_audit_opts("u64 spu_add64(u64 a1, u64 a2)"));
        if (!out.cfunc || !out.ir_func->problems.empty()) {
            record_failure(T, "spu_add64 failed decompile or SSA verify");
            return;
        }
        std::string ctxt = out.cfunc->print_func();
        std::string diag, run_out;
        const uint64_t pairs[][2] = {
            {0x00000000FFFFFFFFULL, 0x0000000000000001ULL},
            {0xFFFFFFFFFFFFFFFFULL, 0x0000000000000001ULL},
            {0x1122334480000000ULL, 0x0102030480000000ULL},
            {0x0000000000000000ULL, 0x0000000000000000ULL},
        };
        std::string drv =
            "int main(void) {\n"
            "  const u64 a[] = {0x00000000FFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0x1122334480000000ULL, 0ULL};\n"
            "  const u64 b[] = {0x0000000000000001ULL, 0x0000000000000001ULL, 0x0102030480000000ULL, 0ULL};\n"
            "  for (int i = 0; i < 4; ++i) printf(\"%016llX\\n\", spu_add64(a[i], b[i]));\n"
            "  return 0;\n}\n";
        if (!msvc_compile_and_run_c("add64", ctxt, drv, &run_out, &diag)) {
            record_failure(T, "spu_add64 failed compile/run:\n" + diag + "\n" + ctxt);
        } else {
            std::istringstream iss(run_out);
            for (int i = 0; i < 4; ++i) {
                SpuRefMachine m;
                m.load_program(0x2100, prog);
                m.load_program(0x2000, {0x04050607u, 0x80808080u, 0x0C0D0E0Fu, 0x80808080u});
                m.set_w(3, 0, static_cast<uint32_t>(pairs[i][0] >> 32));
                m.set_w(3, 1, static_cast<uint32_t>(pairs[i][0] & 0xFFFFFFFFu));
                m.set_w(4, 0, static_cast<uint32_t>(pairs[i][1] >> 32));
                m.set_w(4, 1, static_cast<uint32_t>(pairs[i][1] & 0xFFFFFFFFu));
                if (!m.run(0x2100)) { record_failure(T, "SpuRefMachine::run failed on add64"); break; }
                uint64_t exp = (static_cast<uint64_t>(m.get_w(3, 0)) << 32) | m.get_w(3, 1);
                uint64_t act = 0;
                iss >> std::hex >> act;
                if (act != exp) {
                    char buf[256];
                    std::snprintf(buf, sizeof(buf),
                                  "add64(0x%016llX, 0x%016llX) mismatch: ISA ref=0x%016llX vs compiled C=0x%016llX\nEmitted C:\n%s",
                                  static_cast<unsigned long long>(pairs[i][0]), static_cast<unsigned long long>(pairs[i][1]),
                                  static_cast<unsigned long long>(exp), static_cast<unsigned long long>(act), ctxt.c_str());
                    record_failure(T, buf);
                    break;
                }
            }
        }
    }

    // 15B: 64-bit sub (a1 - a2) via bg(rt=5, ra=4, rb=3) + lqa(borrow_mask) + shufb + sfx(rt=5, ra=4, rb=3)
    {
        MockDatabaseProvider db;
        db.write_u32_be(0x2010, 0x04050607u);
        db.write_u32_be(0x2014, 0xC0C0C0C0u);
        db.write_u32_be(0x2018, 0x0C0D0E0Fu);
        db.write_u32_be(0x201C, 0xC0C0C0C0u);

        std::vector<uint32_t> prog = {
            insn_bg(5, 4, 3),         // bg r5, r4, r3  -> (r3 >= r4)
            insn_lqa(6, 0x2010 >> 2),
            insn_shufb(5, 5, 5, 6),
            insn_sfx(5, 4, 3),        // sfx r5, r4, r3 -> r3 - r4
            insn_lr(3, 5),
            insn_bi(0),
        };
        for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x2140 + i * 4, prog[i]);
        db.func_names[0x2140] = "spu_sub64";
        db.flowcharts[0x2140] = { FlowBlockRange{0, 0x2140, 0x2158, {}, {}} };

        auto out = decompile_function(db, 0x2140, make_audit_opts("u64 spu_sub64(u64 a1, u64 a2)"));
        if (!out.cfunc || !out.ir_func->problems.empty()) {
            record_failure(T, "spu_sub64 failed decompile or SSA verify");
            return;
        }
        std::string ctxt = out.cfunc->print_func();
        std::string diag, run_out;
        const uint64_t pairs[][2] = {
            {0x0000000100000000ULL, 0x0000000000000001ULL},
            {0x0000000000000005ULL, 0x0000000000000005ULL},
            {0x0000000000000000ULL, 0x0000000000000001ULL},
            {0x1122334455667788ULL, 0x0102030405060708ULL},
        };
        std::string drv =
            "int main(void) {\n"
            "  const u64 a[] = {0x0000000100000000ULL, 5ULL, 0ULL, 0x1122334455667788ULL};\n"
            "  const u64 b[] = {0x0000000000000001ULL, 5ULL, 1ULL, 0x0102030405060708ULL};\n"
            "  for (int i = 0; i < 4; ++i) printf(\"%016llX\\n\", spu_sub64(a[i], b[i]));\n"
            "  return 0;\n}\n";
        if (!msvc_compile_and_run_c("sub64", ctxt, drv, &run_out, &diag)) {
            record_failure(T, "spu_sub64 failed compile/run:\n" + diag + "\n" + ctxt);
        } else {
            std::istringstream iss(run_out);
            for (int i = 0; i < 4; ++i) {
                SpuRefMachine m;
                m.load_program(0x2140, prog);
                m.load_program(0x2010, {0x04050607u, 0xC0C0C0C0u, 0x0C0D0E0Fu, 0xC0C0C0C0u});
                m.set_w(3, 0, static_cast<uint32_t>(pairs[i][0] >> 32));
                m.set_w(3, 1, static_cast<uint32_t>(pairs[i][0] & 0xFFFFFFFFu));
                m.set_w(4, 0, static_cast<uint32_t>(pairs[i][1] >> 32));
                m.set_w(4, 1, static_cast<uint32_t>(pairs[i][1] & 0xFFFFFFFFu));
                if (!m.run(0x2140)) { record_failure(T, "SpuRefMachine::run failed on sub64"); break; }
                uint64_t exp = (static_cast<uint64_t>(m.get_w(3, 0)) << 32) | m.get_w(3, 1);
                uint64_t act = 0;
                iss >> std::hex >> act;
                if (act != exp) {
                    char buf[256];
                    std::snprintf(buf, sizeof(buf),
                                  "sub64(0x%016llX, 0x%016llX) mismatch: ISA ref=0x%016llX vs compiled C=0x%016llX\nEmitted C:\n%s",
                                  static_cast<unsigned long long>(pairs[i][0]), static_cast<unsigned long long>(pairs[i][1]),
                                  static_cast<unsigned long long>(exp), static_cast<unsigned long long>(act), ctxt.c_str());
                    record_failure(T, buf);
                    break;
                }
            }
        }
    }

    // 15C: Negative mask hazard: wrong shufb mask (word0 -> word0 instead of word1 -> word0) must NOT fold to add.d!
    {
        MockDatabaseProvider db;
        db.write_u32_be(0x2020, 0x00010203u);
        db.write_u32_be(0x2024, 0x80808080u);
        db.write_u32_be(0x2028, 0x08090A0Bu);
        db.write_u32_be(0x202C, 0x80808080u);

        std::vector<uint32_t> prog = {
            insn_cg(5, 3, 4),
            insn_lqa(6, 0x2020 >> 2),
            insn_shufb(5, 5, 5, 6),
            insn_addx(5, 3, 4),
            insn_lr(3, 5),
            insn_bi(0),
        };
        for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x2180 + i * 4, prog[i]);
        db.func_names[0x2180] = "spu_bad_add64_mask";
        db.flowcharts[0x2180] = { FlowBlockRange{0, 0x2180, 0x2198, {}, {}} };

        auto out = decompile_function(db, 0x2180, make_audit_opts());
        if (!out.ir_func || !out.ir_func->problems.empty()) {
            record_failure(T, "spu_bad_add64_mask failed decompile or SSA verify");
        } else {
            for (const auto &b : out.ir_func->blocks) {
                for (const auto &ins : b->insns) {
                    if (ins->op == Op::ADD && ins->ew == EW::D) {
                        record_failure(T, "fold_u64_arith falsely folded invalid shufb mask into add.d!");
                    }
                }
            }
        }
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 16 (Multi-Reg Return + MSVC /TC Oracle + Scalar False-Positive Guard)
// ---------------------------------------------------------------------------
static void test_e2e_two_reg_return_and_scalar_false_positive_guard() {
    const char *T = "test_e2e_two_reg_return_and_scalar_false_positive_guard";
    // 16A: Positive qword2 two-register vector return: lqd r3, 0(r5); lqd r4, 0x10(r5); bi lr
    {
        MockDatabaseProvider db;
        std::vector<uint32_t> prog = {
            insn_lqd(3, 5, 0),
            insn_lqd(4, 5, 1),
            insn_bi(0),
        };
        for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x2200 + i * 4, prog[i]);
        db.func_names[0x2200] = "spu_ret_qword2";
        db.flowcharts[0x2200] = { FlowBlockRange{0, 0x2200, 0x220C, {}, {}} };

        auto out = decompile_function(db, 0x2200, make_audit_opts());
        if (!out.cfunc || !out.ir_func->problems.empty()) {
            record_failure(T, "spu_ret_qword2 failed decompile or SSA verify");
            return;
        }
        std::string ctxt = out.cfunc->print_func();
        if (ctxt.find("qword2") == std::string::npos && ctxt.find("vec_ullong4") == std::string::npos) {
            record_failure(T, "spu_ret_qword2 did not recover multi-register return:\n" + ctxt);
        }
        std::string diag;
        if (!msvc_syntax_check_c("ret_qword2", ctxt, &diag)) {
            record_failure(T, "spu_ret_qword2 failed MSVC /Zs /TC:\n" + diag + "\n" + ctxt);
        }
    }

    // 16B: Negative false-positive guard (sub_27738-style scalar function clobbering scratch r4 must NOT return qword2!)
    {
        MockDatabaseProvider db;
        std::vector<uint32_t> prog = {
            insn_ila(4, 0x34EF0u),
            insn_ai(3, 3, 1),
            insn_bi(0),
        };
        for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x2240 + i * 4, prog[i]);
        db.func_names[0x2240] = "spu_scalar_scratch_r4";
        db.flowcharts[0x2240] = { FlowBlockRange{0, 0x2240, 0x224C, {}, {}} };

        auto out = decompile_function(db, 0x2240, make_audit_opts());
        if (!out.cfunc || !out.ir_func->problems.empty()) {
            record_failure(T, "spu_scalar_scratch_r4 failed decompile or SSA verify");
            return;
        }
        std::string ctxt = out.cfunc->print_func();
        if (ctxt.find("qword2") != std::string::npos || ctxt.find("vec_ullong4") != std::string::npos) {
            record_failure(T, "False-positive two-register return on scalar function:\n" + ctxt);
        }
    }
    std::printf("done %s\n", T);
}

// ---------------------------------------------------------------------------
// E2E Test 17 (Differential): Native C Rotate Recovery (`roti` & `rot` without `_rotl` intrinsic, zero UB at count=0/32)
// ---------------------------------------------------------------------------
static void test_e2e_native_c_rotl_no_intrinsics() {
    const char *T = "test_e2e_native_c_rotl_no_intrinsics";
    MockDatabaseProvider db;
    std::vector<uint32_t> prog = {
        insn_rot(3, 3, 4),
        insn_bi(0),
    };
    for (size_t i = 0; i < prog.size(); ++i) db.write_u32_be(0x2300 + i * 4, prog[i]);
    db.func_names[0x2300] = "spu_rot_var";
    db.flowcharts[0x2300] = { FlowBlockRange{0, 0x2300, 0x2308, {}, {}} };

    auto out = decompile_function(db, 0x2300, make_audit_opts("u32 spu_rot_var(u32 a1, u32 a2)"));
    if (!out.cfunc || !out.ir_func->problems.empty()) {
        record_failure(T, "spu_rot_var failed decompile or SSA verify");
        return;
    }
    std::string ctxt = out.cfunc->print_func();
    if (ctxt.find("_rotl(") != std::string::npos) {
        record_failure(T, "spu_rot_var still emitted `_rotl(` intrinsic:\n" + ctxt);
    }
    std::string diag, run_out;
    const uint32_t shifts[] = {0u, 1u, 7u, 16u, 31u, 32u, 33u, 0xFFFFFFFFu};
    std::string drv =
        "int main(void) {\n"
        "  const u32 s[] = {0u, 1u, 7u, 16u, 31u, 32u, 33u, 0xFFFFFFFFu};\n"
        "  for (int i = 0; i < 8; ++i) printf(\"%08X\\n\", spu_rot_var(0x12345678u, s[i]));\n"
        "  return 0;\n}\n";
    if (!msvc_compile_and_run_c("rot_var", ctxt, drv, &run_out, &diag)) {
        record_failure(T, "spu_rot_var failed compile/run:\n" + diag + "\n" + ctxt);
    } else {
        std::istringstream iss(run_out);
        for (int i = 0; i < 8; ++i) {
            SpuRefMachine m;
            m.load_program(0x2300, prog);
            m.set_w0(3, 0x12345678u);
            m.set_w0(4, shifts[i]);
            if (!m.run(0x2300)) { record_failure(T, "SpuRefMachine::run failed on rot_var"); break; }
            uint32_t exp = m.get_w(3, 0);
            uint32_t act = 0;
            iss >> std::hex >> act;
            if (act != exp) {
                char buf[256];
                std::snprintf(buf, sizeof(buf),
                              "rot_var(0x12345678, %u) mismatch: ISA ref=0x%08X vs compiled C=0x%08X\nEmitted C:\n%s",
                              shifts[i], exp, act, ctxt.c_str());
                record_failure(T, buf);
                break;
            }
        }
    }
    std::printf("done %s\n", T);
}

} // namespace qa

int main() {
    test_u128_and_sem();
    test_abi_proto_parser();
    test_lifter_and_cfg();
    test_ssa_opt_and_outssa();
    test_lanes_and_scalarize();
    test_user_data_json_and_highlight();
    test_structure_cgen_udt_and_ctree();

    // Adversarial 5-Tier External QA Audit Tests
    qa::test_e2e_arith_signed_unsigned_compare();
    qa::test_e2e_quadword_rotqmbyi_rotqmbii();
    qa::test_e2e_extended_carry_borrow();
    qa::test_e2e_preferred_slot_and_immediates();
    qa::test_e2e_rmw_store_canary_and_alias_hazard();
    qa::test_e2e_struct_if_else_chain();
    qa::test_e2e_struct_while_loop_sum();
    qa::test_e2e_struct_do_while_loop();
    qa::test_e2e_struct_loop_break_continue();
    qa::test_e2e_struct_nested_branches_early_return();
    qa::test_e2e_critical_edge_phi_swap_loop();
    qa::test_e2e_negative_unhandled_channels_wrap();
    qa::test_e2e_vector_shufb_propagate_hazard();
    qa::test_e2e_sub_275F8_pattern_vec_ullong4_return();
    qa::test_e2e_u64_arith_cg_addx_and_bg_sfx();
    qa::test_e2e_two_reg_return_and_scalar_false_positive_guard();
    qa::test_e2e_native_c_rotl_no_intrinsics();

    if (qa::g_failures > 0) {
        std::fprintf(stderr, "\nAUDIT FAILURE: %d adversarial test(s) failed!\n", qa::g_failures);
        return 1;
    }
    std::printf("\nall Phase 1, Phase 2, Phase 3 & Adversarial QA C++ tests passed\n");
    return 0;
}
