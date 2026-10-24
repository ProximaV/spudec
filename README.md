# spudec — SPU lifter + SSA IR for IDA Pro 9.x

Stage 1 of an SPU decompiler: IDA's SPU processor module is used purely as a
decoder, and everything above it is ours.

```
procs/spu.py -> lifter -> CFG -> SSA -> opt -> scalarise -> opt
             -> structure -> pseudocode
```

Place the plugin (`spudec_plugin.py`) and the `spudec/` package folder under the IDA installation directory `plugins/` folder (or `%APPDATA%\Hex-Rays\IDA Pro\plugins\`).

## Interactive Decompiler View

When decompiling in IDA Pro, `spudec` opens a dedicated dockable decompiler view with full interactive analysis features:

| Hotkey / Action | Description |
| --- | --- |
| `Ctrl-Shift-S` | Decompile the function under the cursor |
| `Ctrl-F5` | Batch decompile all functions in the database |
| `F5` | Refresh / re-decompile the active function |
| `N` | Rename variable, callee, symbol, or stack frame member |
| `Y` | Set variable type or function prototype |
| `Tab` | Toggle bidirectional disassembly synchronization |
| `Enter` / `Space` / Double-click | Click-through navigation to callee or jump to disassembly EA |
| `I` | Toggle between high-level C pseudocode and low-level SSA IR |
| `Esc` | Close decompiler viewer and clear instruction highlights |

### Key Features

* **Bidirectional Disassembly Synchronization**: Cursor movement in the decompiler view synchronizes and highlights the corresponding instruction(s) in IDA's disassembly window, and clicking anywhere in disassembly jumps and highlights the matching pseudocode line in real time.
* **Dense Instruction Coverage**: Every instruction across all basic blocks, jump sequences, and out-of-order function tail chunks maps to a valid decompiled line.
* **Theme-Aware Syntax Highlighting**: Auto-detects IDA Pro dark and light palettes for syntax and active line highlighting.
* **Netnode-Backed Persistence**: Variable renames, type overrides, prototype overrides, and view preferences are persistently stored in the IDA database via a dedicated netnode (`$ spudec`).

## Calling Convention & Frame Recovery

The SPU ABI defines arguments in `$r3`–`$r74`, return values in `$r3`, stack pointer in `$r1`, and the link/return address register in `$r0`. Registers `$r80`–`$r127` are callee-saved:
* **Prototype Overrides & Parsing**: Functions accept custom C function prototypes (`int foo(int *buf, unsigned int size)`), mapping arguments to `$r3`+ registers automatically.
* **Stack Frame Recovery**: Resolves stack frame references relative to `$r1`, naming slots and supporting member renaming via IDA 9.0+ UDT/frame interfaces.

## C++ names

Mangled symbols are demangled to the qualified name without its parameter list
(IDA's `MNG_NODEFINIT`), since the real arguments are printed instead, so a
call reads as `ss::ss_iso_dprintf::put_s(r3, "In main: ")`. Two functions can
demangle to one name -- a constructor emits both a complete-object and a
base-object body, differing only in the mangling -- so a name shared by more
than one function keeps its address (`ss::crypto::crypto_1510`). Compiler
helpers whose demangled form is not expression-safe (`` `global constructor
keyed to' ``) are sanitised into identifiers.

## What the listing promises

The declaration block and the body are kept in agreement: every name the body
mentions is declared, and every declared local is assigned somewhere (a
register the function only reads is marked `// live in` instead). That sounds
obvious, but three separate things used to break it, and each produced a
listing that referred to a value it never showed being computed:

* A clobber read only by a phi whose own result went nowhere but another
  call's conservative ABI operand list was printed as `rN = <result in rN>`.
  On call-heavy code that was 14% of all output lines.
* The inlining depth cap printed a bare *name* for a definition that had
  already been dropped as a statement, so a deeply nested expression used an
  undeclared variable. The cap now applies when inlinability is decided, so
  anything too deep simply stays a statement.
* A callee-saved register's name is printed by the prologue save (which reads
  the incoming value) while the epilogue restore prints nothing, so the name
  was classed as a local that is never assigned rather than as live-in.

`tests/test_pipeline.py` audits every function it renders for exactly this
agreement, so a regression in either direction fails a test.

## Lane-wise arithmetic

`a rt, ra, rb` adds four 32-bit lanes, so it is only fair to print `a + b`
when the reader cannot be misled about which lanes are involved. That holds
when scalarisation proved the value lives in the preferred slot, when the
recovered type is a vector whose element width matches, or when the type
occupies no more than one element -- an address, or anything demand analysis
narrowed to a word. Stack-frame arithmetic is all of the third kind, which is
why `add.w(sp, #0xffffec50:w4)` now reads `(char *)sp - 0x13B0`.

Compares are deliberately excluded from the type-based case: they produce an
all-ones mask per lane rather than 0 or 1, so `a > b` is only fair once
scalarisation has *proved* the preferred slot, not merely made it likely.

Address arithmetic carries an explicit `(char *)` because C pointer
arithmetic scales and the SPU's does not -- `sp - 0x13B0` on an
`unsigned int *` would mean 0x4EC0 bytes.

## Tests

```
python tests/test_pipeline.py
python tests/test_recover.py
python tests/test_highlight.py
```

* `test_pipeline.py`: Audits the IR pipeline, phi handling, string rendering, inlining depth cap, and frame slot representations.
* `test_recover.py`: Tests netnode persistence, calling convention prototype parsing, variable rename/type application, and `CodeLines` address mapping.
* `test_highlight.py`: Validates syntax tokenization, keyword coloring, and address prefix formatting.

All test suites run standalone without requiring an active IDA GUI.
