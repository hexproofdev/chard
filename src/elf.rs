// SPDX-License-Identifier: BSD-3-Clause

//! ELF fact extraction for the `elf-static` observation channel.
//!
//! We parse the container ourselves rather than shelling out to
//! `readelf`/`objdump`: their text output drifts between binutils versions, and
//! a guest image we drop chard into may ship no binutils at all (Alpine).
//!
//! Only the facts probes actually look at are implemented — this is deliberately
//! not a general ELF library. Every read is bounds-checked and every arithmetic
//! step is explicit, because the inputs are binaries from compilers we have not
//! seen and a panic here would abort a sweep mid-flight.
//!
//! ## The alignment rule that must not be got wrong
//!
//! GNU notes pad the *absolute* offset of the descriptor up to the note's
//! alignment — `desc = note_start + align_up(12 + namesz, align)`. For an ELF64
//! `.note.gnu.property` (align 8, `namesz` 4 for `"GNU\0"`), `12 + 4 = 16` is
//! already 8-aligned, so there is no padding at all. The tempting-but-wrong
//! `12 + align_up(namesz, align)` yields 20, reads four bytes into the middle of
//! the first property, and reports a CET-marked binary as unmarked. That failure
//! is silent and looks exactly like a real "hardening off" result, which is the
//! one outcome this project cannot tolerate — hence `note_padding_*` in
//! `tests/elf_notes.rs` pins it against a real `-fcf-protection=full` build.
//!
//! ## A table the reader could not finish is said so, in the facts
//!
//! Every per-table walk records what it could not read to its end as a typed
//! [`Truncation`] on [`ElfFacts::truncations`], naming the [`ElfTable`] it cut and whether
//! that table's facts are `unread` or a disagreeing view of it was `ignored`. The
//! consumer is `report::truncation_limitation`, which reads the list against the tables
//! each check declares in `probe::Check::reads`; that pairing is what turns a cut table
//! into a withheld verdict rather than a reading of absence. [`ElfTable::SOFT_SITES`]
//! names the tables with a recording site here, and [`ElfTable::HARD_FAILURES`] the two
//! that `parse` refuses outright instead, which `report::Variant::sufficient_for` turns
//! into `indeterminate` before any detector runs. The architecture of the gate is in
//! `DESIGN.md` under the verdict vocabulary.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

pub mod code;
pub mod entry;

mod reloc_names;

// --- ELF constants, named so call sites read as the spec does ----------------

/// No file type. Named because the spec names it; a zero here is a header that says so.
const ET_NONE: u16 = 0;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const ET_LOOS: u16 = 0xfe00;
const ET_HIOS: u16 = 0xfeff;
const ET_LOPROC: u16 = 0xff00;
const ET_HIPROC: u16 = 0xffff;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
/// The segment `ld.so` and the kernel read the program's property notes from.
const PT_GNU_PROPERTY: u32 = 0x6474_e553;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
/// OpenBSD's per-program opt-out from branch-target enforcement, written by its linker
/// under `-z nobtcfi`. The value is the one OpenBSD 7.9 installs in
/// `/usr/include/llvm/BinaryFormat/ELF.h`; see [`ElfFacts::openbsd_nobtcfi`].
const PT_OPENBSD_NOBTCFI: u32 = 0x65a3_dbe8;

const PF_X: u32 = 0x1;

/// `e_phnum` cannot hold a count of 65535 or more, so the gABI reserves that value to say
/// the real count is in `shdr[0].sh_info`.
const PN_XNUM: u16 = 0xffff;
/// The null section index. As `e_shstrndx` it says the file has no section-name table,
/// which is a different statement from having no sections.
const SHN_UNDEF: u16 = 0;
/// `e_shstrndx` cannot hold an index at or above `SHN_LORESERVE`, so the gABI reserves
/// this value to say the real index is in `shdr[0].sh_link`. `e_shnum == 0` with a nonzero
/// `e_shoff` is the same escape for the section count, held in `shdr[0].sh_size`.
const SHN_XINDEX: u16 = 0xffff;

/// A relocatable object: a `.o`, a kernel module, a grub `.mod`.
///
/// Was missing, so `e_type == 1` fell to `format!("ET_{other}")` and rendered `"ET_1"`, while
/// `inspect`'s classifier tested for `"ET_REL"` — a comparison that could never be true. Every
/// relocatable object was published as `kind: "other"`, and 13,424 of them sat in denominators for
/// properties a relocatable object cannot carry, because it has no program headers at all.
const ET_REL: u16 = 1;
/// A core dump. Named for the same reason: an unnamed type is indistinguishable from a type nobody
/// thought about.
const ET_CORE: u16 = 4;
const SHT_STRTAB: u32 = 3;
/// A symbol that stands for a section; relocations against local data go through one.
const STT_SECTION: u8 = 3;
const SHT_SYMTAB: u32 = 2;
/// Relocation entries with an explicit addend; what x86_64 and aarch64 objects carry.
const SHT_RELA: u32 = 4;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
/// Relocation entries whose addend is in the bytes they patch; what i386 objects carry.
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;
/// Compact relocation entries (CREL), which clang writes under `-Wa,--crel` and the reader
/// does not decode; see [`ElfFacts::function_references`].
const SHT_CREL: u32 = 0x4000_0014;
/// The section's `sh_info` is a section index, which a relocation section sets to name the
/// section its offsets are into.
const SHF_INFO_LINK: u64 = 0x40;
/// A symbol naming code: the symbol type in the low nibble of `st_info`.
const STT_FUNC: u8 = 2;
/// The first reserved section index; a symbol at or above it is absolute, common or
/// escaped through `SHT_SYMTAB_SHNDX`, and names no section a relocation can point into.
const SHN_LORESERVE: u16 = 0xff00;
/// The section occupies memory while the program runs.
const SHF_ALLOC: u64 = 0x2;
/// The section holds instructions.
const SHF_EXECINSTR: u64 = 0x4;
/// The build-id note, which Fedora's GNU ld places in the code segment under
/// `-z separate-code`; see [`ElfFacts::data_in_code_pages`].
const BUILD_ID_SECTION: &str = ".note.gnu.build-id";
/// The smallest page a kernel maps for any machine [`machine_name`] names: 4096 bytes,
/// the floor of every family's configurable page sizes (`i386`, `x86_64`, `aarch64`,
/// `arm`, `ppc`, `ppc64`, `s390`, `mips`, `riscv`, `loongarch`). [`ElfFacts::data_in_code_pages`] widens an
/// executable segment to at least this, whatever its `p_align` says.
const MIN_PAGE: u64 = 0x1000;

const DT_NEEDED: i64 = 1;
const DT_PLTRELSZ: i64 = 2;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
/// The library's own name. Recorded as a raw fact and never consulted by `link_kind`:
/// a linker writes it for any output given `-soname`, an executable included, so its
/// presence does not make an object a library.
const DT_SONAME: i64 = 14;
const DT_RPATH: i64 = 15;
const DT_REL: i64 = 17;
const DT_RELSZ: i64 = 18;
const DT_RELENT: i64 = 19;
const DT_PLTREL: i64 = 20;
/// The slot the loader fills with its `r_debug` address for a debugger to find. A marker
/// tag, like `DT_TEXTREL`. `link_kind` reads it as the third discriminator of an
/// executable: see `LinkKind::StaticPie`.
const DT_DEBUG: i64 = 21;
// The original gABI spelling of the fact `DF_TEXTREL` also carries. A marker tag: its
// presence is the statement and its value is ignored.
const DT_TEXTREL: i64 = 22;
const DT_JMPREL: i64 = 23;
const DT_BIND_NOW: i64 = 24;
const DT_RUNPATH: i64 = 29;
const DT_FLAGS: i64 = 30;
const DT_RELR: i64 = 36;
const DT_FLAGS_1: i64 = 0x6fff_fffb;
const DT_GNU_HASH: i64 = 0x6fff_fef5;

const DF_TEXTREL: u64 = 0x4;
const DF_BIND_NOW: u64 = 0x8;
// DT_FLAGS_1 bits, spelled out in full because they are easy to misremember and
// a wrong bit here is invisible in exactly the wrong way: DF_1_NOOPEN is 0x40,
// while 0x4 is DF_1_GROUP. Reading the wrong bit reports a `-Wl,-z,nodlopen`
// binary as unmarked, which is indistinguishable from a distro that never set
// the flag — a false "off" of the precise kind this project exists to prevent.
const DF_1_NOW: u64 = 0x0000_0001;
const DF_1_NOOPEN: u64 = 0x0000_0040;
const DF_1_PIE: u64 = 0x0800_0000;

/// `e_machine` values, as glibc's `elf.h` defines them; the gABI's table gives the same
/// numbers. Named for the machines a sweep is likely to meet, so `machine` can name them
/// as readelf does, and any other value renders as unrecognised in the style of
/// `elf_type`. `machine_name` is the rendering, and `tests/elf_readelf.rs` checks each
/// name against the oracle's on any object of that machine the differential meets.
const EM_386: u16 = 3;
const EM_MIPS: u16 = 8;
const EM_PPC: u16 = 20;
const EM_PPC64: u16 = 21;
const EM_S390: u16 = 22;
const EM_ARM: u16 = 40;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const EM_RISCV: u16 = 243;
const EM_LOONGARCH: u16 = 258;

const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
/// The floor of the processor-specific property range. A type at or above it means
/// whatever `e_machine` says it means, and nothing without that.
const GNU_PROPERTY_LOPROC: u32 = 0xc000_0000;
const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
/// `0xc0000000` is four things at once. It is `GNU_PROPERTY_LOPROC`, the first value of
/// the processor-specific range; on aarch64 it is `GNU_PROPERTY_AARCH64_FEATURE_1_AND`,
/// the BTI/PAC/GCS word; on `EM_RISCV` it is `GNU_PROPERTY_RISCV_FEATURE_1_AND`; and
/// binutils before 2.32 used it on x86 for `GNU_PROPERTY_X86_ISA_1_USED`, so an x86-64
/// object linked by gcc 8 or 9-era binutils carries this type with an ISA bitmap in it.
/// Read without the machine, that bitmap published `aarch64_bti: true` and
/// `aarch64_pac: true` on an x86-64 binary, which is why `facts` decodes a
/// processor-specific property only on the machine that defines it.
///
/// On RISC-V, GNU readelf 2.46 names the word's bit 1 `CFI_LP_UNLABELED`
/// (Zicfilp landing pads) and bit 2 `CFI_SS` (Zicfiss shadow stack) and prints bit 4 as
/// unknown; the psABI's function-signature labels for bit 4 are known from the sources
/// and not measured here. gcc 16.1.1 (Fedora 44's riscv64 cross compiler) writes the word 3
/// under `-march=rv64gc_zicfilp_zicfiss -fcf-protection=full`, which read as the aarch64
/// word would be BTI and PAC. The reader lists the type there and decodes nothing from
/// it, and no check reads RISC-V's control-flow marking.
const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc000_0000;
const X86_FEATURE_1_IBT: u32 = 0x1;
const X86_FEATURE_1_SHSTK: u32 = 0x2;
const AARCH64_FEATURE_1_BTI: u32 = 0x1;
const AARCH64_FEATURE_1_PAC: u32 = 0x2;
/// Guarded Control Stack, aarch64's counterpart to x86's shadow stack. Set by
/// `-mbranch-protection=gcs`, and also by `standard` on compilers new enough to have it.
const AARCH64_FEATURE_1_GCS: u32 = 0x4;

/// Symbols whose presence or absence a probe may key on. Kept as one list so
/// the extracted facts are the same shape regardless of which probe built the
/// binary, which keeps reports diffable across toolchains.
///
/// Public so `tests/elf_readelf.rs` can check both directions against its oracle: a
/// watched name `readelf` shows and this reader does not is the false negative the
/// list exists to make visible.
pub const WATCHED_SYMBOLS: &[&str] = &[
    "__stack_chk_fail",
    "__stack_chk_fail_local",
    "__stack_chk_guard",
    // OpenBSD's canary failure handler, called where other targets call
    // `__stack_chk_fail`. `predicate::elf_static`'s `CANARY` carries the measurement, and
    // why OpenBSD amd64 emits RETGUARD rather than this by default.
    "__stack_smash_handler",
    "__memcpy_chk",
    "__memmove_chk",
    "__memset_chk",
    "__strcpy_chk",
    "__strncpy_chk",
    "__strcat_chk",
    "__sprintf_chk",
    "__snprintf_chk",
    "__printf_chk",
    // clang's checking `printf`, called from glibc's out-of-line wrapper with the same flag
    // argument gcc passes `__printf_chk`; `predicate::elf_static`'s `FORTIFY_PRINTF_FLAG`
    // reads either. Measured 2026-10-02 with `nm -u` under clang 22.1.8 with glibc 2.43 on
    // Fedora 44 x86_64 and aarch64.
    "__vprintf_chk",
    "__fprintf_chk",
    "__vsnprintf_chk",
    "__read_chk",
    // FreeBSD's failure handler, which its inline wrappers (`__ssp_check` in `<ssp/ssp.h>`,
    // the descriptor functions among them) call directly; the string family reaches the
    // `__*_chk` functions above through `__builtin___*_chk`. `decode::runtime`'s
    // `freebsd_checking_call` reads either kind. Measured 2026-10-27 with `nm -u` on FreeBSD
    // 15.1 amd64 (clang 19.1.7): `read` into a short buffer references `__chk_fail`, and the
    // fortify probes `__memcpy_chk` or `__strcpy_chk`.
    "__chk_fail",
    "__fortify_fail",
    "__asan_init",
    "__ubsan_handle_add_overflow",
    "__ubsan_handle_mul_overflow",
    "__ubsan_handle_type_mismatch_v1",
    // The handlers `probes/ubsan_trap.c`'s constructs call outside trap mode, in each
    // spelling a runtime gives them: the recovering handler, `_abort` under
    // `-fno-sanitize-recover`, and clang's `-fsanitize-minimal-runtime` names, recovering
    // and not (the recovering `add_overflow` and `type_mismatch_v1` are above).
    // `predicate::elf_static`'s `UBSAN_TRAP` reads them beside a trap to tell a build
    // whose checks all trap from one where some still call the runtime. Measured
    // 2026-10-02 with `nm -u` over that probe's object on Fedora 44 x86_64 (gcc 16.1.1,
    // clang 22.1.8) and aarch64 (gcc 16.2.1, clang 22.1.8); gcc refuses
    // `-fsanitize-minimal-runtime`.
    "__ubsan_handle_type_mismatch_v1_abort",
    "__ubsan_handle_type_mismatch_minimal",
    "__ubsan_handle_type_mismatch_minimal_abort",
    "__ubsan_handle_shift_out_of_bounds",
    "__ubsan_handle_shift_out_of_bounds_abort",
    "__ubsan_handle_shift_out_of_bounds_minimal",
    "__ubsan_handle_shift_out_of_bounds_minimal_abort",
    "__ubsan_handle_out_of_bounds",
    "__ubsan_handle_out_of_bounds_abort",
    "__ubsan_handle_out_of_bounds_minimal",
    "__ubsan_handle_out_of_bounds_minimal_abort",
    "__ubsan_handle_add_overflow_abort",
    "__ubsan_handle_add_overflow_minimal",
    "__ubsan_handle_add_overflow_minimal_abort",
    "__ubsan_handle_pointer_overflow",
    "__ubsan_handle_pointer_overflow_abort",
    "__ubsan_handle_pointer_overflow_minimal",
    "__ubsan_handle_pointer_overflow_minimal_abort",
    // The minimal runtime's recovering handlers under clang's
    // `-fsanitize-handler-preserve-all-regs`, which calls them with every register
    // preserved. Measured 2026-10-02 with `nm -u` over `probes/ubsan_trap.c`'s object under
    // clang 22.1.8 on Fedora 44 x86_64 and aarch64, at -O0 and -O2: these five, and with
    // `-fno-sanitize-recover=all` the `_minimal_abort` names above. A handler spelling this
    // list lacks still cannot pass a trap as trap mode: `UBSAN_TRAP`'s `trap-beside-call`
    // reads the call itself.
    "__ubsan_handle_type_mismatch_minimal_preserve",
    "__ubsan_handle_shift_out_of_bounds_minimal_preserve",
    "__ubsan_handle_out_of_bounds_minimal_preserve",
    "__ubsan_handle_add_overflow_minimal_preserve",
    "__ubsan_handle_pointer_overflow_minimal_preserve",
    // The type-mismatch handler's name before its `_v1` revision, which gcc 8 and clang 5
    // adopted: a toolchain older than those calls this one. Not measured, since no host
    // carries such a toolchain; listed so a trap beside it reads as a trap beside a
    // handler rather than as a trap alone.
    "__ubsan_handle_type_mismatch",
    "__ubsan_handle_type_mismatch_abort",
    // The handlers `probes/ubsan_trap.c`'s third and fourth functions call outside trap
    // mode: clang's `local-bounds` on the indexed global array
    // under `-fno-sanitize-trap=local-bounds` (the group traps by default), and clang's
    // `function` on the call through a pointer. gcc's `object-size` on the same array calls
    // `type_mismatch_v1`, above. Measured 2026-10-07 with `nm -u` over that probe's object
    // under clang 22.1.8 on Fedora 44 x86_64 at -O0 and -O2: `_abort` is the recovering
    // default's spelling for `local-bounds` (`-fsanitize-recover=local-bounds` gives the
    // bare name), the `_minimal` pair under `-fsanitize-minimal-runtime`, and
    // `-fsanitize-handler-preserve-all-regs` spells `local-bounds` as `_minimal_abort` and
    // `function` as `_minimal_preserve`.
    "__ubsan_handle_local_out_of_bounds",
    "__ubsan_handle_local_out_of_bounds_abort",
    "__ubsan_handle_local_out_of_bounds_minimal",
    "__ubsan_handle_local_out_of_bounds_minimal_abort",
    "__ubsan_handle_function_type_mismatch",
    "__ubsan_handle_function_type_mismatch_abort",
    "__ubsan_handle_function_type_mismatch_minimal",
    "__ubsan_handle_function_type_mismatch_minimal_abort",
    "__ubsan_handle_function_type_mismatch_minimal_preserve",
    // The handlers `probes/ubsan_trap.c`'s second function, `chard_ubsan_trap_groups`, calls
    // outside trap mode, in every spelling a runtime gives them, so a build whose only
    // sanitizer is one of its groups, in handler mode, reads as handler mode rather than as a
    // call the predicate cannot name. `builtin_unreachable` has no `_abort` form: it never
    // returns. Measured 2026-10-07 with `nm -u` over that probe's object under gcc 16.1.1
    // and clang 22.1.8 on Fedora 44 x86_64, at -O0 and -O2, with `-fsanitize=undefined`
    // beside `float-divide-by-zero` and `float-cast-overflow` (and under clang
    // `implicit-conversion`, `nullability`, `unsigned-integer-overflow` and
    // `unsigned-shift-base`), recovering, `-fno-sanitize-recover=all`, and under clang
    // `-fsanitize-minimal-runtime` with each of those and with
    // `-fsanitize-handler-preserve-all-regs`; the `nullability_*` names with
    // `-fsanitize=nullability` alone, since beside `nonnull-attribute` clang calls the
    // `nonnull_*` handlers for the same constructs.
    "__ubsan_handle_builtin_unreachable",
    "__ubsan_handle_builtin_unreachable_minimal",
    "__ubsan_handle_builtin_unreachable_minimal_preserve",
    "__ubsan_handle_divrem_overflow",
    "__ubsan_handle_divrem_overflow_abort",
    "__ubsan_handle_divrem_overflow_minimal",
    "__ubsan_handle_divrem_overflow_minimal_abort",
    "__ubsan_handle_divrem_overflow_minimal_preserve",
    "__ubsan_handle_float_cast_overflow",
    "__ubsan_handle_float_cast_overflow_abort",
    "__ubsan_handle_float_cast_overflow_minimal",
    "__ubsan_handle_float_cast_overflow_minimal_abort",
    "__ubsan_handle_float_cast_overflow_minimal_preserve",
    "__ubsan_handle_implicit_conversion",
    "__ubsan_handle_implicit_conversion_abort",
    "__ubsan_handle_implicit_conversion_minimal",
    "__ubsan_handle_implicit_conversion_minimal_abort",
    "__ubsan_handle_implicit_conversion_minimal_preserve",
    "__ubsan_handle_invalid_builtin",
    "__ubsan_handle_invalid_builtin_abort",
    "__ubsan_handle_invalid_builtin_minimal",
    "__ubsan_handle_invalid_builtin_minimal_abort",
    "__ubsan_handle_invalid_builtin_minimal_preserve",
    "__ubsan_handle_load_invalid_value",
    "__ubsan_handle_load_invalid_value_abort",
    "__ubsan_handle_load_invalid_value_minimal",
    "__ubsan_handle_load_invalid_value_minimal_abort",
    "__ubsan_handle_load_invalid_value_minimal_preserve",
    "__ubsan_handle_nonnull_arg",
    "__ubsan_handle_nonnull_arg_abort",
    "__ubsan_handle_nonnull_arg_minimal",
    "__ubsan_handle_nonnull_arg_minimal_abort",
    "__ubsan_handle_nonnull_arg_minimal_preserve",
    "__ubsan_handle_nonnull_return_v1",
    "__ubsan_handle_nonnull_return_v1_abort",
    "__ubsan_handle_nonnull_return_minimal",
    "__ubsan_handle_nonnull_return_minimal_abort",
    "__ubsan_handle_nonnull_return_minimal_preserve",
    "__ubsan_handle_nullability_arg",
    "__ubsan_handle_nullability_arg_abort",
    "__ubsan_handle_nullability_arg_minimal",
    "__ubsan_handle_nullability_arg_minimal_abort",
    "__ubsan_handle_nullability_arg_minimal_preserve",
    "__ubsan_handle_nullability_return_v1",
    "__ubsan_handle_nullability_return_v1_abort",
    "__ubsan_handle_nullability_return_minimal",
    "__ubsan_handle_nullability_return_minimal_abort",
    "__ubsan_handle_nullability_return_minimal_preserve",
    "__ubsan_handle_sub_overflow",
    "__ubsan_handle_sub_overflow_abort",
    "__ubsan_handle_sub_overflow_minimal",
    "__ubsan_handle_sub_overflow_minimal_abort",
    "__ubsan_handle_sub_overflow_minimal_preserve",
    "__ubsan_handle_vla_bound_not_positive",
    "__ubsan_handle_vla_bound_not_positive_abort",
    "__ubsan_handle_vla_bound_not_positive_minimal",
    "__ubsan_handle_vla_bound_not_positive_minimal_abort",
    "__ubsan_handle_vla_bound_not_positive_minimal_preserve",
    // Defined by `probes/ubsan_trap.c` where `__has_feature(undefined_behavior_sanitizer)`
    // holds, so `predicate::elf_static`'s `UBSAN_TRAP` can tell a build that enables a
    // sanitizer group the probe has no construct for from one that enables none.
    "chard_ubsan_trap_feature",
    "__cfi_slowpath",
    "abort",
    // libstdc++'s out-of-line assertion failure handler, and the two `__gnu_debug`
    // entry points `-D_GLIBCXX_DEBUG` substitutes for it. Mangled and unversioned:
    // `nm -D` prints `@GLIBCXX_3.4.30` after the first, but the version lives in
    // `.gnu.version` rather than in the symbol's own name, which is what this list
    // matches against. Measured on gcc 16.2.1 and clang 22.1.8 over libstdc++ 16.
    "_ZSt21__glibcxx_assert_failPKciS0_S0_",
    // The same failure before GCC 12 moved it out of line: `std::__replacement_assert`,
    // defined inline in `bits/c++config.h` and emitted as a comdat wherever the compiler
    // did not fold it away. The length prefixes differ because the names do -- `21` for
    // `__glibcxx_assert_fail`, `20` for `__replacement_assert` -- and reading only the
    // first spelling reported the mechanism absent on every libstdc++ up to 11, where it
    // is present under the older name.
    "_ZSt20__replacement_assertPKciS0_S0_",
    "_ZNK11__gnu_debug16_Error_formatter10_M_messageENS_13_Debug_msg_idE",
    "_ZNK11__gnu_debug16_Error_formatter8_M_errorEv",
    // gcc's mark of a slim LTO object: a common symbol in an object that holds GIMPLE in
    // `.gnu.lto_*` sections and no generated code, over which `report::lto_ir_limitation`
    // withholds an elf-static reading. Measured 2026-10-01 with `readelf -sW` over a
    // `-flto -c` object: present under gcc 11.4.0 and 13.3.0 (Ubuntu 22.04, 24.04 x86_64),
    // 15.2.0 (Alpine x86_64), 16.1.1 (Fedora 44 x86_64) and 16.2.1 (Fedora 44 aarch64), and absent
    // under `-flto -ffat-lto-objects`, whose object carries generated code beside the
    // GIMPLE. Reading its absence as fat is `gcc-marks-every-slim-lto-object` in
    // `report::ASSUMPTIONS`.
    "__gnu_lto_slim",
    // libgcc's trapping arithmetic for `int`, which gcc calls in place of a signed
    // addition, subtraction or multiplication under -ftrapv; undefined in the object that
    // calls them. `predicate::elf_static`'s TRAPV_HELPER carries the measurement.
    "__addvsi3",
    "__subvsi3",
    "__mulvsi3",
];

/// The least multiple of `align` that is not below `value`, or `None` when no such
/// multiple is representable.
///
/// `None` has exactly one cause: `value + align - 1` overflows `u64`, so every multiple
/// of `align` at or above `value` is past the end of the address space. No other error
/// path is reachable: the early return establishes `align >= 2` for the rest of the body, so
/// `align - 1` cannot underflow, the division cannot be by zero, and `(bump / align) *
/// align <= bump` cannot overflow. `proofs/align_up_is_least_multiple.rs` checks that
/// claim rather than trusting this paragraph, and checks the postcondition with it.
///
/// Returns `Option` rather than a `Result` for the reason `Cursor` does: an eagerly
/// formatted error on this path is what a model checker follows into
/// `core::slice::memchr`, and there is nothing to say here beyond "did not fit" anyway.
///
/// ## Why this function is worth proving
///
/// The module header calls the alignment rule the one that must not be got wrong, and its
/// failure is silent: `12 + align_up(namesz, align)` instead of `align_up(12 + namesz,
/// align)` reads four bytes into the middle of the first property and reports a
/// `-fcf-protection=full` binary as having no CET markings. Until the proof, the whole
/// rule rested on four hand-picked examples, none of which reaches a non-power-of-two
/// alignment or the overflow edge.
// The bare `align - 1`, `/` and `*` below are the operations this lint exists to catch, and
// they are here deliberately. `the_deleted_error_paths_were_unreachable` in
// `proofs/align_up_is_least_multiple.rs` is a machine-checked proof that none of them can
// underflow, divide by zero or overflow given `align >= 2`, which the early return
// establishes. The checked forms would reintroduce three `None` arms no input can reach,
// and an unreachable arm in a function whose job is to be exactly right is worse than an
// allow with a proof behind it. If the proof is ever removed, remove this too.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "proofs/align_up_is_least_multiple.rs machine-checks that align >= 2 makes \
              the subtraction, division and multiplication total; the checked forms would \
              reintroduce three None arms no input can reach"
)]
fn align_up(value: u64, align: u64) -> Option<u64> {
    if align <= 1 {
        return Some(value);
    }
    // `align >= 2` from here, which is what discharges the other three failure modes.
    let bump = value.checked_add(align - 1)?;
    Some(bump / align * align)
}

/// The alignment a note walk pads to, from the one its container declares.
///
/// Notes are padded to at least 4 bytes whatever the container says, so a declared 0, 1
/// or 2 is read as 4, which is what readelf's `process_notes_at` does. Declared 1 is not
/// hypothetical: annobin's per-function `.gnu.build.attributes..text.*` sections carry
/// `sh_addralign` 1, and walking them with no padding stopped part-way on every
/// annobin-built object, withholding `cet-marked` over a property note that was intact.
fn note_alignment(declared: u64) -> u64 {
    declared.max(4)
}

/// Refuse a table whose declared stride is below the record it is made of.
///
/// A count of zero says nothing about the stride, so it is not grounds to refuse; larger
/// than the record size is legal, since the spec permits padding.
fn check_strides(elf64: bool, ph: (u64, u64), sh: (u64, u64)) -> Result<(), ElfError> {
    let (ph_min, sh_min) = if elf64 { (56, 64) } else { (32, 40) };
    for (field, record, (count, entsize), min) in [
        ("e_phentsize", "program header", ph, ph_min),
        ("e_shentsize", "section header", sh, sh_min),
    ] {
        if count > 0 && entsize < min {
            return Err(ElfError::malformed(format!(
                "{field} is {entsize}, below the {min}-byte {record} this class defines, so \
                 the {count} declared entries overlap rather than follow one another"
            )));
        }
    }
    Ok(())
}

/// The bytes one symbol occupies in this class: `Elf64_Sym` or `Elf32_Sym`.
fn symbol_record(elf64: bool) -> NonZeroU64 {
    if elf64 {
        record_size::<24>()
    } else {
        record_size::<16>()
    }
}

/// `N` as a stride, which a record size always is: `NonZeroU64::MIN` (1) plus `N - 1`,
/// const and total, so the stride type holds no zero and no division by one needs an arm.
const fn record_size<const N: u64>() -> NonZeroU64 {
    const { assert!(N > 0, "a record size is not zero") };
    NonZeroU64::MIN.saturating_add(N.saturating_sub(1))
}

/// The bytes one relocation occupies in this class and form: `Elf64_Rela` 24, `Elf64_Rel`
/// 16, `Elf32_Rela` 12, `Elf32_Rel` 8.
fn relocation_record(elf64: bool, rela: bool) -> NonZeroU64 {
    match (elf64, rela) {
        (true, true) => record_size::<24>(),
        (true, false) => record_size::<16>(),
        (false, true) => record_size::<12>(),
        (false, false) => record_size::<8>(),
    }
}

/// The stride a table of fixed-size records is read at, which is the record size whatever
/// the table declares, beside an `ignored` record on `table` where the declared entry size
/// (`field`: a section's `sh_entsize`, a `DT_RELAENT`) says otherwise.
///
/// The ABI fixes each record's size. The loader walks `DT_SYMTAB` at that size whatever a
/// header declares; glibc's `ld.so` refuses an object whose `DT_RELAENT` is not the record
/// size (measured 2026-10-20 with glibc 2.43 on Fedora 44 x86_64: the assertion in
/// `elf_get_dynamic_info`, exit 127); and readelf reports an invalid `sh_entsize` and reads at
/// the expected size. So no reading at a declared size is one a loader makes, and the record
/// says the size the ABI fixes rather than naming a loader. A walk that took the declared size
/// floored at the record would let a declared size above it choose which records are read.
/// Measured 2026-10-20 on Fedora 44 x86_64 with gcc 16.1.1: a
/// `-O2 -fstack-protector-strong -fPIE -pie -s` program whose `.dynsym` `sh_entsize` is
/// patched from 24 to 48 still runs, and a walk at the declared size reads 4 of its 8 named
/// symbols and loses `__stack_chk_fail`, withheld only by the stops a misaligned read happens
/// to reach; a table whose size the declared stride divides is read every other record with
/// nothing recorded (`tests/elf_truncations.rs`,
/// `a_symbol_table_declaring_another_entry_size_is_read_in_records`).
///
/// This is the one place a stride is decided: a section's walk reaches it through
/// [`Elf::section_stride`], the only reader of `sh_entsize`, and `relocation_reach` calls it
/// for the dynamic tags; `tests::every_stride_is_decided_by_record_stride` holds both. The
/// record is `ignored`, not `unread`: the table is read whole, at the size the ABI fixes, so
/// the facts are the ones every reader of the format takes, and the record names the header
/// or tag that disagreed. A declared size below the record, which a floor at the record
/// would keep from reading one "symbol" per byte, is the same disagreement and is read the same
/// way.
///
/// A named risk, not a withholding: a `DT_RELAENT` or `DT_RELENT` that differs is `ignored`
/// too, though glibc's `ld.so` refuses to run the object. musl's loader runs it and walks the
/// tables at the record size (measured 2026-10-20 with musl 1.2.5 on Fedora 44 x86_64: a
/// `-fPIE -pie` program with `DT_RELAENT` 48 exits 0), so the facts are the ones that loader
/// and readelf take, and an object glibc will not start runs no protection, so no verdict
/// over it describes a running glibc program; the record names the tag.
#[must_use]
fn record_stride(
    declared: u64,
    record: NonZeroU64,
    table: ElfTable,
    field: &str,
) -> (NonZeroU64, Option<Truncation>) {
    let differs = (declared != record.get()).then(|| {
        Truncation::ignored(
            table,
            format!(
                "{field} is {declared} where the record is {record} bytes, so it was read in \
                 {record}{STRIDE_RECORD_TAIL}"
            ),
        )
    });
    (record, differs)
}

/// How every record [`record_stride`] writes ends, after the record size.
const STRIDE_RECORD_TAIL: &str = "-byte records, the size the ABI fixes";

/// Whether `t` is a record [`record_stride`] wrote: `ignored`, and its detail ending as that
/// helper's does. For a reader that compares two readings with the declarations taken out
/// (the `elf_parse` fuzz target), so its filter is this module's and not a copy of the
/// sentence; `tests::a_stride_record_is_told_apart_by_its_writer` holds the two together.
#[must_use]
pub fn is_stride_record(t: &Truncation) -> bool {
    t.kind == TruncationKind::Ignored && t.detail.ends_with(STRIDE_RECORD_TAIL)
}

/// `trunc` with each stride record kept at its first place only: several walks read one
/// section (the symbol readers, a relocatable object's three relocation walks), and
/// [`Elf::section_stride`] labels the record from that section alone (its name, with its
/// index where the name is absent or another section's too), so theirs are equal and two
/// sections' are not. One pass over a set, where checking the list at each push was
/// quadratic in the section count; the other records are left as they are.
fn once_each_stride_record(mut trunc: Vec<Truncation>) -> Vec<Truncation> {
    let mut seen = BTreeSet::new();
    trunc.retain(|t| !is_stride_record(t) || seen.insert((t.table, t.detail.clone())));
    trunc
}

/// Bounds-checked, endianness-aware reader. Every accessor returns `Result` so a
/// truncated or hostile file produces a typed error instead of a panic.
struct Cursor<'a> {
    data: &'a [u8],
    little: bool,
}

/// Why a bounded read could not be served.
///
/// A plain enum rather than an `anyhow::Error`, and the reason is mechanical rather than
/// stylistic. These four are the reader's numeric contact with untrusted bytes; `cstr_at`
/// is a fifth, proved differently, see its own doc comment. `THREAT_MODEL.md` treats a
/// panic in any of the five as a bug to report, so these four are where a Kani proof
/// belongs. `anyhow`'s constructors format eagerly, and a bounded model checker following
/// that path disappears into `core::slice::memchr`: a Kani proof of a *four-line arithmetic
/// helper* in this file was killed at 480s having unwound memchr 6,687 times, while a proof
/// touching no chard code verified in seconds. Constructing an error must therefore allocate
/// and format nothing. `cstr_at` calls `position()` over the same `memchr`-backed path on
/// every input by construction, which is why it is held to a targeted unit test
/// (`a_cstring_read_never_crosses_its_own_tables_declared_end`) instead of a Kani harness:
/// the harness that would prove it is the one this paragraph already measured timing out.
///
/// Callers are unaffected. [`ElfError`] converts from it, so the 50 `?` sites downstream
/// widen into `ElfError::Truncated` at the call site, and the conversion happens in the
/// caller rather than inside the read.
///
/// The payload is captured, not rendered. `Display` runs only when someone prints the error,
/// which is the boundary, never the read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// The offset does not fit this machine's `usize`.
    OffsetTooLarge(u64),
    /// The length does not fit this machine's `usize`.
    LengthTooLarge(u64),
    /// `start + count` overflowed `usize`.
    EndOverflows { start: usize, count: usize },
    /// The window lies outside the object.
    OutOfBounds { start: usize, count: usize },
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::OffsetTooLarge(off) => write!(f, "offset {off} exceeds address space"),
            Self::LengthTooLarge(len) => write!(f, "length {len} exceeds address space"),
            Self::EndOverflows { start, count } => {
                write!(f, "read of {count} bytes at {start} overflows")
            }
            Self::OutOfBounds { start, count } => {
                write!(f, "read of {count} bytes at {start} is out of bounds")
            }
        }
    }
}

impl std::error::Error for ReadError {}

/// Why an object could not be read into facts.
///
/// The type a read fails with once it has left `Cursor`. [`ReadError`] stays the
/// allocation-free `Copy` enum the Kani proofs need, and `From<ReadError>` is where the
/// widening happens: a `?` on a bounded read inside `parse` lands here as `Truncated`,
/// carrying the read that fell outside the object. The other variants are built at the two
/// boundaries, `parse` for the shape of the bytes and `facts_for` for the file around them,
/// and `facts_for` attaches the path to whatever `parse` refused without one.
///
/// Typed because the envelope classifies by variant: `src/error.rs` reads `Io` by its kind
/// and every other variant as the caller's object, and a message string can only be
/// guessed at. `Display` is the whole message, with the path in front when one is known,
/// and `source()` is `None` on every variant. The two consumers want opposite things of a
/// source: the envelope joins the chain and would print it twice, and `Variant::elf_error`
/// stores `Display` alone and would never print it. Carrying the reason in `Display`
/// serves both.
#[derive(Debug)]
pub enum ElfError {
    /// The bytes are not an ELF object: too short for an identification, wrong magic, or
    /// a class or data encoding this reader has no layout for.
    NotElf { path: Option<PathBuf>, why: String },
    /// The bytes open a Mach-O object (`is_mach_o`: a thin magic in either byte order, or a
    /// universal magic beside a plausible architecture count): the format a macOS toolchain
    /// writes, which this reader does not parse.
    /// Told apart from [`Self::NotElf`] because the macro channel's self-report gate reads
    /// the dump by design over a Mach-O artifact on a macOS run and over nothing else this
    /// reader refuses (`report::artifact_account_missing`).
    MachO { path: Option<PathBuf> },
    /// The header describes a table the file cannot hold: a stride below the record, an
    /// offset that overflows, a `shdr[0]` escape that names bytes past the end.
    Malformed { path: Option<PathBuf>, what: String },
    /// A bounded read fell outside the object.
    Truncated {
        path: Option<PathBuf>,
        read: ReadError,
    },
    /// Above the cap `facts_for` names (`MAX_OBJECT_BYTES`). `size` is the length a
    /// regular file's metadata reported, refused before the open; it is `None` for a
    /// stream, whose length is unknown until it ends and which the reader stopped at the
    /// cap.
    TooLarge {
        path: PathBuf,
        size: Option<u64>,
        cap: u64,
    },
    /// The file's metadata or bytes could not be read. The kind is kept for the envelope
    /// to classify.
    Io {
        path: PathBuf,
        op: &'static str,
        source: std::io::Error,
    },
}

impl ElfError {
    fn malformed(what: impl Into<String>) -> Self {
        Self::Malformed {
            path: None,
            what: what.into(),
        }
    }

    /// The same refusal, naming the file it was read from.
    fn with_path(self, path: &Path) -> Self {
        let named = Some(path.to_path_buf());
        match self {
            Self::NotElf { path: None, why } => Self::NotElf { path: named, why },
            Self::MachO { path: None } => Self::MachO { path: named },
            Self::Malformed { path: None, what } => Self::Malformed { path: named, what },
            Self::Truncated { path: None, read } => Self::Truncated { path: named, read },
            other => other,
        }
    }

    /// The file this refusal is about, when it was read from one.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::NotElf { path, .. }
            | Self::MachO { path }
            | Self::Malformed { path, .. }
            | Self::Truncated { path, .. } => path.as_deref(),
            Self::TooLarge { path, .. } | Self::Io { path, .. } => Some(path),
        }
    }
}

impl std::fmt::Display for ElfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn prefixed(
            f: &mut std::fmt::Formatter<'_>,
            path: Option<&Path>,
            body: &dyn std::fmt::Display,
        ) -> std::fmt::Result {
            if let Some(path) = path {
                write!(f, "{}: ", path.display())?;
            }
            write!(f, "{body}")
        }
        match self {
            Self::NotElf { path, why } => prefixed(f, path.as_deref(), why),
            Self::MachO { path } => prefixed(f, path.as_deref(), &MACH_O_REFUSAL),
            Self::Malformed { path, what } => prefixed(f, path.as_deref(), what),
            Self::Truncated { path, read } => prefixed(f, path.as_deref(), read),
            Self::TooLarge {
                path,
                size: Some(size),
                cap,
            } => write!(
                f,
                "{} is {size} bytes, above the {cap}-byte cap on a single object, so it \
                 was not read. Four magic bytes are all that identify a file as ELF, and \
                 this reader holds whatever it opens.",
                path.display()
            ),
            Self::TooLarge {
                path,
                size: None,
                cap,
            } => write!(
                f,
                "{} carried more than {cap} bytes, the cap on a single object, so the rest \
                 was not read. Four magic bytes are all that identify a stream as ELF, and \
                 this reader holds whatever it reads.",
                path.display()
            ),
            Self::Io { path, op, source } => write!(f, "{op} {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for ElfError {}

impl From<ReadError> for ElfError {
    fn from(read: ReadError) -> Self {
        Self::Truncated { path: None, read }
    }
}

/// The result of a bounded read. Deliberately narrower than [`ElfError`]: it is the type
/// the Kani proofs see.
type Read<T> = std::result::Result<T, ReadError>;

impl<'a> Cursor<'a> {
    fn slice(&self, off: u64, len: u64) -> Read<&'a [u8]> {
        // The discarded `TryFromIntError` says only "did not fit", which the variant
        // already says while also carrying the value that did not fit. Named-but-ignored
        // rather than `|_|` so the discard is deliberate and clippy can see that it is.
        let start = usize::try_from(off).map_err(|_too_big| ReadError::OffsetTooLarge(off))?;
        let count = usize::try_from(len).map_err(|_too_big| ReadError::LengthTooLarge(len))?;
        let end = start
            .checked_add(count)
            .ok_or(ReadError::EndOverflows { start, count })?;
        self.data
            .get(start..end)
            .ok_or(ReadError::OutOfBounds { start, count })
    }

    fn u16_at(&self, off: u64) -> Read<u16> {
        // `slice` returned exactly 2 bytes or an error, so the array conversion cannot
        // fail; `unwrap_or` discharges it without a panic rather than asserting it.
        let b: [u8; 2] = self.slice(off, 2)?.try_into().unwrap_or([0; 2]);
        Ok(if self.little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }

    fn u32_at(&self, off: u64) -> Read<u32> {
        let b: [u8; 4] = self.slice(off, 4)?.try_into().unwrap_or([0; 4]);
        Ok(if self.little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    fn u64_at(&self, off: u64) -> Read<u64> {
        let b: [u8; 8] = self.slice(off, 8)?.try_into().unwrap_or([0; 8]);
        Ok(if self.little {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }

    /// Width-dependent read: 4 bytes on ELF32, 8 on ELF64.
    fn addr_at(&self, off: u64, elf64: bool) -> Read<u64> {
        if elf64 {
            self.u64_at(off)
        } else {
            Ok(u64::from(self.u32_at(off)?))
        }
    }

    /// A NUL-terminated string at `base + off`, never read past `off + table_len` bytes
    /// from `base`. `table_len` is the caller's own declared bound on the table `base`
    /// starts (a section's `sh_size`, `DT_STRSZ`, a note's `namesz`) — never the size of
    /// `self.data`. A table whose declared length is exceeded before any NUL appears
    /// reads as truncated at that length, not as reaching into whatever bytes follow.
    ///
    /// Unbounded-but-safe is the hazard: a scan to `self.data.len()` is panic-free
    /// because of `.get()`, which is beside the point. Two failures follow from treating
    /// "cannot panic" as "cannot mislead":
    /// a note name that overruns `namesz` reads bytes belonging to the descriptor or the
    /// next note, changing what the name compares equal to (`gnu_properties` gates on
    /// `note.name == "GNU"`, so a corrupted name silently drops a real property note,
    /// a false `off` from a crafted file, the one verdict this reader exists to refuse);
    /// and a string table with no terminator before EOF turns a bounded-count loop over
    /// `dyn_strings`/`symbols` into an O(n²) scan, the same shape `min_step`
    /// above closes for one trigger without bounding the read underneath it.
    ///
    /// Both are closed here. The misreadings a crafted file can still produce, the ones measured so
    /// far, are the register entries `THREAT_MODEL.md`'s crafted-ELF row names.
    fn cstr_at(&self, base: u64, off: u32, table_len: u64) -> String {
        let Some(remaining) = table_len.checked_sub(u64::from(off)) else {
            return String::new(); // `off` is at or past the table's own declared end
        };
        let Ok(start) = usize::try_from(base.saturating_add(u64::from(off))) else {
            return String::new();
        };
        let cap = usize::try_from(remaining).unwrap_or(usize::MAX);
        let Some(rest) = self.data.get(start..) else {
            return String::new();
        };
        let bounded = rest.get(..cap.min(rest.len())).unwrap_or(rest);
        let end = bounded
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(bounded.len());
        String::from_utf8_lossy(bounded.get(..end).unwrap_or(&[])).into_owned()
    }
}

/// What naming a relocation's symbol reads: the symbol table its section links, that
/// table's string table, and the table's entry stride and whole-entry count.
struct RelocationNames<'s> {
    symtab: &'s Shdr,
    strtab: &'s Shdr,
    sym_step: u64,
    sym_count: u64,
}

struct Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    /// Virtual address. Needed only to translate a `.dynamic` pointer — `DT_STRTAB` and friends
    /// hold vaddrs, and with no section-header table there is no other way to reach the bytes.
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

struct Shdr {
    sh_name: u32,
    sh_type: u32,
    /// Read for `SHF_ALLOC` and `SHF_EXECINSTR`, which is how
    /// [`ElfFacts::data_in_code_pages`] tells a code section from data by the linker's own
    /// account rather than by name, and `SHF_EXECINSTR` is what `code` requires of a section
    /// it searches.
    sh_flags: u64,
    /// The section's address in a linked object, which maps a function's `st_value` back
    /// to the section's bytes; 0 in an `ET_REL`, where `st_value` is already an offset.
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    /// Read from `shdr[0]`, where it carries the program-header count once `e_phnum`
    /// has overflowed to `PN_XNUM`, and from a relocation section, where it is the index
    /// of the section the entries patch ([`ElfFacts::code_relocations`]).
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

/// A function's name and the distinct names its range refers to.
type FunctionRefs<'a> = (&'a str, BTreeSet<&'a str>);

/// The prefix of an [`ElfFacts::function_references`] item naming a target that a
/// relocation in code refers to from outside every function's range: `?:` followed by the
/// target. No C function is named `?`, so the item is never a function's own.
pub const UNATTRIBUTED_REFERENCE: &str = "?:";

/// Per section index, the function ranges `(start, end, function)` sorted by start, beside
/// the running maximum of the ends up to each.
type SectionRanges = BTreeMap<u16, (Vec<(u64, u64, usize)>, Vec<u64>)>;

/// One `.symtab` entry as [`Elf::function_references`] reads it.
struct SymbolEntry {
    name: String,
    info: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

/// `EI_DATA`, as [`ElfFacts::elf_data`] publishes it: the byte order of the file's fields,
/// which is the order its target reads memory in. Spelled `little-endian` and `big-endian`:
/// the words `readelf -h` prints after "2's complement, ", hyphenated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ByteOrder {
    LittleEndian,
    BigEndian,
}

impl ByteOrder {
    /// Every value, for the schema test that pins the published vocabulary to this one.
    pub const ALL: &[Self] = &[Self::LittleEndian, Self::BigEndian];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LittleEndian => "little-endian",
            Self::BigEndian => "big-endian",
        }
    }
}

impl std::fmt::Display for ByteOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The magics a thin Mach-O object opens with, as bytes in file order: 32- and 64-bit in
/// either byte order (`MH_MAGIC`, `MH_MAGIC_64`, `MH_CIGAM`, `MH_CIGAM_64`).
const MACH_O_THIN_MAGICS: [[u8; 4]; 4] = [
    [0xfe, 0xed, 0xfa, 0xce],
    [0xfe, 0xed, 0xfa, 0xcf],
    [0xce, 0xfa, 0xed, 0xfe],
    [0xcf, 0xfa, 0xed, 0xfe],
];

/// The magics a universal (fat) Mach-O binary opens with, big-endian on disk (`FAT_MAGIC`,
/// `FAT_MAGIC_64`). A Java class file opens with `0xcafebabe` too, so the magic alone does
/// not identify the format: [`is_mach_o`] reads the architecture count after it.
const MACH_O_FAT_MAGICS: [[u8; 4]; 2] = [[0xca, 0xfe, 0xba, 0xbe], [0xca, 0xfe, 0xba, 0xbf]];

/// The most architectures a universal header is read as carrying. Apple's toolchains write
/// two or three; a class file holds its version where the count would be, 45 and up.
const MAX_FAT_ARCHS: u32 = 20;

/// The reader's sentence for a Mach-O object ([`ElfError::MachO`]'s `Display`, after the
/// path), which a report's `unreadable` entry carries beside `mach_o` and which
/// `report::refusal_on_read` holds the two to.
pub const MACH_O_REFUSAL: &str = "not an ELF file: a Mach-O object";

/// Whether `ident`, a file's first 16 bytes, opens a Mach-O object: a thin magic, or a
/// universal magic followed by a big-endian architecture count from 1 to [`MAX_FAT_ARCHS`].
fn is_mach_o(ident: &[u8]) -> bool {
    let Some(magic) = ident.get(..4) else {
        return false;
    };
    if MACH_O_THIN_MAGICS.iter().any(|m| magic == m.as_slice()) {
        return true;
    }
    let Some(&[a, b, c, d]) = ident.get(4..8) else {
        return false;
    };
    let count = [a, b, c, d];
    MACH_O_FAT_MAGICS.iter().any(|m| magic == m.as_slice())
        && (1..=MAX_FAT_ARCHS).contains(&u32::from_be_bytes(count))
}

/// The identification: is this an ELF object, and in which class and byte order.
///
/// Returns `(elf64, little)`. Everything refused here is [`ElfError::NotElf`], since a file
/// with no magic, too short to carry one, or in a class or encoding this reader has no
/// layout for is the same statement to the caller: this is not an object it can read. The
/// one exception is a file of at least an identification's length that opens a Mach-O
/// object ([`is_mach_o`]), refused as [`ElfError::MachO`], since the self-report gate reads
/// that format's refusal differently on a macOS run.
fn identify(data: &[u8]) -> Result<(bool, bool), ElfError> {
    let not_elf = |why: String| ElfError::NotElf { path: None, why };
    let ident = data
        .get(..16)
        .ok_or_else(|| not_elf("file too short to be ELF".to_owned()))?;
    if ident.get(..4) != Some(b"\x7fELF") {
        if is_mach_o(ident) {
            return Err(ElfError::MachO { path: None });
        }
        return Err(not_elf("not an ELF file".to_owned()));
    }
    let elf64 = match ident.get(4) {
        Some(2) => true,
        Some(1) => false,
        other => return Err(not_elf(format!("unknown EI_CLASS {other:?}"))),
    };
    let little = match ident.get(5) {
        Some(1) => true,
        Some(2) => false,
        other => return Err(not_elf(format!("unknown EI_DATA {other:?}"))),
    };
    Ok((elf64, little))
}

/// The program-header table: `count` records of `entsize` bytes from `off`.
///
/// A record the file does not hold ends the read with an error, so a header that
/// declares more than the file carries is refused at the header: the reads are what
/// bound a declared count the file cannot satisfy.
fn read_phdrs(
    cur: &Cursor<'_>,
    elf64: bool,
    off: u64,
    count: u64,
    entsize: u64,
) -> Result<Vec<Phdr>, ElfError> {
    let mut phdrs = Vec::new();
    for i in 0..count {
        let base = off
            .checked_add(
                i.checked_mul(entsize)
                    .ok_or_else(|| ElfError::malformed("phdr index overflow"))?,
            )
            .ok_or_else(|| ElfError::malformed("phdr offset overflow"))?;
        let ph = if elf64 {
            Phdr {
                p_type: cur.u32_at(base)?,
                p_flags: cur.u32_at(base.saturating_add(4))?,
                p_offset: cur.u64_at(base.saturating_add(8))?,
                p_vaddr: cur.u64_at(base.saturating_add(16))?,
                p_filesz: cur.u64_at(base.saturating_add(32))?,
                p_memsz: cur.u64_at(base.saturating_add(40))?,
                p_align: cur.u64_at(base.saturating_add(48))?,
            }
        } else {
            Phdr {
                p_type: cur.u32_at(base)?,
                p_offset: u64::from(cur.u32_at(base.saturating_add(4))?),
                p_vaddr: u64::from(cur.u32_at(base.saturating_add(8))?),
                p_filesz: u64::from(cur.u32_at(base.saturating_add(16))?),
                p_memsz: u64::from(cur.u32_at(base.saturating_add(20))?),
                p_flags: cur.u32_at(base.saturating_add(24))?,
                p_align: u64::from(cur.u32_at(base.saturating_add(28))?),
            }
        };
        phdrs.push(ph);
    }
    Ok(phdrs)
}

/// One section header at `base`, in either width.
fn read_shdr(cur: &Cursor<'_>, elf64: bool, base: u64) -> Read<Shdr> {
    let (flags_at, addr_at, off_at, size_at, link_at, info_at, align_at, entsize_at) = if elf64 {
        (8, 16, 24, 32, 40, 44, 48, 56)
    } else {
        (8, 12, 16, 20, 24, 28, 32, 36)
    };
    Ok(Shdr {
        sh_name: cur.u32_at(base)?,
        sh_type: cur.u32_at(base.saturating_add(4))?,
        sh_flags: cur.addr_at(base.saturating_add(flags_at), elf64)?,
        sh_addr: cur.addr_at(base.saturating_add(addr_at), elf64)?,
        sh_offset: cur.addr_at(base.saturating_add(off_at), elf64)?,
        sh_size: cur.addr_at(base.saturating_add(size_at), elf64)?,
        sh_link: cur.u32_at(base.saturating_add(link_at))?,
        sh_info: cur.u32_at(base.saturating_add(info_at))?,
        sh_addralign: cur.addr_at(base.saturating_add(align_at), elf64)?,
        sh_entsize: cur.addr_at(base.saturating_add(entsize_at), elf64)?,
    })
}

/// `shdr[0]`, read for a header escape, or `None` where the count escape names a record
/// the file does not hold.
///
/// A nonzero `e_shoff` that names bytes past the end of the file is a file cut before
/// its section-header table, or one whose header was edited, with `e_shnum` at 0 either
/// way. GNU readelf probes `shdr[0]` for the escapes and, when the probe fails, applies
/// none of them, so it reads the file as having no section-header table and goes on
/// through the program headers. A reader that refused the file would leave
/// `tests/elf_readelf.rs` reporting it unreadable by one side, so this one follows readelf
/// for the count escape, and says so in `truncations` under the `section-header table:` prefix. The
/// other two escapes cannot be tolerated the same way: a declared `e_shnum` above 0 at
/// that offset is a table the file does not hold, and `PN_XNUM` with no `shdr[0]` is a
/// program-header count of 65535 the file does not hold either, so both stay errors, as
/// they are in readelf. A stride below the record size is refused before the probe, on
/// `parse`'s pre-escape check; that is the one place this reader is stricter than the
/// probe.
fn probe_shdr0(
    cur: &Cursor<'_>,
    elf64: bool,
    e_shoff: u64,
    uses_shnum_escape: bool,
    truncations: &mut Vec<Truncation>,
) -> Result<Option<Shdr>, ElfError> {
    match read_shdr(cur, elf64, e_shoff) {
        Ok(first) => Ok(Some(first)),
        Err(e) if uses_shnum_escape => {
            // `SectionHeaders`, because this entry is the cause: the header's escape
            // names a record the file does not hold, and the reader goes on as if there
            // were no section-header table. The effects are `structural_truncations`'
            // entries, `symbols` and `section-names`, which a file with no table at all
            // carries too. Typing the cause as `symbols` as well made one condition two
            // `symbols` entries, a count no reader could use. No check declares
            // `section-headers`, so the cause withholds nothing on its own. (2026-09-30:
            // `ret-protector-emitted` declares it, beside the `section-names` it also
            // declares and this escape also records.)
            truncations.push(Truncation::unread(
                ElfTable::SectionHeaders,
                format!(
                    "section-header table: e_shnum is 0 and e_shoff {e_shoff:#x} names a \
                     shdr[0] the file does not hold ({e}), so the count escape was not \
                     followed and the file is read as having no section-header table, as \
                     readelf reads it"
                ),
            ));
            Ok(None)
        }
        Err(e) => Err(ElfError::malformed(format!(
            "reading shdr[0] for a header escape: {e}"
        ))),
    }
}

/// Every section's name through the table `shstrndx` names, or empty names beside a
/// `section-names` truncation where that table cannot be read as one.
fn section_names(
    cur: &Cursor<'_>,
    shdrs: &[Shdr],
    shstrndx: u32,
    truncations: &mut Vec<Truncation>,
) -> Vec<String> {
    if shdrs.is_empty() {
        // No table at all is `structural_truncations`' case, and it says more there.
        return Vec::new();
    }
    let strtab = match section_name_table(shdrs, shstrndx) {
        Ok(strtab) => strtab,
        Err(why) => {
            truncations.push(Truncation::unread(
                ElfTable::SectionNames,
                format!("section names: {why}"),
            ));
            return vec![String::new(); shdrs.len()];
        }
    };
    // The table's bytes are held before a name is read from them. `cstr_at` answers ""
    // for an offset past the end of the file, and a name table the file does not hold
    // read every section as unnamed and recorded nothing.
    let base = strtab.sh_offset;
    let len = strtab.sh_size;
    if let Err(why) = cur.slice(base, len) {
        truncations.push(Truncation::unread(
            ElfTable::SectionNames,
            format!(
                "section names: the table at {base:#x}+{len:#x} lies past the end of the file \
                 ({why}), so no section can be found by name"
            ),
        ));
        return vec![String::new(); shdrs.len()];
    }
    // Bounded by the table's own `sh_size`, which `cstr_at` requires of every caller: a
    // name that runs past the table's declared end is cut at that end, whatever section
    // follows.
    shdrs
        .iter()
        .map(|sh| cur.cstr_at(base, sh.sh_name, len))
        .collect()
}

/// The section-name table, or why there is none to read.
///
/// Three refusals, each a different file. `SHN_UNDEF` is a file that declares no
/// name table at all; an index past the table is a header that names a section the
/// table does not hold; a candidate of another type is a header pointing somewhere
/// names cannot be read from. Index 0 was the one that mattered: it is the null
/// header, whose `sh_offset` is 0, and reading names through it produced strings cut
/// out of the ELF header itself, which were then published in `sections` as though
/// the file had named them.
fn section_name_table(shdrs: &[Shdr], shstrndx: u32) -> std::result::Result<&Shdr, String> {
    if shstrndx == u32::from(SHN_UNDEF) {
        return Err(
            "e_shstrndx is SHN_UNDEF, so the file declares no section-name table \
                    and no section can be found by name"
                .to_owned(),
        );
    }
    let Some(candidate) = shdrs.get(usize::try_from(shstrndx).unwrap_or(usize::MAX)) else {
        return Err(format!(
            "e_shstrndx {shstrndx} is past the section-header table of {} entries, so no \
             section can be found by name",
            shdrs.len()
        ));
    };
    if candidate.sh_type != SHT_STRTAB {
        return Err(format!(
            "e_shstrndx {shstrndx} names a section of type {:#x}, and only an SHT_STRTAB \
             holds names, so no section can be found by name",
            candidate.sh_type
        ));
    }
    Ok(candidate)
}

/// The dynamic tags whose value is an offset into the dynamic string table.
const DYN_STRING_TAGS: [i64; 3] = [DT_NEEDED, DT_RPATH, DT_RUNPATH];

/// The spelling of a string-valued dynamic tag, for a `dynstr` record.
fn dyn_tag_name(tag: i64) -> &'static str {
    match tag {
        DT_NEEDED => "DT_NEEDED",
        DT_RPATH => "DT_RPATH",
        DT_RUNPATH => "DT_RUNPATH",
        _ => "dynamic",
    }
}

struct Note {
    name: String,
    ntype: u32,
    desc_off: u64,
    desc_len: u64,
}

/// A table of the ELF container, as the reader and the checks name it.
///
/// One vocabulary for two declarations: a [`Truncation`] says which table it cut, and
/// `probe::Check::reads` says which tables a check's observable is read from. The gate
/// in `report::truncation_limitation` is the intersection, so a table that appears in
/// neither list is unrepresentable.
///
/// Two of the tables have no recording site. The ELF header and the program-header table
/// are read in [`Elf::parse`], and a cut there is an `Err` from it: `measure::gather`
/// stores that as `elf_error`, and `report::Variant::sufficient_for` withholds every
/// elf-static check over the artifact as `indeterminate` before a detector runs. They are
/// in the enum so a check can still declare them, and [`Self::SOFT_SITES`] and
/// [`Self::HARD_FAILURES`] partition the enum so a declaration can never name a table
/// nothing records: `probe::tests::every_checks_tables_derive_from_its_decoder` holds
/// every declared table to one of the two lists.
///
/// Two `PT_GNU_STACK` headers that disagree on `PF_X` (`Elf::gnu_stack`) are recorded
/// against [`Self::GnuStack`], a table of its own that only the checks reading the stack
/// header declare, so the program-header table keeps no recording site and the two lists
/// partition the enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ElfTable {
    /// The ELF header: class, type, machine.
    Header,
    /// The program headers: `PT_INTERP`, `PT_GNU_STACK`, `PT_GNU_RELRO`,
    /// `PT_OPENBSD_NOBTCFI`.
    ProgramHeaders,
    /// The `PT_GNU_STACK` headers among the program headers, recorded `unread` where two
    /// disagree on `PF_X` (`Elf::gnu_stack`).
    ///
    /// A finer unit than [`Self::ProgramHeaders`], whose cut it cannot stand for: the
    /// header table read whole, and one segment type in it contradicts itself. Recorded
    /// against the whole table, the disagreement withheld every check declaring it, `pie`,
    /// `relro` and `textrel-absent` among them, which read `PT_INTERP`, `PT_GNU_RELRO` and
    /// the dynamic section and not the stack header. A check reading the stack header
    /// declares both tables, so a program-header table [`Elf::parse`] refuses withholds it
    /// as it withholds every other, and the pair withholds it alone.
    GnuStack,
    /// The section-header table itself, recorded when a header escape names a `shdr[0]`
    /// the file does not hold. Its effects are recorded against the tables it cuts off. A
    /// check whose predicate reads section headers declares it (`ret-protector-emitted`
    /// beside `SectionNames`, because its predicate reads `sections`, which both tables
    /// feed). The escape records `section-names` too, so the declaration withholds nothing
    /// the other does not.
    SectionHeaders,
    /// The section-name string table, which everything reached by name goes through, and
    /// the named sections read as text (`.chard.report`, `.GCC.command.line`) when one is
    /// listed and not held.
    SectionNames,
    /// `.dynamic`, by section or by `PT_DYNAMIC`.
    Dynamic,
    /// The dynamic string table: `DT_NEEDED`, `DT_RPATH` and `DT_RUNPATH` strings.
    /// Spelt `dynstr` in the report, as the section is; the container's kebab-case would
    /// hyphenate it, and `as_str` is held to the serialized form by a test.
    #[serde(rename = "dynstr")]
    DynStr,
    /// `.symtab` and `.dynsym`, with the string tables their `sh_link` names.
    Symbols,
    /// The GNU notes, by `PT_GNU_PROPERTY` segment, by `PT_NOTE` segment where there is
    /// none, or by `SHT_NOTE` section where the file has no program headers.
    Notes,
    /// `.comment`, the section every producer of a linked object appends its line to;
    /// read by `toolchain::artifact_agreement` and declared by no check.
    Comment,
    /// The code bytes of a function [`code::SCANS`] names, which `code` reads
    /// through `.symtab` and a section header; recorded when a listed function is defined
    /// and its bytes could not be read whole, or when the symbol walk stopped before it.
    Code,
    /// The first bytes of a function [`entry::ENTRY_FUNCTIONS`] names, which `entry` reads
    /// through `.symtab` and a section header; recorded when a listed function is defined
    /// and its bytes could not be read, or when the symbol walk stopped before it.
    FunctionEntries,
    /// The `SHT_RELA` and `SHT_REL` sections of a relocatable object that patch code, with
    /// the symbol tables their `sh_link` names: [`ElfFacts::code_relocations`], and
    /// [`ElfFacts::function_references`], whose walk also reads a target holding
    /// a function symbol (a compiler places one only in code) and records a section in an
    /// encoding it does not decode (`SHT_CREL`, or another type carrying `SHF_INFO_LINK`).
    /// Neither walk records a section that patches data, so a cut in debug information or
    /// `.eh_frame` withholds no check that declares this table.
    Relocations,
}

impl ElfTable {
    /// Every table, in declaration order.
    pub const ALL: [Self; 13] = [
        Self::Header,
        Self::ProgramHeaders,
        Self::GnuStack,
        Self::SectionHeaders,
        Self::SectionNames,
        Self::Dynamic,
        Self::DynStr,
        Self::Symbols,
        Self::Notes,
        Self::Comment,
        Self::Code,
        Self::FunctionEntries,
        Self::Relocations,
    ];

    /// The tables with a recording site: a walk that can stop short and pushes a
    /// [`Truncation`] when it does. `GnuStack` is the one entry that stops nothing
    /// short: its site is a self-contradiction, two `PT_GNU_STACK` headers that disagree.
    pub const SOFT_SITES: [Self; 11] = [
        Self::GnuStack,
        Self::SectionHeaders,
        Self::SectionNames,
        Self::Dynamic,
        Self::DynStr,
        Self::Symbols,
        Self::Notes,
        Self::Comment,
        Self::Code,
        Self::FunctionEntries,
        Self::Relocations,
    ];

    /// The tables whose cut is an error from [`Elf::parse`]. Neither is on
    /// [`Self::SOFT_SITES`]; the disagreement `ProgramHeaders` recorded for part of
    /// 2026-10-05 is [`Self::GnuStack`]'s.
    pub const HARD_FAILURES: [Self; 2] = [Self::Header, Self::ProgramHeaders];

    /// The kebab-case spelling the report carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::ProgramHeaders => "program-headers",
            Self::GnuStack => "gnu-stack",
            Self::SectionHeaders => "section-headers",
            Self::SectionNames => "section-names",
            Self::Dynamic => "dynamic",
            Self::DynStr => "dynstr",
            Self::Symbols => "symbols",
            Self::Notes => "notes",
            Self::Comment => "comment",
            Self::Code => "code",
            Self::FunctionEntries => "function-entries",
            Self::Relocations => "relocations",
        }
    }
}

/// What a truncation did to the table's facts.
///
/// `measure::unread_table_faults` publishes each kind at its own severity: an `Unread`
/// table is an `error` diagnostic at the probe, since a reading was withheld, and an
/// `Ignored` entry is a `warning`, since the facts are whole and the finding is about the
/// artifact declaring something the reader did not follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TruncationKind {
    /// The table's facts are absent because they could not be read, so a detector reading
    /// them as absent is reading nothing.
    Unread,
    /// A declaration about the table that disagreed with the loader's view or with the ABI
    /// (a header aimed elsewhere, a second view of one table, an entry size that is not the
    /// record's) was not followed, and the loader's or the ABI's reading was measured; the
    /// facts are whole.
    Ignored,
}

impl TruncationKind {
    /// Both kinds, in declaration order; what the schema's `kind` enum is pinned to.
    pub const ALL: [Self; 2] = [Self::Unread, Self::Ignored];

    /// The kebab-case spelling the report carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unread => "unread",
            Self::Ignored => "ignored",
        }
    }
}

/// A table the reader could not finish, and what that did to the facts.
///
/// `detail` is the site's own sentence, with the offset or index it stopped at, and is
/// what a diagnostic and a gating reason quote. `table` and `kind` are what code reads:
/// the gate never matches prose. The type carries no `Display`: the two sentences that
/// publish an entry, `report::truncated_reading` and `measure::unread_table_faults`, each
/// compose `table.as_str()` and `detail` into their own wording, and a third form nothing
/// printed would drift from both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Truncation {
    pub table: ElfTable,
    pub kind: TruncationKind,
    pub detail: String,
}

impl Truncation {
    fn unread(table: ElfTable, detail: String) -> Self {
        Self {
            table,
            kind: TruncationKind::Unread,
            detail,
        }
    }

    fn ignored(table: ElfTable, detail: String) -> Self {
        Self {
            table,
            kind: TruncationKind::Ignored,
            detail,
        }
    }
}

/// The tags whose value one loader field holds, so a second entry is a second answer to a
/// question the loader asks once.
///
/// `ld.so` and musl store `info[tag]` in a loop that stops at `DT_NULL`, so the last entry of
/// a repeated tag answers. Measured 2026-10-09 on Fedora 44 x86_64 (glibc 2.43, musl): a PIE
/// whose `DT_DEBUG` slot was relabelled `DT_INIT` ran the later `DT_INIT` under both, in both
/// value orders, and a relabelled `DT_FLAGS_1` of `DF_1_NOW` ahead of the real `DF_1_PIE`
/// left `puts` bound after `ld.so` transferred control (lazy), where the same flag last bound
/// it before (now). An entry behind `DT_NULL` (a relabelled `DT_INIT`) was ignored by both. `DT_NEEDED` is absent
/// because it legitimately repeats. `DT_RPATH` and `DT_RUNPATH` are here: the loader keeps
/// the last of each, so `rpath` and `runpath` list the last and the repeat is recorded
/// (`dyn_strings`). No linker writes a repeat of any of these, so a repeat is a
/// file nothing ordinary produced, and a loader family not run here may differ: the value
/// read is the last, and the repeat is recorded `unread`. `DT_SYMTAB`, `DT_HASH` and
/// `DT_GNU_HASH` are here because `dynsym_view` reads the dynamic symbol table through
/// them; the loaders' last-entry rule was measured on `DT_INIT` and `DT_FLAGS_1`, and these
/// are taken to share it because the same loop stores every tag. The relocation tags are
/// here on the same footing: `dynsym_view` reads the relocation tables for the floor they
/// put under the symbol count.
const LOADER_SINGLE_TAGS: [(i64, &str); 19] = [
    (DT_PLTRELSZ, "DT_PLTRELSZ"),
    (DT_HASH, "DT_HASH"),
    (DT_STRTAB, "DT_STRTAB"),
    (DT_SYMTAB, "DT_SYMTAB"),
    (DT_RELA, "DT_RELA"),
    (DT_RELASZ, "DT_RELASZ"),
    (DT_RELAENT, "DT_RELAENT"),
    (DT_STRSZ, "DT_STRSZ"),
    (DT_SONAME, "DT_SONAME"),
    (DT_RPATH, "DT_RPATH"),
    (DT_REL, "DT_REL"),
    (DT_RELSZ, "DT_RELSZ"),
    (DT_RELENT, "DT_RELENT"),
    (DT_PLTREL, "DT_PLTREL"),
    (DT_JMPREL, "DT_JMPREL"),
    (DT_RUNPATH, "DT_RUNPATH"),
    (DT_FLAGS, "DT_FLAGS"),
    (DT_FLAGS_1, "DT_FLAGS_1"),
    (DT_GNU_HASH, "DT_GNU_HASH"),
];

/// How the dynamic symbol table is reached, from the dynamic table and the program headers.
///
/// See `Elf::dynsym_view`. The variants are the answers to "what does the loader read here",
/// and each decides what the `SHT_DYNSYM` headers are held to.
enum DynSymView {
    /// No loader view: no `PT_DYNAMIC`, no section headers, or a dynamic table that could
    /// not be read. The headers are the reading.
    Sections,
    /// A `PT_DYNAMIC` that names no `DT_SYMTAB`: the loader has no dynamic symbols.
    Absent,
    /// `DT_SYMTAB`, a hash table or a relocation table could not be read; recorded
    /// `unread`.
    Unreadable,
    /// The loader's table starts at `offset`. `floor` is the symbol count the hash and
    /// relocation tables reach, a lower bound on the table's length, and `strtab` is
    /// `DT_STRTAB`'s table.
    At {
        offset: u64,
        floor: u64,
        strtab: Option<(u64, u64)>,
    },
}

/// Record one `unread` truncation per tag of [`LOADER_SINGLE_TAGS`] that `entries` repeats.
fn repeated_loader_tags(entries: &[(i64, u64)], trunc: &mut Vec<Truncation>) {
    for (tag, name) in LOADER_SINGLE_TAGS {
        let n = entries.iter().filter(|(t, _)| *t == tag).count();
        if n > 1 {
            trunc.push(Truncation::unread(
                ElfTable::Dynamic,
                format!(
                    "{name} appears {n} times in .dynamic; the loader keeps the last, which \
                     is the one measured, and a loader not run for this was not established \
                     to agree"
                ),
            ));
        }
    }
}

/// How the loader would treat a linked object, from `e_type`, `PT_INTERP`, `.dynamic`,
/// `DF_1_PIE` and `DT_DEBUG`.
///
/// One value, flattened by `LinkKind::flatten` into the four booleans the report carries, so
/// the pairs that cannot both hold are unrepresentable: a shared object that is statically
/// linked, a static PIE that is not. `None` from `link_kind` is an object the loader
/// cannot run at all, and every fact derived here is `None` with it: a relocatable
/// object has no program headers, so "no `PT_GNU_STACK`", "no `PT_GNU_RELRO`" and
/// "statically linked" were true of every `.o` for the wrong reason, and `relro: "none"`
/// on a `.o` was the falsy default this project refuses arriving by another route.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LinkKind {
    /// `PT_INTERP` names a loader. `pie` is whether the object is `ET_DYN`, which with an
    /// interpreter is a position-independent executable.
    Dynamic { pie: bool },
    /// `ET_DYN` with no interpreter, marked as executable output by `DF_1_PIE`, by
    /// `DT_DEBUG`, or by both; the payload says which, and `link_kind` builds the variant
    /// only when at least one holds. It still carries `.dynamic`, since it relocates
    /// itself, which is why "no interpreter and no dynamic section" was the wrong reading
    /// of "statically linked": it made a static PIE not statically linked.
    ///
    /// `DT_DEBUG` is the third discriminator because `DF_1_PIE` alone left a gap: lld
    /// 10.0.0 did not set the flag on a static PIE, so that object read as a shared object
    /// and `pie` read `off`. Measured 2026-09-28 on Fedora 44 x86_64 (`chard-f44-linkers`:
    /// GNU ld and gold 2.46.1, lld 22.1.8, mold 2.40.4) and in an Ubuntu 20.04 container
    /// with lld 10.0.0: every executable output that linked carried `DT_DEBUG`, and no
    /// shared object did. On Fedora the four linkers each linked a dynamic PIE and a
    /// non-PIE executable, and GNU ld, lld and mold a static PIE; gold did not link one.
    /// lld 10.0.0 was measured on a static PIE and a dynamic PIE, and not on a non-PIE
    /// executable. The shared objects were linked plain under all five, and with
    /// `-soname` or with `-e` giving them a non-zero entry point under the four on Fedora.
    /// The lld 10 static PIE is `ET_DYN` with no
    /// interpreter, `DT_DEBUG` and no `DT_FLAGS_1` at all, which is the case this closes.
    /// That object, linked by clang 10 with `-static-pie` from `int main(){return 0;}`,
    /// segfaults at startup in the Ubuntu 20.04 container and on Fedora 44 x86_64 although
    /// it carries glibc's `_dl_relocate_static_pie`; the cause is not established, so it
    /// shows the tags lld 10.0.0 writes on that link and not a working static PIE. The
    /// rule rests on the tag shape, and the assumption it needs is registered as
    /// `dt-debug-marks-only-executable-output` in `report::ASSUMPTIONS`.
    /// The replay corpus agrees: none of its 98 shared objects, from gcc 8.5 through 16
    /// and clang 10 through 23, carries the tag.
    ///
    /// `DT_SONAME` does not veto it. A `-soname` given to an executable link is written
    /// all the same, so the tag names a file and says nothing about how the loader treats
    /// it; `DT_DEBUG` beside `DT_SONAME` is executable output. Measured the same day:
    /// `-Wl,-soname` on a static PIE linked by GNU ld 2.46.1, lld 22.1.8 and mold 2.40.4,
    /// and on a dynamic PIE and a non-PIE executable linked by GNU ld 2.46.1 under gcc
    /// 16.1.1, left both tags in every output, and each static PIE ran. lld 10.0.0 under
    /// clang 10 wrote the same pair with no `DT_FLAGS_1`, so there `DT_DEBUG` is the only
    /// marker and `DT_SONAME` the only reason to doubt it. The pair is pinned on bytes in
    /// `debug_marks_executable_output_whatever_the_soname`.
    ///
    /// What stays open is an interpreter-less `ET_DYN` carrying neither marker, which
    /// reads as a shared object, and a static PIE is written so: lld 10.0.0 under clang 10
    /// `-static-pie -Wl,-z,rodynamic` (Ubuntu 20.04 x86_64, 2026-10-26) wrote no `DT_DEBUG`
    /// and no `DT_FLAGS_1`. The tags cannot tell it from a shared object with no
    /// `DT_NEEDED`, so the case is settled where chard knows what it asked for:
    /// `report::link_mode_limitation` withholds a reading of the classification over an
    /// executable link's artifact that classifies as a shared object.
    StaticPie { df_1_pie: bool, dt_debug: bool },
    /// `ET_DYN` with `.dynamic`, no interpreter, and neither `DF_1_PIE` nor `DT_DEBUG`. A
    /// static PIE written without either marker carries the same tags and reads as this;
    /// over an executable link's artifact the reading is withheld by
    /// `report::link_mode_limitation`.
    SharedObject,
    /// Neither an interpreter nor a shared object: an `ET_EXEC` the kernel maps and runs
    /// with no loader, or an `ET_DYN` with no dynamic section, which nothing could load.
    Static,
}

impl LinkKind {
    /// `(pie, static_pie, shared_object, statically_linked)`, the four booleans the report
    /// carries for this kind. One row per variant, so no pair a variant rules out can be
    /// written.
    fn flatten(self) -> (bool, bool, bool, bool) {
        match self {
            Self::Dynamic { pie } => (pie, false, false, false),
            Self::StaticPie { .. } => (true, true, false, true),
            Self::SharedObject => (false, false, true, false),
            Self::Static => (false, false, false, true),
        }
    }
}

/// The classification for `e_type`, or `None` for a type the loader cannot run, from the
/// tags `.dynamic` carries and the `DT_FLAGS_1` word among them.
fn link_kind(e_type: u16, has_interp: bool, tags: &BTreeSet<i64>, flags1: u64) -> Option<LinkKind> {
    let pie_capable = match e_type {
        ET_DYN => true,
        ET_EXEC => false,
        _ => return None,
    };
    let has_dynamic = !tags.is_empty();
    let df_1_pie = flags1 & DF_1_PIE != 0;
    let dt_debug = tags.contains(&DT_DEBUG);
    Some(if has_interp {
        LinkKind::Dynamic { pie: pie_capable }
    } else if pie_capable && (df_1_pie || dt_debug) {
        LinkKind::StaticPie { df_1_pie, dt_debug }
    } else if pie_capable && has_dynamic {
        LinkKind::SharedObject
    } else {
        LinkKind::Static
    })
}

/// `e_type` as the facts spell it. An unrecognised type says so: `ET_1` read as a decoded
/// name for a value nobody had named, and a classifier that compared it against `"ET_REL"`
/// could never match.
fn type_name(e_type: u16) -> String {
    match e_type {
        ET_NONE => "ET_NONE".to_owned(),
        ET_REL => "ET_REL".to_owned(),
        ET_EXEC => "ET_EXEC".to_owned(),
        ET_DYN => "ET_DYN".to_owned(),
        ET_CORE => "ET_CORE".to_owned(),
        other @ ET_LOOS..=ET_HIOS => format!("unrecognised (OS-specific e_type {other:#x})"),
        other @ ET_LOPROC..=ET_HIPROC => {
            format!("unrecognised (processor-specific e_type {other:#x})")
        }
        other => format!("unrecognised (e_type {other:#x})"),
    }
}

/// The `machine` fact for `e_machine`: the family's short name, or unrecognised.
///
/// The names are the families', lowercase, with width and byte order left to
/// `elf_class` and the file's own `EI_DATA`: `ppc64` covers a ppc64le object and `s390`
/// an s390x one, since `EM_PPC64` and `EM_S390` are the values both carry. A value
/// outside the list says so, with the number, the way `elf_type` does. Before this the
/// fallback was `EM_<n>`, which read as a decoded name for a value nobody had named, and
/// the ELF32 big-endian fixture recorded `PowerPC` as `EM_20`.
fn machine_name(e_machine: u16) -> String {
    match e_machine {
        EM_386 => "i386".to_owned(),
        EM_MIPS => "mips".to_owned(),
        EM_PPC => "ppc".to_owned(),
        EM_PPC64 => "ppc64".to_owned(),
        EM_S390 => "s390".to_owned(),
        EM_ARM => "arm".to_owned(),
        EM_X86_64 => "x86_64".to_owned(),
        EM_AARCH64 => "aarch64".to_owned(),
        EM_RISCV => "riscv".to_owned(),
        EM_LOONGARCH => "loongarch".to_owned(),
        other => format!("unrecognised (e_machine {other:#x})"),
    }
}

/// A symbol's visibility, `st_other & 3`, as `readelf -s` spells it after `STV_`, or
/// `None` for `STV_DEFAULT`: [`ElfFacts::code_relocations`] appends it to an entry whose
/// symbol is not default, and leaves a default one as `TYPE SYMBOL`.
const fn visibility_label(visibility: u8) -> Option<&'static str> {
    match visibility {
        1 => Some("STV_INTERNAL"),
        2 => Some("STV_HIDDEN"),
        3 => Some("STV_PROTECTED"),
        _ => None,
    }
}

/// A relocation type as `readelf -r` names it on `e_machine`, or `reloc-type-` and the
/// number in hex where `elf/reloc_names.rs` has no row for the pair.
pub(crate) fn reloc_type_name(e_machine: u16, kind: u32) -> String {
    let table: &[(u32, &str)] = match e_machine {
        EM_X86_64 => reloc_names::X86_64,
        EM_386 => reloc_names::I386,
        EM_AARCH64 => reloc_names::AARCH64,
        EM_RISCV => reloc_names::RISCV,
        _ => &[],
    };
    table.iter().find(|(n, _)| *n == kind).map_or_else(
        || format!("reloc-type-{kind:#x}"),
        |(_, name)| (*name).to_owned(),
    )
}

/// `PT_GNU_RELRO` with `BIND_NOW`: the whole relocated region is read-only before the
/// program runs.
pub const RELRO_FULL: &str = "full";
/// `PT_GNU_RELRO` without `BIND_NOW`: the region is made read-only after lazy binding
/// has written into it.
pub const RELRO_PARTIAL: &str = "partial";
/// No `PT_GNU_RELRO` segment.
pub const RELRO_NONE: &str = "none";

/// Every value `ElfFacts::relro` carries on an object the loader can run, strongest first.
///
/// The fourth state in the report is `null`: `LinkKind` withholds every link fact on an
/// object the loader cannot run, so `null` describes the object the way the three levels
/// do.
///
/// `schema/chard-report.schema.json` declares this list beside `null` under
/// `$defs/elf_facts`, and `tests/schema_conformance.rs` compares the two, so a level
/// added here without the schema fails on every host.
pub const RELRO_LEVELS: &[&str] = &[RELRO_FULL, RELRO_PARTIAL, RELRO_NONE];

/// A link-classification fact as an `observed` string reads it: `true`, `false`, or
/// `unclassified` for an object the loader cannot run.
pub fn classification(fact: Option<bool>) -> &'static str {
    match fact {
        Some(true) => "true",
        Some(false) => "false",
        None => "unclassified",
    }
}

/// Deserialize an `Option` field that must be present, as `null` or a value.
///
/// serde reads a missing `Option` field as `None`. For the link classification that would
/// make a recording written before the field existed indistinguishable from one that
/// measured "this object carries no classification", and the fixtures in `probe` and
/// `measure` are deserialized precisely so that a missing field fails loudly. With
/// `deserialize_with` and no `default`, it does.
fn required<'de, D, T>(d: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

/// One GNU property type as seen across every property note in the object.
///
/// The linker's rule for a `*_FEATURE_1_AND` word is AND across its inputs, and the
/// output carries the merged word in one note, so a second note of one type is a file no
/// linker wrote. `ElfFacts::gnu_property_notes` says what the count means, and what it
/// does and does not claim about a loader.
struct Property {
    /// Under a feature-word type on this machine, the AND of every note's word, the
    /// linker's rule applied once more; under any other type, the first word seen.
    value: u32,
    /// How many notes carried the type. One is what a linker produces.
    notes: u32,
}

/// One symbol-table entry, reduced to what probes ask about.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymbolFact {
    /// `false` means the symbol is `SHN_UNDEF` — a reference satisfied at load
    /// time. A canary-protected binary *references* `__stack_chk_fail`; one that
    /// statically links libssp *defines* it. Probes need to tell those apart.
    pub defined: bool,
    /// Which tables it appeared in (`.symtab`, `.dynsym`); a stripped binary has
    /// only `.dynsym`, so an absent symbol there is weaker evidence.
    pub tables: Vec<String>,
    /// The spellings that carried a version, as the table stored them:
    /// `__stack_chk_fail@GLIBC_2.4`, or `name@@VERSION` for a default version. The map
    /// key is the name before the first `@`; this keeps what was cut. Empty for a symbol
    /// every table stored bare.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versioned: Vec<String>,
}

/// Everything the `elf-static` channel extracts from one artifact. Serialized
/// verbatim into the report's `facts` store as an `elf` entry keyed by the artifact's
/// digest (`observation.evidence.elf` in the older shape), whose contract is
/// `$defs/elf_facts` in
/// `schema/chard-report.schema.json`: every field here is declared there, the fields
/// with `skip_serializing_if` as optional and the rest as required, and
/// `tests/schema_conformance.rs` holds the two together over the checked-in fixture
/// corpora on every host, since a Darwin host produces no ELF artifact to validate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElfFacts {
    pub elf_class: u8,
    /// `EI_DATA`, the byte order every field of the file was read in. `machine` names the
    /// family without it (`ppc64` covers a `ppc64le` object, `aarch64` an `aarch64_be` one), so
    /// this is what tells them apart, and with `elf_class` it is what the target witness
    /// holds the artifacts to (`toolchain::TargetArch::abi`) and what `env::runs_natively`
    /// holds to the kernel's own order. A live read always writes it (`Elf::facts` is the
    /// one constructor); `None` only in a record without the field, which the
    /// replay corpus holds (the `elf` blocks of `tests/fixtures/detectors.json` predate
    /// it), read back by `#[serde(default)]` as `openbsd_nobtcfi` is. Such a record the
    /// target witness leaves out of `toolchain.target.abi.artifacts`, counting it in the
    /// `no-witness` evidence where no artifact of the family carried an order (beside
    /// recorded ones it is left out silently), and the execution witness withholds on,
    /// since an order it cannot read it cannot hold to the kernel's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elf_data: Option<ByteOrder>,
    pub elf_type: String,
    pub machine: String,
    pub has_interp: bool,
    pub has_dynamic: bool,

    /// `ET_DYN` alone cannot distinguish a PIE from a shared library, so this is
    /// `ET_DYN` plus one of the linker-recorded `DF_1_PIE`, a `PT_INTERP`, or `DT_DEBUG`,
    /// the linker's mark of executable output that `LinkKind::StaticPie` explains.
    ///
    /// This and the eight fields after it are the link classification, derived from
    /// `LinkKind` and carried only for an object the loader can run (`ET_EXEC`,
    /// `ET_DYN`). For anything else they are `null` in the report, and a consumer reads
    /// `None` as an artifact that cannot carry the observable: a relocatable object has
    /// no loader to be position-independent for, and no segment for RELRO to cover. A
    /// detector that reads one of these returns no reading on `None`, and `measure`
    /// withholds the observation as `indeterminate`, or as `not-applicable` where
    /// `report::artifact_limitation` finds the check's precondition on the artifact
    /// failed.
    #[serde(deserialize_with = "required")]
    pub pie: Option<bool>,
    pub df_1_pie: bool,
    /// `ET_DYN` with no interpreter, marked as executable output by `DF_1_PIE` or
    /// `DT_DEBUG`. Requires a marker: without one, an interpreter-less `ET_DYN` is an
    /// ordinary shared library, and reporting every `.so` as a static PIE would corrupt
    /// the `pie` column for any probe that links one. `DT_SONAME` does not veto the
    /// marker; `LinkKind::StaticPie` records why, and the measurements behind both.
    #[serde(deserialize_with = "required")]
    pub static_pie: Option<bool>,
    /// `ET_DYN` with a dynamic section, no interpreter, and neither `DF_1_PIE` nor
    /// `DT_DEBUG`.
    #[serde(deserialize_with = "required")]
    pub shared_object: Option<bool>,
    /// No loader runs it: an `ET_EXEC` with no interpreter, a static PIE, or an `ET_DYN`
    /// with neither an interpreter nor a dynamic section, which nothing could load. A
    /// static PIE counts, although it carries `.dynamic`, because it relocates itself.
    #[serde(deserialize_with = "required")]
    pub statically_linked: Option<bool>,

    #[serde(deserialize_with = "required")]
    pub relro: Option<String>,
    #[serde(deserialize_with = "required")]
    pub gnu_relro: Option<bool>,
    #[serde(deserialize_with = "required")]
    pub bind_now: Option<bool>,

    /// Absent `PT_GNU_STACK` is not the same as a non-executable stack: it
    /// defers to the kernel's default, so probes must not read "no header" as
    /// "noexecstack".
    #[serde(deserialize_with = "required")]
    pub gnu_stack_present: Option<bool>,
    /// `PF_X` on the last `PT_GNU_STACK`, the one the loader acts on; `Elf::gnu_stack`
    /// says why, and what is recorded where two disagree.
    #[serde(deserialize_with = "required")]
    pub gnu_stack_executable: Option<bool>,

    pub df_1_noopen: bool,
    pub textrel: bool,
    pub dt_relr: bool,
    /// A `DT_DEBUG` entry in `.dynamic`: the linker's mark of executable output, and the
    /// third discriminator `LinkKind::StaticPie` reads beside `DF_1_PIE` and `PT_INTERP`.
    /// A raw fact, `false` on an object with no dynamic section, as `df_1_pie` is.
    pub dt_debug: bool,
    /// A `DT_SONAME` entry in `.dynamic`. A raw fact the classification does not consult:
    /// it is carried so that a static PIE read through `DT_DEBUG` beside a `DT_SONAME` is
    /// auditable from the report, and `LinkKind::StaticPie` says why the name does not
    /// make the object a library.
    pub dt_soname: bool,
    /// Every `(tag, value)` pair in `.dynamic`, hex-formatted. Carried because a
    /// verdict that turns on a single dynamic flag bit should be auditable from
    /// the report alone, without re-running `readelf` against an artifact that
    /// may no longer exist.
    pub dynamic_tags: Vec<String>,
    pub needed: Vec<String>,
    pub rpath: Vec<String>,
    pub runpath: Vec<String>,

    /// Property *markings*. A marked binary is not necessarily an enforced one:
    /// IBT/SHSTK and BTI/PAC/GCS enforcement depends on CPU and kernel, and no check
    /// reads enforcement from these words. The kernel-dependent checks,
    /// `noexecstack-enforced` and `shadow-stack-enforced`, read what the kernel did when
    /// the probe ran, and declare `needs_vm`; `DESIGN.md` (Containers vs VMs) says where
    /// their readings belong to the distribution.
    ///
    /// Every property type found is listed, hex-formatted, whatever the machine. Only the
    /// feature words below are *decoded* from them, and only on the machine that defines
    /// the type: see `GNU_PROPERTY_AARCH64_FEATURE_1_AND` for what reading `0xc0000000`
    /// without the machine published.
    pub gnu_property_types: Vec<String>,
    /// How many `NT_GNU_PROPERTY_TYPE_0` notes carried each type in `gnu_property_types`.
    ///
    /// The linker merges its inputs' property notes into one note per output, and its
    /// rule for a `*_FEATURE_1_AND` word is AND: one input without the bit clears it for
    /// the whole object. So a linked object carries each type once, and a count of two
    /// is a file no linker wrote; the count is what exposes it, and what lets a reader
    /// tell "no property note" from "two notes". A feature word that arrived twice is
    /// the AND of both, the linker's rule applied once more. Before this the second note
    /// overwrote the first, so a `0` note behind an `IBT|SHSTK` note published CET off
    /// and the reverse order published it on.
    ///
    /// What a loader makes of a second note is its own rule, and this reader does not
    /// model it. As read in the source: glibc's `_dl_process_pt_gnu_property`
    /// (`elf/dl-load.c`) handles the first `NT_GNU_PROPERTY_TYPE_0` it finds in
    /// `PT_GNU_PROPERTY` and returns, and the kernel's `parse_elf_properties`
    /// (`fs/binfmt_elf.c`) reads the one note that segment begins with. On such a file
    /// the loader's word is the first note's, so an AND that clears a bit the first note
    /// carries reads a marking off that the loader would honour. That is the direction
    /// the count marks for a reader, on a file only a hand produces. The AND was measured
    /// to read `cet-marked` `absent` on such a file, and the case is the assumption
    /// `one-property-note-per-object` in `report::ASSUMPTIONS`; the loaders' rules were
    /// read, not run.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub gnu_property_notes: BTreeMap<String, u32>,
    pub x86_ibt: bool,
    pub x86_shstk: bool,
    pub aarch64_bti: bool,
    pub aarch64_pac: bool,
    /// The default is defensive rather than load-bearing. Every fixture in
    /// `tests/fixtures/detectors.json` that carries an `elf` block records this field
    /// explicitly, and it is always written by a live read, so neither a report nor a
    /// mined fixture carries a defaulted value. `#[serde(default)]` covers only a fixture
    /// without the field, and the tree contains none.
    ///
    /// That last sentence is the whole guarantee. It does not rest on every fixture being
    /// captured on x86_64, where the aarch64 feature word cannot be present at all: the
    /// corpus holds aarch64 recordings (they are what `gcs-marked` is tested against), and
    /// on those a defaulted `false` would be an unmeasured claim that the binary lacks GCS.
    /// What keeps that from happening is that the fixtures are mined
    /// from reports written by a build that has this field, not that they come from a
    /// machine where the answer is knowable in advance.
    #[serde(default)]
    pub aarch64_gcs: bool,
    /// A `PT_OPENBSD_NOBTCFI` program header (`0x65a3dbe8`, as OpenBSD 7.9 installs it in
    /// `/usr/include/llvm/BinaryFormat/ELF.h`; the kernel's flag is `EXEC_NOBTCFI`): the
    /// program's own request that OpenBSD not enforce branch-target CFI on it, BTI on
    /// arm64 and IBT on amd64. lld writes it under `-z nobtcfi`, OpenBSD's base linker and
    /// lld 22.1.8 on Linux alike, for any target. A raw fact, `false` on an object with no
    /// program headers.
    ///
    /// Not a marking, and the reverse of one: on OpenBSD enforcement does not wait for
    /// the property note this struct decodes above, and this header is what turns it off,
    /// per program rather than per mapping. `composite::cfi` reads it, and the measurement
    /// behind that reading is recorded there. GNU ld 2.46.1 ignores `-z nobtcfi` with a
    /// warning. lld 22.1.8 writes the header (clang 22.1.8 in a `fedora:44` container on
    /// Fedora 44 x86_64, 2026-10-01): for `aarch64-unknown-openbsd`,
    /// `x86_64-unknown-openbsd` and `aarch64-unknown-linux-gnu` linked `-nostdlib -static`,
    /// and for x86_64 Linux programs linked through clang and gcc with `-fuse-ld=lld`; the
    /// reader and readelf agreed on all six, and on the four links without it. So a Linux
    /// artifact carries it wherever lld linked it with the flag.
    ///
    /// Absent from the serialization when `false`, as `gnu_property_notes` is when empty,
    /// and `#[serde(default)]` to read it back. A recorded row without the field reads as
    /// `false`, and no detector reads it, so a member written on every artifact would be one the
    /// schema has to require and 3,501 recorded rows lack. The cost is that a report from
    /// before the field and one whose artifact carries no header read alike, which
    /// `run.harness_revision` tells apart; the one reader, `composite::cfi`, reads a live
    /// parse, where `false` is a measured absence.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub openbsd_nobtcfi: bool,

    pub sections: Vec<String>,
    /// The allocated sections that are not code and whose bytes lie in a page an
    /// executable `PT_LOAD` maps, in section-header order: what `-z separate-code` keeps
    /// out of the code segment's pages, and what `-z noseparate-code` lets in. `None` where
    /// the question has no referent: no `PT_LOAD` carries `PF_X` (a relocatable object has
    /// no program headers at all), or no section header describes an allocated section, so
    /// nothing could be classified (a file whose section headers were removed).
    ///
    /// A section is code by its own `SHF_EXECINSTR` flag, never by its name. The detection
    /// recipe's form was a segment's section list against a name allowlist of `.init`,
    /// `.plt*`, `.text*` and `.fini`, and it named its own weakness: a code section the
    /// list does not know (`.text.hot`, `.plt.bnd`, a linker thunk) reads as data, a false
    /// `off`. The flag is the linker's own statement of which bytes are instructions, so a
    /// new code section is classified as code without a list to keep current. Header
    /// bytes are not sections and are not read, so the ELF header and the program header
    /// table never count, as they never did in the recipe's form either.
    ///
    /// The page is the executable segment's own `p_align`, or 4096 bytes where that is smaller:
    /// its file range is widened down and up to that alignment before the sections are
    /// compared against it, because the loader maps whole pages and the linker lays out for
    /// the largest page the target allows. The floor is there because no kernel for a
    /// machine this reader names maps a page below 4096 bytes, so a segment declaring less
    /// still has its neighbours' bytes mapped with it: `-Wl,-z,max-page-size=0x10` with
    /// `-Wl,-z,separate-code` puts `.rodata`, `.dynsym` and `.eh_frame` at 0x4c0 beside a
    /// code segment ending at 0x4b9, and read at its own 16-byte alignment that layout
    /// was `on` (GNU ld 2.46.1 on Fedora 44 x86_64, 2026-10-02). A segment aligned above
    /// the running kernel's page is read at its own alignment, which is the layout the
    /// linker wrote rather than the pages one kernel maps; the assumption
    /// `separate-code-reads-the-linked-layout` in `report::ASSUMPTIONS` carries that and
    /// the exclusions below. Read by pages rather than by segment membership because lld and mold lay
    /// out separate segments either way and differ only there: under
    /// `-z noseparate-code` their executable segment holds `.text` alone, as it does under
    /// `-z separate-code`, and its first and last pages share file bytes with the
    /// read-only and writable segments beside it. A segment-membership reading reads `on`
    /// for both arms there. Measured 2026-10-02 with gcc 16.2.1 and clang 22.1.8 in the
    /// Fedora 44 x86_64 container carrying lld 22.1.8 and mold 2.40.4, by hand with readelf
    /// and a reader of these rules: by membership both arms of both linkers put `.text`,
    /// `.init`, `.fini` and `.plt` alone in the executable segment, and by pages
    /// `-z separate-code` holds no data while `-z noseparate-code` holds `.rodata`,
    /// `.eh_frame`, `.dynsym` and the rest of the image beside the code.
    ///
    /// `.note.gnu.build-id` is not counted. Fedora's GNU ld places the note before `.init`
    /// in the executable segment on x86_64 ("as close to the ELF headers as possible", its
    /// default linker script says, so that a core file carries it), under
    /// `-z separate-code` as well. Counted, the flag's own positive arm reads data in the
    /// code pages on Fedora 44 x86_64 (GNU ld 2.46.1, measured 2026-10-02), and the check
    /// would be `probe-invalid` on the distribution's default linker. The recipe's
    /// allowlist names the note for the same reason. On Fedora 44 aarch64 the same linker
    /// keeps the note out of the code segment.
    ///
    /// Absent from the serialization when `None`, and `#[serde(default)]` to read it back,
    /// for the reason `openbsd_nobtcfi` carries both: a recorded row without the field reads
    /// as absent.
    /// A defaulted `None` reads `indeterminate`, so a row mined before the field existed
    /// cannot read as either verdict. A report's `facts` store states the `null`
    /// (`report::serialize_stored_elf`), so a reader re-evaluating `separate-code` over
    /// the store can tell an artifact with no referent from a store that lost the member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_in_code_pages: Option<Vec<String>>,
    /// The relocations a relocatable object asks the linker to apply to its code, each as
    /// `TYPE SYMBOL`: the type as `readelf -r` names it (`R_X86_64_REX_GOTPCRELX`), one
    /// space, and the symbol's name, or for a section symbol the section's name in
    /// brackets (`R_X86_64_PC32 [.data]`). A named symbol whose visibility is not
    /// `STV_DEFAULT` carries it as a third word (`R_386_PC32 __x86.get_pc_thunk.ax
    /// STV_HIDDEN`), since how the code reaches a symbol depends on it: under `-fPIC` a
    /// hidden global is reached directly, as under `-fPIE`, and `pic-object-relocs` reads a
    /// direct type as `-fPIC` absent only against a default-visibility anchor (added
    /// 2026-10-02; the replay corpus's rows mined before it carry two words throughout).
    /// Distinct entries, sorted. `None` for anything but an
    /// `ET_REL` with a section-header table: a linked object's static relocations were
    /// applied and dropped, and its dynamic ones are the loader's, not the compiler's.
    ///
    /// Code is a relocation section whose `sh_info` names a section with `SHF_EXECINSTR`,
    /// by the flag rather than by name, as [`Self::data_in_code_pages`] reads it, so
    /// `-ffunction-sections`' `.text.<name>` is code without a list. Relocations patching
    /// data are left out: under `-g` the debug sections carry an absolute `R_X86_64_64`
    /// against every global, and under gcc's `-fsanitize=address` the instrumented
    /// globals' descriptors carry one in `.data.rel.local` (gcc 16.1.1, Fedora 44 x86_64,
    /// measured 2026-10-02); neither says how the code reaches the global. A section
    /// symbol, which a reference to a local or anchored object goes through, is listed by
    /// its section in brackets, so no reading keyed on a symbol name matches it and an
    /// `indeterminate` reading still shows where the reference went; an unnamed symbol of
    /// any other type, and symbol index 0, name nothing and are left out. A type
    /// `elf/reloc_names.rs` does not name is spelt `reloc-type-` and its number in hex,
    /// so an unnamed type never reads as a named one.
    ///
    /// The fact `plt-bypassed` reads: a call to a function the object does not define is
    /// relocated through the callee's GOT slot under `-fno-plt`, and as a direct call a PLT
    /// entry serves without it. The same GOT types load external data's addresses, so its
    /// predicate reads the probe callee's entries alone; the measurements are beside it in
    /// `predicate::elf_static`.
    ///
    /// The fact `pic-object-relocs` reads: under `-fPIC` the compiler reaches a defined,
    /// preemptible global through the GOT, and under `-fPIE` or without PIC directly. The
    /// measurements are beside its predicate in `predicate::elf_static`.
    ///
    /// Absent from the serialization when `None`, and `#[serde(default)]` to read it back,
    /// for the reason `data_in_code_pages` carries both; a report's `facts` store states
    /// the `null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_relocations: Option<Vec<String>>,
    /// What each function of a relocatable object refers to, attributed from the object's
    /// own relocations. Each defined `STT_FUNC` symbol, in symbol-table order, is an item
    /// `name:`, followed by an item `name:target` for every distinct named symbol that a
    /// relocation at an offset inside the function's range refers to, the targets sorted.
    /// A `.symtab` name's version suffix is cut as [`Elf::symbols`] cuts it, and a
    /// relocation against an unnamed symbol (a section symbol) names nothing and is not
    /// listed.
    ///
    /// The range is `[st_value, st_value + st_size)` in the section `st_shndx` names, which
    /// in an object is an offset into that section, and a relocation section's `sh_info`
    /// names the section its offsets are into. So the attribution needs no
    /// `-ffunction-sections`, which the recipe built with to read the function off the
    /// section name; a build flag the measured arm and both controls would have had to
    /// share is one more thing that could differ between them. A function in a section
    /// numbered at or above `SHN_LORESERVE` cannot be placed and is not listed, so a
    /// reading that needs it finds it missing rather than finding it with no references.
    /// After the functions, an item `?:target` ([`UNATTRIBUTED_REFERENCE`]) for every
    /// distinct named symbol a relocation in code refers to from outside every function's
    /// range, sorted: the code clang's `-fbasic-block-sections=all` moves into a section
    /// with no function symbol (see `Elf::attribute_relocations`).
    ///
    /// `ssp-level-emitted` reads it: a function whose range refers to the canary failure
    /// handler or the guard got a canary, and a function the list does not hold is not
    /// one without. `None` where the question has no referent: the object is not
    /// relocatable (a link resolves the relocations and keeps none per function), has no
    /// `SHT_SYMTAB`, or is a 64-bit MIPS object, whose `r_info` this reader does not
    /// decode. A relocation section the reader could not finish, or one in an encoding it
    /// does not decode (`SHT_CREL`, or any other type whose `SHF_INFO_LINK` names a
    /// section holding functions), is recorded in
    /// [`Self::truncations`] against [`ElfTable::Relocations`], and a symbol table it
    /// could not read against [`ElfTable::Symbols`]; either withholds the reading.
    ///
    /// Absent from the serialization when `None`, `#[serde(default)]` to read it back, and
    /// stated as `null` in a report's `facts` store, all for the reasons
    /// [`Self::data_in_code_pages`] gives: a recorded row without the field reads as absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_references: Option<Vec<String>>,
    /// The symbol tables the file has, as [`Elf::symbols`] labels them: `.symtab` and
    /// `.dynsym` by name, or `SHT_SYMTAB` and `SHT_DYNSYM` where the section names could
    /// not be read. In header order.
    ///
    /// The fact `report::artifact_limitation` reads for the checks whose observable is a
    /// symbol reference (`canary-emitted`, `ssp-covers-small-arrays`,
    /// `cxx-assertions-symbol`): a linked object with no symbol table at all cannot carry
    /// one, and a stripped static link is that object, since `-s` removes `.symtab` and a
    /// static link has no `.dynsym`. The canary in such an artifact was emitted and is
    /// unreachable, so the reading is `not-applicable` under
    /// `artifact-cannot-carry-observable`; without this fact it read `off` over a
    /// discriminating triple, since the controls are built unstripped. A file whose
    /// section headers are gone has its symbol tables recorded as `unread` in
    /// [`Self::truncations`] instead, which `measure::artifact_gating` consults first.
    ///
    /// `#[serde(default)]` for the reason `comment` carries it: a recorded row without
    /// the field reads as empty, and no detector reads it. Absent from the report when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symbol_tables: Vec<String>,
    pub symbol_count: usize,
    pub watched_symbols: BTreeMap<String, SymbolFact>,

    /// Tables this parse could not read to their end, named.
    ///
    /// Every accessor on `Cursor` returns a `Result`. A caller that discarded it into a `break`
    /// would return, for a table truncated at byte *k*, its first *k* entries as though that were
    /// all of them. Each such failure lands on **absence**, and every detector reads absence as a
    /// measured negative, so an unreadable symbol table would publish `canary: false`, and a
    /// binary with no section-header table would publish `relro: partial` and `dt_relr: false`
    /// while still carrying `DF_1_NOW`. Both are reproduced against such a reader:
    /// `objcopy --strip-section-headers` flips six facts to the unprotected answer on a binary
    /// that still runs, and zeroing `.dynsym`'s `sh_link`, a single four-byte edit, flips
    /// `canary` and the eight `__*_chk` counts while `parse_failed` stays at zero.
    ///
    /// The module header promises *"a truncated or hostile file produces a typed error instead of a
    /// panic"*. `Cursor` keeps that promise with its errors, and this field keeps it above
    /// `Cursor`: a reader that could not finish says so, in the facts, so a consumer can
    /// tell "measured
    /// and absent" from "could not be read". A table read to its end but read differently from the
    /// loader is not this half: those readings, the ones measured so far, are the register
    /// entries `THREAT_MODEL.md`'s crafted-ELF row names.
    ///
    /// Typed, so the consumer can read it: each entry names its [`ElfTable`] and whether that
    /// table's facts went [`TruncationKind::Unread`] or a disagreeing view was
    /// [`TruncationKind::Ignored`]. `report::truncation_limitation` matches `table` against a
    /// check's declared `reads` and withholds on `Unread` alone; [`Self::unread`] is the lookup.
    /// A table that is absent from the file is never recorded here: an `ET_REL` has no
    /// `.dynamic` and a stripped static link no symbol table, and a missing table is
    /// `not-applicable`'s business. `report::artifact_limitation` decides it over the facts
    /// that say which tables the file has, `has_dynamic` for `.dynamic` and
    /// [`Self::symbol_tables`] for the symbol tables, through the precondition rows keyed
    /// on the checks that read each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub truncations: Vec<Truncation>,

    /// Contents of `.chard.report`: the binary's own account of the macros in
    /// effect when it was compiled. Self-reported, hence cross-checked by the
    /// other channels.
    pub self_report: String,
    /// Contents of `.GCC.command.line` (`-frecord-gcc-switches` /
    /// clang's `-frecord-command-line`) — the literal driver command line when
    /// the toolchain was asked to record it. gcc records the options `cc1`
    /// received, driver- and spec-injected ones included; clang records its
    /// driver's arguments, configuration-file options included. Neither records
    /// a default compiled into the compiler, so it complements rather than
    /// replaces the macro channel (measurements in the project's DWARF-producer study).
    pub recorded_command_line: String,
    /// The distinct lines of `.comment`, in file order.
    ///
    /// Every producer that touched the object appends a line of its own: the compiler,
    /// unless built with `-fno-ident` (`GCC: (GNU) 16.1.1 20260515 (Red Hat 16.1.1-2)`,
    /// `clang version 22.1.8 (Fedora 22.1.8-4.fc44)`), lld (`Linker: LLD 22.1.8`) and mold
    /// (`mold 2.40.4 (compatible with GNU ld)`). GNU ld and gold append nothing, so an
    /// object either of them linked carries compiler lines only, and one built under
    /// `-fno-ident` carries none at all. `toolchain::artifact_agreement` reads this field
    /// to hold the banner-derived linker identity to the artifact; the grammar and the
    /// measurements behind it are recorded there.
    ///
    /// Read through [`Elf::section_lines`] and never through `section_text`, whose empty
    /// string means "absent" and "unreadable" alike. Here that conflation would let a
    /// `.comment` the reader could not reach publish as an object no linker signed, which
    /// is the wrong direction for a field whose job is to catch a wrong identity. A
    /// `.comment` that could not be read, or could not be looked up because the file
    /// carries no section-header table or no readable section names, leaves this empty
    /// and names itself in `truncations`; [`ElfFacts::comment_truncation`] is how a
    /// consumer tells the two apart.
    ///
    /// `#[serde(default)]` for the reason `aarch64_gcs` carries it: the fixtures in
    /// `tests/fixtures/detectors.json` predate the field, and no detector reads it, so a
    /// defaulted empty list decides no verdict.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comment: Vec<String>,

    /// `<function>:<pattern>=<count>` for every pattern of this machine that a
    /// [`code::SCANS`] entry lists, searched in that entry's function where its bytes were
    /// read whole, zero counts included. A listed function the file does not define, or a
    /// machine with no pattern, contributes nothing, so a predicate tells "searched and not
    /// found" from "not searched" by this list; a function that is defined and could not be
    /// read is in `truncations` under `code`. The mechanism and why a byte search over one
    /// known function is sound are in the `code` module's documentation.
    ///
    /// Omitted when empty, as `comment` is, so `chard elf`, the replay corpus and the
    /// synthetic fixtures predating it serialize as they did; a report's `elf` store entries
    /// state it, `[]` included, through `report::serialize_stored_elf`, since
    /// `predicate::Published` reads an absent list as `Incomplete`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_scanned: Vec<String>,
    /// `<function>:<pattern>@<offset>` for each match `code_scanned` counts, the offset
    /// from the function's first byte, at most [`code::MATCHES_KEPT`] per function and
    /// pattern. Omitted when empty and stated by the store, as `code_scanned` is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_matches: Vec<String>,
    /// `<function>=<hex>` for each function [`entry::ENTRY_FUNCTIONS`] names that the file
    /// defines and whose bytes were read: its first [`entry::ENTRY_BYTES`] bytes (fewer
    /// where its `st_size` is smaller) as lowercase hex, in file order. A listed function the
    /// file does not define contributes nothing, so a predicate tells "read" from "not
    /// there" by this list; one that is defined and could not be read is in `truncations`
    /// under `function-entries`. The mechanism, and why the bytes at a function's address
    /// are its first instruction, are in the `entry` module's documentation.
    ///
    /// Omitted when empty, as `comment` is, so `chard elf`, the replay corpus and the
    /// synthetic fixtures predating it serialize as they did; a report's `elf` store entries
    /// state it, `[]` included, through `report::serialize_stored_elf`, since
    /// `predicate::Published` reads an absent list as `Incomplete`. `cet-endbr-emitted`
    /// reads it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub function_entries: Vec<String>,
}

impl ElfFacts {
    /// The first truncation that left one of `tables` unread, if any.
    ///
    /// `Ignored` entries never match: the loader's view was measured whole, and a gate
    /// that withheld on them would turn the forged-section defence into a denial of
    /// measurement.
    #[must_use]
    pub fn unread(&self, tables: &[ElfTable]) -> Option<&Truncation> {
        self.truncations
            .iter()
            .find(|t| t.kind == TruncationKind::Unread && tables.contains(&t.table))
    }

    /// The reader's sentence for a `.comment` that was present, or could not be looked
    /// up, and was not read: the `detail` of the [`ElfTable::Comment`] entry.
    ///
    /// Matched on the typed table, so the sentence `Elf::section_lines` writes is free to
    /// change; `toolchain::artifact_agreement` reads this to leave the artifact out of the
    /// linker count and to name it.
    #[must_use]
    pub fn comment_truncation(&self) -> Option<&str> {
        self.unread(&[ElfTable::Comment]).map(|t| t.detail.as_str())
    }
}

/// The section every producer of a linked object appends its line to.
const COMMENT_SECTION: &str = ".comment";

/// The section `probes/chard_selfreport.h` writes the self-report into, and `ElfFacts::self_report`
/// reads it from. Spelled once here: `report::self_report_entries` says whether an artifact
/// carries a readable one, and the gating rule `artifact-lacks-self-report` names it.
pub const SELF_REPORT_SECTION: &str = ".chard.report";

pub struct Elf<'a> {
    cur: Cursor<'a>,
    elf64: bool,
    e_type: u16,
    e_machine: u16,
    phdrs: Vec<Phdr>,
    shdrs: Vec<Shdr>,
    shnames: Vec<String>,
    /// The section names more than one section carries, for [`Elf::section_stride`]'s
    /// labels: counted once here, since asking per section would make the walks quadratic in
    /// the section count (measured 2026-10-20: 32,000 relocation sections read in 2.5 s
    /// against under 0.01 s with the names counted once).
    shared_names: BTreeSet<String>,
    /// What the header declared that could not be followed: a section-name table that
    /// does not exist or is not a string table (`section names:`), or a count escape
    /// whose `shdr[0]` the file does not hold (`section-header table:`). Merged into
    /// `ElfFacts::truncations` by `structural_truncations`.
    header_truncations: Vec<Truncation>,
}

impl<'a> Elf<'a> {
    /// # Errors
    ///
    /// Errors when `data` is not an ELF file, declares a class or endianness we do
    /// not recognize, or is truncated inside the header tables.
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfError> {
        let (elf64, little) = identify(data)?;
        let cur = Cursor { data, little };

        // ELF header field offsets differ only in the width of the address
        // fields, so derive them rather than duplicating two struct layouts.
        let e_type = cur.u16_at(16)?;
        let e_machine = cur.u16_at(18)?;
        let (phoff_at, shoff_at) = if elf64 { (32, 40) } else { (28, 32) };
        let e_phoff = cur.addr_at(phoff_at, elf64)?;
        let e_shoff = cur.addr_at(shoff_at, elf64)?;
        let hdr_tail = if elf64 { 54 } else { 42 };
        let e_phentsize = u64::from(cur.u16_at(hdr_tail)?);
        let e_phnum = cur.u16_at(hdr_tail.saturating_add(2))?;
        let e_shentsize = u64::from(cur.u16_at(hdr_tail.saturating_add(4))?);
        let e_shnum = cur.u16_at(hdr_tail.saturating_add(6))?;
        let e_shstrndx = cur.u16_at(hdr_tail.saturating_add(8))?;

        // A table walk is `base + i * entsize`, so an `entsize` below the real record size
        // makes the walk read overlapping records -- and at zero it makes every index name
        // the *same* bytes. `e_shentsize = 0` with `e_shnum = 65535` aliased one
        // `SHT_DYNAMIC` header onto 65535 logical sections, and `dynamic()` walked its
        // region once per alias: a 16 KB input drove 4.79 `GiB` of resident memory, a 1.09 GB
        // report and 5.0s of wall time. Nothing capped it -- `MAX_OBJECT_BYTES` bounds the
        // *input*, and this PoC shows the derived iteration count is unrelated to input size.
        //
        // Refused rather than clamped. An entsize below the record size describes a table
        // that cannot exist, and a file that declares one is malformed at the header, before
        // any question of what it contains. `readelf -S` silently enumerates zero sections
        // for it and `objdump -h` refuses the file outright; erroring is the nearer of the
        // two and says why. Larger than the record size is legal -- the spec allows padding.
        // The declared counts, before the escapes below can widen them: a stride of zero
        // must be refused before `shdr[0]` is read through it.
        let uses_shnum_escape = e_shnum == 0 && e_shoff != 0;
        let declared_shnum = if uses_shnum_escape {
            1
        } else {
            u64::from(e_shnum)
        };
        check_strides(
            elf64,
            (u64::from(e_phnum), e_phentsize),
            (declared_shnum, e_shentsize),
        )?;

        // The gABI's three escapes, all through `shdr[0]`: the null header carries no
        // section of its own, so its size, link and info fields are free to hold the counts
        // and the index that the 16-bit header fields cannot. `readelf` resolves all three,
        // and so does this reader. Taking `e_shnum == 0` as "no sections" and `e_shstrndx ==
        // 0xffff` as an index past the table would lose, from a file using either escape,
        // every fact that is reached by section name.
        //
        // All three need a table to escape into. With `e_shoff == 0` there is none, and a
        // header that says `PN_XNUM` or `SHN_XINDEX` anyway is malformed: the values are
        // left as declared, and the walks below fail on them. The ELF header is never
        // read as `shdr[0]`. A nonzero `e_shoff` past the end of the file is
        // `probe_shdr0`'s case.
        let mut header_truncations = Vec::new();
        let escapes =
            e_shoff != 0 && (uses_shnum_escape || e_phnum == PN_XNUM || e_shstrndx == SHN_XINDEX);
        let shdr0 = if escapes {
            probe_shdr0(
                &cur,
                elf64,
                e_shoff,
                uses_shnum_escape,
                &mut header_truncations,
            )?
        } else {
            None
        };
        let e_shnum = match shdr0.as_ref() {
            Some(first) if uses_shnum_escape => first.sh_size,
            _ => u64::from(e_shnum),
        };
        let e_phnum = match shdr0.as_ref() {
            Some(first) if e_phnum == PN_XNUM => u64::from(first.sh_info),
            _ => u64::from(e_phnum),
        };
        let shstrndx = match shdr0.as_ref() {
            Some(first) if e_shstrndx == SHN_XINDEX => first.sh_link,
            _ => u32::from(e_shstrndx),
        };
        // Again, over the counts the escapes produced.
        check_strides(elf64, (e_phnum, e_phentsize), (e_shnum, e_shentsize))?;

        let phdrs = read_phdrs(&cur, elf64, e_phoff, e_phnum, e_phentsize)?;
        let mut shdrs = Vec::new();
        for i in 0..e_shnum {
            let base = e_shoff
                .checked_add(
                    i.checked_mul(e_shentsize)
                        .ok_or_else(|| ElfError::malformed("shdr index overflow"))?,
                )
                .ok_or_else(|| ElfError::malformed("shdr offset overflow"))?;
            shdrs.push(read_shdr(&cur, elf64, base)?);
        }

        let shnames = section_names(&cur, &shdrs, shstrndx, &mut header_truncations);
        let mut seen = BTreeSet::new();
        let shared_names = shnames
            .iter()
            .filter(|n| !n.is_empty() && !seen.insert(n.as_str()))
            .cloned()
            .collect();

        Ok(Self {
            cur,
            elf64,
            e_type,
            e_machine,
            phdrs,
            shdrs,
            shnames,
            shared_names,
            header_truncations,
        })
    }

    fn section_bytes(&self, sh: &Shdr) -> Result<&'a [u8], ElfError> {
        if sh.sh_type == SHT_NOBITS {
            return Ok(&[]);
        }
        // `?` rather than a bare tail call: this widens `ReadError` into `ElfError` at
        // the boundary, which is where that conversion belongs.
        Ok(self.cur.slice(sh.sh_offset, sh.sh_size)?)
    }

    /// Translate a virtual address to a file offset, through the `PT_LOAD` that contains it.
    ///
    /// `.dynamic` holds *addresses* (`DT_STRTAB` points at where the string table will be
    /// mapped, not at where it sits in the file), so this is how every table the dynamic section
    /// names is reached: `dyn_strtab` prefers it to `.dynstr`'s section header, and with section
    /// headers gone it is the only route. It bounds on `p_memsz`, not `p_filesz`, which is the
    /// assumption `address-reached-tables-lie-in-the-file-image` in `report::ASSUMPTIONS`.
    fn offset_of_vaddr(&self, vaddr: u64) -> Option<u64> {
        self.phdrs
            .iter()
            .filter(|p| p.p_type == PT_LOAD)
            .find(|p| vaddr >= p.p_vaddr && vaddr < p.p_vaddr.saturating_add(p.p_memsz))
            .map(|p| p.p_offset.saturating_add(vaddr.saturating_sub(p.p_vaddr)))
    }

    /// Bytes from `vaddr` to the end of the containing `PT_LOAD` segment's file image —
    /// a defensive bound for a table reached by address when the table's own size tag
    /// (e.g. `DT_STRSZ`) is absent, so a scan still has a declared limit narrower than
    /// the whole file rather than none at all.
    fn segment_remaining_at(&self, vaddr: u64) -> Option<u64> {
        self.phdrs
            .iter()
            .filter(|p| p.p_type == PT_LOAD)
            .find(|p| vaddr >= p.p_vaddr && vaddr < p.p_vaddr.saturating_add(p.p_memsz))
            .map(|p| p.p_filesz.saturating_sub(vaddr.saturating_sub(p.p_vaddr)))
    }

    fn section_by_name(&self, name: &str) -> Option<&Shdr> {
        self.shnames
            .iter()
            .position(|n| n == name)
            .and_then(|i| self.shdrs.get(i))
    }

    /// Whether `parse` refused the section-name table, leaving every name empty: the
    /// `SectionNames` entry is the record of that refusal, read back here so a lookup by
    /// name can say the name was never available.
    fn section_names_unreadable(&self) -> bool {
        self.header_truncations
            .iter()
            .any(|t| t.table == ElfTable::SectionNames)
    }

    /// The text of section `name`, NULs as newlines, trimmed. Empty when the section is
    /// absent, and when its name table could not be read, which `parse` has already
    /// recorded as a `SectionNames` entry.
    ///
    /// A section that is listed and cannot be read pushes an `Unread` [`ElfTable::SectionNames`]
    /// truncation naming it and returns empty. `.chard.report` is the self-report the
    /// runtime fortify checks read through `Evidence::fortify_impl`, and those checks declare
    /// `SectionNames`: returned empty with no record, a cut section read as a probe that
    /// reported nothing, and the check withheld with no table named.
    fn section_text(&self, name: &str, truncations: &mut Vec<Truncation>) -> String {
        let Some(sh) = self.section_by_name(name) else {
            return String::new();
        };
        let bytes = match self.section_bytes(sh) {
            Ok(bytes) => bytes,
            Err(why) => {
                truncations.push(Truncation::unread(
                    ElfTable::SectionNames,
                    format!(
                        "{name}: {:#x}+{:#x} could not be read ({why:#}), so the section's \
                         text was not read and the field is empty for want of a reading",
                        sh.sh_offset, sh.sh_size
                    ),
                ));
                return String::new();
            }
        };
        String::from_utf8_lossy(bytes)
            .replace('\0', "\n")
            .trim()
            .to_owned()
    }

    /// The NUL-separated strings of section `name`: trimmed, non-empty, first occurrence
    /// kept, file order preserved. Empty when the section is absent.
    ///
    /// A section that is present and cannot be read pushes a [`ElfTable::Comment`]
    /// truncation and returns empty, which is the one difference from `section_text`. There
    /// absence and failure read the same, and a consumer of `.comment` needs them apart:
    /// "no linker signed this object" is a finding only when the section was read to its
    /// end. So does a section that could not be looked up at all: a file with no
    /// section-header table, or one whose section names could not be read, has not
    /// established that the section is absent, and the `structural_truncations` entry
    /// that records the file's shape is not one a consumer of this field reads.
    /// `ElfFacts::comment_truncation` reads the entry back by its table.
    fn section_lines(&self, name: &str, truncations: &mut Vec<Truncation>) -> Vec<String> {
        let unlisted = if self.shdrs.is_empty() {
            Some("no section-header table")
        } else if self.section_names_unreadable() {
            Some("the section names could not be read")
        } else {
            None
        };
        if let Some(why) = unlisted {
            truncations.push(Truncation::unread(
                ElfTable::Comment,
                format!(
                    "{name}: could not be looked up ({why}), so the section's lines were not \
                     read and the field is empty for want of a reading"
                ),
            ));
            return Vec::new();
        }
        let Some(sh) = self.section_by_name(name) else {
            return Vec::new();
        };
        let bytes = match self.section_bytes(sh) {
            Ok(bytes) => bytes,
            Err(why) => {
                truncations.push(Truncation::unread(
                    ElfTable::Comment,
                    format!(
                        "{name}: {:#x}+{:#x} could not be read ({why:#}), so the section's \
                         lines were not read and the field is empty for want of a reading",
                        sh.sh_offset, sh.sh_size
                    ),
                ));
                return Vec::new();
            }
        };
        let mut lines: Vec<String> = Vec::new();
        for raw in String::from_utf8_lossy(bytes).split('\0') {
            let line = raw.trim();
            if !line.is_empty() && !lines.iter().any(|seen| seen == line) {
                lines.push(line.to_owned());
            }
        }
        lines
    }

    /// Truncations that are properties of the file's shape rather than of a read that failed.
    ///
    /// One case, and it is the expensive one: **no section-header table**. Reproduced with
    /// `objcopy --strip-section-headers` on `/usr/bin/ls`, which still runs: six facts flipped to
    /// the unprotected answer, because `.dynamic` and the symbol tables were reached only through
    /// section headers while notes already fell back to `PT_NOTE`.
    ///
    /// Four of the six are now recovered — `dynamic` walks the `PT_DYNAMIC` segment and `dyn_strings`
    /// resolves `DT_STRTAB` through the containing `PT_LOAD` — so RELRO, `BIND_NOW`, `DT_RELR`,
    /// `DF_1_NOOPEN`, `TEXTREL` and the `needed`/`rpath`/`runpath` lists survive the strip. The
    /// symbol tables do not: reaching them without section headers means walking `DT_SYMTAB` and
    /// deriving a count from `DT_HASH` or `DT_GNU_HASH`, which is a larger piece of work.
    ///
    /// So the note names what is *still* lost rather than what was lost before the fallback existed.
    /// A truncation message that overstates is the same defect as a verdict that overstates.
    ///
    /// The second case is a section-header table whose names cannot be read, recorded by
    /// `parse` under the `section names:` prefix. It is distinct from the first: the tables
    /// are all there and are still walked by type, so `.dynamic` and both symbol tables are
    /// read, but nothing reached by name is, and `sections` is empty because the file
    /// named nothing; the truncation is what says the sections exist.
    ///
    /// The first case records two entries, `symbols` for the tables walked by type and
    /// `section-names` for everything reached by name, `.chard.report` among it: the
    /// runtime fortify checks read that self-report and declare `section-names`, so a
    /// stripped object withholds them with the cause named.
    ///
    /// The third is the first reached by a stale header, recorded by `parse` under the
    /// `section-header table:` prefix as a `section-headers` entry and carried beside the
    /// first case's two: a count escape whose `shdr[0]` lies past the end of the file
    /// leaves the reader with no table, and the note says why there is none.
    fn structural_truncations(&self) -> Vec<Truncation> {
        let mut out = Vec::new();
        if self.shdrs.is_empty() {
            out.push(Truncation::unread(
                ElfTable::Symbols,
                "no section-header table: the symbol tables are unreachable, so the stack canary \
                 and the fortify symbol counts are absent here because they could not be read, \
                 not because they are not present. The dynamic segment was read instead, so RELRO, \
                 BIND_NOW, DT_RELR and the library lists are measured"
                    .to_owned(),
            ));
            out.push(Truncation::unread(
                ElfTable::SectionNames,
                "no section-header table: nothing reached by section name was read, so the \
                 .chard.report self-report and .GCC.command.line are empty because they could \
                 not be looked up, not because the object lacks them"
                    .to_owned(),
            ));
        }
        out.extend(self.header_truncations.iter().cloned());
        out
    }

    /// `(tag, value)` pairs from `.dynamic`. Empty for a static non-PIE binary.
    ///
    /// `trunc` collects the name of any table that could not be read to its end, so an empty
    /// result can be told apart from an unreadable one.
    fn dynamic(&self, trunc: &mut Vec<Truncation>) -> Vec<(i64, u64)> {
        let mut out = Vec::new();
        // `(offset, size)` of every `.dynamic` to walk. Sections when they exist; otherwise the
        // `PT_DYNAMIC` segment, which is the same bytes reached the way the loader reaches them.
        //
        // Without this a binary stripped of its section headers reported `bind_now: false` and so
        // `relro: partial`, plus `dt_relr: false`, `df_1_noopen: false` and `textrel: false` — all
        // in the unprotected direction, on a file that still runs and whose `PT_DYNAMIC` segment
        // still carries `DF_1_NOW`. `objcopy --strip-section-headers` (binutils >= 2.42) and
        // `sstrip` both produce it, and it is common in container images.
        // **The segment wins, and the ordering is the whole point.** `ld.so` reads `PT_DYNAMIC`
        // and never reads section headers at all -- they are optional metadata that `strip
        // --strip-all` removes without changing what the file does. Preferring the section view
        // therefore let a crafted file be measured through bytes the loader never consults: a
        // 4.4 KB `ET_DYN` whose `PT_DYNAMIC` sets no flags, plus an `SHT_DYNAMIC` section header
        // aimed at a second, forged table, read as `pie: true`, `df_1_pie: true`,
        // `bind_now: true`, while `readelf -d` reported `FLAGS_1: None` from the real segment and
        // flagged the file as anomalous. That is a false `on` on an attacker-supplied binary,
        // which is the one verdict THREAT_MODEL.md says this project exists to prevent.
        //
        // Nothing is lost by the flip. The stripped-section-header case this fallback was written
        // for -- `objcopy --strip-section-headers`, `sstrip`, common in container images, where
        // `bind_now: false` and `relro: partial` were reported for a file whose `PT_DYNAMIC`
        // still carried `DF_1_NOW` -- has no section headers at all, so it is served by the
        // fallback either way round.
        let segments: Vec<(u64, u64)> = self
            .phdrs
            .iter()
            .filter(|p| p.p_type == PT_DYNAMIC)
            .map(|p| (p.p_offset, p.p_filesz))
            .collect();
        let sections: Vec<(u64, u64)> = self
            .shdrs
            .iter()
            .filter(|s| s.sh_type == SHT_DYNAMIC)
            .map(|s| (s.sh_offset, s.sh_size))
            .collect();
        let regions: Vec<(u64, u64)> = if segments.is_empty() {
            // No loader reads an object with no `PT_DYNAMIC`, so there is no loader rule to
            // follow and the one the segments follow is borrowed: one table is read, the
            // last, and the others are a disagreement this file does not settle. Concatenated,
            // the earlier sections answered for a table the later one displaced.
            if sections.len() > 1 {
                trunc.push(Truncation::unread(
                    ElfTable::Dynamic,
                    format!(
                        "{} SHT_DYNAMIC sections and no PT_DYNAMIC segment; the last is the \
                         one measured, as for a repeated PT_DYNAMIC, and no loader reads \
                         this object to say which it would take",
                        sections.len()
                    ),
                ));
            }
            sections.iter().copied().next_back().into_iter().collect()
        } else {
            // A section view that the loader would not reach is *dropped*, and a drop this file
            // stays silent about reads as agreement. Containment rather than equality, because an
            // ordinary `.dynamic` section sits inside its `PT_DYNAMIC` segment and the two
            // legitimately differ in size.
            for (off, size) in &sections {
                let end = off.saturating_add(*size);
                let contained = segments
                    .iter()
                    .any(|(p_off, p_size)| off >= p_off && end <= p_off.saturating_add(*p_size));
                if !contained {
                    // `Ignored`: the facts are whole, read from the segment. Recording it
                    // as unread would let the forged view withhold the measurement it was
                    // dropped in order to protect.
                    trunc.push(Truncation::ignored(
                        ElfTable::Dynamic,
                        format!(
                            "SHT_DYNAMIC section at {off:#x}+{size:#x} lies outside every \
                             PT_DYNAMIC segment and was not read; the loader reads the segment, \
                             so the segment is what was measured"
                        ),
                    ));
                }
            }
            // **The last `PT_DYNAMIC` is the one the loader reads.** Measured 2026-10-09 on
            // Fedora 44 x86_64 (glibc 2.43 `ld.so`, musl `ld-musl-x86_64.so.1`): a PIE patched
            // to carry two `PT_DYNAMIC` headers ran the `DT_INIT` of the later table under
            // both, in both header orders. The loaders do not concatenate, so neither does
            // this: concatenating let the earlier table's entries answer for a table the
            // loader never reads. No source for either loader was on the host; the rule is
            // the experiment's, and it was not run under a BSD or bionic loader, so the
            // disagreement is recorded `unread`, not resolved silently.
            if segments.len() > 1 {
                trunc.push(Truncation::unread(
                    ElfTable::Dynamic,
                    format!(
                        "{} PT_DYNAMIC segments; glibc and musl read the last and \
                         that is the one measured, and a loader not run for this \
                         was not established to agree",
                        segments.len()
                    ),
                ));
            }
            segments.iter().copied().last().into_iter().collect()
        };
        for (sh_offset, sh_size) in regions {
            self.walk_dynamic(sh_offset, sh_size, &mut out, trunc);
        }
        repeated_loader_tags(&out, trunc);
        out
    }

    /// The entries of one `.dynamic` region, up to `DT_NULL`.
    ///
    /// `DT_NULL` is the loader's terminator: `ld.so` walks `l_ld` from `p_vaddr` to the
    /// first `DT_NULL` and consults neither `p_filesz` nor `sh_size`. So a region whose
    /// declared size ends before `DT_NULL` is a table the reader did not finish, and is
    /// recorded as one. Before this a `PT_DYNAMIC` whose `p_filesz` ended before
    /// `DT_FLAGS_1` read `bind_now: false`, `relro` decided `partial` on a file whose
    /// loader binds now, and the only record was an `ignored` entry for the section view
    /// the segment had displaced, which the gate never reads.
    fn walk_dynamic(
        &self,
        sh_offset: u64,
        sh_size: u64,
        out: &mut Vec<(i64, u64)>,
        trunc: &mut Vec<Truncation>,
    ) {
        let step: u64 = if self.elf64 { 16 } else { 8 };
        let count = sh_size.checked_div(step).unwrap_or(0);
        for i in 0..count {
            let base = sh_offset.saturating_add(i.saturating_mul(step));
            let tag = if self.elf64 {
                self.cur
                    .u64_at(base)
                    .map(|v| i64::from_ne_bytes(v.to_ne_bytes()))
            } else {
                self.cur.u32_at(base).map(i64::from)
            };
            let (Ok(tag), Ok(val)) = (
                tag,
                self.cur.addr_at(base.saturating_add(step / 2), self.elf64),
            ) else {
                trunc.push(Truncation::unread(
                    ElfTable::Dynamic,
                    format!(".dynamic unreadable at entry {i} of {count} (offset {base:#x})"),
                ));
                return;
            };
            if tag == 0 {
                return; // DT_NULL
            }
            out.push((tag, val));
        }
        trunc.push(Truncation::unread(
            ElfTable::Dynamic,
            format!(
                ".dynamic at {sh_offset:#x}+{sh_size:#x} reached the end of the declared table \
                 at entry {count} of {count} without DT_NULL, so the loader's table, which ends \
                 at DT_NULL, was not read whole"
            ),
        ));
    }

    /// Where the dynamic string table is, as `(offset, length)`, or `None` where the file
    /// has none to read.
    ///
    /// Computed once and handed to every [`Self::dyn_strings`] call, so the one note it can
    /// record lands once. It was pushed from inside `dyn_strings`, which `facts` calls
    /// three times, so the same sentence landed three times in `truncations`.
    ///
    /// `DT_STRTAB` first, translated through the containing `PT_LOAD`; `.dynstr` by name only
    /// when the dynamic table named no string table at all.
    fn dyn_strtab(
        &self,
        dyn_entries: &[(i64, u64)],
        trunc: &mut Vec<Truncation>,
    ) -> Option<(u64, u64)> {
        // The order is the one `dynamic` takes, in its sibling. Preferring the section would
        // let a crafted file point `.dynstr` at zeroed bytes while the real `DT_STRTAB` names
        // `libm.so.6`: `needed` would read `[""]`, and `as-needed`, whose detector asks
        // whether any entry starts with `libm.`, would conclude the linker had dropped the
        // unused library and report `on`. A false `on` from a forged section, on the one
        // input THREAT_MODEL.md treats as attacker-supplied. `readelf -d` takes the section's
        // reading, because it reads sections too; the loader does not.
        //
        // The fallback stays for a reason: without it `needed`, `rpath` and `runpath` would
        // all be empty for a section-header-stripped binary, and an empty `rpath` reads as
        // "no baked-in search path", a pass awarded for having read nothing.
        // The last entry of each tag, as `ld.so` stores it (`LOADER_SINGLE_TAGS`): the
        // repeat is recorded as the last read, so the last is what is read.
        let strtab_vaddr = dyn_entries
            .iter()
            .rfind(|(t, _)| *t == DT_STRTAB)
            .map(|(_, v)| *v);
        let from_segment = strtab_vaddr.and_then(|v| self.offset_of_vaddr(v));
        let located = match from_segment {
            Some(off) => {
                // `DT_STRSZ` is the table's own declared length. A file carrying
                // `DT_STRTAB` without it is missing a tag the loader also needs, so the
                // containing segment's remaining bytes is the bound in that case, not
                // the whole file: the same discipline `cstr_at` requires of every
                // caller. Both come back `None` only when `DT_STRTAB` resolves to a
                // vaddr `offset_of_vaddr` just placed inside a `PT_LOAD` segment and
                // `segment_remaining_at` then cannot find that same segment — not
                // reachable given the two share one containment check, but the table is
                // dropped with a reason recorded rather than read as empty, on the
                // chance that stops being true.
                let len = dyn_entries
                    .iter()
                    .rfind(|(t, _)| *t == DT_STRSZ)
                    .map(|(_, v)| *v)
                    .or_else(|| strtab_vaddr.and_then(|v| self.segment_remaining_at(v)));
                if let Some(len) = len {
                    Some((off, len))
                } else {
                    trunc.push(Truncation::unread(
                        ElfTable::DynStr,
                        format!(
                            "DT_STRTAB at {off:#x} has neither DT_STRSZ nor a containing \
                             PT_LOAD segment to bound it, so its strings were not read"
                        ),
                    ));
                    None
                }
            }
            None => self.dyn_strtab_by_name(dyn_entries, strtab_vaddr, trunc),
        };
        // Held whole before a string is read from it. `cstr_at` answers "" for an offset
        // past the end of the file, so a `PT_LOAD` whose `p_offset` lay past the end read
        // `needed` as `[""]` and recorded nothing: `as-needed` found no `libm.` in a list
        // of one empty name and published `on`.
        let (off, len) = located?;
        if let Err(why) = self.cur.slice(off, len) {
            trunc.push(Truncation::unread(
                ElfTable::DynStr,
                format!(
                    "the dynamic string table at {off:#x}+{len:#x} lies past the end of the \
                     file ({why}), so no DT_NEEDED, DT_RPATH or DT_RUNPATH string was read"
                ),
            ));
            return None;
        }
        Some((off, len))
    }

    /// `.dynstr` by name, for a dynamic table whose `DT_STRTAB` lies in no `PT_LOAD` or
    /// that carries no `DT_STRTAB` at all, or `None` beside a `dynstr` record where the
    /// section cannot be found and an entry names a string through it.
    ///
    /// The `None` was silent: a `DT_STRTAB` at an address no segment maps, in a file
    /// whose section names were stripped or could not be read, left `needed`, `rpath` and
    /// `runpath` empty with nothing recorded, so `as-needed` decided `on` and
    /// `rpath-absent` `off` over a string table the reader never located. Recorded when
    /// `DT_STRTAB` is present and unmapped whatever the entries, since the loader needs
    /// that table for every symbol it binds, and when it is absent only beside an entry
    /// that names a string, since a dynamic table with nothing to read through it lacks
    /// nothing. This is the one site for a `None` table: [`Self::dyn_strings`] relies on
    /// it and records nothing of its own for a table it was not handed.
    fn dyn_strtab_by_name(
        &self,
        dyn_entries: &[(i64, u64)],
        strtab_vaddr: Option<u64>,
        trunc: &mut Vec<Truncation>,
    ) -> Option<(u64, u64)> {
        if let Some(sh) = self.section_by_name(".dynstr") {
            return Some((sh.sh_offset, sh.sh_size));
        }
        let named: Vec<&str> = dyn_entries
            .iter()
            .filter(|(t, _)| DYN_STRING_TAGS.contains(t))
            .map(|(t, _)| dyn_tag_name(*t))
            .collect();
        let detail = match strtab_vaddr {
            Some(vaddr) => format!(
                "DT_STRTAB at vaddr {vaddr:#x} lies in no PT_LOAD segment and no .dynstr \
                 section could be found by name, so no DT_NEEDED, DT_RPATH or DT_RUNPATH \
                 string was read"
            ),
            None if !named.is_empty() => format!(
                ".dynamic carries {} but no DT_STRTAB, and no .dynstr section could be found \
                 by name, so no string it names was read",
                named.join(", ")
            ),
            None => return None,
        };
        trunc.push(Truncation::unread(ElfTable::DynStr, detail));
        None
    }

    /// The strings every `tag` entry names in the table [`Self::dyn_strtab`] located.
    ///
    /// An entry whose offset lies at or past the table's declared end names no string the
    /// table holds: it is recorded under `dynstr` and left out of the list. `cstr_at`
    /// answers "" for that offset, and a `DT_STRSZ` of 1 read `needed` as `[""]` with
    /// nothing recorded, which `as-needed` published as `on` and `rpath-absent` as a
    /// present search path. A `None` table beside an entry to read through it was
    /// recorded by [`Self::dyn_strtab_by_name`], once, so nothing is recorded here for
    /// the three tags it would have been recorded under.
    fn dyn_strings(
        &self,
        dyn_entries: &[(i64, u64)],
        tag: i64,
        strtab: Option<(u64, u64)>,
        trunc: &mut Vec<Truncation>,
    ) -> Vec<String> {
        let Some((strtab_off, strtab_len)) = strtab else {
            return Vec::new();
        };
        let mut out = Vec::new();
        // `DT_NEEDED` repeats by design; the search-path tags are single-valued, and the
        // loader's is the last (`LOADER_SINGLE_TAGS`), so only the last is listed.
        let single = tag == DT_RPATH || tag == DT_RUNPATH;
        let mut entries = dyn_entries.iter().filter(|(t, _)| *t == tag);
        let wanted: Vec<&(i64, u64)> = if single {
            entries.next_back().into_iter().collect()
        } else {
            entries.collect()
        };
        for (_, value) in wanted {
            match u32::try_from(*value) {
                Ok(off) if u64::from(off) < strtab_len => {
                    out.push(self.cur.cstr_at(strtab_off, off, strtab_len));
                }
                _ => trunc.push(Truncation::unread(
                    ElfTable::DynStr,
                    format!(
                        "{} string at offset {value:#x} lies past the {strtab_len:#x}-byte \
                         dynamic string table, so the entry was not read",
                        dyn_tag_name(tag)
                    ),
                )),
            }
        }
        out
    }

    /// The string table `sh_link` names for a symbol table, held whole, or `None` beside
    /// a `symbols` record of why its names cannot be resolved.
    ///
    /// An index past the end was always skipped; `0` was not, and `0` is `SHN_UNDEF`, the
    /// null section header, whose `sh_offset` is 0, so names were read from file offset
    /// zero, came back empty, were skipped one by one, and the table reported no symbols
    /// at all. Reproduced: zeroing `.dynsym`'s `sh_link` is a four-byte edit that leaves a
    /// file of identical length, parses cleanly, and flips `canary` to false and the eight
    /// `__*_chk` counts to zero. A symbol table whose names cannot be resolved is
    /// unreadable, and is recorded as such.
    ///
    /// The table is held whole before a name is read through it. `cstr_at` answers "" for
    /// an offset past the end of the file, and a `.strtab` whose `sh_offset` lay past the
    /// end read every symbol as unnamed: the table reported no symbols, `canary-emitted`
    /// decided `off` over a discriminating triple, and nothing was recorded.
    fn symbol_strtab(&self, sh: &Shdr, table: &str, trunc: &mut Vec<Truncation>) -> Option<&Shdr> {
        let link = self
            .shdrs
            .get(usize::try_from(sh.sh_link).unwrap_or(usize::MAX));
        let detail = match link {
            Some(link) if sh.sh_link != 0 && link.sh_type == SHT_STRTAB => {
                match self.cur.slice(link.sh_offset, link.sh_size) {
                    Ok(_) => return Some(link),
                    Err(why) => format!(
                        "{table}: its string table at {:#x}+{:#x} lies past the end of the \
                         file ({why}), so no symbol name can be resolved",
                        link.sh_offset, link.sh_size
                    ),
                }
            }
            Some(_) => format!(
                "{table}: sh_link {} does not name a string table, so its symbol names \
                 cannot be resolved",
                sh.sh_link
            ),
            None => format!(
                "{table}: sh_link {} is past the section-header table",
                sh.sh_link
            ),
        };
        trunc.push(Truncation::unread(ElfTable::Symbols, detail));
        None
    }

    /// A symbol table's label: its name where the file gave one, and its type where it
    /// did not. A file whose section names could not be read still has a symbol table of
    /// a known kind, and `SymbolFact::tables` and `ElfFacts::symbol_tables` say which.
    fn symbol_table_label(&self, idx: usize, sh: &Shdr) -> String {
        match self.shnames.get(idx).filter(|n| !n.is_empty()) {
            Some(name) => name.clone(),
            None if sh.sh_type == SHT_SYMTAB => "SHT_SYMTAB".to_owned(),
            None => "SHT_DYNSYM".to_owned(),
        }
    }

    /// A relocation section's label: its name where the file gave one, and its index where
    /// it did not.
    fn relocation_label(&self, idx: usize) -> String {
        self.shnames
            .get(idx)
            .filter(|n| !n.is_empty())
            .map_or_else(|| format!("relocation section [{idx}]"), Clone::clone)
    }

    /// The stride section `idx` is read at: `record`, its type's record size, with the
    /// `ignored` record [`record_stride`] leaves pushed where `sh_entsize` differs, and kept
    /// once among the walks by [`once_each_stride_record`] when the facts are assembled.
    ///
    /// The only reader of `sh_entsize`. The label is decided here from the index and the
    /// type (a symbol table on `symbols`, a relocation section on `relocations`), so the walks
    /// that read one section write equal records, of which the facts keep the first, and none
    /// can drop it.
    fn section_stride(
        &self,
        idx: usize,
        sh: &Shdr,
        record: NonZeroU64,
        trunc: &mut Vec<Truncation>,
    ) -> NonZeroU64 {
        let (label, table) = if sh.sh_type == SHT_SYMTAB || sh.sh_type == SHT_DYNSYM {
            (self.symbol_table_label(idx, sh), ElfTable::Symbols)
        } else {
            (self.relocation_label(idx), ElfTable::Relocations)
        };
        // A name two sections carry (a relocatable object's COMDAT copies) would merge their
        // records, so the index is added there. So it is for an unnamed symbol table, whose
        // label is its type and so another's too; an unnamed relocation section's label is
        // its index already.
        let indexed = match self.shnames.get(idx).filter(|n| !n.is_empty()) {
            Some(name) => self.shared_names.contains(name),
            None => table == ElfTable::Symbols,
        };
        let label = if indexed {
            format!("{label} [{idx}]")
        } else {
            label
        };
        let (step, differs) = record_stride(
            sh.sh_entsize,
            record,
            table,
            &format!("{label}: sh_entsize"),
        );
        trunc.extend(differs);
        step
    }

    /// The entry size and whole-entry count of symbol table `idx`, or `None` where the table
    /// is too small to hold one entry.
    ///
    /// A real symbol table always holds the null symbol at index 0, so a nonzero `sh_size`
    /// below one entry is a malformed table, not an empty one: read as zero entries it
    /// listed the table and reported no symbols from it with nothing recorded, which is
    /// the false absence a truncation record exists to name. A size that is not a multiple
    /// of the entry size is read to its last whole entry, and the trailing partial entry
    /// is recorded, since the bytes after it are a symbol the reader did not read.
    fn symbol_entries(
        &self,
        idx: usize,
        sh: &Shdr,
        table: &str,
        trunc: &mut Vec<Truncation>,
    ) -> Option<(u64, u64)> {
        // The record size, whatever `sh_entsize` says (`section_stride`). `Sym` is 24 bytes
        // on ELF64 and 16 on ELF32, and `sh_entsize` is meant to confirm that. A form before
        // the floor special-cased 0 and accepted 1..=23, so `sh_entsize = 1` made `count`
        // equal `sh_size` -- one "symbol" per byte instead of per record -- and each one called
        // `cstr_at`, whose NUL scan runs to the end of the file when the string table
        // holds no terminator. The product is quadratic: 200 KB of input took 4.2s, and
        // the fitted rate puts a 10 MB file at roughly three hours. It is pure CPU with a
        // flat 3.7 MB footprint, so unlike the header case nothing OOM-kills it -- it
        // simply never returns.
        let step = self.section_stride(idx, sh, symbol_record(self.elf64), trunc);
        // A `NonZeroU64` divisor: no zero entry size reaches here, so no arm reads one.
        let (count, partial) = (sh.sh_size / step, sh.sh_size % step);
        if sh.sh_size > 0 && count == 0 {
            trunc.push(Truncation::unread(
                ElfTable::Symbols,
                format!(
                    "{table}: sh_size {:#x} is below one {step}-byte entry, so the table \
                     holds not even the null symbol and was not read",
                    sh.sh_size
                ),
            ));
            return None;
        }
        if partial != 0 {
            trunc.push(Truncation::unread(
                ElfTable::Symbols,
                format!(
                    "{table}: sh_size {:#x} is {count} whole {step}-byte entries and \
                     {partial} trailing bytes, so the partial entry after symbol {count} \
                     was not read",
                    sh.sh_size
                ),
            ));
        }
        Some((step.get(), count))
    }

    /// The symbol tables the file has, beside the symbols read from them.
    ///
    /// One walk for both, so `ElfFacts::symbol_tables` names exactly the tables the
    /// symbols were read from: a table whose names cannot be resolved is listed and
    /// recorded in `trunc`, and a file with no `SHT_SYMTAB` or `SHT_DYNSYM` lists nothing
    /// and records nothing, since an absent table is the precondition's business.
    ///
    /// `SHT_SYMTAB` is read from its section header: the loader never reads it, and a
    /// header is the only way to it. The dynamic symbol table is another matter, and where
    /// a `PT_DYNAMIC` exists it is held to [`DynSymView`]: the loader reads the table
    /// `DT_SYMTAB` names, not whatever a `SHT_DYNSYM` header says, so a header aimed
    /// elsewhere (or a second header of the type) must not decide which symbols the object
    /// imports.
    fn symbols(
        &self,
        dyn_entries: &[(i64, u64)],
        dynstr: Option<(u64, u64)>,
        trunc: &mut Vec<Truncation>,
    ) -> (Vec<String>, BTreeMap<String, SymbolFact>) {
        let mut tables = Vec::new();
        let mut out: BTreeMap<String, SymbolFact> = BTreeMap::new();
        let view = self.dynsym_view(dyn_entries, dynstr, trunc);
        let mut loader_table_read = false;
        for (idx, sh) in self.shdrs.iter().enumerate() {
            if sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM {
                continue;
            }
            let table = self.symbol_table_label(idx, sh);
            // What the loader's view holds this header to: the count it must reach, and
            // the string table the names are read through, where the view has them.
            let mut floor = 0;
            let mut loader_strtab = None;
            if sh.sh_type == SHT_DYNSYM {
                match &view {
                    DynSymView::Sections => {}
                    DynSymView::Unreadable => continue,
                    DynSymView::Absent => {
                        trunc.push(Truncation::ignored(
                            ElfTable::Symbols,
                            format!(
                                "{table} was not read: the dynamic table names no DT_SYMTAB, \
                                 so the loader has no dynamic symbol table"
                            ),
                        ));
                        continue;
                    }
                    DynSymView::At {
                        offset,
                        floor: reach,
                        strtab,
                    } => {
                        if sh.sh_offset != *offset || loader_table_read {
                            trunc.push(Truncation::ignored(
                                ElfTable::Symbols,
                                format!(
                                    "{table} at {:#x} is not the table DT_SYMTAB names \
                                     ({offset:#x}), which the loader reads, so it was not read",
                                    sh.sh_offset
                                ),
                            ));
                            continue;
                        }
                        loader_table_read = true;
                        floor = *reach;
                        loader_strtab = *strtab;
                    }
                }
            }
            tables.push(table.clone());
            let Some((step, mut count)) = self.symbol_entries(idx, sh, &table, trunc) else {
                continue;
            };
            if count < floor {
                // The header claims a table shorter than the loader's hash and relocation
                // tables reach. Those can only undercount (a symbol no lookup finds and no
                // relocation names is in neither), so a longer claim stands and a shorter
                // one does not.
                trunc.push(Truncation::ignored(
                    ElfTable::Symbols,
                    format!(
                        "{table}: sh_size {:#x} holds {count} symbols and the dynamic hash \
                         and relocation tables reach {floor}, so their count was read",
                        sh.sh_size
                    ),
                ));
                count = floor;
            }
            // Names come through the header's link, as they always did, while the link
            // names the string table `DT_STRTAB` does. Where it names another, the
            // header's table is not the loader's and the loader's is read, with the
            // disagreement reported.
            let linked = self.linked_strtab_offset(sh);
            let strtab = match loader_strtab {
                Some(loader) if linked != Some(loader.0) => {
                    trunc.push(Truncation::ignored(
                        ElfTable::Symbols,
                        format!(
                            "{table}: sh_link {} is not the string table DT_STRTAB names \
                             ({:#x}), which the loader reads, so the names were read through \
                             DT_STRTAB",
                            sh.sh_link, loader.0
                        ),
                    ));
                    loader
                }
                _ => {
                    let Some(strtab) = self.symbol_strtab(sh, &table, trunc) else {
                        continue;
                    };
                    (strtab.sh_offset, strtab.sh_size)
                }
            };
            self.read_symbols(&table, sh.sh_offset, step, count, strtab, &mut out, trunc);
        }
        if let DynSymView::At { offset, .. } = &view
            && !loader_table_read
        {
            // No header of the type is the loader's table: those there are aimed elsewhere,
            // or there are none (a `.dynsym` header retyped away). Its length is not in the
            // file, since the hash table gives a lower bound only, so what the loader reads
            // cannot be read whole.
            trunc.push(Truncation::unread(
                ElfTable::Symbols,
                format!(
                    "no SHT_DYNSYM header lies at the {offset:#x} DT_SYMTAB names, and the \
                     length of the table the loader reads is not otherwise in the file"
                ),
            ));
        }
        (tables, out)
    }

    /// The file offset of the section a symbol header's `sh_link` names, where it names one.
    fn linked_strtab_offset(&self, sh: &Shdr) -> Option<u64> {
        if sh.sh_link == 0 {
            return None;
        }
        // An index past `usize` names no section, as one past the table does.
        let index = usize::try_from(sh.sh_link).unwrap_or(usize::MAX);
        self.shdrs.get(index).map(|l| l.sh_offset)
    }

    /// How the dynamic symbol table is reached: see [`DynSymView`].
    ///
    /// With a `PT_DYNAMIC`, the loader's table starts where `DT_SYMTAB` translates through
    /// `PT_LOAD` and is named by `DT_STRTAB`. A forged `SHT_DYNSYM` header (a moved offset,
    /// a second header) changed which symbols were read, and with them `__stack_chk_fail`
    /// and the fortify counts, for a table the loader never consults.
    ///
    /// **The length is not the hash table's.** `DT_GNU_HASH` and `DT_HASH` bound the
    /// symbols a lookup can find, and a symbol is indexed from a relocation without a
    /// lookup: the Fedora 44 x86_64 `7z` executable (it exports nothing) carries a
    /// `.gnu.hash` of one symbol over a `.dynsym` of 134 entries. Taken as the count it read 133
    /// imports as absent, which is the false absence this exists to prevent. So the hash
    /// tables give a floor, and the header's `sh_size` the length, where the header is at
    /// the loader's offset; a longer reach than the header claims is the header
    /// understating the table, and the reach is read.
    ///
    /// **The relocations are the floor an import has.** A hash floor of one bounds nothing
    /// for that `7z`: with its `.dynsym` header cut from 3216 bytes to 48 it read one symbol,
    /// no `__stack_chk_fail` and no `__memcpy_chk`, and recorded nothing. The loader resolves
    /// an import through the relocation that names its index, so every `r_sym` in
    /// `DT_RELA`, `DT_REL` and `DT_JMPREL` is an entry the table holds, and the highest one
    /// plus one joins the floor. An import the program uses is named by a relocation, so it
    /// lies under the floor whatever the header says. The residue is a header at the right
    /// offset that claims too many symbols, read as symbols as before, and a symbol no
    /// lookup finds and no relocation names, which is not one the loader binds.
    ///
    /// A table that cannot be located or whose hash tables cannot be read is `Unreadable`
    /// and recorded `unread`, which withholds the checks reading `symbols`: an `ignored`
    /// record would publish a verdict from the section's reading, the reading this exists
    /// to refuse. `Absent` and the headers that are not the loader's are `ignored`, since
    /// the facts read from the loader's view are whole.
    fn dynsym_view(
        &self,
        dyn_entries: &[(i64, u64)],
        dynstr: Option<(u64, u64)>,
        trunc: &mut Vec<Truncation>,
    ) -> DynSymView {
        // A file with no section headers has its symbol tables recorded `unread` by
        // `structural_truncations`, and with no `PT_DYNAMIC` no loader reads the object. One
        // with headers and none of type `SHT_DYNSYM` is held to the loader's view as any
        // other is (2026-10-20): where `DT_SYMTAB` names a table the view is `At`,
        // no header lies there, and `symbols` records the table `unread` as it does where
        // the headers are aimed elsewhere. The view was `Sections` with nothing recorded
        // before, so a `.dynsym` header retyped away read as an object with no dynamic
        // symbols beside a loader that binds them.
        if self.shdrs.is_empty() || !self.phdrs.iter().any(|p| p.p_type == PT_DYNAMIC) {
            return DynSymView::Sections;
        }
        let headers = self.shdrs.iter().any(|s| s.sh_type == SHT_DYNSYM);
        let value = |tag: i64| {
            dyn_entries
                .iter()
                .rfind(|(t, _)| *t == tag)
                .map(|(_, v)| *v)
        };
        let Some(symtab) = value(DT_SYMTAB) else {
            // A dynamic table that was cut short, or yielded nothing, may have lost the tag,
            // and the loader's table is then unlocatable rather than absent. Its own record
            // is the gate; the headers stay the reading they were, and the comparison that
            // could not be made is reported.
            let cut = trunc
                .iter()
                .any(|t| t.table == ElfTable::Dynamic && t.kind == TruncationKind::Unread);
            if cut || dyn_entries.is_empty() {
                // With headers of the type, they are the reading and the comparison that
                // could not be made is reported. With none, nothing reads the table the
                // loader may bind, so it is `unread`, not a reading of no dynamic symbols.
                trunc.push(if headers {
                    Truncation::ignored(
                        ElfTable::Symbols,
                        "the dynamic table was not read whole, so no SHT_DYNSYM header could \
                         be compared with DT_SYMTAB"
                            .to_owned(),
                    )
                } else {
                    Truncation::unread(
                        ElfTable::Symbols,
                        "the dynamic table was not read whole and no section header is \
                         SHT_DYNSYM, so whether DT_SYMTAB names a table the loader reads was \
                         not established"
                            .to_owned(),
                    )
                });
                return DynSymView::Sections;
            }
            return DynSymView::Absent;
        };
        let mut unreadable = |why: String| {
            trunc.push(Truncation::unread(ElfTable::Symbols, why));
            DynSymView::Unreadable
        };
        let Some(offset) = self.offset_of_vaddr(symtab) else {
            return unreadable(format!(
                "DT_SYMTAB at vaddr {symtab:#x} lies in no PT_LOAD segment, so the loader's \
                 dynamic symbol table was not located"
            ));
        };
        let step = symbol_record(self.elf64).get();
        let mut floor = 0;
        for (tag, name) in [(DT_GNU_HASH, "DT_GNU_HASH"), (DT_HASH, "DT_HASH")] {
            let Some(v) = value(tag) else { continue };
            let reach = if tag == DT_HASH {
                self.sysv_hash_count(v)
            } else {
                self.gnu_hash_count(v)
            };
            match reach {
                Ok(n) => floor = floor.max(n),
                Err(why) => return unreadable(format!("{name} {why}")),
            }
        }
        let stride_records = match self.relocation_reach(&value) {
            Ok((n, records)) => {
                floor = floor.max(n);
                records
            }
            Err(why) => return unreadable(why),
        };
        if let Err(why) = self.cur.slice(offset, floor.saturating_mul(step)) {
            return unreadable(format!(
                "the dynamic hash and relocation tables reach {floor} symbols at \
                 {offset:#x}, past the end of the file ({why})"
            ));
        }
        // After the last `unreadable`: a table that could not be counted is recorded
        // `unread`, which says more than an entry size read past.
        trunc.extend(stride_records);
        // The loader's string table, where `DT_STRTAB` maps; otherwise the header's link.
        let strtab = value(DT_STRTAB)
            .and_then(|v| self.offset_of_vaddr(v))
            .and(dynstr);
        DynSymView::At {
            offset,
            floor,
            strtab,
        }
    }

    /// The reach a `DT_GNU_HASH` table at `vaddr` implies, as a symbol count: the table's
    /// highest bucket names the last chain to walk, and the chain ends at the entry with
    /// its low bit set. A table with no populated bucket reaches `symoffset` symbols.
    fn gnu_hash_count(&self, vaddr: u64) -> Result<u64, String> {
        let at = self
            .offset_of_vaddr(vaddr)
            .ok_or_else(|| format!("at vaddr {vaddr:#x} lies in no PT_LOAD segment"))?;
        let word = |off: u64| {
            self.cur
                .u32_at(off)
                .map(u64::from)
                .map_err(|why| format!("is unreadable at {off:#x} ({why})"))
        };
        let nbuckets = word(at)?;
        let symoffset = word(at.saturating_add(4))?;
        let bloom = word(at.saturating_add(8))?;
        let bloom_bytes = bloom.saturating_mul(if self.elf64 { 8 } else { 4 });
        let buckets = at.saturating_add(16).saturating_add(bloom_bytes);
        let bucket_bytes = nbuckets.saturating_mul(4);
        let chains = buckets.saturating_add(bucket_bytes);
        self.cur
            .slice(buckets, bucket_bytes)
            .map_err(|why| format!("has buckets past the end of the file ({why})"))?;
        let mut last = 0;
        for i in 0..nbuckets {
            last = last.max(word(buckets.saturating_add(i.saturating_mul(4)))?);
        }
        if last == 0 {
            return Ok(symoffset);
        }
        if last < symoffset {
            return Err(format!(
                "has a bucket naming symbol {last}, below its symoffset {symoffset}"
            ));
        }
        let mut idx = last;
        loop {
            let at = chains.saturating_add(idx.saturating_sub(symoffset).saturating_mul(4));
            if word(at)? & 1 != 0 {
                return Ok(idx.saturating_add(1));
            }
            idx = idx.saturating_add(1);
        }
    }

    /// The symbol count the dynamic relocation tables reach: one past the highest `r_sym`
    /// that `DT_RELA`, `DT_REL` or `DT_JMPREL` names, or 0 where none names a symbol.
    ///
    /// An entry is read at the record size whatever `DT_RELAENT` or `DT_RELENT` says
    /// ([`record_stride`]), and a tag that says otherwise is returned beside the reach as an
    /// `ignored` record on the dynamic table; `DT_JMPREL` takes its form from `DT_PLTREL`.
    /// `r_info` follows `r_offset` in both forms. Its symbol index is the
    /// high 32 bits on ELF64 and the high 24 on ELF32, except on 64-bit MIPS, whose field
    /// is a 32-bit `r_sym` followed by four type bytes in file order: the high word on a
    /// big-endian object and the low word on a little-endian one, as read.
    fn relocation_reach(
        &self,
        value: &dyn Fn(i64) -> Option<u64>,
    ) -> Result<(u64, Vec<Truncation>), String> {
        let word: u64 = if self.elf64 { 8 } else { 4 };
        let rel = relocation_record(self.elf64, false);
        let rela = relocation_record(self.elf64, true);
        let jmprel_form = match value(DT_PLTREL) {
            Some(v) if i64::try_from(v) == Ok(DT_RELA) => {
                Some((rela, (value(DT_RELAENT), "DT_RELAENT")))
            }
            Some(v) if i64::try_from(v) == Ok(DT_REL) => {
                Some((rel, (value(DT_RELENT), "DT_RELENT")))
            }
            _ => None,
        };
        let mut tables = vec![
            (
                "DT_RELA",
                "DT_RELASZ",
                value(DT_RELA),
                value(DT_RELASZ),
                rela,
                (value(DT_RELAENT), "DT_RELAENT"),
            ),
            (
                "DT_REL",
                "DT_RELSZ",
                value(DT_REL),
                value(DT_RELSZ),
                rel,
                (value(DT_RELENT), "DT_RELENT"),
            ),
        ];
        match (value(DT_JMPREL), jmprel_form) {
            (None, _) => {}
            (Some(_), None) => {
                return Err(
                    "DT_JMPREL has no DT_PLTREL naming DT_RELA or DT_REL, so its entries \
                     could not be read"
                        .to_owned(),
                );
            }
            (Some(at), Some((size, ent))) => {
                tables.push((
                    "DT_JMPREL",
                    "DT_PLTRELSZ",
                    Some(at),
                    value(DT_PLTRELSZ),
                    size,
                    ent,
                ));
            }
        }
        let mips64le = self.elf64 && self.e_machine == EM_MIPS && self.cur.little;
        let mut reach = 0;
        let mut records = Vec::new();
        for (name, size_name, at, len, min_ent, (ent, ent_name)) in tables {
            let Some(vaddr) = at else { continue };
            // The loader takes the table's length from the size tag and has no other; a
            // table without one is a length no reading can bound.
            let Some(len) = len else {
                return Err(format!(
                    "{name} has no {size_name}, so its entries could not be read"
                ));
            };
            let off = self
                .offset_of_vaddr(vaddr)
                .ok_or_else(|| format!("{name} at vaddr {vaddr:#x} lies in no PT_LOAD segment"))?;
            self.cur.slice(off, len).map_err(|why| {
                format!("{name} at {off:#x}+{len:#x} lies past the end of the file ({why})")
            })?;
            // A table with no entry-size tag is read at the record size, as one with a tag is.
            let (ent, differs) = record_stride(
                ent.unwrap_or(min_ent.get()),
                min_ent,
                ElfTable::Dynamic,
                &format!("{name}: {ent_name}"),
            );
            records.extend(differs);
            let count = len / ent;
            let ent = ent.get();
            for i in 0..count {
                let info_at = off
                    .saturating_add(i.saturating_mul(ent))
                    .saturating_add(word);
                let info = self
                    .cur
                    .addr_at(info_at, self.elf64)
                    .map_err(|why| format!("{name} is unreadable at {info_at:#x} ({why})"))?;
                let sym = if mips64le {
                    info & 0xffff_ffff
                } else if self.elf64 {
                    info >> 32
                } else {
                    info >> 8
                };
                if sym > 0 {
                    reach = reach.max(sym.saturating_add(1));
                }
            }
        }
        Ok((reach, records))
    }

    /// The reach a `DT_HASH` table at `vaddr` names: its `nchain`, one chain slot per
    /// symbol the table covers.
    fn sysv_hash_count(&self, vaddr: u64) -> Result<u64, String> {
        let at = self
            .offset_of_vaddr(vaddr)
            .ok_or_else(|| format!("at vaddr {vaddr:#x} lies in no PT_LOAD segment"))?;
        self.cur
            .u32_at(at.saturating_add(4))
            .map(u64::from)
            .map_err(|why| format!("is unreadable ({why})"))
    }

    /// `count` symbols of `step` bytes at `sym_off`, named through the string table at
    /// `(strtab_off, strtab_len)`, folded into `out`.
    #[allow(
        clippy::too_many_arguments,
        reason = "a symbol read is two tables, each an offset and a size, a label and the \
                  two accumulators; a struct for the two call sites would only rename them"
    )]
    fn read_symbols(
        &self,
        table: &str,
        sym_off: u64,
        step: u64,
        count: u64,
        (strtab_off, strtab_len): (u64, u64),
        out: &mut BTreeMap<String, SymbolFact>,
        trunc: &mut Vec<Truncation>,
    ) {
        for i in 0..count {
            let base = sym_off.saturating_add(i.saturating_mul(step));
            let Ok(name_off) = self.cur.u32_at(base) else {
                trunc.push(Truncation::unread(
                    ElfTable::Symbols,
                    format!("{table} unreadable at symbol {i} of {count}"),
                ));
                break;
            };
            // st_shndx sits at a different offset in the two widths.
            let shndx_at = if self.elf64 { 6 } else { 14 };
            let Ok(shndx) = self.cur.u16_at(base.saturating_add(shndx_at)) else {
                trunc.push(Truncation::unread(
                    ElfTable::Symbols,
                    format!("{table} unreadable at symbol {i} of {count} (st_shndx)"),
                ));
                break;
            };
            // An offset at or past the table's declared end names no string the table
            // holds, and is a stop: the entries after it are read through the same
            // table, and "" for each is the false absence this record exists to name.
            if u64::from(name_off) >= strtab_len {
                trunc.push(Truncation::unread(
                    ElfTable::Symbols,
                    format!(
                        "{table}: symbol {i} of {count} names string offset {name_off:#x} \
                         past its {strtab_len:#x}-byte string table, so the names from it on \
                         were not read",
                    ),
                ));
                break;
            }
            let raw = self.cur.cstr_at(strtab_off, name_off, strtab_len);
            // The two string tables spell one symbol two ways. `.dynstr` holds the
            // bare name, and the version it binds to lives in `.gnu.version_r`, which
            // `readelf` appends at display time. `.strtab` stores the version in the
            // name itself: `__stack_chk_fail@GLIBC_2.4` for a reference,
            // `name@@VERSION` for a default definition. Matched raw, the `.symtab`
            // spelling never equalled the watched name, so every fortified binary
            // reported the canary and the `__*_chk` symbols in `.dynsym` alone and
            // counted `symbol_count` over both spellings. The key is the name before
            // the first `@`; the spelling is kept in `versioned`. No C identifier
            // carries `@`, so in what a compiler writes nothing else is cut. A `.dynsym`
            // name given an `@` by hand is cut too: the assumption
            // `dynamic-symbol-names-carry-no-version` in `report::ASSUMPTIONS`.
            let (name, versioned) = match raw.split_once('@') {
                Some((bare, _)) => (bare.to_owned(), Some(raw)),
                None => (raw, None),
            };
            if name.is_empty() {
                continue;
            }
            let entry = out.entry(name).or_insert_with(|| SymbolFact {
                defined: false,
                tables: Vec::new(),
                versioned: Vec::new(),
            });
            if shndx != 0 {
                entry.defined = true;
            }
            if !entry.tables.iter().any(|t| t == table) {
                entry.tables.push(table.to_owned());
            }
            if let Some(spelling) = versioned
                && !entry.versioned.contains(&spelling)
            {
                entry.versioned.push(spelling);
            }
        }
    }

    /// The GNU notes, read through the headers the loader reads: the `PT_GNU_PROPERTY`
    /// segment, `PT_NOTE` where there is none, and `SHT_NOTE` sections only where there are
    /// no program headers at all. Within them the walk is the reader's own, and where it
    /// differs from the kernel's is in `report::ASSUMPTIONS`: `one-property-note-per-object`,
    /// `note-segments-align-to-four-or-eight` and `property-note-name-size-is-four`.
    ///
    /// **The segment wins**, the rule `dynamic()` follows for `.dynamic` and for the same
    /// reason. `ld.so` and the kernel's `parse_elf_properties` consult program headers and
    /// never a section header, so a section-first walk measured whatever bytes a crafted
    /// header pointed at: a gcc 16.1.1 `-fcf-protection=none` binary whose
    /// `.note.gnu.property` header was aimed at an appended `IBT|SHSTK` note, program headers
    /// untouched, still ran and read `x86_ibt` and `x86_shstk` true while the
    /// `GNU_PROPERTY` segment carried neither. A section whose bytes no note segment covers
    /// is not read and is recorded as `ignored`: the facts are whole, from the segments.
    /// Containment rather than equality, because a section sits inside the `PT_NOTE` that
    /// groups it with its neighbours.
    ///
    /// Sections are the view only where the file has no program headers: a relocatable
    /// object, which chard reads too, has no loader view and its sections are all there is.
    /// A file with program headers and no note segment has no note the loader reads, so a
    /// note section in it is dropped, not rescued. A file stripped of section headers has
    /// nothing to drop and is read through its segments, as before.
    ///
    /// **`PT_GNU_PROPERTY` wins over `PT_NOTE`**, the same rule one level down. Where a file
    /// has a `PT_GNU_PROPERTY` segment, the kernel's `parse_elf_properties` and glibc's
    /// `_dl_process_pt_gnu_property` read the property note there and nowhere else, so the
    /// notes are read from that segment alone. A `PT_NOTE` is read only in a file without
    /// one, as a linker before `PT_GNU_PROPERTY` existed wrote it. Reading both measured a
    /// note no loader reads: the same `-fcf-protection=none` binary with `PT_GNU_PROPERTY`
    /// untouched and its first `PT_NOTE` repointed at an appended `IBT|SHSTK` note ran, and
    /// read `x86_ibt` and `x86_shstk` true. A property note a `PT_NOTE` holds outside the
    /// property segment is recorded as `ignored`, as a stray section is. A stop in that
    /// walk is not recorded: it withholds nothing, and the ordinary file stops there. 107 of
    /// 3958 ELF files under `/usr` on Fedora 44 x86_64 (samba's libraries among them) carry
    /// one 8-aligned `PT_NOTE` over `.note.gnu.property` and two 4-aligned notes, which a walk
    /// at the segment's alignment cannot step through, while `PT_GNU_PROPERTY` reads whole.
    ///
    /// The two segment types often cover the same bytes (`PT_GNU_PROPERTY` inside a `PT_NOTE`
    /// as `lld` groups them), so a note is kept once, by where its descriptor sits; a second
    /// copy would publish a count of two for a type a linker wrote once.
    ///
    /// `trunc` records a note table the walk could not finish. Every stop in `parse_notes`
    /// was a silent `break` once: a note table cut mid-way yielded the notes before the cut
    /// and nothing else, so a property note past it read as an object with no CET, BTI or GCS
    /// marking at all, which is the false `absent` the typed truncation exists to name.
    fn notes(&self, trunc: &mut Vec<Truncation>) -> Vec<Note> {
        let mut out: Vec<Note> = Vec::new();
        let segments: Vec<(u64, u64)> = self
            .phdrs
            .iter()
            .filter(|p| p.p_type == PT_NOTE || p.p_type == PT_GNU_PROPERTY)
            .map(|p| (p.p_offset, p.p_filesz))
            .collect();
        if self.phdrs.is_empty() {
            for sh in self.shdrs.iter().filter(|s| s.sh_type == SHT_NOTE) {
                let align = note_alignment(sh.sh_addralign);
                out.extend(self.parse_notes(sh.sh_offset, sh.sh_size, align, trunc));
            }
            return out;
        }
        let property_segment = self.phdrs.iter().any(|p| p.p_type == PT_GNU_PROPERTY);
        for p in self
            .phdrs
            .iter()
            .filter(|p| p.p_type == PT_GNU_PROPERTY || (!property_segment && p.p_type == PT_NOTE))
        {
            let align = note_alignment(p.p_align);
            for note in self.parse_notes(p.p_offset, p.p_filesz, align, trunc) {
                if !out.iter().any(|n| n.desc_off == note.desc_off) {
                    out.push(note);
                }
            }
        }
        if property_segment {
            for p in self.phdrs.iter().filter(|p| p.p_type == PT_NOTE) {
                let align = note_alignment(p.p_align);
                for note in self.parse_notes(p.p_offset, p.p_filesz, align, &mut Vec::new()) {
                    if note.name == "GNU"
                        && note.ntype == NT_GNU_PROPERTY_TYPE_0
                        && !out.iter().any(|n| n.desc_off == note.desc_off)
                    {
                        trunc.push(Truncation::ignored(
                            ElfTable::Notes,
                            format!(
                                "property note at {:#x}+{:#x} lies in a PT_NOTE outside every \
                                 PT_GNU_PROPERTY segment and was not read; the loader reads \
                                 PT_GNU_PROPERTY, so that segment is what was measured",
                                note.desc_off, note.desc_len
                            ),
                        ));
                    }
                }
            }
        }
        // Only an allocated note section claims to be loaded, so only one of those outside
        // the note segments is a view that disagrees with the loader's. A non-allocated note
        // is never mapped and never was a loader view: annobin's `.gnu.build.attributes`,
        // which Fedora's crt objects carry into every program linked there, is one, and
        // recording it would put a warning on every artifact while saying nothing.
        for sh in self
            .shdrs
            .iter()
            .filter(|s| s.sh_type == SHT_NOTE && s.sh_size > 0 && s.sh_flags & SHF_ALLOC != 0)
        {
            let (off, size) = (sh.sh_offset, sh.sh_size);
            let end = off.saturating_add(size);
            let contained = segments
                .iter()
                .any(|(p_off, p_size)| off >= *p_off && end <= p_off.saturating_add(*p_size));
            if !contained {
                // `Ignored`: the facts are whole, read from the segments. Recorded as
                // unread it would let the forged view withhold the measurement it was
                // dropped in order to protect.
                trunc.push(Truncation::ignored(
                    ElfTable::Notes,
                    format!(
                        "SHT_NOTE section at {off:#x}+{size:#x} lies outside every PT_NOTE and \
                         PT_GNU_PROPERTY segment and was not read; the loader reads the \
                         segments, so the segments are what was measured"
                    ),
                ));
            }
        }
        out
    }

    /// The notes in one table, stopping at the first the file does not hold whole.
    ///
    /// A note is held whole when its header words are readable and its descriptor ends
    /// inside both the table and the file. The second bound is the one that matters for
    /// a cut file: a table declared past the end of the file has an `end` past the end
    /// of the file, and a note whose name is cut but whose header was readable would
    /// otherwise be pushed under a name that is not `GNU` and never decoded, leaving the
    /// property bits false with nothing recorded.
    fn parse_notes(
        &self,
        base: u64,
        len: u64,
        align: u64,
        trunc: &mut Vec<Truncation>,
    ) -> Vec<Note> {
        let mut out = Vec::new();
        let end = base.saturating_add(len);
        let file_end = u64::try_from(self.cur.data.len()).unwrap_or(u64::MAX);
        let mut pos = base;
        let mut stop = |pos: u64, why: &str| {
            trunc.push(Truncation::unread(
                ElfTable::Notes,
                format!("note table at {base:#x}+{len:#x}: {why} at {pos:#x}"),
            ));
        };
        while pos.saturating_add(12) <= end {
            let (Ok(namesz), Ok(descsz), Ok(ntype)) = (
                self.cur.u32_at(pos),
                self.cur.u32_at(pos.saturating_add(4)),
                self.cur.u32_at(pos.saturating_add(8)),
            ) else {
                stop(pos, "a note header lies past the end of the file");
                break;
            };
            let name = if namesz == 0 {
                String::new()
            } else {
                self.cur
                    .cstr_at(pos.saturating_add(12), 0, u64::from(namesz))
            };
            // The padding rule this module's header warns about: align the
            // absolute descriptor offset, measured from the note's own start.
            let Some(rel) = align_up(12u64.saturating_add(u64::from(namesz)), align) else {
                stop(pos, "a note's name length overflows the descriptor offset");
                break;
            };
            let desc_off = pos.saturating_add(rel);
            let desc_len = u64::from(descsz);
            let note_end = desc_off.saturating_add(desc_len);
            if note_end > end || note_end > file_end {
                stop(
                    pos,
                    "a note's descriptor runs past the end of the table or the file",
                );
                break;
            }
            out.push(Note {
                name,
                ntype,
                desc_off,
                desc_len,
            });
            let Some(desc_pad) = align_up(desc_len, align) else {
                stop(pos, "a note's descriptor length overflows the next offset");
                break;
            };
            let next = desc_off.saturating_add(desc_pad);
            if next <= pos {
                // No forward progress: malformed, so the walk stops rather than spins.
                stop(pos, "a note advances the walk nowhere");
                break;
            }
            pos = next;
        }
        out
    }

    /// `pr_type -> (merged word, notes seen)` from every `NT_GNU_PROPERTY_TYPE_0` note.
    ///
    /// A type that names a feature word on this machine is AND-reduced across notes,
    /// the linker's rule for `*_FEATURE_1_AND` applied once more; `gnu_property_notes`
    /// says why a second note is counted. Every other type keeps the first word seen and
    /// is never decoded: an `x86` `ISA_1_USED` is an OR, a type in the processor range
    /// on a machine this reader does not know is anything at all, and `facts` reads
    /// neither.
    ///
    /// `trunc` records a descriptor the walk could not finish. `parse_notes` holds every
    /// note it returns whole, so a stop here is reachable only through a property word past
    /// the end of the file; every stop here is recorded on the same rule as `parse_notes`,
    /// where each was a silent `break`. A property whose data runs past its descriptor inside
    /// the file is read, not stopped: the assumption `property-word-lies-in-its-descriptor`
    /// in `report::ASSUMPTIONS`.
    fn gnu_properties(&self, trunc: &mut Vec<Truncation>) -> BTreeMap<u32, Property> {
        let mut props: BTreeMap<u32, Property> = BTreeMap::new();
        let align: u64 = if self.elf64 { 8 } else { 4 };
        for note in self.notes(trunc) {
            if note.name != "GNU" || note.ntype != NT_GNU_PROPERTY_TYPE_0 {
                continue;
            }
            let end = note.desc_off.saturating_add(note.desc_len);
            let mut pos = note.desc_off;
            let mut stop = |pos: u64, why: &str| {
                trunc.push(Truncation::unread(
                    ElfTable::Notes,
                    format!(
                        "property note at {:#x}+{:#x}: {why} at {pos:#x}",
                        note.desc_off, note.desc_len
                    ),
                ));
            };
            while pos.saturating_add(8) <= end {
                let (Ok(pr_type), Ok(pr_datasz)) =
                    (self.cur.u32_at(pos), self.cur.u32_at(pos.saturating_add(4)))
                else {
                    stop(pos, "a property header lies past the end of the file");
                    break;
                };
                let data_off = pos.saturating_add(8);
                let feature_word = self.feature_word_type(pr_type);
                // A feature word is a 4-byte bitmap and is decoded only at that width;
                // one of any other width is recorded as present with value 0 rather
                // than guessed. clang 7.0.1 under `-fcf-protection` writes
                // `X86_FEATURE_1_AND` with `pr_datasz` 8, which readelf prints as
                // `<corrupt length: 0x8>` and ld 2.31.1 reports as a corrupt x86 feature
                // size while keeping the note; reading its first word published
                // `cet-marked` `on` for a marking neither tool accepts. A word the file
                // does not hold is a stop, since `0` is the reading that says every
                // feature is off. That a word of another width reads as no feature, with
                // nothing recorded, is `feature-word-is-four-bytes` in `report::ASSUMPTIONS`.
                let value = if feature_word && pr_datasz != 4 {
                    0
                } else if pr_datasz >= 4 {
                    let Ok(word) = self.cur.u32_at(data_off) else {
                        stop(data_off, "a property word lies past the end of the file");
                        break;
                    };
                    word
                } else {
                    0
                };
                props
                    .entry(pr_type)
                    .and_modify(|p| {
                        p.notes = p.notes.saturating_add(1);
                        if feature_word {
                            p.value &= value;
                        }
                    })
                    .or_insert(Property { value, notes: 1 });
                let Some(pad) = align_up(u64::from(pr_datasz), align) else {
                    stop(pos, "a property's data length overflows the next offset");
                    break;
                };
                let next = data_off.saturating_add(pad);
                if next <= pos {
                    stop(pos, "a property advances the walk nowhere");
                    break;
                }
                pos = next;
            }
        }
        props
    }

    /// Is `pr_type` a feature word this reader decodes on this object's machine?
    ///
    /// The machine is part of the question. `0xc0000002` is `X86_FEATURE_1_AND` on
    /// `EM_386` and `EM_X86_64` and nothing anywhere else; `0xc0000000` is
    /// `AARCH64_FEATURE_1_AND` on `EM_AARCH64` and, on x86, the pre-2.32 binutils
    /// spelling of an ISA bitmap. Below `GNU_PROPERTY_LOPROC` no type is a feature word.
    fn feature_word_type(&self, pr_type: u32) -> bool {
        if pr_type < GNU_PROPERTY_LOPROC {
            return false;
        }
        matches!(
            (self.e_machine, pr_type),
            (EM_386 | EM_X86_64, GNU_PROPERTY_X86_FEATURE_1_AND)
                | (EM_AARCH64, GNU_PROPERTY_AARCH64_FEATURE_1_AND)
        )
    }

    /// The decoded feature word for `pr_type`, or 0 where this machine defines none.
    fn feature_word(&self, props: &BTreeMap<u32, Property>, pr_type: u32) -> u32 {
        if !self.feature_word_type(pr_type) {
            return 0;
        }
        props.get(&pr_type).map_or(0, |p| p.value)
    }

    /// [`ElfFacts::data_in_code_pages`]: the allocated, non-code sections with bytes in a
    /// page an executable `PT_LOAD` maps, the page being the segment's `p_align` and never
    /// less than [`MIN_PAGE`].
    fn data_in_code_pages(&self) -> Option<Vec<String>> {
        // A `p_align` of 0 or 1 says the segment has no alignment requirement, and one that
        // is not a power of two is malformed; both are read at the floor, the smallest page
        // a kernel maps, as is any alignment below it.
        let pages: Vec<(u64, u64)> = self
            .phdrs
            .iter()
            .filter(|p| p.p_type == PT_LOAD && p.p_flags & PF_X != 0)
            .map(|p| {
                let align = if p.p_align.is_power_of_two() {
                    p.p_align.max(MIN_PAGE)
                } else {
                    MIN_PAGE
                };
                // `align` is a power of two, so the mask rounds down and the next multiple
                // rounds up; a range that would round past the end of the address space is
                // held at its end.
                let start = p.p_offset & !align.saturating_sub(1);
                let end = p.p_offset.saturating_add(p.p_filesz);
                let end = end.checked_next_multiple_of(align).unwrap_or(u64::MAX);
                (start, end)
            })
            .collect();
        let allocated = |sh: &&Shdr| sh.sh_flags & SHF_ALLOC != 0;
        if pages.is_empty() || !self.shdrs.iter().any(|sh| allocated(&sh)) {
            return None;
        }
        let mut found = Vec::new();
        for (i, sh) in self.shdrs.iter().enumerate() {
            let name = self.shnames.get(i).map_or("", String::as_str);
            let data = allocated(&sh)
                && sh.sh_flags & SHF_EXECINSTR == 0
                && sh.sh_type != SHT_NOBITS
                && sh.sh_size > 0
                && name != BUILD_ID_SECTION;
            if !data {
                continue;
            }
            let end = sh.sh_offset.saturating_add(sh.sh_size);
            if pages.iter().any(|&(lo, hi)| sh.sh_offset < hi && end > lo) {
                // A section whose name could not be read is named by its index, so the
                // reading still says which header it was.
                let named = if name.is_empty() {
                    format!("[{i}]")
                } else {
                    name.to_owned()
                };
                if !found.contains(&named) {
                    found.push(named);
                }
            }
        }
        Some(found)
    }

    /// [`ElfFacts::code_relocations`]: every named relocation in a section that patches
    /// code, on a relocatable object with a section-header table.
    ///
    /// A section the walk cannot follow, or stops in, is recorded as an `unread`
    /// [`ElfTable::Relocations`] entry and the walk goes on to the next section, so a cut
    /// table keeps the entries read before the cut beside a record saying the list is
    /// partial. A relocation section whose target is not code is skipped without a read,
    /// so a fault in one is not recorded: nothing reads it.
    fn code_relocations(&self, trunc: &mut Vec<Truncation>) -> Option<Vec<String>> {
        if self.e_type != ET_REL || self.shdrs.is_empty() {
            return None;
        }
        let mut found = BTreeSet::new();
        for (idx, sh) in self.shdrs.iter().enumerate() {
            let rela = match sh.sh_type {
                SHT_RELA => true,
                SHT_REL => false,
                _ => continue,
            };
            let label = self.relocation_label(idx);
            let Some(target) = self
                .shdrs
                .get(usize::try_from(sh.sh_info).unwrap_or(usize::MAX))
            else {
                trunc.push(Truncation::unread(
                    ElfTable::Relocations,
                    format!(
                        "{label}: sh_info {} is past the section-header table, so the section \
                         its entries patch is unknown and they were not read",
                        sh.sh_info
                    ),
                ));
                continue;
            };
            if target.sh_flags & SHF_EXECINSTR == 0 {
                continue;
            }
            let step = self.section_stride(idx, sh, relocation_record(self.elf64, rela), trunc);
            let names = self.relocation_names(sh, trunc);
            let mut stop = |detail: String| {
                trunc.push(Truncation::unread(
                    ElfTable::Relocations,
                    format!("{label}: {detail}"),
                ));
            };
            match names {
                Ok(tables) => {
                    self.code_relocation_entries(sh, step, &tables, &mut stop, &mut found);
                }
                Err(why) => stop(why),
            }
        }
        Some(found.into_iter().collect())
    }

    /// The symbol table a relocation section's `sh_link` names and the string table that
    /// table's `sh_link` names, held whole, or why an entry's symbol cannot be named.
    fn relocation_names(
        &self,
        sh: &Shdr,
        trunc: &mut Vec<Truncation>,
    ) -> std::result::Result<RelocationNames<'_>, String> {
        let link = usize::try_from(sh.sh_link).unwrap_or(usize::MAX);
        let symtab = self
            .shdrs
            .get(link)
            .filter(|s| s.sh_type == SHT_SYMTAB || s.sh_type == SHT_DYNSYM)
            .ok_or_else(|| {
                format!(
                    "sh_link {} does not name a symbol table, so no entry's symbol can be \
                     named",
                    sh.sh_link
                )
            })?;
        let strtab = self
            .shdrs
            .get(usize::try_from(symtab.sh_link).unwrap_or(usize::MAX))
            .filter(|s| s.sh_type == SHT_STRTAB)
            .filter(|s| self.cur.slice(s.sh_offset, s.sh_size).is_ok())
            .ok_or_else(|| {
                format!(
                    "its symbol table's sh_link {} names no string table the file holds, \
                     so no entry's symbol can be named",
                    symtab.sh_link
                )
            })?;
        let sym_step = self.section_stride(link, symtab, symbol_record(self.elf64), trunc);
        Ok(RelocationNames {
            symtab,
            strtab,
            sym_step: sym_step.get(),
            sym_count: symtab.sh_size / sym_step,
        })
    }

    /// The entries of one relocation section that patches code, read `step` bytes apart (the
    /// record size, from [`record_stride`]), each with a named symbol added to `found` as
    /// `TYPE SYMBOL`; a stop is handed to `stop` and ends the section.
    fn code_relocation_entries(
        &self,
        sh: &Shdr,
        step: NonZeroU64,
        names: &RelocationNames<'_>,
        stop: &mut dyn FnMut(String),
        found: &mut BTreeSet<String>,
    ) {
        let (count, partial) = (sh.sh_size / step, sh.sh_size % step);
        let step = step.get();
        if partial != 0 {
            stop(format!(
                "sh_size {:#x} is {count} whole {step}-byte entries and a partial one, \
                 which was not read",
                sh.sh_size
            ));
        }
        let (symtab, strtab, sym_count) = (names.symtab, names.strtab, names.sym_count);
        for i in 0..count {
            let base = sh.sh_offset.saturating_add(i.saturating_mul(step));
            let info = if self.elf64 {
                self.cur.u64_at(base.saturating_add(8))
            } else {
                self.cur.u32_at(base.saturating_add(4)).map(u64::from)
            };
            let Ok(info) = info else {
                stop(format!("unreadable at entry {i} of {count}"));
                return;
            };
            let (sym, kind) = if self.elf64 {
                (info >> 32, info & 0xffff_ffff)
            } else {
                (info >> 8, info & 0xff)
            };
            if sym == 0 {
                continue;
            }
            if sym >= sym_count {
                stop(format!(
                    "entry {i} of {count} names symbol {sym}, past its symbol table of \
                     {sym_count}, so the entries from it on were not read"
                ));
                return;
            }
            let at = symtab
                .sh_offset
                .saturating_add(sym.saturating_mul(names.sym_step));
            let Ok(name_off) = self.cur.u32_at(at) else {
                stop(format!(
                    "entry {i} of {count} names symbol {sym}, which the file does not hold"
                ));
                return;
            };
            if u64::from(name_off) >= strtab.sh_size {
                stop(format!(
                    "entry {i} of {count} names symbol {sym}, whose name offset \
                     {name_off:#x} is past its {:#x}-byte string table",
                    strtab.sh_size
                ));
                return;
            }
            let mut name = self.cur.cstr_at(strtab.sh_offset, name_off, strtab.sh_size);
            if name.is_empty() {
                match self.section_symbol_label(at) {
                    Ok(Some(label)) => name = label,
                    Ok(None) => continue,
                    Err(why) => {
                        stop(format!("entry {i} of {count} names symbol {sym}, {why}"));
                        return;
                    }
                }
            }
            // st_other's low two bits; a section symbol is local and carries none.
            let other_at = at.saturating_add(if self.elf64 { 5 } else { 13 });
            let Ok([other]) = self.cur.slice(other_at, 1) else {
                stop(format!(
                    "entry {i} of {count} names symbol {sym}, whose st_other the file does \
                     not hold"
                ));
                return;
            };
            let visibility = other & 0x3;
            let kind = u32::try_from(kind).unwrap_or(u32::MAX);
            let kind = reloc_type_name(self.e_machine, kind);
            found.insert(match visibility_label(visibility) {
                Some(vis) if !name.starts_with('[') => format!("{kind} {name} {vis}"),
                _ => format!("{kind} {name}"),
            });
        }
    }

    /// The label a relocation through the unnamed symbol at `at` is listed under: for a
    /// section symbol, `[` the name of the section it stands for `]`, or `[section N]`
    /// where that section has no name the reader holds; `None` for an unnamed symbol of
    /// any other type, which names nothing. `Err` says which byte the file does not hold.
    ///
    /// Bracketed so it never reads as a symbol: a reference to a local or section-anchored
    /// object goes through its section's symbol, and an `indeterminate` cell of a check
    /// keyed on a symbol then shows `R_AARCH64_ADR_PREL_PG_HI21 [.data]` rather than
    /// nothing, which tells "reached through `.data`" from "not referenced".
    fn section_symbol_label(&self, at: u64) -> std::result::Result<Option<String>, String> {
        // st_info and st_shndx sit at different offsets in the two widths.
        let (info_at, shndx_at) = if self.elf64 { (4, 6) } else { (12, 14) };
        let info = match self.cur.slice(at.saturating_add(info_at), 1) {
            Ok([byte]) => *byte,
            _ => return Err("whose st_info the file does not hold".to_owned()),
        };
        if info & 0xf != STT_SECTION {
            return Ok(None);
        }
        let shndx = self
            .cur
            .u16_at(at.saturating_add(shndx_at))
            .map_err(|_unread| "whose st_shndx the file does not hold".to_owned())?;
        Ok(Some(
            self.shnames
                .get(usize::from(shndx))
                .filter(|n| !n.is_empty())
                .map_or_else(|| format!("[section {shndx}]"), |n| format!("[{n}]")),
        ))
    }

    /// One symbol-table entry's name, type, section index, value and size. The name is
    /// read through `strtab` and cut at its first `@`, as [`Self::symbols`] cuts it.
    fn symbol_at(&self, sh: &Shdr, strtab: &Shdr, step: u64, i: u64) -> Read<SymbolEntry> {
        let base = sh.sh_offset.saturating_add(i.saturating_mul(step));
        let (info_at, shndx_at, value_at, size_at) = if self.elf64 {
            (4, 6, 8, 16)
        } else {
            (12, 14, 4, 8)
        };
        let name_off = self.cur.u32_at(base)?;
        // `slice` returned exactly one byte or an error, as in `Cursor::u16_at`.
        let [info]: [u8; 1] = self
            .cur
            .slice(base.saturating_add(info_at), 1)?
            .try_into()
            .unwrap_or([0]);
        let shndx = self.cur.u16_at(base.saturating_add(shndx_at))?;
        let value = self
            .cur
            .addr_at(base.saturating_add(value_at), self.elf64)?;
        let size = self.cur.addr_at(base.saturating_add(size_at), self.elf64)?;
        let name = if u64::from(name_off) < strtab.sh_size {
            let raw = self.cur.cstr_at(strtab.sh_offset, name_off, strtab.sh_size);
            // The `@` cut of `read_symbols`, and the same assumption:
            // `dynamic-symbol-names-carry-no-version` in `report::ASSUMPTIONS`.
            match raw.split_once('@') {
                Some((bare, _)) => bare.to_owned(),
                None => raw,
            }
        } else {
            String::new()
        };
        Ok(SymbolEntry {
            name,
            info,
            shndx,
            value,
            size,
        })
    }

    /// Every entry of one symbol table, or `None` where the table cannot be read whole.
    ///
    /// Each way this returns `None` is a stop [`Self::symbols`] records against
    /// [`ElfTable::Symbols`] over the same table, so the reason is in the facts already
    /// and is not recorded twice; the sentences go to a scratch list here only to learn
    /// whether there were any, and an entry that cannot be read is the stop `symbols`
    /// records at the same index. A partial table is not used, since it would leave a
    /// function out and read it as one with no references.
    fn symbol_table_entries(&self, idx: usize) -> Option<Vec<SymbolEntry>> {
        let sh = self.shdrs.get(idx)?;
        let mut scratch = Vec::new();
        let (step, count) = self.symbol_entries(idx, sh, "", &mut scratch)?;
        let strtab = self.symbol_strtab(sh, "", &mut scratch)?;
        let mut entries = Vec::new();
        for i in 0..count {
            let Ok(entry) = self.symbol_at(sh, strtab, step, i) else {
                return None;
            };
            entries.push(entry);
        }
        // An `ignored` record (a declared entry size the walk read past) is not a stop; the
        // match names every kind, so a kind added later has to say which it is.
        let stopped = scratch.iter().any(|t| match t.kind {
            TruncationKind::Unread => true,
            TruncationKind::Ignored => false,
        });
        (!stopped).then_some(entries)
    }

    /// The functions of one symbol table, in table order, each with an empty reference set,
    /// and per section their ranges sorted by start beside the running maximum of the ends
    /// up to each.
    fn function_ranges(symbols: &[SymbolEntry]) -> (Vec<FunctionRefs<'_>>, SectionRanges) {
        let mut functions = Vec::new();
        let mut ranges: BTreeMap<u16, Vec<(u64, u64, usize)>> = BTreeMap::new();
        for sym in symbols {
            let placed = sym.shndx != SHN_UNDEF && sym.shndx < SHN_LORESERVE;
            if sym.info & 0xf != STT_FUNC || !placed || sym.name.is_empty() {
                continue;
            }
            ranges.entry(sym.shndx).or_default().push((
                sym.value,
                sym.value.saturating_add(sym.size),
                functions.len(),
            ));
            functions.push((sym.name.as_str(), BTreeSet::new()));
        }
        let ranges = ranges
            .into_iter()
            .map(|(shndx, mut list)| {
                list.sort_unstable();
                let mut max_end = 0;
                let reach = list
                    .iter()
                    .map(|&(_, end, _)| {
                        max_end = max_end.max(end);
                        max_end
                    })
                    .collect();
                (shndx, (list, reach))
            })
            .collect();
        (functions, ranges)
    }

    /// The per-function relocation targets of a relocatable object; see
    /// [`ElfFacts::function_references`].
    ///
    /// The work is linear in the relocations and the functions but for overlapping
    /// function ranges, which a compiler emits only for aliases: each section's ranges are
    /// sorted by start beside a running maximum of their ends, so the search for the
    /// ranges holding an offset stops at the first range no earlier one can reach past.
    fn function_references(&self, trunc: &mut Vec<Truncation>) -> Option<Vec<String>> {
        if self.e_type != ET_REL || (self.elf64 && self.e_machine == EM_MIPS) {
            return None;
        }
        let symtab_idx = self.shdrs.iter().position(|s| s.sh_type == SHT_SYMTAB)?;
        // The walk reads every field of every entry, where the symbol reader reads a name,
        // a type and a section, so a table cut inside the last entries' values or sizes
        // stops this walk alone. Returned as `None` with nothing recorded, that moved the
        // field to absent unannounced, found 2026-10-07 by `tests/elf_truncations.rs`'s
        // `every_fact_a_cut_changes_is_covered_by_a_recorded_truncation` once a longer
        // watch list changed what its seeded objects hold.
        let Some(symbols) = self.symbol_table_entries(symtab_idx) else {
            if !trunc
                .iter()
                .any(|t| t.table == ElfTable::Symbols && t.kind == TruncationKind::Unread)
            {
                trunc.push(Truncation::unread(
                    ElfTable::Symbols,
                    "SHT_SYMTAB: an entry's value or size could not be read, so no \
                     function's range is known and no reference was attributed"
                        .to_owned(),
                ));
            }
            return None;
        };
        let (mut functions, ranges) = Self::function_ranges(&symbols);
        let mut unattributed = BTreeSet::new();
        for (idx, sh) in self.shdrs.iter().enumerate() {
            if sh.sh_type == SHT_RELA || sh.sh_type == SHT_REL {
                self.attribute_relocations(
                    idx,
                    sh,
                    symtab_idx,
                    &symbols,
                    &ranges,
                    (&mut functions, &mut unattributed),
                    trunc,
                );
            } else if self.undecoded_relocations(sh, &ranges) {
                let label = self
                    .shnames
                    .get(idx)
                    .filter(|n| !n.is_empty())
                    .map_or_else(|| format!("section [{idx}]"), Clone::clone);
                trunc.push(Truncation::unread(
                    ElfTable::Relocations,
                    format!(
                        "{label}: type {:#x} carries relocations against a section holding \
                         functions or code in an encoding this reader does not decode, so its \
                         references were not read",
                        sh.sh_type
                    ),
                ));
            }
        }
        let mut out = Vec::new();
        for (name, refs) in functions {
            out.push(format!("{name}:"));
            out.extend(refs.into_iter().map(|r| format!("{name}:{r}")));
        }
        out.extend(
            unattributed
                .into_iter()
                .map(|r| format!("{UNATTRIBUTED_REFERENCE}{r}")),
        );
        Some(out)
    }

    /// A section that is neither `SHT_REL` nor `SHT_RELA` and still holds relocations
    /// against a section with functions in it or a section of code: its `sh_info` names
    /// such a section, and it
    /// is `SHT_CREL` or carries `SHF_INFO_LINK`, which makes `sh_info` a section index.
    ///
    /// Skipped without a word, such a section left every function it covers listed with no
    /// references, which `ssp-level-emitted` read as no canary: measured 2026-10-02 with
    /// clang 22.1.8 on Fedora 44 x86_64 under `-fstack-protector-strong -Wa,--crel,
    /// --allow-experimental-crel`, whose canaries sat in a `.crel.text` of type
    /// `0x40000014`. The relocation sections are recorded unread instead, so the reading
    /// is withheld. A type the reader has never seen is named by the flag rather than by
    /// its number, so the next encoding a toolchain adopts withholds the same way; a
    /// section whose target holds no function and is not code (`.crel.eh_frame`) holds
    /// nothing this field reads.
    ///
    /// A target that is code and holds no function counts. clang's
    /// `-fbasic-block-sections=all` puts a function's canary failure call in a section
    /// whose only symbol is a `NOTYPE` `<fn>.__part.N` (measured with clang 22.1.8 on
    /// Fedora 44 x86_64), and [`Self::attribute_relocations`] reads such a section's
    /// references as unattributed; in an encoding it does not decode, the section is
    /// recorded unread for the same reason.
    fn undecoded_relocations(&self, sh: &Shdr, ranges: &SectionRanges) -> bool {
        let into_functions = u16::try_from(sh.sh_info).is_ok_and(|t| ranges.contains_key(&t));
        (into_functions || self.relocates_code(sh))
            && (sh.sh_type == SHT_CREL || sh.sh_flags & SHF_INFO_LINK != 0)
    }

    /// The section a relocation section's `sh_info` names is code (`SHF_EXECINSTR`). A
    /// section index past the header table names no section and is not code.
    fn relocates_code(&self, sh: &Shdr) -> bool {
        usize::try_from(sh.sh_info).is_ok_and(|t| {
            self.shdrs
                .get(t)
                .is_some_and(|t| t.sh_flags & SHF_EXECINSTR != 0)
        })
    }

    /// One relocation section's references, added to the functions whose ranges hold them,
    /// and to `unattributed` where the section relocates code no function's range holds.
    ///
    /// A target section that is code (`SHF_EXECINSTR`) and holds no function symbol, or an
    /// offset in code that falls outside every function's range, is code the reader cannot
    /// place in a function. Skipped, its references left the function they belong to
    /// reading as one without them: measured 2026-10-02 with clang 22.1.8 on Fedora 44
    /// x86_64 under `-O2 -fstack-protector-strong -fbasic-block-sections=all`, each
    /// canaried function's `__stack_chk_fail` call sat in a section of its own whose only
    /// symbol is a `NOTYPE` `<fn>.__part.N`, the calls `ssp_use` and `ssp_escape` stayed in
    /// the function's own range, and `ssp-level-emitted` published `off`. clang's
    /// `-fsplit-machine-functions` with a profile (`-fprofile-instr-use`) did the same the
    /// same day, its fragments in `.text.split.<fn>` under a `NOTYPE` `<fn>.cold`, which the
    /// predicate's `.cold` reading does not reach since only `STT_FUNC` symbols get a range.
    /// Recorded under [`UNATTRIBUTED_REFERENCE`] instead, which the predicate withholds over when the name
    /// is a canary target. The `__part` symbols are not attributed to the function their
    /// name begins with: that would read a level off a naming convention, where withholding
    /// reads nothing. A target that is not code (`.eh_frame`, debug sections) holds no
    /// reference this field reads.
    #[allow(
        clippy::too_many_arguments,
        reason = "the walk's own state, threaded rather than bundled into a struct used once"
    )]
    fn attribute_relocations<'s>(
        &self,
        idx: usize,
        sh: &Shdr,
        symtab_idx: usize,
        symbols: &'s [SymbolEntry],
        ranges: &SectionRanges,
        (functions, unattributed): (&mut [FunctionRefs<'s>], &mut BTreeSet<&'s str>),
        trunc: &mut Vec<Truncation>,
    ) {
        let label = self.relocation_label(idx);
        // A target no function symbol is placed in, one past `u16` among them, has no
        // range; it holds references this field reads only if it is code.
        let target = match u16::try_from(sh.sh_info) {
            Ok(t) => ranges.get(&t),
            Err(_past_any_symbol_index) => None,
        };
        let code = self.relocates_code(sh);
        if target.is_none() && !code {
            return;
        }
        // Checked after the target, so that a section this field does not read (debug
        // information, `.eh_frame`) records nothing against `ElfTable::Relocations`, whose
        // scope `code_relocations` shares (2026-10-02).
        if usize::try_from(sh.sh_link) != Ok(symtab_idx) {
            trunc.push(Truncation::unread(
                ElfTable::Relocations,
                format!(
                    "{label}: sh_link {} does not name the symbol table at [{symtab_idx}], \
                     so its references cannot be named",
                    sh.sh_link
                ),
            ));
            return;
        }
        let (list, reach) = target.map_or((&[][..], &[][..]), |(l, r)| (&l[..], &r[..]));
        let width: u64 = if self.elf64 { 8 } else { 4 };
        let step = self.section_stride(
            idx,
            sh,
            relocation_record(self.elf64, sh.sh_type == SHT_RELA),
            trunc,
        );
        let (count, partial) = (sh.sh_size / step, sh.sh_size % step);
        let step = step.get();
        if self.cur.slice(sh.sh_offset, sh.sh_size).is_err() || partial != 0 {
            trunc.push(Truncation::unread(
                ElfTable::Relocations,
                format!(
                    "{label}: {:#x} bytes at {:#x} are not {count} whole {step}-byte entries \
                     inside the file, so its references were not read",
                    sh.sh_size, sh.sh_offset
                ),
            ));
            return;
        }
        for i in 0..count {
            let base = sh.sh_offset.saturating_add(i.saturating_mul(step));
            let (offset, info) = match (
                self.cur.addr_at(base, self.elf64),
                self.cur.addr_at(base.saturating_add(width), self.elf64),
            ) {
                (Ok(offset), Ok(info)) => (offset, info),
                (Err(why), _) | (_, Err(why)) => {
                    trunc.push(Truncation::unread(
                        ElfTable::Relocations,
                        format!("{label}: entry {i} of {count} unreadable ({why})"),
                    ));
                    return;
                }
            };
            let sym_idx = if self.elf64 { info >> 32 } else { info >> 8 };
            if sym_idx == 0 {
                continue;
            }
            let Some(sym) = usize::try_from(sym_idx).map_or(None, |n| symbols.get(n)) else {
                trunc.push(Truncation::unread(
                    ElfTable::Relocations,
                    format!(
                        "{label}: entry {i} of {count} names symbol {sym_idx}, past the \
                         {}-entry symbol table, so the entries from it on were not read",
                        symbols.len()
                    ),
                ));
                return;
            };
            if sym.name.is_empty() {
                continue;
            }
            let upto = list.partition_point(|&(start, _, _)| start <= offset);
            let mut placed = false;
            for k in (0..upto).rev() {
                if reach.get(k).is_none_or(|&r| r <= offset) {
                    break;
                }
                if let Some(&(_, end, f)) = list.get(k)
                    && offset < end
                    && let Some((_, refs)) = functions.get_mut(f)
                {
                    refs.insert(sym.name.as_str());
                    placed = true;
                }
            }
            if !placed && code {
                unattributed.insert(sym.name.as_str());
            }
        }
    }

    /// The `PT_GNU_STACK` header the loader acts on, the last, with an `unread`
    /// [`ElfTable::GnuStack`] entry in `trunc` where two disagree on `PF_X`.
    ///
    /// The loaders take the last header, not the first.
    /// Linux's `load_elf_binary` (`fs/binfmt_elf.c`) walks every program header and sets
    /// `executable_stack` at each `PT_GNU_STACK` without leaving the loop; glibc assigns
    /// `stack_flags` the same way in the main program's walk in `rtld.c` and in
    /// `_dl_map_object_from_fd` for each shared object; `FreeBSD`'s `imgact_elf.c` sets
    /// `stack_prot` per header in its loop. That is a reading of the sources, not a
    /// measurement, and OpenBSD's handling was not read. Linux's was measured, 2026-10-05 on Fedora 44
    /// x86_64, kernel 7.3, glibc 2.43: a gcc 16.1.1 `-O2` executable printing its own
    /// `[stack]` mapping, with one other program header retyped by hand to a `PT_GNU_STACK`
    /// carrying `PF_X`, mapped the stack `rwxp` with that header after the linker's `RW` one
    /// and `rw-p` with it before. Over such a pair the first is the opposite of what Linux
    /// does with the file.
    ///
    /// Two headers that agree read normally: whichever a loader takes, it takes the same
    /// `PF_X`. Two that disagree are withheld rather than read as the last, for three
    /// reasons. The loaders' agreement on the last rests on the reading above, and one that
    /// took the first would turn a read-the-last verdict into the clean-looking wrong
    /// reading this project cannot tolerate. No linker chard has measured writes two, so a
    /// pair arrives from a hand edit, a linker script's `PHDRS` or a hostile file, and a
    /// verdict over it says nothing about the flag under test. And withholding costs no
    /// reading on any toolchain output measured. The published facts still carry the last
    /// header, so the fact store states what Linux acts on and agrees with `readelf`'s last
    /// row; the entry is what keeps a check from concluding from them.
    ///
    /// Only `PF_X` is compared, since it is the one bit a fact here carries; `FreeBSD` maps
    /// the read and write bits too, and a pair that differs only there changes nothing
    /// published. The gate's unit is the table, and the entry names [`ElfTable::GnuStack`],
    /// which only the checks reading the stack header declare (`noexecstack` and
    /// `linker-default-noexecstack`, the two over this predicate), so `pie`, `relro` and
    /// `textrel-absent` read over the pair. Each of those reads a fact the pair does not
    /// touch, `PT_INTERP`, `PT_GNU_RELRO` and the dynamic section, whose readings no loader
    /// choice between the two headers changes; withholding them would say nothing about
    /// the stack and cost three readings. A program-header table `parse` refuses withholds
    /// every check, through `elf_error`.
    fn gnu_stack(&self, trunc: &mut Vec<Truncation>) -> Option<&Phdr> {
        let stacks: Vec<(usize, &Phdr)> = self
            .phdrs
            .iter()
            .enumerate()
            .filter(|(_, p)| p.p_type == PT_GNU_STACK)
            .collect();
        let executable: Vec<String> = stacks
            .iter()
            .filter(|(_, p)| p.p_flags & PF_X != 0)
            .map(|(i, _)| i.to_string())
            .collect();
        if !executable.is_empty() && executable.len() != stacks.len() {
            let at: Vec<String> = stacks.iter().map(|(i, _)| i.to_string()).collect();
            trunc.push(Truncation::unread(
                ElfTable::GnuStack,
                format!(
                    "{} PT_GNU_STACK headers disagree on PF_X (program headers {}, PF_X at \
                     {}); a loader that takes the last and one that takes the first \
                     would give the stack different permissions, so whether it is executable \
                     was not read",
                    stacks.len(),
                    at.join(", "),
                    executable.join(", ")
                ),
            ));
        }
        stacks.last().map(|&(_, p)| p)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one struct literal, a field to a line, with the reads each field needs \
                  above it; split, the fields would be filled away from the struct they belong \
                  to"
    )]
    pub fn facts(&self) -> ElfFacts {
        let mut truncations = self.structural_truncations();
        let dyn_entries = self.dynamic(&mut truncations);
        let tags: BTreeSet<i64> = dyn_entries.iter().map(|(t, _)| *t).collect();
        // The last entry of a repeated tag, as `ld.so` stores it (`LOADER_SINGLE_TAGS`).
        let dyn_value = |tag: i64| {
            dyn_entries
                .iter()
                .rfind(|(t, _)| *t == tag)
                .map(|(_, v)| *v)
        };
        let flags = dyn_value(DT_FLAGS).unwrap_or(0);
        let flags1 = dyn_value(DT_FLAGS_1).unwrap_or(0);

        let props = self.gnu_properties(&mut truncations);
        let x86 = self.feature_word(&props, GNU_PROPERTY_X86_FEATURE_1_AND);
        let arm = self.feature_word(&props, GNU_PROPERTY_AARCH64_FEATURE_1_AND);

        let has_interp = self.phdrs.iter().any(|p| p.p_type == PT_INTERP);
        let has_dynamic = !dyn_entries.is_empty();
        let kind = link_kind(self.e_type, has_interp, &tags, flags1);
        let flat = kind.map(LinkKind::flatten);
        // Each of these is a fact about a linked object, so each is `None` where there is
        // no linked object to be a fact about. `Option::map` on the kind is what makes
        // that hold for every field at once.
        let linked = |fact: bool| kind.map(|_| fact);
        let gnu_stack = self.gnu_stack(&mut truncations);
        let gnu_relro = self.phdrs.iter().any(|p| p.p_type == PT_GNU_RELRO);
        let bind_now =
            tags.contains(&DT_BIND_NOW) || flags & DF_BIND_NOW != 0 || flags1 & DF_1_NOW != 0;

        // `dynstr` is located before the symbols are, since the dynamic symbol table is named
        // through it, and its records land after the symbols' so the list keeps its order.
        let mut dynstr_records = Vec::new();
        let dynstr = self.dyn_strtab(&dyn_entries, &mut dynstr_records);
        let (symbol_tables, symbols) = self.symbols(&dyn_entries, dynstr, &mut truncations);
        truncations.append(&mut dynstr_records);
        let (code_scanned, code_matches) = self.code_scan(&mut truncations);
        let watched = watched_of(&symbols);

        ElfFacts {
            elf_class: if self.elf64 { 64 } else { 32 },
            elf_data: Some(if self.cur.little {
                ByteOrder::LittleEndian
            } else {
                ByteOrder::BigEndian
            }),
            elf_type: type_name(self.e_type),
            machine: machine_name(self.e_machine),
            has_interp,
            has_dynamic,
            pie: flat.map(|f| f.0),
            df_1_pie: flags1 & DF_1_PIE != 0,
            static_pie: flat.map(|f| f.1),
            shared_object: flat.map(|f| f.2),
            statically_linked: flat.map(|f| f.3),
            relro: linked(true).map(|_| {
                if gnu_relro && bind_now {
                    RELRO_FULL.to_owned()
                } else if gnu_relro {
                    RELRO_PARTIAL.to_owned()
                } else {
                    RELRO_NONE.to_owned()
                }
            }),
            gnu_relro: linked(gnu_relro),
            bind_now: linked(bind_now),
            gnu_stack_present: linked(gnu_stack.is_some()),
            gnu_stack_executable: linked(gnu_stack.is_some_and(|p| p.p_flags & PF_X != 0)),
            df_1_noopen: flags1 & DF_1_NOOPEN != 0,
            // Two spellings, like `bind_now` three lines of this struct away, and for
            // the same reason: bfd emits `DT_FLAGS` only when `info->flags` is non-zero,
            // so a spec-conformant link may record a text relocation solely as the
            // standalone `DT_TEXTREL` entry. Reading only the flag word answered `false`
            // there — a reassuring absence on a check whose polarity makes absence the
            // good news. The reader's own synthetic fixtures carried `DT_FLAGS`, so they
            // mirrored the blind spot rather than exposing it.
            textrel: flags & DF_TEXTREL != 0 || dyn_value(DT_TEXTREL).is_some(),
            dt_relr: tags.contains(&DT_RELR),
            dt_debug: tags.contains(&DT_DEBUG),
            dt_soname: tags.contains(&DT_SONAME),
            dynamic_tags: dyn_entries
                .iter()
                .map(|(tag, value)| format!("{tag:#x}={value:#x}"))
                .collect(),
            needed: self.dyn_strings(&dyn_entries, DT_NEEDED, dynstr, &mut truncations),
            rpath: self.dyn_strings(&dyn_entries, DT_RPATH, dynstr, &mut truncations),
            runpath: self.dyn_strings(&dyn_entries, DT_RUNPATH, dynstr, &mut truncations),
            gnu_property_types: props.keys().map(|t| format!("{t:#010x}")).collect(),
            gnu_property_notes: props
                .iter()
                .map(|(t, p)| (format!("{t:#010x}"), p.notes))
                .collect(),
            x86_ibt: x86 & X86_FEATURE_1_IBT != 0,
            x86_shstk: x86 & X86_FEATURE_1_SHSTK != 0,
            aarch64_bti: arm & AARCH64_FEATURE_1_BTI != 0,
            aarch64_pac: arm & AARCH64_FEATURE_1_PAC != 0,
            aarch64_gcs: arm & AARCH64_FEATURE_1_GCS != 0,
            openbsd_nobtcfi: self.phdrs.iter().any(|p| p.p_type == PT_OPENBSD_NOBTCFI),
            sections: self
                .shnames
                .iter()
                .filter(|n| !n.is_empty())
                .cloned()
                .collect(),
            data_in_code_pages: self.data_in_code_pages(),
            code_relocations: self.code_relocations(&mut truncations),
            function_references: self.function_references(&mut truncations),
            symbol_tables,
            symbol_count: symbols.len(),
            watched_symbols: watched,
            self_report: self.section_text(SELF_REPORT_SECTION, &mut truncations),
            recorded_command_line: self.section_text(".GCC.command.line", &mut truncations),
            comment: self.section_lines(COMMENT_SECTION, &mut truncations),
            code_scanned,
            code_matches,
            function_entries: self.function_entries(&mut truncations),
            truncations: once_each_stride_record(truncations),
        }
    }
}

/// The entries of `symbols` that [`WATCHED_SYMBOLS`] names.
fn watched_of(symbols: &BTreeMap<String, SymbolFact>) -> BTreeMap<String, SymbolFact> {
    WATCHED_SYMBOLS
        .iter()
        .filter_map(|name| symbols.get_key_value(*name))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Largest object this reader will hold in memory: 512 mebibytes.
///
/// The whole file is slurped, which is right for what chard builds — probe binaries are
/// kilobytes — and wrong for whatever a caller points `chard elf` at, which is not
/// chard's to trust. Nothing before this cap looks past the four magic bytes, so any file
/// at all can claim to be an object: a sparse file occupying four kibibytes on disk drove
/// peak resident memory to four gibibytes.
///
/// The cap is far above any real linked object — the largest on a typical distribution
/// image is a debug-heavy shared library in the low hundreds of megabytes — and far below
/// what would exhaust a build machine. An object above it is reported as unparseable
/// rather than skipped silently, so it stays visible instead of thinning a denominator.
const MAX_OBJECT_BYTES: u64 = 512 * 1024 * 1024;

/// Read `path` and extract facts. The whole file is slurped because probe
/// binaries are kilobytes and holding them lets the parser hand out borrowed
/// slices without a second read.
///
/// A regular file is held to `MAX_OBJECT_BYTES` from its metadata, before the open. A
/// FIFO is read too, since a pipe can carry an object (`chard elf <(...)`, `chard elf
/// /dev/stdin` behind a pipe) and refusing the shape refused the bytes with it; its
/// `len()` is 0, so the cap is held on the bytes as they arrive by `read_under_cap`. A
/// directory, a device or a socket is refused from the metadata: none carries an object,
/// and a `read` on a device or a socket answers with an errno the envelope can only
/// report as chard's own. An `open` on a FIFO with no writer blocks, as it does for
/// `readelf -h` and for `chard table`.
///
/// # Errors
///
/// Errors when the file cannot be read, is a directory, a device or a socket, holds more
/// than `MAX_OBJECT_BYTES`, or is not a parseable ELF object.
pub fn facts_for(path: &Path) -> Result<ElfFacts, ElfError> {
    use std::os::unix::fs::FileTypeExt as _;
    let io = |op: &'static str| {
        move |source: std::io::Error| ElfError::Io {
            path: path.to_path_buf(),
            op,
            source,
        }
    };
    let meta = std::fs::metadata(path).map_err(io("reading the size of"))?;
    let kind = meta.file_type();
    if !(kind.is_file() || kind.is_fifo()) {
        return Err(ElfError::NotElf {
            path: Some(path.to_path_buf()),
            why: format!(
                "not a regular file ({})",
                crate::error::file_type_name(kind)
            ),
        });
    }
    // Size checked before reading where the metadata carries it: the point is not to
    // hold it. The bounded read below holds the same cap on a stream, and on a file that
    // grew between this stat and the read.
    if kind.is_file() && meta.len() > MAX_OBJECT_BYTES {
        return Err(ElfError::TooLarge {
            path: path.to_path_buf(),
            size: Some(meta.len()),
            cap: MAX_OBJECT_BYTES,
        });
    }
    let file = std::fs::File::open(path).map_err(io("opening"))?;
    let data = read_under_cap(file, MAX_OBJECT_BYTES)
        .map_err(io("reading"))?
        .ok_or_else(|| ElfError::TooLarge {
            path: path.to_path_buf(),
            size: None,
            cap: MAX_OBJECT_BYTES,
        })?;
    Ok(Elf::parse(&data)
        .map_err(|refusal| refusal.with_path(path))?
        .facts())
}

/// Read `source` to its end, holding at most `cap` bytes: the bytes when the stream
/// ended within the cap, `None` when it went past it.
///
/// The reader takes `cap + 1` bytes and stops, so the most it ever holds is one byte over
/// the cap, and that byte is what tells a stream that filled the cap exactly from one
/// that went past it. This is the cap for a source whose length the metadata cannot
/// report; a regular file's is checked from its `len()` before the open.
fn read_under_cap(source: impl std::io::Read, cap: u64) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    let mut data = Vec::new();
    source.take(cap.saturating_add(1)).read_to_end(&mut data)?;
    let within = u64::try_from(data.len()).is_ok_and(|held| held <= cap);
    Ok(within.then_some(data))
}

// Kani proofs live in `proofs/`, gated on `cfg(kani)` and `#[path]`-included here rather
// than from the crate root, so they reach `Cursor`'s private fields as a child module and
// nothing has to be widened to `pub(crate)` for a proof to see it. Invisible to normal
// builds, tests and clippy. Run with `make kani`.
#[cfg(kani)]
#[path = "../proofs/cursor_reads_total.rs"]
mod cursor_proofs;

#[cfg(kani)]
#[path = "../proofs/align_up_is_least_multiple.rs"]
mod align_up_proofs;

#[cfg(test)]
mod tests {
    /// Every machine `machine_name` names is the family of some architecture
    /// `toolchain::machine_family` maps, so an artifact of a named machine can agree with
    /// a target: an arm `machine_name` gains without a mapping there would read every run
    /// on that machine as `unmapped`, and a renamed one as `disagrees`. The loop runs over
    /// every `e_machine` value rather than a list of the named ones, so it cannot drift
    /// from the `match`. The same architecture's kernel is held to run the machine
    /// natively, for `report::emulation_limitation`.
    #[test]
    fn every_named_machine_is_a_family_the_target_can_name() {
        let mut named = 0;
        for em in 0..=u16::MAX {
            let name = machine_name(em);
            if name.starts_with("unrecognised") {
                continue;
            }
            named += 1;
            let arch = crate::toolchain::gate_arch_of_machine(&name);
            assert_eq!(
                crate::toolchain::machine_family(arch),
                Some(name.as_str()),
                "e_machine {em}"
            );
            // And a kernel of that architecture runs it natively at the width and in the
            // byte order its read spelling carries, so `report::emulation_limitation` never
            // withholds a native artifact for want of a row in `env::runs_natively`. A
            // spelling that carries no order (`mips`, `mips64`) names none whatever chard's
            // build, and the reading is withheld there rather than published: that is the
            // one family the row cannot name from a spelling, and `env::kernel_byte_order`
            // says so.
            let kernel = crate::env::NativeMachine::read(arch);
            let runs = |order| {
                [32, 64].into_iter().any(|class| {
                    crate::env::runs_natively(kernel, &name, class, Some(order)) == Some(true)
                })
            };
            if crate::env::kernel_byte_order(kernel).is_some() {
                assert!(
                    runs(ByteOrder::LittleEndian) || runs(ByteOrder::BigEndian),
                    "e_machine {em}"
                );
            } else {
                assert_eq!(name, "mips", "only mips carries no order in its spelling");
            }
        }
        assert!(named > 0, "no e_machine value was named");
        assert!(machine_name(0xffff).starts_with("unrecognised"));
    }

    use super::*;

    /// The spelling `as_str` gives a table or a kind is the spelling serde writes into the
    /// report, for every variant.
    ///
    /// The schema's `table` and `kind` enums are pinned to `as_str` in
    /// `tests/schema_conformance.rs`, and the gate's reason and the diagnostics quote it,
    /// so a variant serde spells differently is one the schema admits under a name the
    /// report never carries. `DynStr` was the case: kebab-case wrote `dyn-str` while
    /// `as_str` said `dynstr`, and no fixture carried the entry to show it.
    #[test]
    fn a_tables_serialized_spelling_is_its_as_str() {
        for table in ElfTable::ALL {
            let written = serde_json::to_value(table).expect("a unit variant serializes");
            assert_eq!(written, serde_json::json!(table.as_str()), "{table:?}");
        }
        for kind in TruncationKind::ALL {
            let written = serde_json::to_value(kind).expect("a unit variant serializes");
            assert_eq!(written, serde_json::json!(kind.as_str()), "{kind:?}");
        }
    }

    #[test]
    fn align_up_leaves_aligned_values_alone() {
        assert_eq!(align_up(16, 8).unwrap(), 16);
        assert_eq!(align_up(0, 8).unwrap(), 0);
        assert_eq!(align_up(17, 8).unwrap(), 24);
        assert_eq!(align_up(5, 1).unwrap(), 5);
    }

    /// The exact off-by-four that reported a `-fcf-protection=full` binary as
    /// having no CET markings: for a GNU note with `namesz == 4` and align 8 the
    /// descriptor begins at `note_start + 16`, because 12 + 4 is already aligned.
    #[test]
    fn note_descriptor_offset_is_absolutely_aligned() {
        let namesz: u64 = 4; // "GNU\0"
        let correct = align_up(12 + namesz, 8).unwrap();
        let tempting_and_wrong = 12 + align_up(namesz, 8).unwrap();
        assert_eq!(correct, 16);
        assert_eq!(tempting_and_wrong, 20);
        assert_ne!(correct, tempting_and_wrong);
    }

    /// A minimal ELF64 header, so the three tests below differ only in the field each
    /// is about. `phnum`/`shnum` and their entsizes are the whole subject.
    fn elf64_header(phnum: u16, phentsize: u16, shnum: u16, shentsize: u16) -> Vec<u8> {
        let mut d = vec![0u8; 64];
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 2; // ELFCLASS64
        d[5] = 1; // little-endian
        d[6] = 1;
        d[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        d[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        d[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        // `e_shoff` is written only when there are sections to find there. Zero is what
        // the specification and every stripped file use for "no section-header table",
        // and a nonzero offset with `e_shnum == 0` is the escape that says the count is
        // in `shdr[0]`, which here would be the first program header.
        if shnum > 0 {
            d[40..48].copy_from_slice(&64u64.to_le_bytes()); // e_shoff
        }
        d[54..56].copy_from_slice(&phentsize.to_le_bytes());
        d[56..58].copy_from_slice(&phnum.to_le_bytes());
        d[58..60].copy_from_slice(&shentsize.to_le_bytes());
        d[60..62].copy_from_slice(&shnum.to_le_bytes());
        d.resize(4096, 0);
        d
    }

    /// A table stride below the record size is refused at the header.
    ///
    /// `base + i * entsize` with `entsize` under the real record size makes the declared
    /// entries overlap; at zero every index names the same bytes. A 16 KB file with
    /// `e_shentsize = 0` and `e_shnum = 65535` aliased one `SHT_DYNAMIC` header onto 65535
    /// logical sections and drove 4.79 GB of resident memory and a 1.09 GB report before
    /// this check existed. The input-size cap could not have caught it: the derived
    /// iteration count is unrelated to input size.
    #[test]
    fn a_stride_below_the_record_size_is_refused_rather_than_walked() {
        // Zero, the aliasing case, and one below the real size, the overlapping case.
        // 65534, since 65535 is `PN_XNUM`, which means "the count is in
        // `shdr[0].sh_info`" and is no count of its own.
        for bad in [0u16, 1, 63] {
            assert!(
                Elf::parse(&elf64_header(0, 56, 65534, bad)).is_err(),
                "e_shentsize {bad} must be refused"
            );
            assert!(
                Elf::parse(&elf64_header(65534, bad, 0, 64)).is_err(),
                "e_phentsize {bad} must be refused"
            );
        }
        // Exactly the record size, and larger: the spec permits padding, so both stand.
        assert!(Elf::parse(&elf64_header(1, 56, 1, 64)).is_ok());
        assert!(Elf::parse(&elf64_header(1, 72, 1, 80)).is_ok());
        // A count of zero says nothing about the stride, so it is not grounds to refuse.
        assert!(Elf::parse(&elf64_header(0, 0, 0, 0)).is_ok());
    }

    /// Build an ELF64 whose derived facts are decided by the inputs named here.
    ///
    /// One `PT_DYNAMIC` segment carrying the given tags, optionally a `PT_INTERP`, a
    /// `PT_GNU_RELRO` and a `PT_GNU_STACK` with the given flags.
    fn synth(
        e_type: u16,
        tags: &[(i64, u64)],
        interp: bool,
        relro: bool,
        stack_flags: Option<u32>,
    ) -> Vec<u8> {
        synth_with_note(e_type, tags, interp, relro, stack_flags, None)
    }

    /// As `synth`, plus an optional `PT_NOTE` carrying one
    /// `GNU_PROPERTY_X86_FEATURE_1_AND` with the given bits.
    ///
    /// The descriptor offset is `note_start + align_up(12 + namesz, 8)`, which for
    /// `"GNU\0"` is already aligned and so has no padding -- the exact rule the module
    /// header calls the one that must not be got wrong.
    fn synth_with_note(
        e_type: u16,
        tags: &[(i64, u64)],
        interp: bool,
        relro: bool,
        stack_flags: Option<u32>,
        x86_bits: Option<u32>,
    ) -> Vec<u8> {
        synth_with_property(
            e_type,
            tags,
            interp,
            relro,
            stack_flags,
            x86_bits.map(|bits| (GNU_PROPERTY_X86_FEATURE_1_AND, bits)),
        )
    }

    /// The same object with a GNU property note of any type, not only x86's.
    ///
    /// The builder hardcoded `GNU_PROPERTY_X86_FEATURE_1_AND`, which is why the aarch64
    /// bits had no paired test: there was no way to write the note that carries them.
    fn synth_with_property(
        e_type: u16,
        tags: &[(i64, u64)],
        interp: bool,
        relro: bool,
        stack_flags: Option<u32>,
        property: Option<(u32, u32)>,
    ) -> Vec<u8> {
        let mut phdrs: Vec<(u32, u32)> = vec![(PT_DYNAMIC, 0)];
        if interp {
            phdrs.push((PT_INTERP, 0));
        }
        if relro {
            phdrs.push((PT_GNU_RELRO, 0));
        }
        if let Some(f) = stack_flags {
            phdrs.push((PT_GNU_STACK, f));
        }
        if property.is_some() {
            phdrs.push((PT_NOTE, 0));
        }
        let dyn_at: u64 = 0x400;
        let note_at: u64 = 0x600;
        let mut d = elf64_header(u16::try_from(phdrs.len()).unwrap(), 56, 0, 64);
        d[16..18].copy_from_slice(&e_type.to_le_bytes());
        for (i, (p_type, p_flags)) in phdrs.iter().enumerate() {
            let b = 64 + i * 56;
            d[b..b + 4].copy_from_slice(&p_type.to_le_bytes());
            d[b + 4..b + 8].copy_from_slice(&p_flags.to_le_bytes());
            if *p_type == PT_DYNAMIC {
                d[b + 8..b + 16].copy_from_slice(&dyn_at.to_le_bytes());
                let size = u64::try_from((tags.len() + 1) * 16).unwrap();
                d[b + 32..b + 40].copy_from_slice(&size.to_le_bytes());
            }
            if *p_type == PT_NOTE {
                d[b + 8..b + 16].copy_from_slice(&note_at.to_le_bytes());
                d[b + 32..b + 40].copy_from_slice(&32u64.to_le_bytes()); // p_filesz
                d[b + 48..b + 56].copy_from_slice(&8u64.to_le_bytes()); // p_align
            }
        }
        if let Some((prop_type, bits)) = property {
            let n = usize::try_from(note_at).unwrap();
            d[n..n + 4].copy_from_slice(&4u32.to_le_bytes()); // namesz "GNU\0"
            d[n + 4..n + 8].copy_from_slice(&12u32.to_le_bytes()); // descsz
            d[n + 8..n + 12].copy_from_slice(&NT_GNU_PROPERTY_TYPE_0.to_le_bytes());
            d[n + 12..n + 16].copy_from_slice(b"GNU\0");
            // desc begins at align_up(12 + 4, 8) == 16, i.e. no padding at all.
            d[n + 16..n + 20].copy_from_slice(&prop_type.to_le_bytes());
            d[n + 20..n + 24].copy_from_slice(&4u32.to_le_bytes()); // pr_datasz
            d[n + 24..n + 28].copy_from_slice(&bits.to_le_bytes());
        }
        let mut at = usize::try_from(dyn_at).unwrap();
        for (tag, val) in tags {
            d[at..at + 8].copy_from_slice(&tag.to_le_bytes());
            d[at + 8..at + 16].copy_from_slice(&val.to_le_bytes());
            at += 16;
        }
        d[at..at + 16].copy_from_slice(&[0u8; 16]); // DT_NULL
        d
    }

    fn facts_of(bytes: &[u8]) -> ElfFacts {
        Elf::parse(bytes).expect("synthetic ELF parses").facts()
    }

    /// A program laid out from `loads` (`p_flags`, `p_offset`, `p_filesz`, `p_align`) and
    /// `sections` (name, `sh_type`, `sh_flags`, `sh_offset`, `sh_size`), with a null
    /// section first and the name table last; the section-header table sits at 0x3000 and
    /// the names at 0x3800, past every range the layouts below use.
    fn laid_out(
        loads: &[(u32, u64, u64, u64)],
        sections: &[(&str, u32, u64, u64, u64)],
    ) -> Vec<u8> {
        let shoff: usize = 0x3000;
        let names_at: usize = 0x3800;
        let shnum = sections.len() + 2;
        let mut d = elf64_header(u16::try_from(loads.len()).unwrap(), 56, 0, 64);
        d.resize(0x4000, 0);
        d[40..48].copy_from_slice(&u64::try_from(shoff).unwrap().to_le_bytes());
        d[60..62].copy_from_slice(&u16::try_from(shnum).unwrap().to_le_bytes());
        d[62..64].copy_from_slice(&u16::try_from(shnum - 1).unwrap().to_le_bytes());
        for (i, (flags, offset, filesz, align)) in loads.iter().enumerate() {
            let b = 64 + i * 56;
            d[b..b + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            d[b + 4..b + 8].copy_from_slice(&flags.to_le_bytes());
            d[b + 8..b + 16].copy_from_slice(&offset.to_le_bytes());
            d[b + 32..b + 40].copy_from_slice(&filesz.to_le_bytes());
            d[b + 40..b + 48].copy_from_slice(&filesz.to_le_bytes());
            d[b + 48..b + 56].copy_from_slice(&align.to_le_bytes());
        }
        let mut names = vec![0u8];
        let mut name_of = |name: &str| {
            let at = u32::try_from(names.len()).unwrap();
            names.extend_from_slice(name.as_bytes());
            names.push(0);
            at
        };
        let mut headers: Vec<(u32, u32, u64, u64, u64)> = sections
            .iter()
            .map(|&(name, ty, flags, offset, size)| (name_of(name), ty, flags, offset, size))
            .collect();
        let shstrtab = name_of(".shstrtab");
        let names_len = u64::try_from(names.len()).unwrap();
        headers.push((
            shstrtab,
            SHT_STRTAB,
            0,
            u64::try_from(names_at).unwrap(),
            names_len,
        ));
        for (i, (name, ty, flags, offset, size)) in headers.iter().enumerate() {
            let b = shoff + (i + 1) * 64;
            d[b..b + 4].copy_from_slice(&name.to_le_bytes());
            d[b + 4..b + 8].copy_from_slice(&ty.to_le_bytes());
            d[b + 8..b + 16].copy_from_slice(&flags.to_le_bytes());
            d[b + 24..b + 32].copy_from_slice(&offset.to_le_bytes());
            d[b + 32..b + 40].copy_from_slice(&size.to_le_bytes());
        }
        d[names_at..names_at + names.len()].copy_from_slice(&names);
        d
    }

    /// `data_in_code_pages` on the three layouts the linkers produce, built in bytes: GNU
    /// ld's `-z noseparate-code`, one executable segment holding `.rodata` beside `.text`;
    /// lld's and mold's, a `.text` segment of its own whose first page shares file bytes
    /// with the read-only segment before it; and `-z separate-code`, the same segments
    /// padded to page boundaries. The second is the layout segment membership reads as
    /// separated, and the reason the fact is read by page.
    #[test]
    fn data_in_code_pages_reads_the_pages_an_executable_segment_maps() {
        const PROGBITS: u32 = 1;
        let code = SHF_ALLOC | SHF_EXECINSTR;
        let page = 0x1000;
        // One segment from offset 0: `.rodata` is in it.
        let bfd_off = laid_out(
            &[(PF_X | 0x4, 0, 0x900, page)],
            &[
                (".text", PROGBITS, code, 0x400, 0x200),
                (".rodata", PROGBITS, SHF_ALLOC, 0x600, 0x100),
            ],
        );
        assert_eq!(
            facts_of(&bfd_off).data_in_code_pages,
            Some(vec![".rodata".to_owned()])
        );
        // A `.text` segment of its own at 0x700, whose page begins at 0: `.rodata` and
        // `.eh_frame` before it share that page.
        let shared_page = laid_out(
            &[(0x4, 0, 0x700, page), (PF_X | 0x4, 0x700, 0x200, page)],
            &[
                (".rodata", PROGBITS, SHF_ALLOC, 0x400, 0x100),
                (".eh_frame", PROGBITS, SHF_ALLOC, 0x500, 0x200),
                (".text", PROGBITS, code, 0x700, 0x200),
            ],
        );
        assert_eq!(
            facts_of(&shared_page).data_in_code_pages,
            Some(vec![".rodata".to_owned(), ".eh_frame".to_owned()])
        );
        // Padded: `.text` alone on its page, the read-only data on the next. The build-id
        // note on the code page is not counted, nor is a code section the allowlist in the
        // recipe would not know, nor `.bss`, which has no file bytes.
        let separated = laid_out(
            &[
                (PF_X | 0x4, 0x1000, 0x400, page),
                (0x4, 0x2000, 0x200, page),
                (0x6, 0x2200, 0x10, page),
            ],
            &[
                (BUILD_ID_SECTION, SHT_NOTE, SHF_ALLOC, 0x1000, 0x24),
                (".text", PROGBITS, code, 0x1040, 0x200),
                (".text.hot", PROGBITS, code, 0x1240, 0x100),
                (".rodata", PROGBITS, SHF_ALLOC, 0x2000, 0x200),
                (".bss", SHT_NOBITS, SHF_ALLOC | 0x1, 0x1400, 0x100),
            ],
        );
        assert_eq!(facts_of(&separated).data_in_code_pages, Some(Vec::new()));
        // The layout `-Wl,-z,separate-code -Wl,-z,max-page-size=0x10` gave GNU ld 2.46.1 on
        // Fedora 44 x86_64: a code segment at 0 ending at 0x4b9, aligned to 16 bytes, and
        // the read-only segment at 0x4c0 holding `.dynsym`, `.rodata` and `.eh_frame`. At
        // its own alignment nothing shares its range; on the 4096-byte page a kernel maps,
        // all three do.
        let sub_page = laid_out(
            &[(PF_X | 0x4, 0, 0x4b9, 0x10), (0x4, 0x4c0, 0x300, 0x10)],
            &[
                (".text", PROGBITS, code, 0x100, 0x3b9),
                (".dynsym", SHT_DYNSYM, SHF_ALLOC, 0x4c0, 0x100),
                (".rodata", PROGBITS, SHF_ALLOC, 0x5c0, 0x100),
                (".eh_frame", PROGBITS, SHF_ALLOC, 0x6c0, 0x100),
            ],
        );
        assert_eq!(
            facts_of(&sub_page).data_in_code_pages,
            Some(vec![
                ".dynsym".to_owned(),
                ".rodata".to_owned(),
                ".eh_frame".to_owned()
            ])
        );
        // The same object with its code segment declaring no alignment is read at the
        // floor too: the next page's `.rodata` stays out, still separated.
        let unaligned = laid_out(
            &[(PF_X | 0x4, 0x1000, 0x400, 0), (0x4, 0x2000, 0x200, page)],
            &[
                (".text", PROGBITS, code, 0x1000, 0x400),
                (".rodata", PROGBITS, SHF_ALLOC, 0x2000, 0x200),
            ],
        );
        assert_eq!(facts_of(&unaligned).data_in_code_pages, Some(Vec::new()));
        // No referent: no executable segment, or no allocated section to classify.
        let no_code = laid_out(
            &[(0x4, 0, 0x900, page)],
            &[(".rodata", PROGBITS, SHF_ALLOC, 0x600, 0x100)],
        );
        assert_eq!(facts_of(&no_code).data_in_code_pages, None);
        let no_alloc = laid_out(
            &[(PF_X | 0x4, 0, 0x900, page)],
            &[(".comment", PROGBITS, 0, 0x600, 0x100)],
        );
        assert_eq!(facts_of(&no_alloc).data_in_code_pages, None);
        let stripped = elf64_header(0, 56, 0, 64);
        assert_eq!(facts_of(&stripped).data_in_code_pages, None);
    }

    /// `openbsd_nobtcfi` is read from a program header of type `0x65a3dbe8`, written here
    /// as a literal so a typo in the reader's constant fails rather than agreeing with
    /// itself. The value is OpenBSD 7.9's (`/usr/include/llvm/BinaryFormat/ELF.h`), and the
    /// header lld 22.1.8 writes under `-z nobtcfi`, which readelf prints as
    /// `OPENBSD_NOBTCF`. The replay case in `tests/detector_replay.rs` reads the recorded
    /// fact, not bytes, so without this test a wrong constant would pass every Mac and Linux
    /// gate.
    ///
    /// The paired object retypes the same header to its neighbours on either side, and
    /// one has no program header of that kind at all.
    #[test]
    fn the_nobtcfi_header_is_read_from_its_program_header_type() {
        let tagged = |p_type: u32| {
            // `synth` writes PT_DYNAMIC first and PT_GNU_STACK second; the second is retyped.
            let mut d = synth(3, &[], false, false, Some(PF_X));
            d[64 + 56..64 + 56 + 4].copy_from_slice(&p_type.to_le_bytes());
            d
        };
        assert!(facts_of(&tagged(0x65a3_dbe8)).openbsd_nobtcfi);
        for neighbour in [0x65a3_dbe7, 0x65a3_dbe9, PT_GNU_STACK] {
            assert!(
                !facts_of(&tagged(neighbour)).openbsd_nobtcfi,
                "p_type {neighbour:#x} read as PT_OPENBSD_NOBTCFI"
            );
        }
        assert!(!facts_of(&synth(3, &[], false, false, None)).openbsd_nobtcfi);
    }

    /// A link-classification fact of an object the loader can run. Every builder here
    /// writes `ET_EXEC` or `ET_DYN`, so `None` is a wrong answer.
    fn linked(fact: Option<bool>) -> bool {
        fact.expect("a linked object carries its classification")
    }

    /// A paired case: the input that must produce the fact, the input that must not, and
    /// how to read it back.
    type Case = (&'static str, Vec<u8>, Vec<u8>, fn(&ElfFacts) -> bool);

    /// The rows that decide the link classification, split from `derived_fact_cases` only
    /// to keep each under the line cap.
    fn link_fact_cases() -> Vec<Case> {
        vec![
            (
                "pie needs ET_DYN and DF_1_PIE",
                synth(ET_DYN, &[(DT_FLAGS_1, DF_1_PIE)], false, false, None),
                synth(ET_EXEC, &[(DT_FLAGS_1, DF_1_PIE)], false, false, None),
                |f| linked(f.pie),
            ),
            (
                "pie also from an interpreter",
                synth(ET_DYN, &[], true, false, None),
                synth(ET_DYN, &[], false, false, None),
                |f| linked(f.pie),
            ),
            (
                "static_pie is DF_1_PIE without an interpreter",
                synth(ET_DYN, &[(DT_FLAGS_1, DF_1_PIE)], false, false, None),
                synth(ET_DYN, &[(DT_FLAGS_1, DF_1_PIE)], true, false, None),
                |f| linked(f.static_pie),
            ),
            (
                "static_pie is DT_DEBUG without an interpreter, with no DT_FLAGS_1 at all",
                synth(ET_DYN, &[(DT_DEBUG, 0)], false, false, None),
                synth(ET_DYN, &[(DT_DEBUG, 0)], true, false, None),
                |f| linked(f.static_pie),
            ),
            (
                "shared_object is ET_DYN, no PIE marking, no interpreter \
                 (report::link_mode_limitation)",
                synth(ET_DYN, &[(DT_FLAGS_1, 0)], false, false, None),
                synth(ET_DYN, &[(DT_FLAGS_1, DF_1_PIE)], false, false, None),
                |f| linked(f.shared_object),
            ),
            (
                "shared_object is not an object carrying DT_DEBUG",
                synth(ET_DYN, &[(DT_FLAGS_1, 0)], false, false, None),
                synth(
                    ET_DYN,
                    &[(DT_FLAGS_1, 0), (DT_DEBUG, 0)],
                    false,
                    false,
                    None,
                ),
                |f| linked(f.shared_object),
            ),
            (
                "dt_debug",
                synth(ET_EXEC, &[(DT_DEBUG, 0)], true, false, None),
                synth(ET_EXEC, &[(DT_FLAGS_1, 0)], true, false, None),
                |f| f.dt_debug,
            ),
            (
                "dt_soname",
                synth(ET_DYN, &[(DT_SONAME, 1)], false, false, None),
                synth(ET_DYN, &[(DT_DEBUG, 0)], false, false, None),
                |f| f.dt_soname,
            ),
        ]
    }

    /// Lifted out of the test only to keep it under the line cap.
    fn derived_fact_cases() -> Vec<Case> {
        let rest: Vec<Case> = vec![
            (
                "bind_now via DT_BIND_NOW",
                synth(ET_DYN, &[(DT_BIND_NOW, 0)], false, false, None),
                synth(ET_DYN, &[], false, false, None),
                |f| linked(f.bind_now),
            ),
            (
                "bind_now via DF_BIND_NOW",
                synth(ET_DYN, &[(DT_FLAGS, DF_BIND_NOW)], false, false, None),
                synth(ET_DYN, &[(DT_FLAGS, 0)], false, false, None),
                |f| linked(f.bind_now),
            ),
            (
                "bind_now via DF_1_NOW",
                synth(ET_DYN, &[(DT_FLAGS_1, DF_1_NOW)], false, false, None),
                synth(ET_DYN, &[(DT_FLAGS_1, 0)], false, false, None),
                |f| linked(f.bind_now),
            ),
            (
                "textrel via DT_TEXTREL, with no DT_FLAGS to carry the bit",
                synth(ET_DYN, &[(DT_TEXTREL, 0)], false, false, None),
                synth(ET_DYN, &[], false, false, None),
                |f| f.textrel,
            ),
            (
                "textrel via DF_TEXTREL",
                synth(ET_DYN, &[(DT_FLAGS, DF_TEXTREL)], false, false, None),
                synth(ET_DYN, &[(DT_FLAGS, 0)], false, false, None),
                |f| f.textrel,
            ),
            (
                "df_1_pie",
                synth(ET_DYN, &[(DT_FLAGS_1, DF_1_PIE)], false, false, None),
                synth(ET_DYN, &[(DT_FLAGS_1, DF_1_NOW)], false, false, None),
                |f| f.df_1_pie,
            ),
            (
                "df_1_noopen",
                synth(ET_DYN, &[(DT_FLAGS_1, DF_1_NOOPEN)], false, false, None),
                synth(ET_DYN, &[(DT_FLAGS_1, DF_1_PIE)], false, false, None),
                |f| f.df_1_noopen,
            ),
            (
                "textrel",
                synth(ET_DYN, &[(DT_FLAGS, DF_TEXTREL)], false, false, None),
                synth(ET_DYN, &[(DT_FLAGS, DF_BIND_NOW)], false, false, None),
                |f| f.textrel,
            ),
            (
                "dt_relr",
                synth(ET_DYN, &[(DT_RELR, 0x1000)], false, false, None),
                synth(ET_DYN, &[], false, false, None),
                |f| f.dt_relr,
            ),
            (
                "gnu_relro",
                synth(ET_DYN, &[], false, true, None),
                synth(ET_DYN, &[], false, false, None),
                |f| linked(f.gnu_relro),
            ),
            (
                "gnu_stack_executable",
                synth(ET_DYN, &[], false, false, Some(PF_X)),
                synth(ET_DYN, &[], false, false, Some(0)),
                |f| linked(f.gnu_stack_executable),
            ),
            (
                "gnu_stack_present",
                synth(ET_DYN, &[], false, false, Some(0)),
                synth(ET_DYN, &[], false, false, None),
                |f| linked(f.gnu_stack_present),
            ),
        ];
        let mut cases = link_fact_cases();
        cases.extend(rest);
        cases
    }

    /// Every derived hardening fact flips with the input that decides it, and with nothing
    /// else.
    ///
    /// Without this test, `cargo mutants` over this file leaves survivors exactly here:
    /// `flags & DF_BIND_NOW` mutated to `flags | DF_BIND_NOW` survives the whole suite, so
    /// nothing would notice `bind_now` reading true for every binary on earth. Same for
    /// `&` -> `^`, for the `!=` comparisons against each mask, and for the `&&`/`||` in
    /// `static_pie`, `shared_object` and `statically_linked`. The other tests that parse
    /// real binaries only assert that they do not panic.
    ///
    /// Table-driven and paired: each row states an input that should produce the fact and
    /// an input that should not, so a mutant that hard-wires either answer dies. A one-
    /// sided test would have passed against `| MASK`.
    #[test]
    fn each_derived_fact_is_decided_by_its_own_bit() {
        let cases = derived_fact_cases();
        let mut checked = 0;
        for (name, with, without, read) in &cases {
            assert!(
                read(&facts_of(with)),
                "{name}: absent when the input says present"
            );
            assert!(
                !read(&facts_of(without)),
                "{name}: present when the input says absent"
            );
            checked += 1;
        }
        // The frame beside the count: a row silently dropped would leave a fact unpinned.
        assert_eq!(checked, 20, "every row must run");

        // `relro: full` needs BOTH the segment and bind-now, so the `&&` cannot become `||`.
        let full = facts_of(&synth(ET_DYN, &[(DT_BIND_NOW, 0)], false, true, None));
        assert_eq!(full.relro.as_deref(), Some("full"));
        let partial = facts_of(&synth(ET_DYN, &[], false, true, None));
        assert_eq!(
            partial.relro.as_deref(),
            Some("partial"),
            "relro without bind-now is partial"
        );
        let none = facts_of(&synth(ET_DYN, &[(DT_BIND_NOW, 0)], false, false, None));
        assert_eq!(
            none.relro.as_deref(),
            Some("none"),
            "bind-now without the segment is not relro"
        );

        // `statically_linked` is neither an interpreter nor a shared object, so neither
        // operand may be dropped.
        assert!(linked(
            facts_of(&synth(ET_EXEC, &[], false, false, None)).statically_linked
        ));
        assert!(!linked(
            facts_of(&synth(ET_DYN, &[(DT_FLAGS, 0)], false, false, None)).statically_linked
        ));
        assert!(!linked(
            facts_of(&synth(ET_EXEC, &[], true, false, None)).statically_linked
        ));
    }

    /// The link classification is one value flattened five ways, and only for an object
    /// the loader can run.
    ///
    /// Reproduced with `gcc -c` on a canary: `chard elf t.o` printed `elf_type: "ET_1"`,
    /// `statically_linked: true`, `relro: "none"`, `gnu_stack_present: false`, for a file
    /// `readelf -h` describes as `REL` with no program headers. Every one of those was
    /// the falsy default for a question the object cannot answer, and `relro: "none"` is
    /// a false `off` by another route. And on a linked file, `static_pie: true` sat
    /// beside `statically_linked: false`, because "statically linked" was defined as "no
    /// dynamic section" and a static PIE has one.
    ///
    /// The grid is every `e_type` the reader names or ranges, crossed with the four
    /// inputs that decide the kind and `DT_SONAME`, which must not. `LinkKind` makes the
    /// contradictory pairs unrepresentable; this pins the flattening, which is where they
    /// could come back.
    #[test]
    fn link_facts_are_one_classification_and_only_for_an_object_the_loader_runs() {
        let mut linked_seen = 0;
        let mut unlinked_seen = 0;
        for (e_type, label) in [
            (ET_NONE, "ET_NONE"),
            (ET_REL, "ET_REL"),
            (ET_EXEC, "ET_EXEC"),
            (ET_DYN, "ET_DYN"),
            (ET_CORE, "ET_CORE"),
            (5u16, "unrecognised (e_type 0x5)"),
            (0xfe01, "unrecognised (OS-specific e_type 0xfe01)"),
            (0xff10, "unrecognised (processor-specific e_type 0xff10)"),
        ] {
            for row in grid_inputs() {
                let (interp, dynamic, df_1_pie, dt_debug, dt_soname) = row;
                let tags = grid_tags(row);
                let f = facts_of(&synth(e_type, &tags, interp, true, Some(0)));
                assert_eq!(f.elf_type, label);
                // The raw facts are the tags, whatever the type and whatever the kind.
                assert_eq!(
                    (f.df_1_pie, f.dt_debug, f.dt_soname),
                    (df_1_pie, dt_debug, dt_soname),
                    "{label}: the raw dynamic facts are read as written"
                );
                let all = [
                    f.pie,
                    f.static_pie,
                    f.shared_object,
                    f.statically_linked,
                    f.gnu_relro,
                    f.bind_now,
                    f.gnu_stack_present,
                    f.gnu_stack_executable,
                    f.relro.as_ref().map(|_| true),
                ];
                let runnable = matches!(e_type, ET_EXEC | ET_DYN);
                if !runnable {
                    assert!(
                        all.iter().all(Option::is_none),
                        "{label} interp={interp} dynamic={dynamic}: every link fact must be \
                         null for an object the loader cannot run, got {all:?}"
                    );
                    unlinked_seen += 1;
                    continue;
                }
                assert!(
                    all.iter().all(Option::is_some),
                    "{label}: every link fact is carried for a runnable object, got {all:?}"
                );
                linked_seen += 1;
                let (pie, static_pie, shared, static_) = (
                    linked(f.pie),
                    linked(f.static_pie),
                    linked(f.shared_object),
                    linked(f.statically_linked),
                );
                // The invariants the enum carries, read back through the flattening.
                assert!(
                    !static_pie || static_,
                    "{label}: a static PIE is statically linked"
                );
                assert!(
                    !(shared && static_),
                    "{label}: a shared object is not statically linked"
                );
                assert!(
                    !pie || e_type == ET_DYN,
                    "{label}: only ET_DYN can be a PIE"
                );
                assert!(!static_pie || pie, "{label}: a static PIE is a PIE");
                assert_eq!(
                    static_,
                    !interp && !shared,
                    "{label} interp={interp} dynamic={dynamic} df_1_pie={df_1_pie}: \
                     statically linked is neither an interpreter nor a shared object"
                );
                let row = format!(
                    "{label} interp={interp} dynamic={dynamic} df_1_pie={df_1_pie} \
                     dt_debug={dt_debug} dt_soname={dt_soname}"
                );
                assert_eq!(
                    shared,
                    e_type == ET_DYN && !interp && dynamic && !df_1_pie && !dt_debug,
                    "{row}"
                );
                // Either marker makes an interpreter-less ET_DYN a static PIE, and
                // DT_SONAME changes nothing.
                assert_eq!(
                    static_pie,
                    e_type == ET_DYN && !interp && (df_1_pie || dt_debug),
                    "{row}"
                );
            }
        }
        // The frame: both halves of the grid ran, over the rows `grid_inputs` lists.
        let rows = grid_inputs().len();
        assert_eq!(rows, 18);
        assert_eq!(linked_seen, 2 * rows);
        assert_eq!(unlinked_seen, 6 * rows);
    }

    /// `(interp, dynamic, df_1_pie, dt_debug, dt_soname)`: one row of the classification
    /// grid.
    type GridRow = (bool, bool, bool, bool, bool);

    /// The `.dynamic` a grid row names: `DT_FLAGS_1` whenever there is a dynamic section,
    /// carrying `DF_1_PIE` or nothing, and the two marker tags as the row says.
    fn grid_tags(row: GridRow) -> Vec<(i64, u64)> {
        let (_, dynamic, df_1_pie, dt_debug, dt_soname) = row;
        let mut tags = Vec::new();
        if dynamic {
            tags.push((DT_FLAGS_1, if df_1_pie { DF_1_PIE } else { 0 }));
        }
        if dt_debug {
            tags.push((DT_DEBUG, 0));
        }
        if dt_soname {
            tags.push((DT_SONAME, 1));
        }
        tags
    }

    /// `(interp, dynamic, df_1_pie, dt_debug, dt_soname)` for the classification grid:
    /// every combination, less the ones that name a dynamic tag on an object with no
    /// dynamic section, which cannot carry one.
    fn grid_inputs() -> Vec<GridRow> {
        let mut rows = Vec::new();
        for interp in [false, true] {
            rows.push((interp, false, false, false, false));
            for bits in 0..8u8 {
                rows.push((interp, true, bits & 1 != 0, bits & 2 != 0, bits & 4 != 0));
            }
        }
        rows
    }

    /// `DT_DEBUG` is executable output with or without `DT_SONAME`, and `DT_SONAME` alone
    /// is a shared object.
    ///
    /// The first pair is what `-soname` on an executable link writes: measured on
    /// 2026-09-28 for static PIEs from GNU ld 2.46.1, lld 22.1.8, mold 2.40.4 and lld
    /// 10.0.0, the last with no `DT_FLAGS_1` at all, while every shared object measured
    /// lacked `DT_DEBUG`. A classifier that let the name veto the marker would read the
    /// lld 10.0.0 executable as a library and its `pie` as `off`. So the pair is pinned
    /// here, on bytes, with the other three corners beside it so that neither tag can be
    /// dropped from the rule; `LinkKind::StaticPie` records the runs.
    #[test]
    fn debug_marks_executable_output_whatever_the_soname() {
        let read = |tags: &[(i64, u64)]| facts_of(&synth(ET_DYN, tags, false, false, None));
        let mut corners = 0;
        for (tags, static_pie, label) in [
            (
                &[(DT_DEBUG, 0), (DT_SONAME, 1)][..],
                true,
                "DT_DEBUG beside DT_SONAME",
            ),
            (&[(DT_DEBUG, 0)][..], true, "DT_DEBUG alone"),
            (&[(DT_SONAME, 1)][..], false, "DT_SONAME alone"),
            (&[(DT_FLAGS_1, 0)][..], false, "neither"),
        ] {
            let f = read(tags);
            assert_eq!(f.static_pie, Some(static_pie), "{label}: static_pie");
            assert_eq!(f.pie, Some(static_pie), "{label}: pie");
            assert_eq!(f.shared_object, Some(!static_pie), "{label}: shared_object");
            assert_eq!(
                f.statically_linked,
                Some(static_pie),
                "{label}: statically_linked"
            );
            corners += 1;
        }
        assert_eq!(corners, 4, "every corner of the pair ran");
    }

    /// The link classification is required in a recording, as `null` or a value.
    ///
    /// serde reads a missing `Option` field as `None`, which here would let a recording
    /// with no such field pass for a measurement of "this object carries no
    /// classification". `probe` and `measure` deserialize their fixtures so that a missing
    /// field fails loudly; this is what keeps that true for these nine.
    #[test]
    fn a_recording_must_carry_the_link_classification_even_as_null() {
        let facts = facts_of(&synth(ET_DYN, &[], true, false, None));
        let mut value = serde_json::to_value(&facts).expect("serializes");

        value["pie"] = serde_json::Value::Null;
        let read: ElfFacts = serde_json::from_value(value.clone()).expect("null is a value");
        assert_eq!(read.pie, None, "null reads as unclassified");

        value.as_object_mut().expect("an object").remove("pie");
        let err = serde_json::from_value::<ElfFacts>(value).expect_err("a missing field fails");
        assert!(
            err.to_string().contains("pie"),
            "the error names the field: {err}"
        );

        // And a relocatable object serializes the classification as null, so a report
        // reader sees `null` where the object could not carry the fact.
        let rel = serde_json::to_value(facts_of(&synth(ET_REL, &[], false, true, Some(0))))
            .expect("serializes");
        for field in ["pie", "relro", "gnu_stack_present", "statically_linked"] {
            assert!(
                rel.get(field).is_some_and(serde_json::Value::is_null),
                "{field} must serialize as null for ET_REL, got {:?}",
                rel.get(field)
            );
        }
    }

    /// A `.symtab` is read, its `sh_link` is believed only when it names a string table,
    /// and a symbol's definedness comes from its own `st_shndx`.
    ///
    /// Five survivors sat in `symbols` with nothing to catch them, and each publishes a
    /// wrong answer about the stack protector, whose verdict is `__stack_chk_fail` in
    /// `watched_symbols`:
    ///
    /// - `sh_type != SHT_SYMTAB` to `==` skips `.symtab` while leaving `.dynsym` working,
    ///   so it is invisible to every test that links dynamically — which the existing
    ///   canary test does — and blinds the check on a statically linked binary.
    /// - the `sh_link != 0 && link.sh_type == SHT_STRTAB` guard to `true`, or its `&&` to
    ///   `||`, restores the exact defect the comment inside `symbols` records as
    ///   reproduced: names read from file offset zero come back empty, every symbol is
    ///   skipped, and the table reports no symbols rather than reporting itself unreadable.
    /// - `st_shndx != 0` to `==` swaps defined for undefined, which is the distinction
    ///   between a binary that *references* the canary and one that statically links libssp.
    /// - deleting the `!` in `!entry.tables.contains(&table)` records one table twice for a
    ///   name that appears in it twice.
    ///
    /// Built as bytes rather than compiled, because no compiler emits a symbol table whose
    /// `sh_link` is zero. That case arises from stripping, corruption, or a file chard did
    /// not build — which is the input this reader exists to survive.
    #[test]
    fn a_symbol_table_is_read_only_through_a_string_table_that_exists() {
        // One SHT_NULL, one SHT_SYMTAB, one SHT_STRTAB holding both section and symbol
        // names. No program headers: symbols come from sections alone.
        const SYMS: usize = 0x400;
        const STRS: usize = 0x600;
        const NAME_SYMTAB: u32 = 1;
        const NAME_STRTAB: u32 = 9;
        const NAME_FAIL: u32 = 17;
        const NAME_LOCAL: u32 = 34;

        let build = |sh_link: u32| -> Vec<u8> {
            let mut d = elf64_header(0, 56, 3, 64);
            d.resize(0x800, 0);
            d[40..48].copy_from_slice(&64u64.to_le_bytes()); // e_shoff
            d[62..64].copy_from_slice(&2u16.to_le_bytes()); // e_shstrndx -> the strtab

            // shdr[1]: the symbol table.
            let s = 64 + 64;
            d[s..s + 4].copy_from_slice(&NAME_SYMTAB.to_le_bytes());
            d[s + 4..s + 8].copy_from_slice(&SHT_SYMTAB.to_le_bytes());
            d[s + 24..s + 32].copy_from_slice(&(SYMS as u64).to_le_bytes()); // sh_offset
            d[s + 32..s + 40].copy_from_slice(&(3u64 * 24).to_le_bytes()); // sh_size
            d[s + 40..s + 44].copy_from_slice(&sh_link.to_le_bytes());
            d[s + 56..s + 64].copy_from_slice(&24u64.to_le_bytes()); // sh_entsize

            // shdr[2]: the string table.
            let t = 64 + 128;
            d[t..t + 4].copy_from_slice(&NAME_STRTAB.to_le_bytes());
            d[t + 4..t + 8].copy_from_slice(&SHT_STRTAB.to_le_bytes());
            d[t + 24..t + 32].copy_from_slice(&(STRS as u64).to_le_bytes());
            d[t + 32..t + 40].copy_from_slice(&57u64.to_le_bytes());

            d[STRS + 1..STRS + 9].copy_from_slice(b".symtab\0");
            d[STRS + 9..STRS + 17].copy_from_slice(b".strtab\0");
            d[STRS + 17..STRS + 34].copy_from_slice(b"__stack_chk_fail\0");
            d[STRS + 34..STRS + 57].copy_from_slice(b"__stack_chk_fail_local\0");

            // Three records: the canary symbol defined, the same name a second time so the
            // table-dedup has something to dedup, and a watched symbol left undefined.
            for (i, (name, shndx)) in [(NAME_FAIL, 1u16), (NAME_FAIL, 1u16), (NAME_LOCAL, 0u16)]
                .iter()
                .enumerate()
            {
                let b = SYMS + i * 24;
                d[b..b + 4].copy_from_slice(&name.to_le_bytes());
                d[b + 6..b + 8].copy_from_slice(&shndx.to_le_bytes());
            }
            d
        };

        let facts = Elf::parse(&build(2)).expect("parses").facts();
        let fail = facts
            .watched_symbols
            .get("__stack_chk_fail")
            .expect("the canary symbol is in .symtab and must be read from it");
        assert!(fail.defined, "st_shndx 1 is a defined symbol");
        assert_eq!(
            fail.tables,
            vec![".symtab".to_owned()],
            "one table, recorded once, however many times the name appears in it"
        );
        let local = facts
            .watched_symbols
            .get("__stack_chk_fail_local")
            .expect("an undefined symbol is still a symbol");
        assert!(
            !local.defined,
            "st_shndx 0 is SHN_UNDEF: a reference, not a definition"
        );

        // sh_link 0 is SHN_UNDEF, whose sh_offset is 0. Believing it reads names from the
        // start of the file, which yields nothing and looks like an empty table.
        let broken = Elf::parse(&build(0)).expect("parses").facts();
        assert!(
            broken.watched_symbols.is_empty(),
            "names cannot be resolved through sh_link 0, so no symbol is claimed"
        );
        assert!(
            broken.truncations.iter().any(|t| {
                t.table == ElfTable::Symbols
                    && t.kind == TruncationKind::Unread
                    && t.detail.contains("sh_link")
                    && t.detail.contains(".symtab")
            }),
            "an unreadable symbol table must say so rather than report zero symbols: {:?}",
            broken.truncations
        );

        // A third case, because the two above do not separate the guard's `&&` from `||`:
        // with `sh_link` zero *both* operands are false, so either operator rejects. Only a
        // link that exists and is not a string table tells them apart — here `sh_link` names
        // the symbol table itself.
        //
        // The observable is the truncation, not the symbol set. Reading names through a
        // symbol table lands in a record's zero padding, so the names come back empty and
        // the symbols are skipped either way: an `||` that wrongly accepts this link is
        // silent, and silence is what the truncation exists to break.
        let wrong_kind = Elf::parse(&build(1)).expect("parses").facts();
        assert!(
            wrong_kind.truncations.iter().any(|t| {
                t.table == ElfTable::Symbols
                    && t.kind == TruncationKind::Unread
                    && t.detail.contains("does not name a string table")
            }),
            "sh_link naming a non-strtab section must be refused and said aloud: {:?}",
            wrong_kind.truncations
        );
        assert!(
            wrong_kind.watched_symbols.is_empty(),
            "no symbol may be claimed through a link that is not a string table"
        );
    }

    /// A relocatable object laid out for [`Elf::code_relocations`]: `.text` (code),
    /// `.rela.text` applying to it, `.symtab`, `.strtab` (which also names the sections),
    /// `.data`, and `.rela.data` applying to that. Symbols: the null symbol, a section
    /// symbol for `.text`, the undefined `chard_no_plt_callee`, and a defined caller.
    /// `text_relocs` is `(symbol, type)` per `.rela.text` record.
    struct RelObject {
        e_type: u16,
        text_relocs: Vec<(u64, u64)>,
        text_rela_link: u32,
        text_rela_size_extra: usize,
    }

    /// A section header's fields as `RelObject::build` writes them: name, type, flags,
    /// offset, size, link, info and entry size.
    type Header = (u32, u32, u64, usize, u64, u32, u32, u64);

    impl RelObject {
        fn new(text_relocs: Vec<(u64, u64)>) -> Self {
            Self {
                e_type: ET_REL,
                text_relocs,
                text_rela_link: 3,
                text_rela_size_extra: 0,
            }
        }

        fn build(&self) -> Vec<u8> {
            const SHDRS: usize = 64;
            const SYMS: usize = 0x300;
            const STRS: usize = 0x400;
            const DATA_RELA: usize = 0x500;
            const TEXT_RELA: usize = 0x600;
            // Names in the one string table, at fixed offsets.
            let strings: &[(usize, &[u8])] = &[
                (1, b".text\0"),
                (7, b".rela.text\0"),
                (18, b".symtab\0"),
                (26, b".strtab\0"),
                (34, b".data\0"),
                (40, b".rela.data\0"),
                (51, b"chard_no_plt_callee\0"),
                (71, b"chard_no_plt_caller\0"),
            ];
            let mut d = elf64_header(0, 56, 7, 64);
            d[16..18].copy_from_slice(&self.e_type.to_le_bytes());
            d[62..64].copy_from_slice(&4u16.to_le_bytes()); // e_shstrndx -> .strtab
            let text_len = self.text_relocs.len() * 24 + self.text_rela_size_extra;
            let text_size = u64::try_from(text_len).expect("fits");
            d.resize(TEXT_RELA + text_len + 64, 0);
            // (name, type, flags, offset, size, link, info, entsize)
            let headers: [Header; 6] = [
                (1, 1, SHF_ALLOC | SHF_EXECINSTR, 0x200, 16, 0, 0, 0),
                (
                    7,
                    SHT_RELA,
                    0,
                    TEXT_RELA,
                    text_size,
                    self.text_rela_link,
                    1,
                    24,
                ),
                (18, SHT_SYMTAB, 0, SYMS, 4 * 24, 4, 2, 24),
                (26, SHT_STRTAB, 0, STRS, 91, 0, 0, 0),
                (34, 1, SHF_ALLOC | 0x1, 0x280, 8, 0, 0, 0),
                (40, SHT_RELA, 0, DATA_RELA, 24, 3, 5, 24),
            ];
            for (n, (name, kind, flags, off, size, link, info, entsize)) in
                headers.iter().enumerate()
            {
                let h = SHDRS + (n + 1) * 64;
                d[h..h + 4].copy_from_slice(&name.to_le_bytes());
                d[h + 4..h + 8].copy_from_slice(&kind.to_le_bytes());
                d[h + 8..h + 16].copy_from_slice(&flags.to_le_bytes());
                d[h + 24..h + 32].copy_from_slice(&(*off as u64).to_le_bytes());
                d[h + 32..h + 40].copy_from_slice(&size.to_le_bytes());
                d[h + 40..h + 44].copy_from_slice(&link.to_le_bytes());
                d[h + 44..h + 48].copy_from_slice(&info.to_le_bytes());
                d[h + 56..h + 64].copy_from_slice(&entsize.to_le_bytes());
            }
            for (at, text) in strings {
                d[STRS + at..STRS + at + text.len()].copy_from_slice(text);
            }
            // Symbols: [1] the `.text` section symbol, [2] the callee, undefined, [3] the
            // caller, defined in `.text`.
            for (i, (name, info, shndx)) in [(0u32, 3u8, 1u16), (51, 0x12, 0), (71, 0x12, 1)]
                .iter()
                .enumerate()
            {
                let b = SYMS + (i + 1) * 24;
                d[b..b + 4].copy_from_slice(&name.to_le_bytes());
                d[b + 4] = *info;
                d[b + 6..b + 8].copy_from_slice(&shndx.to_le_bytes());
            }
            let write = |d: &mut Vec<u8>, at: usize, symbol: u64, kind: u64| {
                d[at + 8..at + 16].copy_from_slice(&((symbol << 32) | kind).to_le_bytes());
            };
            // `.rela.data` names the callee too, as a data reference to it would.
            write(&mut d, DATA_RELA, 2, 1);
            for (i, (symbol, kind)) in self.text_relocs.iter().enumerate() {
                write(&mut d, TEXT_RELA + i * 24, *symbol, *kind);
            }
            d
        }

        fn facts(&self) -> ElfFacts {
            Elf::parse(&self.build()).expect("parses").facts()
        }
    }

    fn relocation_cuts(facts: &ElfFacts) -> Vec<&str> {
        facts
            .truncations
            .iter()
            .filter(|t| t.table == ElfTable::Relocations)
            .map(|t| t.detail.as_str())
            .collect()
    }

    /// The reader records a code section's relocations against named symbols, defined or
    /// not, as `TYPE SYMBOL`, once each, and one through a section symbol by its section in
    /// brackets: not those against the null symbol, not those applying to a data section,
    /// and an unnamed type by number.
    #[test]
    fn code_relocations_name_the_symbols_code_reaches() {
        let facts = RelObject::new(vec![(2, 4), (2, 4), (3, 2), (1, 2), (0, 0), (2, 99)]).facts();
        assert_eq!(
            facts.code_relocations,
            Some(vec![
                "R_X86_64_PC32 [.text]".to_owned(),
                "R_X86_64_PC32 chard_no_plt_caller".to_owned(),
                "R_X86_64_PLT32 chard_no_plt_callee".to_owned(),
                "reloc-type-0x63 chard_no_plt_callee".to_owned(),
            ])
        );
        assert!(
            relocation_cuts(&facts).is_empty(),
            "{:?}",
            facts.truncations
        );

        let none = RelObject::new(Vec::new()).facts();
        assert_eq!(
            none.code_relocations,
            Some(Vec::new()),
            "an object whose code names no symbol has an empty list, not none"
        );

        let mut linked = RelObject::new(vec![(2, 4)]);
        linked.e_type = ET_DYN;
        assert_eq!(
            linked.facts().code_relocations,
            None,
            "a linked object's relocations are the linker's, not the compiler's"
        );
    }

    /// Each stop in the walk is recorded against `relocations`, and the records read before
    /// it are kept.
    ///
    /// The `function_references` walk reads the same sections and records its own stop
    /// beside this walk's where it stops too, so each case asserts this walk's record among
    /// the section's records rather than the only one.
    #[test]
    fn a_relocation_section_the_reader_cannot_finish_is_recorded() {
        let mut partial = RelObject::new(vec![(2, 41)]);
        partial.text_rela_size_extra = 5;
        let facts = partial.facts();
        assert_eq!(
            facts.code_relocations,
            Some(vec!["R_X86_64_GOTPCRELX chard_no_plt_callee".to_owned()])
        );
        let cuts = relocation_cuts(&facts);
        assert!(
            cuts.iter().all(|c| c.starts_with(".rela.text: "))
                && cuts.iter().any(|c| c.contains("a partial one")),
            "{cuts:?}"
        );

        let facts = RelObject::new(vec![(2, 4), (9, 41), (2, 41)]).facts();
        assert_eq!(
            facts.code_relocations,
            Some(vec!["R_X86_64_PLT32 chard_no_plt_callee".to_owned()]),
            "the records from the bad symbol index on are not read"
        );
        let cuts = relocation_cuts(&facts);
        assert!(
            cuts.iter().all(|c| c.starts_with(".rela.text: "))
                && cuts
                    .iter()
                    .any(|c| c.contains("past its symbol table of 4")),
            "{cuts:?}"
        );

        let mut unlinked = RelObject::new(vec![(2, 4)]);
        unlinked.text_rela_link = 0;
        let facts = unlinked.facts();
        assert_eq!(facts.code_relocations, Some(Vec::new()));
        let cuts = relocation_cuts(&facts);
        assert!(
            cuts.iter().all(|c| c.starts_with(".rela.text: "))
                && cuts.iter().any(|c| c.contains("sh_link 0")),
            "{cuts:?}"
        );
        assert!(facts.unread(&[ElfTable::Relocations]).is_some());
    }

    /// The names the reader gives are elf.h's, by machine, and every other number renders
    /// as `reloc-type-` and hex, so no unnamed type reads as a named one. RISC-V's 19 read
    /// `reloc-type-0x13` until the table gained `EM_RISCV` (2026-10-05); `EM_LOONGARCH` has no
    /// table, and 42 is a number RISC-V leaves unassigned.
    #[test]
    fn relocation_types_are_named_by_machine() {
        assert_eq!(reloc_type_name(EM_X86_64, 4), "R_X86_64_PLT32");
        assert_eq!(reloc_type_name(EM_X86_64, 41), "R_X86_64_GOTPCRELX");
        assert_eq!(reloc_type_name(EM_386, 43), "R_386_GOT32X");
        assert_eq!(reloc_type_name(EM_AARCH64, 283), "R_AARCH64_CALL26");
        assert_eq!(reloc_type_name(EM_AARCH64, 311), "R_AARCH64_ADR_GOT_PAGE");
        assert_eq!(
            reloc_type_name(EM_AARCH64, 313),
            "R_AARCH64_LD64_GOTPAGE_LO15"
        );
        assert_eq!(reloc_type_name(EM_RISCV, 19), "R_RISCV_CALL_PLT");
        assert_eq!(reloc_type_name(EM_RISCV, 20), "R_RISCV_GOT_HI20");
        assert_eq!(reloc_type_name(EM_RISCV, 42), "reloc-type-0x2a");
        assert_eq!(reloc_type_name(EM_LOONGARCH, 19), "reloc-type-0x13");
        assert_eq!(reloc_type_name(EM_X86_64, 40), "reloc-type-0x28");
    }

    /// A `.symtab` name is keyed on what comes before its `@`, and `.dynsym`'s bare
    /// spelling lands on the same key.
    ///
    /// Reproduced with `gcc -O2 -D_FORTIFY_SOURCE=3 -fstack-protector-strong`: `chard elf`
    /// listed `__stack_chk_fail` and `__strcpy_chk` with `tables: [".dynsym"]` and
    /// `symbol_count: 40`, while `readelf -sW` shows both in `.symtab` too and the raw
    /// `.strtab` holds `__stack_chk_fail@GLIBC_2.4`. Forty distinct raw names, thirty-five
    /// once the versions are cut. Built as bytes, since no compiler here emits ELF; the
    /// `readelf` differential in `tests/elf_readelf.rs` pins it against a real `.strtab`
    /// on a Linux host.
    #[test]
    fn a_versioned_symtab_name_is_keyed_on_the_name_before_its_version() {
        // Sections: null, .dynsym (link 3), .symtab (link 4), .dynstr, .strtab, .shstrtab.
        const SHOFF: usize = 0x100;
        const DYNSYM_AT: u64 = 0x400;
        const SYMTAB_AT: u64 = 0x480;
        const DYNSTR_AT: u64 = 0x600;
        const STRTAB_AT: u64 = 0x680;
        const SHSTRTAB_AT: u64 = 0x780;
        const DYNSTR: &[u8] = b"\0__stack_chk_fail\0";
        const STRTAB: &[u8] = b"\0__stack_chk_fail@GLIBC_2.4\0__memcpy_chk@@GLIBC_2.3.4\0";
        const SHSTRTAB: &[u8] = b"\0.dynsym\0.symtab\0.dynstr\0.strtab\0.shstrtab\0";
        assert_eq!(&STRTAB[1..27], b"__stack_chk_fail@GLIBC_2.4");
        assert_eq!(&STRTAB[28..53], b"__memcpy_chk@@GLIBC_2.3.4");
        assert_eq!(&SHSTRTAB[1..8], b".dynsym");
        assert_eq!(&SHSTRTAB[9..16], b".symtab");
        assert_eq!(&SHSTRTAB[17..24], b".dynstr");
        assert_eq!(&SHSTRTAB[25..32], b".strtab");
        assert_eq!(&SHSTRTAB[33..42], b".shstrtab");

        let mut d = elf64_header(0, 56, 6, 64);
        d[40..48].copy_from_slice(&(SHOFF as u64).to_le_bytes());
        d[62..64].copy_from_slice(&5u16.to_le_bytes());
        let mut shdr = |i: usize, name: u32, kind: u32, off: u64, size: u64, link: u32| {
            let b = SHOFF + i * 64;
            d[b..b + 4].copy_from_slice(&name.to_le_bytes());
            d[b + 4..b + 8].copy_from_slice(&kind.to_le_bytes());
            d[b + 24..b + 32].copy_from_slice(&off.to_le_bytes());
            d[b + 32..b + 40].copy_from_slice(&size.to_le_bytes());
            d[b + 40..b + 44].copy_from_slice(&link.to_le_bytes());
            d[b + 56..b + 64].copy_from_slice(&24u64.to_le_bytes());
        };
        shdr(1, 1, SHT_DYNSYM, DYNSYM_AT, 2 * 24, 3);
        shdr(2, 9, SHT_SYMTAB, SYMTAB_AT, 3 * 24, 4);
        shdr(3, 17, SHT_STRTAB, DYNSTR_AT, DYNSTR.len() as u64, 0);
        shdr(4, 25, SHT_STRTAB, STRTAB_AT, STRTAB.len() as u64, 0);
        shdr(5, 33, SHT_STRTAB, SHSTRTAB_AT, SHSTRTAB.len() as u64, 0);
        for (at, bytes) in [
            (DYNSTR_AT, DYNSTR),
            (STRTAB_AT, STRTAB),
            (SHSTRTAB_AT, SHSTRTAB),
        ] {
            let at = usize::try_from(at).unwrap();
            d[at..at + bytes.len()].copy_from_slice(bytes);
        }
        // Symbol records: (table offset, st_name). All undefined, after the null symbol.
        for (at, names) in [(DYNSYM_AT, vec![0u32, 1]), (SYMTAB_AT, vec![0u32, 1, 28])] {
            for (i, name) in names.iter().enumerate() {
                let b = usize::try_from(at).unwrap() + i * 24;
                d[b..b + 4].copy_from_slice(&name.to_le_bytes());
            }
        }

        let facts = facts_of(&d);
        assert!(
            facts.watched_symbols.keys().all(|k| !k.contains('@')),
            "no key carries a version: {:?}",
            facts.watched_symbols.keys().collect::<Vec<_>>()
        );
        let canary = facts
            .watched_symbols
            .get("__stack_chk_fail")
            .expect("the canary is keyed on its bare name");
        assert_eq!(
            canary.tables,
            vec![".dynsym".to_owned(), ".symtab".to_owned()],
            "both tables land on one key, whatever each spelled"
        );
        assert_eq!(
            canary.versioned,
            vec!["__stack_chk_fail@GLIBC_2.4".to_owned()],
            "the spelling that carried a version is kept"
        );
        let memcpy = facts
            .watched_symbols
            .get("__memcpy_chk")
            .expect("a default-version spelling is keyed before its first @");
        assert_eq!(memcpy.tables, vec![".symtab".to_owned()]);
        assert_eq!(
            memcpy.versioned,
            vec!["__memcpy_chk@@GLIBC_2.3.4".to_owned()]
        );
        assert_eq!(
            facts.symbol_count, 2,
            "two symbols, however many spellings the two tables held"
        );
    }

    /// The size cap is the size it says, on both sides of it.
    ///
    /// Without this test nothing holds `MAX_OBJECT_BYTES` to its value: mutating
    /// `512 * 1024 * 1024` to `512 + 1024 * 1024` or `512 * 1024 + 1024`, a cap of one
    /// megabyte or of half a one, survives the whole suite. Every other test parses bytes in
    /// memory through `Elf::parse`, which never consults the cap, so this is the only test
    /// of the code path that reads it. A cap that quietly shrinks refuses real objects as
    /// unparseable, and
    /// this reader reports a refusal as absence of evidence.
    ///
    /// Both files are sparse: `set_len` writes no blocks, and the oversize one is refused
    /// from its metadata without ever being opened for reading, which is the property that
    /// makes the cap worth having.
    #[test]
    fn the_object_size_cap_is_enforced_at_the_size_it_states() {
        let dir = std::env::temp_dir().join(format!("chard-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");

        // Comfortably above both mutated caps and far below the real one, so it
        // distinguishes them: the real reader parses it, a shrunken cap refuses it.
        let under = dir.join("under.so");
        let bytes = synth(ET_DYN, &[], false, false, None);
        std::fs::write(&under, &bytes).expect("write object");
        let f = std::fs::File::options()
            .write(true)
            .open(&under)
            .expect("reopen object");
        f.set_len(2 * 1024 * 1024).expect("extend sparsely");
        drop(f);
        assert!(
            facts_for(&under).is_ok(),
            "a two-mebibyte object is under the cap and must be read"
        );

        let over = dir.join("over.so");
        let f = std::fs::File::create(&over).expect("create oversize");
        f.set_len(MAX_OBJECT_BYTES + 1).expect("extend sparsely");
        drop(f);
        let err = facts_for(&over).expect_err("above the cap must be refused");
        let text = format!("{err}");
        assert!(
            text.contains("cap"),
            "the refusal must say it was the cap, not merely fail: {text}"
        );
        assert!(
            matches!(
                err,
                ElfError::TooLarge { size, cap, .. }
                    if size == Some(MAX_OBJECT_BYTES + 1) && cap == MAX_OBJECT_BYTES
            ),
            "the refusal is typed as the cap, with the size and the cap it compared: {err:?}"
        );

        // Propagated rather than `.ok()`-ed: `tests/discarded_failures.rs` counts every
        // construct in this file that turns a failure into a value, and a cleanup discard
        // is indistinguishable from a measurement one to a counter. A test that cannot
        // remove what it wrote should say so.
        std::fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    /// The aarch64 feature bits are read per flag, not as a word.
    ///
    /// The x86 pair is pinned this way against `flags & DF_BIND_NOW` mutating to
    /// `flags | DF_BIND_NOW`. The aarch64 three are pinned against six mutants across
    /// `aarch64_pac` and `aarch64_gcs`: `&` to `|`, `&` to `^`, and `!=` to `==` on each.
    ///
    /// Each of those six is a wrong hardening verdict on aarch64, because `gcs-marked`
    /// reads `aarch64_gcs` and `branch-protection-marked` reads `aarch64_pac`. `&` to `|`
    /// reads PAC as present whenever *any* feature bit is, which for a BTI-only build
    /// publishes protection the binary does not have. The aarch64 artifact channel rests
    /// on exactly these three lines.
    ///
    /// Paired per bit for the reason the CET test gives: the property is an AND-reduction
    /// of independent flags, so a mutant returning the whole word reads one bit as
    /// another, and only an input that must *not* produce the fact catches it.
    #[test]
    fn the_aarch64_feature_bits_are_read_independently() {
        // On an aarch64 object, since the word is decoded only there.
        let arm = |bits: u32| {
            let mut d = synth_with_property(
                ET_DYN,
                &[],
                false,
                false,
                None,
                Some((GNU_PROPERTY_AARCH64_FEATURE_1_AND, bits)),
            );
            d[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
            d
        };
        let all = arm(AARCH64_FEATURE_1_BTI | AARCH64_FEATURE_1_PAC | AARCH64_FEATURE_1_GCS);
        let bti = arm(AARCH64_FEATURE_1_BTI);
        let pac = arm(AARCH64_FEATURE_1_PAC);
        let gcs = arm(AARCH64_FEATURE_1_GCS);
        let none = arm(0);

        let f = facts_of(&all);
        assert!(
            f.aarch64_bti && f.aarch64_pac && f.aarch64_gcs,
            "all three bits set must read as all three"
        );
        // And the note was actually parsed, or every assertion here is vacuous.
        assert!(
            !f.gnu_property_types.is_empty(),
            "the synthetic aarch64 note was not parsed at all"
        );

        for (name, obj, want) in [
            ("bti", &bti, [true, false, false]),
            ("pac", &pac, [false, true, false]),
            ("gcs", &gcs, [false, false, true]),
            ("none", &none, [false, false, false]),
        ] {
            let f = facts_of(obj);
            assert_eq!(
                [f.aarch64_bti, f.aarch64_pac, f.aarch64_gcs],
                want,
                "{name}-only object read as [bti, pac, gcs] = {:?}",
                [f.aarch64_bti, f.aarch64_pac, f.aarch64_gcs]
            );
        }

        // The two architectures' properties share a note type and differ only by property
        // id, so reading one word for the other is a live confusion rather than a
        // theoretical one.
        assert!(
            !facts_of(&all).x86_ibt && !facts_of(&all).x86_shstk,
            "an aarch64 property is not an x86 one"
        );
    }

    /// The CET bits are read per flag, not as a word.
    ///
    /// Split out of the table above only because the two together exceeded the line cap.
    /// Paired per bit: the property is an AND-reduction of two independent flags, so a
    /// mutant returning the whole word, or flipping the comparison, reads one bit as the
    /// other. The note also exercises `align_up(12 + namesz, 8)` -- the rule the module
    /// header calls the one that must not be got wrong.
    #[test]
    fn the_cet_bits_are_read_independently() {
        let both = synth_with_note(
            ET_DYN,
            &[],
            false,
            false,
            None,
            Some(X86_FEATURE_1_IBT | X86_FEATURE_1_SHSTK),
        );
        let ibt_only = synth_with_note(ET_DYN, &[], false, false, None, Some(X86_FEATURE_1_IBT));
        let shstk_only =
            synth_with_note(ET_DYN, &[], false, false, None, Some(X86_FEATURE_1_SHSTK));
        let neither = synth_with_note(ET_DYN, &[], false, false, None, Some(0));
        assert!(facts_of(&both).x86_ibt && facts_of(&both).x86_shstk);
        assert!(facts_of(&ibt_only).x86_ibt, "IBT bit set must read as IBT");
        assert!(
            !facts_of(&ibt_only).x86_shstk,
            "IBT set must not read as SHSTK"
        );
        assert!(facts_of(&shstk_only).x86_shstk);
        assert!(
            !facts_of(&shstk_only).x86_ibt,
            "SHSTK set must not read as IBT"
        );
        assert!(!facts_of(&neither).x86_ibt && !facts_of(&neither).x86_shstk);
        assert!(
            !facts_of(&both).aarch64_bti,
            "an x86 property is not an aarch64 one"
        );
        // And the note must actually have been found, or every assertion above is vacuous.
        assert!(
            !facts_of(&both).gnu_property_types.is_empty(),
            "the synthetic note was not parsed at all"
        );
    }

    /// An ELF64 with one `PT_NOTE` holding two notes: a build-id-shaped one of the given
    /// descriptor size, then the `GNU_PROPERTY_X86_FEATURE_1_AND` note carrying IBT.
    ///
    /// `second_at` is where the second note is written, relative to the segment, and it is
    /// passed in rather than computed with `align_up`. Deriving it here would move the
    /// fixture and the parser together under a mutation of that function, and the test
    /// would pass against the mutant.
    fn two_note_segment(p_align: u64, first_descsz: u32, second_at: u64) -> Vec<u8> {
        let note_at: u64 = 0x600;
        let mut d = elf64_header(1, 56, 0, 64);
        d[16..18].copy_from_slice(&ET_DYN.to_le_bytes());

        let b = 64;
        d[b..b + 4].copy_from_slice(&PT_NOTE.to_le_bytes());
        d[b + 8..b + 16].copy_from_slice(&note_at.to_le_bytes());
        d[b + 32..b + 40].copy_from_slice(&second_at.saturating_add(28).to_le_bytes());
        d[b + 48..b + 56].copy_from_slice(&p_align.to_le_bytes());

        write_two_notes(&mut d, note_at, first_descsz, second_at);
        d
    }

    /// The same two notes in a `SHT_NOTE` *section*, which is the path a binary with
    /// section headers actually takes -- `notes()` only falls back to `PT_NOTE` when the
    /// section walk yields nothing.
    fn two_note_section(sh_addralign: u64, first_descsz: u32, second_at: u64) -> Vec<u8> {
        let note_at: u64 = 0x600;
        // No program headers: `e_phoff` and `e_shoff` are both 64 in this header, so the
        // two tables would overlap, and a count of zero is what keeps them apart.
        let mut d = elf64_header(0, 56, 1, 64);
        d[16..18].copy_from_slice(&ET_DYN.to_le_bytes());

        let b = 64;
        d[b + 4..b + 8].copy_from_slice(&SHT_NOTE.to_le_bytes());
        d[b + 24..b + 32].copy_from_slice(&note_at.to_le_bytes());
        d[b + 32..b + 40].copy_from_slice(&second_at.saturating_add(28).to_le_bytes());
        d[b + 48..b + 56].copy_from_slice(&sh_addralign.to_le_bytes());

        write_two_notes(&mut d, note_at, first_descsz, second_at);
        d
    }

    /// A build-id-shaped note of `first_descsz` bytes, then the IBT property note at
    /// `second_at`. Both names are `"GNU\0"`, so what separates them is type and position
    /// rather than a name the walk could shortcut on.
    fn write_two_notes(d: &mut [u8], note_at: u64, first_descsz: u32, second_at: u64) {
        const NT_GNU_BUILD_ID: u32 = 3;
        let n = usize::try_from(note_at).unwrap();
        d[n..n + 4].copy_from_slice(&4u32.to_le_bytes());
        d[n + 4..n + 8].copy_from_slice(&first_descsz.to_le_bytes());
        d[n + 8..n + 12].copy_from_slice(&NT_GNU_BUILD_ID.to_le_bytes());
        d[n + 12..n + 16].copy_from_slice(b"GNU\0");
        for i in 0..usize::try_from(first_descsz).unwrap() {
            d[n + 16 + i] = 0xAA;
        }

        let s = n + usize::try_from(second_at).unwrap();
        d[s..s + 4].copy_from_slice(&4u32.to_le_bytes());
        d[s + 4..s + 8].copy_from_slice(&12u32.to_le_bytes());
        d[s + 8..s + 12].copy_from_slice(&NT_GNU_PROPERTY_TYPE_0.to_le_bytes());
        d[s + 12..s + 16].copy_from_slice(b"GNU\0");
        d[s + 16..s + 20].copy_from_slice(&GNU_PROPERTY_X86_FEATURE_1_AND.to_le_bytes());
        d[s + 20..s + 24].copy_from_slice(&4u32.to_le_bytes());
        d[s + 24..s + 28].copy_from_slice(&X86_FEATURE_1_IBT.to_le_bytes());
    }

    /// The alignment a note container declares decides where the *next* note begins.
    ///
    /// A single note cannot show this. For `"GNU\0"` the descriptor sits at
    /// `align_up(12 + 4, a)`, which is 16 at every alignment an ELF note carries — and at
    /// zero too, since `align_up` returns the value unchanged for `align <= 1`. So one note
    /// parses identically however the alignment is read, which is why the whole fallback
    /// went untested while the tests looked thorough. It takes a second note, placed past a
    /// descriptor whose padding differs between the candidate alignments, to see it.
    ///
    /// Both cases put the second note at +24 and reach it by different routes, which is the
    /// point: a reader that ignores the declared 8 looks at +20, and one that treats a
    /// declared 0 as an alignment rather than falling back to 4 looks at +21. Either way
    /// the property note is missed and the object reads as having no CET markings -- the
    /// same class of silent wrong verdict as the off-by-four above, reached through the
    /// other operand.
    #[test]
    fn a_second_note_is_found_at_the_alignment_the_container_declares() {
        // Declared 8, first descriptor 4 bytes: 4 padded to 8 puts the second note at +24.
        let declared_8 = two_note_segment(8, 4, 24);
        // Declared 0 is not an alignment. The fallback is 4, and a 5-byte descriptor padded
        // to 8 lands at +24 as well; left unpadded at 0 it would be +21.
        let declared_0 = two_note_segment(0, 5, 24);

        // The same two cases through the section walk, which is the path a binary with
        // section headers takes. Both containers declare their alignment in their own
        // field, and each is read by its own line.
        let section_8 = two_note_section(8, 4, 24);
        let section_0 = two_note_section(0, 5, 24);
        // Declared 1 is what annobin writes on its `.gnu.build.attributes` sections. It is
        // below the 4 every note is padded to, so it reads as 4 and lands at +24 too; taken
        // at its word it would be +21, the declared-0 failure reached through a value the
        // `> 0` test let through.
        let section_1 = two_note_section(1, 5, 24);
        let segment_1 = two_note_segment(1, 5, 24);

        for (case, obj) in [
            ("PT_NOTE, declared 8", &declared_8),
            ("PT_NOTE, declared 0", &declared_0),
            ("PT_NOTE, declared 1", &segment_1),
            ("SHT_NOTE, declared 8", &section_8),
            ("SHT_NOTE, declared 0", &section_0),
            ("SHT_NOTE, declared 1", &section_1),
        ] {
            let f = facts_of(obj);
            assert!(
                !f.gnu_property_types.is_empty(),
                "{case}: the second note was not parsed at all"
            );
            assert!(
                f.x86_ibt,
                "{case}: the second note's IBT property was not read"
            );
            assert!(
                !f.truncations.iter().any(|t| t.table == ElfTable::Notes),
                "{case}: the note walk stopped part-way: {:?}",
                f.truncations
            );
        }
    }

    /// A stripped object says what it could not read, and an intact one stays quiet.
    ///
    /// Paired, because a one-sided test passes against a function that returns the message
    /// unconditionally. The message is evidence a reader acts on: it separates "the canary
    /// is absent" from "the canary could not be looked for", and the doc comment on
    /// `structural_truncations` puts an understated truncation on the same footing as an
    /// overstated verdict.
    #[test]
    fn a_stripped_object_reports_what_it_could_not_read() {
        // Same notes either way; what differs is whether a section-header table exists.
        let stripped = two_note_segment(8, 4, 24);
        let intact = two_note_section(8, 4, 24);

        let says_stripped = |o: &[u8]| {
            facts_of(o).truncations.iter().any(|t| {
                t.table == ElfTable::Symbols
                    && t.kind == TruncationKind::Unread
                    && t.detail.starts_with("no section-header table")
            })
        };
        assert!(
            says_stripped(&stripped),
            "an object with no section headers must say the symbol tables were unreachable"
        );
        assert!(
            !says_stripped(&intact),
            "an object with section headers must not claim they are missing"
        );
    }

    /// A property note the file does not hold whole is recorded, and the bits it would
    /// have carried read as unread.
    ///
    /// The same two-note segment, cut at three places inside the second note: its
    /// header, its name and its descriptor. Each cut leaves `x86_ibt` false, which is the
    /// reading a `-fcf-protection=none` build produces, and before the notes walk
    /// recorded anything the two were the same fact. The name cut is the case the
    /// file-end bound in `parse_notes` exists for: the header is readable, so without
    /// that bound the note is pushed under a cut name, never decoded, and nothing says
    /// so. The control is the whole file, which decodes the bit and records nothing.
    #[test]
    fn a_cut_property_note_is_recorded_as_unread() {
        let whole = two_note_segment(8, 4, 24);
        let control = facts_of(&whole);
        assert!(
            control.x86_ibt,
            "the control decodes IBT from the second note"
        );
        // The segment-only object carries the `symbols` entry every header-less file
        // does; what a whole note table must not add is a `notes` entry.
        assert!(
            control
                .truncations
                .iter()
                .all(|t| t.table != ElfTable::Notes),
            "a whole note table records nothing about the notes: {:?}",
            control.truncations
        );

        // The second note begins at 0x600 + 24: header to 0x624, name to 0x628,
        // descriptor to 0x634.
        let mut cuts = 0;
        for (cut, inside) in [(0x61c, "header"), (0x626, "name"), (0x62c, "descriptor")] {
            let short = whole
                .get(..cut)
                .expect("the cut is inside the file")
                .to_vec();
            let facts = facts_of(&short);
            assert!(
                !facts.x86_ibt,
                "cut inside the {inside}: the bit cannot have been read"
            );
            let note = facts
                .truncations
                .iter()
                .find(|t| t.table == ElfTable::Notes)
                .unwrap_or_else(|| {
                    panic!(
                        "cut inside the {inside} at {cut:#x}: a note the file does not \
                         hold must be recorded, got {:?}",
                        facts.truncations
                    )
                });
            assert_eq!(note.kind, TruncationKind::Unread, "cut inside the {inside}");
            assert!(
                note.detail.starts_with("note table at 0x600+0x34:"),
                "the record names the table it was walking: {}",
                note.detail
            );
            cuts += 1;
        }
        assert_eq!(cuts, 3, "three cuts examined");
    }

    /// `facts().sections` holds the *named* sections, not the unnamed ones.
    ///
    /// The filter drops the empty name that index 0 always carries. Inverted, the list
    /// becomes those empty names and every real section disappears -- a report field that
    /// silently empties rather than erroring, which is the shape this project treats as
    /// worse than a crash. Read from a real object, since the synthetic builders here carry
    /// no section-name table.
    #[test]
    fn the_section_list_holds_named_sections_and_drops_the_unnamed() {
        let Some(object) = a_real_object("that the section list drops the unnamed section") else {
            return;
        };
        let sections = facts_of(&object).sections;
        assert!(
            sections.iter().any(|s| s == ".text"),
            "a real object's section list must contain .text, got {sections:?}"
        );
        assert!(
            !sections.iter().any(String::is_empty),
            "the unnamed section at index 0 must not appear"
        );
    }

    /// One `PT_LOAD` at `vaddr`, `memsz` bytes wide, mapped from file offset 0.
    fn one_load_segment(p_vaddr: u64, p_memsz: u64) -> Vec<u8> {
        let mut d = elf64_header(1, 56, 0, 64);
        d[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        d[64..68].copy_from_slice(&PT_LOAD.to_le_bytes());
        d[72..80].copy_from_slice(&0u64.to_le_bytes()); // p_offset
        d[80..88].copy_from_slice(&p_vaddr.to_le_bytes());
        d[96..104].copy_from_slice(&p_memsz.to_le_bytes()); // p_filesz
        d[104..112].copy_from_slice(&p_memsz.to_le_bytes()); // p_memsz
        d
    }

    /// The segment a virtual address falls in is a half-open interval, and both ends matter.
    ///
    /// This is the only route to `.dynamic` in an object whose section headers are gone, so
    /// a wrong answer here is not a lookup failure -- it resolves `DT_STRTAB` to the wrong
    /// bytes and the library list is read out of whatever sits there. Both operands of the
    /// bounds test get their own case, because either one alone is satisfied by an address
    /// in the middle.
    #[test]
    fn a_virtual_address_is_inside_a_segment_only_within_both_bounds() {
        const BASE: u64 = 0x1000;
        const SIZE: u64 = 0x1000;
        let obj = one_load_segment(BASE, SIZE);
        let elf = Elf::parse(&obj).expect("synthetic ELF parses");

        assert_eq!(
            elf.offset_of_vaddr(BASE),
            Some(0),
            "the first address of the segment is inside it"
        );
        assert_eq!(
            elf.offset_of_vaddr(BASE + SIZE - 1),
            Some(SIZE - 1),
            "the last address of the segment is inside it"
        );
        // The upper bound is exclusive: one past the end belongs to no segment.
        assert_eq!(
            elf.offset_of_vaddr(BASE + SIZE),
            None,
            "one past the end must not resolve"
        );
        // And the lower bound is a bound, not decoration.
        assert_eq!(
            elf.offset_of_vaddr(BASE - 1),
            None,
            "an address below the segment must not resolve"
        );
    }

    /// A `SHT_DYNAMIC` section reaching outside its segment is reported, at either end.
    ///
    /// The containment test has two operands and the existing case only exercises one. A
    /// section that begins *before* the segment is the other, and it is the one a crafted
    /// file would use: the bytes before `PT_DYNAMIC` are not the tags the loader reads.
    #[test]
    fn a_dynamic_section_starting_before_its_segment_is_reported() {
        const SHOFF: usize = 256;
        const SEG_AT: u64 = 0x400;
        const SEG_SIZE: u64 = 0x30;
        let mut d = elf64_header(1, 56, 1, 64);
        d[40..48].copy_from_slice(&(SHOFF as u64).to_le_bytes());
        d[64..68].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        d[72..80].copy_from_slice(&SEG_AT.to_le_bytes());
        d[96..104].copy_from_slice(&SEG_SIZE.to_le_bytes());

        // Starts 16 bytes before the segment and ends well inside it, so only the lower
        // operand of the containment test can reject it.
        d[SHOFF + 4..SHOFF + 8].copy_from_slice(&SHT_DYNAMIC.to_le_bytes());
        d[SHOFF + 24..SHOFF + 32].copy_from_slice(&(SEG_AT - 16).to_le_bytes());
        d[SHOFF + 32..SHOFF + 40].copy_from_slice(&0x20u64.to_le_bytes());

        let facts = Elf::parse(&d).expect("parses").facts();
        assert!(
            facts.truncations.iter().any(|t| {
                t.table == ElfTable::Dynamic
                    && t.kind == TruncationKind::Ignored
                    && t.detail.contains("lies outside every PT_DYNAMIC segment")
            }),
            "a section starting before its segment must be reported, got {:?}",
            facts.truncations
        );
    }

    /// One note view per call: program headers of the given types all covering a property
    /// note at `SEG_AT` that carries `segment_word`, and, where `section_word` is given, one
    /// `SHT_NOTE` section header aimed at a second property note at `SECTION_AT`. With
    /// `sections` false the section-header table is absent (`e_shnum` 0), as after
    /// `objcopy --strip-section-headers`.
    ///
    /// The builder for the forged-note shape: a binary whose segments say one thing and
    /// whose `.note.gnu.property` section header says another.
    fn note_view(
        machine: u16,
        segment_types: &[u32],
        pr_type: u32,
        segment_word: u32,
        section_word: Option<u32>,
    ) -> Vec<u8> {
        const SEG_AT: u64 = 0x600;
        const SECTION_AT: u64 = 0x700;
        const SHOFF: usize = 512;
        let shnum = u16::from(section_word.is_some());
        let mut d = elf64_header(u16::try_from(segment_types.len()).unwrap(), 56, shnum, 64);
        d[18..20].copy_from_slice(&machine.to_le_bytes());
        for (i, p_type) in segment_types.iter().enumerate() {
            let b = 64 + i * 56;
            d[b..b + 4].copy_from_slice(&p_type.to_le_bytes());
            d[b + 8..b + 16].copy_from_slice(&SEG_AT.to_le_bytes());
            d[b + 32..b + 40].copy_from_slice(&32u64.to_le_bytes()); // p_filesz
            d[b + 48..b + 56].copy_from_slice(&8u64.to_le_bytes()); // p_align
        }
        let mut put = |at: u64, word: u32| {
            let n = usize::try_from(at).unwrap();
            d[n..n + 4].copy_from_slice(&4u32.to_le_bytes());
            d[n + 4..n + 8].copy_from_slice(&12u32.to_le_bytes());
            d[n + 8..n + 12].copy_from_slice(&NT_GNU_PROPERTY_TYPE_0.to_le_bytes());
            d[n + 12..n + 16].copy_from_slice(b"GNU\0");
            d[n + 16..n + 28].copy_from_slice(&property(pr_type, word, false));
        };
        put(SEG_AT, segment_word);
        if let Some(word) = section_word {
            put(SECTION_AT, word);
            d[40..48].copy_from_slice(&(SHOFF as u64).to_le_bytes()); // e_shoff
            d[SHOFF + 4..SHOFF + 8].copy_from_slice(&SHT_NOTE.to_le_bytes());
            // Allocated, as `.note.gnu.property` is: the section claims to be loaded.
            d[SHOFF + 8..SHOFF + 16].copy_from_slice(&SHF_ALLOC.to_le_bytes());
            d[SHOFF + 24..SHOFF + 32].copy_from_slice(&SECTION_AT.to_le_bytes());
            d[SHOFF + 32..SHOFF + 40].copy_from_slice(&32u64.to_le_bytes());
            d[SHOFF + 48..SHOFF + 56].copy_from_slice(&8u64.to_le_bytes());
        }
        d
    }

    /// A note section that is not allocated is never mapped, so outside the segments it is
    /// no disagreeing view: annobin's `.gnu.build.attributes` is that shape in every program
    /// Fedora's crt objects are linked into, and it records nothing.
    #[test]
    fn an_unallocated_note_section_outside_the_segments_records_nothing() {
        let mut d = note_view(
            EM_X86_64,
            &[PT_NOTE],
            GNU_PROPERTY_X86_FEATURE_1_AND,
            0,
            Some(X86_FEATURE_1_IBT | X86_FEATURE_1_SHSTK),
        );
        d[512 + 8..512 + 16].copy_from_slice(&0u64.to_le_bytes()); // sh_flags: not SHF_ALLOC
        let facts = facts_of(&d);
        assert!(
            ignored_note_section(&facts).is_none(),
            "{:?}",
            facts.truncations
        );
        assert!(!facts.x86_ibt && !facts.x86_shstk);
    }

    fn ignored_note_section(facts: &ElfFacts) -> Option<&Truncation> {
        facts.truncations.iter().find(|t| {
            t.table == ElfTable::Notes
                && t.kind == TruncationKind::Ignored
                && t.detail.contains("lies outside every PT_NOTE")
        })
    }

    /// The loader reads the segment, so a note section aimed at other bytes is not measured.
    ///
    /// Reproduced with a gcc 16.1.1 `-fcf-protection=none` binary whose `.note.gnu.property`
    /// header was pointed at an appended `X86_FEATURE_1_AND` note of `IBT|SHSTK`, program
    /// headers untouched: the file ran, `chard elf` read `x86_ibt` and `x86_shstk` true, and
    /// the `GNU_PROPERTY` segment carried neither. The section walk went first and the
    /// segment was read only when it found nothing. Both segment types are covered, and the
    /// forged view is recorded as `ignored`, the kind `dynamic()` uses for its own.
    #[test]
    fn a_note_section_outside_every_note_segment_is_not_the_measurement() {
        let both = X86_FEATURE_1_IBT | X86_FEATURE_1_SHSTK;
        for p_type in [PT_GNU_PROPERTY, PT_NOTE] {
            let f = facts_of(&note_view(
                EM_X86_64,
                &[p_type],
                GNU_PROPERTY_X86_FEATURE_1_AND,
                0,
                Some(both),
            ));
            assert!(
                !f.x86_ibt && !f.x86_shstk,
                "segment type {p_type:#x}: the forged section was measured: {f:?}"
            );
            assert!(
                ignored_note_section(&f).is_some(),
                "segment type {p_type:#x}: the dropped view is not recorded: {:?}",
                f.truncations
            );
            assert!(
                f.unread(&[ElfTable::Notes]).is_none(),
                "a dropped view leaves the table read: {:?}",
                f.truncations
            );
        }
    }

    /// The reverse direction: the segment carries the marking and a section aimed
    /// elsewhere does not erase it.
    #[test]
    fn a_note_section_elsewhere_does_not_hide_the_segments_marking() {
        let f = facts_of(&note_view(
            EM_X86_64,
            &[PT_GNU_PROPERTY],
            GNU_PROPERTY_X86_FEATURE_1_AND,
            X86_FEATURE_1_IBT | X86_FEATURE_1_SHSTK,
            Some(0),
        ));
        assert!(f.x86_ibt && f.x86_shstk, "{f:?}");
        assert!(ignored_note_section(&f).is_some(), "{:?}", f.truncations);
    }

    /// `PT_GNU_PROPERTY` and a `PT_NOTE` over the same bytes is what a linker writes, and
    /// the note is read once: a second read would publish a count of two, "a file no linker
    /// wrote".
    #[test]
    fn a_property_note_under_both_segment_types_is_read_once() {
        let f = facts_of(&note_view(
            EM_X86_64,
            &[PT_NOTE, PT_GNU_PROPERTY],
            GNU_PROPERTY_X86_FEATURE_1_AND,
            X86_FEATURE_1_IBT,
            None,
        ));
        assert!(f.x86_ibt && !f.x86_shstk, "{f:?}");
        assert_eq!(
            f.gnu_property_notes.get("0xc0000002"),
            Some(&1),
            "{:?}",
            f.gnu_property_notes
        );
        assert!(
            f.truncations.iter().all(|t| t.table != ElfTable::Notes),
            "{:?}",
            f.truncations
        );
    }

    /// `note_view` with a `PT_NOTE` first and a `PT_GNU_PROPERTY` second, the `PT_NOTE`
    /// repointed at a property note of `note_word` at 0x680: the second forged-note
    /// shape.
    fn stray_property_note(segment_word: u32, note_word: u32) -> Vec<u8> {
        let mut d = note_view(
            EM_X86_64,
            &[PT_NOTE, PT_GNU_PROPERTY],
            GNU_PROPERTY_X86_FEATURE_1_AND,
            segment_word,
            None,
        );
        d[64 + 8..64 + 16].copy_from_slice(&0x680u64.to_le_bytes()); // p_offset
        d[0x680..0x684].copy_from_slice(&4u32.to_le_bytes());
        d[0x684..0x688].copy_from_slice(&12u32.to_le_bytes());
        d[0x688..0x68c].copy_from_slice(&NT_GNU_PROPERTY_TYPE_0.to_le_bytes());
        d[0x68c..0x690].copy_from_slice(b"GNU\0");
        d[0x690..0x69c].copy_from_slice(&property(
            GNU_PROPERTY_X86_FEATURE_1_AND,
            note_word,
            false,
        ));
        d
    }

    fn ignored_property_note(facts: &ElfFacts) -> Option<&Truncation> {
        facts.truncations.iter().find(|t| {
            t.table == ElfTable::Notes
                && t.kind == TruncationKind::Ignored
                && t.detail.contains("outside every PT_GNU_PROPERTY")
        })
    }

    /// Where a `PT_GNU_PROPERTY` exists the loader reads the property there, so a `PT_NOTE`
    /// aimed at other bytes is not measured.
    ///
    /// Reproduced with a gcc 16.1.1 `-fcf-protection=none` binary, `PT_GNU_PROPERTY`
    /// untouched and the first `PT_NOTE` repointed at an appended `X86_FEATURE_1_AND` note of
    /// `IBT|SHSTK`: the file ran, and a reader of every note segment read both bits true.
    #[test]
    fn a_property_note_outside_the_property_segment_is_not_the_measurement() {
        let f = facts_of(&stray_property_note(
            0,
            X86_FEATURE_1_IBT | X86_FEATURE_1_SHSTK,
        ));
        assert!(
            !f.x86_ibt && !f.x86_shstk,
            "the stray note was measured: {f:?}"
        );
        assert_eq!(
            f.gnu_property_notes.get("0xc0000002"),
            Some(&1),
            "{:?}",
            f.gnu_property_notes
        );
        assert!(ignored_property_note(&f).is_some(), "{:?}", f.truncations);
        assert!(
            f.unread(&[ElfTable::Notes]).is_none(),
            "a dropped note leaves the table read: {:?}",
            f.truncations
        );
    }

    /// The reverse direction: the property segment carries the marking and a `PT_NOTE`
    /// aimed elsewhere does not clear it by the AND a second note would get.
    #[test]
    fn a_property_note_outside_the_property_segment_does_not_hide_its_marking() {
        let f = facts_of(&stray_property_note(
            X86_FEATURE_1_IBT | X86_FEATURE_1_SHSTK,
            0,
        ));
        assert!(f.x86_ibt && f.x86_shstk, "{f:?}");
        assert!(ignored_property_note(&f).is_some(), "{:?}", f.truncations);
    }

    /// A `PT_NOTE` cut short beside a `PT_GNU_PROPERTY` hides no property the loader reads,
    /// so its stop withholds nothing and is not recorded: the shape of an 8-aligned
    /// `PT_NOTE` over 4-aligned notes, which samba's libraries on Fedora 44 carry.
    #[test]
    fn a_cut_note_segment_beside_a_property_segment_records_nothing() {
        let mut d = note_view(
            EM_X86_64,
            &[PT_NOTE, PT_GNU_PROPERTY],
            GNU_PROPERTY_X86_FEATURE_1_AND,
            X86_FEATURE_1_SHSTK,
            None,
        );
        d[64 + 32..64 + 40].copy_from_slice(&0x10_0000u64.to_le_bytes()); // p_filesz
        let f = facts_of(&d);
        assert!(!f.x86_ibt && f.x86_shstk, "{f:?}");
        assert!(
            f.truncations.iter().all(|t| t.table != ElfTable::Notes),
            "{:?}",
            f.truncations
        );
        // The same segment alone is the table read, and its stop is recorded.
        d[120..124].copy_from_slice(&0u32.to_le_bytes()); // PT_NULL for the property segment
        assert!(facts_of(&d).unread(&[ElfTable::Notes]).is_some());
    }

    /// A note section inside its segment is the ordinary file and records nothing, and a
    /// file with no section headers is read through its segments alone.
    #[test]
    fn a_note_section_inside_its_segment_records_nothing() {
        let mut d = note_view(
            EM_X86_64,
            &[PT_GNU_PROPERTY],
            GNU_PROPERTY_X86_FEATURE_1_AND,
            X86_FEATURE_1_SHSTK,
            Some(X86_FEATURE_1_SHSTK),
        );
        // Aim the section at the segment's own bytes.
        d[512 + 24..512 + 32].copy_from_slice(&0x600u64.to_le_bytes());
        let f = facts_of(&d);
        assert!(!f.x86_ibt && f.x86_shstk, "{f:?}");
        assert!(
            f.truncations.iter().all(|t| t.table != ElfTable::Notes),
            "{:?}",
            f.truncations
        );

        let stripped = facts_of(&note_view(
            EM_X86_64,
            &[PT_GNU_PROPERTY],
            GNU_PROPERTY_X86_FEATURE_1_AND,
            X86_FEATURE_1_SHSTK,
            None,
        ));
        assert!(!stripped.x86_ibt && stripped.x86_shstk, "{stripped:?}");
        assert!(
            stripped
                .truncations
                .iter()
                .all(|t| t.table != ElfTable::Notes),
            "{:?}",
            stripped.truncations
        );
    }

    /// Program headers that name no note segment leave a note section unread: the loader
    /// reads no note from such a file, so the section is not the file's marking.
    #[test]
    fn a_note_section_in_a_file_with_program_headers_but_no_note_segment_is_not_read() {
        let f = facts_of(&note_view(
            EM_X86_64,
            &[PT_LOAD],
            GNU_PROPERTY_X86_FEATURE_1_AND,
            0,
            Some(X86_FEATURE_1_IBT | X86_FEATURE_1_SHSTK),
        ));
        assert!(!f.x86_ibt && !f.x86_shstk, "{f:?}");
        assert!(ignored_note_section(&f).is_some(), "{:?}", f.truncations);
    }

    /// The same rule serves the aarch64 feature word: BTI and PAC come from the segment.
    #[test]
    fn a_forged_note_section_does_not_mark_aarch64_either() {
        let f = facts_of(&note_view(
            EM_AARCH64,
            &[PT_GNU_PROPERTY],
            GNU_PROPERTY_AARCH64_FEATURE_1_AND,
            AARCH64_FEATURE_1_PAC,
            Some(AARCH64_FEATURE_1_BTI | AARCH64_FEATURE_1_PAC),
        ));
        assert!(!f.aarch64_bti && f.aarch64_pac, "{f:?}");
        assert!(ignored_note_section(&f).is_some(), "{:?}", f.truncations);
    }

    /// One `PT_NOTE` holding a single `"GNU\0"` note of the given type and descriptor.
    fn one_note(ntype: u32, desc: &[u8]) -> Vec<u8> {
        let note_at: u64 = 0x600;
        let desc_len = u64::try_from(desc.len()).unwrap();
        let mut d = elf64_header(1, 56, 0, 64);
        d[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        d[64..68].copy_from_slice(&PT_NOTE.to_le_bytes());
        d[72..80].copy_from_slice(&note_at.to_le_bytes());
        d[96..104].copy_from_slice(&(16 + desc_len).to_le_bytes());
        d[112..120].copy_from_slice(&8u64.to_le_bytes()); // p_align

        let n = usize::try_from(note_at).unwrap();
        d[n..n + 4].copy_from_slice(&4u32.to_le_bytes());
        d[n + 4..n + 8].copy_from_slice(&u32::try_from(desc.len()).unwrap().to_le_bytes());
        d[n + 8..n + 12].copy_from_slice(&ntype.to_le_bytes());
        d[n + 12..n + 16].copy_from_slice(b"GNU\0");
        d[n + 16..n + 16 + desc.len()].copy_from_slice(desc);
        d
    }

    /// A property record: type, a 4-byte datum, and padding to the ELF64 alignment.
    fn property(pr_type: u32, value: u32, pad_to_8: bool) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&pr_type.to_le_bytes());
        v.extend_from_slice(&4u32.to_le_bytes());
        v.extend_from_slice(&value.to_le_bytes());
        if pad_to_8 {
            v.extend_from_slice(&[0u8; 4]);
        }
        v
    }

    /// Only `NT_GNU_PROPERTY_TYPE_0` notes carry properties, name notwithstanding.
    ///
    /// `"GNU\0"` is the name on the build-id note too, so the type is the whole of what
    /// separates them. Read the wrong one and a build id -- arbitrary bytes -- is decoded as
    /// a feature bitmap, which is a hardening verdict invented out of a hash.
    #[test]
    fn a_gnu_named_note_of_another_type_carries_no_properties() {
        const NT_GNU_BUILD_ID: u32 = 3;
        let desc = property(GNU_PROPERTY_X86_FEATURE_1_AND, X86_FEATURE_1_IBT, false);

        let as_property = facts_of(&one_note(NT_GNU_PROPERTY_TYPE_0, &desc));
        assert!(as_property.x86_ibt, "the property note must be read");

        let as_build_id = facts_of(&one_note(NT_GNU_BUILD_ID, &desc));
        assert!(
            !as_build_id.x86_ibt,
            "a build-id note must not be decoded as a property"
        );
        assert!(
            as_build_id.gnu_property_types.is_empty(),
            "no property should be recorded from a non-property note, got {:?}",
            as_build_id.gnu_property_types
        );
    }

    /// A descriptor holding two properties yields both, not just the first.
    ///
    /// The walk advances by the padded size of each record, and a mutation that stops after
    /// one is invisible while every fixture carries a single property. The second record is
    /// an aarch64 one behind an x86 one. On an x86-64 object it is listed and left undecoded;
    /// on an aarch64 object it is the one that decodes, so a stalled walk reads as "no
    /// branch protection" there -- a specific wrong answer rather than an empty one.
    #[test]
    fn every_property_in_one_descriptor_is_read() {
        let mut desc = property(GNU_PROPERTY_X86_FEATURE_1_AND, X86_FEATURE_1_IBT, true);
        desc.extend(property(
            GNU_PROPERTY_AARCH64_FEATURE_1_AND,
            AARCH64_FEATURE_1_BTI,
            false,
        ));
        let both = vec!["0xc0000000".to_owned(), "0xc0000002".to_owned()];

        let on_x86 = one_note(NT_GNU_PROPERTY_TYPE_0, &desc);
        let facts = facts_of(&on_x86);
        assert!(facts.x86_ibt, "the first property must be read");
        assert_eq!(
            facts.gnu_property_types, both,
            "the second property must be reached and listed"
        );
        assert!(
            !facts.aarch64_bti,
            "an aarch64 word is not decoded on an x86-64 object"
        );

        let mut on_aarch64 = on_x86;
        on_aarch64[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        let facts = facts_of(&on_aarch64);
        assert_eq!(facts.gnu_property_types, both);
        assert!(
            facts.aarch64_bti,
            "the second property must be read too, got {:?}",
            facts.gnu_property_types
        );
        assert!(
            !facts.x86_ibt,
            "an x86 word is not decoded on an aarch64 object"
        );
    }

    /// One `PT_NOTE` holding one `NT_GNU_PROPERTY_TYPE_0` note per `(type, word)` given,
    /// on an object of machine `machine`.
    ///
    /// Each note is 28 bytes and the next begins at 32, the descriptor's 12 bytes padded
    /// to the ELF64 note alignment. A linker emits one merged note; this builder is for
    /// the files a linker did not merge.
    fn property_notes(machine: u16, notes: &[(u32, u32)]) -> Vec<u8> {
        let note_at: u64 = 0x600;
        let mut d = elf64_header(1, 56, 0, 64);
        d[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        d[18..20].copy_from_slice(&machine.to_le_bytes());
        d[64..68].copy_from_slice(&PT_NOTE.to_le_bytes());
        d[72..80].copy_from_slice(&note_at.to_le_bytes());
        let size = u64::try_from(notes.len() * 32).unwrap();
        d[96..104].copy_from_slice(&size.to_le_bytes());
        d[112..120].copy_from_slice(&8u64.to_le_bytes()); // p_align
        for (i, (pr_type, word)) in notes.iter().enumerate() {
            let n = usize::try_from(note_at).unwrap() + i * 32;
            d[n..n + 4].copy_from_slice(&4u32.to_le_bytes());
            d[n + 4..n + 8].copy_from_slice(&12u32.to_le_bytes());
            d[n + 8..n + 12].copy_from_slice(&NT_GNU_PROPERTY_TYPE_0.to_le_bytes());
            d[n + 12..n + 16].copy_from_slice(b"GNU\0");
            d[n + 16..n + 28].copy_from_slice(&property(*pr_type, *word, false));
        }
        d
    }

    /// A feature word of any width but 4 marks nothing.
    ///
    /// The descriptor is the one clang 7.0.1 wrote under `-fcf-protection` in Debian 10 and
    /// Fedora 29, byte for byte: `X86_FEATURE_1_AND`, `pr_datasz` 8, IBT and SHSTK in the
    /// first word. readelf 2.31.1 and 2.46.1 print `<corrupt length: 0x8>`; read by its
    /// first word it published `x86_ibt` and `x86_shstk` true and `cet-marked` `on`.
    #[test]
    fn a_feature_word_of_the_wrong_width_marks_nothing() {
        let wide: [u8; 16] = [
            0x02, 0x00, 0x00, 0xc0, 0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let f = facts_of(&one_note(NT_GNU_PROPERTY_TYPE_0, &wide));
        assert_eq!(
            f.gnu_property_types,
            vec!["0xc0000002".to_owned()],
            "the type is still listed"
        );
        assert!(
            !f.x86_ibt && !f.x86_shstk,
            "an 8-byte feature word is not decoded"
        );

        let mut exact = wide;
        exact[4] = 4;
        let f = facts_of(&one_note(NT_GNU_PROPERTY_TYPE_0, &exact[..12]));
        assert!(
            f.x86_ibt && f.x86_shstk,
            "the same word at width 4 is decoded"
        );
    }

    /// A processor-specific property means what `e_machine` says, and nothing without it.
    ///
    /// Reproduced with a synthetic `EM_X86_64` object whose only property was
    /// `(0xc0000000, 3)`: `chard elf` printed `aarch64_bti: true, aarch64_pac: true` on an
    /// x86-64 binary, while `readelf -n` printed `x86 ISA used: i486, 586`, because that
    /// type was `GNU_PROPERTY_X86_ISA_1_USED` in binutils before 2.32 and still is in
    /// objects those linkers produced. The type is listed either way; the word is
    /// decoded only on the machine whose feature word it is, and on a machine this
    /// reader does not know it is decoded as nothing.
    #[test]
    fn a_processor_specific_property_is_decoded_only_on_the_machine_that_defines_it() {
        let legacy_isa = (GNU_PROPERTY_AARCH64_FEATURE_1_AND, 3);
        let cet = (GNU_PROPERTY_X86_FEATURE_1_AND, X86_FEATURE_1_IBT);
        let bits = |f: &ElfFacts| [f.x86_ibt, f.x86_shstk, f.aarch64_bti, f.aarch64_pac];

        let x86_isa = facts_of(&property_notes(EM_X86_64, &[legacy_isa]));
        assert_eq!(
            x86_isa.gnu_property_types,
            vec!["0xc0000000".to_owned()],
            "the type is listed on every machine"
        );
        assert_eq!(
            bits(&x86_isa),
            [false; 4],
            "0xc0000000 on x86-64 is an ISA bitmap"
        );

        let arm = facts_of(&property_notes(EM_AARCH64, &[legacy_isa]));
        assert_eq!(
            bits(&arm),
            [false, false, true, true],
            "the same word on aarch64 is the feature word it defines there"
        );

        let cet_on_386 = facts_of(&property_notes(EM_386, &[cet]));
        assert_eq!(
            bits(&cet_on_386),
            [true, false, false, false],
            "EM_386 defines X86_FEATURE_1_AND as EM_X86_64 does"
        );
        let cet_on_arm = facts_of(&property_notes(EM_AARCH64, &[cet]));
        assert_eq!(
            bits(&cet_on_arm),
            [false; 4],
            "0xc0000002 on aarch64 is not a CET word"
        );

        let unknown = facts_of(&property_notes(EM_RISCV, &[legacy_isa, cet]));
        assert_eq!(
            unknown.gnu_property_types,
            vec!["0xc0000000".to_owned(), "0xc0000002".to_owned()],
            "both types are listed on a machine the reader does not decode for"
        );
        assert_eq!(bits(&unknown), [false; 4], "and neither is decoded");
    }

    /// Two notes carrying one feature word are combined by AND, in either order, and counted.
    ///
    /// `props.insert` overwrote: `(0, then IBT|SHSTK)` published CET on and the reverse
    /// order published it off, on files `readelf -n` printed both notes for. The linker's
    /// rule for `*_FEATURE_1_AND` is an AND across inputs, emitted in one note, so a
    /// second note is a file no linker wrote and the word is the AND of both, the same
    /// rule applied once more. The count beside it is how a reader tells a file with no
    /// property note from one with two, and `gnu_property_notes` says what the loader
    /// does with the second.
    #[test]
    fn repeated_feature_words_are_anded_in_either_order_and_counted() {
        let t = GNU_PROPERTY_X86_FEATURE_1_AND;
        let full = X86_FEATURE_1_IBT | X86_FEATURE_1_SHSTK;
        let key = "0xc0000002";

        for (name, notes) in [
            ("0 then full", vec![(t, 0), (t, full)]),
            ("full then 0", vec![(t, full), (t, 0)]),
        ] {
            let f = facts_of(&property_notes(EM_X86_64, &notes));
            assert!(
                !f.x86_ibt && !f.x86_shstk,
                "{name}: a note that clears the word clears it whatever the order"
            );
            assert_eq!(
                f.gnu_property_notes.get(key),
                Some(&2),
                "{name}: both notes are counted"
            );
        }

        // Partial agreement keeps only the shared bit, which is what tells AND from OR.
        let mixed = facts_of(&property_notes(
            EM_X86_64,
            &[(t, X86_FEATURE_1_IBT), (t, full)],
        ));
        assert!(mixed.x86_ibt, "IBT is in both notes");
        assert!(
            !mixed.x86_shstk,
            "SHSTK is in one note only, so it does not survive"
        );

        // The same rule on the other machine's word.
        let arm = facts_of(&property_notes(
            EM_AARCH64,
            &[
                (GNU_PROPERTY_AARCH64_FEATURE_1_AND, AARCH64_FEATURE_1_BTI),
                (GNU_PROPERTY_AARCH64_FEATURE_1_AND, AARCH64_FEATURE_1_PAC),
            ],
        ));
        assert!(
            !arm.aarch64_bti && !arm.aarch64_pac,
            "BTI and PAC share no bit"
        );
        assert_eq!(arm.gnu_property_notes.get("0xc0000000"), Some(&2));

        // One note is what a linker produces, and no note leaves the map empty rather
        // than carrying a zero.
        let one = facts_of(&property_notes(EM_X86_64, &[(t, full)]));
        assert!(one.x86_ibt && one.x86_shstk);
        assert_eq!(one.gnu_property_notes.get(key), Some(&1));
        let none = facts_of(&property_notes(EM_X86_64, &[]));
        assert!(none.gnu_property_notes.is_empty());
        assert!(none.gnu_property_types.is_empty());
    }

    /// What `.chard.report` holds, once `section_text` has turned its NULs into newlines.
    const REPORT_TEXT: &str = "fortify=2\nstack_protector=strong";

    /// A `.chard.report` listed and cut is recorded against the section-names table with
    /// an entry that opens on the section's name, which `report::self_report_entries` reads
    /// to tell a section the reader could not finish from one the list lacks; the facts
    /// then read as an artifact that gave no account, with that entry quoted.
    #[test]
    fn a_cut_self_report_is_named_at_the_head_of_its_entry() {
        const SHOFF: usize = 256;
        let mut d = object_with_named_sections();
        // Section 2 is `.chard.report`; its size runs past the end of the file.
        d[SHOFF + 2 * 64 + 32..SHOFF + 2 * 64 + 40].copy_from_slice(&0x10_0000u64.to_le_bytes());
        let facts = facts_of(&d);
        assert!(facts.self_report.is_empty(), "{:?}", facts.self_report);
        assert!(facts.sections.iter().any(|s| s == SELF_REPORT_SECTION));
        let entry = facts
            .truncations
            .iter()
            .find(|t| t.table == ElfTable::SectionNames && t.kind == TruncationKind::Unread)
            .expect("the cut is recorded against the section-names table");
        assert!(
            entry
                .detail
                .starts_with(&format!("{SELF_REPORT_SECTION}: ")),
            "{}",
            entry.detail
        );
        match crate::report::self_report_entries(&facts) {
            Err(crate::report::SelfReportAbsence::Unread { detail }) => {
                assert_eq!(detail, entry.detail);
            }
            other => panic!("a cut section reads as unread, not {other:?}"),
        }
    }

    /// An object with a real section-name table: a null section, the name table itself,
    /// a `.chard.report` holding the self report, and a `.bss` that is `SHT_NOBITS`.
    ///
    /// `.bss` deliberately points at `.chard.report`'s bytes. A `NOBITS` section occupies no
    /// file space, so its `sh_offset` names bytes belonging to something else -- and a
    /// reader that forgets to check the type returns those bytes as if they were the
    /// section's own. Pointing it somewhere harmless would make that mistake invisible.
    fn object_with_named_sections() -> Vec<u8> {
        const SHT_PROGBITS: u32 = 1;
        const SHOFF: usize = 256;
        const STRTAB_AT: u64 = 0x800;
        const REPORT_AT: u64 = 0x900;
        // Offsets into the table below, checked here so a typo fails as a test error rather
        // than as an empty section name.
        const NAMES: &[u8] = b"\0.shstrtab\0.chard.report\0.bss\0";
        assert_eq!(&NAMES[1..10], b".shstrtab");
        assert_eq!(&NAMES[11..24], b".chard.report");
        assert_eq!(&NAMES[25..29], b".bss");

        let report = b"fortify=2\0stack_protector=strong\0";
        let mut d = elf64_header(0, 56, 4, 64);
        d[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        d[40..48].copy_from_slice(&(SHOFF as u64).to_le_bytes());
        d[62..64].copy_from_slice(&1u16.to_le_bytes()); // e_shstrndx -> section 1

        let mut shdr = |i: usize, name: u32, kind: u32, off: u64, size: u64| {
            let b = SHOFF + i * 64;
            d[b..b + 4].copy_from_slice(&name.to_le_bytes());
            d[b + 4..b + 8].copy_from_slice(&kind.to_le_bytes());
            d[b + 24..b + 32].copy_from_slice(&off.to_le_bytes());
            d[b + 32..b + 40].copy_from_slice(&size.to_le_bytes());
        };
        shdr(0, 0, 0, 0, 0);
        shdr(1, 1, SHT_STRTAB, STRTAB_AT, 30);
        shdr(2, 11, SHT_PROGBITS, REPORT_AT, 33);
        shdr(3, 25, SHT_NOBITS, REPORT_AT, 33);

        let s = usize::try_from(STRTAB_AT).unwrap();
        d[s..s + NAMES.len()].copy_from_slice(NAMES);
        let r = usize::try_from(REPORT_AT).unwrap();
        d[r..r + report.len()].copy_from_slice(report);
        d
    }

    /// An object whose only named section besides the name table is a `.comment` of
    /// `sh_type`, `size` bytes at `offset`, holding `payload` where the file has room.
    ///
    /// `offset` and `size` are parameters so one builder can produce the three shapes the
    /// reader must tell apart: a section it can read, a `NOBITS` one that occupies no file
    /// space, and one whose header points past the end of the file.
    fn object_with_comment(sh_type: u32, offset: u64, size: u64, payload: &[u8]) -> Vec<u8> {
        const SHOFF: usize = 256;
        const STRTAB_AT: u64 = 0x800;
        const NAMES: &[u8] = b"\0.shstrtab\0.comment\0";
        assert_eq!(&NAMES[1..10], b".shstrtab");
        assert_eq!(&NAMES[11..19], b".comment");

        let mut d = elf64_header(0, 56, 3, 64);
        d[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        d[40..48].copy_from_slice(&(SHOFF as u64).to_le_bytes());
        d[62..64].copy_from_slice(&1u16.to_le_bytes());

        let mut shdr = |i: usize, name: u32, kind: u32, off: u64, size: u64| {
            let b = SHOFF + i * 64;
            d[b..b + 4].copy_from_slice(&name.to_le_bytes());
            d[b + 4..b + 8].copy_from_slice(&kind.to_le_bytes());
            d[b + 24..b + 32].copy_from_slice(&off.to_le_bytes());
            d[b + 32..b + 40].copy_from_slice(&size.to_le_bytes());
        };
        shdr(0, 0, 0, 0, 0);
        shdr(1, 1, SHT_STRTAB, STRTAB_AT, 20);
        shdr(2, 11, sh_type, offset, size);

        let s = usize::try_from(STRTAB_AT).unwrap();
        d[s..s + NAMES.len()].copy_from_slice(NAMES);
        if let Ok(at) = usize::try_from(offset)
            && at + payload.len() <= d.len()
        {
            d[at..at + payload.len()].copy_from_slice(payload);
        }
        d
    }

    /// `.comment` reaches the facts as one line per producer, and the three ways of
    /// carrying nothing stay distinct.
    ///
    /// `toolchain::artifact_agreement` reads `comment` to decide whether the linker the
    /// banner named is the one that produced the artifact, and it reads an empty list as
    /// "no linker signed this object" only when the section was read to its end. So the
    /// absent section, the `NOBITS` section and the section the reader could not reach
    /// are each pinned here: the first two are empty with no truncation, the third is
    /// empty with a truncation `comment_truncation` finds, and a reader that returned an
    /// empty list for the third would turn an unreadable file into a clean-looking
    /// absence.
    #[test]
    fn the_comment_section_reaches_the_facts() {
        const SHT_PROGBITS: u32 = 1;
        const AT: u64 = 0x900;
        let payload = b"GCC: (GNU) 16.1.1 20260515 (Red Hat 16.1.1-2)\0Linker: LLD 22.1.8\0";
        let size = u64::try_from(payload.len()).unwrap();

        let read = facts_of(&object_with_comment(SHT_PROGBITS, AT, size, payload));
        assert_eq!(
            read.comment,
            vec![
                "GCC: (GNU) 16.1.1 20260515 (Red Hat 16.1.1-2)".to_owned(),
                "Linker: LLD 22.1.8".to_owned(),
            ],
            "one line per producer, in file order"
        );
        assert!(
            read.comment_truncation().is_none(),
            "{:?}",
            read.truncations
        );

        // Merged twice into one table, the same line is one line.
        let twice = b"GCC: (GNU) 16.1.1\0GCC: (GNU) 16.1.1\0";
        let deduped = facts_of(&object_with_comment(
            SHT_PROGBITS,
            AT,
            u64::try_from(twice.len()).unwrap(),
            twice,
        ));
        assert_eq!(deduped.comment, vec!["GCC: (GNU) 16.1.1".to_owned()]);

        let absent = facts_of(&object_with_named_sections());
        assert!(absent.comment.is_empty(), "no section, no lines");
        assert!(absent.comment_truncation().is_none());

        let nobits = facts_of(&object_with_comment(SHT_NOBITS, AT, size, payload));
        assert!(
            nobits.comment.is_empty(),
            "a NOBITS section occupies no file space, whatever its offset names"
        );
        assert!(nobits.comment_truncation().is_none());

        let past_eof = facts_of(&object_with_comment(SHT_PROGBITS, 0x10_0000, size, payload));
        assert!(past_eof.comment.is_empty());
        let why = past_eof
            .comment_truncation()
            .expect("a .comment the reader could not reach is named in truncations");
        assert!(
            why.starts_with(".comment: ") && why.contains("could not be read"),
            "{why}"
        );
        assert!(
            past_eof.sections.iter().any(|s| s == ".comment"),
            "the section is listed as present, which is what makes the truncation load-bearing"
        );

        // No section-header table at all, as `objcopy --strip-section-headers` leaves a
        // file: the section could not be looked up, which is a fourth way of carrying
        // nothing and reads as the third. Without this entry the file counted as read to
        // its end with no lines, and under an lld banner that was a false `disagrees`.
        let mut headerless = object_with_comment(SHT_PROGBITS, AT, size, payload);
        headerless[40..48].copy_from_slice(&0u64.to_le_bytes());
        headerless[60..62].copy_from_slice(&0u16.to_le_bytes());
        headerless[62..64].copy_from_slice(&0u16.to_le_bytes());
        let unlisted = facts_of(&headerless);
        assert!(unlisted.comment.is_empty());
        assert!(unlisted.sections.is_empty(), "{:?}", unlisted.sections);
        let why = unlisted
            .comment_truncation()
            .expect("a .comment that could not be looked up is named in truncations");
        assert!(
            why.contains("could not be looked up") && why.contains("no section-header table"),
            "{why}"
        );
    }

    /// The self report reaches the facts from the section that carries it.
    ///
    /// `probe.rs` reads `facts().self_report` and parses it into the key/value pairs the
    /// runtime channel answers with, and its own tests build `ElfFacts` with the string
    /// already in place. So the parsing was covered while the step before it -- finding
    /// `.chard.report` in the object and reading its bytes -- was not, and an accessor
    /// returning nothing would have emptied the channel without an error anywhere.
    #[test]
    fn the_self_report_section_reaches_the_facts() {
        let facts = facts_of(&object_with_named_sections());
        assert_eq!(facts.self_report, REPORT_TEXT);
        assert!(facts.sections.iter().any(|s| s == SELF_REPORT_SECTION));
        // A section that is absent reads as empty, which is what makes the case above
        // meaningful rather than a value that appears whatever is asked for.
        assert!(facts.recorded_command_line.is_empty());
    }

    /// A `NOBITS` section has no bytes in the file, whatever its offset says.
    ///
    /// `.bss` is the everyday case. Its `sh_offset` is a placeholder pointing into a
    /// neighbour, so reading it as an ordinary section returns that neighbour's contents --
    /// here, the self report -- and a caller cannot tell the difference.
    #[test]
    fn a_nobits_section_has_no_bytes_and_an_ordinary_one_has_its_own() {
        let obj = object_with_named_sections();
        let elf = Elf::parse(&obj).expect("synthetic ELF parses");

        let bss = elf.section_by_name(".bss").expect(".bss is present");
        assert_eq!(
            elf.section_bytes(bss).expect("NOBITS reads without error"),
            b"",
            "a NOBITS section occupies no file space"
        );

        let report = elf
            .section_by_name(".chard.report")
            .expect(".chard.report is present");
        assert_eq!(
            elf.section_bytes(report).expect("PROGBITS reads"),
            b"fortify=2\0stack_protector=strong\0",
            "an ordinary section reads its own bytes"
        );
    }

    /// `section_by_name` answers for the name it was given, and only that one.
    #[test]
    fn a_section_is_found_by_its_own_name_and_no_other() {
        let obj = object_with_named_sections();
        let elf = Elf::parse(&obj).expect("synthetic ELF parses");

        let found = elf
            .section_by_name(".chard.report")
            .expect(".chard.report must be found");
        assert_eq!(found.sh_size, 33, "the section found is the one named");
        assert!(
            elf.section_by_name(".text").is_none(),
            "a name the object does not carry must not resolve to some other section"
        );
    }

    /// The names the header's three escapes point at, and the names it withholds.
    ///
    /// Reproduced on `/bin/ls` against a reader that ignores the escapes: with
    /// `e_shstrndx = 0` it takes the null header as the name table, reads C strings out of
    /// file offset 0, and publishes `"\x7fELF\x02\x01\x01"` in `sections` as a name the file
    /// carried, while `readelf -S` prints `<no-strings>` for every one. With
    /// `e_shstrndx = 0xffff` and the real index in `shdr[0].sh_link` it finds no table and
    /// every fact reached by name goes empty, and with `e_shnum = 0` and the count in
    /// `shdr[0].sh_size` it finds no sections at all, so `relro` falls from `full` to
    /// `partial` on a file whose sections are all there. All three exit 0.
    ///
    /// The refusals are as important as the escapes. A name table that is not a string
    /// table is not read, and the file says so under the `section names:` prefix, which
    /// is what separates "this file named nothing" from "this file has nothing".
    #[test]
    fn section_names_follow_the_headers_escapes_and_refuse_a_table_that_is_not_one() {
        const SHOFF: usize = 256;
        let named = |d: &[u8]| facts_of(d).sections;
        let names_note = |d: &[u8]| {
            facts_of(d)
                .truncations
                .into_iter()
                .find(|t| t.table == ElfTable::SectionNames)
                .inspect(|t| assert_eq!(t.kind, TruncationKind::Unread))
                .map(|t| t.detail)
                .inspect(|detail| assert!(detail.starts_with("section names:"), "{detail}"))
        };
        let base = object_with_named_sections();
        let all = vec![
            ".shstrtab".to_owned(),
            ".chard.report".to_owned(),
            ".bss".to_owned(),
        ];
        assert_eq!(named(&base), all, "the control: every name resolves");
        assert_eq!(names_note(&base), None, "and nothing is withheld");

        // SHN_UNDEF: the file declares no name table. Nothing is fabricated from offset 0.
        let mut undef = base.clone();
        undef[62..64].copy_from_slice(&0u16.to_le_bytes());
        assert!(
            named(&undef).is_empty(),
            "no name table means no names, got {:?}",
            named(&undef)
        );
        let note = names_note(&undef).expect("the withheld names are said aloud");
        assert!(note.contains("SHN_UNDEF"), "the reason is named: {note}");
        assert!(!note.contains("  "), "one space between words: {note}");
        assert!(
            facts_of(&undef).self_report.is_empty(),
            "a section reached by name is unreachable without names"
        );

        // SHN_XINDEX: the index lives in shdr[0].sh_link.
        let mut xindex = base.clone();
        xindex[62..64].copy_from_slice(&SHN_XINDEX.to_le_bytes());
        xindex[SHOFF + 40..SHOFF + 44].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            named(&xindex),
            all,
            "e_shstrndx = SHN_XINDEX resolves through shdr[0]"
        );
        assert_eq!(names_note(&xindex), None);

        // e_shnum = 0 with a table present: the count lives in shdr[0].sh_size.
        let mut shnum0 = base.clone();
        shnum0[60..62].copy_from_slice(&0u16.to_le_bytes());
        shnum0[SHOFF + 32..SHOFF + 40].copy_from_slice(&4u64.to_le_bytes());
        assert_eq!(
            named(&shnum0),
            all,
            "e_shnum = 0 resolves the count through shdr[0]"
        );
        assert_eq!(facts_of(&shnum0).self_report, REPORT_TEXT);

        // A candidate that is not a string table is refused, and so is one past the table.
        let mut progbits = base.clone();
        progbits[62..64].copy_from_slice(&2u16.to_le_bytes());
        assert!(named(&progbits).is_empty());
        let note = names_note(&progbits).expect("refused, and said");
        assert!(
            note.contains("SHT_STRTAB"),
            "the reason is the type: {note}"
        );
        assert!(!note.contains("  "), "one space between words: {note}");
        // With no names, `.comment` could not be looked up, and its consumer is told so;
        // an empty list would read as a section read to its end.
        assert!(
            facts_of(&progbits)
                .comment_truncation()
                .is_some_and(|why| why.contains("section names could not be read")),
            "{:?}",
            facts_of(&progbits).truncations
        );
        let mut past = base.clone();
        past[62..64].copy_from_slice(&7u16.to_le_bytes());
        assert!(named(&past).is_empty());
        let note = names_note(&past).expect("refused, and said");
        assert!(note.contains("past"), "the reason is the range: {note}");
        assert!(!note.contains("  "), "one space between words: {note}");

        // A name is bounded by the table's declared size. With
        // `.shstrtab` cut to 12 bytes, `.chard.report` at offset 11 has one byte left and
        // `.bss` at 25 has none; a read bounded by EOF would still return both in full.
        let mut short = base.clone();
        short[SHOFF + 64 + 32..SHOFF + 64 + 40].copy_from_slice(&12u64.to_le_bytes());
        assert_eq!(
            named(&short),
            vec![".shstrtab".to_owned(), ".".to_owned()],
            "a name is cut at its table's declared end"
        );
    }

    /// `e_phnum = PN_XNUM` means the count is in `shdr[0].sh_info`, and only when there
    /// is a section-header table to hold it.
    #[test]
    fn a_program_header_count_of_pn_xnum_is_read_from_the_null_section_header() {
        const SHOFF: usize = 256;
        // One real program header at e_phoff = 64, in the space the builder leaves free.
        let mut d = object_with_named_sections();
        d[64..68].copy_from_slice(&PT_GNU_STACK.to_le_bytes());
        d[56..58].copy_from_slice(&PN_XNUM.to_le_bytes());

        d[SHOFF + 44..SHOFF + 48].copy_from_slice(&1u32.to_le_bytes());
        assert!(
            linked(facts_of(&d).gnu_stack_present),
            "sh_info = 1 makes the one header visible"
        );
        d[SHOFF + 44..SHOFF + 48].copy_from_slice(&0u32.to_le_bytes());
        assert!(
            !linked(facts_of(&d).gnu_stack_present),
            "sh_info = 0 is a count of zero, whatever e_phnum says"
        );

        // Without a section table there is nowhere to escape to: the declared 65535 is
        // walked and runs off the file, which is an error. The ELF header is never read
        // as `shdr[0]`.
        assert!(
            Elf::parse(&elf64_header(PN_XNUM, 56, 0, 64)).is_err(),
            "PN_XNUM with e_shoff = 0 is malformed and must not parse"
        );
    }

    /// A count escape whose `shdr[0]` the file does not hold reads as no section-header
    /// table, with the reason recorded, and the facts reached through segments survive.
    ///
    /// `e_shnum = 0` with a nonzero `e_shoff` says the count is in `shdr[0]`. A file cut
    /// before its section-header table, or one whose header was edited, leaves that offset
    /// past the end. GNU readelf probes `shdr[0]` for the escapes and applies none of them
    /// when the probe fails, so it reports no sections and reads on; this reader refused
    /// the file, and the differential in `tests/elf_readelf.rs` would have reported it
    /// unreadable by one side. Pinned on a synthetic file, since the checked-in fixtures
    /// are also compared against `llvm-readelf`, which refuses such a file outright
    /// (`section header table goes past the end of the file`, LLVM 23.1.0).
    ///
    /// The tolerance is for the count escape alone. The same stale offset under a declared
    /// count is a table the file does not hold, and under `PN_XNUM` it leaves a
    /// program-header count of 65535 the file does not hold either; both stay errors, as
    /// they are in readelf.
    #[test]
    fn a_count_escape_whose_shdr0_the_file_does_not_hold_reads_as_no_section_table() {
        const STALE: u64 = 0x10000; // the synthetic file is 4096 bytes
        let mut d = synth(ET_DYN, &[(DT_BIND_NOW, 0)], true, true, Some(0));
        assert_eq!(
            &d[40..48],
            &0u64.to_le_bytes(),
            "the builder writes no e_shoff"
        );
        assert_eq!(&d[60..62], &0u16.to_le_bytes(), "and no section count");
        d[40..48].copy_from_slice(&STALE.to_le_bytes());

        let facts = Elf::parse(&d)
            .expect("a stale e_shoff under e_shnum = 0 reads as readelf reads it")
            .facts();
        assert!(facts.sections.is_empty(), "{:?}", facts.sections);
        assert!(
            facts.truncations.iter().any(|t| {
                t.table == ElfTable::Symbols
                    && t.kind == TruncationKind::Unread
                    && t.detail.starts_with("no section-header table")
            }),
            "the file is read as having no section-header table: {:?}",
            facts.truncations
        );
        let note = facts
            .truncations
            .iter()
            .find(|t| t.detail.starts_with("section-header table:"))
            .expect("the unreadable shdr[0] is named");
        // The cause is typed apart from its effects, so `symbols` carries one entry for
        // one condition; the notes and `.dynamic` are reached through their segments.
        assert_eq!(note.table, ElfTable::SectionHeaders);
        assert_eq!(
            facts
                .truncations
                .iter()
                .filter(|t| t.table == ElfTable::Symbols)
                .count(),
            1,
            "{:?}",
            facts.truncations
        );
        assert_eq!(note.kind, TruncationKind::Unread);
        let note = &note.detail;
        assert!(
            note.contains("shdr[0]") && note.contains("0x10000"),
            "the note names the record and the offset: {note}"
        );
        assert!(!note.contains("  "), "one space between words: {note}");
        // Everything reached through the segments is still measured, as on a stripped file.
        assert_eq!(facts.relro.as_deref(), Some("full"));
        assert_eq!(facts.bind_now, Some(true));
        assert_eq!(facts.gnu_stack_present, Some(true));
        assert!(facts.has_interp);

        // The control: a readable shdr[0] is followed, and records no note. The same
        // escape on the object with a real name table, its count in `shdr[0].sh_size`.
        let mut followed = object_with_named_sections();
        followed[60..62].copy_from_slice(&0u16.to_le_bytes());
        followed[256 + 32..256 + 40].copy_from_slice(&4u64.to_le_bytes());
        let control = facts_of(&followed);
        assert_eq!(control.sections.len(), 3, "the escape was followed");
        assert!(
            control.truncations.is_empty(),
            "a readable shdr[0] records no note: {:?}",
            control.truncations
        );

        // The scope: the same stale offset under a declared count, and under PN_XNUM.
        let mut declared = d.clone();
        declared[60..62].copy_from_slice(&1u16.to_le_bytes());
        assert!(
            Elf::parse(&declared).is_err(),
            "e_shnum = 1 at a stale e_shoff is a table the file does not hold"
        );
        let mut xnum = d;
        xnum[56..58].copy_from_slice(&PN_XNUM.to_le_bytes());
        assert!(
            Elf::parse(&xnum).is_err(),
            "PN_XNUM with an unreadable shdr[0] is a count of 65535 the file does not hold"
        );
    }

    /// Every machine the reader names renders as its name, and any other as unrecognised.
    ///
    /// The values are the ones glibc's `elf.h` defines. The same ten headers were run
    /// through `llvm-readelf` (Homebrew LLVM 23.1.0), which named them `Intel 80386`,
    /// `MIPS R3000`, `PowerPC`, `PowerPC64`, `IBM S/390`,
    /// `ARM`, `Advanced Micro Devices X86-64`, `AArch64`, `RISC-V` and `LoongArch`;
    /// `tests/elf_readelf.rs`
    /// repeats that comparison on every object of those machines the differential meets.
    /// The numbers are written out here on purpose, so a constant that drifts from the
    /// table is a red test and the fixture record is a second witness for `EM_PPC`.
    #[test]
    fn a_machine_is_named_or_said_to_be_unrecognised() {
        let machine_of = |e_machine: u16| {
            let mut d = synth(ET_DYN, &[], false, false, None);
            d[18..20].copy_from_slice(&e_machine.to_le_bytes());
            facts_of(&d).machine
        };
        let named = [
            (3u16, "i386"),
            (8, "mips"),
            (20, "ppc"),
            (21, "ppc64"),
            (22, "s390"),
            (40, "arm"),
            (62, "x86_64"),
            (183, "aarch64"),
            (243, "riscv"),
            (258, "loongarch"),
        ];
        let mut checked = 0;
        for (e_machine, name) in named {
            assert_eq!(machine_of(e_machine), name, "e_machine {e_machine}");
            checked += 1;
        }
        assert_eq!(checked, 10, "every named machine ran");
        // `EM_NONE`, a value from no table, and `EM_BPF`, which a distribution's
        // `/usr/lib` can hold and this reader does not name.
        for (e_machine, rendered) in [
            (0u16, "unrecognised (e_machine 0x0)"),
            (0x1234, "unrecognised (e_machine 0x1234)"),
            (247, "unrecognised (e_machine 0xf7)"),
        ] {
            assert_eq!(machine_of(e_machine), rendered);
        }
    }

    /// `cstr_at` never reads past `off + table_len` bytes from `base`, even when no NUL
    /// appears within that window and one does appear just past it.
    ///
    /// This is the property the earlier, unbounded `cstr_at` did not have: it scanned for
    /// the nearest NUL regardless of what the caller's own table declared, so a crafted
    /// table with no terminator inside its declared length pulled in whatever followed —
    /// the next table, a descriptor, or (worst case) ran to the true end of the file. The
    /// fixture below is built to fail exactly that way if the bound were ever dropped: the
    /// declared window holds no NUL at all, and the first NUL in the underlying buffer sits
    /// several bytes past it.
    #[test]
    fn a_cstring_read_never_crosses_its_own_tables_declared_end() {
        // "AAAA" + more non-NUL bytes, then a NUL well past any window under test.
        let mut data = vec![b'A'; 16];
        data.push(0);
        data.extend_from_slice(b"unreachable");
        let cur = Cursor {
            data: &data,
            little: true,
        };

        // Declared window of 4 bytes, no NUL inside it: must read as the 4 bytes on hand,
        // not scan forward to the NUL at offset 16.
        let bounded = cur.cstr_at(0, 0, 4);
        assert_eq!(
            bounded, "AAAA",
            "a table with no terminator inside its declared length must stop at that \
             length, not scan into whatever follows"
        );

        // `off` is an index into the table, and the bound is relative to the table's
        // start, not to `off` — so a nonzero `off` shrinks the remaining window rather
        // than resetting it.
        let from_middle = cur.cstr_at(0, 2, 4);
        assert_eq!(
            from_middle, "AA",
            "off=2 into a 4-byte table leaves 2 bytes, not the full table_len again"
        );

        // `off` at or past the declared end reads as absent, not as reaching past it.
        assert_eq!(
            cur.cstr_at(0, 4, 4),
            "",
            "an offset at the table's own declared end must not read past it"
        );
        assert_eq!(
            cur.cstr_at(0, 9, 4),
            "",
            "an offset past the table's own declared end must not read at all"
        );

        // The control: the same buffer with a window wide enough to reach the real NUL
        // reads the intended string, so the bound above is doing the cutting, not an
        // unrelated off-by-one.
        assert_eq!(
            cur.cstr_at(0, 0, 100),
            "A".repeat(16),
            "a window that reaches the real terminator must read up to it"
        );
    }

    /// A read error says how much was read and where, because that is the whole of its use.
    ///
    /// These messages reach a report as evidence for a refusal. One that renders to nothing
    /// turns "this object could not be read at 0x900" into a blank, and the reader is left
    /// with a failure and no location.
    #[test]
    fn a_read_error_names_the_size_and_the_place() {
        for (err, wanted) in [
            (ReadError::OffsetTooLarge(4097), vec!["4097"]),
            (ReadError::LengthTooLarge(8193), vec!["8193"]),
            (
                ReadError::EndOverflows {
                    start: 12,
                    count: 34,
                },
                vec!["12", "34"],
            ),
            (
                ReadError::OutOfBounds {
                    start: 56,
                    count: 78,
                },
                vec!["56", "78"],
            ),
        ] {
            let rendered = err.to_string();
            for needle in wanted {
                assert!(
                    rendered.contains(needle),
                    "{err:?} rendered as {rendered:?}, which does not say {needle}"
                );
            }
        }
    }

    /// A forged `.dynstr` section cannot outvote the `DT_STRTAB` the loader resolves.
    ///
    /// The sibling of `dynamic()`'s order, in `dyn_strings`. A crafted file points `.dynstr`
    /// at zeroed bytes while the real `DT_STRTAB` names `libm.so.6`. Read by the section,
    /// `needed` would read `[""]`, and `as-needed`, whose detector asks whether any entry
    /// starts with `libm.`, would conclude the linker had dropped the unused library and
    /// report `on`. `readelf -d` takes the section's reading, because it reads sections too;
    /// the loader does not.
    #[test]
    fn a_forged_dynstr_section_cannot_outvote_dt_strtab() {
        const REAL_STR: u64 = 0x800; // file offset and vaddr of the honest string table
        const FAKE_STR: u64 = 0x900; // the section points here, and it is all zeroes
        // Clear of the program headers: the second phdr spans 120..176.
        const SHOFF: usize = 256;
        let mut d = elf64_header(2, 56, 1, 64);
        d[40..48].copy_from_slice(&(SHOFF as u64).to_le_bytes());

        // phdr 0: PT_LOAD covering the whole file at vaddr == offset, so `offset_of_vaddr`
        // is the identity and DT_STRTAB's address resolves.
        d[64..68].copy_from_slice(&PT_LOAD.to_le_bytes());
        d[72..80].copy_from_slice(&0u64.to_le_bytes()); // p_offset
        d[80..88].copy_from_slice(&0u64.to_le_bytes()); // p_vaddr
        d[96..104].copy_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
        // p_memsz too: `offset_of_vaddr` bounds on it, not on p_filesz, and a fixture that
        // leaves it zero makes the address resolve to None and the test fail against
        // correct code.
        d[104..112].copy_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
        // phdr 1: PT_DYNAMIC
        let dyn_at: u64 = 0x400;
        d[120..124].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        d[128..136].copy_from_slice(&dyn_at.to_le_bytes());
        d[152..160].copy_from_slice(&0x30u64.to_le_bytes()); // p_filesz

        // shdr 0: an `SHT_STRTAB` named `.dynstr`, aimed at the zeroed region.
        d[SHOFF + 4..SHOFF + 8].copy_from_slice(&SHT_STRTAB.to_le_bytes());
        d[SHOFF + 24..SHOFF + 32].copy_from_slice(&FAKE_STR.to_le_bytes());
        d[SHOFF + 32..SHOFF + 40].copy_from_slice(&0x40u64.to_le_bytes());
        // `section_by_name` needs e_shstrndx to resolve the name; point it at shdr 0 itself
        // and place ".dynstr\0" at the start of the fake table so shdr 0's sh_name finds it.
        d[62..64].copy_from_slice(&0u16.to_le_bytes()); // e_shstrndx = 0
        let f = usize::try_from(FAKE_STR).unwrap();
        d[f..f + 8].copy_from_slice(b".dynstr\0");
        d[SHOFF..SHOFF + 4].copy_from_slice(&0u32.to_le_bytes()); // sh_name -> offset 0

        // The honest table, and the dynamic entries that name it.
        let r = usize::try_from(REAL_STR).unwrap();
        d[r] = 0;
        d[r + 1..r + 11].copy_from_slice(b"libm.so.6\0");
        let at = usize::try_from(dyn_at).unwrap();
        for (i, (tag, val)) in [(DT_STRTAB, REAL_STR), (DT_NEEDED, 1), (0, 0)]
            .iter()
            .enumerate()
        {
            let b = at + i * 16;
            d[b..b + 8].copy_from_slice(&tag.to_le_bytes());
            d[b + 8..b + 16].copy_from_slice(&val.to_le_bytes());
        }

        let facts = Elf::parse(&d).expect("parses").facts();
        assert_eq!(
            facts.needed,
            vec!["libm.so.6".to_owned()],
            "DT_STRTAB names the real table; the forged .dynstr must not win"
        );
    }

    /// The loader's view wins when a file offers two that disagree.
    ///
    /// `ld.so` reads `PT_DYNAMIC` and never reads section headers; `strip --strip-all`
    /// removes them without changing what the file does. Preferring the section view let a
    /// crafted `ET_DYN` whose real segment set no flags read as `pie: true`,
    /// `df_1_pie: true`, `bind_now: true` -- a false `on` on an attacker-supplied binary,
    /// while `readelf -d` reported `FLAGS_1: None` from the segment the loader uses.
    ///
    /// Both directions, because only checking that the forged `on` is gone would also pass
    /// if the parser had stopped reading `.dynamic` altogether.
    #[test]
    fn a_dynamic_section_cannot_outvote_the_segment_the_loader_reads() {
        // One PT_DYNAMIC phdr and one SHT_DYNAMIC shdr, each aimed at its own table.
        let build = |seg_flags1: u64, sec_flags1: u64| -> Vec<u8> {
            let (seg_tab, sec_tab) = (0x200u64, 0x300u64);
            let mut d = elf64_header(1, 56, 1, 64);
            // The helper puts both tables at 64; move the section table clear of the
            // program table, or shdr[0] and phdr[0] are the same bytes.
            d[40..48].copy_from_slice(&128u64.to_le_bytes()); // e_shoff
            // phdr at 64: PT_DYNAMIC covering seg_tab..+0x20
            d[64..68].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
            d[72..80].copy_from_slice(&seg_tab.to_le_bytes()); // p_offset
            d[96..104].copy_from_slice(&0x20u64.to_le_bytes()); // p_filesz
            // shdr at 128: SHT_DYNAMIC pointing outside the segment entirely
            d[128 + 4..128 + 8].copy_from_slice(&SHT_DYNAMIC.to_le_bytes());
            d[128 + 24..128 + 32].copy_from_slice(&sec_tab.to_le_bytes()); // sh_offset
            d[128 + 32..128 + 40].copy_from_slice(&0x20u64.to_le_bytes()); // sh_size
            for (at, flags) in [(seg_tab, seg_flags1), (sec_tab, sec_flags1)] {
                let at = usize::try_from(at).unwrap();
                d[at..at + 8].copy_from_slice(&DT_FLAGS_1.to_le_bytes());
                d[at + 8..at + 16].copy_from_slice(&flags.to_le_bytes());
                // DT_NULL terminator
                d[at + 16..at + 32].copy_from_slice(&[0u8; 16]);
            }
            d
        };

        // The forgery: segment says nothing, section claims everything.
        let forged = build(0, DF_1_PIE | DF_1_NOW);
        let elf = Elf::parse(&forged).expect("parses");
        let facts = elf.facts();
        assert!(!facts.df_1_pie, "the section must not manufacture DF_1_PIE");
        assert!(
            !linked(facts.bind_now),
            "the section must not manufacture DF_1_NOW"
        );
        assert!(
            facts.truncations.iter().any(|t| {
                t.table == ElfTable::Dynamic
                    && t.kind == TruncationKind::Ignored
                    && t.detail.contains("SHT_DYNAMIC")
            }),
            "a dropped section view must be reported, not silently discarded: {:?}",
            facts.truncations
        );

        // The converse: the segment is still read, so this is not "stopped parsing".
        let honest = build(DF_1_PIE | DF_1_NOW, 0);
        let elf = Elf::parse(&honest).expect("parses");
        let facts = elf.facts();
        assert!(
            facts.df_1_pie,
            "the segment's own DF_1_PIE must still be read"
        );
        assert!(
            linked(facts.bind_now),
            "the segment's own DF_1_NOW must still be read"
        );
    }

    /// Bytes that are not an object are refused as `NotElf`, with the two messages the
    /// envelope and `Variant::elf_error` carry verbatim, and a class or data encoding this
    /// reader has no layout for is the same variant naming the byte.
    #[test]
    fn rejects_non_elf_input() {
        let Err(text) = Elf::parse(b"not an elf at all, just some bytes") else {
            panic!("bytes with no magic must be refused");
        };
        assert!(
            matches!(&text, ElfError::NotElf { path: None, why } if why == "not an ELF file"),
            "{text:?}"
        );
        let Err(empty) = Elf::parse(b"") else {
            panic!("an empty file must be refused");
        };
        assert!(
            matches!(&empty, ElfError::NotElf { path: None, why } if why == "file too short to be ELF"),
            "{empty:?}"
        );
        let mut odd_class = b"\x7fELF\x03\x01\x01".to_vec();
        odd_class.resize(64, 0);
        let Err(refused) = Elf::parse(&odd_class) else {
            panic!("EI_CLASS 3 must be refused");
        };
        assert!(
            matches!(&refused, ElfError::NotElf { why, .. } if why.contains("EI_CLASS") && why.contains('3')),
            "{refused:?}"
        );
        // A Mach-O header, thin in each spelling or universal with two architectures, is
        // its own refusal and says so; an ELF magic over a class this reader has no layout
        // for, above, is not one.
        let refused_as = |head: &[u8]| {
            let mut bytes = head.to_vec();
            bytes.resize(64, 0);
            match Elf::parse(&bytes) {
                Ok(_) => panic!("{head:02x?} must be refused"),
                Err(refused) => refused,
            }
        };
        let fat = |magic: [u8; 4], count: u32| [magic, count.to_be_bytes()].concat();
        for head in MACH_O_THIN_MAGICS
            .iter()
            .map(|m| m.to_vec())
            .chain(MACH_O_FAT_MAGICS.iter().map(|m| fat(*m, 2)))
        {
            let refused = refused_as(&head);
            assert!(
                matches!(refused, ElfError::MachO { path: None }),
                "{refused:?}"
            );
            assert_eq!(refused.to_string(), MACH_O_REFUSAL);
        }
        // A universal magic is a Mach-O object exactly where the count after it is 1 to
        // MAX_FAT_ARCHS; beside no architecture, or a Java class file's version (45 and up
        // in the major half, 0x0003_002d with a minor), it is not.
        for magic in MACH_O_FAT_MAGICS {
            for count in (0..=70).chain([0x0003_002d]) {
                let refused = refused_as(&fat(magic, count));
                if (1..=MAX_FAT_ARCHS).contains(&count) {
                    assert!(
                        matches!(refused, ElfError::MachO { .. }),
                        "{count}: {refused:?}"
                    );
                } else {
                    assert!(
                        matches!(&refused, ElfError::NotElf { why, .. } if why == "not an ELF file"),
                        "{count}: {refused:?}"
                    );
                }
            }
        }
    }

    /// [`is_stride_record`] knows [`record_stride`]'s records and no other `ignored` one: the
    /// two share the sentence's tail, so a reworded record cannot leave the filter behind.
    #[test]
    fn a_stride_record_is_told_apart_by_its_writer() {
        for table in [ElfTable::Symbols, ElfTable::Relocations, ElfTable::Dynamic] {
            let (_, written) = record_stride(48, record_size::<24>(), table, "a: sh_entsize");
            let written = written.expect("48 is not 24");
            assert!(is_stride_record(&written), "{written:?}");
        }
        let (_, written) = record_stride(
            48,
            record_size::<24>(),
            ElfTable::Symbols,
            ".dynsym: sh_entsize",
        );
        let written = written.expect("48 is not 24");
        assert!(is_stride_record(&written), "{written:?}");
        assert!(
            record_stride(24, record_size::<24>(), ElfTable::Symbols, "x")
                .1
                .is_none()
        );
        let unread = Truncation::unread(written.table, written.detail.clone());
        assert!(!is_stride_record(&unread), "an unread record is not one");
        let other = Truncation::ignored(
            ElfTable::Symbols,
            "the dynamic table was not read whole, so no SHT_DYNSYM header could be compared \
             with DT_SYMTAB"
                .to_owned(),
        );
        assert!(!is_stride_record(&other), "{other:?}");
        assert_eq!(
            (
                record_size::<8>().get(),
                record_size::<12>().get(),
                record_size::<24>().get()
            ),
            (8, 12, 24)
        );
    }

    /// The reader's source files the stride test scans, each with whether it ends in a
    /// `tests` module.
    const READER_SOURCES: [(&str, &str, bool); 4] = [
        ("elf.rs", include_str!("elf.rs"), true),
        ("elf/code.rs", include_str!("elf/code.rs"), true),
        ("elf/entry.rs", include_str!("elf/entry.rs"), true),
        (
            "elf/reloc_names.rs",
            include_str!("elf/reloc_names.rs"),
            false,
        ),
    ];

    /// The modules `elf.rs` declares, but the model checker's proofs (`#[cfg(kani)]`).
    fn declared_reader_modules() -> Vec<&'static str> {
        let lines: Vec<&str> = include_str!("elf.rs").lines().collect();
        lines
            .iter()
            .enumerate()
            .filter_map(|(i, l)| {
                let name = l
                    .strip_prefix("pub mod ")
                    .or_else(|| l.strip_prefix("mod "))?
                    .strip_suffix(';')?;
                // Attribute lines alone: the comment above the first include names
                // `cfg(kani)` and is not its gate.
                let kani = lines
                    .iter()
                    .take(i)
                    .rev()
                    .take_while(|p| p.starts_with("#[") || p.starts_with("//"))
                    .any(|p| *p == "#[cfg(kani)]");
                (!kani).then_some(name)
            })
            .collect()
    }

    /// One file's code before its `tests` module, comment lines left out: its `sh_entsize`
    /// reads as (byte offset, line), and the span scanned, as a line of the frame. An entry
    /// size floored at the record fails here, and so does a first `#[cfg(test)]` that does
    /// not open the `tests` module, which would have shrunk the span unseen.
    fn stride_reads(
        file: &str,
        source: &'static str,
        has_tests: bool,
    ) -> (&'static str, Vec<(usize, String)>, usize, String) {
        let marker = format!("#[cfg({})]", "test");
        let floor = format!("{}.max(", "entsize");
        let name = format!("sh_{}", "entsize");
        let code = if let Some((code, tests)) = source.split_once(&marker) {
            assert!(
                tests.starts_with("\nmod tests {"),
                "{file}: the first {marker} at byte {} does not open the tests module",
                code.len()
            );
            code
        } else {
            assert!(!has_tests, "{file}: no {marker} found");
            source
        };
        let (mut at, mut lines, mut reads, mut fields) = (0usize, 0usize, Vec::new(), 0usize);
        for line in code.split_inclusive('\n') {
            lines += 1;
            if !line.trim_start().starts_with("//") {
                assert!(
                    !line.contains(&floor),
                    "{file}: an entry size floored: {line}"
                );
                // Every mention is one of four things: a field read (`.sh_entsize`), a word
                // inside a string literal, the field itself (`sh_entsize:`, its declaration and
                // the parse that sets it), or a longer identifier. A destructuring or any other
                // spelling of a read is none of them and fails.
                for (pos, _) in line.match_indices(&name) {
                    let (before, rest) = line.split_at(pos);
                    let after = rest.split_at(name.len()).1;
                    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
                    if after.starts_with(word) || before.ends_with(word) {
                        continue;
                    }
                    if before.ends_with('.') {
                        reads.push((at, line.trim().to_owned()));
                    } else if before.matches('"').count() % 2 == 1 {
                        // A word of a message.
                    } else if after.starts_with(':') {
                        fields += 1;
                    } else {
                        panic!(
                            "{file}: {name} named outside a read, a string or the field: {line}"
                        );
                    }
                }
            }
            at += line.len();
        }
        let frame = format!(
            "{file}: {lines} lines, bytes 0..{} of {}",
            code.len(),
            source.len()
        );
        (code, reads, fields, frame)
    }

    /// The body of `fn name` in `code`, with its byte offset: from the signature to the
    /// first line that closes a method.
    fn fn_body(code: &'static str, name: &str) -> (usize, &'static str) {
        let (before, rest) = code
            .split_once(&format!("fn {name}("))
            .unwrap_or_else(|| panic!("fn {name} is in elf.rs"));
        let (body, _) = rest.split_once("\n    }\n").expect("the fn closes");
        (before.len(), body)
    }

    /// Every walk of a fixed-record table takes its stride from [`record_stride`]
    /// (2026-10-20). In the reader's non-test source no entry size is floored at the record,
    /// the one read of a section's `sh_entsize` is in [`Elf::section_stride`], which hands it
    /// to the helper, and the dynamic relocation tables' entry-size tags are read in
    /// `relocation_reach` alone, which calls it. The scanned files are the reader's modules,
    /// and each assertion names the frame it was made over.
    #[test]
    fn every_stride_is_decided_by_record_stride() {
        let listed: Vec<&str> = READER_SOURCES
            .iter()
            .filter_map(|(file, _, _)| file.strip_prefix("elf/")?.strip_suffix(".rs"))
            .collect();
        assert_eq!(
            declared_reader_modules(),
            listed,
            "the reader's modules and the scanned files"
        );
        let mut frame = Vec::new();
        let mut reads = Vec::new();
        let mut fields = 0usize;
        let mut elf_code = "";
        for (file, source, has_tests) in READER_SOURCES {
            let (code, found, named, span) = stride_reads(file, source, has_tests);
            fields += named;
            if file == "elf.rs" {
                elf_code = code;
            }
            reads.extend(found.into_iter().map(|(at, line)| (file, at, line)));
            frame.push(span);
        }
        assert_eq!(
            fields, 2,
            "the field is named twice, its declaration and the parse, over {frame:?}"
        );
        let (stride_at, stride) = fn_body(elf_code, "section_stride");
        assert!(
            stride.contains("record_stride("),
            "section_stride calls the helper"
        );
        let [one] = reads.as_slice() else {
            panic!("one sh_entsize read, in section_stride, over {frame:?}: {reads:?}");
        };
        assert!(
            one.0 == "elf.rs" && (stride_at..stride_at + stride.len() + 16).contains(&one.1),
            "the sh_entsize read is section_stride's, over {frame:?}: {reads:?}"
        );
        let (_, reach) = fn_body(elf_code, "relocation_reach");
        assert!(
            reach.contains("record_stride("),
            "relocation_reach strides through the helper"
        );
        for tag in ["DT_RELAENT", "DT_RELENT"] {
            let read = format!("value({tag})");
            assert_eq!(
                elf_code.matches(&read).count(),
                reach.matches(&read).count(),
                "{tag} is read outside relocation_reach, over {frame:?}"
            );
            assert!(reach.contains(&read), "{tag} is read in relocation_reach");
        }
    }

    /// A header cut short is a bounded read that fell outside the object, typed as such,
    /// so a future re-typing cannot pass as a bare `is_err()`.
    #[test]
    fn truncated_elf_header_is_an_error_not_a_panic() {
        let mut data = b"\x7fELF\x02\x01\x01".to_vec();
        data.resize(20, 0);
        let Err(err) = Elf::parse(&data) else {
            panic!("a 20-byte header must be refused");
        };
        assert!(
            matches!(
                err,
                ElfError::Truncated {
                    path: None,
                    read: ReadError::OutOfBounds { .. }
                }
            ),
            "{err:?}"
        );
    }

    /// A directory, a device or a socket is refused from its metadata, before it is
    /// opened, and the refusal names what it was.
    ///
    /// The directory is the case a unit test can build without a shell-out. A FIFO is
    /// read, and `tests/error_classes.rs` holds that through the built binary with an
    /// object fed down a pipe; the cap on that read is pinned by
    /// `a_stream_is_read_to_its_end_and_stopped_at_the_cap`.
    #[test]
    fn what_is_not_a_regular_file_is_refused_before_it_is_opened() {
        let dir = std::env::temp_dir().join(format!("chard-notfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let err = facts_for(&dir).expect_err("a directory is not an object");
        assert!(
            matches!(
                &err,
                ElfError::NotElf { path: Some(p), why }
                    if p == &dir && why.contains("not a regular file") && why.contains("directory")
            ),
            "{err:?}"
        );
        assert_eq!(
            crate::error::file_type_name(std::fs::metadata(&dir).expect("stat").file_type()),
            "a directory"
        );
        crate::error::best_effort(std::fs::remove_dir_all(&dir));
    }

    /// The cap on a source whose length the metadata cannot report.
    ///
    /// A stream that ends within the cap is read whole, one that ends exactly at the cap
    /// is read whole, and one that goes past it is refused after one byte over: the
    /// endless source proves the reader stops rather than reading to an end that never
    /// comes.
    #[test]
    fn a_stream_is_read_to_its_end_and_stopped_at_the_cap() {
        let bytes = [7u8; 16];
        assert_eq!(
            read_under_cap(&bytes[..12], 16).expect("read"),
            Some(bytes[..12].to_vec())
        );
        assert_eq!(
            read_under_cap(&bytes[..], 16).expect("read"),
            Some(bytes.to_vec()),
            "a stream that fills the cap exactly is within it"
        );
        assert_eq!(read_under_cap(&bytes[..], 15).expect("read"), None);
        assert_eq!(
            read_under_cap(std::io::repeat(0), 64).expect("read"),
            None,
            "an endless stream is refused at the cap rather than read to its end"
        );
    }

    /// Every variant renders its path in front of its reason, and `facts_for` is what
    /// attaches the path to a refusal `parse` made without one.
    ///
    /// The messages reach the envelope and `Variant::elf_error` as evidence, and one that
    /// names no file leaves a reader with a refusal and nothing to open. `Display` carries
    /// the whole message and `source()` is `None`, for the reason the type's doc gives.
    #[test]
    fn an_elf_error_names_the_path_and_the_reason() {
        use std::error::Error as _;
        let at = Path::new("/objects/probe-clean");
        let rows: Vec<(ElfError, Vec<&str>)> = vec![
            (
                ElfError::NotElf {
                    path: None,
                    why: "not an ELF file".to_owned(),
                }
                .with_path(at),
                vec!["/objects/probe-clean", "not an ELF file"],
            ),
            (
                ElfError::MachO { path: None }.with_path(at),
                vec!["/objects/probe-clean", MACH_O_REFUSAL],
            ),
            (
                ElfError::malformed("e_shentsize is 0, below the 64-byte record").with_path(at),
                vec!["/objects/probe-clean", "e_shentsize is 0"],
            ),
            (
                ElfError::from(ReadError::OutOfBounds {
                    start: 0x900,
                    count: 8,
                })
                .with_path(at),
                vec!["/objects/probe-clean", "2304", "8", "out of bounds"],
            ),
            (
                ElfError::TooLarge {
                    path: at.to_path_buf(),
                    size: Some(7),
                    cap: 6,
                },
                vec!["/objects/probe-clean", "7 bytes", "6-byte cap"],
            ),
            (
                ElfError::TooLarge {
                    path: at.to_path_buf(),
                    size: None,
                    cap: 6,
                },
                vec!["/objects/probe-clean", "more than 6 bytes", "cap"],
            ),
            (
                ElfError::Io {
                    path: at.to_path_buf(),
                    op: "reading",
                    source: std::io::Error::from_raw_os_error(13),
                },
                vec!["reading /objects/probe-clean", "os error 13"],
            ),
        ];
        assert_eq!(
            rows.len(),
            7,
            "one row per variant, and two for the cap's two sources"
        );
        for (err, wanted) in rows {
            assert_eq!(err.path(), Some(at), "{err:?}");
            assert!(err.source().is_none(), "{err:?}");
            let rendered = err.to_string();
            for needle in wanted {
                assert!(
                    rendered.contains(needle),
                    "{err:?} rendered as {rendered:?}, which does not say {needle}"
                );
            }
        }
        // A refusal that already names a file keeps it: `with_path` is for the ones
        // `parse` made, and `facts_for` calls it once.
        let kept = ElfError::NotElf {
            path: Some(PathBuf::from("/first")),
            why: "not an ELF file".to_owned(),
        }
        .with_path(at);
        assert_eq!(kept.path(), Some(Path::new("/first")));
    }

    /// A deterministic pseudo-random sequence, so a failure reproduces exactly.
    ///
    /// A xorshift rather than a dependency, and seeded rather than drawn from the clock:
    /// a fuzz test that cannot be re-run on the input that broke it is a bug report
    /// nobody can act on.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// A real ELF object to mutate, taken from the running test binary.
    ///
    /// Deliberately not synthesised. A hand-built header exercises the paths a reader
    /// already agrees with itself about; a real linked object carries the section,
    /// segment, dynamic, symbol and note tables whose *offsets into each other* are where
    /// this parser does its arithmetic, and those are what a corrupted length actually
    /// puts under pressure.
    ///
    /// `None` on a host whose binaries are not ELF, where there is no seed and no
    /// substitute: a checked-in object would be a binary chard did not build, and a
    /// synthesised one is what the paragraph above rejects. The callers announce and
    /// return rather than being `#[cfg]`-ed away, which is how this was written first --
    /// that silently moved the lib binary from 248 tests to 246 on a Mac, and a count that
    /// changes with the host without saying so is the reduced coverage nobody notices.
    fn a_real_object(verifies: &str) -> Option<Vec<u8>> {
        let path = std::env::current_exe().expect("the test binary's own path");
        let bytes = std::fs::read(&path).expect("reading the test binary");
        if !bytes.starts_with(b"\x7fELF") {
            crate::error::capability_gap(
                verifies,
                &format!(
                    "{} is not an ELF object, so there is no seed to mutate",
                    path.display()
                ),
            );
            return None;
        }
        Some(bytes)
    }

    /// The parser must return, never panic, on any corruption of a real object.
    ///
    /// `src/elf.rs` reads binaries chard did not build — `chard elf` takes any path a
    /// caller hands it — so its input is the one thing in this project that is not
    /// chard's to trust. `unsafe_code = "deny"` rules out memory unsafety, which leaves
    /// panics: an out-of-range slice, an overflowing offset, a length taken from the file
    /// and used as a bound. A panic costs the caller every object not yet reached.
    ///
    /// Two existing tests covered one truncation and one non-ELF buffer. This covers the
    /// shape those miss: a header that parses, leading the reader into tables whose
    /// offsets and counts have been corrupted underneath it.
    #[test]
    fn no_corruption_of_a_real_object_makes_the_parser_panic() {
        let Some(original) = a_real_object("that no corruption of a real object panics the parser")
        else {
            return;
        };
        let mut rng = Rng(0x5eed_1234_abcd_ef01);

        // Concentrated on the first 4 KiB, where every table offset and count lives. A
        // byte flipped in the middle of .text changes nothing this parser reads.
        let header_span = original.len().min(4096);
        // The corruptions, drawn first and in order from the one seed, so the set is the
        // same however it is shared out below. A flip is a byte offset and the bit it flips.
        let plans: Vec<Vec<(usize, u8)>> = (0..1200)
            .map(|_| {
                let flips = 1 + (rng.next() % 4) as usize;
                (0..flips)
                    .map(|_| {
                        let at = usize::try_from(rng.next() % header_span as u64).unwrap_or(0);
                        (at, 1u8 << (rng.next() % 8))
                    })
                    .collect()
            })
            .collect();
        // Each corruption parsed and walked, on every thread the host offers: one parse
        // of a debug test binary of some megabytes takes a fifth of a second, and the
        // twelve hundred of them one after another were the merge gate's longest wait.
        // Each thread mutates its own copy in place and restores it, rather than
        // cloning per corruption: cloning the seed four thousand times spent the test's
        // whole runtime in the allocator rather than in the parser.
        // At most eight: each worker holds its own copy of the seed, a debug test binary of up
        // to some 140 MB, and eight already make the walk a matter of seconds.
        let threads = std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .min(8);
        let chunk = plans.len().div_ceil(threads);
        let (parsed_ok, errored) = std::thread::scope(|s| {
            let workers: Vec<_> = plans
                .chunks(chunk)
                .map(|share| {
                    let original = &original;
                    std::thread::Scope::spawn(s, move || {
                        let mut data = original.clone();
                        let (mut parsed, mut rejected) = (0usize, 0usize);
                        for plan in share {
                            for &(at, bit) in plan {
                                if let Some(byte) = data.get_mut(at) {
                                    *byte ^= bit;
                                }
                            }
                            match Elf::parse(&data) {
                                Ok(elf) => {
                                    // Force the whole extraction, not just the header:
                                    // `facts()` is what walks the tables the corrupted
                                    // offsets point into.
                                    let _ = elf.facts();
                                    parsed = parsed.saturating_add(1);
                                }
                                Err(_) => rejected = rejected.saturating_add(1),
                            }
                            for &(at, bit) in plan {
                                if let Some(byte) = data.get_mut(at) {
                                    *byte ^= bit;
                                }
                            }
                        }
                        assert!(
                            data == *original,
                            "the in-place mutations were not fully restored"
                        );
                        (parsed, rejected)
                    })
                })
                .collect();
            workers.into_iter().fold((0usize, 0usize), |(p, r), w| {
                // A worker that panicked is the parser panicking on a corruption (or the
                // restore failing): the test fails with that panic, as it did on one thread.
                let (wp, wr) = w.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
                (p.saturating_add(wp), r.saturating_add(wr))
            })
        });

        // Truncation at every length up to the header region, which is the other way a
        // table can run off the end.
        let mut truncations_parsed = 0usize;
        for len in 0..header_span.min(1024) {
            if let Ok(elf) = Elf::parse(original.get(..len).unwrap_or(&original)) {
                let _ = elf.facts();
                truncations_parsed = truncations_parsed.saturating_add(1);
            }
        }

        // The frame. Reaching here having only ever failed at the magic bytes would mean
        // the parser was never entered, and the test would pass having exercised nothing.
        eprintln!(
            "fuzzed {} corrupted objects ({parsed_ok} parsed, {errored} rejected, on {} \
             threads) and {} truncations ({truncations_parsed} parsed)",
            parsed_ok.saturating_add(errored),
            plans.len().div_ceil(chunk),
            header_span.min(1024),
        );
        assert!(
            parsed_ok > 100,
            "only {parsed_ok} corrupted objects parsed far enough to walk their tables; \
             this test is not reaching the code it exists to exercise"
        );
        assert!(
            errored > 0,
            "no corruption was rejected, which means the mutations are not landing on \
             anything the parser validates"
        );
    }
}
