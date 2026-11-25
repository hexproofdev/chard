// SPDX-License-Identifier: BSD-3-Clause

//! ELF fact extraction for the `elf-static` observation channel.

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
/// The thread-local storage template; a segment like any other for `p_flags`.
const PT_TLS: u32 = 7;
/// The segment `ld.so` and the kernel read the program's property notes from.
const PT_GNU_PROPERTY: u32 = 0x6474_e553;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
/// OpenBSD's per-program opt-out from branch-target enforcement, written by its linker
/// under `-z nobtcfi`. The value is the one OpenBSD 7.9 installs in
/// `/usr/include/llvm/BinaryFormat/ELF.h`; see [`ElfFacts::openbsd_nobtcfi`].
const PT_OPENBSD_NOBTCFI: u32 = 0x65a3_dbe8;

const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;

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
const ET_REL: u16 = 1;
/// A core dump. Named because an unnamed type is indistinguishable from a type nobody thought
/// about.
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
/// `arm`, `ppc`, `ppc64`, `s390`, `mips`, `riscv`, `loongarch`).
/// [`ElfFacts::data_in_code_pages`] widens an executable segment to at least this, whatever
/// its `p_align` says.
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
// The original gABI spelling of the fact `DF_TEXTREL` also carries.
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
// DT_FLAGS_1 bits, spelled out in full: `DF_1_NOOPEN` is 0x40, while 0x4 is `DF_1_GROUP`,
// and the wrong bit reads a `-Wl,-z,nodlopen` binary as unmarked, a false `off`.
const DF_1_NOW: u64 = 0x0000_0001;
const DF_1_NOOPEN: u64 = 0x0000_0040;
const DF_1_PIE: u64 = 0x0800_0000;

/// `e_machine` values, as glibc's `elf.h` and the gABI define them, for the machines a sweep
/// is likely to meet: `machine_name` names them as readelf does and renders any other value
/// as unrecognised. `tests/elf_readelf.rs` checks each name against readelf's on any object
/// of that machine it meets.
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
/// The note [`Elf::parse_notes`] keeps for one walk: its owner and type, and whether a note
/// of that type whose name bytes are the owner and its NUL is held to that `n_namesz`.
#[derive(Clone, Copy)]
struct NoteKind {
    owner: &'static str,
    ntype: u32,
    name_size_held: bool,
}

/// The GNU property note, the one note [`Elf::parse_notes`] keeps for [`Elf::notes`]. Its
/// `n_namesz` is held: Linux 7.3-rc1's `parse_elf_properties` (`fs/binfmt_elf.c`) returns
/// `ENOEXEC` for a property note whose `n_namesz` is not `sizeof("GNU")`.
const GNU_PROPERTY_NOTE: NoteKind = NoteKind {
    owner: "GNU",
    ntype: NT_GNU_PROPERTY_TYPE_0,
    name_size_held: true,
};
/// The floor of the processor-specific property range. A type at or above it means
/// whatever `e_machine` says it means, and nothing without that.
const GNU_PROPERTY_LOPROC: u32 = 0xc000_0000;
const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
/// `0xc0000000` is four things at once. It is `GNU_PROPERTY_LOPROC`, the first value of
/// the processor-specific range; on aarch64 it is `GNU_PROPERTY_AARCH64_FEATURE_1_AND`,
/// the BTI/PAC/GCS word; on `EM_RISCV` it is `GNU_PROPERTY_RISCV_FEATURE_1_AND`; and
/// binutils before 2.32 used it on x86 for `GNU_PROPERTY_X86_ISA_1_USED`, so an x86-64
/// object linked by gcc 8 or 9-era binutils carries this type with an ISA bitmap in it.
/// Read without the machine, that bitmap publishes `aarch64_bti: true` and
/// `aarch64_pac: true` on an x86-64 binary, which is why `facts` decodes a
/// processor-specific property only on the machine that defines it.
const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc000_0000;
const X86_FEATURE_1_IBT: u32 = 0x1;
const X86_FEATURE_1_SHSTK: u32 = 0x2;
const AARCH64_FEATURE_1_BTI: u32 = 0x1;
const AARCH64_FEATURE_1_PAC: u32 = 0x2;
/// Guarded Control Stack, aarch64's counterpart to x86's shadow stack. Set by
/// `-mbranch-protection=gcs`, and also by `standard` on compilers new enough to have it.
const AARCH64_FEATURE_1_GCS: u32 = 0x4;

/// `SHT_AARCH64_ATTRIBUTES`, `SHT_LOPROC + 3`: the type of `.ARM.attributes` on aarch64, the
/// build-attributes section of the Arm ELF ABI for the 64-bit architecture (format version `A`).
const SHT_AARCH64_ATTRIBUTES: u32 = 0x7000_0003;
/// The build-attributes subsection that states the BTI, PAC and GCS marking, tags 0, 1 and 2,
/// each ULEB128 and 1 for marked. gcc 16.1.1 with binutils 2.46 (Fedora 44's aarch64 cross
/// compiler) writes it to an unlinked object in place of a GNU property note.
const AEABI_FEATURE_AND_BITS: &[u8] = b"aeabi_feature_and_bits";

/// Symbols whose presence or absence a probe may key on. One list, so the facts have the
/// same shape whichever probe built the binary and reports diff across toolchains.
pub const WATCHED_SYMBOLS: &[&str] = &[
    "__stack_chk_fail",
    "__stack_chk_fail_local",
    "__stack_chk_guard",
    // OpenBSD's canary failure handler, called where other targets call
    // `__stack_chk_fail`.
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
    // reads either and carries the measurement.
    "__vprintf_chk",
    "__fprintf_chk",
    "__vsnprintf_chk",
    "__read_chk",
    // FreeBSD's failure handler, which its inline wrappers (`__ssp_check` in `<ssp/ssp.h>`)
    // call directly; `decode::runtime::FREEBSD_CHECKING_CALLS` lists it beside the `__*_chk`
    // functions above.
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
    // preserved.
    "__ubsan_handle_type_mismatch_minimal_preserve",
    "__ubsan_handle_shift_out_of_bounds_minimal_preserve",
    "__ubsan_handle_out_of_bounds_minimal_preserve",
    "__ubsan_handle_add_overflow_minimal_preserve",
    "__ubsan_handle_pointer_overflow_minimal_preserve",
    // The type-mismatch handler's name before its `_v1` revision, which gcc 8 and clang 5
    // adopted: a toolchain older than those calls this one.
    "__ubsan_handle_type_mismatch",
    "__ubsan_handle_type_mismatch_abort",
    // The handlers `probes/ubsan_trap.c`'s third and fourth functions call outside trap
    // mode: clang's `local-bounds` on the indexed global array
    // under `-fno-sanitize-trap=local-bounds` (the group traps by default), and clang's
    // `function` on the call through a pointer.
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
    // call the predicate cannot name.
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
    // entry points `-D_GLIBCXX_DEBUG` substitutes for it.
    "_ZSt21__glibcxx_assert_failPKciS0_S0_",
    // The same failure before GCC 12 moved it out of line: `std::__replacement_assert`,
    // defined inline in `bits/c++config.h` and emitted as a comdat wherever the compiler
    // did not fold it away.
    "_ZSt20__replacement_assertPKciS0_S0_",
    "_ZNK11__gnu_debug16_Error_formatter10_M_messageENS_13_Debug_msg_idE",
    "_ZNK11__gnu_debug16_Error_formatter8_M_errorEv",
    // gcc's mark of a slim LTO object: a common symbol in an object that holds GIMPLE in
    // `.gnu.lto_*` sections and no generated code, over which `report::lto_ir_limitation`
    // withholds an elf-static reading.
    "__gnu_lto_slim",
    // libgcc's trapping arithmetic for `int`, which gcc calls in place of a signed
    // addition, subtraction or multiplication under -ftrapv; undefined in the object that
    // calls them.
    "__addvsi3",
    "__subvsi3",
    "__mulvsi3",
];

/// The `aeabi_feature_and_bits` word of one build-attributes section's bytes: `Ok(None)`
/// where the section holds no such subsection, `Err` with the reason where it cannot be
/// read whole.
fn feature_and_bits(bytes: &[u8], little: bool) -> Result<Option<u32>, String> {
    let Some((&version, mut rest)) = bytes.split_first() else {
        return Ok(None);
    };
    if version != b'A' {
        return Err(format!("format version {version:#04x}, not 'A'"));
    }
    let mut word: Option<u32> = None;
    while !rest.is_empty() {
        let Some(&head) = rest.first_chunk::<4>() else {
            return Err("a subsection length lies past the end of the section".to_owned());
        };
        let len = if little {
            u32::from_le_bytes(head)
        } else {
            u32::from_be_bytes(head)
        };
        let fits = usize::try_from(len)
            .ok()
            .filter(|&n| n > 4)
            .and_then(|n| Some((rest.get(4..n)?, rest.get(n..)?)));
        let Some((sub, next)) = fits else {
            return Err(format!(
                "a subsection of length {len} does not fit the {} bytes left",
                rest.len()
            ));
        };
        rest = next;
        let mut parts = sub.splitn(2, |&b| b == 0);
        let (Some(name), Some(tail)) = (parts.next(), parts.next()) else {
            return Err("a subsection name has no terminator".to_owned());
        };
        if name != AEABI_FEATURE_AND_BITS {
            continue;
        }
        let Some((&[_comprehension, encoding], mut pairs)) = tail.split_first_chunk::<2>() else {
            return Err("the feature subsection ends before its encoding byte".to_owned());
        };
        if encoding != 0 {
            return Err(format!("the feature subsection's encoding is {encoding}"));
        }
        let mut found = [None::<bool>; 3];
        while !pairs.is_empty() {
            let (tag, after) = uleb128(pairs).ok_or("a tag is cut off")?;
            let (value, after) = uleb128(after).ok_or("a value is cut off")?;
            pairs = after;
            let Some(slot) = usize::try_from(tag).ok().and_then(|t| found.get_mut(t)) else {
                continue;
            };
            if slot.is_some() {
                return Err(format!("tag {tag} is given twice"));
            }
            *slot = Some(match value {
                0 => false,
                1 => true,
                v => return Err(format!("tag {tag} holds {v}, not 0 or 1")),
            });
        }
        let this = found
            .iter()
            .zip([
                AARCH64_FEATURE_1_BTI,
                AARCH64_FEATURE_1_PAC,
                AARCH64_FEATURE_1_GCS,
            ])
            .filter(|(set, _)| **set == Some(true))
            .fold(0, |w, (_, bit)| w | bit);
        word = Some(word.map_or(this, |w| w & this));
    }
    Ok(word)
}

/// One ULEB128 number from the front of `bytes`, and what follows it; `None` where the
/// number runs off the end or past 64 bits.
fn uleb128(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0u64;
    let mut rest = bytes;
    for shift in (0..64).step_by(7) {
        let (&b, after) = rest.split_first()?;
        rest = after;
        // The tenth byte holds bit 63 alone: anything above it is a number past 64 bits.
        if shift == 63 && b & 0x7e != 0 {
            return None;
        }
        value |= u64::from(b & 0x7f).checked_shl(shift)?;
        if b & 0x80 == 0 {
            return Some((value, rest));
        }
    }
    None
}

/// The least multiple of `align` that is not below `value`, or `None` when `value + align -
/// 1` overflows, which for an alignment that is a power of two means no such multiple is
/// representable.
// The bare `align - 1`, `/` and `*` below are the operations this lint exists to catch.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "align >= 2 makes the subtraction, division and multiplication total"
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
fn note_alignment(declared: u64) -> u64 {
    declared.max(4)
}

/// Where the note whose header is at `pos` puts its descriptor, and where the next note
/// starts. `proofs/note_walk_stays_in_its_table.rs` proves what a walk takes from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NoteSpan {
    desc_off: u64,
    /// `None` where the descriptor's padded length overflows.
    next: Option<u64>,
}

/// Why [`note_span`] refuses a note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoteRefusal {
    /// The name's padded length overflows the descriptor's offset.
    Overflows,
    /// The descriptor runs past the end of the table or the file.
    PastTheEnd,
}

/// The note at `pos` with an `n_namesz` of `namesz` and an `n_descsz` of `descsz`, in a table
/// that ends at `end` of a file that ends at `file_end`. The descriptor starts at `pos` plus
/// `12 + namesz` rounded up to `align`: the padding is of the offset from the note's own start,
/// the rule this module's header warns about. It must end inside both the table and the file.
/// The next note starts after the descriptor padded to `align`.
fn note_span(
    pos: u64,
    namesz: u32,
    descsz: u32,
    align: u64,
    end: u64,
    file_end: u64,
) -> Result<NoteSpan, NoteRefusal> {
    let rel =
        align_up(12u64.saturating_add(u64::from(namesz)), align).ok_or(NoteRefusal::Overflows)?;
    // Saturating is safe here: a saturated sum exceeds `file_end`, a slice's length, and is
    // refused.
    let desc_off = pos.saturating_add(rel);
    let desc_len = u64::from(descsz);
    let desc_end = desc_off.saturating_add(desc_len);
    if desc_end > end || desc_end > file_end {
        return Err(NoteRefusal::PastTheEnd);
    }
    Ok(NoteSpan {
        desc_off,
        next: align_up(desc_len, align).map(|pad| desc_off.saturating_add(pad)),
    })
}

/// Where the data of the property whose header is at `pos` starts, and where the next
/// property starts. `proofs/note_walk_stays_in_its_table.rs` proves what a walk takes from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PropertySpan {
    data_off: u64,
    next: u64,
}

/// Why [`property_span`] refuses a property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PropertyRefusal {
    /// The data's padded length, or the next offset, overflows.
    Overflows,
    /// The data, padded to `pad` bytes, runs past the descriptor.
    PastTheEnd { pad: u64 },
}

/// The property at `pos` with a `pr_datasz` of `datasz`, in a descriptor that ends at `end`.
/// Its data follows the 8-byte header, and the next property follows the data padded to
/// `align`, which must not pass the descriptor's end.
fn property_span(
    pos: u64,
    datasz: u32,
    align: u64,
    end: u64,
) -> Result<PropertySpan, PropertyRefusal> {
    let data_off = pos.saturating_add(8);
    let pad = align_up(u64::from(datasz), align).ok_or(PropertyRefusal::Overflows)?;
    // Checked, not saturating: a sum saturated to `u64::MAX` would pass the test below for a
    // descriptor that ends there.
    let next = data_off
        .checked_add(pad)
        .ok_or(PropertyRefusal::Overflows)?;
    if next > end {
        return Err(PropertyRefusal::PastTheEnd { pad });
    }
    Ok(PropertySpan { data_off, next })
}

/// The bytes one program header and one section header occupy in this class: `Elf64_Phdr`
/// and `Elf64_Shdr` are 56 and 64 bytes, `Elf32_Phdr` and `Elf32_Shdr` 32 and 40.
fn header_records(elf64: bool) -> (NonZeroU64, NonZeroU64) {
    if elf64 {
        (record_size::<56>(), record_size::<64>())
    } else {
        (record_size::<32>(), record_size::<40>())
    }
}

/// Refuse a header table whose declared stride is no record size.
fn check_strides(elf64: bool, ph: (u64, u64), sh: (u64, u64)) -> Result<(), ElfError> {
    let (ph_record, sh_record) = header_records(elf64);
    for (field, record, (count, entsize), min) in [
        ("e_phentsize", "program header", ph, ph_record.get()),
        ("e_shentsize", "section header", sh, sh_record.get()),
    ] {
        if count > 0 && entsize < min {
            return Err(ElfError::malformed(format!(
                "{field} is {entsize}, below the {min}-byte {record} this class defines, so \
                 the {count} declared entries overlap rather than follow one another"
            )));
        }
    }
    let (count, entsize) = ph;
    if count > 0 && entsize != ph_record.get() {
        return Err(ElfError::malformed(format!(
            "e_phentsize is {entsize}, not the {ph_record}-byte program header this class defines, so the program-header table ({count} declared) was not read"
        )));
    }
    Ok(())
}

/// Why the section-header table is not read, where `e_shoff` is 0 and the header still declares
/// sections: an `unread` [`ElfTable::SectionHeaders`] record, under which the file is read as
/// having no section-header table. `None` where `e_shoff` names a table or no section is
/// declared.
fn section_table_at_no_offset(e_shoff: u64, count: u64) -> Option<Truncation> {
    (e_shoff == 0 && count > 0).then(|| {
        Truncation::unread(
            ElfTable::SectionHeaders,
            format!(
                "section-header table: e_shoff is 0, which says the file has none, while e_shnum declares {count} headers"
            ),
        )
    })
}

/// Why the section-header table is not read, where it declares a stride above the record's:
/// an `unread` [`ElfTable::SectionHeaders`] record, under which the file is read as having no
/// section-header table. `None` where the table is read.
fn section_table_withheld(count: u64, entsize: u64, record: NonZeroU64) -> Option<Truncation> {
    (count > 0 && entsize != record.get()).then(|| {
        Truncation::unread(
            ElfTable::SectionHeaders,
            format!(
                "section-header table: e_shentsize is {entsize} where the record is {record} bytes, so its {count} headers could lie at either stride"
            ),
        )
    })
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

/// Whether `t` is a record `record_stride` wrote: `ignored`, and its detail ending as that
/// helper's does. For a reader that compares two readings with the declarations taken out
/// (the `elf_parse` fuzz target), so its filter is this module's and not a copy of the
/// sentence; `tests::a_stride_record_is_told_apart_by_its_writer` holds the two together.
#[must_use]
pub fn is_stride_record(t: &Truncation) -> bool {
    t.kind == TruncationKind::Ignored && t.detail.ends_with(STRIDE_RECORD_TAIL)
}

/// `trunc` with each stride record kept at its first place only: several walks read one
/// section (the symbol readers, a relocatable object's three relocation walks), and
/// [`Elf::section_stride`] labels the record from that section alone, so theirs are equal
/// and two sections' are not. One pass over a set, not quadratic in the section count; the
/// other records are left as they are.
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
    /// The header describes a table the file cannot hold, or one chard reads at no stride: a
    /// stride below the record, a program-header stride other than the record, an offset that
    /// overflows, a `shdr[0]` escape that names bytes past the end.
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
                "{} is {size} bytes, above the {cap}-byte cap on a single object.",
                path.display()
            ),
            Self::TooLarge {
                path,
                size: None,
                cap,
            } => write!(
                f,
                "{} carried more than {cap} bytes, the cap on a single object.",
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
type Read<T> = Result<T, ReadError>;

impl<'a> Cursor<'a> {
    fn slice(&self, off: u64, len: u64) -> Read<&'a [u8]> {
        // The discarded `TryFromIntError` says only "did not fit", which the variant
        // already says while also carrying the value that did not fit.
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

    /// A NUL-terminated string at `base + off`, never read past `table_len` bytes from
    /// `base`. `table_len` is the caller's own declared bound on the table `base`
    /// starts (a section's `sh_size`, `DT_STRSZ`, a note's `namesz`), never the size of
    /// `self.data`. A table whose declared length is exceeded before any NUL appears
    /// reads as truncated at that length, not as reaching into whatever bytes follow. An
    /// `off` at or past `table_len`, or a start past the data, reads as the empty name.
    fn cstr_at(&self, base: u64, off: u32, table_len: u64) -> Result<&'a [u8], Overlong> {
        let Some(remaining) = table_len.checked_sub(u64::from(off)) else {
            return Ok(&[]); // `off` is at or past the table's own declared end
        };
        let Ok(start) = usize::try_from(base.saturating_add(u64::from(off))) else {
            return Ok(&[]);
        };
        let cap = usize::try_from(remaining).unwrap_or(usize::MAX);
        let Some(rest) = self.data.get(start..) else {
            return Ok(&[]);
        };
        let bounded = rest.get(..cap.min(rest.len())).unwrap_or(rest);
        // One byte past the bound is searched, so a name of exactly `MAX_NAME_BYTES` is
        // told from a longer one by the NUL after it.
        let window = bounded
            .get(..bounded.len().min(MAX_NAME_BYTES.saturating_add(1)))
            .unwrap_or(bounded);
        match window.iter().position(|&c| c == 0) {
            Some(end) => Ok(window.get(..end).unwrap_or(&[])),
            None if bounded.len() <= MAX_NAME_BYTES => Ok(bounded),
            None => Err(Overlong),
        }
    }
}

/// The longest name, in bytes and without its NUL, the reader takes from a string table:
/// a section, symbol, note or dynamic-string name longer than this is not read, and the walk
/// that met it records its table `unread` and stops (`NameFault::Overlong`).
pub const MAX_NAME_BYTES: usize = 64 * 1024;

/// The longest section name a label carries whole; see [`label_of`].
const LABEL_BYTES: usize = 256;

/// Section `idx`'s label in the records and facts the walks write: its name, or, for a name
/// longer than [`LABEL_BYTES`], the name's first 64 bytes, an ellipsis and the index.
fn label_of(name: &str, idx: usize) -> String {
    if name.len() <= LABEL_BYTES {
        return name.to_owned();
    }
    let cut = name
        .char_indices()
        .map(|(at, _)| at)
        .take_while(|&at| at <= 64)
        .fold(0, |_, at| at);
    format!("{}... [{idx}]", name.get(..cut).unwrap_or(""))
}

/// A name past [`MAX_NAME_BYTES`]: the scan found no NUL within the bound and the table
/// goes on past it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Overlong;

/// Units of reader work allowed per byte of the file read; see [`work_budget`].
pub const WORK_PER_BYTE: u64 = 16;

/// Units of reader work allowed whatever the file's length; see [`work_budget`].
pub const WORK_FLOOR: u64 = 1 << 20;

/// The units of work the reader may spend on a file of `len` bytes:
/// [`WORK_PER_BYTE`] per byte plus [`WORK_FLOOR`].
#[must_use]
pub fn work_budget(len: usize) -> u64 {
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    len.saturating_mul(WORK_PER_BYTE).saturating_add(WORK_FLOOR)
}

/// The work one file's reading may still spend.
struct Budget {
    granted: u64,
    left: std::cell::Cell<u64>,
    /// Whether a spend has failed, which `left` at zero does not say: a spend can take the
    /// last unit and succeed.
    ran_out: std::cell::Cell<bool>,
    /// What was left, and whether a spend had failed, when [`Elf::parse_within`] returned: each
    /// [`Elf::facts`] starts from it, so a second reading spends what the first did.
    parsed: std::cell::Cell<(u64, bool)>,
}

impl Budget {
    fn new(granted: u64) -> Self {
        Self {
            granted,
            left: std::cell::Cell::new(granted),
            ran_out: std::cell::Cell::new(false),
            parsed: std::cell::Cell::new((granted, false)),
        }
    }

    /// Keep what is left as the point every reading starts from.
    fn mark_parsed(&self) {
        self.parsed.set((self.left.get(), self.ran_out.get()));
    }

    /// Go back to the point [`Self::mark_parsed`] kept.
    fn restart(&self) {
        let (left, ran_out) = self.parsed.get();
        self.left.set(left);
        self.ran_out.set(ran_out);
    }

    /// The failure a spend has met, if one has: for a walk whose own records go to a
    /// scratch list, to say its table was cut by the budget.
    fn exhausted(&self) -> Option<Spent> {
        self.ran_out.get().then_some(Spent {
            granted: self.granted,
        })
    }

    /// Take `units` from what is left, or fail and leave nothing, so every later spend
    /// fails too.
    fn spend(&self, units: u64) -> Result<(), Spent> {
        if let Some(left) = self.left.get().checked_sub(units) {
            self.left.set(left);
            return Ok(());
        }
        self.left.set(0);
        self.ran_out.set(true);
        Err(Spent {
            granted: self.granted,
        })
    }

    fn spent(&self) -> u64 {
        self.granted.saturating_sub(self.left.get())
    }
}

/// The budget ran out: the walk that meets this stops and records its table `unread`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Spent {
    granted: u64,
}

impl std::fmt::Display for Spent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the reader's work budget for this file ({} units) was spent",
            self.granted
        )
    }
}

/// Why a name was not taken from its string table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameFault {
    /// Longer than [`MAX_NAME_BYTES`].
    Overlong,
    /// The file's work budget ran out.
    Spent(Spent),
}

impl From<Spent> for NameFault {
    fn from(spent: Spent) -> Self {
        Self::Spent(spent)
    }
}

impl std::fmt::Display for NameFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overlong => write!(
                f,
                "a name runs past the reader's {MAX_NAME_BYTES}-byte bound on one name"
            ),
            Self::Spent(spent) => spent.fmt(f),
        }
    }
}

/// Why one symbol-table entry was not read: its bytes are not in the file, or its name was
/// not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryStop {
    Read(ReadError),
    Name(NameFault),
}

impl From<ReadError> for EntryStop {
    fn from(read: ReadError) -> Self {
        Self::Read(read)
    }
}

impl From<NameFault> for EntryStop {
    fn from(fault: NameFault) -> Self {
        Self::Name(fault)
    }
}

impl std::fmt::Display for EntryStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(read) => read.fmt(f),
            Self::Name(fault) => fault.fmt(f),
        }
    }
}

/// The name at `base + off` in a table of `table_len` bytes, charged to `budget`: one unit
/// per byte and one for the NUL.
fn name_in(
    cur: &Cursor<'_>,
    budget: &Budget,
    (base, off, table_len): (u64, u32, u64),
) -> Result<String, NameFault> {
    let Ok(bytes) = cur.cstr_at(base, off, table_len) else {
        // The bytes searched before the refusal are charged too, so headers aliasing one
        // table whose name runs past the bound each pay for the search.
        budget.spend(u64::try_from(MAX_NAME_BYTES).unwrap_or(u64::MAX))?;
        return Err(NameFault::Overlong);
    };
    let units = u64::try_from(bytes.len())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    budget.spend(units)?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

/// The symbols [`Elf::symbols`] has read, and every versioned spelling kept among them, so a
/// repeat is found in a set and not by a scan of the name's list: `N` symbols sharing one bare
/// name under distinct versions would scan `N x N`.
#[derive(Default)]
struct SymbolsRead {
    facts: BTreeMap<String, SymbolFact>,
    spellings: BTreeSet<String>,
}

/// The (function, symbol) pairs and the unattributed symbols `function_references` has listed,
/// by index, so a repeat is found without comparing names, whose shared prefix a crafted file
/// makes as long as the bound on one name.
#[derive(Default)]
struct Attributed {
    pairs: BTreeSet<(usize, u64)>,
    unattributed: BTreeSet<u64>,
}

/// The symbols `code_relocations` has named, by the offset of the symbol's entry and the offset
/// and size of the string table its name was read through, and the kinds listed through each,
/// so an entry through a symbol already named reads and lists nothing again: otherwise a
/// relocatable object of `R` entries through one long name would copy that name `R` times.
#[derive(Default)]
struct RelocationsRead {
    names: BTreeMap<(u64, u64, u64), Option<(String, u8)>>,
    listed: BTreeSet<(u32, (u64, u64, u64))>,
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

/// The program-header table: `count` records of the class's program-header size from
/// `off`. It takes no declared stride: [`check_strides`] has refused any other.
fn read_phdrs(cur: &Cursor<'_>, elf64: bool, off: u64, count: u64) -> Result<Vec<Phdr>, ElfError> {
    let (record, _) = header_records(elf64);
    let mut phdrs = Vec::new();
    for i in 0..count {
        let base = off
            .checked_add(
                i.checked_mul(record.get())
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
            // were no section-header table.
            truncations.push(Truncation::unread(
                ElfTable::SectionHeaders,
                format!(
                    "section-header table: e_shnum is 0 and e_shoff {e_shoff:#x} names a shdr[0] the file does not hold ({e})"
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
    budget: &Budget,
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
    // `cstr_at` answers "" for an offset past the end of the file, so the table's bytes are
    // held first: a table the file does not hold would read every section as unnamed.
    let base = strtab.sh_offset;
    let len = strtab.sh_size;
    if let Err(why) = cur.slice(base, len) {
        truncations.push(Truncation::unread(
            ElfTable::SectionNames,
            format!(
                "section names: the table at {base:#x}+{len:#x} lies past the end of the file ({why})"
            ),
        ));
        return vec![String::new(); shdrs.len()];
    }
    // Bounded by the table's own `sh_size`, which `cstr_at` requires of every caller: a
    // name that runs past the table's declared end is cut at that end.
    let mut names = Vec::with_capacity(shdrs.len());
    for (i, sh) in shdrs.iter().enumerate() {
        match name_in(cur, budget, (base, sh.sh_name, len)) {
            Ok(name) => names.push(name),
            Err(fault) => {
                truncations.push(Truncation::unread(
                    ElfTable::SectionNames,
                    format!(
                        "section names: section {i} of {} names offset {:#x} of the table at {base:#x}+{len:#x}, and {fault}",
                        shdrs.len(),
                        sh.sh_name
                    ),
                ));
                return vec![String::new(); shdrs.len()];
            }
        }
    }
    names
}

/// The section-name table, or why there is none to read.
fn section_name_table(shdrs: &[Shdr], shstrndx: u32) -> Result<&Shdr, String> {
    if shstrndx == u32::from(SHN_UNDEF) {
        return Err(
            "e_shstrndx is SHN_UNDEF, so the file declares no section-name table \
                    and no section can be found by name"
                .to_owned(),
        );
    }
    let Some(candidate) = shdrs.get(usize::try_from(shstrndx).unwrap_or(usize::MAX)) else {
        return Err(format!(
            "e_shstrndx {shstrndx} is past the section-header table of {} entries",
            shdrs.len()
        ));
    };
    if candidate.sh_type != SHT_STRTAB {
        return Err(format!(
            "e_shstrndx {shstrndx} names a section of type {:#x}",
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

/// Byte ranges `[start, end)` sorted by start, beside the running maximum of their ends, so
/// whether any range overlaps or contains a given one is a binary search, not a scan.
struct Spans {
    starts: Vec<u64>,
    reach: Vec<u64>,
}

impl Spans {
    fn new(mut spans: Vec<(u64, u64)>) -> Self {
        spans.sort_unstable();
        let mut furthest = 0;
        let reach = spans
            .iter()
            .map(|&(_, end)| {
                furthest = furthest.max(end);
                furthest
            })
            .collect();
        Self {
            starts: spans.into_iter().map(|(start, _)| start).collect(),
            reach,
        }
    }

    /// The furthest end among the ranges starting where `starts_before` holds.
    fn reach_of(&self, starts_before: impl Fn(u64) -> bool) -> Option<u64> {
        let n = self.starts.partition_point(|&s| starts_before(s));
        n.checked_sub(1)
            .and_then(|last| self.reach.get(last).copied())
    }

    /// Whether some range shares a byte with `[start, end)`.
    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.reach_of(|s| s < end).is_some_and(|r| r > start)
    }

    /// Whether some range holds all of `[start, end)`.
    fn contains(&self, start: u64, end: u64) -> bool {
        self.reach_of(|s| s <= start).is_some_and(|r| r >= end)
    }
}

/// A note of the one owner and type a walk asked [`Elf::parse_notes`] for, by its descriptor's
/// offset and length: a GNU property note (`GNU`, `NT_GNU_PROPERTY_TYPE_0`) for the property
/// note walks, the only notes a property check reads, or the run witness for
/// [`Elf::run_witness`]. Every note of a table is read, and these alone are kept.
struct Note {
    desc_off: u64,
    desc_len: u64,
    short_len: u64,
}

impl Note {
    /// The note one header read: its descriptor at `desc_off`, `desc_len` long.
    fn read(desc_off: u64, desc_len: u64) -> Self {
        Self {
            desc_off,
            desc_len,
            short_len: desc_len,
        }
    }
}

/// Keep `note` once by its descriptor's offset, with the longest and the shortest length read
/// there.
fn keep_note(kept: &mut BTreeMap<u64, usize>, out: &mut Vec<Note>, note: Note) {
    if let Some(&i) = kept.get(&note.desc_off) {
        if let Some(held) = out.get_mut(i) {
            held.desc_len = held.desc_len.max(note.desc_len);
            held.short_len = held.short_len.min(note.short_len);
        }
    } else {
        kept.insert(note.desc_off, out.len());
        out.push(note);
    }
}

/// The one `unread` record of the property notes [`Elf::gnu_properties`] did not walk because
/// their headers read the descriptor at two lengths: the first such note, and how many follow it.
fn record_disagreeing(disagreeing: Option<(&Note, u64)>, trunc: &mut Vec<Truncation>) {
    let Some((note, more)) = disagreeing else {
        return;
    };
    let others = match more {
        0 => String::new(),
        n => format!(", and {n} more property notes are"),
    };
    trunc.push(Truncation::unread(
        ElfTable::Notes,
        format!(
            "property note at {:#x}: headers read its descriptor as {:#x} and {:#x} bytes{others}",
            note.desc_off, note.short_len, note.desc_len
        ),
    ));
}

/// A table of the ELF container, as the reader and the checks name it.
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
    GnuStack,
    /// The section-header table itself, recorded when the file declares one that is not read:
    /// a header escape names a `shdr[0]` the file does not hold (`probe_shdr0`), `e_shoff` is 0
    /// with sections declared (`section_table_at_no_offset`), or the declared stride is above
    /// the record (`section_table_withheld`). Its effects are recorded against the tables it
    /// cuts off (`Elf::structural_truncations`), `symbols` and `section-names` among them,
    /// and a check whose predicate reads section headers declares it beside one of those.
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
    /// none, or by `SHT_NOTE` section in a relocatable object or a file with no program
    /// headers (`Elf::notes_from_sections`). On an unlinked
    /// aarch64 object it is also the `SHT_AARCH64_ATTRIBUTES` section the marking is read from
    /// where no property note carries it (`Elf::aarch64_attribute_word`), and the disagreement
    /// of the two where both do: the marking checks declare this table, so either withholds
    /// them.
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
    /// [`Self::SOFT_SITES`].
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

/// How a symbol table spells a version, which decides what a symbol's name is keyed on.
#[derive(Clone, Copy)]
enum Spelling {
    /// `.symtab`: the name before the first `@` is the key, and the whole spelling is kept in
    /// `versioned`.
    Versioned,
    /// `.dynsym`: the name is the key, whole.
    Whole,
}

impl Spelling {
    /// How a symbol table of `sh_type` spells a name: `SHT_SYMTAB` with its version, every
    /// other type (`SHT_DYNSYM`, the one other the reader reads) bare.
    fn of(sh_type: u32) -> Self {
        if sh_type == SHT_SYMTAB {
            Self::Versioned
        } else {
            Self::Whole
        }
    }
}

/// How the dynamic symbol table is reached, from the dynamic table and the program headers.
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
                format!("{name} appears {n} times in .dynamic"),
            ));
        }
    }
}

/// How the loader would treat a linked object, from `e_type`, `PT_INTERP`, `.dynamic`,
/// `DF_1_PIE` and `DT_DEBUG`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LinkKind {
    /// `PT_INTERP` names a loader. `pie` is whether the object is `ET_DYN`, which with an
    /// interpreter is a position-independent executable.
    Dynamic { pie: bool },
    /// `ET_DYN` with no interpreter, marked as executable output by `DF_1_PIE`, by
    /// `DT_DEBUG`, or by both; the payload says which, and `link_kind` builds the variant
    /// only when at least one holds. It still carries `.dynamic`, since it relocates
    /// itself, and is statically linked all the same.
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

/// `e_type` as the facts spell it. An unrecognised type says so, with the number, rather
/// than in a spelling that reads as a decoded name.
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
fn required<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

/// One GNU property type as seen across every property note in the object.
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
    /// `false` means the symbol is `SHN_UNDEF`, a reference satisfied at load time: a
    /// canary-protected binary *references* `__stack_chk_fail`, and one that statically
    /// links libssp *defines* it.
    pub defined: bool,
    /// Which tables it appeared in (`.symtab`, `.dynsym`); a stripped binary has
    /// only `.dynsym`, so an absent symbol there is weaker evidence.
    pub tables: Vec<String>,
    /// The spellings that carried a version, as `.symtab` stored them:
    /// `__stack_chk_fail@GLIBC_2.4`, or `name@@VERSION` for a default version. The map
    /// key is such a name before its first `@` (`Spelling`); this keeps what was cut. Empty
    /// for a symbol every table stored bare, and a `.dynsym` name, kept whole, adds none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versioned: Vec<String>,
}

/// Everything the `elf-static` channel extracts from one artifact. Serialized
/// verbatim into the report's `facts` store as an `elf` entry keyed by the artifact's
/// digest, whose contract is `$defs/elf_facts` in
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
    /// one constructor); `None` only in a record without the field, read back by
    /// `#[serde(default)]`. The target witness leaves such a record out of
    /// `toolchain.target.abi.artifacts`, and the execution witness withholds on it, since an
    /// order it cannot read it cannot hold to the kernel's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elf_data: Option<ByteOrder>,
    pub elf_type: String,
    pub machine: String,
    pub has_interp: bool,
    pub has_dynamic: bool,

    /// `ET_DYN` alone cannot distinguish a PIE from a shared library, so this is
    /// `ET_DYN` plus one of the linker-recorded `DF_1_PIE`, a `PT_INTERP`, or `DT_DEBUG`,
    /// the linker's mark of executable output that `LinkKind::StaticPie` explains.
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
    /// A `PT_LOAD` or `PT_TLS` segment carrying both `PF_W` and `PF_X`: for a `PT_LOAD`, a
    /// page the linked program maps writable and executable at once; a `PT_TLS` is the
    /// template each thread's block is copied from, read because GNU ld warns on its flags
    /// too (`segment-flags-are-the-mappings`). `None` where there is no
    /// linked object to be a fact about (`elf::LinkKind`), as the classification-linked
    /// fields above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rwx_segment: Option<bool>,

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
    /// reads enforcement from these words. The kernel-dependent checks read what the kernel
    /// did when the probe ran, and declare `needs_vm`.
    pub gnu_property_types: Vec<String>,
    /// How many `NT_GNU_PROPERTY_TYPE_0` notes carried each type in `gnu_property_types`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub gnu_property_notes: BTreeMap<String, u32>,
    pub x86_ibt: bool,
    pub x86_shstk: bool,
    pub aarch64_bti: bool,
    pub aarch64_pac: bool,
    /// The default is defensive rather than load-bearing: a live read always writes this
    /// field, so a report never carries a defaulted value. `#[serde(default)]` covers only a
    /// record without the field; on an aarch64 record a defaulted `false` would be an
    /// unmeasured claim that the binary lacks GCS.
    #[serde(default)]
    pub aarch64_gcs: bool,
    /// A `PT_OPENBSD_NOBTCFI` program header (`0x65a3dbe8`, as OpenBSD 7.9 installs it in
    /// `/usr/include/llvm/BinaryFormat/ELF.h`; the kernel's flag is `EXEC_NOBTCFI`): the
    /// program's own request that OpenBSD not enforce branch-target CFI on it, BTI on
    /// arm64 and IBT on amd64. lld writes it under `-z nobtcfi`, OpenBSD's base linker and
    /// lld 22.1.8 on Linux alike, for any target. A raw fact, `false` on an object with no
    /// program headers.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub openbsd_nobtcfi: bool,

    pub sections: Vec<String>,
    /// The allocated sections that are not code and whose bytes lie in a page an
    /// executable `PT_LOAD` maps, in section-header order: what `-z separate-code` keeps
    /// out of the code segment's pages, and what `-z noseparate-code` lets in. `None` where
    /// the question has no referent: no `PT_LOAD` carries `PF_X` (a relocatable object has
    /// no program headers at all), or no section header describes an allocated section, so
    /// nothing could be classified (a file whose section headers were removed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_in_code_pages: Option<Vec<String>>,
    /// The relocations a relocatable object asks the linker to apply to its code, each as
    /// `TYPE SYMBOL`: the type as `readelf -r` names it (`R_X86_64_REX_GOTPCRELX`), one
    /// space, and the symbol's name, or for a section symbol the section's name in
    /// brackets (`R_X86_64_PC32 [.data]`). A named symbol whose visibility is not
    /// `STV_DEFAULT` carries it as a third word (`R_386_PC32 __x86.get_pc_thunk.ax
    /// STV_HIDDEN`), since how the code reaches a symbol depends on it: under `-fPIC` a
    /// hidden global is reached directly, as under `-fPIE`, and `pic-object-relocs` reads a
    /// direct type as `-fPIC` absent only against a default-visibility anchor.
    /// Distinct entries, sorted. `None` for anything but an
    /// `ET_REL` with a section-header table: a linked object's static relocations were
    /// applied and dropped, and its dynamic ones are the loader's, not the compiler's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_relocations: Option<Vec<String>>,
    /// What each function of a relocatable object refers to, attributed from the object's
    /// own relocations. Each defined `STT_FUNC` symbol, in symbol-table order, is an item
    /// `name:`, followed by an item `name:target` for every distinct named symbol that a
    /// relocation at an offset inside the function's range refers to, the targets sorted.
    /// A `.symtab` name's version suffix is cut as `Elf::symbols` cuts it, and a
    /// relocation against an unnamed symbol (a section symbol) names nothing and is not
    /// listed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_references: Option<Vec<String>>,
    /// The symbol tables the file has, as `Elf::symbols` labels them: `.symtab` and
    /// `.dynsym` by name, or `SHT_SYMTAB` and `SHT_DYNSYM` where the section names could
    /// not be read. In header order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symbol_tables: Vec<String>,
    pub symbol_count: usize,
    pub watched_symbols: BTreeMap<String, SymbolFact>,

    /// Tables this parse could not read to their end, named.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub truncations: Vec<Truncation>,

    /// The run witnesses the file carries: the descriptor, in hex, of each note of
    /// [`RUN_WITNESS_SECTION`], or of a `PT_NOTE` segment where the file shows no such
    /// section, walked at [`RUN_WITNESS_ALIGN`], that is owned by
    /// [`RUN_WITNESS_OWNER`], typed [`RUN_WITNESS_TYPE`] and [`RUN_WITNESS_BYTES`] long,
    /// each distinct value once, in file order, at most [`RUN_WITNESSES_KEPT`] of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub run_witness: Vec<String>,
    /// Contents of `.chard.report`: the binary's own account of the macros in
    /// effect when it was compiled. Self-reported, hence cross-checked by the
    /// other channels.
    pub self_report: String,
    /// Contents of `.GCC.command.line` (`-frecord-gcc-switches`, clang's
    /// `-frecord-command-line`): the driver command line when the toolchain was asked to
    /// record it. gcc records the options `cc1` received, driver- and spec-injected ones
    /// included; clang records its driver's arguments, configuration-file options included.
    /// Neither records a default compiled into the compiler, so it complements rather than
    /// replaces the macro channel.
    pub recorded_command_line: String,
    /// The distinct lines of `.comment`, in file order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comment: Vec<String>,

    /// `<function>:<pattern>=<count>` for every pattern of this machine that a
    /// [`code::SCANS`] entry lists, searched in that entry's function where its bytes were
    /// read whole, zero counts included. A listed function the file does not define, or a
    /// machine with no pattern, contributes nothing, so a predicate tells "searched and not
    /// found" from "not searched" by this list; a function that is defined and could not be
    /// read is in `truncations` under `code`. The mechanism and why a byte search over one
    /// known function is sound are in the `code` module's documentation.
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub function_entries: Vec<String>,
}

impl ElfFacts {
    /// The first truncation that left one of `tables` unread, if any.
    #[must_use]
    pub fn unread(&self, tables: &[ElfTable]) -> Option<&Truncation> {
        self.truncations
            .iter()
            .find(|t| t.kind == TruncationKind::Unread && tables.contains(&t.table))
    }

    /// The reader's sentence for a `.comment` that was present, or could not be looked
    /// up, and was not read: the `detail` of the [`ElfTable::Comment`] entry.
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

/// The note section the run's generated header (`compile::RunWitness::header`) writes the
/// run's nonce into, and [`ElfFacts::run_witness`] reads it from. A `SHT_NOTE` section, so
/// that a link under `--gc-sections` keeps it: measured on Fedora 44 x86_64 with gcc 16.2.1
/// and clang 22.1.8 over GNU ld 2.46, `-O2 -ffunction-sections -fdata-sections
/// -Wl,--gc-sections` linked a program whose `.note.chard.run` held the note, and so did
/// the same link through mold 2.40.4 and through the distribution's lld (gcc 16.2.1).
pub const RUN_WITNESS_SECTION: &str = ".note.chard.run";

/// The owner of the run-witness note, as its name field spells it.
pub const RUN_WITNESS_OWNER: &str = "chard";

/// The type of the run-witness note. The owner namespaces it; `readelf -n` prints an
/// unknown owner's type 1 as `NT_VERSION`.
pub const RUN_WITNESS_TYPE: u32 = 1;

/// The alignment the run-witness note is written with, which is the alignment its table is
/// walked at, whatever alignment the section or segment that holds it declares. The
/// generated header pads the note to four bytes (`.balign 4`). A linker is free to put it
/// in a `PT_NOTE` segment of alignment 8 beside an 8-aligned property note, and walked at
/// the segment's alignment the note's descriptor is read four bytes late, as a value no
/// build wrote. Measured on Fedora 44 x86_64 with gcc 16.2.1 and mold 2.40.4, whose one
/// note segment, of alignment 8, holds `.note.gnu.property` (aligned to 8),
/// `.note.ABI-tag`, `.note.chard.run` and `.note.gnu.build-id` (each aligned to 4).
pub const RUN_WITNESS_ALIGN: u64 = 4;

/// The length of the run-witness note's descriptor: the nonce's 128 bits.
pub const RUN_WITNESS_BYTES: usize = 16;

/// The run-witness note, the one note [`Elf::parse_notes`] keeps for [`Elf::run_witness`].
/// Its `n_namesz` is not held: the witness walk keeps every note that reads as a witness, so a
/// look-alike with another name size is counted, and a foreign nonce in it refuses the file,
/// where a stop would end the walk of a segment and leave a note after it unseen.
const RUN_WITNESS_NOTE: NoteKind = NoteKind {
    owner: RUN_WITNESS_OWNER,
    ntype: RUN_WITNESS_TYPE,
    name_size_held: false,
};

/// How many distinct run witnesses [`ElfFacts::run_witness`] keeps. An artifact of one run
/// carries one, so a second is already the finding; the bound keeps a section of forged
/// notes from growing the facts with the file.
pub const RUN_WITNESSES_KEPT: usize = 4;

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
    /// The work this file's reading may still spend, [`work_budget`] of its length.
    budget: Budget,
    /// The notes the latest [`Self::facts`] kept, for [`Self::notes_kept`]; `None` before one.
    notes_kept: std::cell::Cell<Option<u64>>,
}

/// The header's identity and the two tables' entry counts. The file's bytes and the tables
/// themselves are left out: a crafted file can make them as large as the file.
impl std::fmt::Debug for Elf<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Elf")
            .field("elf64", &self.elf64)
            .field("little", &self.cur.little)
            .field("e_type", &self.e_type)
            .field("e_machine", &self.e_machine)
            .field("phdr_count", &self.phdrs.len())
            .field("shdr_count", &self.shdrs.len())
            .finish_non_exhaustive()
    }
}

impl<'a> Elf<'a> {
    /// Errors when `data` is not an ELF file, declares a class or endianness we do
    /// not recognize, or is truncated inside the header tables.
    ///
    /// # Errors
    ///
    /// Errors when `data` is not an ELF file, declares a class or endianness we do
    /// not recognize, or is truncated inside the header tables.
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfError> {
        Self::parse_within(data, work_budget(data.len()))
    }

    /// [`Self::parse`] with a work budget of `units` in place of [`work_budget`]'s, for the
    /// tests that hold a reading under every budget to the rule `Budget` states.
    ///
    /// # Errors
    ///
    /// As [`Self::parse`].
    pub fn parse_within(data: &'a [u8], units: u64) -> Result<Self, ElfError> {
        let budget = Budget::new(units);
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
        // reads overlapping records, and at zero every index names the same bytes: one
        // header can alias onto 65535 sections, a work count `MAX_OBJECT_BYTES` does not
        // bound.
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

        // The gABI's three escapes, all through `shdr[0]`, whose size, link and info fields
        // hold the counts and the index the 16-bit header fields cannot.
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

        let phdrs = read_phdrs(&cur, elf64, e_phoff, e_phnum)?;
        let (_, sh_record) = header_records(elf64);
        let walked = match section_table_at_no_offset(e_shoff, e_shnum)
            .or_else(|| section_table_withheld(e_shnum, e_shentsize, sh_record))
        {
            Some(withheld) => {
                header_truncations.push(withheld);
                0
            }
            None => e_shnum,
        };
        let mut shdrs = Vec::new();
        for i in 0..walked {
            let base = e_shoff
                .checked_add(
                    i.checked_mul(sh_record.get())
                        .ok_or_else(|| ElfError::malformed("shdr index overflow"))?,
                )
                .ok_or_else(|| ElfError::malformed("shdr offset overflow"))?;
            shdrs.push(read_shdr(&cur, elf64, base)?);
        }

        let shnames = section_names(&cur, &budget, &shdrs, shstrndx, &mut header_truncations);
        let mut seen = BTreeSet::new();
        let shared_names = shnames
            .iter()
            .filter(|n| !n.is_empty() && !seen.insert(n.as_str()))
            .cloned()
            .collect();
        budget.mark_parsed();

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
            budget,
            notes_kept: std::cell::Cell::new(None),
        })
    }

    /// The units of work spent so far, by the parse and the latest [`Self::facts`], of the
    /// budget the file was given.
    #[must_use]
    pub fn work_spent(&self) -> u64 {
        self.budget.spent()
    }

    /// The GNU property notes the latest [`Self::facts`] kept, each once by its descriptor's
    /// offset (`Self::notes`), however many headers name the bytes they lie in, so fewer than
    /// the file has bytes; `None` before a reading.
    #[must_use]
    pub fn notes_kept(&self) -> Option<u64> {
        self.notes_kept.get()
    }

    /// The name at `off` in the string table of `table_len` bytes at `base`, charged to the
    /// file's budget; [`Cursor::cstr_at`] says how it is bounded.
    fn name_at(&self, base: u64, off: u32, table_len: u64) -> Result<String, NameFault> {
        name_in(&self.cur, &self.budget, (base, off, table_len))
    }

    /// One unit of the file's budget, for one entry of a walk.
    fn step(&self) -> Result<(), Spent> {
        self.budget.spend(1)
    }

    /// [`Self::step`], recording `table` `unread` at the place `at` names where the budget is
    /// spent; `true` then, and the walk stops.
    fn out_of_budget(
        &self,
        table: ElfTable,
        trunc: &mut Vec<Truncation>,
        at: impl FnOnce() -> String,
    ) -> bool {
        self.out_of_budget_for(1, table, trunc, at)
    }

    /// [`Self::out_of_budget`] for `units` at once, the bytes of a copy the facts keep.
    fn out_of_budget_for(
        &self,
        units: usize,
        table: ElfTable,
        trunc: &mut Vec<Truncation>,
        at: impl FnOnce() -> String,
    ) -> bool {
        let units = u64::try_from(units).unwrap_or(u64::MAX);
        let Err(spent) = self.budget.spend(units) else {
            return false;
        };
        trunc.push(Truncation::unread(table, format!("{}: {spent}", at())));
        true
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
    fn offset_of_vaddr(&self, vaddr: u64) -> Option<u64> {
        self.phdrs
            .iter()
            .filter(|p| p.p_type == PT_LOAD)
            .find(|p| vaddr >= p.p_vaddr && vaddr < p.p_vaddr.saturating_add(p.p_memsz))
            .map(|p| p.p_offset.saturating_add(vaddr.saturating_sub(p.p_vaddr)))
    }

    /// Bytes from `vaddr` to the end of the containing `PT_LOAD` segment's file image: the
    /// bound for a table reached by address whose own size tag (`DT_STRSZ`) is absent,
    /// narrower than the whole file.
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
                        "{name}: {:#x}+{:#x} could not be read ({why:#})",
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
                format!("{name}: could not be looked up ({why})"),
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
                        "{name}: {:#x}+{:#x} could not be read ({why:#})",
                        sh.sh_offset, sh.sh_size
                    ),
                ));
                return Vec::new();
            }
        };
        // A repeat is found in a set, not by a scan of the lines kept, which is quadratic
        // in the lines: a section of `N` one-byte lines would scan `N x N / 2`.
        let text = String::from_utf8_lossy(bytes);
        let mut seen = BTreeSet::new();
        let mut lines: Vec<String> = Vec::new();
        for raw in text.split('\0') {
            let line = raw.trim();
            if !line.is_empty() && seen.insert(line) {
                lines.push(line.to_owned());
            }
        }
        lines
    }

    /// Whether this file's dynamic section, if it has one, was out of reach: no `PT_DYNAMIC`,
    /// which leaves [`Self::dynamic`] the `SHT_DYNAMIC` sections, and either no program headers
    /// or a section-header table the file declares and `parse` did not read (its
    /// `section-headers` cause is recorded). A stripped program with program headers and no
    /// `PT_DYNAMIC` has no dynamic section the loader reads, so its reading stands.
    fn dynamic_unreached(&self) -> bool {
        let segment = self.phdrs.iter().any(|p| p.p_type == PT_DYNAMIC);
        let declared_unread = self
            .header_truncations
            .iter()
            .any(|t| t.table == ElfTable::SectionHeaders);
        self.shdrs.is_empty() && !segment && (self.phdrs.is_empty() || declared_unread)
    }

    /// Truncations that are properties of the file's shape rather than of a read that failed.
    fn structural_truncations(&self) -> Vec<Truncation> {
        let mut out = Vec::new();
        if self.shdrs.is_empty() {
            let dynamic_unreached = self.dynamic_unreached();
            let mut symbols =
                "no section-header table: the symbol tables are unreachable.".to_owned();
            if !dynamic_unreached {
                symbols.push_str(" The dynamic segment was read instead");
            }
            out.push(Truncation::unread(ElfTable::Symbols, symbols));
            out.push(Truncation::unread(
                ElfTable::SectionNames,
                "no section-header table: nothing reached by section name was read".to_owned(),
            ));
            if self.notes_from_sections() {
                out.push(Truncation::unread(
                    ElfTable::Notes,
                    "no section-header table, in a relocatable object or a file with no program headers"
                        .to_owned(),
                ));
            }
            if dynamic_unreached {
                out.push(Truncation::unread(
                    ElfTable::Dynamic,
                    "no section-header table read and no PT_DYNAMIC segment".to_owned(),
                ));
            }
        }
        out.extend(self.header_truncations.iter().cloned());
        out
    }

    /// `(tag, value)` pairs from `.dynamic`. Empty for a static non-PIE binary.
    fn dynamic(&self, trunc: &mut Vec<Truncation>) -> Vec<(i64, u64)> {
        let mut out = Vec::new();
        // `(offset, size)` of every `.dynamic` to walk: the `PT_DYNAMIC` segment, and the
        // `SHT_DYNAMIC` sections only in a file with none.
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
            // No loader reads an object with no `PT_DYNAMIC`, so the segments' rule is
            // borrowed: the last table is read, and the others are a disagreement this file
            // does not settle.
            if sections.len() > 1 {
                trunc.push(Truncation::unread(
                    ElfTable::Dynamic,
                    format!(
                        "{} SHT_DYNAMIC sections and no PT_DYNAMIC segment",
                        sections.len()
                    ),
                ));
            }
            sections.iter().copied().next_back().into_iter().collect()
        } else {
            // A section view the loader would not reach is dropped and recorded, since a
            // silent drop reads as agreement.
            let held = Spans::new(
                segments
                    .iter()
                    .map(|&(p_off, p_size)| (p_off, p_off.saturating_add(p_size)))
                    .collect(),
            );
            for (off, size) in &sections {
                let end = off.saturating_add(*size);
                let contained = held.contains(*off, end);
                if !contained {
                    // `Ignored`: the facts are whole, read from the segment.
                    trunc.push(Truncation::ignored(
                        ElfTable::Dynamic,
                        format!(
                            "SHT_DYNAMIC section at {off:#x}+{size:#x} lies outside every PT_DYNAMIC segment and was not read"
                        ),
                    ));
                }
            }
            // **The last `PT_DYNAMIC` is the one the loader reads.** Measured 2026-10-09 on
            // Fedora 44 x86_64 (glibc 2.43 `ld.so`, musl `ld-musl-x86_64.so.1`): a PIE patched
            // to carry two `PT_DYNAMIC` headers ran the `DT_INIT` of the later table under
            // both, in both header orders.
            if segments.len() > 1 {
                trunc.push(Truncation::unread(
                    ElfTable::Dynamic,
                    format!(
                        "{} PT_DYNAMIC segments; glibc and musl read the last and that is the one measured",
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
            if let Err(spent) = self.step() {
                trunc.push(Truncation::unread(
                    ElfTable::Dynamic,
                    format!(".dynamic not read past entry {i} of {count}: {spent}"),
                ));
                return;
            }
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
                ".dynamic at {sh_offset:#x}+{sh_size:#x} reached the end of the declared table at entry {count} of {count} without DT_NULL"
            ),
        ));
    }

    /// Where the dynamic string table is, as `(offset, length)`, or `None` where the file
    /// has none to read.
    fn dyn_strtab(
        &self,
        dyn_entries: &[(i64, u64)],
        trunc: &mut Vec<Truncation>,
    ) -> Option<(u64, u64)> {
        // The order is the one `dynamic` takes.
        let strtab_vaddr = dyn_entries
            .iter()
            .rfind(|(t, _)| *t == DT_STRTAB)
            .map(|(_, v)| *v);
        let from_segment = strtab_vaddr.and_then(|v| self.offset_of_vaddr(v));
        let located = match from_segment {
            Some(off) => {
                // `DT_STRSZ` is the table's declared length; without it the containing
                // segment's remaining bytes bound the table, not the whole file.
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
                            "DT_STRTAB at {off:#x} has neither DT_STRSZ nor a containing PT_LOAD segment to bound it"
                        ),
                    ));
                    None
                }
            }
            None => self.dyn_strtab_by_name(dyn_entries, strtab_vaddr, trunc),
        };
        // Held whole before a string is read from it: `cstr_at` answers "" for an offset
        // past the end of the file, and `needed` read as `[""]` would publish `as-needed` `on`.
        let (off, len) = located?;
        if let Err(why) = self.cur.slice(off, len) {
            trunc.push(Truncation::unread(
                ElfTable::DynStr,
                format!(
                    "the dynamic string table at {off:#x}+{len:#x} lies past the end of the file ({why})"
                ),
            ));
            return None;
        }
        Some((off, len))
    }

    /// `.dynstr` by name, for a dynamic table whose `DT_STRTAB` lies in no `PT_LOAD` or
    /// that carries no `DT_STRTAB` at all, or `None` beside a `dynstr` record where the
    /// section cannot be found and an entry names a string through it.
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
                "DT_STRTAB at vaddr {vaddr:#x} lies in no PT_LOAD segment and no .dynstr section could be found by name"
            ),
            None if !named.is_empty() => {
                format!(".dynamic carries {} but no DT_STRTAB", named.join(", "))
            }
            None => return None,
        };
        trunc.push(Truncation::unread(ElfTable::DynStr, detail));
        None
    }

    /// The strings every `tag` entry names in the table [`Self::dyn_strtab`] located.
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
                    match self.name_at(strtab_off, off, strtab_len) {
                        Ok(name) => out.push(name),
                        Err(fault) => {
                            trunc.push(Truncation::unread(
                                ElfTable::DynStr,
                                format!(
                                    "{} string at offset {value:#x} of the dynamic string \
                                     table was not read, and neither were the entries after \
                                     it: {fault}",
                                    dyn_tag_name(tag)
                                ),
                            ));
                            break;
                        }
                    }
                }
                _ => trunc.push(Truncation::unread(
                    ElfTable::DynStr,
                    format!(
                        "{} string at offset {value:#x} lies past the {strtab_len:#x}-byte dynamic string table",
                        dyn_tag_name(tag)
                    ),
                )),
            }
        }
        out
    }

    /// The string table `sh_link` names for a symbol table, held whole, or `None` beside
    /// a `symbols` record of why its names cannot be resolved.
    fn symbol_strtab(&self, sh: &Shdr, table: &str, trunc: &mut Vec<Truncation>) -> Option<&Shdr> {
        let link = self
            .shdrs
            .get(usize::try_from(sh.sh_link).unwrap_or(usize::MAX));
        let detail = match link {
            Some(link) if sh.sh_link != 0 && link.sh_type == SHT_STRTAB => {
                match self.cur.slice(link.sh_offset, link.sh_size) {
                    Ok(_) => return Some(link),
                    Err(why) => format!(
                        "{table}: its string table at {:#x}+{:#x} lies past the end of the file ({why})",
                        link.sh_offset, link.sh_size
                    ),
                }
            }
            Some(_) => format!(
                "{table}: sh_link {} does not name a string table",
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
            Some(name) => label_of(name, idx),
            None if sh.sh_type == SHT_SYMTAB => "SHT_SYMTAB".to_owned(),
            None => "SHT_DYNSYM".to_owned(),
        }
    }

    /// A relocation section's label: its name where the file gave one, and its index where
    /// it did not.
    fn relocation_label(&self, idx: usize) -> String {
        self.shnames.get(idx).filter(|n| !n.is_empty()).map_or_else(
            || format!("relocation section [{idx}]"),
            |name| label_of(name, idx),
        )
    }

    /// The stride section `idx` is read at: `record`, its type's record size, with the
    /// `ignored` record [`record_stride`] leaves pushed where `sh_entsize` differs, and kept
    /// once among the walks by [`once_each_stride_record`] when the facts are assembled.
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
        // records, so the index is added there.
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
    fn symbol_entries(
        &self,
        idx: usize,
        sh: &Shdr,
        table: &str,
        trunc: &mut Vec<Truncation>,
    ) -> Option<(u64, u64)> {
        // The record size, whatever `sh_entsize` says (`section_stride`): a smaller stride
        // would read a symbol per byte, each a name scan that can run to the end of the
        // file, which is quadratic in the input.
        let step = self.section_stride(idx, sh, symbol_record(self.elf64), trunc);
        // A `NonZeroU64` divisor: no zero entry size reaches here, so no arm reads one.
        let (count, partial) = (sh.sh_size / step, sh.sh_size % step);
        if sh.sh_size > 0 && count == 0 {
            trunc.push(Truncation::unread(
                ElfTable::Symbols,
                format!(
                    "{table}: sh_size {:#x} is below one {step}-byte entry",
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
    fn symbols(
        &self,
        dyn_entries: &[(i64, u64)],
        dynstr: Option<(u64, u64)>,
        trunc: &mut Vec<Truncation>,
    ) -> (Vec<String>, BTreeMap<String, SymbolFact>) {
        let mut tables = Vec::new();
        let mut out = SymbolsRead::default();
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
                            format!("{table} was not read: the dynamic table names no DT_SYMTAB"),
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
                                    "{table} at {:#x} is not the table DT_SYMTAB names ({offset:#x})",
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
                // tables reach.
                trunc.push(Truncation::ignored(
                    ElfTable::Symbols,
                    format!(
                        "{table}: sh_size {:#x} holds {count} symbols and the dynamic hash and relocation tables reach {floor}",
                        sh.sh_size
                    ),
                ));
                count = floor;
            }
            // Names come through the header's link while it names the string table
            // `DT_STRTAB` does; where it names another, the loader's is read and the
            // disagreement reported.
            let linked = self.linked_strtab_offset(sh);
            let strtab = match loader_strtab {
                Some(loader) if linked != Some(loader.0) => {
                    trunc.push(Truncation::ignored(
                        ElfTable::Symbols,
                        format!(
                            "{table}: sh_link {} is not the string table DT_STRTAB names ({:#x})",
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
            self.read_symbols(&table, sh, step, count, strtab, &mut out, trunc);
        }
        if let DynSymView::At { offset, .. } = &view
            && !loader_table_read
        {
            // No header of the type is the loader's table: those there are aimed elsewhere,
            // or there are none (a `.dynsym` header retyped away).
            trunc.push(Truncation::unread(
                ElfTable::Symbols,
                format!("no SHT_DYNSYM header lies at the {offset:#x} DT_SYMTAB names"),
            ));
        }
        (tables, out.facts)
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
    fn dynsym_view(
        &self,
        dyn_entries: &[(i64, u64)],
        dynstr: Option<(u64, u64)>,
        trunc: &mut Vec<Truncation>,
    ) -> DynSymView {
        // A file with no section headers has its symbol tables recorded `unread` by
        // `structural_truncations`, and with no `PT_DYNAMIC` no loader reads the object.
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
            // and the loader's table is then unlocatable rather than absent.
            let cut = trunc
                .iter()
                .any(|t| t.table == ElfTable::Dynamic && t.kind == TruncationKind::Unread);
            if cut || dyn_entries.is_empty() {
                // With headers of the type, they are the reading and the comparison that
                // could not be made is reported.
                trunc.push(if headers {
                    Truncation::ignored(
                        ElfTable::Symbols,
                        "the dynamic table was not read whole".to_owned(),
                    )
                } else {
                    Truncation::unread(
                        ElfTable::Symbols,
                        "the dynamic table was not read whole and no section header is SHT_DYNSYM"
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
                "DT_SYMTAB at vaddr {symtab:#x} lies in no PT_LOAD segment"
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
        let charge = || {
            self.step()
                .map_err(|spent| format!("was not read whole: {spent}"))
        };
        let mut last = 0;
        for i in 0..nbuckets {
            charge()?;
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
            charge()?;
            let at = chains.saturating_add(idx.saturating_sub(symoffset).saturating_mul(4));
            if word(at)? & 1 != 0 {
                return Ok(idx.saturating_add(1));
            }
            idx = idx.saturating_add(1);
        }
    }

    /// The symbol count the dynamic relocation tables reach: one past the highest `r_sym`
    /// that `DT_RELA`, `DT_REL` or `DT_JMPREL` names, or 0 where none names a symbol.
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
                return Err("DT_JMPREL has no DT_PLTREL naming DT_RELA or DT_REL".to_owned());
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
                self.step()
                    .map_err(|spent| format!("{name} was not read whole: {spent}"))?;
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

    /// `count` symbols of `step` bytes from the table `sh` heads, named through the string
    /// table at `(strtab_off, strtab_len)` and spelled as its type spells a name
    /// ([`Spelling::of`]), folded into `out`.
    #[expect(
        clippy::too_many_arguments,
        reason = "a symbol read takes the table's label, header, entry size and count"
    )]
    fn read_symbols(
        &self,
        table: &str,
        sh: &Shdr,
        step: u64,
        count: u64,
        (strtab_off, strtab_len): (u64, u64),
        SymbolsRead {
            facts: out,
            spellings,
        }: &mut SymbolsRead,
        trunc: &mut Vec<Truncation>,
    ) {
        let (sym_off, names) = (sh.sh_offset, Spelling::of(sh.sh_type));
        for i in 0..count {
            if let Err(spent) = self.step() {
                trunc.push(Truncation::unread(
                    ElfTable::Symbols,
                    format!("{table} not read past symbol {i} of {count}: {spent}"),
                ));
                break;
            }
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
                        "{table}: symbol {i} of {count} names string offset {name_off:#x} past its {strtab_len:#x}-byte string table",
                    ),
                ));
                break;
            }
            let raw = match self.name_at(strtab_off, name_off, strtab_len) {
                Ok(raw) => raw,
                Err(fault) => {
                    trunc.push(Truncation::unread(
                        ElfTable::Symbols,
                        format!(
                            "{table}: the name of symbol {i} of {count}, at string offset \
                             {name_off:#x}, was not read, and neither were the symbols after \
                             it: {fault}"
                        ),
                    ));
                    break;
                }
            };
            // The two string tables spell one symbol two ways ([`Spelling`]).
            let (name, versioned) = match (names, raw.split_once('@')) {
                (Spelling::Versioned, Some((bare, _))) => (bare.to_owned(), Some(raw)),
                _ => (raw, None),
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
            // The scan of the name's tables is charged too, by the bytes it can compare: `N`
            // headers aliasing one table under `N` long names would make each of its symbols
            // compare a list of `N` labels.
            let listed = u64::try_from(entry.tables.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(
                    u64::try_from(table.len())
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                );
            if let Err(spent) = self.budget.spend(listed) {
                trunc.push(Truncation::unread(
                    ElfTable::Symbols,
                    format!("{table} not read past symbol {i} of {count}: {spent}"),
                ));
                break;
            }
            if !entry.tables.iter().any(|t| t == table) {
                // Each symbol keeps its own copy of the table's label, so the copy is charged:
                // one table under a long name holding many symbols would otherwise keep the
                // name once per symbol.
                let label = u64::try_from(table.len()).unwrap_or(u64::MAX);
                if let Err(spent) = self.budget.spend(label) {
                    trunc.push(Truncation::unread(
                        ElfTable::Symbols,
                        format!("{table} not read past symbol {i} of {count}: {spent}"),
                    ));
                    break;
                }
                entry.tables.push(table.to_owned());
            }
            if let Some(spelling) = versioned
                && spellings.insert(spelling.clone())
            {
                entry.versioned.push(spelling);
            }
        }
    }

    /// Whether this file's marking is read from its sections rather than its segments: a
    /// relocatable object, whatever program headers it carries, and a file with no program
    /// headers at all. No loader of a program loads a relocatable object: the linker reads its
    /// sections, as Linux's module loader does a kernel module's. Its notes ([`Self::notes`])
    /// and an aarch64 relocatable object's build attributes
    /// ([`Self::aarch64_attribute_word`]) are read from its sections.
    /// [`Self::structural_truncations`] records `notes` unread for such a file where no
    /// section header was read, so the two cannot disagree on which files they mean.
    fn notes_from_sections(&self) -> bool {
        self.e_type == ET_REL || self.phdrs.is_empty()
    }

    /// The GNU notes, read through the headers the loader reads: the `PT_GNU_PROPERTY`
    /// segment, `PT_NOTE` where there is none, and `SHT_NOTE` sections only in a file
    /// [`Self::notes_from_sections`] names. It assumes one property note per object and
    /// note segments aligned to four or eight bytes.
    fn notes(&self, trunc: &mut Vec<Truncation>) -> Vec<Note> {
        let mut out: Vec<Note> = Vec::new();
        // Each kept note's place in `out` by its descriptor's offset, a lookup and not a
        // quadratic scan: a `PT_NOTE` of empty property notes holds one every 16 bytes, 33
        // million of them at `MAX_OBJECT_BYTES`.
        let mut kept: BTreeMap<u64, usize> = BTreeMap::new();
        let segments = Spans::new(
            self.phdrs
                .iter()
                .filter(|p| p.p_type == PT_NOTE || p.p_type == PT_GNU_PROPERTY)
                .map(|p| (p.p_offset, p.p_offset.saturating_add(p.p_filesz)))
                .collect(),
        );
        if self.notes_from_sections() {
            for sh in self.shdrs.iter().filter(|s| s.sh_type == SHT_NOTE) {
                let align = note_alignment(sh.sh_addralign);
                for note in
                    self.parse_notes(sh.sh_offset, sh.sh_size, align, GNU_PROPERTY_NOTE, trunc)
                {
                    keep_note(&mut kept, &mut out, note);
                }
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
            for note in self.parse_notes(p.p_offset, p.p_filesz, align, GNU_PROPERTY_NOTE, trunc) {
                keep_note(&mut kept, &mut out, note);
            }
        }
        if property_segment {
            let before = self.budget.exhausted();
            // Each property note outside the property segments is recorded once, by its
            // descriptor's offset, in the record of the first `PT_NOTE` that holds it, so
            // headers that all name one region are one record.
            let mut ignored = BTreeSet::new();
            for p in self.phdrs.iter().filter(|p| p.p_type == PT_NOTE) {
                let align = note_alignment(p.p_align);
                let mut first = None;
                let mut more: u64 = 0;
                for note in self.parse_notes(
                    p.p_offset,
                    p.p_filesz,
                    align,
                    GNU_PROPERTY_NOTE,
                    &mut Vec::new(),
                ) {
                    if !kept.contains_key(&note.desc_off) && ignored.insert(note.desc_off) {
                        if first.is_none() {
                            first = Some((note.desc_off, note.desc_len));
                        } else {
                            more = more.saturating_add(1);
                        }
                    }
                }
                if let Some((desc_off, desc_len)) = first {
                    let (others, lie, was) = match more {
                        0 => (String::new(), "lies", "was"),
                        n => (format!(" and {n} more after it"), "lie", "were"),
                    };
                    trunc.push(Truncation::ignored(
                        ElfTable::Notes,
                        format!(
                            "property note at {desc_off:#x}+{desc_len:#x}{others} {lie} in a PT_NOTE outside every PT_GNU_PROPERTY segment and {was} not read"
                        ),
                    ));
                }
            }
            // A stop in this walk is not recorded, but a spent budget is: the walk is
            // where the budget ran out, and every later walk is cut by it.
            if let (None, Some(spent)) = (before, self.budget.exhausted()) {
                trunc.push(Truncation::unread(
                    ElfTable::Notes,
                    format!(
                        "the PT_NOTE segments beside PT_GNU_PROPERTY were not all read: {spent}"
                    ),
                ));
            }
        }
        // Only an allocated note section claims to be loaded, so only one outside the note
        // segments disagrees with the loader.
        for sh in self
            .shdrs
            .iter()
            .filter(|s| s.sh_type == SHT_NOTE && s.sh_size > 0 && s.sh_flags & SHF_ALLOC != 0)
        {
            let (off, size) = (sh.sh_offset, sh.sh_size);
            let end = off.saturating_add(size);
            if !segments.contains(off, end) {
                // `Ignored`: the facts are whole, read from the segments.
                trunc.push(Truncation::ignored(
                    ElfTable::Notes,
                    format!(
                        "SHT_NOTE section at {off:#x}+{size:#x} lies outside every PT_NOTE and PT_GNU_PROPERTY segment and was not read"
                    ),
                ));
            }
        }
        out
    }

    /// The run witnesses of [`RUN_WITNESS_SECTION`] ([`ElfFacts::run_witness`]).
    fn run_witness(&self, trunc: &mut Vec<Truncation>) -> Vec<String> {
        let before = self.budget.exhausted();
        let found = self.run_witnesses();
        if let (None, Some(spent)) = (before, self.budget.exhausted()) {
            trunc.push(Truncation::unread(
                ElfTable::Notes,
                format!("the run-witness notes were not all read: {spent}"),
            ));
        }
        found
    }

    /// [`Self::run_witness`]'s walk.
    fn run_witnesses(&self) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        let sections: Vec<(u64, u64)> = self
            .shnames
            .iter()
            .zip(&self.shdrs)
            .filter(|(name, sh)| *name == RUN_WITNESS_SECTION && sh.sh_type == SHT_NOTE)
            .map(|(_, sh)| (sh.sh_offset, sh.sh_size))
            .collect();
        // The segments, the other view of the same bytes, are read only where the file shows
        // no `SHT_NOTE` section of the witness's name: beside the sections they add nothing a
        // link of the run's objects wrote, so a witness note in a segment outside every such
        // section is not seen, as `run-witness-is-written-by-this-runs-compile` says.
        let named = !sections.is_empty();
        let tables = if named {
            sections
        } else {
            self.phdrs
                .iter()
                .filter(|p| p.p_type == PT_NOTE)
                .map(|p| (p.p_offset, p.p_filesz))
                .collect()
        };
        for (offset, size) in tables {
            let mut stops = Vec::new();
            let notes = self.parse_notes(
                offset,
                size,
                RUN_WITNESS_ALIGN,
                RUN_WITNESS_NOTE,
                &mut stops,
            );
            // A section of the witness's own name that could not be followed to its end is
            // no witness at all: a note past the stop is unseen, and a list that held this
            // run's nonce alone would confirm a file that also carries another's.
            if named && !stops.is_empty() {
                return Vec::new();
            }
            for note in notes {
                if usize::try_from(note.desc_len) != Ok(RUN_WITNESS_BYTES) {
                    continue;
                }
                let Ok(desc) = self.cur.slice(note.desc_off, note.desc_len) else {
                    continue;
                };
                let hex = hex_of(desc);
                if !found.contains(&hex) {
                    if found.len() == RUN_WITNESSES_KEPT {
                        return found;
                    }
                    found.push(hex);
                }
            }
        }
        found
    }

    /// Do the bytes at `at` spell `owner` and a NUL, inside the note table that ends at `end`?
    /// Read from the file whatever `n_namesz` declares, so a note declaring a name shorter than
    /// its owner's over the owner's bytes is told from a note of another name.
    fn spells_owner(&self, at: u64, end: u64, owner: &str) -> bool {
        let named = u64::try_from(owner.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        at.saturating_add(named) <= end
            && self
                .cur
                .slice(at, named)
                .is_ok_and(|bytes| bytes.split_last() == Some((&0, owner.as_bytes())))
    }

    /// The notes of one owner and type in one table, every note of it walked and charged,
    /// stopping at the first the file does not hold whole: the GNU property notes for
    /// [`Self::notes`], the run witness for [`Self::run_witness`].
    fn parse_notes(
        &self,
        base: u64,
        len: u64,
        align: u64,
        kind: NoteKind,
        trunc: &mut Vec<Truncation>,
    ) -> Vec<Note> {
        let NoteKind {
            owner,
            ntype: kept,
            name_size_held,
        } = kind;
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
            if let Err(spent) = self.step() {
                stop(pos, &spent.to_string());
                break;
            }
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
                match self.name_at(pos.saturating_add(12), 0, u64::from(namesz)) {
                    Ok(name) => name,
                    Err(fault) => {
                        stop(pos, &fault.to_string());
                        break;
                    }
                }
            };
            let span = match note_span(pos, namesz, descsz, align, end, file_end) {
                Ok(span) => span,
                Err(NoteRefusal::Overflows) => {
                    stop(pos, "a note's name length overflows the descriptor offset");
                    break;
                }
                Err(NoteRefusal::PastTheEnd) => {
                    stop(
                        pos,
                        "a note's descriptor runs past the end of the table or the file",
                    );
                    break;
                }
            };
            let (desc_off, desc_len) = (span.desc_off, u64::from(descsz));
            // Every note is walked and charged; only those of the owner and type asked for are
            // kept.
            if ntype == kept {
                let named = owner.len().saturating_add(1);
                if name_size_held
                    && usize::try_from(namesz) != Ok(named)
                    && (name == owner || self.spells_owner(pos.saturating_add(12), end, owner))
                {
                    stop(
                        pos,
                        &format!(
                            "a note named {owner} declares n_namesz {namesz}, not the \
                             {named} bytes of its name and NUL"
                        ),
                    );
                    break;
                }
                if name == owner {
                    out.push(Note::read(desc_off, desc_len));
                }
            }
            let Some(next) = span.next else {
                stop(pos, "a note's descriptor length overflows the next offset");
                break;
            };
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
    fn gnu_properties(&self, trunc: &mut Vec<Truncation>) -> BTreeMap<u32, Property> {
        let mut props: BTreeMap<u32, Property> = BTreeMap::new();
        let align: u64 = if self.elf64 { 8 } else { 4 };
        let notes = self.notes(trunc);
        self.notes_kept
            .set(Some(u64::try_from(notes.len()).unwrap_or(u64::MAX)));
        // A descriptor two headers read at two lengths is not walked, and the notes so read are
        // recorded once, by the first and how many follow: which length the loader takes
        // depends on which header it reads (`one-property-note-per-object` says which Linux
        // reads), so neither length's walk is the measurement.
        let mut disagreeing: Option<(&Note, u64)> = None;
        'notes: for note in &notes {
            if note.short_len != note.desc_len {
                match &mut disagreeing {
                    Some((_, more)) => *more = more.saturating_add(1),
                    None => disagreeing = Some((note, 0)),
                }
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
            while pos < end {
                if let Err(spent) = self.step() {
                    // A spent budget stays spent, so every note after this one would meet it on
                    // its first step: one record says the property notes were not all read.
                    stop(pos, &spent.to_string());
                    break 'notes;
                }
                // Each property lies whole in its descriptor, its data padded to the class's
                // alignment, as Linux 7.3-rc1's `parse_elf_property` (`fs/binfmt_elf.c`) holds
                // it: fewer than 8 bytes left, a `pr_datasz` past what is left, and a padded
                // step past it each return `ENOEXEC` there, and binutils `readelf` prints such a
                // property corrupt.
                let left = end.saturating_sub(pos);
                if left < 8 {
                    stop(
                        pos,
                        &format!(
                            "the descriptor's last {left} bytes hold no whole property header"
                        ),
                    );
                    break;
                }
                let (Ok(pr_type), Ok(pr_datasz)) =
                    (self.cur.u32_at(pos), self.cur.u32_at(pos.saturating_add(4)))
                else {
                    stop(pos, "a property header lies past the end of the file");
                    break;
                };
                let PropertySpan { data_off, next } =
                    match property_span(pos, pr_datasz, align, end) {
                        Ok(span) => span,
                        Err(PropertyRefusal::Overflows) => {
                            stop(pos, "a property's data length overflows the next offset");
                            break;
                        }
                        Err(PropertyRefusal::PastTheEnd { pad }) => {
                            stop(
                                pos,
                                &format!(
                                    "a property's {pr_datasz}-byte data, padded to {pad}, runs \
                                     past the descriptor"
                                ),
                            );
                            break;
                        }
                    };
                let feature_word = self.feature_word_type(pr_type);
                // A feature word is a 4-byte bitmap and is decoded only at that width;
                // one of any other width is recorded as present with value 0 rather
                // than guessed.
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
                if next <= pos {
                    stop(pos, "a property advances the walk nowhere");
                    break;
                }
                pos = next;
            }
        }
        record_disagreeing(disagreeing, trunc);
        props
    }

    /// Is `pr_type` a feature word this reader decodes on this object's machine?
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

    /// The aarch64 feature word an unlinked object states in its build attributes: the
    /// `aeabi_feature_and_bits` subsection of each `SHT_AARCH64_ATTRIBUTES` section, as
    /// [`AARCH64_FEATURE_1_BTI`], [`AARCH64_FEATURE_1_PAC`] and [`AARCH64_FEATURE_1_GCS`] bits,
    /// the words of several subsections combined by AND, as the linker combines inputs.
    /// `None` on any machine but aarch64, on any type but `ET_REL`, and where no section
    /// carries the subsection.
    fn aarch64_attribute_word(&self, trunc: &mut Vec<Truncation>) -> Option<u32> {
        if self.e_machine != EM_AARCH64 || self.e_type != ET_REL {
            return None;
        }
        let mut word: Option<u32> = None;
        for sh in self
            .shdrs
            .iter()
            .filter(|s| s.sh_type == SHT_AARCH64_ATTRIBUTES)
        {
            let at = sh.sh_offset;
            let mut stop = |why: String| {
                trunc.push(Truncation::unread(
                    ElfTable::Notes,
                    format!("build attributes at {at:#x}+{:#x}: {why}", sh.sh_size),
                ));
            };
            let bytes = match self.section_bytes(sh) {
                Ok(b) => b,
                Err(e) => {
                    stop(format!("{e}"));
                    continue;
                }
            };
            // An empty attributes section holds no format version: it is no statement of the
            // marking, and reading it as one that marks nothing would be a guess.
            if bytes.is_empty() {
                stop("the section holds no bytes".to_owned());
                continue;
            }
            // Charged by the byte, since `feature_and_bits` walks the section whole, and
            // headers aliasing one section would walk it once each.
            let units = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            if let Err(spent) = self.budget.spend(units) {
                stop(spent.to_string());
                break;
            }
            match feature_and_bits(bytes, self.cur.little) {
                Ok(None) => {}
                Ok(Some(found)) => word = Some(word.map_or(found, |w| w & found)),
                Err(why) => stop(why),
            }
        }
        word
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
        // Sorted once and searched per section, and the names kept found by a set: a scan of
        // the pages and of the names found per section is quadratic in the headers.
        let pages = Spans::new(pages);
        let mut seen = BTreeSet::new();
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
            if pages.overlaps(sh.sh_offset, end) {
                // A section whose name could not be read is named by its index, so the
                // reading still says which header it was.
                let named = if name.is_empty() {
                    format!("[{i}]")
                } else {
                    name.to_owned()
                };
                if seen.insert(named.clone()) {
                    found.push(named);
                }
            }
        }
        Some(found)
    }

    /// [`ElfFacts::code_relocations`]: every named relocation in a section that patches
    /// code, on a relocatable object with a section-header table.
    fn code_relocations(&self, trunc: &mut Vec<Truncation>) -> Option<Vec<String>> {
        if self.e_type != ET_REL || self.shdrs.is_empty() {
            return None;
        }
        let mut found = BTreeSet::new();
        let mut read = RelocationsRead::default();
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
                        "{label}: sh_info {} is past the section-header table",
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
                    self.code_relocation_entries(
                        sh,
                        step,
                        &tables,
                        &mut stop,
                        (&mut found, &mut read),
                    );
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
    ) -> Result<RelocationNames<'_>, String> {
        let link = usize::try_from(sh.sh_link).unwrap_or(usize::MAX);
        let symtab = self
            .shdrs
            .get(link)
            .filter(|s| s.sh_type == SHT_SYMTAB || s.sh_type == SHT_DYNSYM)
            .ok_or_else(|| format!("sh_link {} does not name a symbol table", sh.sh_link))?;
        let strtab = self
            .shdrs
            .get(usize::try_from(symtab.sh_link).unwrap_or(usize::MAX))
            .filter(|s| s.sh_type == SHT_STRTAB)
            .filter(|s| self.cur.slice(s.sh_offset, s.sh_size).is_ok())
            .ok_or_else(|| {
                format!(
                    "its symbol table's sh_link {} names no string table the file holds",
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
        (found, read): (&mut BTreeSet<String>, &mut RelocationsRead),
    ) {
        let (count, partial) = (sh.sh_size / step, sh.sh_size % step);
        let step = step.get();
        if partial != 0 {
            stop(format!(
                "sh_size {:#x} is {count} whole {step}-byte entries and a partial one",
                sh.sh_size
            ));
        }
        let (symtab, strtab, sym_count) = (names.symtab, names.strtab, names.sym_count);
        for i in 0..count {
            if let Err(spent) = self.step() {
                stop(format!("not read past entry {i} of {count}: {spent}"));
                return;
            }
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
                    "entry {i} of {count} names symbol {sym}, past its symbol table of {sym_count}"
                ));
                return;
            }
            let at = symtab
                .sh_offset
                .saturating_add(sym.saturating_mul(names.sym_step));
            let kind = u32::try_from(kind).unwrap_or(u32::MAX);
            // The string table's size is in the key with its offset: it bounds the name and
            // decides the stop for an offset past it, so two headers over one table at two
            // sizes name a symbol two ways.
            let key = (at, strtab.sh_offset, strtab.sh_size);
            if read.listed.contains(&(kind, key)) {
                continue;
            }
            if let std::collections::btree_map::Entry::Vacant(slot) = read.names.entry(key) {
                match self.relocation_symbol(at, strtab, (i, count, sym)) {
                    Ok(named) => slot.insert(named),
                    Err(why) => {
                        stop(why);
                        return;
                    }
                };
            }
            let Some(Some((name, visibility))) = read.names.get(&key) else {
                continue;
            };
            if let Err(spent) = self.list_relocation(found, kind, name, *visibility) {
                stop(format!("not read past entry {i} of {count}: {spent}"));
                return;
            }
            read.listed.insert((kind, key));
        }
    }

    /// The name and visibility a relocation lists for the symbol whose entry is at `at`,
    /// `None` for an unnamed symbol that names nothing, or the sentence that stops the walk.
    fn relocation_symbol(
        &self,
        at: u64,
        strtab: &Shdr,
        (i, count, sym): (u64, u64, u64),
    ) -> Result<Option<(String, u8)>, String> {
        let Ok(name_off) = self.cur.u32_at(at) else {
            return Err(format!("entry {i} of {count} names symbol {sym}"));
        };
        if u64::from(name_off) >= strtab.sh_size {
            return Err(format!(
                "entry {i} of {count} names symbol {sym}, whose name offset {name_off:#x} is \
                 past its {:#x}-byte string table",
                strtab.sh_size
            ));
        }
        let mut name = self
            .name_at(strtab.sh_offset, name_off, strtab.sh_size)
            .map_err(|fault| {
                format!(
                    "entry {i} of {count} names symbol {sym}, whose name was not read, and \
                     neither were the entries after it: {fault}"
                )
            })?;
        if name.is_empty() {
            match self.section_symbol_label(at) {
                Ok(Some(label)) => name = label,
                Ok(None) => return Ok(None),
                Err(why) => return Err(format!("entry {i} of {count} names symbol {sym}, {why}")),
            }
        }
        // st_other's low two bits; a section symbol is local and carries none.
        let other_at = at.saturating_add(if self.elf64 { 5 } else { 13 });
        let Ok([other]) = self.cur.slice(other_at, 1) else {
            return Err(format!("entry {i} of {count} names symbol {sym}"));
        };
        Ok(Some((name, other & 0x3)))
    }

    /// One `code_relocations` entry, charged its length: each kind of relocation through
    /// each symbol is listed once, so a name is copied once per kind, not once per entry.
    fn list_relocation(
        &self,
        found: &mut BTreeSet<String>,
        kind: u32,
        name: &str,
        visibility: u8,
    ) -> Result<(), Spent> {
        self.budget
            .spend(u64::try_from(name.len()).unwrap_or(u64::MAX))?;
        let kind = reloc_type_name(self.e_machine, kind);
        found.insert(match visibility_label(visibility) {
            Some(vis) if !name.starts_with('[') => format!("{kind} {name} {vis}"),
            _ => format!("{kind} {name}"),
        });
        Ok(())
    }

    /// The label a relocation through the unnamed symbol at `at` is listed under: for a
    /// section symbol, `[` the name of the section it stands for `]`, or `[section N]`
    /// where that section has no name the reader holds; `None` for an unnamed symbol of
    /// any other type, which names nothing. `Err` says which byte the file does not hold.
    fn section_symbol_label(&self, at: u64) -> Result<Option<String>, String> {
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

    /// One `SHT_SYMTAB` entry's name, type, section index, value and size, or why not: the
    /// file does not hold the entry, or its name was not read ([`Self::name_at`]). The name is
    /// read through `strtab` and cut at its first `@`, as [`Self::symbols`] cuts a `.symtab`
    /// name ([`Spelling::Versioned`]).
    fn symbol_at(
        &self,
        sh: &Shdr,
        strtab: &Shdr,
        step: u64,
        i: u64,
    ) -> Result<SymbolEntry, EntryStop> {
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
            let raw = self.name_at(strtab.sh_offset, name_off, strtab.sh_size)?;
            // The `@` cut of `read_symbols` for `.symtab`: this reads that table alone.
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
    fn symbol_table_entries(&self, idx: usize) -> Option<Vec<SymbolEntry>> {
        let sh = self.shdrs.get(idx)?;
        let mut scratch = Vec::new();
        let (step, count) = self.symbol_entries(idx, sh, "", &mut scratch)?;
        let strtab = self.symbol_strtab(sh, "", &mut scratch)?;
        let mut entries = Vec::new();
        for i in 0..count {
            // A spent budget is named by the caller, which reads it from the budget.
            if self.step().is_err() {
                return None;
            }
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
    fn function_references(&self, trunc: &mut Vec<Truncation>) -> Option<Vec<String>> {
        if self.e_type != ET_REL || (self.elf64 && self.e_machine == EM_MIPS) {
            return None;
        }
        let symtab_idx = self.shdrs.iter().position(|s| s.sh_type == SHT_SYMTAB)?;
        // The walk reads every field of every entry, where the symbol reader reads a name,
        // a type and a section, so a table cut inside the last entries' values or sizes
        // stops this walk alone, and it records its own stop: `None` with nothing recorded
        // would move the field to absent unannounced.
        let Some(symbols) = self.symbol_table_entries(symtab_idx) else {
            if !trunc
                .iter()
                .any(|t| t.table == ElfTable::Symbols && t.kind == TruncationKind::Unread)
            {
                let why = self.budget.exhausted().map_or_else(
                    || "an entry's value or size could not be read".to_owned(),
                    |spent| spent.to_string(),
                );
                trunc.push(Truncation::unread(
                    ElfTable::Symbols,
                    format!(
                        "SHT_SYMTAB: {why}, so no function's range is known and no reference \
                         was attributed"
                    ),
                ));
            }
            return None;
        };
        let (mut functions, ranges) = Self::function_ranges(&symbols);
        let mut unattributed = BTreeSet::new();
        let mut seen = Attributed::default();
        for (idx, sh) in self.shdrs.iter().enumerate() {
            if sh.sh_type == SHT_RELA || sh.sh_type == SHT_REL {
                self.attribute_relocations(
                    idx,
                    sh,
                    symtab_idx,
                    &symbols,
                    &ranges,
                    (&mut functions, &mut unattributed, &mut seen),
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
                        "{label}: type {:#x} carries relocations against a section holding functions or code in an encoding this reader does not decode",
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
    /// such a section, and it is `SHT_CREL` or carries `SHF_INFO_LINK`, which makes `sh_info`
    /// a section index.
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
    #[expect(
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
        (functions, unattributed, seen): (
            &mut [FunctionRefs<'s>],
            &mut BTreeSet<&'s str>,
            &mut Attributed,
        ),
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
        // scope `code_relocations` shares.
        if usize::try_from(sh.sh_link) != Ok(symtab_idx) {
            trunc.push(Truncation::unread(
                ElfTable::Relocations,
                format!(
                    "{label}: sh_link {} does not name the symbol table at [{symtab_idx}]",
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
                    "{label}: {:#x} bytes at {:#x} are not {count} whole {step}-byte entries inside the file",
                    sh.sh_size, sh.sh_offset
                ),
            ));
            return;
        }
        let at = |i: u64| format!("{label}: not read past entry {i} of {count}");
        for i in 0..count {
            if self.out_of_budget(ElfTable::Relocations, trunc, || at(i)) {
                return;
            }
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
                        "{label}: entry {i} of {count} names symbol {sym_idx}, past the {}-entry symbol table",
                        symbols.len()
                    ),
                ));
                return;
            };
            if sym.name.is_empty() {
                continue;
            }
            let Some(placed) = self.place_reference(
                offset,
                (list, reach),
                (sym.name.as_str(), sym_idx, &mut *functions, &mut seen.pairs),
                trunc,
                &|| at(i),
            ) else {
                return;
            };
            if !placed && code && seen.unattributed.insert(sym_idx) {
                let units = sym.name.len();
                if self.out_of_budget_for(units, ElfTable::Relocations, trunc, || at(i)) {
                    return;
                }
                unattributed.insert(sym.name.as_str());
            }
        }
    }

    /// Attribute a relocation at `offset` through `name` to every function whose range holds
    /// it: whether one did, or `None` where the budget ran out, recorded at the place `at`
    /// names.
    fn place_reference<'s>(
        &self,
        offset: u64,
        (list, reach): (&[(u64, u64, usize)], &[u64]),
        (name, symbol, functions, pairs): (
            &'s str,
            u64,
            &mut [FunctionRefs<'s>],
            &mut BTreeSet<(usize, u64)>,
        ),
        trunc: &mut Vec<Truncation>,
        at: &dyn Fn() -> String,
    ) -> Option<bool> {
        let upto = list.partition_point(|&(start, _, _)| start <= offset);
        let mut placed = false;
        for k in (0..upto).rev() {
            if reach.get(k).is_none_or(|&r| r <= offset) {
                break;
            }
            if self.out_of_budget(ElfTable::Relocations, trunc, at) {
                return None;
            }
            if let Some(&(_, end, f)) = list.get(k)
                && offset < end
                && let Some((function, refs)) = functions.get_mut(f)
            {
                // A pair is found by the function's and the symbol's index, not by comparing
                // names, which share a prefix as long as a crafted file makes them.
                if pairs.insert((f, symbol)) {
                    let units = function.len().saturating_add(name.len());
                    if self.out_of_budget_for(units, ElfTable::Relocations, trunc, at) {
                        return None;
                    }
                    refs.insert(name);
                }
                placed = true;
            }
        }
        Some(placed)
    }

    /// The `PT_GNU_STACK` header the loader acts on, the last, with an `unread`
    /// [`ElfTable::GnuStack`] entry in `trunc` where two disagree on `PF_X`.
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
                    "{} PT_GNU_STACK headers disagree on PF_X (program headers {}, PF_X at {})",
                    stacks.len(),
                    at.join(", "),
                    executable.join(", ")
                ),
            ));
        }
        stacks.last().map(|&(_, p)| p)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one struct literal, a field to a line"
    )]
    pub fn facts(&self) -> ElfFacts {
        // Each reading spends from where the parse left the budget, so two readings of one
        // `Elf` are the same reading.
        self.budget.restart();
        let mut truncations = self.structural_truncations();
        // Before every other walk: an honest artifact large enough to spend the budget
        // elsewhere must still be told from one that carries no witness.
        let run_witness = self.run_witness(&mut truncations);
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
        let noted = self.feature_word(&props, GNU_PROPERTY_AARCH64_FEATURE_1_AND);
        // An unlinked aarch64 object with no property note is marked by its build attributes
        // (`aarch64_attribute_word`, none on a linked object).
        let arm = match self.aarch64_attribute_word(&mut truncations) {
            None => noted,
            Some(stated) if !props.contains_key(&GNU_PROPERTY_AARCH64_FEATURE_1_AND) => stated,
            Some(stated) => {
                let bits = AARCH64_FEATURE_1_BTI | AARCH64_FEATURE_1_PAC | AARCH64_FEATURE_1_GCS;
                if stated & bits != noted & bits {
                    truncations.push(Truncation::unread(
                        ElfTable::Notes,
                        format!(
                            "the property note's aarch64 feature word {noted:#x} and the build attributes' {stated:#x} disagree"
                        ),
                    ));
                }
                noted & stated
            }
        };

        let has_interp = self.phdrs.iter().any(|p| p.p_type == PT_INTERP);
        let has_dynamic = !dyn_entries.is_empty();
        let kind = link_kind(self.e_type, has_interp, &tags, flags1);
        let flat = kind.map(LinkKind::flatten);
        // Each is a fact about a linked object, so each is `None` where there is none.
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
            rwx_segment: linked(self.phdrs.iter().any(|p| {
                (p.p_type == PT_LOAD || p.p_type == PT_TLS)
                    && p.p_flags & PF_W != 0
                    && p.p_flags & PF_X != 0
            })),
            df_1_noopen: flags1 & DF_1_NOOPEN != 0,
            // Two spellings, like `bind_now`: bfd emits `DT_FLAGS` only when `info->flags`
            // is non-zero, so a link may record a text relocation solely as the standalone
            // `DT_TEXTREL` entry, where the flag word alone would read a reassuring `false`.
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
            run_witness,
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

/// `bytes` as lowercase hex, two digits a byte: how a run witness is spelled
/// ([`ElfFacts::run_witness`], `compile::RunWitness::nonce_hex`).
#[must_use]
pub fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        // Writing to a `String` does not fail.
        crate::error::best_effort(write!(out, "{byte:02x}"));
        out
    })
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
const MAX_OBJECT_BYTES: u64 = 512 * 1024 * 1024;

/// Read `path` and extract facts. The whole file is held, so the parser hands out
/// borrowed slices without a second read.
///
/// # Errors
///
/// Errors when the file cannot be read, is a directory, a device or a socket, holds more
/// than `MAX_OBJECT_BYTES`, or is not a parseable ELF object.
pub fn facts_for(path: &Path) -> Result<ElfFacts, ElfError> {
    facts_from(path, &read_object(path)?)
}

/// The bytes `facts_for` reads from `path`: the same metadata refusals, the same size cap and
/// one `open`.
///
/// # Errors
///
/// Errors when the file cannot be read, is a directory, a device or a socket, or holds more
/// than `MAX_OBJECT_BYTES`.
pub fn read_object(path: &Path) -> Result<Vec<u8>, ElfError> {
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
    // hold it.
    if kind.is_file() && meta.len() > MAX_OBJECT_BYTES {
        return Err(ElfError::TooLarge {
            path: path.to_path_buf(),
            size: Some(meta.len()),
            cap: MAX_OBJECT_BYTES,
        });
    }
    let file = std::fs::File::open(path).map_err(io("opening"))?;
    read_under_cap(file, MAX_OBJECT_BYTES)
        .map_err(io("reading"))?
        .ok_or_else(|| ElfError::TooLarge {
            path: path.to_path_buf(),
            size: None,
            cap: MAX_OBJECT_BYTES,
        })
}

/// The facts of `data`, the bytes [`read_object`] read from `path`.
///
/// # Errors
///
/// Errors when `data` is not a parseable ELF object.
pub fn facts_from(path: &Path, data: &[u8]) -> Result<ElfFacts, ElfError> {
    Ok(Elf::parse(data)
        .map_err(|refusal| refusal.with_path(path))?
        .facts())
}

/// Read `source` to its end, holding at most `cap` bytes: the bytes when the stream
/// ended within the cap, `None` when it went past it.
fn read_under_cap(source: impl std::io::Read, cap: u64) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    let mut data = Vec::new();
    source.take(cap.saturating_add(1)).read_to_end(&mut data)?;
    let within = u64::try_from(data.len()).is_ok_and(|held| held <= cap);
    Ok(within.then_some(data))
}

// Kani proofs live in `proofs/`, included here under `cfg(kani)` rather than from the crate
// root so they reach `Cursor`'s private fields as a child module.
#[cfg(kani)]
#[path = "../proofs/cursor_reads_total.rs"]
mod cursor_proofs;

#[cfg(kani)]
#[path = "../proofs/align_up_is_least_multiple.rs"]
mod align_up_proofs;

#[cfg(kani)]
#[path = "../proofs/note_walk_stays_in_its_table.rs"]
mod note_walk_proofs;

#[cfg(test)]
mod tests {
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
            // A kernel of that architecture runs it natively at the width and byte order its
            // spelling carries.
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

    #[test]
    fn align_up_is_the_least_multiple_or_refuses_on_overflow_at_sampled_alignments() {
        let top = u64::MAX;
        let aligns = (1..=257_u64).chain([top / 2, top / 2 + 1, top / 2 + 2, top - 1, top]);
        for align in aligns {
            let last_served = top - (align - 1);
            let values = [
                0,
                1,
                align - 1,
                align,
                align.saturating_add(1),
                top - align,
                last_served,
                last_served.saturating_add(1),
                top,
            ];
            for value in values {
                let refuses = align >= 2 && value.checked_add(align - 1).is_none();
                match align_up(value, align) {
                    None => assert!(refuses, "align_up({value}, {align}) refused"),
                    Some(m) => {
                        assert!(!refuses, "align_up({value}, {align}) served {m}");
                        assert_eq!(m % align, 0, "align_up({value}, {align}) = {m}");
                        assert!(
                            m >= value && m - value < align,
                            "align_up({value}, {align}) = {m}"
                        );
                    }
                }
            }
        }
        assert_eq!(align_up(1 << 63 | 1, 1 << 63 | 1), None);
    }

    #[test]
    fn note_descriptor_offset_is_absolutely_aligned() {
        let namesz: u64 = 4; // "GNU\0"
        let correct = align_up(12 + namesz, 8).unwrap();
        let tempting_and_wrong = 12 + align_up(namesz, 8).unwrap();
        assert_eq!(correct, 16);
        assert_eq!(tempting_and_wrong, 20);
        assert_ne!(correct, tempting_and_wrong);
    }

    /// A minimal ELF64 `ET_DYN` header for x86_64 with the program-header table at 64, and
    /// the section-header table there too where `shnum` is nonzero.
    fn elf64_header(phnum: u16, phentsize: u16, shnum: u16, shentsize: u16) -> Vec<u8> {
        let mut d = vec![0u8; 64];
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 2; // ELFCLASS64
        d[5] = 1; // little-endian
        d[6] = 1;
        d[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        d[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        d[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        // Zero is no section-header table, and a nonzero offset with `e_shnum == 0` is the
        // escape to a count in `shdr[0]`, which here would be the first program header.
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

    #[test]
    fn a_header_stride_other_than_the_record_is_never_walked() {
        // Zero aliases, one below the real size overlaps.
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
        let section_header_causes = |elf: &Elf<'_>| -> Vec<Truncation> {
            elf.facts()
                .truncations
                .into_iter()
                .filter(|t| t.table == ElfTable::SectionHeaders)
                .collect()
        };
        // Exactly the record size stands, and reads its one section header.
        let bytes = elf64_header(1, 56, 1, 64);
        let exact = Elf::parse(&bytes).expect("record-size strides");
        assert_eq!(exact.shdrs.len(), 1);
        assert_eq!(section_header_causes(&exact), Vec::new());
        // Above it, a program-header table is refused, since the loaders disagree on it.
        for above in [57u16, 64, 72, 112, u16::MAX] {
            let Err(ElfError::Malformed { what, .. }) = Elf::parse(&elf64_header(1, above, 0, 64))
            else {
                panic!("e_phentsize {above} must be refused as malformed");
            };
            assert!(
                what.starts_with(&format!(
                    "e_phentsize is {above}, not the 56-byte program header"
                )),
                "{what}"
            );
        }
        // And a section-header table is not read: no section, and the cause recorded once.
        for above in [65u16, 80, 128, u16::MAX] {
            let bytes = elf64_header(1, 56, 1, above);
            let elf = Elf::parse(&bytes)
                .unwrap_or_else(|e| panic!("e_shentsize {above} is withheld, not refused: {e:?}"));
            assert_eq!(
                elf.shdrs.len(),
                0,
                "e_shentsize {above}: no section is read"
            );
            let causes = section_header_causes(&elf);
            let [cause] = causes.as_slice() else {
                panic!("e_shentsize {above}: one cause, got {causes:?}");
            };
            assert_eq!(cause.kind, TruncationKind::Unread);
            assert!(
                cause.detail.starts_with(&format!(
                    "section-header table: e_shentsize is {above} where the record is 64 bytes"
                )),
                "{}",
                cause.detail
            );
        }
        // A count of zero says nothing about the stride, so it is not grounds to refuse or
        // to withhold: an object with no program headers writes `e_phentsize` 0, and one
        // stripped of its section headers `e_shentsize` 0.
        for (phentsize, shentsize) in [(0, 0), (112, 128), (u16::MAX, u16::MAX)] {
            let bytes = elf64_header(0, phentsize, 0, shentsize);
            let elf = Elf::parse(&bytes)
                .unwrap_or_else(|e| panic!("({phentsize}, {shentsize}) with no tables: {e:?}"));
            assert_eq!(section_header_causes(&elf), Vec::new());
        }
    }

    /// [`elf64_header`]'s ELF32 counterpart: an `ET_DYN` for i386 with both tables at 52.
    fn elf32_header(phnum: u16, phentsize: u16, shnum: u16, shentsize: u16) -> Vec<u8> {
        let mut d = vec![0u8; 52];
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 1; // ELFCLASS32
        d[5] = 1; // little-endian
        d[6] = 1;
        d[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        d[18..20].copy_from_slice(&3u16.to_le_bytes()); // EM_386
        d[28..32].copy_from_slice(&52u32.to_le_bytes()); // e_phoff
        if shnum > 0 {
            d[32..36].copy_from_slice(&52u32.to_le_bytes()); // e_shoff
        }
        d[42..44].copy_from_slice(&phentsize.to_le_bytes());
        d[44..46].copy_from_slice(&phnum.to_le_bytes());
        d[46..48].copy_from_slice(&shentsize.to_le_bytes());
        d[48..50].copy_from_slice(&shnum.to_le_bytes());
        d.resize(4096, 0);
        d
    }

    #[test]
    fn an_elf32_header_stride_other_than_its_record_is_never_walked() {
        let exact = elf32_header(1, 32, 1, 40);
        let elf = Elf::parse(&exact).expect("record-size strides");
        assert_eq!(elf.shdrs.len(), 1);
        for other in [31u16, 33, 40, 56] {
            let Err(ElfError::Malformed { what, .. }) = Elf::parse(&elf32_header(1, other, 0, 40))
            else {
                panic!("ELF32 e_phentsize {other} must be refused as malformed");
            };
            assert!(
                what.starts_with(&format!("e_phentsize is {other}")),
                "{what}"
            );
            if other < 32 {
                assert!(
                    what.contains("below the 32-byte program header"),
                    "the below-record arm refuses {other}: {what}"
                );
            }
        }
        for above in [41u16, 64, 128] {
            let bytes = elf32_header(1, 32, 1, above);
            let elf = Elf::parse(&bytes)
                .unwrap_or_else(|e| panic!("ELF32 e_shentsize {above} is withheld: {e:?}"));
            assert_eq!(elf.shdrs.len(), 0, "ELF32 e_shentsize {above}");
            assert!(
                elf.facts().truncations.iter().any(|t| {
                    t.table == ElfTable::SectionHeaders
                    && t.kind == TruncationKind::Unread
                    && t.detail.starts_with(&format!(
                        "section-header table: e_shentsize is {above} where the record is 40 bytes"
                    ))
                }),
                "ELF32 e_shentsize {above}"
            );
        }
        let Err(ElfError::Malformed { what, .. }) = Elf::parse(&elf32_header(1, 32, 1, 39)) else {
            panic!("ELF32 e_shentsize 39 must be refused as malformed");
        };
        assert!(
            what.starts_with("e_shentsize is 39, below the 40-byte section header"),
            "{what}"
        );
    }

    #[test]
    fn sections_declared_at_no_offset_are_not_read() {
        let mut bytes = elf64_header(1, 56, 2, 64);
        bytes[40..48].copy_from_slice(&0u64.to_le_bytes()); // e_shoff
        let elf = Elf::parse(&bytes).expect("sections at no offset are withheld, not refused");
        assert_eq!(elf.shdrs.len(), 0);
        let facts = elf.facts();
        let causes: Vec<&Truncation> = facts
            .truncations
            .iter()
            .filter(|t| t.table == ElfTable::SectionHeaders)
            .collect();
        let [cause] = causes.as_slice() else {
            panic!("one cause, got {causes:?}");
        };
        assert_eq!(cause.kind, TruncationKind::Unread);
        assert!(
            cause
                .detail
                .starts_with("section-header table: e_shoff is 0, which says the file has none"),
            "{}",
            cause.detail
        );
    }

    #[test]
    fn an_escaped_section_count_is_withheld_at_another_stride() {
        let mut bytes = elf64_header(1, 56, 1, 128);
        bytes[40..48].copy_from_slice(&1024u64.to_le_bytes()); // e_shoff, clear of the phdr
        bytes[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum: the count escape
        bytes[1024 + 32..1024 + 40].copy_from_slice(&2u64.to_le_bytes()); // shdr[0].sh_size
        let elf = Elf::parse(&bytes).expect("an escaped count at another stride is withheld");
        assert_eq!(elf.shdrs.len(), 0);
        let causes: Vec<Truncation> = elf
            .facts()
            .truncations
            .into_iter()
            .filter(|t| t.table == ElfTable::SectionHeaders)
            .collect();
        let [cause] = causes.as_slice() else {
            panic!("one cause, got {causes:?}");
        };
        assert_eq!(cause.kind, TruncationKind::Unread);
        assert!(
            cause.detail.starts_with(
                "section-header table: e_shentsize is 128 where the record is 64 bytes, so its 2 \
                 headers"
            ),
            "{}",
            cause.detail
        );
    }

    /// Build an ELF64 whose derived facts are decided by the inputs named here.
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
            d[n + 4..n + 8].copy_from_slice(&16u32.to_le_bytes()); // descsz
            d[n + 8..n + 12].copy_from_slice(&NT_GNU_PROPERTY_TYPE_0.to_le_bytes());
            d[n + 12..n + 16].copy_from_slice(b"GNU\0");
            // desc at align_up(12 + 4, 8) == 16, 16 bytes: the property padded to 8 as a
            // linker writes it.
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

    /// An `ET_EXEC` whose program headers are `phdrs` (`p_type`, `p_flags`) and nothing else.
    fn with_phdrs(phdrs: &[(u32, u32)]) -> Vec<u8> {
        let mut d = elf64_header(u16::try_from(phdrs.len()).unwrap(), 56, 0, 64);
        d[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        for (i, (p_type, p_flags)) in phdrs.iter().enumerate() {
            let b = 64 + i * 56;
            d[b..b + 4].copy_from_slice(&p_type.to_le_bytes());
            d[b + 4..b + 8].copy_from_slice(&p_flags.to_le_bytes());
        }
        d
    }

    #[test]
    fn rwx_segment_reads_one_segment_writable_and_executable() {
        const R: u32 = 0x4;
        let read = |phdrs: &[(u32, u32)]| facts_of(&with_phdrs(phdrs)).rwx_segment;
        assert_eq!(
            read(&[(PT_LOAD, R | PF_X), (PT_LOAD, R), (PT_LOAD, R | PF_W)]),
            Some(false),
            "the default split layout"
        );
        assert_eq!(
            read(&[(PT_LOAD, R | PF_W | PF_X)]),
            Some(true),
            "one RWX PT_LOAD"
        );
        assert_eq!(
            read(&[
                (PT_LOAD, R | PF_X),
                (PT_LOAD, R | PF_W),
                (PT_TLS, R | PF_W | PF_X)
            ]),
            Some(true),
            "an RWX PT_TLS beside split loads"
        );
        assert_eq!(
            read(&[(PT_LOAD, R | PF_X), (PT_LOAD, R | PF_W), (PT_TLS, R | PF_X)]),
            Some(false),
            "a PT_TLS executable and not writable is not read as RWX"
        );
        assert_eq!(
            read(&[
                (PT_LOAD, R | PF_X),
                (PT_LOAD, R | PF_W),
                (PT_GNU_STACK, R | PF_W | PF_X)
            ]),
            Some(false),
            "an executable stack is noexecstack's to read"
        );
        assert_eq!(
            read(&[
                (PT_LOAD, R | PF_W),
                (PT_LOAD, R | PF_X),
                (PT_NOTE, R | PF_W | PF_X)
            ]),
            Some(false),
            "a program header other than PT_LOAD and PT_TLS is not read"
        );
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
        // Padded: `.text` alone on its page, the read-only data on the next.
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
        // the read-only segment at 0x4c0 holding `.dynsym`, `.rodata` and `.eh_frame`.
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

    /// Every grid row, less those naming a dynamic tag on an object with no dynamic section.
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

        // A relocatable object serializes the classification as null.
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

    #[test]
    fn a_symbol_table_is_read_only_through_a_string_table_that_exists() {
        // SHT_NULL, SHT_SYMTAB, and one SHT_STRTAB for section and symbol names.
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

            // The canary defined, the same name again, and a watched symbol undefined.
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

        // sh_link 0 is SHN_UNDEF: believing it reads names from the start of the file.
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

        // A link that exists and is not a string table (here the symbol table itself) is the
        // case `sh_link` zero cannot tell from an `||` guard.
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

    /// A relocatable object laid out for [`Elf::code_relocations`]: `.text`, `.rela.text`,
    /// `.symtab`, `.strtab` (which also names the sections), `.data` and `.rela.data`.
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
            // [1] the `.text` section symbol, [2] the callee, undefined, [3] the caller.
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
        // Symbol records: (table offset, st_name).
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

        std::fs::remove_dir_all(&dir).expect("remove temp dir");
    }

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
    fn two_note_segment(p_align: u64, first_descsz: u32, second_at: u64) -> Vec<u8> {
        let note_at: u64 = 0x600;
        let mut d = elf64_header(1, 56, 0, 64);
        d[16..18].copy_from_slice(&ET_DYN.to_le_bytes());

        let b = 64;
        d[b..b + 4].copy_from_slice(&PT_NOTE.to_le_bytes());
        d[b + 8..b + 16].copy_from_slice(&note_at.to_le_bytes());
        d[b + 32..b + 40].copy_from_slice(&second_at.saturating_add(32).to_le_bytes());
        d[b + 48..b + 56].copy_from_slice(&p_align.to_le_bytes());

        write_two_notes(&mut d, note_at, first_descsz, second_at);
        d
    }

    /// The same two notes in a `SHT_NOTE` *section* of a file with no program headers,
    /// which `notes_from_sections` names, so `notes()` reads the section.
    fn two_note_section(sh_addralign: u64, first_descsz: u32, second_at: u64) -> Vec<u8> {
        let note_at: u64 = 0x600;
        // No program headers: `e_phoff` and `e_shoff` are both 64 in this header, so the
        // two tables would overlap, and a count of zero is what keeps them apart.
        let mut d = elf64_header(0, 56, 1, 64);
        d[16..18].copy_from_slice(&ET_DYN.to_le_bytes());

        let b = 64;
        d[b + 4..b + 8].copy_from_slice(&SHT_NOTE.to_le_bytes());
        d[b + 24..b + 32].copy_from_slice(&note_at.to_le_bytes());
        d[b + 32..b + 40].copy_from_slice(&second_at.saturating_add(32).to_le_bytes());
        d[b + 48..b + 56].copy_from_slice(&sh_addralign.to_le_bytes());

        write_two_notes(&mut d, note_at, first_descsz, second_at);
        d
    }

    /// A build-id-shaped note of `first_descsz` bytes, then the IBT property note at
    /// `second_at`, both named `"GNU\0"`, so type and position alone separate them.
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
        d[s + 4..s + 8].copy_from_slice(&16u32.to_le_bytes());
        d[s + 8..s + 12].copy_from_slice(&NT_GNU_PROPERTY_TYPE_0.to_le_bytes());
        d[s + 12..s + 16].copy_from_slice(b"GNU\0");
        d[s + 16..s + 20].copy_from_slice(&GNU_PROPERTY_X86_FEATURE_1_AND.to_le_bytes());
        d[s + 20..s + 24].copy_from_slice(&4u32.to_le_bytes());
        d[s + 24..s + 28].copy_from_slice(&X86_FEATURE_1_IBT.to_le_bytes());
    }

    #[test]
    fn a_second_note_is_found_at_the_alignment_the_container_declares() {
        // Declared 8, first descriptor 4 bytes: 4 padded to 8 puts the second note at +24.
        let declared_8 = two_note_segment(8, 4, 24);
        // Declared 0 is not an alignment.
        let declared_0 = two_note_segment(0, 5, 24);

        // The same two cases through the section walk, which a file with no program
        // headers takes; each container declares its alignment in its own field.
        let section_8 = two_note_section(8, 4, 24);
        let section_0 = two_note_section(0, 5, 24);
        // Declared 1 is what annobin writes on its `.gnu.build.attributes` sections: below
        // the 4 every note is padded to, it reads as 4 and lands at +24 too; taken at its
        // word it would be +21.
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
        // descriptor to 0x638.
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
                note.detail.starts_with("note table at 0x600+0x38:"),
                "the record names the table it was walking: {}",
                note.detail
            );
            cuts += 1;
        }
        assert_eq!(cuts, 3, "three cuts examined");
    }

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
    /// `SHT_NOTE` section header aimed at a second property note at `SECTION_AT`. With no
    /// `section_word` the section-header table is absent (`e_shnum` 0), as after
    /// `objcopy --strip-section-headers`.
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
            d[n + 4..n + 8].copy_from_slice(&16u32.to_le_bytes());
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
        d[0x684..0x688].copy_from_slice(&16u32.to_le_bytes());
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

    #[test]
    fn a_property_note_outside_the_property_segment_does_not_hide_its_marking() {
        let f = facts_of(&stray_property_note(
            X86_FEATURE_1_IBT | X86_FEATURE_1_SHSTK,
            0,
        ));
        assert!(f.x86_ibt && f.x86_shstk, "{f:?}");
        assert!(ignored_property_note(&f).is_some(), "{:?}", f.truncations);
    }

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

    /// The `.ARM.attributes` gcc 16.1.1 (Fedora 44's aarch64 cross compiler, binutils 2.46)
    /// writes to an object under `-mbranch-protection=standard`, its bytes copied from such
    /// an object, with each feature tag's value given here.
    fn gcc16_attributes(bti: u8, pac: u8, gcs: u8) -> Vec<u8> {
        let mut a = b"A\x23\0\0\0aeabi_feature_and_bits\0\x01\x00".to_vec();
        a.extend_from_slice(&[0, bti, 1, pac, 2, gcs]);
        assert_eq!(
            a.len(),
            36,
            "the section is 0x24 bytes in the witness object"
        );
        a
    }

    /// An aarch64 file of `e_type` with no program headers: a `SHT_AARCH64_ATTRIBUTES`
    /// section holding `attributes`, and, where `note_word` is given, a `SHT_NOTE` section
    /// holding one property note with that aarch64 feature word.
    fn attributes_object(e_type: u16, attributes: &[u8], note_word: Option<u32>) -> Vec<u8> {
        const SHOFF: usize = 512;
        const ATTR_AT: u64 = 0x800;
        const NOTE_AT: u64 = 0x900;
        let shnum = 2 + u16::from(note_word.is_some());
        let mut d = elf64_header(0, 56, shnum, 64);
        d[16..18].copy_from_slice(&e_type.to_le_bytes());
        d[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        d[40..48].copy_from_slice(&(SHOFF as u64).to_le_bytes());
        let mut shdr = |i: usize, kind: u32, off: u64, size: u64, align: u64| {
            let b = SHOFF + i * 64;
            d[b + 4..b + 8].copy_from_slice(&kind.to_le_bytes());
            d[b + 24..b + 32].copy_from_slice(&off.to_le_bytes());
            d[b + 32..b + 40].copy_from_slice(&size.to_le_bytes());
            d[b + 48..b + 56].copy_from_slice(&align.to_le_bytes());
        };
        let size = u64::try_from(attributes.len()).unwrap();
        shdr(1, SHT_AARCH64_ATTRIBUTES, ATTR_AT, size, 1);
        if note_word.is_some() {
            shdr(2, SHT_NOTE, NOTE_AT, 32, 8);
        }
        let a = usize::try_from(ATTR_AT).unwrap();
        d[a..a + attributes.len()].copy_from_slice(attributes);
        if let Some(word) = note_word {
            let n = usize::try_from(NOTE_AT).unwrap();
            d[n..n + 4].copy_from_slice(&4u32.to_le_bytes());
            d[n + 4..n + 8].copy_from_slice(&16u32.to_le_bytes());
            d[n + 8..n + 12].copy_from_slice(&NT_GNU_PROPERTY_TYPE_0.to_le_bytes());
            d[n + 12..n + 16].copy_from_slice(b"GNU\0");
            d[n + 16..n + 32].copy_from_slice(&property(
                GNU_PROPERTY_AARCH64_FEATURE_1_AND,
                word,
                true,
            ));
        }
        d
    }

    fn marking(f: &ElfFacts) -> [bool; 3] {
        [f.aarch64_bti, f.aarch64_pac, f.aarch64_gcs]
    }

    fn notes_unread(f: &ElfFacts) -> Vec<&str> {
        f.truncations
            .iter()
            .filter(|t| t.table == ElfTable::Notes && t.kind == TruncationKind::Unread)
            .map(|t| t.detail.as_str())
            .collect()
    }

    #[test]
    fn an_unlinked_aarch64_object_is_marked_by_its_build_attributes() {
        for (tags, expected) in [
            ((1, 1, 1), [true, true, true]),
            ((1, 0, 0), [true, false, false]),
            ((0, 1, 0), [false, true, false]),
            ((0, 0, 1), [false, false, true]),
            ((0, 0, 0), [false, false, false]),
        ] {
            let (bti, pac, gcs) = tags;
            let f = facts_of(&attributes_object(
                ET_REL,
                &gcc16_attributes(bti, pac, gcs),
                None,
            ));
            assert_eq!(marking(&f), expected, "{tags:?}: {f:?}");
            assert!(notes_unread(&f).is_empty(), "{tags:?}: {:?}", f.truncations);
            assert!(
                f.gnu_property_types.is_empty(),
                "no property type is invented"
            );
        }
    }

    #[test]
    fn a_linked_aarch64_program_is_never_marked_by_its_build_attributes() {
        for e_type in [ET_EXEC, ET_DYN] {
            let f = facts_of(&attributes_object(e_type, &gcc16_attributes(1, 1, 1), None));
            assert_eq!(marking(&f), [false; 3], "e_type {e_type}: {f:?}");
            assert!(notes_unread(&f).is_empty(), "{:?}", f.truncations);
        }
    }

    #[test]
    fn build_attributes_are_read_on_aarch64_alone() {
        let mut d = attributes_object(ET_REL, &gcc16_attributes(1, 1, 1), None);
        d[18..20].copy_from_slice(&EM_RISCV.to_le_bytes());
        let f = facts_of(&d);
        assert_eq!(marking(&f), [false; 3], "{f:?}");
        assert!(notes_unread(&f).is_empty(), "{:?}", f.truncations);
    }

    #[test]
    fn a_note_and_attributes_that_disagree_leave_the_marking_unread() {
        let all = AARCH64_FEATURE_1_BTI | AARCH64_FEATURE_1_PAC | AARCH64_FEATURE_1_GCS;
        let agree = facts_of(&attributes_object(
            ET_REL,
            &gcc16_attributes(1, 1, 1),
            Some(all),
        ));
        assert_eq!(marking(&agree), [true; 3], "{agree:?}");
        assert!(notes_unread(&agree).is_empty(), "{:?}", agree.truncations);

        for (note, tags, expected) in [
            (all, (0, 0, 0), [false; 3]),
            (0, (1, 1, 1), [false; 3]),
            (AARCH64_FEATURE_1_BTI, (1, 1, 0), [true, false, false]),
        ] {
            let (bti, pac, gcs) = tags;
            let f = facts_of(&attributes_object(
                ET_REL,
                &gcc16_attributes(bti, pac, gcs),
                Some(note),
            ));
            assert_eq!(marking(&f), expected, "note {note:#x} tags {tags:?}");
            let unread = notes_unread(&f);
            assert!(
                unread.len() == 1 && unread[0].contains("disagree"),
                "note {note:#x} tags {tags:?}: {unread:?}"
            );
        }
    }

    #[test]
    fn unreadable_build_attributes_are_recorded_and_mark_nothing() {
        let good = gcc16_attributes(1, 1, 1);
        let mut cut = good.clone();
        cut[1] = 0x24; // one byte longer than the section holds
        let mut version = good.clone();
        version[0] = b'a';
        let mut strings = good.clone();
        strings[29] = 1;
        let mut value = good.clone();
        value[31] = 2;
        let mut twice = good.clone();
        twice[32] = 0; // PAC's tag rewritten as BTI's
        // GCS's value continues past the end of the subsection.
        let mut cut_value = good.clone();
        cut_value[35] = 0x81;
        // The subsection one byte shorter: GCS's tag with no value after it, and that tag
        // continuing past the end.
        let mut no_value = good[..35].to_vec();
        no_value[1] = 0x22;
        let mut cut_tag = no_value.clone();
        cut_tag[34] = 0x82;
        // BTI's value as a ULEB128 of eleven bytes, past 64 bits, and as one of ten whose last
        // byte carries a bit above bit 63, which a reader dropping it would take as 0.
        let with_value = |value: &[u8]| {
            let mut b = good[..30].to_vec();
            b.push(0); // BTI's tag
            b.extend_from_slice(value);
            b[1] = u8::try_from(b.len() - 1).unwrap();
            b
        };
        let long = with_value(&[
            0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
        ]);
        let wide = with_value(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02]);
        for (name, bytes) in [
            ("length", cut),
            ("version", version),
            ("encoding", strings),
            ("value", value),
            ("repeated tag", twice),
            ("cut-off value", cut_value),
            ("no value", no_value),
            ("cut-off tag", cut_tag),
            ("empty section", Vec::new()),
            ("eleven-byte value", long),
            ("value past bit 63", wide),
        ] {
            let f = facts_of(&attributes_object(ET_REL, &bytes, None));
            assert_eq!(marking(&f), [false; 3], "{name}: {f:?}");
            assert_eq!(notes_unread(&f).len(), 1, "{name}: {:?}", f.truncations);
        }
        // Another subsection, unread by name, beside the feature one is skipped.
        let mut other = b"A\x0b\0\0\0vendor\0".to_vec();
        other.extend_from_slice(&good[1..]);
        let f = facts_of(&attributes_object(ET_REL, &other, None));
        assert_eq!(marking(&f), [true; 3], "{f:?}");
        assert!(notes_unread(&f).is_empty(), "{:?}", f.truncations);
    }

    #[test]
    fn the_attributes_are_compared_on_their_three_bits_and_read_in_the_files_byte_order() {
        let all = AARCH64_FEATURE_1_BTI | AARCH64_FEATURE_1_PAC | AARCH64_FEATURE_1_GCS;
        let f = facts_of(&attributes_object(
            ET_REL,
            &gcc16_attributes(1, 1, 1),
            Some(all | 0x8),
        ));
        assert_eq!(marking(&f), [true; 3], "{f:?}");
        assert!(notes_unread(&f).is_empty(), "{:?}", f.truncations);

        let little = gcc16_attributes(1, 0, 1);
        let mut big = little.clone();
        big[1..5].copy_from_slice(&0x23u32.to_be_bytes());
        let both = AARCH64_FEATURE_1_BTI | AARCH64_FEATURE_1_GCS;
        assert_eq!(feature_and_bits(&little, true), Ok(Some(both)));
        assert_eq!(feature_and_bits(&big, false), Ok(Some(both)));
        assert!(
            feature_and_bits(&big, true).is_err(),
            "the length read in the wrong order"
        );
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

    #[test]
    fn a_gnu_named_note_of_another_type_carries_no_properties() {
        const NT_GNU_BUILD_ID: u32 = 3;
        let desc = property(GNU_PROPERTY_X86_FEATURE_1_AND, X86_FEATURE_1_IBT, true);

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

    #[test]
    fn every_property_in_one_descriptor_is_read() {
        let mut desc = property(GNU_PROPERTY_X86_FEATURE_1_AND, X86_FEATURE_1_IBT, true);
        desc.extend(property(
            GNU_PROPERTY_AARCH64_FEATURE_1_AND,
            AARCH64_FEATURE_1_BTI,
            true,
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
    /// on an object of machine `machine`: the files a linker, which emits one merged note,
    /// did not write.
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
            d[n + 4..n + 8].copy_from_slice(&16u32.to_le_bytes());
            d[n + 8..n + 12].copy_from_slice(&NT_GNU_PROPERTY_TYPE_0.to_le_bytes());
            d[n + 12..n + 16].copy_from_slice(b"GNU\0");
            d[n + 16..n + 28].copy_from_slice(&property(*pr_type, *word, false));
        }
        d
    }

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
        let f = facts_of(&one_note(NT_GNU_PROPERTY_TYPE_0, &exact));
        assert!(
            f.x86_ibt && f.x86_shstk,
            "the same word at width 4 is decoded"
        );
    }

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
        assert!(
            none.gnu_property_types.is_empty(),
            "an object with no property note has no property type: {:?}",
            none.gnu_property_types
        );
    }

    /// What `.chard.report` holds, once `section_text` has turned its NULs into newlines.
    const REPORT_TEXT: &str = "fortify=2\nstack_protector=strong";

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
        assert!(
            past_eof.comment.is_empty(),
            "a .comment past the end of the file reads no line: {:?}",
            past_eof.comment
        );
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
        // file: a fourth way of carrying nothing, which reads as the third; read as a
        // section read to its end, it would make an lld banner a false `disagrees`.
        let mut headerless = object_with_comment(SHT_PROGBITS, AT, size, payload);
        headerless[40..48].copy_from_slice(&0u64.to_le_bytes());
        headerless[60..62].copy_from_slice(&0u16.to_le_bytes());
        headerless[62..64].copy_from_slice(&0u16.to_le_bytes());
        let unlisted = facts_of(&headerless);
        assert!(
            unlisted.comment.is_empty(),
            "an object with no section headers reads no .comment line: {:?}",
            unlisted.comment
        );
        assert!(unlisted.sections.is_empty(), "{:?}", unlisted.sections);
        let why = unlisted
            .comment_truncation()
            .expect("a .comment that could not be looked up is named in truncations");
        assert!(
            why.contains("could not be looked up") && why.contains("no section-header table"),
            "{why}"
        );
    }

    #[test]
    fn the_self_report_section_reaches_the_facts() {
        let facts = facts_of(&object_with_named_sections());
        assert_eq!(facts.self_report, REPORT_TEXT);
        assert!(facts.sections.iter().any(|s| s == SELF_REPORT_SECTION));
        // A section that is absent reads as empty, which is what makes the case above
        // meaningful rather than a value that appears whatever is asked for.
        assert!(
            facts.recorded_command_line.is_empty(),
            "an absent section reads as empty: {:?}",
            facts.recorded_command_line
        );
    }

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

        // SHN_UNDEF: the file declares no name table.
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
        assert!(
            named(&progbits).is_empty(),
            "a candidate that is not a string table names nothing"
        );
        let note = names_note(&progbits).expect("refused, and said");
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
        assert!(
            named(&past).is_empty(),
            "a candidate past the section table names nothing"
        );
        let note = names_note(&past).expect("refused, and said");
        assert!(note.contains("past"), "the reason is the range: {note}");
        assert!(!note.contains("  "), "one space between words: {note}");

        // A name is bounded by the table's declared size.
        let mut short = base.clone();
        short[SHOFF + 64 + 32..SHOFF + 64 + 40].copy_from_slice(&12u64.to_le_bytes());
        assert_eq!(
            named(&short),
            vec![".shstrtab".to_owned(), ".".to_owned()],
            "a name is cut at its table's declared end"
        );
    }

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
        // walked and runs off the file, which is an error.
        assert!(
            Elf::parse(&elf64_header(PN_XNUM, 56, 0, 64)).is_err(),
            "PN_XNUM with e_shoff = 0 is malformed and must not parse"
        );
    }

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

        // The control: a readable shdr[0] is followed, and records no note.
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

    #[test]
    fn a_read_past_the_address_space_is_refused_by_its_own_variant() {
        let data = [0u8; 16];
        let cur = Cursor {
            data: &data,
            little: true,
        };
        let past = u64::from(u32::MAX) + 1;
        if usize::BITS < 64 {
            assert_eq!(cur.slice(past, 1), Err(ReadError::OffsetTooLarge(past)));
            assert_eq!(cur.slice(0, past), Err(ReadError::LengthTooLarge(past)));
            assert_eq!(cur.u32_at(past), Err(ReadError::OffsetTooLarge(past)));
            assert_eq!(
                cur.addr_at(past, false),
                Err(ReadError::OffsetTooLarge(past))
            );
        } else {
            let start = usize::try_from(past).expect("a 64-bit usize");
            assert_eq!(
                cur.slice(past, 1),
                Err(ReadError::OutOfBounds { start, count: 1 })
            );
        }
    }

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

        // A 4-byte window with no NUL reads its 4 bytes, not on to the NUL at offset 16.
        let bounded = cur.cstr_at(0, 0, 4);
        assert_eq!(
            bounded,
            Ok(&b"AAAA"[..]),
            "a table with no terminator inside its declared length must stop at that \
             length, not scan into whatever follows"
        );

        // The bound is relative to the table's start, not to `off`: a nonzero `off` shrinks
        // the window rather than resetting it.
        let from_middle = cur.cstr_at(0, 2, 4);
        assert_eq!(
            from_middle,
            Ok(&b"AA"[..]),
            "off=2 into a 4-byte table leaves 2 bytes, not the full table_len again"
        );

        // `off` at or past the declared end reads as absent, not as reaching past it.
        assert_eq!(
            cur.cstr_at(0, 4, 4),
            Ok(&b""[..]),
            "an offset at the table's own declared end must not read past it"
        );
        assert_eq!(
            cur.cstr_at(0, 9, 4),
            Ok(&b""[..]),
            "an offset past the table's own declared end must not read at all"
        );

        // The control: a window that reaches the real NUL reads the string, so the bound
        // above does the cutting.
        assert_eq!(
            cur.cstr_at(0, 0, 100),
            Ok("A".repeat(16).as_bytes()),
            "a window that reaches the real terminator must read up to it"
        );
    }

    #[test]
    fn a_name_past_the_bound_on_one_name_is_refused_not_cut() {
        let at_bound = [vec![b'n'; MAX_NAME_BYTES], vec![0]].concat();
        let past_bound = [vec![b'n'; MAX_NAME_BYTES + 1], vec![0]].concat();
        let no_nul = vec![b'n'; MAX_NAME_BYTES * 2];
        let len = |d: &[u8]| u64::try_from(d.len()).expect("a length fits u64");
        let read = |d: &[u8]| {
            Cursor {
                data: d,
                little: true,
            }
            .cstr_at(0, 0, len(d))
            .map(<[u8]>::len)
        };
        assert_eq!(read(&at_bound), Ok(MAX_NAME_BYTES));
        assert_eq!(read(&past_bound), Err(Overlong));
        assert_eq!(read(&no_nul), Err(Overlong));
        // A table that ends at the bound with no NUL is the table-length rule, not a refusal.
        assert_eq!(read(&no_nul[..MAX_NAME_BYTES]), Ok(MAX_NAME_BYTES));
        // A name read is charged its bytes and its NUL, and one past the budget is refused.
        let cur = Cursor {
            data: &at_bound,
            little: true,
        };
        let budget = Budget::new(u64::try_from(MAX_NAME_BYTES).expect("fits") + 1);
        assert!(name_in(&cur, &budget, (0, 0, len(&at_bound))).is_ok());
        assert_eq!(budget.left.get(), 0);
        assert_eq!(budget.exhausted(), None);
        assert!(matches!(
            name_in(&cur, &budget, (0, 0, len(&at_bound))),
            Err(NameFault::Spent(_))
        ));
        assert!(budget.exhausted().is_some());
    }

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
        // p_memsz too: `offset_of_vaddr` bounds on it, not on p_filesz.
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
                // the parse that sets it), or a longer identifier.
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

    /// A deterministic xorshift sequence, seeded rather than drawn from the clock, so a
    /// failure reproduces exactly.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// A real ELF object to mutate, the running test binary; `None`, announced as a
    /// capability gap, on a host whose binaries are not ELF.
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

    /// The parser returns, never panics, on any corruption of a real object: a header that
    /// parses, leading the reader into tables whose offsets and counts are corrupted.
    ///
    /// `chard elf` reads any path a caller hands it, and `unsafe_code = "deny"` leaves a
    /// panic as the failure, which costs the caller every object not yet reached.
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
        // Drawn first, in order from the one seed, so the set is the same however it is
        // shared out below. A flip is a byte offset and the bit it flips.
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
        // Each corruption parsed and walked on up to eight threads, each mutating its own
        // copy of the seed in place and restoring it: a copy per corruption spends the run
        // in the allocator, and each worker's copy is a whole debug test binary.
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
                                    // `facts()` walks the tables the corrupted offsets
                                    // point into.
                                    let _: ElfFacts = elf.facts();
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
                // A worker's panic is the parser's (or the restore's): the test fails with it.
                let (wp, wr) = w.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
                (p.saturating_add(wp), r.saturating_add(wr))
            })
        });

        // Truncation at every length up to the header region, which is the other way a
        // table can run off the end.
        let mut truncations_parsed = 0usize;
        for len in 0..header_span.min(1024) {
            if let Ok(elf) = Elf::parse(original.get(..len).unwrap_or(&original)) {
                let _: ElfFacts = elf.facts();
                truncations_parsed = truncations_parsed.saturating_add(1);
            }
        }

        // The frame: a run that only ever failed at the magic bytes never entered the
        // parser, and would pass having exercised nothing.
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
