// SPDX-License-Identifier: BSD-3-Clause

//! Environment fingerprint: where a measurement happened.
//!
//! Deliberately separate from [`crate::toolchain`], which describes the thing
//! under test. The same toolchain measured under a different kernel can give
//! different `runtime`-channel verdicts — CET/shadow-stack enforcement and the
//! treatment of a missing `PT_GNU_STACK` are kernel policy, not compiler output.
//! That is also why `execution.mode` is recorded: under `container` the kernel
//! is the *host's*, so kernel-dependent verdicts describe the host rather than
//! the distro whose name is on the column, and probes marked `needs_vm` must be
//! reported as `indeterminate` rather than measured. The mode alone does not
//! settle it: `host` is also what is recorded when nothing observed the mode and
//! nobody asserted it, and nothing chard reads tells a container it has no
//! instrument for from a system that owns its kernel, so those probes are withheld
//! there too
//! ([`Execution::kernel_attribution`]).

use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::path::Path;

use serde::Serialize;

use crate::elf::ByteOrder;

/// CPU features that gate a hardening mechanism. A binary can carry IBT
/// markings on a CPU that cannot enforce them, so "marked" and "enforced" are
/// different claims and the report must let a reader tell them apart.
///
/// The list pairs with the checks that read markings: `ibt`/`shstk` for `cet-marked`,
/// `bti`/`paca`/`pacg` for `branch-protection-marked`, and `gcs` for `gcs-marked`. A
/// marking check added without its feature here still reports honestly — it says the
/// binary is marked, which is true — but the reader loses the second half of the
/// sentence this list exists to complete.
const RELEVANT_CPU_FEATURES: &[&str] = &[
    "ibt",
    "shstk",
    "user_shstk",
    "smap",
    "smep",
    "bti",
    "paca",
    "pacg",
    // Guarded Control Stack. Spelled as the arm64 kernel spells it in the `Features`
    // line of /proc/cpuinfo, which is where this is read from.
    "gcs",
];

#[derive(Debug, Clone, Serialize)]
pub struct Distro {
    pub id: String,
    pub version_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pretty_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codename: Option<String>,
}

impl Distro {
    /// Whether the run is on macOS: `SystemVersion.plist` named the system, which
    /// [`detect_distro`] reads only where no `os-release` exists, lowercasing its
    /// `ProductName`. A Mac whose file could not be read is `unknown` and reads `false`.
    ///
    /// The platform on which `report::emulation_limitation` consults a `Machine` probe's
    /// `sysctl.proc_translated` line (`decode::runtime::translation`), which only Darwin's
    /// probes print; elsewhere the rule reads as it did without the line.
    #[must_use]
    pub fn is_macos(&self) -> bool {
        self.id == "macos"
    }

    /// The distribution half of `toolchain.id`: `id` and `version_id` run together, as
    /// in `fedora44`.
    ///
    /// A system with no os-release reports `unknown` for both, and the tag is then the
    /// id alone: concatenating the two gave `unknownunknown`, a name a reader has to
    /// trust, since this feeds the key reports are joined on. Composed into the id by
    /// [`crate::toolchain::Detected::qualified`].
    #[must_use]
    pub fn tag(&self) -> String {
        if self.version_id == "unknown" {
            self.id.clone()
        } else {
            format!("{}{}", self.id, self.version_id)
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Kernel {
    pub release: String,
    /// The architecture chard's own binary was compiled for, which is the kernel's only
    /// while chard runs natively. See [`Kernel::machine`].
    pub arch: String,
    /// The kernel's own machine, as Linux's `/proc/sys/kernel/arch` names it, and `None`
    /// where that file is absent (every non-Linux platform, and Linux before the sysctl).
    ///
    /// Read because `arch` cannot answer the question it is now asked. chard run under
    /// user-mode emulation (an aarch64 chard in an arm64 container on an x86_64 host,
    /// through `binfmt_misc` and `qemu-aarch64`) was compiled for aarch64, and `uname(2)`
    /// answers `aarch64` there too, since qemu-user intercepts it. The file is read through
    /// to the host's kernel: measured 2026-10-01 under qemu-aarch64 10.2.2 on a Fedora 44
    /// x86_64 host, `uname -m` printed `aarch64` and the file `x86_64`, and `/proc/cpuinfo`
    /// was qemu's own, advertising `bti`, `paca`, `gcs` and `mte` the host has none of.
    /// [`Kernel::native_machine`] is what `report::emulation_limitation` compares a runtime
    /// artifact's `e_machine` against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// True when `mode` is `container`, where the kernel is the host's and not the measured
    /// distro's. Read from the mode alone, so false where the mode is `host` by default as
    /// well as on an asserted `host` or `vm`; [`Kernel::ownership`] says which.
    pub is_host_kernel: bool,
    /// Whose kernel this is, from the mode read with its basis
    /// ([`Execution::kernel_attribution`], which the `needs_vm` gate reads): `unsettled`
    /// where `is_host_kernel` reads `false` on the default and nothing settled it.
    pub ownership: KernelOwnership,
}

/// [`KernelAttribution`] as the report publishes it: `kernel.ownership`.
///
/// `is_host_kernel` is a bool read off the mode, so on the default (`host` on
/// `assumed-host`) it reads `false`, "the distribution's own kernel", while the `needs_vm`
/// checks beside it are withheld because whose kernel it is was never settled. This is the
/// word that can say so. It drops what [`KernelAttribution::Assumed`] quotes: the observation
/// is published beside it as `execution.mode_evidence.observation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KernelOwnership {
    /// The measured system's own: the operator asserted `host` or `vm`.
    Own,
    /// Another system's: a container, observed or asserted.
    Borrowed,
    /// Nobody settled it: `host` by default.
    Unsettled,
}

impl KernelOwnership {
    pub const ALL: &'static [Self] = &[Self::Own, Self::Borrowed, Self::Unsettled];

    /// The spelling the report publishes; a test holds it to the serde attribute.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Own => "own",
            Self::Borrowed => "borrowed",
            Self::Unsettled => "unsettled",
        }
    }
}

impl From<KernelAttribution<'_>> for KernelOwnership {
    fn from(attribution: KernelAttribution<'_>) -> Self {
        match attribution {
            KernelAttribution::Established => Self::Own,
            KernelAttribution::Borrowed => Self::Borrowed,
            KernelAttribution::Assumed { .. } => Self::Unsettled,
        }
    }
}

impl Kernel {
    /// The machine the kernel executes natively: [`Kernel::machine`] where it was read,
    /// and chard's own `arch` otherwise, which is the kernel's unless chard itself is
    /// emulated (the register entry `kernel-machine-is-chards-without-proc` in
    /// `THREAT_MODEL.md`). The value says which of the two it is, since
    /// [`kernel_byte_order`] reads them differently.
    #[must_use]
    pub fn native_machine(&self) -> NativeMachine<'_> {
        match self.machine.as_deref() {
            Some(read) => NativeMachine::read(read),
            None => NativeMachine::chards_own(&self.arch),
        }
    }
}

/// The spelling of the machine a kernel executes natively, with where it came from:
/// [`Kernel::machine`], read from `/proc/sys/kernel/arch`, or chard's own
/// `std::env::consts::ARCH` standing in where that file is absent.
///
/// The source decides what the spelling says about byte order. A read spelling is the
/// kernel's own word and names its order by the table in [`kernel_byte_order`], or names
/// none (`mips`); and a user-mode emulator reads the file through to the host's kernel, so
/// a read `aarch64` under a big-endian aarch64 chard is a little-endian kernel's. chard's
/// own `ARCH` names chard's own build's order, since without the file chard runs on the
/// kernel that answers, in either order a family has. The two are not one `&str`: a reader
/// that took chard's own order for any spelling equal to `ARCH`, a read one included, would
/// let a big-endian aarch64 chard under `qemu-aarch64_be` on a little-endian aarch64 kernel
/// read its own artifacts as native. Carrying the source with the spelling makes that
/// misreading unrepresentable: [`runs_natively`] and
/// [`kernel_byte_order`] take this value, and only [`Kernel::native_machine`] and the two
/// constructors make one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeMachine<'a> {
    spelling: &'a str,
    read: bool,
}

impl<'a> NativeMachine<'a> {
    /// A spelling read from `/proc/sys/kernel/arch`: the kernel's own word.
    #[must_use]
    pub const fn read(spelling: &'a str) -> Self {
        Self {
            spelling,
            read: true,
        }
    }

    /// chard's own `std::env::consts::ARCH`, standing in where the file is absent.
    #[must_use]
    pub const fn chards_own(spelling: &'a str) -> Self {
        Self {
            spelling,
            read: false,
        }
    }

    /// The spelling itself, as a reason names it.
    #[must_use]
    pub const fn spelling(&self) -> &'a str {
        self.spelling
    }

    /// Whether the spelling was read from `/proc/sys/kernel/arch`; false where it is
    /// chard's own `ARCH`.
    #[must_use]
    pub const fn was_read(&self) -> bool {
        self.read
    }
}

impl std::fmt::Display for NativeMachine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.spelling)
    }
}

/// Whether a kernel whose machine is `kernel` executes an ELF artifact whose `elf.machine`
/// is `artifact` and whose `elf_class` is `elf_class` itself, rather than handing it to a
/// `binfmt_misc` interpreter.
///
/// `kernel` is a `/proc/sys/kernel/arch` value or a Rust `ARCH` constant, each saying which
/// ([`NativeMachine`]), and `artifact` the reader's family name (`elf::machine_name`). The kernel's family is
/// `toolchain::machine_family`'s, the table the target gate reads, with the `i?86` and
/// `arm64` spellings a kernel uses and a triple does not; `elf.rs`'s
/// `every_named_machine_is_a_family_the_target_can_name` holds every machine the reader
/// names to a kernel spelling that runs it, so a native artifact of a named machine is
/// never withheld for want of a row.
///
/// The family is not the whole answer, because `EM_RISCV`, `EM_MIPS`, `EM_X86_64` and
/// `EM_S390` each cover both widths: an rv32 artifact on a riscv64 kernel, a mips o32 or n32
/// one on a mips64 kernel, and an x32 one on x86_64 name the kernel's family and are run, if
/// at all, by a compat option the kernel was or was not built with, or by `binfmt_misc`. So
/// the artifact's class is held to the kernel's own width ([`kernel_elf_class`]) as well,
/// and a mismatch reads `false`.
///
/// An x86_64 kernel runs i386 binaries itself, which rests on the register entry
/// `x86-64-kernel-runs-i386-itself` in `THREAT_MODEL.md`: IA32 emulation is a build and
/// boot option, and a `binfmt_misc` entry for i386 ELF would take the artifact first.
/// Every other kernel is held to its own family and width. An aarch64 kernel's `AArch32`
/// compat is CPU-dependent and a ppc64 kernel's 32-bit compat is the build option
/// `CONFIG_COMPAT`, which little-endian configurations leave off by default, so an `arm`
/// artifact on the first and a `ppc` one on the second read `false`: the reading it gates
/// is withheld, not published, when chard cannot tell.
///
/// The byte order is held too: `order` is the artifact's `EI_DATA`
/// ([`crate::elf::ElfFacts::elf_data`]) and the kernel's is [`kernel_byte_order`]'s. A
/// kernel parses an ELF header in its own order, so an artifact of the other order (ppc64 on
/// ppc64le, aarch64 on `aarch64_be`, either mips order on the other) fails its loader's
/// machine check and goes to `binfmt_misc`, which Fedora's qemu-user-static registers an
/// interpreter for in each order. Without the comparison such an artifact would read `true`
/// here.
///
/// `None` where the kernel is a machine the family table does not name (sparc64, m68k,
/// and the rest), where its read spelling carries no byte order (a `mips` or `mips64`
/// kernel, whatever chard's own build), or where the artifact's record carries no order
/// (a record without the field), each of which a caller reads as "cannot rule
/// emulation out". The reader names no artifact of the unnamed machines either, so on such
/// a kernel the `Machine` reading is withheld for a native artifact too: it costs the
/// reading, never publishes one.
#[must_use]
pub fn runs_natively(
    kernel: NativeMachine<'_>,
    artifact: &str,
    elf_class: u8,
    order: Option<ByteOrder>,
) -> Option<bool> {
    let own = match kernel.spelling() {
        "i386" | "i486" | "i586" | "i686" => "i386",
        "arm64" => "aarch64",
        other => crate::toolchain::machine_family(other)?,
    };
    let own_class = kernel_elf_class(kernel.spelling());
    let family_and_width = (artifact == own && elf_class == own_class)
        || (own == "x86_64" && artifact == "i386" && elf_class == 32);
    if !family_and_width {
        return Some(false);
    }
    Some(order? == kernel_byte_order(kernel)?)
}

/// The byte order of a kernel's own executables, from its machine's spelling and where the
/// spelling came from.
///
/// chard's own `std::env::consts::ARCH`, standing in where `/proc/sys/kernel/arch` is
/// absent ([`NativeMachine::chards_own`]), names chard's own build's order
/// (`cfg!(target_endian)`): chard then runs on the kernel that answers, in either order a
/// family has. A read spelling ([`NativeMachine::read`]) is the kernel's own word, and
/// chard's build says nothing about it, since under a user-mode emulator the file is the
/// host kernel's; what it says, in order: `_be` or `eb` at the end is big and `le` or `el`
/// little (`aarch64_be`, `armeb`, `mipseb`; `ppc64le`, `mipsel`, `mips64el`); an arm kernel
/// appends `l` or `b` to its `armv<N>` (`armv7l`, `armv7b`, `armv8b`), which is read next;
/// then the one order the family's Linux port runs without a suffix: x86, aarch64, arm,
/// riscv and loongarch little, `PowerPC` and s390 big. `mips` and `mips64` carry no order
/// (`uname -m` spells both orders alike), so a read one is `None` whatever chard's build:
/// the one case the spelling cannot decide, which [`runs_natively`] withholds on. The
/// whole table is the register entry `kernel-spelling-names-its-byte-order` in
/// `THREAT_MODEL.md`, which holds that the spelling names its byte
/// order: `armv7b` and `armv8b` read big.
#[must_use]
pub fn kernel_byte_order(kernel: NativeMachine<'_>) -> Option<ByteOrder> {
    let own = if cfg!(target_endian = "big") {
        ByteOrder::BigEndian
    } else {
        ByteOrder::LittleEndian
    };
    kernel_byte_order_as(kernel, own)
}

/// [`kernel_byte_order`] for a chard whose build's order is `own_order`: the rule with
/// chard's own identity as an argument, so a test on this host can hold what a big-endian
/// chard reads from a read `aarch64` (little, the kernel's word) and from its own `ARCH`
/// (big, its build).
#[must_use]
pub fn kernel_byte_order_as(kernel: NativeMachine<'_>, own_order: ByteOrder) -> Option<ByteOrder> {
    if !kernel.was_read() {
        return Some(own_order);
    }
    let kernel = kernel.spelling();
    let family = match kernel {
        "i386" | "i486" | "i586" | "i686" => Some("i386"),
        "arm64" => Some("aarch64"),
        other => crate::toolchain::machine_family(other),
    }?;
    if kernel.ends_with("_be") || kernel.ends_with("eb") {
        return Some(ByteOrder::BigEndian);
    }
    if kernel.ends_with("le") || kernel.ends_with("el") {
        return Some(ByteOrder::LittleEndian);
    }
    if family == "arm" {
        if kernel.ends_with('b') {
            return Some(ByteOrder::BigEndian);
        }
        if kernel.ends_with('l') {
            return Some(ByteOrder::LittleEndian);
        }
    }
    match family {
        "ppc" | "ppc64" | "s390" => Some(ByteOrder::BigEndian),
        "i386" | "x86_64" | "aarch64" | "arm" | "riscv" | "loongarch" => {
            Some(ByteOrder::LittleEndian)
        }
        _ => None,
    }
}

/// The ELF class of a kernel's own executables, from its machine's spelling: 64 where the
/// spelling carries the width (`x86_64`, `aarch64`, `arm64`, `ppc64le`, `riscv64`,
/// `mips64`, `loongarch64`, and Rust's `powerpc64`) or is `s390x`, which spells it with a
/// letter, and 32 otherwise (`i686`, `armv7l`, `ppc`, `mips`, `riscv32`, Rust's `x86`).
/// Only consulted where [`runs_natively`] found the spelling in its family table.
fn kernel_elf_class(kernel: &str) -> u8 {
    if kernel.contains("64") || kernel.starts_with("s390x") {
        64
    } else {
        32
    }
}

/// Every value [`detect_libc`] can put in `libc.impl`.
///
/// The vocabulary lived only as string literals inside that function, so nothing held it
/// against the schema and the two drifted: `openbsd` has been returnable for as long as
/// the OpenBSD arm has existed, and the schema's enum never listed it — the first OpenBSD
/// report would have failed its own conformance test. `uclibc` and `other` sat in the
/// schema in the other direction, declared and unreachable.
///
/// Not an enum, because `impl_name` is a `String` that feeds `toolchain.id` and
/// `report::libc_limitation`'s keying; the constant plus the two tests that bind it — one
/// scanning this file for names, one comparing against the schema — is what a closed
/// vocabulary buys without the refactor.
pub const LIBC_NAMES: &[&str] = &[
    "apple", "bionic", "freebsd", "glibc", "musl", "openbsd", "unknown",
];

/// The C library reading `environment.libc` publishes. Read back as written by the
/// consistency rule `fhardened-fortify-slot-disagrees-with-inputs` on read, which
/// recomputes the umbrella's fortify bar from it.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Libc {
    /// Serialized as `impl`, which is the schema's name for it; the Rust field
    /// carries a suffix only because `impl` is a keyword.
    #[serde(rename = "impl")]
    pub impl_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub detection: String,
}

impl Libc {
    /// The libc half of `toolchain.id`: implementation and version run together, as in
    /// `glibc2.43`, and the bare implementation name where no version was read.
    ///
    /// The libc is in the key because `musl-gcc` and `gcc` on one host produced the same
    /// id without it, and a join then merged two toolchains that disagree about six
    /// checks. Composed into the id by [`crate::toolchain::Detected::qualified`].
    /// `matrix::key_of` spells the same tag over a parsed report's `environment.libc`,
    /// and the unit test here pins this function to the strings that module's fixtures
    /// key on, so the two spellings are held to one another.
    #[must_use]
    pub fn tag(&self) -> String {
        match self.version.as_deref() {
            Some(v) => format!("{}{v}", self.impl_name),
            None => self.impl_name.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Cpu {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    pub relevant_features: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionMode {
    Host,
    Container,
    Vm,
}

impl ExecutionMode {
    pub const ALL: &'static [Self] = &[Self::Host, Self::Container, Self::Vm];

    /// Whether kernel-enforced properties measured here describe the distro
    /// named in this report. False under `Container`, where the kernel is the
    /// host's. Reads the mode alone, which `kernel.is_host_kernel` publishes;
    /// the `needs_vm` gate reads [`Execution::kernel_attribution`], the mode with
    /// its basis, since `host` by default describes no kernel in particular.
    pub fn kernel_is_representative(self) -> bool {
        !matches!(self, Self::Container)
    }

    /// The spelling the report publishes, which is also the one `run.id` hashes.
    ///
    /// One definition beside the serde attribute it has to agree with, so the id's
    /// input and the field a reader sees cannot part; a test holds the two equal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Container => "container",
            Self::Vm => "vm",
        }
    }
}

/// What established that the system measured is the image this report names.
///
/// The distinction this type exists to draw: `execution.image` is a string the operator
/// passed on the command line, and `environment.distro` is the running system's own
/// account of itself in `/etc/os-release`. Neither establishes that the artifact measured
/// came from the publisher's image, because a modified image reports whatever its
/// `os-release` was edited to say, and the label is whatever was typed.
///
/// Nothing observable from inside a booted system can close that gap. There is no
/// in-guest measurement that binds a running kernel to the file it booted from, so chard
/// cannot verify this and does not claim to. What it can do is carry the evidence
/// obtained *before* boot — by whatever fetched the image and checked it against the
/// publisher's manifest — into the report that depends on it, and say plainly that it is
/// an attestation received rather than a verification performed.
///
/// Without it the evidence would be real and simply elsewhere: a harness that verified
/// every image's digest against a published manifest and wrote the verdict to a file
/// beside the report would leave it outside the report, outside the dataset-identity join,
/// and absent from any published row, so every distribution attribution in the dataset
/// would rest on an operator-supplied label while the justification sat next door.
///
/// Where the disk that booted is not the artifact the fetcher verified but one installed
/// from it, the attestation also carries that disk's identity; see [`InstalledDisk`].
#[derive(Debug, Clone, Serialize)]
pub struct ImageAttestation {
    /// Which of the three cases this is.
    pub status: AttestationStatus,
    /// What a reader is being asked to trust, in words, because the status alone does
    /// not distinguish an attestation chard verified from one it recorded.
    pub established_by: &'static str,
    /// The fetcher's own verdict — `signature-verified`, `signed-unpinned`,
    /// `digest-matched`, `unverified` — kept because a digest matching a manifest served
    /// over TLS is weaker evidence than a digest under a signature, and collapsing the
    /// two would discard the difference.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
}

/// Which of the three cases an image's identity is in.
///
/// An enum rather than a string, because the three are a closed set and the crate already
/// spells closed sets this way — `Verdict` is an enum with an `ALL`. As a `&'static str`
/// this compiled with a typo in it and `dataset` matched against its own copies of the
/// spellings, so a rename in one file would have silently reclassified every row in the
/// other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationStatus {
    /// Measuring the running system: there is no image, so there is nothing to attest to.
    NotApplicable,
    /// An image was named and nothing carried in supports the name.
    Unattested,
    /// A fetcher's attestation was supplied and its digest matched.
    Attested,
}

impl AttestationStatus {
    /// Every status, so a consumer can enumerate them and a test can cover them all.
    pub const ALL: &'static [Self] = &[Self::NotApplicable, Self::Unattested, Self::Attested];

    /// The spelling used in the JSON, so other modules compare against this rather than
    /// against a second copy of the string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not-applicable",
            Self::Unattested => "unattested",
            Self::Attested => "attested",
        }
    }

    /// Whether this status means the image's identity was established. `false` for
    /// `Unattested`; `true` for `Attested` and for `NotApplicable`, where there is no
    /// image whose identity could be in question.
    pub fn is_established(self) -> bool {
        !matches!(self, Self::Unattested)
    }
}

/// Why an attestation could not be turned into a record.
///
/// Named cases rather than one string, so a caller can phrase each refusal for whoever can
/// act on it: the fetcher that produced a mismatch, or the invocation that contradicted
/// itself.
#[derive(Debug, Clone)]
pub enum AttestationRefusal {
    /// The fetcher reported that the image did not match the publisher's manifest.
    DigestMismatch(Box<Attestation>),
    /// An attestation was supplied for a run that booted no image.
    NoImageToAttest,
}

/// An attestation as received, recorded field-for-field rather than summarised.
///
/// Deliberately the fetcher's field names. A reader comparing a report against the
/// session file that produced it should see the same object, not a translation of it.
///
/// # Why the fields are private
///
/// Because the digest is checked on the way in. The one `Deserialize` impl routes every
/// deserialisation through `Attestation`'s `TryFrom<RawAttestation>`, which refuses a digest that is
/// not hex of the length its own `digest_kind` implies — so there is no way to hold an
/// `Attestation` whose digest is empty, truncated, or a sha256 labelled `sha512`. With
/// public fields that guarantee lasted until the next assignment.
///
/// This was not hypothetical. Before the check existed, an attestation carrying
/// `digest: ""` with `digest_matched: true` was recorded as `attested`: a report stating
/// that its image had been established, with no evidence in it at all. Validating and
/// then continuing to pass the wide type around is the demotion; parsing into a type that
/// cannot hold the bad value is the fix.
#[derive(Debug, Clone, Serialize)]
pub struct Attestation {
    verdict: String,
    url: String,
    served_by: String,
    /// How `url` came to be known: `recorded-at-fetch`, `confirmed-by-refetch`, or
    /// `not-recorded`.
    ///
    /// A URL in a provenance record reads as "these bytes were downloaded from here", and for
    /// the container lanes that was not true of any of them — nothing recorded a URL when the
    /// artifacts were obtained. Rather than invent one, the harness re-fetches the candidate to
    /// a scratch path and checks the digest, which establishes that the publisher *serves*
    /// identical bytes there without replacing the artifact or moving a measured row.
    ///
    /// That is genuinely weaker than the VM lane, where the fetcher records the URL as it
    /// downloads: a confirmed origin does not establish that this copy came from there. Two
    /// different strengths of the same field would otherwise be indistinguishable, which is the
    /// shape of every other defect this type exists to prevent.
    ///
    /// Absent in attestations written before the field existed, where it reads as
    /// `not-recorded` — the weakest reading, since those are the ones that carried a local path.
    #[serde(default = "not_recorded")]
    origin: String,
    manifest_url: String,
    digest_kind: String,
    digest: String,
    digest_matched: bool,
    /// Whether the publisher's manifest was retrieved at all.
    ///
    /// `digest_matched: false` carried two facts and chard read both as one. "The manifest
    /// said X and the image is Y" is a statement about the image and must be refused. "There
    /// was no manifest to compare against" is a statement about the *publisher's hosting* and
    /// says nothing about the bytes.
    ///
    /// openSUSE Tumbleweed is where that costs something. Its dated snapshot rotates out of
    /// the mirror after roughly two days, so the manifest 404s while the image on disk stays
    /// byte-identical to the one verified against that same manifest a day earlier. A
    /// refusal of all six openSUSE profiles with a message asserting the bytes did not match
    /// the publisher would be false. No re-fetch could fix it, because the file the message
    /// tells the operator to re-fetch does not exist.
    ///
    /// Defaults to `true` when the fetcher does not say, so an attestation without the
    /// field reads as one whose manifest was fetched.
    #[serde(default = "yes")]
    manifest_fetched: bool,
    signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    caveat: Option<String>,
    /// The disk that booted, when it is not the artifact `digest` names but one installed
    /// from it. Absent, not null, when the verified artifact is itself what booted.
    #[serde(skip_serializing_if = "Option::is_none")]
    installed_disk: Option<InstalledDisk>,
}

/// A disk installed from the attested artifact, identified by its own digest.
///
/// The harness builds its Alpine guests by running the publisher's installer ISO, which is
/// what the publisher signed and so what `digest` and `verdict` describe. The disk that then
/// boots is signed by nobody; the harness hashes it after the install and re-hashes it
/// before every boot against the record it wrote. Before this field existed that record
/// reached a report only as prose in `caveat`, which `run.inputs_sha256` does not hash, so
/// two installs of `alpine-edge` on different days (different package sets, the same ISO)
/// produced reports with identical input digests. As structured fields it is hashed: two
/// different installed disks give two different `run.inputs_sha256`, and a report with no
/// installed disk digests exactly as it did before (`report::inputs_of`).
///
/// Like [`Attestation`], received rather than verified: chard runs inside the installed
/// system and cannot hash the disk it booted from. What it does check is that the record
/// agrees with itself: `installed_from_digest` must be the attestation's own `digest`, so
/// a disk record cannot be attached to an attestation for some other image.
#[derive(Debug, Clone, Serialize)]
pub struct InstalledDisk {
    /// SHA-256 of the installed disk image as the harness recorded it after installing.
    sha256: String,
    /// When the installer started, UTC, `YYYY-MM-DDTHH:MM:SSZ`. For a rolling branch this
    /// dates every package the installer fetched.
    installed_at: String,
    /// The digest, in the attestation's own `digest_kind`, of the artifact installed from.
    installed_from_digest: String,
}

/// [`InstalledDisk`] as it appears on disk, before it is checked. Unknown keys are refused,
/// because a misspelled key in a record that exists to be hashed would drop out silently.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInstalledDisk {
    sha256: String,
    installed_at: String,
    installed_from_digest: String,
}

/// Whether `text` is a real instant written `YYYY-MM-DDTHH:MM:SSZ`, the one shape
/// [`crate::report::iso8601_utc`] emits.
///
/// Shape alone is not enough. The field is published under a schema declaring
/// `format: date-time`, and `2026-13-45T25:61:61Z` has the shape while being no instant at
/// all: a shape-only check let chard publish a report that a standard RFC 3339 validator
/// rejects against chard's own schema. So each field is range-checked, the day against its
/// month's length in the proleptic Gregorian calendar. A second of 60, which RFC 3339
/// permits for a leap second, is refused: `iso8601_utc` cannot emit one, and neither can
/// the harness's clock, so one arriving here was not written by either.
fn is_utc_timestamp(text: &str) -> bool {
    const SHAPE: &[u8; 20] = b"dddd-dd-ddTdd:dd:ddZ";
    let shaped = text.len() == SHAPE.len()
        && text.bytes().zip(SHAPE).all(|(got, want)| match want {
            b'd' => got.is_ascii_digit(),
            _ => got == *want,
        });
    if !shaped {
        return false;
    }
    // Every slice below is ASCII digits by the shape check, so each fold succeeds; the
    // absent arm cannot occur, and `u32::MAX` would fail every range check below if it did.
    let field = |range: std::ops::Range<usize>| {
        text.get(range)
            .and_then(|digits| {
                digits
                    .chars()
                    .try_fold(0u32, |n, c| n.checked_mul(10)?.checked_add(c.to_digit(10)?))
            })
            .unwrap_or(u32::MAX)
    };
    let (year, month, day) = (field(0..4), field(5..7), field(8..10));
    let (hour, minute, second) = (field(11..13), field(14..16), field(17..19));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_length = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=month_length).contains(&day) && hour < 24 && minute < 60 && second < 60
}

impl TryFrom<RawInstalledDisk> for InstalledDisk {
    type Error = String;

    fn try_from(raw: RawInstalledDisk) -> Result<Self, Self::Error> {
        if raw.sha256.len() != 64 || !raw.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "installed_disk.sha256 `{}` is not sixty-four hex digits",
                raw.sha256
            ));
        }
        if !is_utc_timestamp(&raw.installed_at) {
            return Err(format!(
                "installed_disk.installed_at `{}` is not YYYY-MM-DDTHH:MM:SSZ",
                raw.installed_at
            ));
        }
        if raw.installed_from_digest.is_empty()
            || !raw
                .installed_from_digest
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err(format!(
                "installed_disk.installed_from_digest `{}` is not hex",
                raw.installed_from_digest
            ));
        }
        Ok(Self {
            sha256: raw.sha256.to_ascii_lowercase(),
            installed_at: raw.installed_at,
            installed_from_digest: raw.installed_from_digest.to_ascii_lowercase(),
        })
    }
}

impl InstalledDisk {
    /// The installed disk's SHA-256.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// When it was installed.
    pub fn installed_at(&self) -> &str {
        &self.installed_at
    }

    /// The digest of the artifact it was installed from.
    pub fn installed_from_digest(&self) -> &str {
        &self.installed_from_digest
    }
}

/// Deserialise `T` from a JSON object and nothing else.
///
/// serde's derive reads a struct from a sequence as well as a map, field by field in
/// declaration order, and `deny_unknown_fields` does not reach that path: there are no keys
/// to refuse. So `["v","u","s",...]` parsed as an [`Attestation`], and a writer with another
/// field order would have had its strings assigned to one another's fields without a word,
/// the silent reinterpretation `deny_unknown_fields` refuses for keys. The schema publishes
/// both records as objects. Asking the deserializer for a map, and handing the derive only
/// the map it yields, leaves an array nothing to be read as. The `attestation` fuzz target's
/// shape oracle holds this over a hand-written array, which mutation from the object seeds
/// does not produce.
fn from_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    struct ObjectOnly<T>(std::marker::PhantomData<T>);

    impl<'de, T: serde::Deserialize<'de>> serde::de::Visitor<'de> for ObjectOnly<T> {
        type Value = T;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(ObjectOnly(std::marker::PhantomData))
}

impl<'de> serde::Deserialize<'de> for Attestation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: RawAttestation = from_object(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

impl<'de> serde::Deserialize<'de> for InstalledDisk {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: RawInstalledDisk = from_object(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

/// `serde(default)` for a bool that must default to `true`.
fn yes() -> bool {
    true
}

/// `serde(default)` for `origin`: the weakest reading, for attestations predating the field.
fn not_recorded() -> String {
    "not-recorded".to_owned()
}

/// The attestation exactly as it appears on disk, before the digest is checked.
///
/// Exists only as [`Attestation`]'s deserialisation target. Keeping it separate is what
/// makes the refinement unavoidable: there is no `Deserialize` for `Attestation` that
/// skips `try_from`. It is read through [`from_object`], so only from a JSON object.
///
/// Unknown keys are refused. An attestation is hashed into `run.inputs_sha256`, so a key
/// this build does not know is a part of the input it would drop without a trace. A
/// reader that dropped `installed_disk` would publish `attested` with the digest of a
/// report made without it, the collision the field exists to remove. Refusing makes a
/// reader fail loudly on a newer writer, and the harness also checks the published report
/// for the disk record it supplied. Both attestation writers (the VM lane's
/// `ImageProvenance` and `attest-containers.py`) write only keys named here, and every
/// attestation fed in a fleet sweep and the 2026-09-30 catalogue evidence parses under the
/// refusal: 151 fed, 151 parsed.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAttestation {
    verdict: String,
    url: String,
    served_by: String,
    #[serde(default = "not_recorded")]
    origin: String,
    manifest_url: String,
    digest_kind: String,
    digest: String,
    digest_matched: bool,
    #[serde(default = "yes")]
    manifest_fetched: bool,
    signature: String,
    signer: Option<String>,
    caveat: Option<String>,
    installed_disk: Option<InstalledDisk>,
}

/// Hex digest lengths for the algorithms a publisher's manifest actually uses.
///
/// A digest of the wrong length for its own `digest_kind` is not a near miss. It means the
/// two fields came from different places, and an attestation whose fields disagree with
/// each other establishes nothing. Without this table a sha256 labelled `sha512` would be
/// accepted.
const DIGEST_LENGTHS: &[(&str, usize)] = &[
    ("md5", 32),
    ("sha1", 40),
    ("sha256", 64),
    ("sha384", 96),
    ("sha512", 128),
    ("blake2b", 128),
];

impl TryFrom<RawAttestation> for Attestation {
    type Error = String;

    fn try_from(raw: RawAttestation) -> Result<Self, Self::Error> {
        let kind = raw.digest_kind.to_ascii_lowercase();
        let Some((_, expected)) = DIGEST_LENGTHS.iter().find(|(name, _)| *name == kind) else {
            return Err(format!(
                "digest_kind `{}` is not one this reads; known: {}",
                raw.digest_kind,
                DIGEST_LENGTHS
                    .iter()
                    .map(|(n, _)| *n)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        };
        if raw.digest.len() != *expected {
            return Err(format!(
                "digest is {} characters, but {kind} is {expected}: an attestation whose \
                 digest and digest_kind disagree establishes nothing",
                raw.digest.len()
            ));
        }
        if !raw.digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("digest `{}` is not hex", raw.digest));
        }
        let digest = raw.digest.to_ascii_lowercase();
        if let Some(disk) = &raw.installed_disk
            && disk.installed_from_digest != digest
        {
            return Err(format!(
                "installed_disk.installed_from_digest is {}, but this attestation's digest \
                 is {digest}: a disk installed from another artifact is not derived from \
                 the one attested here",
                disk.installed_from_digest
            ));
        }
        Ok(Self {
            verdict: raw.verdict,
            url: raw.url,
            served_by: raw.served_by,
            origin: raw.origin,
            manifest_url: raw.manifest_url,
            digest_kind: raw.digest_kind,
            digest,
            digest_matched: raw.digest_matched,
            manifest_fetched: raw.manifest_fetched,
            signature: raw.signature,
            signer: raw.signer,
            caveat: raw.caveat,
            installed_disk: raw.installed_disk,
        })
    }
}

impl Attestation {
    /// Parse an attestation from JSON, refusing one whose digest does not match its own
    /// `digest_kind`.
    ///
    /// # Errors
    ///
    /// When the text is not JSON, is missing a field, carries a key this build does not
    /// know, or carries a digest that is not hex of the length its algorithm implies.
    pub fn from_json(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|e| e.to_string())
    }

    /// Where the bytes were fetched from, for a refusal message.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The manifest the digest was compared against, for a refusal message.
    pub fn manifest_url(&self) -> &str {
        &self.manifest_url
    }

    /// The digest algorithm, for a refusal message.
    pub fn digest_kind(&self) -> &str {
        &self.digest_kind
    }

    /// The digest itself, for a refusal message.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The disk installed from the attested artifact, when that is what booted.
    pub fn installed_disk(&self) -> Option<&InstalledDisk> {
        self.installed_disk.as_ref()
    }
}

impl ImageAttestation {
    /// No image: the running system is the specimen and there is nothing to attest to.
    fn not_applicable() -> Self {
        Self {
            status: AttestationStatus::NotApplicable,
            established_by: "measuring the running system; no image is involved",
            attestation: None,
        }
    }

    /// An image was named and nothing supports the name.
    fn unattested() -> Self {
        Self {
            status: AttestationStatus::Unattested,
            established_by: "nothing: the image is an operator-supplied label, and the \
                             distribution named in this report is the running system's \
                             own claim about itself",
            attestation: None,
        }
    }

    /// Unattested because the publisher's manifest could not be retrieved.
    ///
    /// Same status as having no attestation at all — nothing established the image either way
    /// — but not the same situation, and the difference is actionable. "Nobody supplied one"
    /// is fixed by supplying one. "The publisher no longer serves the manifest this image was
    /// fetched against" cannot be fixed by the operator at all, and a reader deciding whether
    /// to trust the row needs to know which they are looking at. The fetcher's record is kept
    /// so its caveat — the HTTP status, usually — survives into the report.
    fn unattested_no_manifest(attestation: Attestation) -> Self {
        Self {
            status: AttestationStatus::Unattested,
            established_by: "nothing: the publisher's manifest could not be retrieved, so the \
                             image's digest was computed but never compared against anything. \
                             The fetcher's own record is kept below, including why the fetch \
                             failed",
            attestation: Some(attestation),
        }
    }

    fn attested(attestation: Attestation) -> Self {
        let established_by = if attestation.installed_disk.is_some() {
            "the fetcher that obtained the image checked it against the publisher's \
             manifest before boot, and the disk that booted was installed from it; the \
             disk is identified by installed_disk, which only the fetcher's install record \
             binds to the image. Both recorded as received and not re-verified from inside, \
             which no in-guest measurement can do"
        } else {
            "the fetcher that obtained the image checked it against the \
             publisher's manifest before boot; recorded as received and \
             not re-verified from inside, which no in-guest measurement \
             can do"
        };
        Self {
            status: AttestationStatus::Attested,
            established_by,
            attestation: Some(attestation),
        }
    }

    /// Classify an attestation, or the absence of one, for `mode`.
    ///
    /// Total over the whole domain: three modes by three attestation shapes. Written as a
    /// `match` on the pair rather than as guards on one of them, because the pair is what
    /// decides. A wrong cell is a totality defect that no compiler reports: a `match` that
    /// sent `(Host, Some(_))` to `attested` would compile and be exhaustive, and measuring
    /// the running system while passing an attestation would publish a report claiming its
    /// image had been established while naming no image at all.
    ///
    /// # Errors
    ///
    /// [`AttestationRefusal::DigestMismatch`] when the fetcher reported the image did not
    /// match the publisher's manifest — publishing that would attach a distribution's name
    /// to bytes known not to be that distribution's. [`AttestationRefusal::NoImageToAttest`]
    /// when an attestation was supplied for a run that booted no image, which is a
    /// contradiction in the invocation rather than a property of the specimen.
    pub fn classify(
        mode: ExecutionMode,
        attestation: Option<Attestation>,
    ) -> Result<Self, AttestationRefusal> {
        match (mode, attestation) {
            // Compared, and disagreed. A statement about the bytes: refuse.
            (_, Some(a)) if !a.digest_matched && a.manifest_fetched => {
                Err(AttestationRefusal::DigestMismatch(Box::new(a)))
            }
            // Never compared, because the publisher no longer serves the manifest. That is
            // exactly the evidential position of having no attestation at all, so it takes
            // the same status and the same caution — and not a refusal asserting the image
            // is not the publisher's, which is a claim nothing here supports.
            (ExecutionMode::Container | ExecutionMode::Vm, Some(a)) if !a.manifest_fetched => {
                Ok(Self::unattested_no_manifest(a))
            }
            (ExecutionMode::Host, Some(_)) => Err(AttestationRefusal::NoImageToAttest),
            (ExecutionMode::Container | ExecutionMode::Vm, Some(a)) => Ok(Self::attested(a)),
            (ExecutionMode::Host, None) => Ok(Self::not_applicable()),
            (ExecutionMode::Container | ExecutionMode::Vm, None) => Ok(Self::unattested()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Execution {
    pub mode: ExecutionMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    pub detection: String,
    /// What chard observed about the mode, beside what it was told. Present
    /// unconditionally, for the same reason the attestation is.
    pub mode_evidence: ModeEvidence,
    /// Present unconditionally, including when nothing was attested. An omitted field
    /// would read as "nothing to report" when what is being reported is precisely that
    /// nothing established the image. That is the hazard of a `contradictions` list
    /// skipped when empty, where absence would read as self-consistency.
    pub image_attestation: ImageAttestation,
}

/// Whose kernel a reading that needs a kernel of its own (`needs_vm`) would describe, from
/// `execution.mode` and how it was arrived at.
///
/// The mode alone is not enough. `host` is also what chard records when nothing settled the
/// mode and nobody said: on a bare host or a VM guest, which own their kernel, and in a
/// container chard has no instrument for (Apptainer, mock, a chroot, a runtime that writes
/// no `/run/systemd/container` and sets no `container=` on PID 1, or one whose PID 1
/// environment this user may not read), since nothing chard reads from inside tells that
/// container from a system that owns its kernel. A VM guest is not told from a bare host
/// either: the CPUID hypervisor bit and DMI strings would tell most apart, but chard reads
/// neither, and the gate does not need them told apart. A `needs_vm` gate that read the mode
/// and measured under that default would let an unrecognised container publish the host
/// kernel's policy under the distribution's name; the reading would be true of the kernel
/// that ran it, and the error would be the attribution. Derived here, in
/// one place, so the gate cannot read the evidence another way than the record states it.
/// `Established` rests on the operator's word alone: chard observes `container` and nothing
/// else, which `env::tests` holds, and the register entry
/// `asserted-mode-names-the-kernels-owner` carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelAttribution<'a> {
    /// The measured system's own: the operator asserted `host` or `vm` (`--execution`).
    Established,
    /// Another system's: a container, observed or asserted.
    Borrowed,
    /// Unsettled: `host` by default, with what chard looked at and found.
    Assumed {
        /// `mode_evidence.observation`, which the withholding reason quotes.
        observation: &'a str,
    },
}

impl Execution {
    /// See [`KernelAttribution`].
    #[must_use]
    pub fn kernel_attribution(&self) -> KernelAttribution<'_> {
        KernelAttribution::of(
            self.mode,
            self.mode_evidence.basis,
            &self.mode_evidence.observation,
        )
    }
}

impl<'a> KernelAttribution<'a> {
    /// The attribution of `mode` established on `basis`, quoting `observation` where it is
    /// unsettled. [`Execution::kernel_attribution`] at measurement, and
    /// `report::reread_contradictions` over a report's published mode and basis, both call
    /// this, so the field and its re-check on read cannot part.
    #[must_use]
    pub fn of(mode: ExecutionMode, basis: ModeBasis, observation: &'a str) -> Self {
        match (mode, basis) {
            (ExecutionMode::Container, _) => KernelAttribution::Borrowed,
            (ExecutionMode::Host | ExecutionMode::Vm, ModeBasis::AssumedHost) => {
                KernelAttribution::Assumed { observation }
            }
            (
                ExecutionMode::Host | ExecutionMode::Vm,
                ModeBasis::Measured
                | ModeBasis::AssertedAndCorroborated
                | ModeBasis::AssertedButUnobservable
                | ModeBasis::AssertedAndContradicted,
            ) => KernelAttribution::Established,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Environment {
    pub distro: Distro,
    pub kernel: Kernel,
    pub libc: Libc,
    pub cpu: Cpu,
    pub execution: Execution,
}

#[cfg(target_os = "linux")]
fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
}

/// What reading a file yielded, where the file's absence and a refusal to read it mean
/// different things in the sentence a run publishes.
///
/// The `Option<String>` reads of [`PlatformReads`] conflate the two, and for them that is
/// right: a `/proc/1/cgroup` that is not there and one that refuses both leave the
/// instrument silent. The two positive container markers are read as systemd reads its own
/// (`detect_container` in its `src/basic/virt.c`): content alone settles anything, and a
/// refusal is named as a refusal rather than read as absence. `/proc/1/environ` is readable
/// only as root or PID 1's user, so an ordinary user's run on a bare host reads a refusal, and
/// a sentence that said "no `container=` word" of a file it could not open would be false. A
/// refusal does not show the path exists: a parent this user may not search, a non-directory
/// in the path and a symlink loop all read the same, so `Unreadable` claims nothing about
/// presence, and nothing settles on it.
///
/// Public, with [`read_file`], so `tests/platform_reads.rs` holds the classification on real
/// paths through the suite's ledger; the builds for the other platforms construct none of it,
/// since their reads carry `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileRead {
    /// Nothing is at the path (a symlink to nowhere included).
    Absent,
    /// The read failed for a reason other than absence; the error's kind and number. Says
    /// nothing about whether the path exists.
    Unreadable(String),
    /// The file's content, as read.
    Content(String),
}

/// systemd's marker of a container it detected: written by systemd as PID 1 from its own
/// non-empty `container=` word, world-readable (`write_container_id` in its `src/core/main.c`).
pub const SYSTEMD_CONTAINER_MARKER: &str = "/run/systemd/container";

/// PID 1's environment, where a container runtime sets `container=`; readable as root or
/// PID 1's user.
pub const PID1_ENVIRON: &str = "/proc/1/environ";

/// The error's kind and number as words for a published sentence, `permission denied, os
/// error 13`: the kind's own spelling, the same whatever the locale.
#[cfg(target_os = "linux")]
fn refusal_words(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => format!("{}, os error {code}", e.kind()),
        None => e.kind().to_string(),
    }
}

/// Read a marker file into a [`FileRead`]: absence from `ENOENT` alone, content from a
/// readable file, and `Unreadable` from everything else.
#[cfg(target_os = "linux")]
pub fn read_file(path: &str) -> FileRead {
    match std::fs::read(path) {
        Ok(bytes) => FileRead::Content(String::from_utf8_lossy(&bytes).into_owned()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileRead::Absent,
        Err(e) => FileRead::Unreadable(refusal_words(&e)),
    }
}

/// How many characters of a planted value a published sentence quotes.
const QUOTED_VALUE_MAX: usize = 64;

/// A marker's value as a sentence quotes it: in backticks, with backticks escaped and every
/// character that does not print as itself escaped by `char::escape_debug` (a newline reads
/// `\n`, an escape `\u{1b}`, a right-to-left override `\u{202e}`, a line separator
/// `\u{2028}`, a backslash `\\`, so a planted `\u{1b}` reads apart from an escape), and cut at
/// [`QUOTED_VALUE_MAX`] characters with the cut said. The two quotes, which print as
/// themselves inside backticks, are kept as written. The value names a container
/// manager; anything longer or stranger was planted by the container's owner for a reader of
/// the report or of the terminal the refusal prints to, and a format character would turn
/// the sentence around it as displayed.
fn quoted(value: &str) -> String {
    let mut out = String::from("`");
    let mut chars = value.chars();
    for c in chars.by_ref().take(QUOTED_VALUE_MAX) {
        match c {
            '`' => out.push_str("\\`"),
            '\'' | '"' => out.push(c),
            c if c.escape_debug().nth(1).is_some() => out.extend(c.escape_debug()),
            c => out.push(c),
        }
    }
    out.push('`');
    let cut = chars.count();
    if cut == 0 {
        out
    } else {
        format!("{out} ({cut} more characters cut)")
    }
}

/// What each host instrument yielded, gathered before anything interprets it.
///
/// The point of the indirection is testability, not tidiness. Every instrument chard has
/// for describing its environment is a Linux file, and a port cannot be checked on a box
/// that does not exist. Collecting the raw text first makes the platform difference a
/// **value** — `PlatformReads::default()` is precisely what an OS with none of these
/// instruments produces — so the derived `Environment` is exercisable here, on Linux,
/// rather than only on the target.
///
/// `None` means the instrument could not be read, which is not the same as reading empty.
/// Conflating those is what published a false `is_host_kernel`.
///
/// Public, with its fields and [`observe_execution_mode`], so the `env_reads` fuzz target
/// (`fuzz/fuzz_targets/env_reads.rs`) can hand the observer reads no host has; chard itself
/// builds one only in `platform_reads`.
#[derive(Debug, Default, Clone)]
pub struct PlatformReads {
    pub os_release: Option<String>,
    pub cpuinfo: Option<String>,
    pub kernel_release: Option<String>,
    /// `/proc/sys/kernel/arch`, the kernel's own machine; see [`Kernel::machine`]. Not
    /// mode-bearing, so [`PlatformReads::is_barren`] does not consult it.
    pub kernel_machine: Option<String>,
    pub pid1_comm: Option<String>,
    pub uid_map: Option<String>,
    pub pid1_cgroup: Option<String>,
    /// The container runtime's own marker file, if one is present.
    pub container_marker: Option<&'static str>,
    /// [`SYSTEMD_CONTAINER_MARKER`], which systemd as PID 1 writes only inside a container
    /// it detected, from its own non-empty `container=` word, naming the manager
    /// (`systemd-nspawn`, `lxc`, `podman`, `docker`): content settles `container`; an empty
    /// file, a refusal and absence settle nothing. `None` where the platform has no such
    /// path to read.
    pub systemd_container: Option<FileRead>,
    /// [`PID1_ENVIRON`], where a container runtime sets `container=` on PID 1
    /// (`systemd-nspawn`, `lxc`; podman sets `oci`). Readable only as root or PID 1's
    /// user, so an ordinary user's run reads a refusal, which [`FileRead`] tells apart
    /// from a read that carries no such word. `None` where the platform has no such path
    /// to read.
    pub pid1_environ: Option<FileRead>,
    /// macOS's `SystemVersion.plist`, which is that platform's `os-release`.
    pub system_version: Option<String>,
}

impl PlatformReads {
    /// Whether no instrument bearing on the *execution mode* answered at all.
    ///
    /// Distinct from every field being individually absent by accident: on a platform
    /// with none of these files this is the *expected* state, and the execution-mode
    /// observer must not read a barren set as evidence of a bare host.
    ///
    /// `system_version` is deliberately not consulted. It identifies the OS release and
    /// says nothing about containment, and counting it would send macOS past the guard
    /// below into the container checks — which would still conclude nothing, but would
    /// report having found no container marker and no user namespace on a platform where
    /// chard has neither instrument to look with. The verdict would stay honest and the
    /// sentence explaining it would not.
    fn is_barren(&self) -> bool {
        self.os_release.is_none()
            && self.cpuinfo.is_none()
            && self.kernel_release.is_none()
            && self.pid1_comm.is_none()
            && self.uid_map.is_none()
            && self.pid1_cgroup.is_none()
            && self.container_marker.is_none()
            && self.systemd_container.is_none()
            && self.pid1_environ.is_none()
    }
}

#[cfg(target_os = "linux")]
fn platform_reads() -> PlatformReads {
    PlatformReads {
        // The vendor copy survives an empty /etc, which some minimal images ship with.
        os_release: std::fs::read_to_string("/etc/os-release")
            .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
            .ok(),
        cpuinfo: std::fs::read_to_string("/proc/cpuinfo").ok(),
        kernel_release: read_trimmed("/proc/sys/kernel/osrelease"),
        kernel_machine: read_trimmed("/proc/sys/kernel/arch").filter(|m| !m.is_empty()),
        pid1_comm: read_trimmed("/proc/1/comm"),
        uid_map: read_trimmed("/proc/self/uid_map"),
        pid1_cgroup: read_trimmed("/proc/1/cgroup"),
        container_marker: [
            ("/run/.containerenv", "podman marker /run/.containerenv"),
            ("/.dockerenv", "docker marker /.dockerenv"),
        ]
        .into_iter()
        .find(|(path, _)| Path::new(path).exists())
        .map(|(_, why)| why),
        systemd_container: Some(read_file(SYSTEMD_CONTAINER_MARKER)),
        pid1_environ: Some(read_file(PID1_ENVIRON)),
        // Darwin's, and deliberately not probed for on Linux: a path that cannot exist
        // here would be a read per run to learn nothing.
        system_version: None,
    }
}

/// OpenBSD has none of these instruments, and that is the honest answer rather than a
/// gap to be filled with plausible values.
///
/// There is no `/proc` at all — it was removed — and no `/etc/os-release`. The facts do
/// exist behind `sysctl(3)`, but reaching them would mean either a `libc` dependency,
/// against the four-crate floor, or a third spawn site, against the pin in
/// `compile.rs` that keeps child processes to the compiler and the probe. Neither is
/// worth it for provenance fields: every one of these already reports `unknown`
/// already, because Linux images exist where the read fails too.
///
/// What chard actually measures — the compiler, and the artifacts it emits — needs none
/// of this. See `ENVIRONMENT.md`... deliberately not written; the register entry
/// `openbsd-environment-unobserved` in `THREAT_MODEL.md` carries what would retire this.
#[cfg(target_os = "openbsd")]
fn platform_reads() -> PlatformReads {
    PlatformReads::default()
}

/// FreeBSD carries `/etc/os-release` and none of the rest.
///
/// It is ELF, so the artifact channel works unchanged; what is missing is the Linux
/// procfs. `procfs` exists but is deprecated and unmounted by default, so reading it
/// would describe the few systems that opt in and nothing else. The kernel release and
/// CPU are behind `sysctl(3)`, which costs either a fifth crate or a third child-process
/// spawn — the same trade recorded for OpenBSD in `openbsd-environment-unobserved`.
///
/// Jails are the container analogue and are not detected: `security.jail.jailed` is a
/// sysctl, so the honest answer is the same `assumed-host` a bare Linux host gets, and
/// `mode_evidence.basis` says which.
#[cfg(target_os = "freebsd")]
fn platform_reads() -> PlatformReads {
    PlatformReads {
        os_release: std::fs::read_to_string("/etc/os-release").ok(),
        ..PlatformReads::default()
    }
}

/// macOS has one of these instruments, and it is not a Linux one.
///
/// The artifact channel reads ELF and macOS produces Mach-O, so those checks meet a reader
/// that rejects the magic. What runs there is the `macro` and `compiler-diag` channels
/// against Apple clang, and that has been exercised across nine rounds on Apple clang 21 /
/// arm64 — it is where `_USE_FORTIFY_LEVEL`, the `__DATA` section syntax and the
/// branch-protection macros were established.
///
/// `SystemVersion.plist` is that platform's `os-release`, and reading it is what gives a
/// Darwin report an identity: without it every Mac at a given clang version produced the
/// same `toolchain.id`, which is the key reports are joined on. Nothing else here has an
/// instrument — no `/proc`, and the kernel release and CPU are behind `sysctl(3)`, the same
/// trade recorded for OpenBSD in `openbsd-environment-unobserved`.
#[cfg(target_os = "macos")]
fn platform_reads() -> PlatformReads {
    PlatformReads {
        system_version: std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist")
            .ok(),
        ..PlatformReads::default()
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "macos"
)))]
compile_error!(
    "chard has no environment implementation for this target_os. Add a `platform_reads` \
     arm in src/env.rs rather than letting the build fall through to Linux defaults: a \
     report that names a distribution, a kernel and an execution mode it never observed \
     is not a thing chard emits."
);

/// Parse `os-release` shell-assignment syntax, stripping optional quotes.
///
/// A key whose value is empty once unquoted is left out, so every reader sees it as
/// absent. Fedora ships `VERSION_CODENAME=""`, and carrying that through as `Some("")`
/// would publish `codename: ""`: an empty string in a populated field, which a join key
/// assembled by concatenating the distro fields reads as a value and renders as a doubled
/// separator. An empty assignment and a missing one carry the same information, so they
/// get the same representation, and the `UBUNTU_CODENAME` fallback in [`distro_from`]
/// then reaches a derivative that writes the primary key empty. The same rule reaches
/// `VERSION_ID`: an empty `VERSION_ID=` reads as a missing key, which [`distro_from`]
/// records as `rolling`, the reading a file that omits the version already earns.
fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim().trim_matches('"').trim_matches('\'');
            if value.is_empty() {
                continue;
            }
            out.insert(key.trim().to_owned(), value.to_owned());
        }
    }
    out
}

/// The distribution, from `/etc/os-release`, the vendor copy at `/usr/lib/os-release`, or
/// — where neither exists — macOS's `SystemVersion.plist`.
pub fn detect_distro() -> Distro {
    let reads = platform_reads();
    match (reads.os_release.as_deref(), reads.system_version.as_deref()) {
        (Some(text), _) => distro_from(Some(text)),
        (None, Some(plist)) => distro_from_system_version(plist),
        (None, None) => distro_from(None),
    }
}

/// macOS's equivalent of `os-release`, and the only instrument on that platform that
/// distinguishes one machine's report from another's.
///
/// Nine rounds of Darwin reports carried `distro: unknown / unknown`, which made
/// `toolchain.id` — the key reports are joined on — identical for every Mac at a given
/// clang version. Two machines running different OS releases produced the same join key,
/// so a dataset could merge them and nothing would say so.
///
/// A file read, in the same class as `/etc/os-release`: no `sw_vers`, no third spawn site,
/// no fifth crate. If the path is wrong or the file is unreadable the result is the
/// `unknown` this already reported, so the failure mode is today's behaviour rather than a
/// fabricated one.
fn distro_from_system_version(plist: &str) -> Distro {
    let field = |key: &str| plist_string(plist, key);
    let name = field("ProductName");
    let version = field("ProductVersion");
    let build = field("ProductBuildVersion");
    Distro {
        // Lowercased to sit beside os-release `ID` values, which are lowercase by that
        // spec: `macos` reads the way `fedora` and `debian` do in the same field.
        id: name
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), |n| n.to_lowercase()),
        // `unknown` rather than `rolling` when the version is missing: the os-release arm
        // reads a missing VERSION_ID as a rolling release because Arch means it that way,
        // and macOS does not.
        version_id: version.clone().unwrap_or_else(|| "unknown".to_owned()),
        // The build is what separates two machines on the same release, so it goes in the
        // one field that carries free text rather than being dropped.
        pretty_name: match (&name, &version, &build) {
            (Some(n), Some(v), Some(b)) => Some(format!("{n} {v} ({b})")),
            (Some(n), Some(v), None) => Some(format!("{n} {v}")),
            _ => None,
        },
        codename: None,
    }
}

/// The `<string>` following `<key>NAME</key>` in an XML property list.
///
/// Scoped deliberately at "enough for SystemVersion.plist": that file is a flat
/// `dict` of string values, so a full plist parser would be a dependency bought to read
/// three keys. Returns `None` for anything it does not recognise, which is the same answer
/// an absent file gives.
fn plist_string(plist: &str, key: &str) -> Option<String> {
    let marker = format!("<key>{key}</key>");
    let after = plist.split_once(&marker)?.1;
    let open = after.find("<string>")?;
    let rest = after.get(open.saturating_add("<string>".len())..)?;
    let close = rest.find("</string>")?;
    let value = rest.get(..close)?.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// `None` -- no os-release at all -- is a different fact from an os-release without a
/// `VERSION_ID`, and the two are kept apart.
///
/// A file present but silent about its version is Arch and the other rolling releases, so
/// `rolling` is a real reading there. A file that does not exist says nothing about the
/// release model, and answering `rolling` for it asserts one. On Linux that case is a
/// stripped image; on an OS with no os-release it is every run.
fn distro_from(text: Option<&str>) -> Distro {
    let Some(text) = text else {
        return Distro {
            id: "unknown".to_owned(),
            version_id: "unknown".to_owned(),
            pretty_name: None,
            codename: None,
        };
    };
    let fields = parse_os_release(text);
    Distro {
        id: fields
            .get("ID")
            .cloned()
            .unwrap_or_else(|| "unknown".to_owned()),
        version_id: fields
            .get("VERSION_ID")
            .cloned()
            .unwrap_or_else(|| "rolling".to_owned()),
        pretty_name: fields.get("PRETTY_NAME").cloned(),
        codename: fields
            .get("VERSION_CODENAME")
            .or_else(|| fields.get("UBUNTU_CODENAME"))
            .cloned(),
    }
}

fn detect_cpu() -> Cpu {
    cpu_from(platform_reads().cpuinfo.as_deref())
}

fn cpu_from(text: Option<&str>) -> Cpu {
    let text = text.unwrap_or_default();
    let mut vendor = None;
    let mut model_name = None;
    let mut features = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "vendor_id" if vendor.is_none() => vendor = Some(value.to_owned()),
            "model name" if model_name.is_none() => model_name = Some(value.to_owned()),
            // x86 uses "flags", aarch64 uses "Features".
            "flags" | "Features" if features.is_empty() => {
                for flag in value.split_whitespace() {
                    if RELEVANT_CPU_FEATURES.contains(&flag) {
                        features.push(flag.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    Cpu {
        vendor,
        model_name,
        relevant_features: features,
    }
}

/// The mode, and how it was established. Separated from `Execution` so that the
/// attestation can be classified against a known mode before the record is built:
/// `not-applicable` and `unattested` are different statuses and only the mode tells them
/// apart.
struct ModeFacts {
    mode: ExecutionMode,
    engine: Option<String>,
    detection: String,
    evidence: ModeEvidence,
}

/// How `execution.mode` was arrived at.
///
/// An enum rather than a `&'static str`, for the reason [`AttestationStatus`] gives: a
/// closed set spelled as a string compiles with a typo in it. This one had a second
/// problem a string cannot express — one of its values must never reach a published
/// report, and the only thing saying so was a sentence in this file and a matching
/// sentence in the schema's description. `PUBLISHABLE` states it in a form
/// `tests/schema_conformance.rs` can compare against the schema, and
/// `report::tests::contradicted_is_exactly_the_unpublishable_basis` machine-checks the
/// pairing over every (observed, asserted) combination rather than trusting the prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModeBasis {
    /// chard observed it and was not told.
    Measured,
    /// The operator's claim matches what chard observed.
    AssertedAndCorroborated,
    /// chard could not tell either way. The honest answer under bubblewrap, and the one
    /// that says `mode` is an assertion.
    AssertedButUnobservable,
    /// The operator's claim contradicts what chard observed. **Never appears in a
    /// published report** -- it is two claims about one property that disagree, so the
    /// consistency pass refuses the report and `main` diverts it to `.contradicted`.
    AssertedAndContradicted,
    /// Nothing settled it and nobody said, so `host` is a default rather than a
    /// measurement.
    AssumedHost,
}

impl ModeBasis {
    /// Every variant, so a test can cover them all.
    pub const ALL: &'static [Self] = &[
        Self::Measured,
        Self::AssertedAndCorroborated,
        Self::AssertedButUnobservable,
        Self::AssertedAndContradicted,
        Self::AssumedHost,
    ];

    /// The variants a report on disk may carry. `AssertedAndContradicted` is absent by
    /// construction, not by omission: a report bearing it is quarantined before it is
    /// written, so a consumer that switched on it would have written dead code.
    pub const PUBLISHABLE: &'static [Self] = &[
        Self::Measured,
        Self::AssertedAndCorroborated,
        Self::AssertedButUnobservable,
        Self::AssumedHost,
    ];

    /// The spelling used in the JSON, so other modules compare against this rather than
    /// against a second copy of the string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::AssertedAndCorroborated => "asserted-and-corroborated",
            Self::AssertedButUnobservable => "asserted-but-unobservable",
            Self::AssertedAndContradicted => "asserted-and-contradicted",
            Self::AssumedHost => "assumed-host",
        }
    }
}

/// Which basis an operator's `--execution` claim earns, given what chard observed.
///
/// Pulled out of `detect_execution_mode` so it can be checked without `/proc`. The
/// whole point of the extraction is that this decision and
/// `report::execution_mode_agrees` must agree about when the two claims disagree, and
/// that is the defect class this crate has already met once.
pub fn mode_basis(observed: Option<ExecutionMode>, asserted: ExecutionMode) -> ModeBasis {
    match observed {
        Some(seen) if seen == asserted => ModeBasis::AssertedAndCorroborated,
        Some(_) => ModeBasis::AssertedAndContradicted,
        None => ModeBasis::AssertedButUnobservable,
    }
}

/// What chard could observe about the execution mode, independently of what it was told.
///
/// `execution.mode` gates whether a kernel-enforced verdict is attributed to the
/// distribution named in the report: `kernel.is_host_kernel` is computed from it, and
/// probes marked `needs_vm` are withheld under `container` and where `basis` is
/// `assumed-host` ([`Execution::kernel_attribution`] reads the two together). So it decides
/// how much of the report is believable, and it is not taken on the operator's word: the
/// markers are consulted, and `--execution` is checked against them.
///
/// Measured, not supposed: inside a real bubblewrap cage, with no `--execution` flag, a
/// search for the usual container markers reports `mode: host`,
/// `detection: "no container marker found; assuming host"` and `is_host_kernel: false`,
/// while running on the host's kernel, the same release string the host reports. The claim
/// that the measured kernel is the distribution's is false, and the `detection` string
/// says chard looked.
///
/// Two separate defects produce that, and both are answered here. Those instruments do not
/// see bubblewrap at all: it plants no `/run/.containerenv`, and it leaves PID 1's cgroup
/// as the host's user session, so a search for `docker|libpod|containerd|lxc` in
/// `/proc/1/cgroup` reads the right file with the wrong needles. And an override that
/// replaced the observation instead of being checked against it could not notice a
/// disagreement.
#[derive(Debug, Clone, Serialize)]
pub struct ModeEvidence {
    /// How `mode` was arrived at. See [`ModeBasis`], which also records which of its
    /// values a published report may carry.
    pub basis: ModeBasis,
    /// What chard observed, or `None` when no instrument could settle it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<ExecutionMode>,
    /// The instrument and what it returned, so a reader can judge the observation rather
    /// than take it.
    pub observation: String,
}

/// Whether PID 1 is a system init, which it is not inside a namespace whose PID 1 is the
/// container runtime or a shell.
///
/// `/proc/1/comm` reads `systemd` on this host and `bwrap` inside a bubblewrap cage, so it
/// discriminates the case the marker files miss. Checked before shipping rather than
/// assumed: an instrument that cannot tell the two apart is worse than none, because it
/// makes a default look like a measurement.
fn pid1_is_system_init(reads: &PlatformReads) -> Option<(bool, String)> {
    let comm = reads.pid1_comm.clone()?;
    let is_init = matches!(comm.as_str(), "systemd" | "init" | "runit" | "s6-svscan");
    Some((is_init, comm))
}

/// One line of a uid map: `count` ids from `inside` this namespace map to `outside` in its
/// parent's (`user_namespaces(7)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UidExtent {
    pub inside: u32,
    pub outside: u32,
    pub count: u32,
}

impl std::fmt::Display for UidExtent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.inside, self.outside, self.count)
    }
}

/// The initial user namespace's map: one extent mapping every id to itself. The kernel
/// gives it to every process outside a user namespace, as `0 0 4294967295` with its fields
/// padded (`%10u %10u %10u`).
const IDENTITY_EXTENT: UidExtent = UidExtent {
    inside: 0,
    outside: 0,
    count: u32::MAX,
};

/// What `/proc/self/uid_map` says about this process's user namespace.
///
/// Public, with [`read_uid_map`], so `tests/platform_reads.rs` holds the shapes a runtime
/// writes (a one-id map, a multi-extent map, an empty one) through the suite's ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UidMap {
    /// The whole map is [`IDENTITY_EXTENT`] alone. No user namespace chard can see: a
    /// privileged runtime may write the identity map into one, which reads the same.
    Identity,
    /// The file is empty: a user namespace whose map is not written yet (`unshare -U`
    /// with no mapping). The initial namespace always has its map, and a kernel without
    /// user namespaces has no file, so an empty read is a user namespace; a runtime that
    /// masked the file with an empty one would read the same, and would be a container.
    Unwritten,
    /// Any other map of well-formed extents, in the kernel's order; only a user namespace
    /// has one.
    Mapped(Vec<UidExtent>),
    /// A line that is not three decimal numbers of ASCII digits within `u32`, which the
    /// kernel does not write: the read, its lines whitespace normalised and joined by
    /// `, `. It settles nothing.
    Malformed(String),
}

/// Classify a `/proc/self/uid_map` read: [`UidMap::Identity`] for the whole map equal to
/// [`IDENTITY_EXTENT`] and nothing else, each line split on whitespace and blank lines
/// dropped.
///
/// The whole map, not its first line: a map is identity where every id maps to itself,
/// and inside equal to outside on the first line says that of the ids that line covers
/// alone. `1000 1000 1` (`unshare -U --map-user=1000`) maps one id to itself and none of
/// the others.
pub fn read_uid_map(text: &str) -> UidMap {
    let lines = text
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|fields| !fields.is_empty())
        .collect::<Vec<_>>();
    // ASCII digits alone, as the kernel writes them: `u32::from_str` would take `+0`.
    let field = |text: &str| {
        text.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| text.parse::<u32>().ok())
            .flatten()
    };
    let extents = lines
        .iter()
        .map(|fields| match fields.as_slice() {
            [inside, outside, count] => Some(UidExtent {
                inside: field(inside)?,
                outside: field(outside)?,
                count: field(count)?,
            }),
            _ => None,
        })
        .collect::<Option<Vec<_>>>();
    match extents {
        None => UidMap::Malformed(
            lines
                .iter()
                .map(|fields| fields.join(" "))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        Some(extents) if extents.is_empty() => UidMap::Unwritten,
        Some(extents) if extents == [IDENTITY_EXTENT] => UidMap::Identity,
        Some(extents) => UidMap::Mapped(extents),
    }
}

/// Whether this process is in a user namespace with a non-identity uid mapping, and the
/// sentence that says what was read.
///
/// `/proc/self/uid_map` is `0 0 4294967295` on this host, `0 1000 1` inside a bubblewrap
/// cage, `1000 1000 1` under `unshare -U --map-user=1000`, `0 1000 1, 1 524288 65536`
/// under rootless podman, `0 1 1000, 1000 0 1, 1001 1001 64536` under its `keep-id`, and
/// empty in a user namespace whose map is not written. A non-identity map means a user
/// namespace, which every unprivileged container runtime uses and a VM guest does not.
fn in_userns(reads: &PlatformReads) -> Option<(bool, String)> {
    let read = reads.uid_map.as_deref()?;
    Some(match read_uid_map(read) {
        UidMap::Identity => (false, format!("the identity uid map `{IDENTITY_EXTENT}`")),
        UidMap::Unwritten => (
            true,
            "/proc/self/uid_map is empty, a user namespace whose map is not written".to_owned(),
        ),
        UidMap::Mapped(extents) => (
            true,
            format!(
                "/proc/self/uid_map is {}, {} extent{}, not the identity map `{IDENTITY_EXTENT}`, so a user-namespace mapping",
                quoted(
                    &extents
                        .iter()
                        .map(UidExtent::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                extents.len(),
                if extents.len() == 1 { "" } else { "s" }
            ),
        ),
        UidMap::Malformed(read) => (
            false,
            format!(
                "/proc/self/uid_map is {}, not three numbers to a line, so read as nothing",
                quoted(&read)
            ),
        ),
    })
}

/// One positive marker's reading: the sentence that settles `container`, or the sentence
/// saying why the marker settles nothing.
///
/// Both sentences are kept because both are published: the first as the observation, the
/// second inside the sentence of a run that settled nothing, where which marker was
/// absent, which was refused and which was read and silent are three different facts.
enum MarkerRead {
    Settles(String),
    Silent(String),
}

/// What [`SYSTEMD_CONTAINER_MARKER`] settles.
///
/// systemd as PID 1 writes the file only inside a container it detected and only from a
/// non-empty `container=` word of its own, with the manager's name as the content
/// (`write_container_id` in its `src/core/main.c`), and reads it back only where it has
/// content (`detect_container` in `src/basic/virt.c`). chard reads it the same way: a
/// non-empty file settles `container` naming the manager; an empty file, which systemd never
/// writes and does not read, settles nothing; a refusal says the instrument was not
/// available rather than that a container is there, and shows nothing about presence. A
/// bare host and a VM guest have no such file, and its absence settles nothing: a runtime
/// without systemd in the payload writes none.
fn systemd_container(reads: &PlatformReads) -> MarkerRead {
    match &reads.systemd_container {
        None => MarkerRead::Silent(format!(
            "{SYSTEMD_CONTAINER_MARKER} not read on this platform"
        )),
        Some(FileRead::Absent) => MarkerRead::Silent(format!("no {SYSTEMD_CONTAINER_MARKER}")),
        Some(FileRead::Unreadable(why)) => {
            MarkerRead::Silent(format!("{SYSTEMD_CONTAINER_MARKER} unreadable ({why})"))
        }
        Some(FileRead::Content(text)) => {
            let manager = text.trim();
            if manager.is_empty() {
                MarkerRead::Silent(format!(
                    "{SYSTEMD_CONTAINER_MARKER} is empty, which systemd reads as no container"
                ))
            } else {
                MarkerRead::Settles(format!(
                    "{SYSTEMD_CONTAINER_MARKER} names {}",
                    quoted(manager)
                ))
            }
        }
    }
}

/// What PID 1's `container=` word settles.
///
/// systemd-nspawn sets it on the payload's PID 1 naming itself (its stub PID 1 does so
/// expressly for clients that read [`PID1_ENVIRON`]), LXC likewise, and podman sets `oci`;
/// the word is the environment's own entry, not a value inside another entry's. systemd
/// reads an empty value as "not a container" (`detect_container`), and so does chard. The
/// file is readable only as root or PID 1's user, so a refusal is named as such rather than
/// read as the word's absence: it says the instrument was not available to this user, not
/// that the marker is missing.
fn pid1_container_word(reads: &PlatformReads) -> MarkerRead {
    match &reads.pid1_environ {
        None => MarkerRead::Silent(format!("{PID1_ENVIRON} not read on this platform")),
        Some(FileRead::Absent) => MarkerRead::Silent(format!("{PID1_ENVIRON} not found")),
        Some(FileRead::Unreadable(why)) => {
            MarkerRead::Silent(format!("{PID1_ENVIRON} unreadable ({why})"))
        }
        Some(FileRead::Content(environ)) => {
            match environ
                .split('\0')
                .find_map(|entry| entry.strip_prefix("container="))
            {
                None => {
                    MarkerRead::Silent("no `container=` word in PID 1's environment".to_owned())
                }
                Some("") => MarkerRead::Silent(
                    "PID 1's environment carries `container=` with no value, which systemd reads as no container"
                        .to_owned(),
                ),
                Some(runtime) => MarkerRead::Settles(format!(
                    "PID 1's environment carries {}",
                    quoted(&format!("container={runtime}"))
                )),
            }
        }
    }
}

/// Observe the execution mode, without reference to anything the operator said.
///
/// Returns `None` for the mode when no instrument settles it. That is not the same as
/// `host`, and conflating the two is what published a false `is_host_kernel`.
#[must_use]
pub fn observe_execution_mode(
    reads: &PlatformReads,
) -> (Option<ExecutionMode>, Option<String>, String) {
    // An OS with none of these instruments reaches the inconclusive arm at the bottom,
    // which is the same answer a bare Linux host gives -- and it is the right one. `host`
    // is a default there rather than a measurement, and `mode_evidence.basis` says
    // `assumed-host` so a reader is told which.
    if reads.is_barren() {
        return (
            None,
            None,
            "no instrument on this platform settles the execution mode".to_owned(),
        );
    }
    if let Some(why) = reads.container_marker {
        return (Some(ExecutionMode::Container), None, why.to_owned());
    }
    if let Some(cgroup) = reads.pid1_cgroup.clone() {
        for needle in ["docker", "libpod", "containerd", "lxc"] {
            if cgroup.contains(needle) {
                return (
                    Some(ExecutionMode::Container),
                    Some(needle.to_owned()),
                    format!("/proc/1/cgroup mentions {needle}"),
                );
            }
        }
    }
    // The two positive markers a runtime plants for the payload's own init to read: systemd
    // writes `/run/systemd/container` only inside a container it detected, and
    // systemd-nspawn and LXC set `container=` on PID 1 (podman sets `oci` there beside its
    // marker file, which the arm above has already read, so its sentence is unchanged).
    // Either settles `container` on content, and so refuses an asserted `host` or `vm`
    // through the consistency pass; each one's negative case is understood, which is the
    // bar the comment below sets: an absent file, an empty one, an absent word and an empty
    // one settle nothing, and a path this user may not read is named as unreadable rather
    // than counted as silent or read as present.
    let mut silence = Vec::new();
    for marker in [systemd_container(reads), pid1_container_word(reads)] {
        match marker {
            MarkerRead::Settles(why) => return (Some(ExecutionMode::Container), None, why),
            MarkerRead::Silent(why) => silence.push(why),
        }
    }
    let silence = silence.join(", ");
    // Bubblewrap and the other runtimes that plant no marker. The user-namespace mapping
    // is the conclusion; PID 1's name only corroborates it.
    //
    // Those two were briefly given equal standing, and that was a false positive waiting
    // for the next sweep. A non-init `/proc/1/comm` concluded `container` on its own, and
    // this conclusion *refuses reports* through the consistency pass — so a VM guest
    // labelled `--execution vm` whose PID 1 is not one of four names would have been
    // refused for not running systemd. Alpine's is busybox. An instrument that decides a
    // refusal has to be one whose negative case is understood, and "PID 1 is not on a
    // list" is not that. A non-identity uid map is: it means a user namespace, which a VM
    // guest does not have for an ordinary login.
    let pid1 = pid1_is_system_init(reads).map_or_else(
        || String::from("/proc/1 unreadable"),
        |(is_init, comm)| {
            // PID 1's name is the container owner's to set (`prctl(PR_SET_NAME)` takes any
            // byte but NUL), so it is quoted as the marker values are: an ordinary name reads
            // as it did in backticks, and a character that does not print is escaped rather
            // than handed to the report's reader and the terminal a refusal prints to. Found
            // by the `env_reads` fuzz target (`fuzz/crashes/env_reads/`).
            let note = if is_init { ", a system init" } else { "" };
            format!("/proc/1/comm is {}{note}", quoted(&comm))
        },
    );
    let userns = match in_userns(reads) {
        Some((true, why)) => {
            return (
                Some(ExecutionMode::Container),
                None,
                format!("{why}; {pid1}; {silence}"),
            );
        }
        Some((false, why)) => why,
        None => String::from("/proc/self/uid_map absent or unreadable"),
    };
    // Nothing positive was found. Nothing chard reads tells a container that plants none of
    // these from a bare host or a VM guest, so this is inconclusive among them rather than
    // evidence of any; the sentence names each marker's silence, a refusal apart from an
    // absence, so a reader knows which instrument this run could not use.
    (
        None,
        None,
        format!(
            "no runtime marker file, {silence}, {userns}, {pid1}: nothing chard reads from inside tells a container that plants none of these from a system that owns its kernel"
        ),
    )
}

/// The execution mode, and what was observed independently of what chard was told.
///
/// `override_mode` is `--execution`. It sets `mode`, but never replaces `evidence.observed`
/// — the two are carried separately so a claim that disagrees with the observation is
/// visible rather than overwritten, which is what `ModeBasis::AssertedAndContradicted`
/// records and the consistency pass refuses.
fn detect_execution_mode(override_mode: Option<ExecutionMode>) -> ModeFacts {
    let (observed, engine, observation) = observe_execution_mode(&platform_reads());
    if let Some(mode) = override_mode {
        let basis = mode_basis(observed, mode);
        return ModeFacts {
            mode,
            engine,
            detection: "operator-supplied via --execution".to_owned(),
            evidence: ModeEvidence {
                basis,
                observed,
                observation,
            },
        };
    }
    if let Some(mode) = observed {
        return ModeFacts {
            mode,
            engine,
            detection: observation.clone(),
            evidence: ModeEvidence {
                basis: ModeBasis::Measured,
                observed: Some(mode),
                observation,
            },
        };
    }
    // Nothing settled it, and nobody said. Nothing chard reads tells a container that plants
    // no marker from a bare host or a VM guest, so `host` here is a default rather than a
    // measurement, which the evidence block states rather than implying.
    ModeFacts {
        mode: ExecutionMode::Host,
        engine,
        detection: "no container marker found; assuming host".to_owned(),
        evidence: ModeEvidence {
            basis: ModeBasis::AssumedHost,
            observed: None,
            observation,
        },
    }
}

/// musl's version, from the loader, which prints it when run with no arguments.
///
/// Not a read of `/lib/libc.musl-x86_64.so.1`: that path is a several-hundred-KB ELF that
/// a string read rejects, and the name is x86_64-only. musl publishes no version macro, so
/// executing the loader is the available route.
///
/// `None` on any failure, because a missing version is honest and a wrong one is not.
/// The loader's exit status is not read: run with no program it prints its banner and
/// exits non-zero by design, so a `Version ` line is the answer and the status is not.
///
/// Goes through [`crate::compile::capture`] rather than calling `.output()` directly.
/// That is not tidiness: `.output()` waits forever, so a direct call would be the one child
/// chard spawns outside `invoke`'s bound, the single exception to the claim `INVOKE_TIMEOUT`
/// makes about itself, on the `chard measure` path of every musl host. It also picks up
/// the environment scrubbing, which matters here because this parses another program's
/// human-readable banner.
fn musl_version() -> Option<String> {
    let loader = std::path::Path::new("/lib")
        .read_dir()
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("ld-musl-"))
        })?;
    let record = crate::compile::capture(&loader, &[]).ok()?;
    // The banner goes to stderr: "musl libc (x86_64)\nVersion 1.2.6\n..."
    record
        .stderr
        .lines()
        .find_map(|l| l.strip_prefix("Version "))
        .map(|v| v.trim().to_owned())
}

/// Determine the libc from the toolchain's own macro view.
///
/// This deliberately uses the macro dump rather than running `ldd --version`:
/// the question that matters is which libc the *compiler will build against*,
/// which on a cross or multi-libc host is not necessarily the one `ldd`
/// describes. `__GLIBC__` only appears once a libc header has been
/// preprocessed, so this reads the with-headers dump from
/// [`crate::toolchain`].
fn detect_libc(macros_with_headers: &BTreeMap<String, String>) -> Libc {
    let major = macros_with_headers.get("__GLIBC__");
    let minor = macros_with_headers.get("__GLIBC_MINOR__");
    if let Some(major) = major {
        return Libc {
            impl_name: "glibc".to_owned(),
            version: Some(match minor {
                Some(minor) => format!("{major}.{minor}"),
                None => major.clone(),
            }),
            detection: "__GLIBC__/__GLIBC_MINOR__ from the toolchain's own macro dump".to_owned(),
        };
    }
    // musl is identified by its internal `__NEED_*` header guards — it defines no macro
    // meant to announce itself the way `__GLIBC__` does. Recording *how* this was
    // concluded matters, because "musl" gates several checks to `unsupported`.
    // `__NEED_*` only. `__DEFINED_size_t` was here too and was actively harmful: GCC's
    // own `stddef.h` defines it for *every* libc — the header carries the comment
    // `/* musl libc */` at the definition, which is presumably how it got in — so on
    // gcc the disjunct amounted to "some header preprocessed". Measured on Fedora 44
    // with glibc: `__DEFINED_size_t`, `__DEFINED_ptrdiff_t` and `__DEFINED_wchar_t` are
    // all defined, and `__NEED_*` is empty.
    //
    // Only the `__GLIBC__` early return above kept glibc out of this branch, which made
    // the test useless where it mattered: any libc that does not define `__GLIBC__` —
    // uclibc-ng, dietlibc, picolibc, a bare cross toolchain — was silently reported as
    // musl, and the `bionic` arm below was unreachable under gcc. That is a silent
    // misidentification of a field carried in `toolchain.id`, the key reports are joined
    // on, and it gates six fortify checks to `unsupported`.
    //
    // `__NEED_*` is genuinely musl's: 8 are present under `musl-gcc` and none under
    // gcc with glibc. gcc's own spelling is lowercase `__need_size_t` and is `#undef`'d
    // after use, so there is no collision.
    if macros_with_headers.keys().any(|k| k.starts_with("__NEED_")) {
        return Libc {
            impl_name: "musl".to_owned(),
            version: musl_version(),
            detection: "musl internal __NEED_* header guards present, no __GLIBC__".to_owned(),
        };
    }
    // OpenBSD's libc has no macro of its own, so the platform macro stands in. That is a
    // weaker inference than the three above and is recorded as such in `detection`: it says
    // "this is OpenBSD" and infers the libc from there, which holds because OpenBSD ships
    // exactly one and it is not separable from the base system. Measured on 7.9, not
    // assumed -- `cc -dM -E` defines `__OpenBSD__ 1` and `__VERSION__ "OpenBSD Clang
    // 19.1.7"`, and none of `__GLIBC__`, `__NEED_*` or `__BIONIC__`.
    //
    // It is load-bearing rather than cosmetic: `report::libc_limitation` is keyed on this
    // name, so without it every check whose mechanism OpenBSD's libc does not have reports
    // `probe-invalid` -- indistinguishable from a harness fault -- instead of
    // `unsupported`, which says the mechanism is not there to measure.
    if macros_with_headers.contains_key("__OpenBSD__") {
        return Libc {
            impl_name: "openbsd".to_owned(),
            version: None,
            detection: "__OpenBSD__ present, and no __GLIBC__, __NEED_* or __BIONIC__; \
                        OpenBSD's libc is part of the base system and carries no macro of \
                        its own, so the platform is the identification"
                .to_owned(),
        };
    }
    if macros_with_headers.contains_key("__BIONIC__") {
        return Libc {
            impl_name: "bionic".to_owned(),
            version: None,
            detection: "__BIONIC__ present".to_owned(),
        };
    }
    // FreeBSD's libc, on the OpenBSD footing: part of the base system, no macro of its own,
    // so the platform macro is the identification. Its value is the release major, kept as
    // the version because the libc ships with the release and the major is where its
    // fortify implementation begins: 15's headers carry `<ssp/ssp.h>` and 14.5 has no
    // /usr/include/ssp/ at all. Measured on 14.5 (clang 21.1.8) and 15.1 (clang 19.1.7)
    // amd64: `cc -dM -E` defines `__FreeBSD__ 14` and `15`, and none of `__GLIBC__`,
    // `__NEED_*` or `__BIONIC__`.
    //
    // Load-bearing as OpenBSD's arm is, and for the same reason: `report::libc_limitation`
    // keys on this name. While FreeBSD read `unknown`, every fortify rung on both releases
    // published `probe-invalid`, indistinguishable from a harness fault, where 14.5's lack of
    // an implementation and 15.1's missing rungs are `unsupported`.
    if let Some(major) = macros_with_headers.get("__FreeBSD__") {
        return Libc {
            impl_name: "freebsd".to_owned(),
            version: Some(major.clone()),
            detection: "__FreeBSD__ present, and no __GLIBC__, __NEED_* or __BIONIC__; \
                        FreeBSD's libc is part of the base system and carries no macro of \
                        its own, so the platform is the identification and the release \
                        major its version"
                .to_owned(),
        };
    }
    // Apple's libc, on the same footing as the OpenBSD arm above and for the same reason:
    // it announces itself with no macro of its own, and it is not separable from the base
    // system, so the platform macros are the identification. `detection` says so rather
    // than implying a `__GLIBC__`-grade reading.
    //
    // Nine rounds of Darwin reports read `libc: unknown` with the detection string "no
    // recognized libc macro in the with-headers dump" — which was doubly wrong. The dump
    // had Apple's macros in it all along, and chard elsewhere already knows this libc by
    // name: `_FORTIFY_IMPL=apple` is a value the fortify detectors match on. One half of
    // the code recognised Apple and the other reported it unidentifiable.
    //
    // Both macros, not `__APPLE__` alone: it is also defined by some non-Apple toolchains
    // targeting Apple-adjacent platforms, and `__MACH__` is what says the kernel and the
    // base system are Darwin's.
    if macros_with_headers.contains_key("__APPLE__") && macros_with_headers.contains_key("__MACH__")
    {
        return Libc {
            impl_name: "apple".to_owned(),
            version: None,
            detection: "__APPLE__ and __MACH__ present, and no __GLIBC__, __NEED_* or \
                        __BIONIC__; Apple's libc is part of the base system and carries no \
                        macro announcing itself, so the platform is the identification"
                .to_owned(),
        };
    }
    Libc {
        impl_name: "unknown".to_owned(),
        version: None,
        detection: "no recognized libc macro in the with-headers dump".to_owned(),
    }
}

/// The with-headers dump as [`detect`] reads it (`toolchain::Detected::headers_dump`): its
/// macros, and its failure where it exited non-zero, `exited N` or `was killed by a signal`
/// and the first stderr line, or where it exited 0 with its output cut off, as
/// `toolchain.libc_headers_error` publishes it.
#[derive(Clone, Copy, Debug)]
pub struct HeadersDump<'a> {
    pub macros: &'a BTreeMap<String, String>,
    pub failure: Option<&'a str>,
}

/// The C library [`detect_libc`] reads from `dump`, held to what a failed dump can establish.
///
/// A dump that exited non-zero can lack macros and cannot gain them: each line read from it
/// is a define the headers made (`compile::BuildRecord::whole_stdout` drops a last line the
/// output ended partway through, whatever the status), and gcc lists
/// them in identifier-table order (measured, `compile::macro_dump`), so which ones are
/// missing says nothing. A library a present macro names therefore stands, with a
/// detection that names that macro and the failure and claims no absence, where the clean
/// arms of [`detect_libc`] say "no `__GLIBC__`". A value read from two macros needs both: glibc's
/// version is read only where `__GLIBC_MINOR__` came out beside `__GLIBC__`, and is absent
/// otherwise rather than `2`. Where no macro names a library the reading is `unknown`,
/// `not identified`, naming the failure.
///
/// Reading the failed dump as no library at all would move a verdict: `unknown` would lower
/// `fhardened-effective`'s fortify bar from 3 to 2, and on glibc 2.43 a level-2 build would
/// read `in-force` where the identified glibc demands 3. So an absent version or an
/// `unknown` that the dump could not settle, like one from a dump that exited 0, sets no
/// bar: the composite withholds the fortify slot where the bar would decide it
/// (`composite::fortify_bar`, the library reading, which stands where the driver's own
/// `-fhardened` dump does not answer, `composite::fhardened_bar`).
fn libc_of(dump: HeadersDump<'_>) -> Libc {
    let libc = detect_libc(dump.macros);
    let Some(failure) = dump.failure else {
        return libc;
    };
    let named_by = match libc.impl_name.as_str() {
        "glibc" if !dump.macros.contains_key("__GLIBC_MINOR__") => {
            return Libc {
                version: None,
                detection: format!(
                    "glibc by __GLIBC__ in a with-headers macro dump that {failure}; \
                     __GLIBC_MINOR__ is not in the lines read from it, so the version is not \
                     read"
                ),
                ..libc
            };
        }
        "glibc" => "__GLIBC__ and __GLIBC_MINOR__",
        "musl" => "musl's __NEED_* header guards",
        "openbsd" => "__OpenBSD__",
        "bionic" => "__BIONIC__",
        "freebsd" => "__FreeBSD__",
        "apple" => "__APPLE__ and __MACH__",
        _ => {
            return Libc {
                detection: format!(
                    "not identified: the with-headers macro dump {failure}, and no macro in \
                     the lines read from it names a C library"
                ),
                ..libc
            };
        }
    };
    Libc {
        detection: format!(
            "{} by {named_by} in a with-headers macro dump that {failure}; a failed dump's \
             defines are real and what it lacks is not read",
            libc.impl_name
        ),
        ..libc
    }
}

/// Build the environment record.
///
/// `headers` is the with-headers dump with its failure, if any ([`libc_of`]).
///
/// # Errors
///
/// See [`ImageAttestation::classify`]. There is no `Environment` for a refused
/// attestation on purpose: the caller cannot proceed and accidentally publish, because it
/// has nothing to publish with.
pub fn detect(
    headers: HeadersDump<'_>,
    execution: Option<ExecutionMode>,
    image: Option<String>,
    attestation: Option<Attestation>,
) -> Result<Environment, AttestationRefusal> {
    let facts = detect_execution_mode(execution);
    let image_attestation = ImageAttestation::classify(facts.mode, attestation)?;
    let exec = Execution {
        mode: facts.mode,
        engine: facts.engine,
        image,
        detection: facts.detection,
        mode_evidence: facts.evidence,
        image_attestation,
    };
    Ok(Environment {
        distro: detect_distro(),
        kernel: Kernel {
            release: platform_reads()
                .kernel_release
                .unwrap_or_else(|| "unknown".to_owned()),
            // The architecture chard was built for, which is the run arch while chard runs
            // natively; `machine` is the kernel's own word where it has one.
            arch: std::env::consts::ARCH.to_owned(),
            machine: platform_reads().kernel_machine,
            is_host_kernel: !exec.mode.kernel_is_representative(),
            ownership: exec.kernel_attribution().into(),
        },
        libc: libc_of(headers),
        cpu: detect_cpu(),
        execution: exec,
    })
}

#[cfg(test)]
mod tests {

    /// The libc tag carries the version where one was read and the bare name where
    /// none was, so `glibc2.43` and `musl` are both keys and neither is `glibcNone`.
    ///
    /// The bare forms are the exact strings `matrix::key_of`'s test fixtures key on
    /// (`environment.libc.impl` with no `version`), which is what holds that module's
    /// spelling over JSON to this one over the struct.
    #[test]
    fn the_libc_tag_carries_the_version_only_when_one_was_read() {
        let libc = |impl_name: &str, version: Option<&str>| super::Libc {
            impl_name: impl_name.to_owned(),
            version: version.map(ToOwned::to_owned),
            detection: String::new(),
        };
        assert_eq!(libc("glibc", Some("2.43")).tag(), "glibc2.43");
        assert_eq!(libc("musl", Some("1.2.5")).tag(), "musl1.2.5");
        assert_eq!(libc("glibc", None).tag(), "glibc");
        assert_eq!(libc("musl", None).tag(), "musl");
    }

    /// `fedora` and `44` read as `fedora44`; a system with no os-release reads as
    /// `unknown`, since `unknownunknown` was the key the concatenation produced.
    #[test]
    fn the_distro_tag_is_the_id_alone_when_the_version_is_unknown() {
        let fedora = super::Distro {
            id: "fedora".to_owned(),
            version_id: "44".to_owned(),
            pretty_name: None,
            codename: None,
        };
        assert_eq!(fedora.tag(), "fedora44");
        let nowhere = super::Distro {
            id: "unknown".to_owned(),
            version_id: "unknown".to_owned(),
            pretty_name: None,
            codename: None,
        };
        assert_eq!(nowhere.tag(), "unknown");
    }

    /// `as_str` and the serialized form are one spelling, since `run.id` hashes the
    /// first and a reader compares the second.
    #[test]
    fn the_execution_mode_hashed_into_the_run_id_is_the_one_published() {
        use super::ExecutionMode;
        for mode in [
            ExecutionMode::Host,
            ExecutionMode::Container,
            ExecutionMode::Vm,
        ] {
            let published = serde_json::to_string(&mode).expect("serializes");
            assert_eq!(published, format!("\"{}\"", mode.as_str()));
        }
    }

    /// A platform with no instruments claims nothing, over every field it could claim.
    ///
    /// The `Features` line is aarch64's spelling of `flags`, and every hardening feature
    /// this list carries for that architecture arrives on it. Worth a test rather than a
    /// glance because the failure is silent: a feature spelled differently from the kernel
    /// is simply never matched, and an absent entry reads exactly like a CPU that lacks
    /// the capability — the one confusion `relevant_features` exists to prevent.
    #[test]
    fn aarch64_hardening_features_are_recognised_under_their_kernel_spelling() {
        let cpuinfo = "processor\t: 0\n\
                       BogoMIPS\t: 50.00\n\
                       Features\t: fp asimd aes sha1 bti paca pacg gcs sve\n\
                       CPU implementer\t: 0x41\n";
        let c = cpu_from(Some(cpuinfo));
        assert_eq!(c.relevant_features, vec!["bti", "paca", "pacg", "gcs"]);

        // And the x86 line still works, since one parser serves both.
        let intel = "vendor_id\t: GenuineIntel\n\
                     flags\t\t: fpu vme ibt shstk smap smep avx2\n";
        let c = cpu_from(Some(intel));
        assert_eq!(c.relevant_features, vec!["ibt", "shstk", "smap", "smep"]);
        assert_eq!(c.vendor.as_deref(), Some("GenuineIntel"));
    }

    /// This is the port's load-bearing property and the reason `PlatformReads` exists: an
    /// OS without `/proc` and without `os-release` must produce a report that says
    /// "unknown" everywhere, never a plausible default that reads like a measurement.
    /// Exhaustive over the derived fields rather than spot-checked, because the failure
    /// mode is one field quietly keeping a Linux-shaped answer.
    #[test]
    fn a_platform_with_no_instruments_asserts_nothing() {
        let barren = PlatformReads::default();
        assert!(barren.is_barren());

        let d = distro_from(barren.os_release.as_deref());
        assert_eq!(d.id, "unknown");
        // Not `rolling`. A missing file says nothing about the release model.
        assert_eq!(d.version_id, "unknown");
        assert_eq!(d.pretty_name, None);
        assert_eq!(d.codename, None);

        let c = cpu_from(barren.cpuinfo.as_deref());
        assert_eq!(c.vendor, None);
        assert_eq!(c.model_name, None);
        assert!(c.relevant_features.is_empty());

        let (observed, engine, why) = observe_execution_mode(&barren);
        assert_eq!(
            observed, None,
            "a barren read set is not evidence of a host"
        );
        assert_eq!(engine, None);
        assert!(why.contains("no instrument"), "{why}");
        // And the basis that follows from `observed: None` under no assertion.
        assert_eq!(
            mode_basis(observed, ExecutionMode::Host),
            ModeBasis::AssertedButUnobservable
        );
    }

    /// The `rolling` reading is earned by a file that exists and omits the version.
    ///
    /// The converse of the test above, and the pair is the point: if both inputs produced
    /// `rolling`, the value could not distinguish Arch from an image with no os-release at
    /// all.
    #[test]
    fn rolling_means_the_file_said_so_not_that_it_was_missing() {
        let arch = distro_from(Some("ID=arch\nPRETTY_NAME=\"Arch Linux\"\n"));
        assert_eq!(arch.id, "arch");
        assert_eq!(arch.version_id, "rolling");

        let debian = distro_from(Some("ID=debian\nVERSION_ID=\"13\"\n"));
        assert_eq!(debian.version_id, "13");

        assert_eq!(distro_from(None).version_id, "unknown");
    }

    /// `is_barren` is false as soon as any one execution-mode instrument answers.
    ///
    /// Exhaustive over the nine that bear on the mode: a field added to `PlatformReads`
    /// and forgotten in `is_barren` would let a platform that answered *only* through that
    /// field still be treated as having no instruments at all.
    ///
    /// `system_version` is the tenth field and is excluded on purpose, so it gets the
    /// opposite assertion rather than no case. Reading macOS's OS release must not make
    /// chard claim it looked for a container there.
    #[test]
    fn any_single_instrument_answering_makes_the_set_non_barren() {
        let some = || Some("x".to_owned());
        let mut n = 0;
        for r in [
            PlatformReads {
                os_release: some(),
                ..Default::default()
            },
            PlatformReads {
                cpuinfo: some(),
                ..Default::default()
            },
            PlatformReads {
                kernel_release: some(),
                ..Default::default()
            },
            PlatformReads {
                pid1_comm: some(),
                ..Default::default()
            },
            PlatformReads {
                uid_map: some(),
                ..Default::default()
            },
            PlatformReads {
                pid1_cgroup: some(),
                ..Default::default()
            },
            PlatformReads {
                container_marker: Some("marker"),
                ..Default::default()
            },
            // A read that found the path absent is still an instrument that answered.
            PlatformReads {
                systemd_container: Some(FileRead::Absent),
                ..Default::default()
            },
            PlatformReads {
                pid1_environ: Some(FileRead::Absent),
                ..Default::default()
            },
        ] {
            assert!(
                !r.is_barren(),
                "one answering instrument is not barren: {r:?}"
            );
            n += 1;
        }
        // The frame, not just the count: nine mode-bearing fields, nine cases.
        assert_eq!(
            n, 9,
            "every mode-bearing field of PlatformReads must have a case here"
        );

        let mac = PlatformReads {
            system_version: some(),
            ..Default::default()
        };
        assert!(
            mac.is_barren(),
            "SystemVersion.plist identifies the OS release and says nothing about \
             containment; counting it would send macOS into the container checks and \
             have chard report finding no marker where it has no instrument to look"
        );
        let (mode, _, why) = observe_execution_mode(&mac);
        assert!(mode.is_none(), "the mode stays unsettled on macOS");
        assert!(
            why.contains("no instrument on this platform"),
            "and the sentence says why, rather than listing Linux instruments it never \
             consulted: {why}"
        );
    }
    use super::*;

    /// Built through `from_json`, not by struct literal.
    ///
    /// The fields are private to everything outside this module, but a child test module
    /// can still name them — so a helper that assembled an `Attestation` directly could
    /// hold a digest the refinement forbids, and every test would then be exercising a
    /// value that cannot occur in production. Going through the parser keeps the tests
    /// honest about what values exist.
    fn attestation(digest_matched: bool) -> Attestation {
        let text = format!(
            r#"{{"verdict":"signature-verified","url":"https://example.invalid/i.qcow2",
                 "served_by":"example.invalid",
                 "manifest_url":"https://example.invalid/SHA256SUMS",
                 "digest_kind":"sha256","digest":"{}","digest_matched":{digest_matched},
                 "signature":"detached .asc"}}"#,
            "ab".repeat(32)
        );
        Attestation::from_json(&text).expect("the helper's own attestation must be well-formed")
    }

    /// An unreachable manifest is `unattested`, not an accusation about the image.
    ///
    /// The two readings of `digest_matched: false` that this keeps apart. openSUSE Tumbleweed
    /// rotates its dated snapshot off the mirror after about two days, so the manifest 404s
    /// while the image on disk stays byte-identical to the one verified against that same
    /// manifest the day before. A refusal there would assert the bytes are not the
    /// publisher's, and its remedy, re-fetch the image, would point at a file that does not
    /// exist.
    ///
    /// The harness never emits `digest_matched: false` for a real mismatch: that path bails
    /// before writing anything. So a refusal of an unfetched manifest would misread its input
    /// in every case it fired.
    #[test]
    fn an_unreachable_manifest_is_unattested_rather_than_a_mismatch() {
        let text = format!(
            r#"{{"verdict":"unverified","url":"https://example.invalid/i.qcow2",
                 "served_by":"example.invalid",
                 "manifest_url":"https://example.invalid/i.qcow2.sha256",
                 "digest_kind":"sha256","digest":"{}","digest_matched":false,
                 "manifest_fetched":false,"signature":"unchecked",
                 "caveat":"manifest not fetched: HTTP 404"}}"#,
            "ab".repeat(32)
        );
        let a = Attestation::from_json(&text).expect("well-formed");
        for mode in [ExecutionMode::Vm, ExecutionMode::Container] {
            let got = ImageAttestation::classify(mode, Some(a.clone()));
            assert!(
                matches!(
                    got,
                    Ok(ImageAttestation {
                        status: AttestationStatus::Unattested,
                        ..
                    })
                ),
                "{mode:?}: a manifest that was never fetched establishes nothing about the \
                 image, which is the same evidential position as no attestation at all"
            );
        }
        // And the case that must still be refused: compared, and disagreed.
        let mismatched = format!(
            r#"{{"verdict":"unverified","url":"https://example.invalid/i.qcow2",
                 "served_by":"example.invalid",
                 "manifest_url":"https://example.invalid/SHA256SUMS",
                 "digest_kind":"sha256","digest":"{}","digest_matched":false,
                 "manifest_fetched":true,"signature":"detached .asc"}}"#,
            "cd".repeat(32)
        );
        let m = Attestation::from_json(&mismatched).expect("well-formed");
        assert!(
            matches!(
                ImageAttestation::classify(ExecutionMode::Vm, Some(m)),
                Err(AttestationRefusal::DigestMismatch(_))
            ),
            "a manifest that was read and disagreed is still a refusal"
        );
    }

    /// An attestation written before `manifest_fetched` existed reads exactly as it did.
    #[test]
    fn an_attestation_without_the_field_still_refuses_on_mismatch() {
        assert!(
            matches!(
                ImageAttestation::classify(ExecutionMode::Vm, Some(attestation(false))),
                Err(AttestationRefusal::DigestMismatch(_))
            ),
            "absent `manifest_fetched` defaults to true, so old files keep their old meaning"
        );
    }

    /// Every cell of `classify`'s domain: three modes by three attestation shapes.
    ///
    /// Enumerated rather than sampled, because nine cells is a proof by cases and picking
    /// seven of them is what let the wrong answer through. `(Host, Some(matched))` returned
    /// `attested` — a report claiming its image had been established while measuring the
    /// running system and naming no image — and the example tests that preceded this
    /// covered `(Host, None)` and `(Vm, Some)` but never their combination. An exhaustive
    /// table cannot miss a cell; a list of examples misses exactly the ones nobody thought
    /// of, which is the set the bug lives in.
    #[test]
    fn classify_is_exhaustive_over_mode_by_attestation() {
        use ExecutionMode::{Container, Host, Vm};

        // mode, attestation, expected outcome
        let expected: &[(ExecutionMode, Option<bool>, Result<AttestationStatus, &str>)] = &[
            (Host, None, Ok(AttestationStatus::NotApplicable)),
            (Container, None, Ok(AttestationStatus::Unattested)),
            (Vm, None, Ok(AttestationStatus::Unattested)),
            (Host, Some(true), Err("NoImageToAttest")),
            (Container, Some(true), Ok(AttestationStatus::Attested)),
            (Vm, Some(true), Ok(AttestationStatus::Attested)),
            (Host, Some(false), Err("DigestMismatch")),
            (Container, Some(false), Err("DigestMismatch")),
            (Vm, Some(false), Err("DigestMismatch")),
        ];

        // The table must cover the domain, not merely agree with itself: 3 modes by
        // {absent, matched, mismatched}. A row dropped from the table above would
        // otherwise pass unnoticed, which is the failure this test exists to prevent.
        assert_eq!(expected.len(), 3 * 3, "the table must cover every cell");

        for (mode, matched, want) in expected {
            let got = ImageAttestation::classify(*mode, matched.map(attestation));
            match (want, got) {
                (Ok(status), Ok(record)) => {
                    assert_eq!(record.status, *status, "{mode:?} with {matched:?}");
                    assert_eq!(
                        record.attestation.is_some(),
                        *status == AttestationStatus::Attested,
                        "an attestation is carried exactly when the status is attested: \
                         {mode:?} with {matched:?}"
                    );
                }
                (Err("NoImageToAttest"), Err(AttestationRefusal::NoImageToAttest))
                | (Err("DigestMismatch"), Err(AttestationRefusal::DigestMismatch(_))) => {}
                (want, got) => {
                    panic!("{mode:?} with {matched:?}: wanted {want:?}, got {got:?}")
                }
            }
        }
    }

    /// `ALL` must list every variant, since `dataset` reads a report's status by searching
    /// it: a variant missing from `ALL` would make every report carrying it read as
    /// unrecognised, and so as unattested.
    #[test]
    fn every_status_is_in_all_and_spelled_once() {
        let spellings: Vec<&str> = AttestationStatus::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(spellings.len(), 3);
        assert_eq!(
            spellings
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            spellings.len(),
            "two statuses share a spelling: {spellings:?}"
        );
        for status in AttestationStatus::ALL {
            let json = serde_json::to_value(status).unwrap();
            assert_eq!(
                json.as_str(),
                Some(status.as_str()),
                "as_str and the serialised form must agree, or dataset compares against \
                 the wrong string"
            );
        }
        assert!(!AttestationStatus::Unattested.is_established());
        assert!(AttestationStatus::Attested.is_established());
        assert!(AttestationStatus::NotApplicable.is_established());
    }

    /// A digest that does not match its own `digest_kind` is refused at parse time, so no
    /// `Attestation` value can carry one.
    ///
    /// The empty case is the one that happened: `digest: ""` with `digest_matched: true`
    /// was recorded as `attested`, a report asserting that its image had been established
    /// with no evidence in it whatsoever.
    #[test]
    fn a_digest_that_contradicts_its_own_algorithm_is_refused_at_parse_time() {
        let ok = format!(
            r#"{{"verdict":"v","url":"u","served_by":"s","manifest_url":"m",
                 "digest_kind":"sha256","digest":"{}","digest_matched":true,
                 "signature":"none"}}"#,
            "ab".repeat(32)
        );
        assert!(
            Attestation::from_json(&ok).is_ok(),
            "a well-formed sha256 must parse"
        );

        for (label, kind, digest) in [
            ("empty", "sha512", String::new()),
            ("sha256 length labelled sha512", "sha512", "ab".repeat(32)),
            ("truncated", "sha256", "ab".repeat(31)),
            ("not hex", "sha256", "z".repeat(64)),
            ("unknown algorithm", "sha3-256", "ab".repeat(32)),
        ] {
            let text = format!(
                r#"{{"verdict":"v","url":"u","served_by":"s","manifest_url":"m",
                     "digest_kind":"{kind}","digest":"{digest}","digest_matched":true,
                     "signature":"none"}}"#
            );
            assert!(
                Attestation::from_json(&text).is_err(),
                "{label} must be refused, not recorded as attested"
            );
        }
    }

    /// An attestation is serialised beside the status rather than nested under a key of
    /// its own, so a reader sees one flat record of what is known about the image. The
    /// fields keep the fetcher's own names: a reader comparing a report against the
    /// session file that produced it should see the same object, not a translation.
    #[test]
    fn an_attestation_serialises_flat_with_the_fetchers_field_names() {
        let a = ImageAttestation::classify(ExecutionMode::Vm, Some(attestation(true))).unwrap();
        let json = serde_json::to_value(&a).unwrap();
        for key in [
            "status",
            "established_by",
            "verdict",
            "url",
            "served_by",
            "manifest_url",
            "digest_kind",
            "digest",
            "digest_matched",
            "signature",
        ] {
            assert!(json.get(key).is_some(), "missing {key} in {json}");
        }
        assert!(
            json.get("attestation").is_none(),
            "the attestation must be flattened, not nested: {json}"
        );
    }

    /// An installed-disk record, with `from` as the digest it names.
    fn with_installed_disk(disk: &str) -> String {
        format!(
            r#"{{"verdict":"signature-verified","url":"https://example.invalid/i.iso",
                 "served_by":"example.invalid",
                 "manifest_url":"https://example.invalid/i.iso.sha256",
                 "digest_kind":"sha256","digest":"{}","digest_matched":true,
                 "signature":"detached .asc","installed_disk":{disk}}}"#,
            "ab".repeat(32)
        )
    }

    /// An installed disk is carried as a nested object, is absent rather than null when
    /// not supplied, and says in `established_by` that the booted disk is derived.
    #[test]
    fn an_installed_disk_is_carried_nested_and_absent_when_not_supplied() {
        let disk = format!(
            r#"{{"sha256":"{}","installed_at":"2026-09-30T16:23:38Z",
                 "installed_from_digest":"{}"}}"#,
            "EF".repeat(32),
            "ab".repeat(32)
        );
        let a = Attestation::from_json(&with_installed_disk(&disk)).expect("well-formed");
        let record = ImageAttestation::classify(ExecutionMode::Vm, Some(a)).unwrap();
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["installed_disk"]["sha256"], "ef".repeat(32));
        assert_eq!(
            json["installed_disk"]["installed_at"],
            "2026-09-30T16:23:38Z"
        );
        assert_eq!(
            json["installed_disk"]["installed_from_digest"],
            "ab".repeat(32)
        );
        assert!(
            record.established_by.contains("installed_disk"),
            "{}",
            record.established_by
        );

        let plain = ImageAttestation::classify(ExecutionMode::Vm, Some(attestation(true)));
        let json = serde_json::to_value(plain.unwrap()).unwrap();
        assert!(
            json.as_object().unwrap().get("installed_disk").is_none(),
            "absent, not null: {json}"
        );
    }

    /// A key this build does not know is refused rather than dropped. The attestation is
    /// hashed into `run.inputs_sha256`, so a dropped key is a dropped input: a build that
    /// predated `installed_disk` published `attested` with the digest of a report made
    /// before the field existed. The same misspelling one level down is refused by
    /// `RawInstalledDisk`; this is the level above it.
    #[test]
    fn an_attestation_with_a_key_this_build_does_not_know_is_refused() {
        let known = format!(
            r#"{{"verdict":"v","url":"u","served_by":"s","manifest_url":"m",
                 "digest_kind":"sha256","digest":"{}","digest_matched":true,
                 "signature":"none"}}"#,
            "ab".repeat(32)
        );
        assert!(
            Attestation::from_json(&known).is_ok(),
            "the known keys parse"
        );
        let unknown = known.replacen('{', r#"{"installed_disc":{},"#, 1);
        let refused = Attestation::from_json(&unknown);
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains("installed_disc")),
            "an unknown key must be refused by name, not dropped: {refused:?}"
        );
    }

    /// An attestation, and its installed disk, is an object and nothing else. serde's derive
    /// also reads a struct from a JSON array, field by field in declaration order, so
    /// `["v","u","s",...]` would parse as an attestation (`fuzz/crashes/attestation/`) and
    /// a writer with another field order would have its strings (`verdict`, `url`,
    /// `served_by`, `origin`, `manifest_url`) assigned to one another's fields without a
    /// refusal, the silent reinterpretation `deny_unknown_fields` exists to prevent for
    /// keys. The schema publishes both as objects with `additionalProperties: false`.
    #[test]
    fn an_attestation_or_installed_disk_written_as_an_array_is_refused() {
        let digest = "ab".repeat(32);
        let positional = format!(
            r#"["v","u","s","recorded-at-fetch","m","sha256","{digest}",true,true,"none",
                null,null,null]"#
        );
        let refused = Attestation::from_json(&positional);
        assert!(
            refused.as_ref().is_err_and(|e| e.contains("sequence")),
            "an array is not an attestation: {refused:?}"
        );
        let disk = format!(
            r#"{{"verdict":"v","url":"u","served_by":"s","manifest_url":"m",
                 "digest_kind":"sha256","digest":"{digest}","digest_matched":true,
                 "signature":"none","installed_disk":["{}","2024-02-29T00:00:00Z","{digest}"]}}"#,
            "f".repeat(64)
        );
        let refused = Attestation::from_json(&disk);
        assert!(
            refused.as_ref().is_err_and(|e| e.contains("sequence")),
            "an array is not an installed disk: {refused:?}"
        );
        // The same records as objects parse, so the refusal is of the shape alone.
        let object = disk.replace(
            &format!(
                r#"["{}","2024-02-29T00:00:00Z","{digest}"]"#,
                "f".repeat(64)
            ),
            &format!(
                r#"{{"sha256":"{}","installed_at":"2024-02-29T00:00:00Z",
                     "installed_from_digest":"{digest}"}}"#,
                "f".repeat(64)
            ),
        );
        assert!(Attestation::from_json(&object).is_ok(), "{object}");
    }

    /// Each field of a timestamp is held at its own edge: an hour of 24 and a minute of 60
    /// are refused, a February day in a common year is accepted, and the shape is the
    /// whole text, so a trailing word or a wrong separator is refused.
    #[test]
    fn a_timestamp_is_held_at_each_field_s_edge() {
        assert!(is_utc_timestamp("2026-02-10T00:00:00Z"));
        assert!(!is_utc_timestamp("2026-10-23T24:00:00Z"));
        assert!(!is_utc_timestamp("2026-10-23T00:60:00Z"));
        assert!(!is_utc_timestamp("2026-10-23T00:00:00Z trailing"));
        assert!(!is_utc_timestamp("2026/10/23T00:00:00Z"));
    }

    /// An installed disk reads back the digest it was installed from, and an empty one is
    /// refused.
    #[test]
    fn an_installed_disk_reads_back_its_source_and_refuses_an_empty_one() {
        let disk = |from: &str| {
            format!(
                r#"{{"sha256":"{}","installed_at":"2026-09-30T16:23:38Z",
                     "installed_from_digest":"{from}"}}"#,
                "ef".repeat(32)
            )
        };
        let from = "ab".repeat(32);
        let read = Attestation::from_json(&with_installed_disk(&disk(&from)))
            .expect("a well-formed record");
        assert_eq!(
            read.installed_disk()
                .map(InstalledDisk::installed_from_digest),
            Some(from.as_str())
        );
        assert!(Attestation::from_json(&with_installed_disk(&disk(""))).is_err());
        // Read alone, before the attestation's own digest is compared with it: an empty
        // source digest is refused by the record itself.
        let alone = serde_json::from_str::<InstalledDisk>(&disk(""))
            .expect_err("an empty source digest is refused");
        assert!(alone.to_string().contains("is not hex"), "{alone}");
    }

    /// The fields a refusal quotes read back as the attestation wrote them, and one written
    /// without an `origin` reads as `not-recorded`.
    #[test]
    fn an_attestation_reads_back_the_fields_a_refusal_quotes() {
        let read = attestation(true);
        assert_eq!(
            (read.url(), read.manifest_url(), read.digest_kind()),
            (
                "https://example.invalid/i.qcow2",
                "https://example.invalid/SHA256SUMS",
                "sha256"
            )
        );
        let published = serde_json::to_value(&read).expect("an attestation serializes");
        assert_eq!(published["origin"], "not-recorded");
    }

    /// A value quoted into a sentence escapes its backticks and every character that does not
    /// print as itself (controls, format and separator characters) and its backslashes, and
    /// keeps every other character as written, the quotes among them.
    #[test]
    fn a_quoted_value_escapes_backticks_and_what_does_not_print_only() {
        assert_eq!(quoted("it's \"x\" é"), "`it's \"x\" é`");
        assert_eq!(quoted("a\\u{1b}b"), "`a\\\\u{1b}b`");
        assert_ne!(quoted("\\u{1b}"), quoted("\u{1b}"));
        assert_eq!(quoted("a\tb`c"), "`a\\tb\\`c`");
        assert_eq!(
            quoted("lxc\u{202e}cxl\u{2028}\u{200b}"),
            "`lxc\\u{202e}cxl\\u{2028}\\u{200b}`"
        );
    }

    /// The kernel's own machine is read where `/proc/sys/kernel/arch` names one.
    #[test]
    fn the_kernel_s_own_machine_is_read_where_the_kernel_names_it() {
        let arch = match std::fs::read_to_string("/proc/sys/kernel/arch") {
            Ok(arch) => arch,
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                panic!("/proc/sys/kernel/arch is there and does not read: {e}")
            }
            Err(_) => {
                crate::error::capability_gap(
                    "the_kernel_s_own_machine_is_read_where_the_kernel_names_it",
                    "this kernel has no /proc/sys/kernel/arch",
                );
                return;
            }
        };
        assert_eq!(
            platform_reads().kernel_machine.as_deref(),
            Some(arch.trim()).filter(|a| !a.is_empty())
        );
    }

    /// A macOS identity without a build number still names the release.
    #[test]
    fn a_mac_identity_without_a_build_names_the_release() {
        let plist = "<plist version=\"1.0\">\n<dict>\n\
             \t<key>ProductName</key>\n\t<string>macOS</string>\n\
             \t<key>ProductVersion</key>\n\t<string>27.0</string>\n\
             </dict>\n</plist>\n";
        assert_eq!(
            distro_from_system_version(plist).pretty_name.as_deref(),
            Some("macOS 27.0")
        );
    }

    /// A CPU's vendor, model and features are the first core's, as `/proc/cpuinfo` repeats
    /// them per core.
    #[test]
    fn the_cpu_is_read_from_its_first_core() {
        let cpu = cpu_from(Some(
            "vendor_id\t: GenuineIntel\nmodel name\t: first\nflags\t\t: fpu ibt shstk\n\n\
             vendor_id\t: AuthenticAMD\nmodel name\t: second\nflags\t\t: shstk smap\n",
        ));
        assert_eq!(cpu.vendor.as_deref(), Some("GenuineIntel"));
        assert_eq!(cpu.model_name.as_deref(), Some("first"));
        assert_eq!(cpu.relevant_features, ["ibt", "shstk"]);
    }

    /// A timestamp is an instant, not a shape: the day is checked against its month,
    /// including the Gregorian leap rule, which admits these and refuses their neighbours
    /// in `a_malformed_installed_disk_is_refused_at_parse_time`.
    #[test]
    fn a_real_leap_day_and_the_last_second_of_a_day_are_accepted() {
        for stamp in [
            "2028-02-29T00:00:00Z",
            "2000-02-29T12:00:00Z",
            "2026-12-31T23:59:59Z",
        ] {
            assert!(is_utc_timestamp(stamp), "{stamp} is a real instant");
        }
    }

    /// An installed-disk record that disagrees with itself or with its attestation is
    /// refused at parse time, as a malformed digest is.
    #[test]
    fn a_malformed_installed_disk_is_refused_at_parse_time() {
        let good_from = "ab".repeat(32);
        let good_disk = "ef".repeat(32);
        for (label, disk) in [
            (
                "installed from another artifact",
                format!(
                    r#"{{"sha256":"{good_disk}","installed_at":"2026-09-30T16:23:38Z",
                         "installed_from_digest":"{}"}}"#,
                    "cd".repeat(32)
                ),
            ),
            (
                "truncated disk digest",
                format!(
                    r#"{{"sha256":"{}","installed_at":"2026-09-30T16:23:38Z",
                         "installed_from_digest":"{good_from}"}}"#,
                    "ef".repeat(31)
                ),
            ),
            (
                "date without a time",
                format!(
                    r#"{{"sha256":"{good_disk}","installed_at":"2026-09-30",
                         "installed_from_digest":"{good_from}"}}"#
                ),
            ),
            (
                "month 13",
                format!(
                    r#"{{"sha256":"{good_disk}","installed_at":"2026-13-01T00:00:00Z",
                         "installed_from_digest":"{good_from}"}}"#
                ),
            ),
            (
                "every field out of range",
                format!(
                    r#"{{"sha256":"{good_disk}","installed_at":"2026-13-45T25:61:61Z",
                         "installed_from_digest":"{good_from}"}}"#
                ),
            ),
            (
                "the thirty-first of September",
                format!(
                    r#"{{"sha256":"{good_disk}","installed_at":"2026-09-31T12:00:00Z",
                         "installed_from_digest":"{good_from}"}}"#
                ),
            ),
            (
                "the twenty-ninth of February in a common year",
                format!(
                    r#"{{"sha256":"{good_disk}","installed_at":"2100-02-29T12:00:00Z",
                         "installed_from_digest":"{good_from}"}}"#
                ),
            ),
            (
                "a leap second",
                format!(
                    r#"{{"sha256":"{good_disk}","installed_at":"2026-12-31T23:59:60Z",
                         "installed_from_digest":"{good_from}"}}"#
                ),
            ),
            (
                "missing installed_at",
                format!(r#"{{"sha256":"{good_disk}","installed_from_digest":"{good_from}"}}"#),
            ),
            (
                "unknown key",
                format!(
                    r#"{{"sha256":"{good_disk}","installed_at":"2026-09-30T16:23:38Z",
                         "installed_from_digest":"{good_from}","disk_sha256":"x"}}"#
                ),
            ),
            ("null", "null".to_owned()),
        ] {
            let parsed = Attestation::from_json(&with_installed_disk(&disk));
            if label == "null" {
                // `null` deserialises to `None`: the same as the key being absent, and
                // serialised back out as absent.
                assert!(parsed.expect("null is absence").installed_disk().is_none());
                continue;
            }
            assert!(parsed.is_err(), "{label} must be refused: {parsed:?}");
        }
    }

    /// The status must always be rendered. An omitted field would read as nothing to
    /// report when what is being reported is that nothing established the image.
    #[test]
    fn an_unattested_status_is_serialised_rather_than_skipped() {
        let a = ImageAttestation::classify(ExecutionMode::Vm, None).unwrap();
        let json = serde_json::to_value(&a).unwrap();
        assert_eq!(
            json.get("status").and_then(|s| s.as_str()),
            Some("unattested")
        );
        assert!(json.get("digest").is_none());
    }

    #[test]
    fn os_release_values_are_unquoted() {
        let text = "NAME=\"Fedora Linux\"\nID=fedora\nVERSION_ID=44\n# comment\n\n";
        let fields = parse_os_release(text);
        assert_eq!(fields.get("NAME").map(String::as_str), Some("Fedora Linux"));
        assert_eq!(fields.get("ID").map(String::as_str), Some("fedora"));
        assert_eq!(fields.get("VERSION_ID").map(String::as_str), Some("44"));
        assert_eq!(fields.len(), 3);
    }

    /// A present-but-empty value is the absence it spells.
    ///
    /// Fedora's os-release carries `VERSION_CODENAME=""`, and the field came through as
    /// `Some("")`. Every report from that image then published `codename: ""`, and a
    /// column key built by concatenating the distro fields read `fedora+44++gcc-...`,
    /// with a doubled separator where a reader expects either a codename or nothing.
    #[test]
    fn a_present_but_empty_os_release_value_is_absent() {
        let fedora = "NAME=\"Fedora Linux\"\nID=fedora\nVERSION_ID=44\n\
                      VERSION_CODENAME=\"\"\nPRETTY_NAME=''\n";
        let fields = parse_os_release(fedora);
        assert!(!fields.contains_key("VERSION_CODENAME"));
        assert!(!fields.contains_key("PRETTY_NAME"));
        assert_eq!(fields.len(), 3, "the three populated keys survive");

        let d = distro_from(Some(fedora));
        assert_eq!(d.id, "fedora");
        assert_eq!(d.version_id, "44");
        assert_eq!(d.codename, None, "an empty codename is no codename");
        assert_eq!(d.pretty_name, None);

        // The fallback reaches a derivative that spells the primary key empty.
        let derivative = "ID=mint\nVERSION_ID=22\nVERSION_CODENAME=\"\"\nUBUNTU_CODENAME=noble\n";
        assert_eq!(
            distro_from(Some(derivative)).codename.as_deref(),
            Some("noble")
        );

        // A populated codename is untouched.
        let ubuntu = "ID=ubuntu\nVERSION_ID=\"26.04\"\nVERSION_CODENAME=resolute\n";
        assert_eq!(
            distro_from(Some(ubuntu)).codename.as_deref(),
            Some("resolute")
        );
    }

    /// A failed with-headers dump keeps the C library a present macro names, under every
    /// arm, with a detection naming that macro and the failure and claiming no absence;
    /// glibc's version only where both of its macros came out; `not identified` where no
    /// macro names a library. A clean dump reads as `detect_libc` reads it.
    #[test]
    fn a_failed_headers_dump_keeps_what_its_macros_name_and_says_it_failed() {
        let map = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        let failure = "exited 1: macros-with-headers.c:1:10: fatal error: late.h";
        let failed = |macros: &BTreeMap<String, String>| {
            libc_of(HeadersDump {
                macros,
                failure: Some(failure),
            })
        };
        let glibc = map(&[("__GLIBC__", "2"), ("__GLIBC_MINOR__", "43")]);
        let clean = libc_of(HeadersDump {
            macros: &glibc,
            failure: None,
        });
        let direct = detect_libc(&glibc);
        assert_eq!(
            (&clean.impl_name, &clean.version, &clean.detection),
            (&direct.impl_name, &direct.version, &direct.detection)
        );
        for (macros, impl_name, version, named_by) in [
            (
                glibc.clone(),
                "glibc",
                Some("2.43"),
                "__GLIBC__ and __GLIBC_MINOR__",
            ),
            (
                map(&[("__NEED_size_t", "")]),
                "musl",
                None,
                "musl's __NEED_* header guards",
            ),
            (map(&[("__OpenBSD__", "1")]), "openbsd", None, "__OpenBSD__"),
            (map(&[("__BIONIC__", "1")]), "bionic", None, "__BIONIC__"),
            (
                map(&[("__FreeBSD__", "15")]),
                "freebsd",
                Some("15"),
                "__FreeBSD__",
            ),
            (
                map(&[("__APPLE__", "1"), ("__MACH__", "1")]),
                "apple",
                None,
                "__APPLE__ and __MACH__",
            ),
        ] {
            let read = failed(&macros);
            assert_eq!(read.impl_name, impl_name);
            if impl_name != "musl" {
                // musl's version is the loader's, not the dump's.
                assert_eq!(read.version.as_deref(), version, "{impl_name}");
            }
            assert_eq!(
                read.detection,
                format!(
                    "{impl_name} by {named_by} in a with-headers macro dump that {failure}; a \
                     failed dump's defines are real and what it lacks is not read"
                )
            );
            assert!(
                !read.detection.contains("no __GLIBC__"),
                "{}",
                read.detection
            );
        }
        let half = failed(&map(&[("__GLIBC__", "2")]));
        assert_eq!(
            (half.impl_name.as_str(), half.version.as_deref()),
            ("glibc", None)
        );
        assert!(
            half.detection.contains("the version is not read"),
            "{}",
            half.detection
        );
        let none = BTreeMap::new();
        let unread = libc_of(HeadersDump {
            macros: &none,
            failure: Some("was killed by a signal"),
        });
        assert_eq!(
            (unread.impl_name.as_str(), unread.version),
            ("unknown", None)
        );
        assert_eq!(
            unread.detection,
            "not identified: the with-headers macro dump was killed by a signal, and no macro \
             in the lines read from it names a C library"
        );
    }

    #[test]
    fn glibc_version_comes_from_macros() {
        let macros = BTreeMap::from([
            ("__GLIBC__".to_owned(), "2".to_owned()),
            ("__GLIBC_MINOR__".to_owned(), "43".to_owned()),
        ]);
        let libc = detect_libc(&macros);
        assert_eq!(libc.impl_name, "glibc");
        assert_eq!(libc.version.as_deref(), Some("2.43"));
    }

    #[test]
    fn absent_glibc_macros_do_not_silently_become_glibc() {
        let libc = detect_libc(&BTreeMap::new());
        assert_eq!(libc.impl_name, "unknown");
        assert!(libc.version.is_none());
    }

    /// musl announces itself with no macro, so the identification reads its internal
    /// `__NEED_*` header guards: `<stdio.h>`, `<stdlib.h>` and `<string.h>` each define a
    /// set before including `<bits/alltypes.h>` and never undefine them, and the
    /// with-headers dump includes all three. The names below are the ones musl 1.2's
    /// `stdio.h` sets.
    ///
    /// `__DEFINED_size_t` is in the fixture deliberately and carries no weight: gcc's own
    /// `stddef.h` defines it for every libc, which would identify a glibc host
    /// as musl. The second half holds that a dump carrying only the `__DEFINED_*` markers
    /// stays `unknown`. Four fortify checks gate on the string `musl`, so a wrong answer in
    /// either direction changes a published verdict: `unknown` on Alpine lets
    /// `fortify-requested` publish `on` for a libc with no `_FORTIFY_SOURCE`, and `musl` on
    /// a glibc host withholds four checks as `unsupported`. The assumption this rests on is
    /// `need-macros-identify-musl` in `THREAT_MODEL.md`'s register.
    #[test]
    fn musl_is_identified_by_its_need_guards_and_by_nothing_else() {
        let musl = BTreeMap::from([
            ("__NEED_FILE".to_owned(), String::new()),
            ("__NEED___isoc_va_list".to_owned(), String::new()),
            ("__NEED_off_t".to_owned(), String::new()),
            ("__NEED_size_t".to_owned(), String::new()),
            ("__NEED_ssize_t".to_owned(), String::new()),
            ("__NEED_va_list".to_owned(), String::new()),
            ("__DEFINED_FILE".to_owned(), String::new()),
            ("__DEFINED_size_t".to_owned(), String::new()),
        ]);
        let libc = detect_libc(&musl);
        assert_eq!(libc.impl_name, "musl");
        // The composite reads musl by the name this function writes: a native musl driver's
        // triple sets the umbrella's fortify bar at 2 from this very reading, so a rename
        // here cannot quietly turn musl back into a withheld slot.
        assert_eq!(
            crate::composite::fortify_bar(
                &libc,
                Some("x86_64-alpine-linux-musl"),
                crate::composite::FHARDENED_FORTIFY
            )
            .map(|(level, _)| level),
            Ok(2),
            "musl from its __NEED_ guards sets the fortify bar gcc's rule gives it"
        );
        assert!(
            libc.detection.contains("__NEED_"),
            "the detection string names the guards that were read: {}",
            libc.detection
        );

        // gcc's stddef.h markers alone identify nothing.
        let stddef_only = BTreeMap::from([
            ("__DEFINED_ptrdiff_t".to_owned(), String::new()),
            ("__DEFINED_size_t".to_owned(), String::new()),
            ("__DEFINED_wchar_t".to_owned(), String::new()),
        ]);
        assert_eq!(detect_libc(&stddef_only).impl_name, "unknown");

        // glibc with those same markers is glibc.
        let mut glibc = stddef_only.clone();
        glibc.insert("__GLIBC__".to_owned(), "2".to_owned());
        glibc.insert("__GLIBC_MINOR__".to_owned(), "43".to_owned());
        let libc = detect_libc(&glibc);
        assert_eq!(libc.impl_name, "glibc");
        assert_eq!(libc.version.as_deref(), Some("2.43"));

        // `__GLIBC__` wins over the guards where a dump somehow carries both.
        let mut both = musl.clone();
        both.insert("__GLIBC__".to_owned(), "2".to_owned());
        assert_eq!(detect_libc(&both).impl_name, "glibc");
    }

    /// Nine rounds of Darwin reports read `libc: unknown`, with a detection string saying
    /// no libc macro was in the dump. The dump had Apple's macros throughout, and `apple`
    /// was already a name elsewhere in this crate: `detect_fortify_runtime` credits a trap
    /// under `_FORTIFY_IMPL` of `fortify-headers` or `apple`.
    ///
    /// The macros in the fixture below are the ones Apple clang 21 emits on arm64; only
    /// the pair being tested for matters, and `__GLIBC__`'s absence is the point of the
    /// second half.
    #[test]
    fn apple_is_identified_rather_than_reported_unidentifiable() {
        let apple = BTreeMap::from([
            ("__APPLE__".to_owned(), "1".to_owned()),
            ("__MACH__".to_owned(), "1".to_owned()),
            ("_USE_FORTIFY_LEVEL".to_owned(), "2".to_owned()),
        ]);
        let libc = detect_libc(&apple);
        assert_eq!(libc.impl_name, "apple");
        assert!(
            libc.detection.contains("__MACH__"),
            "the detection string has to name what was read, since this is a platform \
             inference rather than a libc announcing itself: {}",
            libc.detection
        );

        // glibc still wins where both are somehow present: a cross toolchain targeting
        // Darwin from a glibc host must not have its host libc relabelled.
        let mut both = apple.clone();
        both.insert("__GLIBC__".to_owned(), "2".to_owned());
        assert_eq!(detect_libc(&both).impl_name, "glibc");

        // `__APPLE__` without `__MACH__` is not enough to claim the base system.
        let partial = BTreeMap::from([("__APPLE__".to_owned(), "1".to_owned())]);
        assert_eq!(detect_libc(&partial).impl_name, "unknown");
    }

    /// The names in the code and the names in `LIBC_NAMES` are the same names.
    ///
    /// Scanned from the source because `impl_name` is a `String`: an arm returning a name
    /// nobody declared compiles, ships, and fails validation on the one platform that
    /// reaches it. `openbsd` did exactly that. The schema half of the binding is in
    /// `tests/schema_conformance.rs`.
    ///
    /// The needle is assembled at runtime so this test does not match itself.
    /// The plist read cannot be exercised on this host; the derivation from it can, which
    /// is the whole reason `PlatformReads` collects raw text before anything interprets it.
    /// The sample is `SystemVersion.plist`'s real shape, tabs and all.
    #[test]
    fn a_mac_report_carries_an_identity_rather_than_two_unknowns() {
        let plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <plist version=\"1.0\">\n<dict>\n\
             \t<key>ProductBuildVersion</key>\n\t<string>25F80</string>\n\
             \t<key>ProductCopyright</key>\n\t<string>1983-2026 Apple Inc.</string>\n\
             \t<key>ProductName</key>\n\t<string>macOS</string>\n\
             \t<key>ProductVersion</key>\n\t<string>26.5.1</string>\n\
             </dict>\n</plist>\n";
        let d = distro_from_system_version(plist);
        assert_eq!(d.id, "macos");
        assert!(d.is_macos());
        assert!(!distro_from(Some("ID=fedora\nVERSION_ID=44\n")).is_macos());
        assert!(!distro_from(None).is_macos());
        assert_eq!(d.version_id, "26.5.1");
        assert_eq!(d.pretty_name.as_deref(), Some("macOS 26.5.1 (25F80)"));
        assert!(d.codename.is_none());

        // An unreadable or unexpected file must give back `unknown`, not a plausible-looking
        // value.
        let empty = distro_from_system_version("<plist><dict></dict></plist>");
        assert_eq!(empty.id, "unknown");
        assert!(
            !empty.is_macos(),
            "a Mac whose file could not be read reads no translation line, so withholds"
        );
        assert_eq!(
            empty.version_id, "unknown",
            "`rolling` is os-release's reading of a missing version, and it means Arch; \
             macOS does not release that way"
        );

        // The key must be matched, not merely contained: a prefix match would read
        // `ProductVersion` out of the `ProductVersionExtra` above it.
        let shadowed = "<key>ProductVersionExtra</key><string>(a)</string>\
                        <key>ProductVersion</key><string>26.5.1</string>";
        assert_eq!(
            plist_string(shadowed, "ProductVersion").as_deref(),
            Some("26.5.1")
        );
    }

    #[test]
    fn no_libc_name_escapes_the_published_vocabulary() {
        let needle = format!("impl_name: {}", '"');
        let source = include_str!("env.rs");
        let found: std::collections::BTreeSet<&str> = source
            .match_indices(&needle)
            .filter_map(|(at, _)| {
                let rest = source.get(at.saturating_add(needle.len())..)?;
                rest.split('"').next()
            })
            .collect();
        assert!(
            !found.is_empty(),
            "no `impl_name:` assignments found at all, so this test verified nothing — \
             the field was probably renamed"
        );
        let declared: std::collections::BTreeSet<&str> = LIBC_NAMES.iter().copied().collect();
        assert_eq!(
            found,
            declared,
            "libc names in the code and in LIBC_NAMES disagree.\n  \
             returned here, undeclared: {:?}\n  declared, unreachable: {:?}",
            found.difference(&declared).collect::<Vec<_>>(),
            declared.difference(&found).collect::<Vec<_>>(),
        );
    }

    /// The kernel's machines against an artifact's: the readings of 2026-10-01 (an
    /// aarch64 artifact on the x86_64 host, under qemu-user, and on an aarch64 kernel), the
    /// x86_64 kernel's own i386 compat, an artifact of the kernel's family and the other
    /// width, and a kernel chard has no table for.
    #[test]
    fn a_kernel_runs_its_own_machines_and_hands_the_rest_on() {
        use ByteOrder::{BigEndian as BE, LittleEndian as LE};
        assert_eq!(
            runs_natively(read("x86_64"), "aarch64", 64, Some(LE)),
            Some(false)
        );
        assert_eq!(
            runs_natively(read("aarch64"), "aarch64", 64, Some(LE)),
            Some(true)
        );
        assert_eq!(
            runs_natively(read("x86_64"), "x86_64", 64, Some(LE)),
            Some(true)
        );
        assert_eq!(
            runs_natively(read("x86_64"), "i386", 32, Some(LE)),
            Some(true)
        );
        assert_eq!(
            runs_natively(read("i686"), "x86_64", 64, Some(LE)),
            Some(false)
        );
        assert_eq!(
            runs_natively(read("i686"), "i386", 32, Some(LE)),
            Some(true)
        );
        assert_eq!(
            runs_natively(read("aarch64"), "arm", 32, Some(LE)),
            Some(false)
        );
        assert_eq!(
            runs_natively(
                read("aarch64"),
                "unrecognised (e_machine 0x99)",
                64,
                Some(LE)
            ),
            Some(false)
        );
        assert_eq!(
            runs_natively(read("sparc64"), "sparc64", 64, Some(BE)),
            None
        );
        assert_eq!(
            runs_natively(read("ppc64le"), "ppc", 32, Some(LE)),
            Some(false)
        );
        assert_eq!(
            runs_natively(read("ppc64le"), "ppc64", 64, Some(LE)),
            Some(true)
        );
        assert_eq!(runs_natively(read("ppc"), "ppc", 32, Some(BE)), Some(true));
        assert_eq!(
            runs_natively(read("powerpc"), "ppc", 32, Some(BE)),
            Some(true)
        );
        assert_eq!(
            runs_natively(read("s390x"), "s390", 64, Some(BE)),
            Some(true)
        );
        assert_eq!(
            runs_natively(read("s390x"), "s390", 32, Some(BE)),
            Some(false)
        );
        // One `e_machine`, both widths: the class decides.
        assert_eq!(
            runs_natively(read("riscv64"), "riscv", 64, Some(LE)),
            Some(true)
        );
        assert_eq!(
            runs_natively(read("riscv64"), "riscv", 32, Some(LE)),
            Some(false)
        );
        assert_eq!(
            runs_natively(read("mips64"), "mips", 32, Some(LE)),
            Some(false)
        );
        assert_eq!(
            runs_natively(read("x86_64"), "x86_64", 32, Some(LE)),
            Some(false)
        );
    }

    /// One `e_machine`, both orders: the order decides. The cases of the other order, each of
    /// which would read `true` without the comparison; a record with no order; and chard's
    /// own `ARCH` standing in for an absent file, which runs chard's own order and not the
    /// other.
    #[test]
    fn a_kernel_runs_its_own_byte_order_and_hands_the_other_on() {
        use ByteOrder::{BigEndian as BE, LittleEndian as LE};
        assert_eq!(
            runs_natively(read("ppc64le"), "ppc64", 64, Some(BE)),
            Some(false)
        );
        assert_eq!(
            runs_natively(read("ppc64"), "ppc64", 64, Some(LE)),
            Some(false)
        );
        assert_eq!(
            runs_natively(read("ppc64"), "ppc64", 64, Some(BE)),
            Some(true)
        );
        assert_eq!(
            runs_natively(read("aarch64_be"), "aarch64", 64, Some(LE)),
            Some(false)
        );
        assert_eq!(
            runs_natively(read("aarch64_be"), "aarch64", 64, Some(BE)),
            Some(true)
        );
        assert_eq!(
            runs_natively(read("aarch64"), "aarch64", 64, Some(BE)),
            Some(false)
        );
        assert_eq!(
            runs_natively(read("mips64el"), "mips", 64, Some(BE)),
            Some(false)
        );
        assert_eq!(
            runs_natively(read("mips64el"), "mips", 64, Some(LE)),
            Some(true)
        );
        assert_eq!(
            runs_natively(read("x86_64"), "i386", 32, Some(BE)),
            Some(false)
        );
        // A read spelling that carries no order is nothing, whatever chard's build: a mips
        // kernel's word cannot be told, so the reading is withheld.
        assert_eq!(kernel_byte_order(read("mips64")), None);
        assert_eq!(runs_natively(read("mips64"), "mips", 64, Some(BE)), None);
        // A record that carries no order (one written before the field) is held to nothing
        // and rules nothing out.
        assert_eq!(runs_natively(read("x86_64"), "x86_64", 64, None), None);
        // Every value `std::env::consts::ARCH` takes on the platforms chard builds for has
        // a family row, since it is the fallback where `/proc/sys/kernel/arch` is absent,
        // and as chard's own it runs chard's own artifacts at its own width and in the
        // order chard was built for, not the other.
        let own = if cfg!(target_endian = "big") { BE } else { LE };
        let other = if own == BE { LE } else { BE };
        for (arch, machine, class) in [
            ("x86_64", "x86_64", 64),
            ("x86", "i386", 32),
            ("aarch64", "aarch64", 64),
            ("arm", "arm", 32),
            ("powerpc64", "ppc64", 64),
            ("s390x", "s390", 64),
            ("riscv64", "riscv", 64),
        ] {
            assert_eq!(
                runs_natively(NativeMachine::chards_own(arch), machine, class, Some(own)),
                Some(true),
                "{arch}"
            );
            assert_eq!(
                runs_natively(NativeMachine::chards_own(arch), machine, class, Some(other)),
                Some(false),
                "{arch}"
            );
        }
    }

    /// A spelling read from `/proc/sys/kernel/arch`, as a test names one.
    fn read(spelling: &str) -> NativeMachine<'_> {
        NativeMachine::read(spelling)
    }

    /// The kernel's own order from its spelling, each case the comparison rests on.
    #[test]
    fn a_kernels_byte_order_is_read_from_its_spelling() {
        use ByteOrder::{BigEndian as BE, LittleEndian as LE};
        for (kernel, order) in [
            ("x86_64", LE),
            ("i686", LE),
            ("aarch64", LE),
            ("arm64", LE),
            ("aarch64_be", BE),
            ("armv7l", LE),
            ("armv7b", BE),
            ("armv8b", BE),
            ("armv5tel", LE),
            ("armv5teb", BE),
            ("armeb", BE),
            ("ppc64le", LE),
            ("ppc64", BE),
            ("powerpc64", BE),
            ("ppc", BE),
            ("s390x", BE),
            ("riscv64", LE),
            ("loongarch64", LE),
            ("mipsel", LE),
            ("mips64el", LE),
            ("mipseb", BE),
        ] {
            assert_eq!(kernel_byte_order(read(kernel)), Some(order), "{kernel}");
        }
        for kernel in ["armv7", "arm"] {
            assert_eq!(
                kernel_byte_order(read(kernel)),
                Some(LE),
                "{kernel}: an arm spelling without its letter is the port's default"
            );
        }
        assert_eq!(kernel_byte_order(read("sparc64")), None, "no family row");
        assert_eq!(
            kernel_byte_order(read("mips")),
            None,
            "no order in the spelling, whatever this host is"
        );
        // chard's own `ARCH`, standing in for an absent file, answers from chard's own
        // build.
        let own = if cfg!(target_endian = "big") { BE } else { LE };
        assert_eq!(
            kernel_byte_order(NativeMachine::chards_own(std::env::consts::ARCH)),
            Some(own)
        );
    }

    /// chard's build decides the order only where the spelling is its own `ARCH` standing
    /// in for an absent `/proc/sys/kernel/arch`; a read spelling is the kernel's word,
    /// whatever chard was built for. The case that distinguishes them: a
    /// big-endian aarch64 chard under `qemu-aarch64_be` on a little-endian aarch64 kernel
    /// reads `aarch64` from the file, which is that kernel's, not chard's.
    #[test]
    fn a_read_spelling_is_the_kernels_word_and_only_chards_own_is_its_build() {
        use ByteOrder::{BigEndian as BE, LittleEndian as LE};
        let own = NativeMachine::chards_own;
        // The big-endian aarch64 chard, both ways.
        assert_eq!(kernel_byte_order_as(read("aarch64"), BE), Some(LE));
        assert_eq!(kernel_byte_order_as(own("aarch64"), BE), Some(BE));
        // A ppc64le chard spells its own `ARCH` `powerpc64`, and reads a `powerpc64` file
        // as the big-endian kernel it names.
        assert_eq!(kernel_byte_order_as(read("powerpc64"), LE), Some(BE));
        assert_eq!(kernel_byte_order_as(own("powerpc64"), LE), Some(LE));
        // A mips chard: its own `ARCH` is its build, and a read `mips64` is nobody's.
        assert_eq!(kernel_byte_order_as(read("mips64"), BE), None);
        assert_eq!(kernel_byte_order_as(own("mips64"), BE), Some(BE));
        // The read x86_64 of every run on this host is the table's little, not a clause
        // about chard's build.
        assert_eq!(kernel_byte_order_as(read("x86_64"), BE), Some(LE));
        assert!(read("x86_64").was_read() && !own("x86_64").was_read());
    }

    /// A big-endian arm kernel hands a little-endian arm artifact to an interpreter: the
    /// case a reader of `armv7b` alone decides wrongly, and the case the register entry
    /// `kernel-spelling-names-its-byte-order` names.
    #[test]
    fn a_big_endian_arm_kernel_does_not_run_a_little_endian_arm_artifact() {
        use ByteOrder::{BigEndian as BE, LittleEndian as LE};
        for kernel in ["armv7b", "armv8b", "armeb", "armv5teb"] {
            assert_eq!(
                runs_natively(read(kernel), "arm", 32, Some(LE)),
                Some(false),
                "{kernel}"
            );
            assert_eq!(
                runs_natively(read(kernel), "arm", 32, Some(BE)),
                Some(true),
                "{kernel}"
            );
        }
        for kernel in ["armv7l", "armv8l", "armv5tel"] {
            assert_eq!(
                runs_natively(read(kernel), "arm", 32, Some(LE)),
                Some(true),
                "{kernel}"
            );
            assert_eq!(
                runs_natively(read(kernel), "arm", 32, Some(BE)),
                Some(false),
                "{kernel}"
            );
        }
    }

    /// `machine` where read, chard's own `arch` where not: under qemu-user the two differ
    /// and the kernel's is the one that says the run was emulated.
    #[test]
    fn the_native_machine_is_the_kernels_word_where_it_has_one() {
        let mut kernel = Kernel {
            release: "7.3.0".to_owned(),
            arch: "aarch64".to_owned(),
            machine: Some("x86_64".to_owned()),
            is_host_kernel: false,
            ownership: KernelOwnership::Own,
        };
        assert_eq!(kernel.native_machine(), NativeMachine::read("x86_64"));
        kernel.machine = None;
        assert_eq!(
            kernel.native_machine(),
            NativeMachine::chards_own("aarch64")
        );
    }

    #[test]
    fn container_mode_marks_the_kernel_unrepresentative() {
        assert!(!ExecutionMode::Container.kernel_is_representative());
        assert!(ExecutionMode::Vm.kernel_is_representative());
        assert!(ExecutionMode::Host.kernel_is_representative());
    }

    /// An `Execution` of `mode` on `basis`, with the one observation the attribution quotes.
    fn execution_on(mode: ExecutionMode, basis: ModeBasis) -> Execution {
        let observed = matches!(
            basis,
            ModeBasis::Measured | ModeBasis::AssertedAndCorroborated
        );
        Execution {
            mode,
            engine: None,
            image: None,
            detection: String::new(),
            mode_evidence: ModeEvidence {
                basis,
                observed: observed.then_some(mode),
                observation: "what chard looked at".to_owned(),
            },
            image_attestation: ImageAttestation::not_applicable(),
        }
    }

    /// Whose kernel a `needs_vm` reading describes is the mode read with its basis: a
    /// container, observed or asserted, is borrowed; `host` or `vm` on the operator's word
    /// is established; `host` by default is neither, and carries the observation. Until
    /// 2026-10-15 the gate read the mode alone, under which the default measured.
    #[test]
    fn whose_kernel_a_needs_vm_reading_describes_is_the_mode_read_with_its_basis() {
        use ExecutionMode::{Container, Host, Vm};
        use KernelAttribution::{Assumed, Borrowed, Established};
        use ModeBasis::{
            AssertedAndContradicted, AssertedAndCorroborated, AssertedButUnobservable, AssumedHost,
            Measured,
        };
        let assumed = Assumed {
            observation: "what chard looked at",
        };
        let expected = [
            // The default, the case that published before: whatever the mode's word.
            (Host, AssumedHost, assumed),
            (Vm, AssumedHost, assumed),
            // The operator's word, which nothing observed: established on that word alone.
            (Host, AssertedButUnobservable, Established),
            (Vm, AssertedButUnobservable, Established),
            // A container, however it was arrived at.
            (Container, Measured, Borrowed),
            (Container, AssertedAndCorroborated, Borrowed),
            (Container, AssertedButUnobservable, Borrowed),
            (Container, AssumedHost, Borrowed),
            // A contradicted assertion never publishes; the attribution still reads the mode.
            (Host, AssertedAndContradicted, Established),
            (Container, AssertedAndContradicted, Borrowed),
        ];
        for (mode, basis, want) in expected {
            assert_eq!(
                execution_on(mode, basis).kernel_attribution(),
                want,
                "{mode:?} on {basis:?}"
            );
        }
        // The frame: every basis is a row above, so a basis added to the enum fails here
        // until the table says what it attributes.
        for basis in ModeBasis::ALL {
            assert!(
                expected.iter().any(|(_, b, _)| b == basis),
                "{basis:?} has no row"
            );
        }
    }

    /// `kernel.ownership` is the attribution and nothing else: `unsettled` on the default
    /// whatever the mode's word, where `is_host_kernel` reads `false`; `own` on the
    /// operator's `host` or `vm`; `borrowed` in a container. Its published spelling is the
    /// one `as_str` gives, which the re-check on read parses.
    #[test]
    fn the_published_ownership_is_the_attribution() {
        use ExecutionMode::{Container, Host, Vm};
        use KernelOwnership::{Borrowed, Own, Unsettled};
        use ModeBasis::{AssertedButUnobservable, AssumedHost, Measured};
        for (mode, basis, want, is_host_kernel) in [
            (Host, AssumedHost, Unsettled, false),
            (Vm, AssumedHost, Unsettled, false),
            (Host, AssertedButUnobservable, Own, false),
            (Vm, AssertedButUnobservable, Own, false),
            (Container, Measured, Borrowed, true),
            (Container, AssertedButUnobservable, Borrowed, true),
        ] {
            let execution = execution_on(mode, basis);
            assert_eq!(
                KernelOwnership::from(execution.kernel_attribution()),
                want,
                "{mode:?} on {basis:?}"
            );
            assert_eq!(!mode.kernel_is_representative(), is_host_kernel);
        }
        // The lists the re-check on read parses through: a variant the match below names
        // must be in its list, and a variant added to an enum fails this match to compile.
        for mode in [Host, Container, Vm] {
            match mode {
                Host | Container | Vm => assert!(ExecutionMode::ALL.contains(&mode)),
            }
        }
        for ownership in [Own, Borrowed, Unsettled] {
            match ownership {
                Own | Borrowed | Unsettled => assert!(KernelOwnership::ALL.contains(&ownership)),
            }
        }
        for ownership in KernelOwnership::ALL {
            assert_eq!(
                serde_json::to_value(ownership).expect("serializes"),
                serde_json::json!(ownership.as_str())
            );
        }
        for mode in ExecutionMode::ALL {
            assert_eq!(
                serde_json::to_value(mode).expect("serializes"),
                serde_json::json!(mode.as_str())
            );
        }
    }

    /// A container chard has no instrument for reads as a bare host does: nothing settles
    /// either, so the mode is `host` by default and whose kernel it is stays open. The
    /// shape is a rootful runtime with the marker files gone and no positive marker planted
    /// (mock, a chroot, a runtime that writes no `/run/systemd/container` and sets no
    /// `container=` on PID 1; systemd-nspawn and LXC plant both, which are read): cgroup
    /// v2's root for PID 1, a shell as PID 1 whose environment carries
    /// no word, an identity uid map. `Established` is therefore never observed, only
    /// asserted.
    #[test]
    fn an_unrecognised_container_reads_as_the_default_a_bare_host_reads() {
        let unrecognised = PlatformReads {
            os_release: Some("ID=debian".to_owned()),
            cpuinfo: Some("processor\t: 0".to_owned()),
            kernel_release: Some("7.3.0".to_owned()),
            pid1_comm: Some("bash".to_owned()),
            uid_map: Some("0 0 4294967295".to_owned()),
            pid1_cgroup: Some("0::/".to_owned()),
            systemd_container: Some(FileRead::Absent),
            pid1_environ: Some(FileRead::Content("PATH=/usr/bin\0HOME=/root\0".to_owned())),
            ..Default::default()
        };
        let bare = PlatformReads {
            pid1_comm: Some("systemd".to_owned()),
            pid1_cgroup: Some("0::/init.scope".to_owned()),
            pid1_environ: Some(FileRead::Unreadable(
                "permission denied, os error 13".to_owned(),
            )),
            ..unrecognised.clone()
        };
        for (name, reads) in [
            ("an unrecognised container", unrecognised),
            ("a bare host", bare),
        ] {
            let (observed, engine, observation) = observe_execution_mode(&reads);
            assert_eq!(observed, None, "{name} settles nothing: {observation}");
            assert_eq!(engine, None);
            assert!(
                observation.contains("no runtime marker file, no /run/systemd/container")
                    && observation.contains("the identity uid map `0 0 4294967295`"),
                "{name}: {observation}"
            );
            assert_eq!(
                mode_basis(observed, ExecutionMode::Host),
                ModeBasis::AssertedButUnobservable,
                "{name}: the operator's word is the one thing that establishes it"
            );
        }
        // And without that word the record is `host` on `assumed-host`, which the gate holds
        // open rather than measuring under.
        let by_default = execution_on(ExecutionMode::Host, ModeBasis::AssumedHost);
        assert_eq!(
            by_default.kernel_attribution(),
            KernelAttribution::Assumed {
                observation: "what chard looked at"
            }
        );
    }

    /// A positive marker's row: `reads` settle `container` with exactly `says` as the
    /// observation and `engine` beside it; an asserted `host` or `vm` beside that is
    /// contradicted, which the consistency pass refuses, and an asserted `container`
    /// corroborated.
    fn settles_container(name: &str, reads: &PlatformReads, says: &str, engine: Option<&str>) {
        let (observed, read_engine, observation) = observe_execution_mode(reads);
        assert_eq!(
            observed,
            Some(ExecutionMode::Container),
            "{name}: {observation}"
        );
        assert_eq!(observation, says, "{name}");
        assert_eq!(read_engine.as_deref(), engine, "{name}");
        for asserted in [ExecutionMode::Host, ExecutionMode::Vm] {
            assert_eq!(
                mode_basis(observed, asserted),
                ModeBasis::AssertedAndContradicted,
                "{name}: an asserted {asserted:?} beside the marker is contradicted"
            );
        }
        assert_eq!(
            mode_basis(observed, ExecutionMode::Container),
            ModeBasis::AssertedAndCorroborated,
            "{name}"
        );
    }

    /// A silent row: `reads` settle nothing, with exactly `says` as the observation.
    fn settles_nothing(name: &str, reads: &PlatformReads, says: &str) {
        let (observed, engine, observation) = observe_execution_mode(reads);
        assert_eq!(observed, None, "{name} settles nothing: {observation}");
        assert_eq!(engine, None, "{name}");
        assert_eq!(observation, says, "{name}");
        assert_eq!(
            mode_basis(observed, ExecutionMode::Host),
            ModeBasis::AssertedButUnobservable,
            "{name}: the operator's word is the one thing that establishes it"
        );
    }

    /// A rootful container with the runtime's marker gone and no word on PID 1, which the
    /// positive-marker tests plant their one marker into.
    fn marker_free_container() -> PlatformReads {
        PlatformReads {
            os_release: Some("ID=fedora".to_owned()),
            pid1_comm: Some("bash".to_owned()),
            uid_map: Some("0 0 4294967295".to_owned()),
            pid1_cgroup: Some("0::/".to_owned()),
            systemd_container: Some(FileRead::Absent),
            pid1_environ: Some(FileRead::Content("PATH=/usr/bin\0HOME=/root\0".to_owned())),
            ..Default::default()
        }
    }

    /// PID 1's environment with `word` as one entry, as the runtimes write it.
    fn environ_with(word: &str) -> FileRead {
        FileRead::Content(format!("PATH=/usr/bin\0{word}\0TERM=dumb\0"))
    }

    /// The default's sentence for a marker-free container whose markers read `silence`.
    fn default_sentence(silence: &str) -> String {
        format!(
            "no runtime marker file, {silence}, the identity uid map `0 0 4294967295`, /proc/1/comm is `bash`: nothing chard reads from inside tells a container that plants none of these from a system that owns its kernel"
        )
    }

    /// `/run/systemd/container` settles `container` on its content, which names the manager,
    /// and on nothing else: an empty file, which systemd neither writes nor reads, and a file
    /// this user may not read settle nothing and say so. Both markers planted read the
    /// file's sentence; a cgroup needle beside the file keeps its own. A planted value is
    /// quoted with its control characters and backticks escaped and its length capped.
    #[test]
    fn a_systemd_marker_settles_container_on_its_content_alone() {
        let file = |read: FileRead| PlatformReads {
            systemd_container: Some(read),
            ..marker_free_container()
        };
        settles_container(
            "systemd-nspawn's file",
            &file(FileRead::Content("systemd-nspawn\n".to_owned())),
            "/run/systemd/container names `systemd-nspawn`",
            None,
        );
        settles_container(
            "both markers planted",
            &PlatformReads {
                pid1_environ: Some(environ_with("container=lxc")),
                ..file(FileRead::Content("lxc".to_owned()))
            },
            "/run/systemd/container names `lxc`",
            None,
        );
        settles_container(
            "a cgroup needle beside the file",
            &PlatformReads {
                pid1_cgroup: Some("0::/lxc.payload.guest".to_owned()),
                ..file(FileRead::Content("lxc".to_owned()))
            },
            "/proc/1/cgroup mentions lxc",
            Some("lxc"),
        );
        settles_container(
            "a manager with a newline, an escape, a bell and a backtick in its name",
            &file(FileRead::Content(
                "systemd\nnspawn\u{1b}\u{7}`x\n".to_owned(),
            )),
            "/run/systemd/container names `systemd\\nnspawn\\u{1b}\\u{7}\\`x`",
            None,
        );
        settles_container(
            "a manager longer than the quote",
            &file(FileRead::Content("m".repeat(80))),
            &format!(
                "/run/systemd/container names `{}` (16 more characters cut)",
                "m".repeat(64)
            ),
            None,
        );
        settles_nothing(
            "an empty file",
            &file(FileRead::Content(String::new())),
            &default_sentence(
                "/run/systemd/container is empty, which systemd reads as no container, no `container=` word in PID 1's environment",
            ),
        );
        settles_nothing(
            "a file this user may not read",
            &file(FileRead::Unreadable(
                "permission denied, os error 13".to_owned(),
            )),
            &default_sentence(
                "/run/systemd/container unreadable (permission denied, os error 13), no `container=` word in PID 1's environment",
            ),
        );
    }

    /// A `container=` word on PID 1 settles `container` naming the runtime, as the
    /// environment's own entry wherever it sits and however it ends; an empty value is
    /// systemd's spelling of "not a container" and settles nothing; the instruments read
    /// before the word keep their sentence where both speak (podman sets `container=oci`
    /// beside `/run/.containerenv`), and a word beside a user namespace is read first. A
    /// planted value is quoted escaped and capped.
    #[test]
    fn a_container_word_on_pid_1_settles_container_and_an_empty_one_settles_nothing() {
        let word = |environ: &str| PlatformReads {
            pid1_environ: Some(FileRead::Content(environ.to_owned())),
            ..marker_free_container()
        };
        let long = "a".repeat(80);
        for (name, reads, says, engine) in [
            (
                "LXC's word",
                word("PATH=/usr/bin\0container=lxc\0TERM=dumb\0"),
                "PID 1's environment carries `container=lxc`".to_owned(),
                None,
            ),
            (
                "the word first",
                word("container=lxc\0PATH=/usr/bin\0"),
                "PID 1's environment carries `container=lxc`".to_owned(),
                None,
            ),
            (
                "the word last and unterminated",
                word("PATH=/usr/bin\0container=systemd-nspawn"),
                "PID 1's environment carries `container=systemd-nspawn`".to_owned(),
                None,
            ),
            (
                "the word beside a user namespace",
                PlatformReads {
                    uid_map: Some("1000 0 1".to_owned()),
                    ..word("container=lxc\0")
                },
                "PID 1's environment carries `container=lxc`".to_owned(),
                None,
            ),
            (
                "podman's marker file beside its word",
                PlatformReads {
                    container_marker: Some("podman marker /run/.containerenv"),
                    ..word("container=oci\0")
                },
                "podman marker /run/.containerenv".to_owned(),
                None,
            ),
            (
                "a value with a newline, an escape, a bell and a backtick",
                word("container=lx\nc\u{1b}\u{7}`x\0"),
                "PID 1's environment carries `container=lx\\nc\\u{1b}\\u{7}\\`x`".to_owned(),
                None,
            ),
            (
                "a value longer than the quote",
                word(&format!("container={long}\0")),
                format!(
                    "PID 1's environment carries `container={}` (26 more characters cut)",
                    "a".repeat(54)
                ),
                None,
            ),
        ] {
            settles_container(name, &reads, &says, engine);
        }
        settles_nothing(
            "an empty word",
            &word("PATH=/usr/bin\0container=\0TERM=dumb\0"),
            &default_sentence(
                "no /run/systemd/container, PID 1's environment carries `container=` with no value, which systemd reads as no container",
            ),
        );
    }

    /// Where neither marker settles it, the sentence says which was absent, which was
    /// refused and which was read and silent: a refusal says the instrument was not
    /// available to this user, not that the marker is missing. None of them reads `host`,
    /// a `container=` inside another entry's value is not the word, and a user namespace
    /// still settles `container` with the markers' silence beside it, in one fixed order.
    #[test]
    fn a_silent_marker_is_told_apart_from_a_refused_one_and_settles_nothing() {
        let bare = PlatformReads {
            os_release: Some("ID=fedora".to_owned()),
            pid1_comm: Some("systemd".to_owned()),
            uid_map: Some("0 0 4294967295".to_owned()),
            pid1_cgroup: Some("0::/init.scope".to_owned()),
            systemd_container: Some(FileRead::Absent),
            pid1_environ: Some(FileRead::Unreadable(
                "permission denied, os error 13".to_owned(),
            )),
            ..Default::default()
        };
        let closing = "the identity uid map `0 0 4294967295`, /proc/1/comm is `systemd`, a system init: nothing chard reads from inside tells a container that plants none of these from a system that owns its kernel";
        let mut n = 0;
        for (name, reads, silence) in [
            (
                "an ordinary user on a bare host",
                bare.clone(),
                "no /run/systemd/container, /proc/1/environ unreadable (permission denied, os error 13)",
            ),
            (
                "root on a bare host",
                PlatformReads {
                    pid1_environ: Some(FileRead::Content(
                        "PATH=/usr/bin\0container_host=x\0FOO=container=lxc\0".to_owned(),
                    )),
                    ..bare.clone()
                },
                "no /run/systemd/container, no `container=` word in PID 1's environment",
            ),
            (
                "PID 1's environment not found, under hidepid or without procfs",
                PlatformReads {
                    pid1_environ: Some(FileRead::Absent),
                    ..bare.clone()
                },
                "no /run/systemd/container, /proc/1/environ not found",
            ),
            (
                "a platform that reads neither",
                PlatformReads {
                    systemd_container: None,
                    pid1_environ: None,
                    ..bare.clone()
                },
                "/run/systemd/container not read on this platform, /proc/1/environ not read on this platform",
            ),
        ] {
            settles_nothing(
                name,
                &reads,
                &format!("no runtime marker file, {silence}, {closing}"),
            );
            n += 1;
        }
        assert_eq!(n, 4, "every silence above is a row");
        // The user namespace is still the conclusion where the markers are silent, and the
        // sentence carries their silence beside it, whole and in order.
        let caged = PlatformReads {
            uid_map: Some("1000 0 1".to_owned()),
            pid1_comm: Some("bwrap".to_owned()),
            ..bare
        };
        let (observed, engine, observation) = observe_execution_mode(&caged);
        assert_eq!(observed, Some(ExecutionMode::Container), "{observation}");
        assert_eq!(engine, None);
        assert_eq!(
            observation,
            "/proc/self/uid_map is `1000 0 1`, 1 extent, not the identity map `0 0 4294967295`, so a user-namespace mapping; /proc/1/comm is `bwrap`; no /run/systemd/container, /proc/1/environ unreadable (permission denied, os error 13)"
        );
    }

    /// PID 1's name reaches the sentence quoted: in backticks as before for a plain one, with
    /// a control character escaped and a long one cut, since a container's owner names it.
    #[test]
    fn pid1_s_name_is_quoted_as_a_planted_value() {
        let named = |comm: &str| {
            let reads = PlatformReads {
                pid1_comm: Some(comm.to_owned()),
                uid_map: Some("1000 0 1".to_owned()),
                ..PlatformReads::default()
            };
            observe_execution_mode(&reads).2
        };
        assert!(
            named("bwrap").contains("/proc/1/comm is `bwrap`;"),
            "{}",
            named("bwrap")
        );
        let planted = named("\u{1b}]0;x\u{7}");
        assert!(
            planted.contains("/proc/1/comm is `\\u{1b}]0;x\\u{7}`"),
            "{planted}"
        );
        assert!(!planted.chars().any(char::is_control), "{planted:?}");
        let long = named(&"a".repeat(100));
        assert!(long.contains("(36 more characters cut)"), "{long}");
    }

    /// The markers' silence on a bare host as an ordinary user, which the uid-map rows sit
    /// beside.
    const UID_MAP_SILENCE: &str =
        "no /run/systemd/container, /proc/1/environ unreadable (permission denied, os error 13)";

    /// The default sentence's close on a bare host whose PID 1 is systemd.
    const UID_MAP_CLOSING: &str = "/proc/1/comm is `systemd`, a system init: nothing chard reads from inside tells a container that plants none of these from a system that owns its kernel";

    /// A bare host with `map` as its `/proc/self/uid_map` read (`None`: not read).
    fn bare_with_uid_map(map: Option<&str>) -> PlatformReads {
        PlatformReads {
            os_release: Some("ID=fedora".to_owned()),
            pid1_comm: Some("systemd".to_owned()),
            uid_map: map.map(str::to_owned),
            pid1_cgroup: Some("0::/init.scope".to_owned()),
            systemd_container: Some(FileRead::Absent),
            pid1_environ: Some(FileRead::Unreadable(
                "permission denied, os error 13".to_owned(),
            )),
            ..Default::default()
        }
    }

    /// The whole uid map is read, not its first line: a map whose first extent maps an id
    /// to itself is a user namespace all the same, as is one with no extent written, and
    /// each settles `container` with the map, its extent count and why it is not identity
    /// in the sentence, the map quoted and cut as a planted value is. The identity map
    /// settles nothing with its kernel padding, and with blank lines or trailing
    /// whitespace around it, and says it read identity; a map that could not be read
    /// settles nothing and says so rather than "no user namespace".
    #[test]
    fn the_whole_uid_map_is_read_and_only_the_identity_map_is_identity() {
        let silence = UID_MAP_SILENCE;
        let with = |map: &str| bare_with_uid_map(Some(map));
        let mut n = 0;
        for (name, map, says) in [
            (
                "a one-id map, unshare -U --map-user=1000",
                "1000 1000 1",
                "/proc/self/uid_map is `1000 1000 1`, 1 extent, not the identity map `0 0 4294967295`, so a user-namespace mapping",
            ),
            (
                "the kernel's padding of a one-id map",
                "      1000       1000          1",
                "/proc/self/uid_map is `1000 1000 1`, 1 extent, not the identity map `0 0 4294967295`, so a user-namespace mapping",
            ),
            (
                "a bubblewrap cage",
                "0 1000 1",
                "/proc/self/uid_map is `0 1000 1`, 1 extent, not the identity map `0 0 4294967295`, so a user-namespace mapping",
            ),
            (
                "rootless podman, two extents",
                "         0       1000          1\n         1     524288      65536",
                "/proc/self/uid_map is `0 1000 1, 1 524288 65536`, 2 extents, not the identity map `0 0 4294967295`, so a user-namespace mapping",
            ),
            (
                "two extents, the first an id to itself",
                "1000 1000 1\n0 524288 1000",
                "/proc/self/uid_map is `1000 1000 1, 0 524288 1000`, 2 extents, not the identity map `0 0 4294967295`, so a user-namespace mapping",
            ),
            (
                "rootless podman's keep-id, three extents",
                "         0          1       1000\n      1000          0          1\n      1001       1001      64536",
                "/proc/self/uid_map is `0 1 1000, 1000 0 1, 1001 1001 64536`, 3 extents, not the identity map `0 0 4294967295`, so a user-namespace mapping",
            ),
            (
                "six extents, cut in the quote and counted whole",
                "0 100000 1\n1 100001 1\n2 100002 1\n3 100003 1\n4 100004 1\n5 100005 1",
                "/proc/self/uid_map is `0 100000 1, 1 100001 1, 2 100002 1, 3 100003 1, 4 100004 1, 5 10` (6 more characters cut), 6 extents, not the identity map `0 0 4294967295`, so a user-namespace mapping",
            ),
            (
                "the identity map and an extent after it, which the kernel refuses as an overlap \
                 and is held so that identity is the whole map",
                "0 0 4294967295\n0 524288 1",
                "/proc/self/uid_map is `0 0 4294967295, 0 524288 1`, 2 extents, not the identity map `0 0 4294967295`, so a user-namespace mapping",
            ),
            (
                "a one-id map with trailing whitespace and a blank line",
                "1000 1000 1  \n\n",
                "/proc/self/uid_map is `1000 1000 1`, 1 extent, not the identity map `0 0 4294967295`, so a user-namespace mapping",
            ),
            (
                "a user namespace whose map is not written, unshare -U",
                "",
                "/proc/self/uid_map is empty, a user namespace whose map is not written",
            ),
        ] {
            settles_container(
                name,
                &with(map),
                &format!("{says}; /proc/1/comm is `systemd`, a system init; {silence}"),
                None,
            );
            n += 1;
        }
        assert_eq!(n, 10, "every mapped shape above is a row");
        let closing = UID_MAP_CLOSING;
        for (name, map) in [
            ("the identity map", "0 0 4294967295"),
            (
                "the kernel's padding of it",
                "         0          0 4294967295\n",
            ),
            (
                "blank lines and trailing whitespace around it",
                "\n0 0 4294967295  \n\n",
            ),
        ] {
            settles_nothing(
                name,
                &with(map),
                &format!(
                    "no runtime marker file, {silence}, the identity uid map `0 0 4294967295`, {closing}"
                ),
            );
        }
        settles_nothing(
            "a map that could not be read",
            &bare_with_uid_map(None),
            &format!(
                "no runtime marker file, {silence}, /proc/self/uid_map absent or unreadable, {closing}"
            ),
        );
    }

    /// A uid map with a line that is not three numbers, which the kernel does not write,
    /// settles nothing: it is not called a user namespace, which would refuse an asserted
    /// `host` or `vm`. The sentence quotes it as read, escaped as a planted value is.
    #[test]
    fn a_uid_map_that_is_not_three_numbers_to_a_line_settles_nothing() {
        let (silence, closing) = (UID_MAP_SILENCE, UID_MAP_CLOSING);
        let mut m = 0;
        for (name, map, quoted) in [
            ("a word", "garbage", "`garbage`"),
            ("two fields", "0 0", "`0 0`"),
            ("four fields", "0 0 4294967295 1", "`0 0 4294967295 1`"),
            ("a count past u32", "0 0 4294967296", "`0 0 4294967296`"),
            (
                "a good extent beside a bad line",
                "1000 1000 1\n`\u{1b} 0 1",
                "`1000 1000 1, \\`\\u{1b} 0 1`",
            ),
        ] {
            settles_nothing(
                name,
                &bare_with_uid_map(Some(map)),
                &format!(
                    "no runtime marker file, {silence}, /proc/self/uid_map is {quoted}, not three numbers to a line, so read as nothing, {closing}"
                ),
            );
            m += 1;
        }
        assert_eq!(m, 5, "every malformed shape above is a row");
    }
}
