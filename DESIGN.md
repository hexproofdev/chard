<!-- SPDX-License-Identifier: BSD-3-Clause -->

# chard: design

## The question

> Given a C toolchain on some distro, which hardening flags are *actually in effect*
> for a build, and how does that differ across distros, distro versions, and gcc vs clang?

chard answers from the artifacts it compiles and from how they run, never from a distro's
packaging spec. [jvoisin/compiler-flags-distro](https://github.com/jvoisin/compiler-flags-distro)
answers the neighboring question from the other side: what a distro's package builds inject,
in a curated table with its evidence linked where it is known.

The project ledger, cited below, is the record of deferred work and of the measurements that
decide it. It is kept outside this repository. The fleet is the set of machines on which the
whole probe corpus is run at one revision, in three lanes: Linux virtual machines, containers,
and BSD guests. A fleet sweep at a revision is that run; its reports are kept with the ledger.

## Non-goals

chard doesn't ask the OS what it is, doesn't shell out to rpm/dpkg-buildflags/abuild/makepkg/
portageq for build flags, and gives no verdict about a binary it did not build. `chard elf`
reads whatever object a caller names, and `THREAT_MODEL.md` treats those bytes as input chard
did not build: `tests/elf_readelf.rs` holds the reader to readelf over checked-in fixtures, the
host's own objects and generated ones, and the error envelope reports an object the reader
refuses as the caller's input. chard also doesn't rank flags or say what is "worth it"; it
reports `defects` and `boundary`, and leaves judgment to the caller.

## What is universal

chard's Linux artifact reading is distribution-agnostic: injected flags, the binary's package
owner and the compiler's package owner are not looked up by distribution name, and `os-release`
is recorded for human comparison but drives no behavior. The one behavioral fork is by libc, not
distro: musl lacks glibc-style `_FORTIFY_SOURCE`, so those checks report `unsupported` rather
than `off`. The libc gate never fires on the name alone. It requires the flag forced on and the
observable absent, because one libc name can differ in fact: Alpine's musl fortifies at level 1
through fortify-headers, and Fedora's `musl-gcc` does not. FreeBSD's libc is named the same way,
by its platform macro, and its gate names the cause in place of the generic sentence
(`report::freebsd_limitation_cause`). A release below 15 has no `<ssp/ssp.h>` (measured on
14.5), and 15's headers lack what the subobject, `%n` and dynamic-size rungs measure, and the
strict-flex enforcement shares the subobject rung's cause, a strcpy wrapper asking the
whole-object bound. A rung that a 15 with its wrappers instantiated implements is not gated: a
positive arm that showed nothing there stays `probe-invalid`. FreeBSD's silent abort is credited
by `decode::runtime::detect_fortify_runtime`, under the register's
`freebsd-silent-abort-is-the-fortify-kill`.

## Two questions that must never be conflated

| profile | what it measures | how it is obtained |
|---|---|---|
| `bare` | the compiler's **compiled-in defaults**: how the distro configured gcc/clang (`--enable-default-pie`, `--enable-default-ssp`, distro patches, clang config files in `/etc/clang/`, a spec-file wrapper on `PATH`) | `cc probe.c` with no flags |
| `bare-optimized` | the same, plus `-O2` and nothing else | `cc -O2 probe.c` |
| `openssf-tldr` | the guide's unconditional recommended block, as a **near** end-to-end control | the 20-flag TL;DR block verbatim and its executables row (`-fPIE -pie`), plus `-fcf-protection=full` on x86_64 or `-mbranch-protection=standard` on aarch64, each with `-fzero-call-used-regs=used-gpr`, and none of the three on another architecture (32-bit x86 included); `guide::INVENTORY` transcribes the pinned guide revision and its tests hold this profile to those rows. Where the driver's macro dump names an architecture the profile resolves to other flags under, the invocation is refused (`refuse_on_witnessed_arch` in `src/main.rs`) |
| `explicit` | any user-specified set | `--flags '...'` |

Never merge the two questions "what did the compiler ship with?" and "what does an external
guide recommend?" into one column. chard measures the first (`bare`, `bare-optimized`) by
running the compiler with no flags or `-O2` alone, and the second (`openssf-tldr`) by
applying the TL;DR block verbatim. That is a *near*, not full, control: on gcc 16.1.1 it leaves
real gaps `off`, beside the `weaken`-polarity checks that are `off` by design. chard does not
measure through distro package-manager flag injection (rpm, dpkg-buildflags, abuild,
makepkg, portageq, the Nix wrapper), since a runtime query describes only its own image;
[jvoisin/compiler-flags-distro](https://github.com/jvoisin/compiler-flags-distro)'s curated
table records that, and `--profile explicit --flags`
takes real build flags. Whether such flags suit the compiler rests on what the caller knows;
chard does not infer it.

## Two umbrellas, and why they are not one

Two umbrellas answer different questions; merging them would blur both.

- **fhardened-effective**: "did you match GCC's `-fhardened` set for this arch?" The set is the
  constant `composite::FHARDENED_FLAGS`, transcribed from `gcc --help=hardened` under gcc
  16.1.1; chard never runs that command, so a newer GCC that adds a constituent leaves the
  constant claiming too much until it is re-read. The help text does not depend on the target
  (`tests/fhardened_set.rs` compares it on x86_64 and aarch64 Linux), so the constant keeps its
  `-fcf-protection=full` slot on every target: on x86 it reads a marking and is `marked`, never
  `in-force` (below), and elsewhere it is `not-applicable`. On aarch64 the set has nothing in
  its place, so the umbrella says nothing about branch protection there: a gap, not a wrong
  answer, since filling the slot with `branch-protection-marked` would fail builds that used
  `-fhardened` correctly.

  The fortify slot's bar follows gcc's rule (`linux_fortify_source_default_level`): 3 on glibc
  2.35 and later, 2 below it and on musl, keyed on the library gcc was configured for, which the
  headers need not be. So chard reads the level the driver's own `-fhardened -O2 -dM -E` defines
  (`toolchain.fhardened_fortify`) where the driver takes the option, and otherwise the level the
  headers' library and the target triple agree on. Where neither settles a bar, the level
  decides: the one `fortify-effective` measured where it reads `on` or `partial`, or on
  fortify-headers the level requested. One that meets 3 is in force, one under 2 is absent, and
  one between is `not-established`; a `fortify-effective` that did not measure leaves the slot
  `not-established`. On fortify-headers (Alpine, Chimera), which enforces level 1 whatever is
  requested, the slot is in force where `fortify-effective` is and the requested level meets the
  bar. The slot publishes its level, its `implementation`, and its bar with the reading that set
  it (`bar`); `composite::fortify_bar` names the cases and their measurements. The consistency
  rule `fhardened-fortify-slot-disagrees-with-inputs` recomputes the slot from its inputs
  through `composite::fortify_constituent`, at publication and on read; `THREAT_MODEL.md` lists
  what else it refuses and what it does not.

  The `-fstack-protector-strong` slot reads `ssp-level-emitted`, the graded check: in force at
  `on` with `strong` or `all`; absent at `off` with no level, or at `partial` below the ask
  (plain `-fstack-protector`'s `basic`); and not established where the check withholds,
  publishes `on` or `partial` with no level, publishes a word on no rung, or publishes a verdict
  and a level that disagree (`off` beside a level among them). A slot on the presence-only
  `canary-emitted` would read the umbrella `on` for the `-fhardened` set with
  `-fstack-protector` in place of `-strong`, beside an `ssp-level-emitted` reading `partial` at
  `basic` (gcc 16.1.1, Fedora 44 x86_64, `--profile explicit`); that is why the slot reads the
  graded check. The consistency rule `fhardened-ssp-slot-disagrees-with-input` recomputes the
  slot through `composite::ssp_constituent`. It holds the slot's `check` field only where this
  chard revision wrote the report; a slot of another revision that cites `canary-emitted` is
  held on `level` only where it carries one.

- **cfi-effective**: "does the artifact ask for control-flow protection on both edges, in
  whatever form the arch offers?" It pairs by *edge*, not spelling: x86's `-fcf-protection=full`
  (IBT and SHSTK) against aarch64's `-mbranch-protection=standard` (BTI and PAC), so results
  compare across architectures. GCS is noted but never gates the verdict, and an arch with no
  CFI mechanism reports `not-applicable`, not `off` (`composite::cfi_constituent`).

**Marked, not in force.** The constituent of `cfi-effective`, and the `-fcf-protection=full`
slot of `fhardened-effective`, read a marking check: the property note by which the program asks
the kernel, CPU and C library for the protection. Whether they act on it is a separate
measurement, which chard makes for one edge on one architecture (`shadow-stack-enforced`, the
backward edge on x86_64, which needs a kernel the run owns) and no other: mainline Linux has no
user-mode IBT enforcement to measure (none as of Linux 7.3), and chard has no aarch64
enforcement check. So a marking measured `on` is the constituent state `marked`, never
`in-force`. In the composite's reduction `marked` counts as confirmed, so `cfi-effective` reads
`on` where both edges are marked and no opt-out header is carried, and the constituent's note
names what the report measured of enforcement beside it. Reading `on` only where an enforcement
check reads `on` would leave the composite `on` nowhere. While no check measures the enforcement
of both edges the marking asks for, the consistency rule
`composite-verdict-disagrees-with-constituents` refuses, at publication, `in-force` on these
constituents, and `marked` anywhere but on a forward-edge marking measured `on`.

The marking is not always what enforcement reads. On OpenBSD the kernel enforces the forward
edge whether or not the program is marked, and a `PT_OPENBSD_NOBTCFI` program header turns it
off for the whole program. So both umbrellas read that header from the artifact, through one
constituent builder, and read `off` where an OpenBSD program carries it while the marking check
stays `on`; `composite::cfi_constituent` says why that `off` is earned and carries the
measurement.

## Four observation channels

- **macro**: visible in predefined preprocessor macros (`__SSP_STRONG__`, `_FORTIFY_SOURCE`,
  `__PIE__`, `__CET__`, `__OPTIMIZE__`).
- **elf-static**: in the artifact itself: dynamic tags, phdrs, symbols, `.note.gnu.property`
  (`DF_1_PIE`, `PT_GNU_RELRO`+`DF_BIND_NOW`, `__stack_chk_fail`, IBT/SHSTK). For
  `ubsan-trap-mode` and `fortify-printf-flag` it also reads the code bytes of named functions in
  an object chard built, by a fixed-pattern search rather than a disassembly (`elf::code` says
  why that is sound). The channel's readings are published whole, once per artifact, in the
  report's `facts`; `$defs/elf_facts` in the schema gives each fact's meaning.
- **runtime**: visible only when the program executes: exit status, signal, stderr (live
  `_FORTIFY_SOURCE` level, `_GLIBCXX_ASSERTIONS`, `-fwrapv`, auto-var-init fill).
- **compiler-diag**: absent from the binary, present only in compiler stderr
  (`-Wformat-security`, default `-std`, implicit-function-declaration-as-error). Most of the
  guide's Table 1 lives here, so compiler output is a captured result, not a throwaway build
  log.

Channels are readers, not witnesses. The macro channel reads the artifact's `.chard.report`,
elf-static its headers, and runtime a run of it, so three channels over one probe's build
agree about one artifact and share any fault in it. The build's stderr comes from the same
invocation and counts as the same witness. The preprocessor dump is the one source outside
every artifact. So `corroboration` publishes, per group, what each measuring member read
(`sources`) and how many distinct witnesses that is (`independent_witnesses`); every witness
comes from one compiler and flag list, so the count separates artifacts, not toolchains.

A group's `agree` compares levels as well as presence: where two members read the protection
present on one graded scale but read different words, the group disagrees and its note names
both. The case that made this concrete is clang's `-fsanitize=safe-stack` beside
`-fstack-protector-all`, where the macro reads `all` and the object reads `unsafe-frame`, a
selection on no rung of the scale (`probe::SSP_LEVELS`). `report::corroboration` carries the
mechanism, and `corroboration-disagrees-with-members` re-derives it at publication. Whether `on`
is the right verdict for a word on no rung (canaries present, requested level not realised) is
an open decision the ledger carries.

A disagreement about presence is not left for the group to name. The macro channel reads what
the preprocessor was told, which every input of a build can set, and the elf-static and runtime
channels read what the build made, whose vocabulary is closed. So a macro reading of a
code-generation observable (`__SSP_STRONG__`, `__PIE__`, `__CET__`, `__EXCEPTIONS`, the aarch64
`*_DEFAULT` macros) is held to the checks that read the same protection from the artifact or a
run of it (`report::MACRO_TWINS`), and where one of them read the opposite presence the macro
reading is withheld `indeterminate` under `macro-contradicted-by-artifact`, the reason naming
both readings; the twin keeps its verdict. A twin that is withheld decides nothing, and a
request macro (`_FORTIFY_SOURCE`, the C++ hardening macros) is held to nothing, since a request
beside a protection not in force is the finding its runtime and elf-static counterparts exist
to show. The rule and its consistency rule are under "Verdict vocabulary".

## The control triple: the anti-false-zero mechanism

The failure this project can't tolerate is a **clean-looking zero**: reporting "flag off"
when in fact the probe never ran or the detector looked in the wrong place. A detector's
absence of evidence is worthless unless it is independently known that the detector *can*
see the thing on this toolchain.

So each check builds three variants:

```
measured   cc <profile flags> probe.c      <- what's reported
positive   cc <flag forced on> probe.c     <- must show the observable
negative   cc <flag forced off> probe.c    <- must NOT show it
```

The `measured` verdict is trusted only when `positive != negative` as expected. Otherwise the
recipe is broken on this toolchain (unsupported flag, renamed symbol, optimized-away probe),
and the check is `probe-invalid`, not a quiet `off`. A negative control or scaffolding flag
the driver says it does not know publishes `indeterminate` under its declared limitation;
one the driver knows and refuses to enable publishes a plain `probe-invalid` with no
`gating`. Both rules rest on the unknown-flag sentence (`report::gating_rule::ALL`).

**Controls carry no profile flags.** Controls answer "can this detector tell on from off *on
this toolchain*?", a property of detector and toolchain alone. Built on the profile, they answer
a different, useless question: "can I switch this off from within this profile?" The two diverge
once a distro injects hardening through something a flag can't countermand. Fedora's
`%build_cflags` does this with `-specs=/usr/lib/rpm/redhat/redhat-hardened-cc1`: a later flag
cannot override a spec file, so every negative control built on the profile still shows the
observable, and a harness asking the profile's question would conclude that nine detectors
were broken. Separating the two questions is what keeps those detectors trustworthy under
such a build.

Four kinds of profile flag do reach the arms: none hardens anything, and each decides what the
triple validates. The **linker selection** reaches the arms that link, on every channel but the
macro channel. The **target selection** (`-m32`, `--target=`, `-arch`, with the system root and
its `-L`) reaches every channel and the clean build. The **runtime selection** (the C++ library,
compiler runtime, startup objects and headers: clang's `-stdlib=` and its kin, the driver's
search prefix, a GNU/Linux gcc's C library selection) reaches every arm, the clean build and a
probe's chain libraries. The **header selection** (the profile's own `-I`, `-isystem`,
`-idirafter`, `-iquote`, `-include`, `-imacros`, `-undef` and `-pthread`; the last two change
the predefined macros, and are carried with the words that choose the headers) reaches every
arm of a check that reads the measured build, and the chain libraries, so the compile listing
comparison below (`compile-inputs-unmatched-by-arms`) matches on those words. A header that
silences the measured build silences every arm with it, and the triple reads a silent positive
arm, never `off`. A header keyed on a macro only the measured build defines (the profile's own
`-D`, or a macro a flag the arms do not carry implies, `__PIE__` under `-fPIE`) acts on the
measured build alone, since the arms carry the header and neither the macro words nor the
hardening flags: the arms read it as inert, the triple discriminates, and the reading is of
the build the profile makes, as under a system header keyed on such a macro. Under `-O2
-DNDEBUG -D_FORTIFY_SOURCE=3 -include h`, `h` undefining `_FORTIFY_SOURCE` under `NDEBUG`,
the runtime fortify checks and the request read `off` of a build compiled without the request
(`toolchain::header_selecting_flags` has the shape). Where such a header defines or undefines
a macro the compiler reserves for its own account of its code generation, the reading is
forged, and the verdict layer holds it only where the check has an artifact twin
(`report::MACRO_TWINS`): `-O2 -fcf-protection=none -DGATE -include h` with `h` defining
`__CET__ 3` under `GATE` reads `cet-macro` `indeterminate` under
`macro-contradicted-by-artifact` beside `cet-marked` `off`, and for the two checks with no
twin, `optimization-enabled` and `fortify-effective`, `macro-supplied-by-profile` withholds
the reading wherever the list selects a header search directory, under which a header the
probe includes can be shadowed, or carries a forced include or macro file, an input it
cannot read by name, as it withholds the branching probes' checks under such an input (the
same header keyed on `__OPTIMIZE__` read `on` under `-O0` and `off` under `-O2` without that
clause, forced in and as a shadow `stdc-predef.h` under the profile's `-I` alike). The
selection does not reach the clean build, nor the arms of the check that reads it: that check
answers the linker's default from an assembly probe, which a forced C include cannot build
(`measure::clean_flags` has the measurement). A flag that removes the startup objects, default
libraries or headers (`-nostdlib` and its kin) is refused as `CONFIGURATION`, since carrying
the removal alone builds the arms against nothing. `-specs=` and `--config=` still reach no
arm, for the reason above.
The spellings are at `toolchain::target_selecting_flags`, `toolchain::runtime_selecting_flags`,
`toolchain::header_selecting_flags` and `toolchain::runtime_removing_flags`, and the
measurements that forced each at `measure::arm_flags` and `measure::clean_flags`.

A two-token selection's value is that selection's and no other's. `--library-directory
-B<dir>/` is a library directory named `-B<dir>/` to both drivers, and the arms carry it as
the pair, once: the four selection readers (the target's, the runtime's, the header's and the
linker's) are projections of one walk, `toolchain::selections`, which classifies each word
once, so no reader reads another's value as an option of its own (`toolchain::selections` has
the measurement: a `-B<dir>/` read as a prefix put specs and a linker under the arms that the
measured build never had). The same holds of the value of a two-token driver option that is
no reader's spelling: `-u -B<dir>/` is the undefined symbol named `-B<dir>/` to both drivers,
and the walk passes over the pair as it passes over a word handed to another tool, so the
selection it spells reaches no arm and no clean build (`toolchain::Hand::Value`: the
two-token options gcc 16.1.1 and clang 22.1.8 accept, measured under `-###`, with the
abbreviations gcc takes; `toolchain::takes_a_value` has the frame and says what an option
outside the table, on another driver, still does).

What the driver does with the word after each is one classifier, `toolchain::read`, asked by
every reader of a flag list: the selection walk; the two listing readers
(`compile_inputs::macro_words`, `optimization_words`, which carry the profile's `-D`, `-U` and
`-O` words into the arms' stand-in listing and pass over a `-D` or `-O` a selection or such an
option took as its value); the refusals (of a divided pair, `toolchain::driver_divided_pairs`;
of a relative path, `compile::relative_path_readings`; of a target chard does not measure,
`toolchain::unsupported_target_flags`); the macro-operation reader the forgery guard reads the
list through; the level reader of `no-strict-overflow`; the partition of a profile's flags
into what each output kind compiles with; and the readers of a build's own line and of the
arms (a target's silencing flag, the control arms' macro set, a shared-object build's
position-independence choice, a link line's text-relocation permission), each reading the
word clang applies for one architecture as the driver's own. It reads each word as gcc reads
it, so gcc's long spellings of a reader's word and the abbreviations gcc takes for them are
that word to every
reader (`toolchain::LONG_ALIASES`, measured under `-###` on gcc 16.1.1 and clang 22.1.8:
`--machine 32`, `--machine=32` and `--machine-32` are the target `-m32`, `--def X` is `-D X`,
`--im f` is `-imacros f`, `--li`, `--sys` and `--pref` are `-L`, `--sysroot` and `-B`, `--op`
is `-O`, `--sh` is `-shared`). It reads gcc's generic map wherever no reader owns the spelling
in any form: gcc reads any unmatched `--word` as `-fword` (`--no-pie` is the position choice
`-fno-pie`, `--use-ld=gold` the linker selection `-fuse-ld=gold`), so the classifier does
(`toolchain::generic_map`), and clang refuses each; a spelling some reader owns stays as
written, on either driver (clang's `--config=f` is the relative-path reader's word, not
`-fconfig=f`).

An exact reader of a long option is still incomplete by construction. The abbreviation bounds
are one gcc's, and a gcc whose option table differs takes other prefixes; gcc's maps of a long
spelling to a prefix other than `-f` are read as `-f` words no reader names; and a two-token
option of another driver, or of a later version, that no table holds is read as the driver's
own word, so its value reaches the readers as the word it is (`toolchain::takes_a_value` has
the frame). A target word the classifier does not read builds the arms for the host's target
against a measured build for another, and only the arch-gated checks are then held to the
artifact's machine (`target-arch-contradicted`): a diagnostic check reads its arms under the
arms' target. The ledger's control-arms entry carries both remainders. A pair the two drivers
read differently, clang's `-isystem-after` or `-include-pch` alone, or an option one driver
takes a value for and the other reads as its own (gcc's `-Tbss`, clang's `-dependency-file`),
before a word a reader takes, is refused before any build (`toolchain::driver_divided_pairs`).

Where `-specs=` or `--config=` chooses the startup objects, archives, headers or predefined
macros the measured build reads, the checks those decide are withheld rather than validated
against a different set. chard asks the driver's `-###` what it would hand the linker and the
compile, under the measured build's flags and under the arms' selection, at each optimization
level the arms carry, and compares the inputs and the link program. Where they differ or either
cannot be read, the checks in `report::LINK_INPUT_READINGS` and `report::COMPILE_INPUT_READINGS`
publish `indeterminate` under `link-inputs-unmatched-by-arms` and
`compile-inputs-unmatched-by-arms` respectively; a difference only in a macro the controls set
themselves does not withhold (the assumption
`optimization-level-defaults-decide-only-their-own-checks`). A check that reads the clean
build (`linker-default-noexecstack`) is not compared that way, since the measured link is not
its subject; instead the clean build's link is held to the measured build's. The driver is
asked for each build's `-###` link line, the clean build's taken with the measured line's
linker selection, and compared on the program, the `-L` directories and the system root;
and for each build's `-print-search-dirs` answer, compared on its program and library
lists. Where they differ, or where any of those answers cannot be read, the check publishes
`indeterminate` under `clean-link-unmatched-by-measured` (`report::clean_link_limitation`).
`src/link_inputs.rs` and
`src/compile_inputs.rs` say how each listing is read and compared, and what equal means under
Fedora's own specs, where neither gate fires (Fedora 44 x86_64, gcc 16.1.1 and clang 22.1.8; the
link listing measured on 2026-10-06 and the compile listing on 2026-10-07).

chard does not measure x32, 16-bit or aarch64 ILP32 targets. An explicit profile whose flags
select one is refused as `CONFIGURATION` before any build, wherever the flag stands and whatever
follows it: `-mx32` and `-m16` (also through `-Wp,` or `-Xpreprocessor`, as one relayed word or
as `--machine` and its value across two, since `cc1` reads the words gcc relays to it as one
stream), `-mabi=ilp32` (also to the assembler), Darwin's `-arch arm64_32`, a triple with an x32,
`code16` or `gnu_ilp32`
environment or an `arm64_32` or `aarch64_32` architecture, and GNU as's `--x32` in any
abbreviation through the assembler's carriers. `toolchain::unsupported_target_flags` lists each
spelling's carriers and their measurement.

The same `-###` compile command is read for link-time optimization. Under clang's `-flto` the
link generates the code at a position-independence it chooses, so a `-shared` link that
succeeds says nothing of what the profile asked: `pic-shared-link` reading `on` is withheld under
`lto-codegen-at-link`, unless the command resolves the compile to `-fPIC` or `-fpic`, which the
cell's `evidence.observed` then quotes. An `off` stands (`report::lto_codegen_limitation`).

A check with no negative control (correct when a flag is off by default) uses the **clean**
build as its negative sample: no profile flags, only the target and runtime selections
(`measure::clean_flags`). Where the profile makes a selection the arms carry and the clean build
does not (the linker's program, the header selection), the negative arm is built from that
selection with no control flag instead, so it stands on the positive arm's footing.

**A positive control can differ by target architecture.** Where the way a control
manufactures the observable is architecture-specific while the property is not, the check
carries a per-architecture positive list, selected by the same target architecture its arch
gate reads; the arm publishes the list it used as `controls.positive.flags`. The mechanism
and why a wrong selection cannot read `off` are on `probe::ArchControl`.

**Each arm publishes what built it.** A report that asserts discrimination without showing
either arm asks to be believed about the one thing the triple exists to prove. Every arm
carries its own build record, and its run record where the channel runs one, so an `off` can
be re-derived from the argv and exit status rather than from a prose excerpt.
`report::decide` takes each arm as a `report::ArmInput`, detection and flags together, so no
`Controls` exists whose arms claim fewer flags than built them.

The cost is a handful of millisecond builds; the harness proves its instruments work before
reporting a number. In development it caught three bugs that all looked like "hardening is
off here":

| bug | what it would have published |
|---|---|
| GNU note padding computed as `12 + align_up(namesz, 8)` instead of `align_up(12 + namesz, 8)` | CET off everywhere, including distros that enable it |
| `DF_1_NOOPEN` defined as `0x4` (actually `DF_1_GROUP`) instead of `0x40` | `-z nodlopen` off everywhere |
| `-Wl,-z,nodlopen` measured on an executable, which the linker silently ignores | `-z nodlopen` off everywhere, for a second reason |

The third is a class, not a single bug, and the artifact preconditions under "Verdict
vocabulary" make the next instance `not-applicable` rather than a plausible `off`.

### The other direction: a false `on`

Controls guard against a detector blind to a present flag. They don't guard against a flag that
is present but *inert*, the same error reversed. `-D_FORTIFY_SOURCE=3` with no `-O` leaves the
macro at 3 while glibc sets `__USE_FORTIFY_LEVEL` to 0 and installs no checks (measured on gcc
16.1.1 with glibc 2.43). Reporting `on:3` would claim hardening that isn't there; `off` would be
wrong too, since the flag was passed. The `requested-without-optimization` clause of
`predicate::macro_channel::fortify_requested` withholds the verdict as `indeterminate` with its
reads and reason, leaving the effective-level and runtime checks to give the real answer.

That guard is one branch in one detector. The rule behind it is `tests/inert_flags.rs`: every
graded check, and every check whose two control arms both carry `-O2`, names the form in which
its flag is present and does nothing, or states why it has none, and the built binary is driven
once per form to show the verdict is anything but `on`. Each row carries the host condition
under which its form is inert, and its comment carries the measurement, or says the expected set
was derived from the detector and awaits a host that meets the condition.

**A flag being requested is not a measurement.** A macro that says only that a flag was asked
for (`_FORTIFY_SOURCE`, the C++ hardening macros) reports intent: its `on` is tallied as
`requested`, not as protection (`probe::Observes`, "Defect status" below), and only a `runtime`
or `elf-static` check shows the protection. Other macro checks, a protection's own macro among
them, count as protection.

### The third control arm: signals a co-enabled flag can produce

The two profile-free arms show the detector can see the flag at all, not that the signal in
the **measured** build came from that flag, since it ran under different settings. That gap
caused a second false `on` while adding `-ftrivial-auto-var-init`:

- The observable is a zero byte read from an uninitialized local, in a frame pre-dirtied with
  `0x5A` so surviving dirt proves nothing initialized it.
- `-fstack-protector-strong` reorders and pads the frame, so those locals read `0x00`
  regardless of any auto-var-init flag. Verified on gcc 16.1.1: `-O2` alone reads garbage,
  `-O2 -fstack-protector-strong` reads `00`.
- Fedora's `%build_cflags` has SSP and no auto-var-init flag at all, yet chard reported
  `-ftrivial-auto-var-init: on (zero)`.
- The controls discriminated *perfectly* (positive `present`, negative `absent`), stamping
  `discriminating: true` on a fabricated verdict.

So a check with a **generic** observable declares `Regime::Arm` in `src/probe.rs`, the flags the
driver appends to the profile for a third arm: the negative control reapplied *on top of* the
profile. If the observable survives that, the signal isn't attributable and the verdict is
withheld. A check with a specific observable declares `Regime::NotOwed` with the argument and
the profiles and toolchains it was made over. The field has no default, so no check leaves
the question unanswered, and `tests/regime_arms.rs` holds the declarations. An arm the
toolchain cannot build (gcc 7.5 and clang 6.0 reject `-fcf-protection=none`) is withheld too,
as `regime-unevaluable`.

The third arm is owed only by checks with a generic observable, because requiring it where
the observable is **specific** costs real verdicts for nothing. glibc's `*** buffer overflow
detected ***` is emitted by nothing else. Fedora passes fortify as `-Wp,-D_FORTIFY_SOURCE=3`,
which a later plain `-U_FORTIFY_SOURCE` can't countermand, so the arm couldn't suppress a
signal never in doubt. Applying it to every check would have withheld both fortify verdicts
on the Fedora column.

What matters is **how specific the observable is to the flag**:

| observable | specific? | needs regime control |
|---|---|---|
| glibc's `buffer overflow detected` on stderr | yes: only fortify emits it | no |
| a `__stack_chk_fail` relocation | yes | no |
| `DF_1_NOOPEN` in `DT_FLAGS_1` | yes | no |
| a zero byte in an uninitialized local | **no**: SSP and clang's optimizer both produce it | **yes** |
| gcc's `0xFE` / clang's `0xAA` pattern fill | yes: nothing else produces those | yes, cheaply |
| the x86 CET property bits on a linked program | **no**: `-z ibt -z shstk` forces them over code with no landing pad | **yes** |
| the aarch64 BTI and GCS property bits on a linked program | **no**: `-z force-bti` and `-z gcs=always` force them over code compiled `-mbranch-protection=none` | **yes** |

On an `ELFCLASS32` artifact clang's pattern fill is `0xFF`, which other code also produces;
there the specificity rests on a control local and on three locals agreeing
(`AUTO_VAR_INIT_CLANG_PATTERN_32` in `src/decode/runtime.rs`).

Where the zero byte survives that arm, the reading is withheld as `regime-confounded`. The
stack protector does not by itself make the zero byte survive: the probe reuses one frame and reads
through volatile lvalues (`auto-var-init-active`'s notes in `src/probe.rs`). Under
`openssf-tldr`, which carries `-fstack-protector-strong`, chard on Fedora 44 x86_64
read both auto-var-init checks as a decided `off` with gcc 16.1.1 and with clang 22.1.8.

### What a differential control structurally cannot see

The triple works by *difference*: forced-on against forced-off, trusted only where they
diverge. That is its strength and its blind spot. **A disturbance affecting both arms equally
is invisible to it, however large.** The arms still diverge, so `discriminating: true` is
stamped on a cell measured under a condition nobody recorded.

Three cases that look unrelated share this property:

- A distro spec file patching `*cc1_options` but not `*cpp_options` reaches every arm
  identically, so the macro channel's controls discriminate perfectly while describing a
  compiler other than the one generating code.
- A wedged compiler orphaned by a timeout keeps consuming the host for the rest of the sweep,
  slowing positive, negative and measured arms alike, so the triple sees nothing and every
  later `duration_ms` is quietly wrong.
- A reader that stops short at the same point of the same table in every arm, as one
  malformed `.dynamic` layout emitted for every link would cause. The arms keep diverging on
  the entries before the cut, so the triple discriminates, while the measured build's own
  reading rests on the entries after it. The `artifact-unreadable` gate exists for this.

**The triple validates the detector, not the conditions.** Anything moving both arms
together (host, clock, an ambient variable, an upstream spec file) must be established some
other way: the environment scrubbing in `compile::invoke` and `run::execute`, and the
self-report cross-check (the `.chard.report` in an artifact's stored facts against the
preprocessor's dump, where a dump was taken: a probe with a macro-channel check). When adding
a check, ask which confounders are *common-mode*; the control triple won't catch those.

## Detection recipes, and where the macro channel reads its macros

Every detection recipe tried, refuted ones included, is recorded outside this repository.

`cc -dM -E` and `cc1_options` diverge through `-specs=`, reproduced in both directions, with
Wolfi's `openssf-compiler-options`/`openssf.spec` as the real-world case. So the macro channel reads
the `.chard.report` section `cc1` itself embeds. It reads the preprocessor dump only where
the artifact cannot carry the section or the reader refused it (the self-report gate below
names each case), never in place of a section that should be there.

## Verdict vocabulary

Per check:

- `on` and `off` require earned proof; `off` is absent with controls that confirmed detection
  works.
- `partial`: active, but below the guide's ask on the check's own scale.
- `unsupported`: the toolchain or arch can't do it.
- `not-applicable`: the observable is out of reach for what was measured, either a profile it
  does not belong to or an artifact that structurally cannot carry it.
- `indeterminate`: an ambiguous result, or a question chard's instrument could not pose (the
  premise classes below).
- `probe-invalid`: the controls didn't discriminate, so the verdict is withheld.
- `build-failed` and `run-failed`: the check could not be tested.

A report counts two kinds of non-measurement apart, in `coverage.withholding`
(`report::Standing`). An earned limitation is an `unsupported` or `not-applicable` beside the
gating rule whose premise publishes it (below), and it settles `--fail-on-missing`. An
instrument withholding is every other non-measurement: a check that earned no verdict because
chard could not pose or read the question, or the build or run it needed failed. Each set is
counted by verdict and by reason, no rate is published over either, and
`coverage.all_verdicts_published` is true exactly when every corpus check was attempted and the
second set is empty. `withholding-disagrees-with-verdict-counts` holds the sets to the tally and
the observations.

A level is a word on the check's own vocabulary (`probe::Levels`), and no two checks' words are
compared: the stack protector's `explicit < basic < strong < all`, `_FORTIFY_SOURCE`'s numbers,
RELRO's `partial < full`, and the control-flow components `branch`/`return`/`full`, of which only
`full` meets the ask. Where the check grades nothing, the word is information beside `on`, such
as `__PIE__`'s code model. `partial` is earned only on a graded check, by a word below the ask. A
word the scale lacks, or a graded check whose detector reported no word, is `indeterminate`
under `level-outside-check-scale`, never the strongest verdict a fallthrough would publish. A
detector that withholds for a reason the gating table names says so in its reading
(`probe::Detection::rule`), and `measure::settle` publishes it under that rule. The one such rule
is `guard-kept-without-the-flag`: `no-strict-overflow`'s guard that ran and cannot be credited to
the flag is `indeterminate` under it, counted by rule rather than among the withholdings with no
named cause. A
macro read as a number whose text has no integer reading (`-D_FORTIFY_SOURCE=(3)`) is
`indeterminate`, never `off` (`predicate::macro_channel::unreadable`). `chard probes` publishes
each check's vocabulary under `levels`.

These are properties of the artifact, not the running system: CET's shadow stack needs kernel
and glibc support, PIE means little without ASLR, and `strong` protects a subset of functions.
An observation whose protection depends on something outside the binary carries a `boundary`
field naming what must also hold at runtime, so a policy engine reading `pie: on` knows the
claim is about `ET_DYN`, not address randomization. A stack canary or a fortified call needs
nothing further and carries none.

The artifact half of `not-applicable` is a gate on the object the detector read
(`report::ARTIFACT_PRECONDITIONS`): `relative-relocs` needs position-independent output, `relro`
a dynamic section, `nodlopen` a shared object, `as-needed` a `DT_NEEDED` entry to leave another
out beside, and the checks that read symbols a symbol table, which a stripped static link lacks.
`-Wl,-z,pack-relative-relocs` is why the gate exists: `ld` accepts the keyword on a fixed-address
link and does nothing, and without the gate the check published `off` there, saying a
distribution declined something it never had the option to do. The gate fires on a withheld or
absent reading alone, so a detector that finds the observable where the rule calls it impossible
refutes the rule.

`as-needed` reads the `DT_NEEDED` list ahead of the link classification, because the two
disagree on measured shapes and the list is where the flag leaves its mark, and it reads the
list only where an entry names the C library. A `-static-pie -Wl,--dynamic-linker=<path>` link
carries an interpreter, so it classifies as a dynamic PIE, and records no library, libm and libc
having come from their archives; a clause on the classification would let it read `on` over a
discriminating triple with `-Wl,--no-as-needed` in the profile (clang 10 with lld 10.0.0 and gcc
9.4 with GNU ld 2.34 on Ubuntu 20.04 x86_64 and gcc 13.3 with GNU ld 2.42 on Ubuntu 24.04 x86_64;
gcc 16.2.1 with GNU ld 2.46.1 and with lld 22.1.8 on Fedora 44 x86_64, without the flag). A
`-pie -Wl,--no-dynamic-linker` link has no interpreter and is marked as executable output, so it
classifies as a static PIE, and keeps the entries the link wrote, the unused library's among
them where the driver passes no `--as-needed` (lld 10.0.0 and GNU ld 2.34 under clang 10, Ubuntu
20.04 x86_64; GNU ld 2.46.1 under gcc 16.1.1 and clang 22.1.8, Fedora 44 x86_64; GNU ld 2.42
under gcc 13.3, Ubuntu 24.04 x86_64, whose driver does and drops it); the same clause would
withhold it with a sentence saying the artifact records no library. What the list
has to carry is the C library's entry and not merely an entry: the probe's executable link
records its C library through its startup object whenever it takes the library from a shared
object (the register's `probe-executable-link-records-its-c-library`), and a profile cannot
remove the startup object, chard refusing `-nostartfiles`, `-nostdlib` and `-nodefaultlibs`,
but it can take the C library from an archive while naming another shared library, as
`-static-pie -Wl,--no-as-needed -Wl,-Bdynamic libz.so.1 -Wl,-Bstatic` does, whose list names
`libz.so.1` alone and whose libm came from its archive (gcc 9.4 with GNU ld 2.34 and clang 10
with lld 10.0.0 and GNU ld 2.34, Ubuntu 20.04 x86_64; gcc 13.3 with GNU ld 2.42, Ubuntu 24.04
x86_64). So the predicate withholds a list with no `libc.` entry under its own clause, the row
turns that into `not-applicable` naming the entry the artifact lacks, and a list with the entry
is read whatever the object's classification, with one more question for output linked with no
dynamic loader (a static PIE, or an `ET_EXEC` with no interpreter): it takes its libraries from
archives unless the link chose shared ones, and the tags cannot say which it chose, so where the
C library is recorded and the unused library's entry is not, the archive may have supplied the
library, and the reading is withheld `indeterminate` rather than read `on`. The shape is
`-static-pie -Wl,--no-as-needed -Wl,-Bdynamic libc.so.6 -Wl,-Bstatic`, and the same under
`-no-pie -Wl,--no-dynamic-linker`, whose trailing `-Bstatic` sends the probe's own `-lm` to
`libm.a` (gcc 9.4 with GNU ld 2.34 and clang 10 with GNU ld 2.34, Ubuntu 20.04 x86_64; gcc 13.3
with GNU ld 2.42, Ubuntu 24.04 x86_64); a `-pie -Wl,--no-dynamic-linker` link under
`--as-needed`, where the flag did drop the entry, is withheld the same way. The same route with
an interpreter, a dynamic link whose profile ends in `-Wl,-Bstatic` or otherwise takes the
unused library from an archive while the C library stays shared, reads `on`: the observable, an
entry left out, cannot say whether the flag or the archive left it out, and a ledger row
carries it. The other classification the predicate reads is a shared object's, where no entry
names the C library: a `-shared` link has no startup object, and
under `--as-needed` it records nothing (gcc 13.3 with GNU ld 2.42 on Ubuntu 24.04 x86_64, whose
driver passes the flag by default; gcc 16.1.1 with GNU ld 2.46.1 on Fedora 44 x86_64 given it),
so there the missing entry may be the flag's own doing and the reading is withheld without that
cause. An object the loader cannot run is withheld on its type before any of this, so a dynamic
section forged onto a relocatable or core file is not read as a link.

A third shape has a gate of its own, `artifact-contradicts-link-mode`. An interpreter-less
`ET_DYN` with a dynamic section and neither `DF_1_PIE` nor `DT_DEBUG` reads as a shared object,
and lld 10.0.0 under clang 10 (Ubuntu 20.04 x86_64) writes executable output in that form under
`-static-pie -Wl,-z,rodynamic`, where `pie` then reads a wrong `off` and `as-needed`, reading the
classification because no entry names the C library, withholds. The tags cannot tell such output
from a shared object, but the probe can: `pie` and `as-needed` are read from probes linked as
executables, so a shared-object classification contradicts what chard asked for, and every
reading that rested on the classification is withheld `indeterminate` on the measured build.
The gate is keyed on the fields the reading read, not on the fields a predicate could read, so
its reason names what this reading rested on, and a reading that decided on a kept `DT_NEEDED`
list stands: `off` with the unused library recorded under a `-shared` profile (gcc 16.1.1 and
clang 22.1.8 with GNU ld 2.46.1, Fedora 44 x86_64) and under lld 10.0.0's `-pie
-Wl,--no-dynamic-linker -Wl,-z,rodynamic`, where `pie` is withheld. It is not `probe-invalid`,
because the triple did not fail; one artifact's reading contradicts the request.
`report::link_mode_limitation` carries the shapes, and `measure::artifact_gating` the order of
this gate among the others.

`artifact-unreadable` is the gate on the reader. Each elf-static check declares the tables its
observable is read from (`Check::reads`, derived from its decoder), the reader records every table
it could not finish in the stored facts' `truncations`, and where the two meet the reading is
withheld `indeterminate`: the instrument worked, and this one reading is unreadable. A control arm
cut the same way withholds the triple as `probe-invalid` through its own cause. The gate reads the
artifact's own account, independently of the triple (`report::truncation_limitation`;
`tests/elf_truncations.rs` holds which checks read which table).

`artifact-lacks-self-report` is the macro channel's gate. A driver that strips `.chard.report`
after the link (`objcopy --remove-section`), leaves an artifact the reader refuses, or writes
none, leaves the `-dM -E` dump as the only macro reading, and nothing holds the dump to the code
the compiler generated. So a macro reading over a measured build whose artifact gave no account
is withheld, whatever the triple decided short of `probe-invalid` and `unsupported`, with a
reason naming how the account is missing. A profile that writes no artifact or one the reader
refuses (`-fsyntax-only`, `-E`, `-S`) withholds the same way, and gcc's slim LTO object is
withheld first under `artifact-holds-lto-ir`. The arms stay dump readings and may discriminate,
which is why this gates the measured build and is not a `probe-invalid` (the register's
`self-report-absent-withholds-the-macro-channel`). A macOS run, whose probes are Mach-O, reads
the dump by design where the reader refused the artifact as a Mach-O object, the format its
probes are built in; every other refused artifact, and a build that wrote none, is withheld on
every host. A section a tool rewrote is read as the artifact's account: the redirected-toolchain
position `THREAT_MODEL.md` does not defend. `report::self_report_limitation` and
`report::artifact_account_missing` carry the reasons, and the consistency rule
`macro-verdict-unearned-by-artifact` holds a published report to the gate on read. Without the
gate, a driver that removed the section would publish the dump's verdicts at `confidence: high`;
`tests/fake_driver.rs` (`a_driver_that_strips_the_self_report_withholds_every_macro_verdict`)
carries that measurement.

`macro-contradicted-by-artifact` is the macro channel's other gate, on the reading rather than
on its source. A macro reading is the compiler's account of its own code generation, read back
through the preprocessor, and the preprocessor's state is set by every input of the build: a
`-D` (`macro-supplied-by-profile` reads four spellings of that one input), a forced include, a
header the profile selects, a specs or configuration file, a wrapper that recognises which build
it is compiling. An enumeration of inputs is complete until the next spelling; the artifact's
vocabulary is closed. So where a check reads the same protection from the artifact or a run of
it in the same report (`report::MACRO_TWINS`: the stack protector's canary and function map,
PIE's dynamic tags, CET's property notes and landing pads, GCS's and branch protection's notes,
the exception table) and reads the opposite presence, the macro reading is withheld
`indeterminate` with a reason naming both readings, and the twin keeps its verdict: it
observes the artifact or a run of it, and nothing in this rule puts that reading in question. The withholding is the
conservative direction, as for `target-arch-contradicted`: without it, a forced include
defining `__CET__ 3` under a profile-only macro reads `cet-macro` `on` at `full` over
discriminating arms beside `cet-marked` and `cet-endbr-emitted` `off`, and the report publishes
it beside a `CHANNELS DISAGREE` error (gcc 16.1.1, Fedora 44 x86_64, 2026-10-28, with the forced
include carried to the arms), as the redirected toolchain of `THREAT_MODEL.md` publishes
`ssp-level` beside readings of artifacts it had hardened. A twin that is withheld,
`probe-invalid` or not in the run decides nothing; a reading at an opt-in level
(`report::OPT_IN_LEVELS`) is held to nothing, since its artifact readers read `off` by the
level's meaning; `cet-endbr-emitted` is consulted for a `cet-macro` reading at `branch` or
`full`, at no level, or an absent one, since `-fcf-protection=return` compiles no landing pad;
`pic-object-relocs` is consulted for an absent `pic-macro` only, since `-fPIE` defines `__PIC__`
beside a direct relocation; a pair whose readings describe different stages of one build is
kept and the reason says so (`-fPIE` without `-pie` reads `__PIE__` beside a link that is not a
PIE, and `-fPIC -pie` the reverse; the withholding is `indeterminate`); and a request macro is
held to nothing (`report::MACRO_WITHOUT_TWIN` names the other macro checks left out and why:
`optimization-enabled`, which no artifact reads; `fortify-effective`, whose runtime rungs
diverge from it honestly under fortify-headers and on FreeBSD). The rule compares presence,
not levels: a level split between two present readings is the corroboration group's
`LEVELS DISAGREE` note, and a level forged into a present reading is a route `THREAT_MODEL.md`
records. The rule reads settled verdicts after the target rule, so it overwrites no earlier
gating; a corroboration group with a member it withheld says so in its note; and the
consistency rule `macro-verdict-contradicted-by-artifact` re-derives the selection from the
published verdicts at publish and on read, reading a channel the file omits from the corpus. The probes whose own source branches on a reserved
macro (`measure::PROBE_MACRO_BRANCHES`) have no twin to be held to; their checks are withheld
under `macro-supplied-by-profile` where the flag list defines or undefines the macro the probe
branches on, or carries a preprocessor input the reader does not read by name (a forced
include or macro file, a response file, a define handed to clang's frontend), or where the
driver's listing for the measured compile differs from the arms' (a `-specs=` or `--config=`
file's macro operations), and the compile-input readings among their checks
(`strict-flex-arrays-enforced`, `cxx-stdlib-assertions`, `cxx-assertions-symbol`) where the
list selects a header search directory, under which a header the probe includes can be
shadowed (the listing comparison withheld those three under any such directory until the arms
carried it). The two macro checks with no twin (`report::MACRO_WITHOUT_TWIN`,
`optimization-enabled` and `fortify-effective`) are withheld under the same rule wherever the
list carries such an input or selects a header search directory, since the control arms
carry the profile's directory and include words as the header selection and never its
macro words, so a header keyed on one, forced in or shadowing one the probe includes, acts
on the measured build alone (`measure::twinless_unread_input`).

The runtime channel has the same gate on its streams. A run whose output hit the capture cap or
could not be read withholds every runtime reading over it under `run-output-unreadable`, because
each decoder reads a marker's absence on its way to an outcome; a probe killed at
`run.deadlines.probe_run_ms` withholds under `run-deadline-elapsed` (`run::RunRecord::stream_cut`).

A runtime artifact the kernel does not run natively runs through a `binfmt_misc` emulator, which
the triple cannot see, since every arm runs under it. A runtime reading that rests on the machine
(`probe::RunBasis`) is withheld under `run-under-emulation` where the artifact's machine or class
is foreign to the kernel's, or unreadable; one that rests on what the instructions compute stands.
`report::emulation_limitation` carries the mechanism and its macOS case.

`decide` is enumerated over every combination of its inputs and reaches exactly `on`, `off`,
`partial`, `indeterminate` and `probe-invalid`; the gating rules and evidence sufficiency publish
the rest, and a test holds the two sets to cover the vocabulary, so no verdict sits in it
unreachable.

A gating rule's verdict follows from the class of its premise (`report::gating_rule::Premise`): a
fact about the measured system (its toolchain, target, C library or kernel) publishes
`unsupported`, a limit of chard's own instrument `indeterminate`, and a question with no referent
in what was measured `not-applicable`. Only the first and last settle `--fail-on-missing`, so an
instrument that could not pose its question leaves the gate open; a cell that accepts that
withholding lists it in `tests/sweep-expected`. `gating-rule-reserves-a-different-verdict`
refuses a verdict its rule does not reserve. Each gating publishes its class as
`gating.premise`, and a reader holds the verdict by the class written there, so a report keeps
the standing its writer gave it after a later chard moves a rule between classes; a report that
wrote no class is held to the reader's table. `THREAT_MODEL.md` ("What a reader checks of a
report it did not write") states where a changed class is refused as an edit and what each
reader says otherwise; `report::gating_rule::premise_on_read` carries the mechanism. The rules
are one table, `report::gating_rule::ALL`, and the tests in `measure::tests` reach every row
through its construction site and hold its stage, its builds and the evidence its reason
quotes; the stages before `decide` are early returns that no test drives together.

The base inferences are held as the rollups are: a verdict against its published triple, a level
against its check's scale, a quoted rejection against the arm's stderr and a corroboration group
against its members are each a consistency rule in `report::RULES`, published in
`consistency.rules_applied`.

Each probe tags `polarity` (`harden`: present is good; `weaken`: present is bad), so a table
colours a verdict without knowing the flag. `coverage` is published in every report, since a
driver has to count what it fed in to catch a probe that silently never ran.

Defect status is separate. `defect_coverage` rolls the checks bearing on one defect class into
`mitigated`, `partial`, `not-mitigated` or `unknown` (`report::defect_coverage`), counting each
check in terms of protection, so a `weaken` check's `off` counts as protected. Only a check
whose `on` is evidence of the protection moves the status. One whose `on` is a request
(`_FORTIFY_SOURCE`, the C++ hardening macros) or a marking (a CET, BTI, PAC or GCS property
note) is tallied under `requested` or `marked` and moves it in neither direction
(`probe::Observes`, published as each observation's `observes`, which also carries the cases
where a request's `off` is not protection absent). A request's `on` is not protection observed:
counted as protection, `fortify-requested` alone would read `stack-buffer-overflow` `partial`
on OpenBSD amd64 under `openssf-tldr`, where every fortify runtime rung is unsupported (fleet
sweep, 2026-10-26). A protection's own macro (`__SSP_STRONG__`, `__PIE__`) and the layout an
artifact carries (`pie`, `relro`, `noexecstack`) count as protection. A class no check observes
protection against reads `unknown`: `jump-oriented-programming`, since no check measures IBT,
BTI or PAC enforcement. A defect's summary says what its bearing checks cover: `null-deref` is
borne by `no-delete-null-pointer-checks` alone, so a dereference the source itself performs is
outside every check. A report of another corpus is read with the `observes` it carries. A
report without the field is refused whatever its corpus. Where its corpus is another and no
observation carries the field, the refusal names it a report shape this chard does not write and
says how to read it.

`mitigated` requires every bearing check that observes protection to read a full `on`. An any-of
rule would let partial RELRO count against got-overwrite, which it does not mitigate where the
linker leaves the lazy-binding slots outside PT_GNU_RELRO, as GNU ld, gold, lld and mold do on
Linux (measured on Fedora 44 x86_64 with glibc); OpenBSD's lld places the whole table inside, so
there the rollup understates, as the `relro` check's note says. An any-of rule would also let
one passing C++ check count as mitigation where `_FORTIFY_SOURCE` is fully off in a C build. A
withheld bearing check is evidence in neither direction: the class is `partial` at best, or
`not-mitigated` where nothing read protective, and the entry's `complete` is false.

## The command-line contract

A command is one operation that reads reports, binaries or nothing and writes one document:
`measure` builds the probes with a compiler and writes a report; `table` and `matrix` read
reports, and `digest` reads one and writes the block that report leads with; `detect` reads a
report or another of chard's documents (`--evidence`) or one binary (`--artifact`); `elf` reads
binaries; `probes` reads nothing and lists what `measure` builds. Setup and tooling, building
chard and running its gates among them, are flags or Makefile targets, not commands. A command
writes its document to stdout, or to the file `-o` names (`-o -` is stdout); `measure` writes
its report to `chard-<cc>-<profile>.json` in the current directory unless `-o` names another
file or `-`. The document is JSON except `table`'s rendering and `probes --format text`, which
are text for people (as are `--help` and `--version`); progress and notes go to stderr, prefixed
`chard: `, and a usage error's own text goes there unprefixed. `measure` ends every run that
exits 0, 1, 2 or 3, a refused one too, with one line there naming its exit status, the file it
wrote or kept, the report's counts and what to run next; a panic (exit 101) ends on a line
saying so, and a killed run on none. Exit 0: the document is written, and from `detect` every
reading it replayed agrees. Exit 1: a gate tripped and the document is written: from `measure
--fail-on-missing`, a check did not settle; from `detect`, a reading disagrees with its replay.
Exit 2: chard refused the invocation or failed, a usage error among them, and a `--execution`
that what chard observed contradicts, whose report is kept as for exit 3 and not published.
stdout then carries an error envelope in place of the document, `{"chard_schema", "error":
{"code", "operation", "message", "hint"}}`, whose `code` names whose action comes next:
`USER_INPUT` the caller, `PERMISSION` whoever owns the filesystem, `TRANSIENT` a retry,
`CONFIGURATION` the invocation's settings, `INTERNAL` a bug report against chard. Exit 3: chard
contradicted itself, and only `measure` exits 3: the report it built disagrees with itself and
is not published (it is written only to `<file>.contradicted`, beside the file it would have
gone to, and under `-o -` nowhere), and stdout carries an `INTERNAL` envelope whose hint names
that file or says how to keep one. Every JSON document but `elf`'s carries `chard_schema`, the
major version of its own shape; the shapes of a report, a matrix, `detect`'s output and the
envelope are in `schema/`, and `digest`'s is the report's `digest`. `elf`'s output is a map from
the paths it was given to their facts, with no place for a key beside them. A key chard adds is
not a change: a consumer ignores keys it does not know, and the shipped schemas admit them.
Removing or renaming a key, changing a value's type or meaning, or adding a value to an
enumeration raises `chard_schema`. The rule holds from chard's first publication, where every
document is at `1`. `table`, `matrix`, `digest` and `detect` read a report at the `chard_schema`
this chard writes and refuse any other with exit 2, and `table`, `matrix` and `digest` refuse a
report without its `digest` the same way.

That paragraph is `CONTRACT` in `src/main.rs`, which `chard --help` prints, and
`the_contract_is_stated_once` holds this copy to it word for word.

The four statuses are apart because each asks for a different action. `1` lets a caller tell a
complete sweep from one with holes on the status alone, since an incomplete sweep rendered as a
full column is how a false negative is published; `detect`'s disagreement shares `1`, being a
finding about the report it was handed. `3` is apart from `2` because a failure means chard
could not measure, while a contradiction means it measured and disagreed with itself, a defect
in chard to report. `3` is apart from `1` because a gate's document is valid and a contradicted
report is not; were `detect`'s disagreement `3`, a caller routing `3` to a chard bug report
would file one for every report that failed its replay. A report from the same chard,
untouched, that disagrees with its replay is a defect to report; only the caller, who knows
where the report came from, can say whether a `detect` `1` is that case.

The schema rule keeps the shipped schemas open where chard's own tests keep them closed. Every
object in the report, matrix, `detect` and error schemas declares `additionalProperties: true`,
so a consumer pinned to a published schema accepts a report a later chard extended, while
`tests/schema_conformance.rs` still fails a field chard emits and the schema does not declare.
A value added to an enumeration (a gating rule, an ELF field, a verdict word) raises
`chard_schema`, since a pinned validator refuses it. `schema/chard-predicate.schema.json`
describes input chard reads and stays closed, as does the copy of its definitions the report
schema carries for `decoders`: a predicate key an evaluator does not know could change what the
predicate concludes, so it is refused rather than ignored.

## The error envelope

stdout carries a document or an error envelope: for a failure or refusal, what chard stopped on;
for `measure`'s exit 3, where the refused report is kept (`schema/chard-error.schema.json`). The
envelope's `code` names whose action comes next, as the contract lists them. For an io failure
the errno alone cannot say which owner acts, since a missing file is the caller's typo on a path
they typed and chard's defect on one it built, so the class is decided by who owns the path.
`src/error.rs` carries the mechanism, and `tests/error_classes.rs` holds the classes through the
built binary.

## The binary testifies about itself

The `.chard.report` ELF section embeds every relevant predefined macro (stringified at compile
time) in the binary, readable later with `readelf -p .chard.report` or `strings | grep CHARD`.
It is the macro channel's self-report: portable across machines, but self-reported, and held to
the generated code only where a check on another channel reads the same mechanism
(`report::MACRO_TWINS`, under which a macro reading the artifact contradicts is withheld; the
corroboration group names a split between two present readings). The `used` attribute
keeps the array through the compiler; `retain` (gcc 11, clang 13, binutils 2.36) keeps the
section through `--gc-sections` where the compiler has it (read as the `R` flag by `readelf` on
gcc 16.1.1 and clang 22.1.8; no test holds it); and every probe with a macro-channel check
references the array from its own code, which keeps it on a toolchain without `retain`. `strip
--strip-all` leaves it in place and `objcopy --remove-section` takes it out
(`tests/probe_sources.rs` links and strips each such probe and reads the section back). An
artifact without a readable section is the self-report gate's case, under "Verdict vocabulary".

`-frecord-gcc-switches`/`-frecord-command-line` (`.GCC.command.line`) and
`-grecord-gcc-switches` (`DW_AT_producer`) complement the self-report: they capture the literal
explicit driver arguments, not defaults. gcc records the options `cc1` received, so options its
driver or a spec file adds appear (Ubuntu 22.04's and 24.04's `-fstack-protector-strong
-fstack-clash-protection -fcf-protection`, Fedora 44's `-fPIE -fplugin=gcc-annobin` from its rpm
spec files), and a default compiled into `cc1` does not (Alpine gcc 15.2.0's
`--enable-default-ssp`). clang records its driver's arguments, configuration-file options
included.

`.comment` is the only place the linker testifies about itself: lld and mold append a line
naming themselves and their version; GNU ld and gold write nothing. `toolchain.linker.artifact`
publishes those lines beside the `--version` banner of the program chard resolved, each keeping
its own word, because they answer different questions: the banner says what the harness `PATH`
holds, the lines say what linked the artifacts. So a `bfd` or `gold` banner is confirmed by
nothing: at best it is uncontradicted (`no-signature`). A banner chard could not read leaves the
artifact as the only witness (`artifact-only`, a warning: a gap in chard's own reading). A
banner the artifacts contradict (`disagrees`, an error diagnostic) is a finding about the
environment, not a contradiction of the report, which still exits 0. The linker is held to the
artifacts its own link line produced: under a profile whose link line selects a linker, the
clean build was linked without the selection, so it is named and left out of the count.
`-frecord-*` records the `-fuse-ld=` request; `.comment` records which program linked.
`src/toolchain.rs` carries the grammar, its measurements and the verdict beside
`artifact_agreement`.

The arch gate decides from the mechanism table, `src/mechanism.rs`, keyed on the question a
check answers: for each question, which mechanism answers it on each architecture the project's
own hosts have witnessed (x86_64, x86 through `-m32`, aarch64), and which checks read that
mechanism there.
Off a check's architectures the table publishes one of three things, and only the first is a
verdict about the target:

- `arch-gated`, `unsupported`: the target answers the question with another mechanism a check
  reads (x86 CET on aarch64, whose BTI, PAC and GCS markings the aarch64 checks read).
- `no-check-on-target`, `indeterminate`: the target has the mechanism but no check reads it there
  (`DT_TEXTREL`, whose check is built for other architectures, or GCS enforcement on aarch64).
- `arch-outside-table`, `indeterminate`: the table has no row for the target.

Every row with no reader carries the measurement or source it rests on.

`e_machine` is the artifact's testimony about its target, and `toolchain.target` holds the arch
gate to it. The gate decides from `-dumpmachine` before any build, so every arch-gated verdict
rests on the driver's account of its own target. Here a contradiction moves verdicts, which the
linker's does not: each observation whose gate an artifact's machine decides otherwise is
withheld as `indeterminate` under `target-arch-contradicted`, with an error diagnostic. It is
withheld rather than re-gated on the artifacts' machine, because a verdict gated on a premise
the run never built under would be a measurement nobody made. A machine that decides a gate the
same way contradicts nothing (`-m32` on an x86_64 driver yields `i386`, and the x86 gates
stand). The consistency rule `arch-gate-contradicted-by-artifacts` re-derives the block from the
stored `elf.machine` of the observations' builds (`report::withhold_on_contradicted_target`).

The machine is not the whole target. An x32 object is `EM_X86_64` at `ELFCLASS32`, and an
`aarch64_be` object `EM_AARCH64` in the other byte order. The table's rows were measured on one
width and order each (`toolchain::Abi::of_arch`), so a target of the family at another has no
row, as a foreign machine has none. The artifacts' `EI_CLASS` and `EI_DATA`, and each dump's
`__SIZEOF_POINTER__` and `__BYTE_ORDER__` (which gcc 16.1.1's and clang 22.1.8's dumps define
for every target asked, measured on 2026-10-14), witness it (`toolchain.target.abi`). Only
witnesses that agree about the machine family are read, and one at another width or order
withholds every arch-gated check under `target-abi-contradicted`. The abi witness pools C and
C++, where the machine comparison is per language, so it withholds more than it must and never
publishes a wrong verdict. For clang's `aarch64-linux-gnu_ilp32` triple the dump names 8 while
the objects are ELF32, so only an artifact witnesses that target.

The driver's intrinsic macro dump is the second witness: the compiler proper defines
`__x86_64__`, `__i386__` or `__aarch64__` for the target it emits code for, so a wrapper that
prints a fixed `-dumpmachine` triple leaves the macros telling the truth, and on a run that
reads no ELF artifact the dump is the only witness. It is taken with no flags
(`toolchain.target.macros`), under the profile's C flags (`toolchain.target.profile_macros`),
and through the C++ driver under the C++ flags where those differ
(`toolchain.target.profile_macros_cxx`); each probe is held to the dump taken under the flags it
was built with. A dump the driver refused, or one cut off partway through a line, witnesses
nothing. Where the gate's architecture is x86_64, x86 or aarch64 and the dump defines none of
the three macros, it withholds every arch-gated check, unless every ELF artifact the run built
carries that family and a probe of the dump's language built one: then the artifacts overrule
the dump (`overruled`), and the evidence names a flag that suppresses the predefined macros
(`-undef`, `-U` of the family's macro) as the cause where one was passed. Where the profile's C
flags select a target, the gate reads it from the dump under those flags rather than from
`-dumpmachine`. `src/toolchain.rs` carries the mechanism beside `MacroWitness` and
`gate_target`.

The artifact's machine, `elf.elf_class` and `elf.elf_data` also decide whether a run is native:
`env::runs_natively` compares them with the kernel's. The kernel's byte order is read from its
spelling of the machine in `/proc/sys/kernel/arch` (the register entry
`kernel-spelling-names-its-byte-order`) or, where `/proc/sys/kernel/arch` is absent, from
chard's own build (`env::NativeMachine`); a record with no byte order, or a spelling that names
none, withholds.

## The block a report leads with

A report's first key is `digest`: the consistency status, coverage with its earned limitations
apart from its instrument withholdings, one row per check (verdict, level, polarity, channel,
gating rule), every reason a check is not a measurement in one list, and the toolchain, profile
(with `profile.flags_sha256` and a sentence on what the profile measures), execution mode and
revision. `chard digest REPORT` prints it alone. A reader going front to back, an agent with a
context budget among them, reaches the verdicts and whether to trust them before the controls,
`facts` and `decoders` a replay needs. The digest states nothing the report does not:
`report::digest` derives it from the report's own JSON, and the consistency rule
`digest-disagrees-with-report` refuses a digest the fields under it do not give, at publication
and on read. `chard digest` runs that check and prints the block; `jq` over the file reads
whatever the file holds, so read through `chard digest` where the file came from elsewhere. The
digest's `consistency` is the status word `measure` wrote after applying every rule; reading a
report, chard re-runs only the rules `report::REREAD_RULES` lists, which need only the file and
this binary's own tables. In the digest `gating` is a rule id; in the report it is an object. To
read the digest:

```sh
chard digest chard-gcc-bare.json > digest.json
jq -r '.checks[] | select(.verdict == "off" and .polarity == "harden") | .check' digest.json
jq -r '.checks[] | select(.polarity == "weaken") | [.check, .verdict] | @tsv' digest.json
jq -r '.reasons[] | [.check, .standing, .reason] | @tsv' digest.json
```

The first lists the protections measured absent. For a `weaken` check `off` is the protected
state (the flag's effect is absent), so the second lists those apart. `chard table` reads its
rows in protection terms and so shows such a cell inverted, which its legend says; `matrix`
carries each flag's polarity beside its verdict.

## Proof objects and evidence by digest

The control triple earns a verdict inside the chard that measured. A reader who did not run
chard sees only the verdict; a report that publishes each step of a macro or elf-static
reading as a value lets that reader check it without chard's code.

- **The decoder is data.** Each macro and elf-static check decodes through a `chard-predicate/1`
  predicate, and the report's `decoders` carries the predicate of every check it publishes a
  reading of. The language is normative in the `src/predicate` module documentation, and
  `schema/chard-predicate-vectors.json` pins it per language version. A `Decoder` enum makes a
  code decoder on those two channels unrepresentable.
- **The facts are stored once, by digest.** `facts` holds each artifact and preprocessor dump
  the report read, keyed by digest, for the measured build and every evaluated arm
  (`report::FactStore`).
- **The reading is a value.** `decoded` on the measured evidence and on every evaluated arm
  names the store keys it was evaluated over, the deciding clause, the outcome and the level.
- **Two consistency rules close the loop before publication.**
  `fact-store-disagrees-with-references` resolves every reference in both directions and holds
  each to the kinds it admits; `decoded-reading-disagrees-with-facts` re-evaluates every reading
  with the Published view over the store and the published predicate, holds each reading's keys
  to the digests its own site's record publishes, and restates each arm's outcome and each
  measured verdict and level from its reading.
- **The replay also runs outside the measurement.** `chard detect <check> --evidence <report>`
  performs the same replay from the report's JSON alone, restates each measured verdict and each
  `probe-invalid` beside a triple against that triple, and counts `expected == replayed +
  not_replayable`; `--artifact` re-reads a retained object (`src/detect.rs`). It does not
  re-derive the gating rules or the fortify ratchet, so a measurement relabelled
  `indeterminate`, `unsupported` or `not-applicable` is outside what it restates.
- **Identity covers the decoders and the inputs.** `run.decoders_sha256` fingerprints the
  predicates and the decoder source, and `probe_corpus_sha256` folds it in, so a decoder change
  moves the join key; `run.inputs_sha256` digests what the run was asked to measure.

What this does not reach: the fact extractor (`src/elf.rs`) and the runtime and
compiler-diag decoders stay code. `THREAT_MODEL.md` names what still rests on each, and
the project ledger, "Replay beyond the published predicates", carries the open follow-ups.

The cost is size, measured as the byte size of each pretty-printed report `chard measure -o`
writes, in six cells (gcc and clang under `bare`, `bare-optimized` and `openssf-tldr`), against
the same host's reports without the proof objects (2026-09-28). With them (2026-09-29), the
reports were larger by 7.91, 9.81 and 13.25% (gcc) and 8.10, 9.70 and 13.79% (clang) on
Fedora 44 x86_64 (gcc 16.1.1, clang 22.1.8, GNU ld 2.46.1), and by 7.39, 9.22 and 12.82% (gcc) and 6.62,
8.55 and 12.45% (clang) on Fedora 44 aarch64 (gcc 16.2.1, clang 22.1.8, GNU ld 2.46.1), within
a budget of +15%; no verdict or level differed, no report contradicted itself, and
every reading replayed in the report's own `consistency.replay` and through `chard detect
--evidence`.

## One binary, running where the toolchain is

chard is a single Rust binary (static when built with `make musl`): probe corpus, compiler
invocation, ELF parsing and verdict in one process, so the guest needs no python3 or binutils,
only the toolchain being tested. ELF is parsed with safe Rust over bytes, with no `readelf`
shell-out, since its output format drifts across binutils versions.

The trade-off is that no second tool recomputes verdicts from copied-out artifacts; the
replay above, the logged `build.argv` and artifact `sha256`, and `chard detect --artifact` over
a probe binary left in the workdir stand in for one.

## Containers vs VMs

- **Container (cheap)**: `macro`, `compiler-diag` and `elf-static` need only the toolchain, and
  a container covers most of `runtime` (canary abort, FORTIFY abort, UBSan text).
- **VM (required)**: kernel-enforced runtime behavior (shadow stack, missing `PT_GNU_STACK`
  handling), since containers share the host kernel and would misreport per-distro results.
  Probes needing this declare `needs_vm`.
- Two checks declare `needs_vm`: `noexecstack-enforced` and `shadow-stack-enforced`. Under
  `--execution container` they publish `indeterminate` under `needs-vm`. A kernel that answers
  the shadow-stack status query with `EINVAL` reads `unsupported` under
  `kernel-lacks-shadow-stack`, and another refusal, such as a seccomp filter's `EPERM`, is
  not read as the kernel's lack; a CPU that does not enumerate CET_SS reads `indeterminate`
  under `cpu-lacks-shadow-stack`, since in a guest the CPU is the hypervisor's.
- **Rows measured in containers** (Wolfi, Chimera, Gentoo's hardened and default stage3) run on
  the host's kernel, so no kernel-dependent result from them belongs to the distribution.

Two C-library behaviours silence the `needs_vm` checks, and are named as the instrument class
(chard's question could not be put) rather than left `probe-invalid`. A glibc that ignores
`GLIBC_TUNABLES` never applies the shadow-stack opt-in, which the probe sees through a second
tunable it carries as a witness (`opt-in-not-honoured`); a glibc loader that refuses
executable-stack programs stops the `-z execstack` arm before `main`
(`loader-refuses-execstack`, quoting the loader). A Wolfi-derived rootfs's glibc 2.44-r23 does
both. Neither reads `off`, and `environment.libc` cannot name such a variant, since it is read from headers
that say nothing of how the library was patched.

A `needs_vm` check is measured only on the operator's word that the kernel is the system's own,
`--execution host` or `vm`, since a container chard has no instrument for (Apptainer, mock, a
chroot) reads the same as a bare host. No instrument of chard's can corroborate the word, but
five can contradict it (a runtime's marker file, a cgroup needle, systemd's
`/run/systemd/container`, a `container=` word on PID 1, a user namespace), and the word beside
any of them is refused. With no word, `host` is assumed and the checks are withheld under
`execution-mode-assumed`, so a plain `chard measure` on a bare host needs `--execution host` to
publish them, and `--fail-on-missing` fails without it; `environment.kernel.ownership` publishes
`own`, `borrowed` or `unsettled` (`env::KernelAttribution`). chard doesn't boot images; that is
the caller's harness, and `make sweep` and the CI lane declare the mode per lane.

## Platform support

The platforms chard is held on, each with its tier and the compiler versions held, are the
matrix in [`SUPPORT.md`](SUPPORT.md), which `tests/support_matrix.rs` holds to the fixture
corpus. On macOS the artifacts are Mach-O, so the artifact checks read indeterminate or
arch-gated, while `macro`, `compiler-diag` and `runtime` still work; `runtime` detects Apple's
silent fortify clamp (level 3 to 2) through a `SIGTRAP`-identified report. `SUPPORT.md` gives
what is measured on the BSDs; FreeBSD's fortify gate is under "What is universal". aarch64 ELF
markers (BTI, PAC, GCS) are read and measured on Fedora 44 and Ubuntu 26.04, with gcc and clang.
