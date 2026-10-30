/* SPDX-License-Identifier: BSD-3-Clause */

/* Makes a probe binary testify about its own compilation.
 *
 * CHARD_EMIT_REPORT defines a string in a dedicated `.chard.report` section
 * listing every hardening-relevant predefined macro as it stood when this
 * translation unit was preprocessed. Read it back with either of:
 *
 *     readelf -p .chard.report ./probe
 *     otool -s __DATA .chard.report ./probe     (Mach-O)
 *     strings ./probe | grep -A40 CHARD-REPORT-V2
 *
 * chard reads only ELF, so on Mach-O the section is emitted but not extracted;
 * the `strings` route is what recovers it there.
 *
 * chard extracts it into the artifact's stored facts, `facts[<digest>].elf.self_report`,
 * automatically. The value of
 * doing it this way is that the evidence travels *with the artifact*: copy a
 * binary out of a VM and it still names the toolchain settings that built it.
 * It is self-reported, so the elf-static and runtime channels cross-check it.
 *
 * Include this header *after* a libc header. `__USE_FORTIFY_LEVEL` is defined by
 * glibc's <features.h> rather than by the compiler, and it is the most valuable
 * macro here: the fortify level glibc actually settled on, which can be lower
 * than the one the command line asked for (glibc silently downgrades a requested
 * level 3 when the compiler cannot support it). The order is enforced at
 * preprocess time; the block below the include guard says how, and what went
 * wrong while it was only asked for.
 *
 * Every entry renders as `name=value` when defined and `name undefined` when not, so
 * a report is complete and diffable across toolchains rather than sparse. The two
 * cannot be confused: a defined line always holds `=` after the name, and the
 * undefined line holds none. A value cannot reach another line either, since a
 * stringified macro never contains a newline (gcc and clang cut a `-D` value at an
 * embedded newline). Until `CHARD-REPORT-V2` the undefined spelling was `name=?`,
 * which is also what a macro defined as `?` writes, so `-D__EXCEPTIONS=?` read as
 * undefined; `src/decode/common.rs` still reads a `CHARD-REPORT-V1` report that way.
 */

#ifndef CHARD_SELFREPORT_H
#define CHARD_SELFREPORT_H

/* --- the include-order precondition, enforced ------------------------------
 *
 * Included before any libc header, this file reported `__USE_FORTIFY_LEVEL` and
 * `__GLIBC__` undefined for a build that really was `-O2 -D_FORTIFY_SOURCE=2`, with
 * no diagnostic even under `-Wall -Wextra`. The report's own convention reads that as
 * "the compiler did not define this", so the understated level was
 * indistinguishable from a deliberate absence, in the part of the output that
 * travels with the artifact. Nothing enforced the order but a sentence above.
 *
 * So it is checked here, using the guard macro each C library's own headers
 * define on the way in. glibc, musl and uclibc all spell it `_FEATURES_H` in
 * <features.h>, which every one of their headers includes; Apple's <sys/cdefs.h>
 * defines `_CDEFS_H_`; FreeBSD, OpenBSD and NetBSD define `_SYS_CDEFS_H_` in
 * theirs. Each guard was read from that library's own source. A platform none of
 * these clauses names is not checked: an #error there would fail every probe
 * build on a C library this file has never met, which is loud and also wrong, so
 * its guard is added here when it is measured. Bionic is excluded from the Linux
 * clause for that reason. tests/probe_sources.rs compiles a wrong-order
 * translation unit on the host and reads the error back.
 */
#if defined(__linux__) && !defined(__ANDROID__) && !defined(_FEATURES_H)
#  error "chard_selfreport.h must be included after a libc header: <features.h> has not been seen, so __USE_FORTIFY_LEVEL and __GLIBC__ would report as undefined"
#elif defined(__APPLE__) && !defined(_CDEFS_H_)
#  error "chard_selfreport.h must be included after a libc header: <sys/cdefs.h> has not been seen, so _USE_FORTIFY_LEVEL would report as undefined"
#elif (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)) && !defined(_SYS_CDEFS_H_)
#  error "chard_selfreport.h must be included after a libc header: <sys/cdefs.h> has not been seen"
#endif

#define CHARD_REPORT_MARKER "CHARD-REPORT-V2"

#define CHARD__STR(x) #x
#define CHARD__XSTR(x) CHARD__STR(x)

/* --- compiler identity ---------------------------------------------------- */

#ifdef __GNUC__
#  define CHARD__R_GNUC "__GNUC__=" CHARD__XSTR(__GNUC__) "\n"
#else
#  define CHARD__R_GNUC "__GNUC__ undefined\n"
#endif

#ifdef __GNUC_MINOR__
#  define CHARD__R_GNUC_MINOR "__GNUC_MINOR__=" CHARD__XSTR(__GNUC_MINOR__) "\n"
#else
#  define CHARD__R_GNUC_MINOR "__GNUC_MINOR__ undefined\n"
#endif

#ifdef __clang_major__
#  define CHARD__R_CLANG "__clang_major__=" CHARD__XSTR(__clang_major__) "\n"
#else
#  define CHARD__R_CLANG "__clang_major__ undefined\n"
#endif

#ifdef __STDC_VERSION__
#  define CHARD__R_STDC "__STDC_VERSION__=" CHARD__XSTR(__STDC_VERSION__) "\n"
#else
#  define CHARD__R_STDC "__STDC_VERSION__ undefined\n"
#endif

/* --- optimization: FORTIFY is inert without it, so it belongs in the report - */

#ifdef __OPTIMIZE__
#  define CHARD__R_OPT "__OPTIMIZE__=" CHARD__XSTR(__OPTIMIZE__) "\n"
#else
#  define CHARD__R_OPT "__OPTIMIZE__ undefined\n"
#endif

#ifdef __NO_INLINE__
#  define CHARD__R_NOINLINE "__NO_INLINE__=" CHARD__XSTR(__NO_INLINE__) "\n"
#else
#  define CHARD__R_NOINLINE "__NO_INLINE__ undefined\n"
#endif

/* --- position independence ------------------------------------------------ */

#ifdef __PIC__
#  define CHARD__R_PIC "__PIC__=" CHARD__XSTR(__PIC__) "\n"
#else
#  define CHARD__R_PIC "__PIC__ undefined\n"
#endif

#ifdef __PIE__
#  define CHARD__R_PIE "__PIE__=" CHARD__XSTR(__PIE__) "\n"
#else
#  define CHARD__R_PIE "__PIE__ undefined\n"
#endif

/* --- stack protector: the four macros encode the level -------------------- */

#ifdef __SSP__
#  define CHARD__R_SSP "__SSP__=" CHARD__XSTR(__SSP__) "\n"
#else
#  define CHARD__R_SSP "__SSP__ undefined\n"
#endif

#ifdef __SSP_STRONG__
#  define CHARD__R_SSP_STRONG "__SSP_STRONG__=" CHARD__XSTR(__SSP_STRONG__) "\n"
#else
#  define CHARD__R_SSP_STRONG "__SSP_STRONG__ undefined\n"
#endif

#ifdef __SSP_ALL__
#  define CHARD__R_SSP_ALL "__SSP_ALL__=" CHARD__XSTR(__SSP_ALL__) "\n"
#else
#  define CHARD__R_SSP_ALL "__SSP_ALL__ undefined\n"
#endif

/* gcc's -fstack-protector-explicit, which instruments only functions marked
 * __attribute__((stack_protect)); clang rejects the flag and defines no such macro. */
#ifdef __SSP_EXPLICIT__
#  define CHARD__R_SSP_EXPLICIT "__SSP_EXPLICIT__=" CHARD__XSTR(__SSP_EXPLICIT__) "\n"
#else
#  define CHARD__R_SSP_EXPLICIT "__SSP_EXPLICIT__ undefined\n"
#endif

/* --- fortify: requested vs. what glibc settled on ------------------------- */

#ifdef _FORTIFY_SOURCE
#  define CHARD__R_FORTIFY "_FORTIFY_SOURCE=" CHARD__XSTR(_FORTIFY_SOURCE) "\n"
#else
#  define CHARD__R_FORTIFY "_FORTIFY_SOURCE undefined\n"
#endif

#ifdef __USE_FORTIFY_LEVEL
#  define CHARD__R_FORTIFY_EFF "__USE_FORTIFY_LEVEL=" CHARD__XSTR(__USE_FORTIFY_LEVEL) "\n"
#else
#  define CHARD__R_FORTIFY_EFF "__USE_FORTIFY_LEVEL undefined\n"
#endif

/* Apple's parallel to the macro above, and note the single leading underscore: this is
 * `_USE_FORTIFY_LEVEL`, defined by `<secure/_common.h>`, not glibc's
 * `__USE_FORTIFY_LEVEL`. Reported under its own name rather than folded into the field
 * above, because the two are different macros from different libraries and a reader
 * comparing reports across platforms needs to see which one answered.
 *
 * It is the level the C library settled on, which is the same role `__USE_FORTIFY_LEVEL`
 * plays for glibc, and on Apple it is a *clamped* level: `<secure/_common.h>` maps
 * everything above 1 to 2, so a requested `_FORTIFY_SOURCE=3` reports 2 here. That is
 * not a downgrade the command line asked for; Apple implements no level 3.
 */
#ifdef _USE_FORTIFY_LEVEL
#  define CHARD__R_FORTIFY_APPLE "_USE_FORTIFY_LEVEL=" CHARD__XSTR(_USE_FORTIFY_LEVEL) "\n"
#else
#  define CHARD__R_FORTIFY_APPLE "_USE_FORTIFY_LEVEL undefined\n"
#endif

/* FreeBSD's level macro, from `<ssp/ssp.h>`, which `<string.h>` and the other wrapped
 * headers reach only under `_FORTIFY_SOURCE > 0`. The header settles the level itself: 1
 * for a request of 1, 2 for any request above 1 (it implements no level 3), and 0 where its
 * wrappers do not instantiate, which its `#if` admits for a C++ translation unit or a build
 * without `__OPTIMIZE__` under a compiler other than clang (clang gets the wrappers at every
 * optimization level). Undefined where no request reached a header that settles it, and on
 * a FreeBSD before 15, whose headers carry no `<ssp/ssp.h>` at all; 15.1's `<sys/select.h>`
 * settles 0 itself where no request reached it, so a unit that includes it reads 0 under no
 * request. Measured on FreeBSD 15.1 amd64 (clang 19.1.7): 1, 2 and 2 for requests of 1, 2
 * and 3 at -O2, 2 for a request of 2 at -O0, 0 in a C++ translation unit that reaches
 * `<ssp/ssp.h>` (its C++ branch; measured at a request of 3), 0 in a C++ unit of
 * `<cstdio>` and `<vector>` with no request (through `<sys/select.h>`), and undefined in a
 * unit of `<stdio.h>`, `<stdlib.h>` and `<string.h>` with none, in C or C++; and on 14.5
 * (clang 21.1.8): no /usr/include/ssp/, the macro undefined at every request.
 * Reported under its own name, as Apple's is, since it is another library's macro and a
 * reader comparing reports needs to see which one answered. */
#ifdef __SSP_FORTIFY_LEVEL
#  define CHARD__R_FORTIFY_FREEBSD "__SSP_FORTIFY_LEVEL=" CHARD__XSTR(__SSP_FORTIFY_LEVEL) "\n"
#else
#  define CHARD__R_FORTIFY_FREEBSD "__SSP_FORTIFY_LEVEL undefined\n"
#endif

/* Which implementation is providing the wrappers, because they fail differently.
 *
 * glibc's `__chk_fail` aborts with "buffer overflow detected" on stderr; Alpine's
 * fortify-headers calls `__builtin_trap()`, which says nothing. A detector that knows
 * only glibc's signature reads a live fortify-headers trap as an unrecognised death and
 * withholds the verdict, which is safe but reports nothing.
 *
 * Apple is a third case, and the reason it needs naming is subtler than the other two:
 * its `__chk_fail_overflow` does emit "detected buffer overflow", but `ReportCrash`
 * writes that to a `.ips` crash report and the unified log *after* the process dies, not
 * to the process's own stderr. Measured on arm64: both pipes come back empty. So for a
 * detector reading the streams it opened (which is all chard reads), Apple presents the
 * fortify-headers shape, a bare trap with nothing in band, and has to be credited the
 * same way.
 *
 * `_FORTIFY_HEADERS_H` is that package's own include guard, so it is set only once the
 * wrappers are genuinely in the translation unit, the header is reached through
 * `<string.h>` and only when `_FORTIFY_SOURCE` is defined. `__has_include` alone would
 * answer "installed", which is a weaker claim than "active here". `_USE_FORTIFY_LEVEL`
 * carries the same guarantee for Apple: `<_string.h>` includes `<secure/_string.h>` on
 * `__GNUC__ && _FORTIFY_SOURCE > 0 && !defined(__cplusplus)`, so the macro is undefined (
 * not zero) when fortify is off.
 *
 * That `__cplusplus` term is not a detail. Apple's fortify wrappers never engage in a C++
 * translation unit at all, so a C++ probe there reports `_FORTIFY_SOURCE=2` beside
 * `_USE_FORTIFY_LEVEL` and `_FORTIFY_IMPL` undefined, and that is the honest reading
 * rather than a gap: what was requested, and nothing enforcing it. Measured on macOS
 * 26.5.1 (build 25F80), SDK 26.5, Apple clang 21.0.0, arm64, which is the only Apple
 * configuration any claim in this file rests on.
 *
 * FreeBSD is a fourth case, and the one that fails most quietly. Its `__chk_fail` writes
 * "buffer overflow detected; terminated" to syslog(3) and aborts: a bare SIGABRT with
 * nothing on stderr and no survival marker on stdout, since the message goes to the system
 * log and not to the process. Measured on FreeBSD 15.1 amd64 (clang 19.1.7): the
 * abort, an empty stderr, and the line in /var/log/messages. `__SSP_FORTIFY_LEVEL` above 0
 * is the claim that `<ssp/ssp.h>`'s wrappers instantiated in this translation unit, the
 * same claim `__USE_FORTIFY_LEVEL > 0` makes for glibc; the platform macro is required
 * beside it so that another library spelling the same name is not read as FreeBSD's.
 */
#ifdef _FORTIFY_HEADERS_H
#  define CHARD__R_FORTIFY_IMPL "_FORTIFY_IMPL=fortify-headers\n"
#elif defined(__USE_FORTIFY_LEVEL) && __USE_FORTIFY_LEVEL > 0
#  define CHARD__R_FORTIFY_IMPL "_FORTIFY_IMPL=glibc\n"
#elif defined(__APPLE__) && defined(_USE_FORTIFY_LEVEL) && _USE_FORTIFY_LEVEL > 0
#  define CHARD__R_FORTIFY_IMPL "_FORTIFY_IMPL=apple\n"
#elif defined(__FreeBSD__) && defined(__SSP_FORTIFY_LEVEL) && __SSP_FORTIFY_LEVEL > 0
#  define CHARD__R_FORTIFY_IMPL "_FORTIFY_IMPL=freebsd\n"
#else
#  define CHARD__R_FORTIFY_IMPL "_FORTIFY_IMPL undefined\n"
#endif

/* --- control-flow integrity ----------------------------------------------- */

#ifdef __CET__
#  define CHARD__R_CET "__CET__=" CHARD__XSTR(__CET__) "\n"
#else
#  define CHARD__R_CET "__CET__ undefined\n"
#endif

#ifdef __ARM_FEATURE_BTI_DEFAULT
#  define CHARD__R_BTI "__ARM_FEATURE_BTI_DEFAULT=" CHARD__XSTR(__ARM_FEATURE_BTI_DEFAULT) "\n"
#else
#  define CHARD__R_BTI "__ARM_FEATURE_BTI_DEFAULT undefined\n"
#endif

#ifdef __ARM_FEATURE_PAC_DEFAULT
#  define CHARD__R_PAC "__ARM_FEATURE_PAC_DEFAULT=" CHARD__XSTR(__ARM_FEATURE_PAC_DEFAULT) "\n"
#else
#  define CHARD__R_PAC "__ARM_FEATURE_PAC_DEFAULT undefined\n"
#endif

/* Guarded Control Stack: the third bit in the same feature word as BTI and PAC, and
 * aarch64's counterpart to the x86 shadow stack reported above through __CET__. Newer
 * than the other two, so a toolchain that predates it reports it undefined while
 * still answering for BTI and PAC. */
#ifdef __ARM_FEATURE_GCS_DEFAULT
#  define CHARD__R_GCS "__ARM_FEATURE_GCS_DEFAULT=" CHARD__XSTR(__ARM_FEATURE_GCS_DEFAULT) "\n"
#else
#  define CHARD__R_GCS "__ARM_FEATURE_GCS_DEFAULT undefined\n"
#endif

/* --- libc / C++ library hardening ----------------------------------------- */

#ifdef __GLIBC__
#  define CHARD__R_GLIBC "__GLIBC__=" CHARD__XSTR(__GLIBC__) "\n"
#else
#  define CHARD__R_GLIBC "__GLIBC__ undefined\n"
#endif

#ifdef __GLIBC_MINOR__
#  define CHARD__R_GLIBC_MINOR "__GLIBC_MINOR__=" CHARD__XSTR(__GLIBC_MINOR__) "\n"
#else
#  define CHARD__R_GLIBC_MINOR "__GLIBC_MINOR__ undefined\n"
#endif

/* FreeBSD's libc announces itself through the platform macro alone, as OpenBSD's and
 * Apple's do, and its value is the release major, which is the libc's too, since the two
 * ship together. The fortify readers need it beside `_FORTIFY_IMPL`: a request that reached
 * the headers with `__SSP_FORTIFY_LEVEL` undefined is, on a FreeBSD, a release whose headers
 * carry no fortify implementation (below 15), which is not the same silence as a
 * library chard does not know. */
#ifdef __FreeBSD__
#  define CHARD__R_FREEBSD "__FreeBSD__=" CHARD__XSTR(__FreeBSD__) "\n"
#else
#  define CHARD__R_FREEBSD "__FreeBSD__ undefined\n"
#endif

#ifdef _GLIBCXX_ASSERTIONS
#  define CHARD__R_GLIBCXX "_GLIBCXX_ASSERTIONS=" CHARD__XSTR(_GLIBCXX_ASSERTIONS) "\n"
#else
#  define CHARD__R_GLIBCXX "_GLIBCXX_ASSERTIONS undefined\n"
#endif

/* Which C++ standard library is providing the headers, because the two answer the
 * hardening question with different macros and a build with neither macro defined is
 * ambiguous without it. `_GLIBCXX_ASSERTIONS` undefined alone cannot distinguish
 * libstdc++ with assertions off from libc++, which does not use that macro at all,
 * the same ambiguity `_FORTIFY_IMPL` was added to resolve for the C library.
 *
 * `__GLIBCXX__` and `_LIBCPP_VERSION` are each library's own version macro, so they are
 * set by including any header from it rather than by asking for hardening. In a C
 * translation unit neither is defined and this reports undefined, which is correct:
 * a C build has no C++ standard library. */
#if defined(_LIBCPP_VERSION)
#  define CHARD__R_CXX_STDLIB "_CXX_STDLIB=libc++\n"
#elif defined(__GLIBCXX__)
#  define CHARD__R_CXX_STDLIB "_CXX_STDLIB=libstdc++\n"
#else
#  define CHARD__R_CXX_STDLIB "_CXX_STDLIB undefined\n"
#endif

#ifdef _LIBCPP_HARDENING_MODE
#  define CHARD__R_LIBCPP "_LIBCPP_HARDENING_MODE=" CHARD__XSTR(_LIBCPP_HARDENING_MODE) "\n"
#else
#  define CHARD__R_LIBCPP "_LIBCPP_HARDENING_MODE undefined\n"
#endif

/* --- sanitizers and semantics --------------------------------------------- */

#ifdef __SANITIZE_ADDRESS__
#  define CHARD__R_ASAN "__SANITIZE_ADDRESS__=" CHARD__XSTR(__SANITIZE_ADDRESS__) "\n"
#else
#  define CHARD__R_ASAN "__SANITIZE_ADDRESS__ undefined\n"
#endif

#ifdef __SANITIZE_UNDEFINED__
#  define CHARD__R_UBSAN "__SANITIZE_UNDEFINED__=" CHARD__XSTR(__SANITIZE_UNDEFINED__) "\n"
#else
#  define CHARD__R_UBSAN "__SANITIZE_UNDEFINED__ undefined\n"
#endif

#ifdef __EXCEPTIONS
#  define CHARD__R_EXCEPTIONS "__EXCEPTIONS=" CHARD__XSTR(__EXCEPTIONS) "\n"
#else
#  define CHARD__R_EXCEPTIONS "__EXCEPTIONS undefined\n"
#endif

/* -ffast-math weakens rather than hardens; recorded so a report can flag it. */
#ifdef __FAST_MATH__
#  define CHARD__R_FASTMATH "__FAST_MATH__=" CHARD__XSTR(__FAST_MATH__) "\n"
#else
#  define CHARD__R_FASTMATH "__FAST_MATH__ undefined\n"
#endif

#ifdef _FILE_OFFSET_BITS
#  define CHARD__R_FOB "_FILE_OFFSET_BITS=" CHARD__XSTR(_FILE_OFFSET_BITS) "\n"
#else
#  define CHARD__R_FOB "_FILE_OFFSET_BITS undefined\n"
#endif

#define CHARD_REPORT_BODY \
    CHARD__R_GNUC CHARD__R_GNUC_MINOR CHARD__R_CLANG CHARD__R_STDC \
    CHARD__R_OPT CHARD__R_NOINLINE \
    CHARD__R_PIC CHARD__R_PIE \
    CHARD__R_SSP CHARD__R_SSP_STRONG CHARD__R_SSP_ALL CHARD__R_SSP_EXPLICIT \
    CHARD__R_FORTIFY CHARD__R_FORTIFY_EFF CHARD__R_FORTIFY_APPLE CHARD__R_FORTIFY_FREEBSD \
    CHARD__R_FORTIFY_IMPL \
    CHARD__R_CET CHARD__R_BTI CHARD__R_PAC CHARD__R_GCS \
    CHARD__R_GLIBC CHARD__R_GLIBC_MINOR CHARD__R_FREEBSD CHARD__R_GLIBCXX CHARD__R_LIBCPP \
    CHARD__R_CXX_STDLIB \
    CHARD__R_ASAN CHARD__R_UBSAN CHARD__R_EXCEPTIONS CHARD__R_FASTMATH \
    CHARD__R_FOB

/* `retain` keeps the section through `--gc-sections`; it needs GCC 11 / Clang 13,
 * so it is applied only where supported rather than failing the build on older
 * toolchains we still want to measure.
 */
#if defined(__has_attribute)
#  if __has_attribute(retain)
#    define CHARD__RETAIN , retain
#  endif
#endif
#ifndef CHARD__RETAIN
#  define CHARD__RETAIN
#endif

/* Mach-O needs "segment,section"; ELF takes the bare name. Same section name
 * either way, so the reader has one spelling to look for.
 *
 * `__DATA` because Mach-O protects per segment and neither choice reproduces ELF's
 * `A` without `W` or `X`: measured on arm64, `__TEXT` links with `initprot 0x5`
 * (read + execute) and `__DATA` with `0x3` (read + write). This section is a string
 * nothing jumps to, so writable is the lesser of the two, a tool that measures
 * hardening should not put its own bytes in an executable mapping to avoid a
 * writable one.
 */
#if defined(__APPLE__)
#  define CHARD__REPORT_SECTION section("__DATA,.chard.report")
#else
#  define CHARD__REPORT_SECTION section(".chard.report")
#endif

#define CHARD_EMIT_REPORT \
    __attribute__((used CHARD__RETAIN, CHARD__REPORT_SECTION)) \
    static const char chard_report[] = \
        CHARD_REPORT_MARKER "\n" CHARD_REPORT_BODY "CHARD-REPORT-END\n"

/* Print the same report on stdout, for readers with no object-format reader.
 *
 * The section above travels with the artifact, which is the stronger property and
 * why it stays the preferred source. It is also unreachable wherever chard cannot
 * parse the container: on Mach-O the section says `_FORTIFY_IMPL=apple` in plain
 * text (verified with `otool -s __DATA .chard.report` on an arm64 build) and
 * chard's ELF-only reader returns nothing, so the runtime detector that was written
 * to credit Apple's fortify trap could never fire on Apple.
 *
 * Requires <stdio.h>, and must be the first statement in `main`. Both matter: these
 * probes exist to be killed, and a report still sitting in a stdio buffer when the
 * process takes SIGTRAP is a report that was never written. Hence the explicit
 * fflush rather than trusting exit-time flushing, which a signal death skips.
 *
 * The markers delimit it, so a probe's own output stays separable from this.
 */
#define CHARD_PRINT_REPORT \
    do { \
        fputs(chard_report, stdout); \
        fflush(stdout); \
    } while (0)

/* --- no core, for probes that crash in their own process --------------------
 *
 * A probe that defines CHARD_WANT_NOT_DUMPABLE before including this header gets
 * `CHARD_NOT_DUMPABLE`, a statement to put at the top of `main`: after its declarations,
 * after CHARD_PRINT_REPORT where the probe prints one, and before any other statement
 * but an unbuffering of stdout, which must come before any output on it.
 * On Linux it makes the process non-dumpable (`PR_SET_DUMPABLE` 0), so the crash the
 * probe exists to take leaves no core. Off Linux it is an empty statement.
 *
 * Why. A core_pattern that pipes to a handler (systemd-coredump on Fedora) ignores a
 * core limit of 0 and starts the handler for every crash. The handler's time lands in
 * the run's `duration_ms` and narrows its margin against the deadline. Measured on
 * Fedora 44 x86_64 (kernel 7.3.0-rc3, systemd-coredump, a store of about 9,000 cores,
 * gcc 16.1.1, `bare`): the probes' crash runs took 61 to 88 ms each, and 0 to 1 ms
 * non-dumpable. A store grown to 123,075 cores made one dumpable abort of a
 * test program take about 500 ms on the same host (quoted from the performance review
 * of 2026-10-25, not re-derived). The cost off Linux was not measured here.
 *
 * `fs.suid_dumpable` does not undo it. That sysctl sets the flag only where a process
 * changes credentials (a set-id exec), and the kernel skips the dump of a non-dumpable
 * process before it reads the sysctl. The host above sets it to 2, as systemd's
 * defaults do, and a non-dumpable abort there wrote no core.
 *
 * Where the call fails, the run goes on as before and one line on stdout says so:
 * `chard-note dumpable-unset errno=N`. stdout, because a detector reads an empty stderr
 * as part of a reading (`detect_trapv`). The line comes after the self-report where the
 * probe prints one, so it is outside the report's markers.
 *
 * Opt-in, so the probes that do not crash include nothing more. `tests/core_files.rs`
 * holds the list of probes that call it to the runs that crash, and names the probes
 * left out with their reasons. A probe that re-executes itself starts dumpable again,
 * since exec resets the flag. A probe that forks its crashes
 * (`strict_flex_arrays_enforced.c`) makes its own call, so the rows inherit it. */
#if defined(CHARD_WANT_NOT_DUMPABLE) && defined(__linux__)
#include <errno.h>
#include <stdio.h>
#include <sys/prctl.h>
#define CHARD_NOT_DUMPABLE \
    do { \
        if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) { \
            fprintf(stdout, "chard-note dumpable-unset errno=%d\n", errno); \
            fflush(stdout); \
        } \
    } while (0)
#elif defined(CHARD_WANT_NOT_DUMPABLE)
#define CHARD_NOT_DUMPABLE \
    do { \
    } while (0)
#endif

/* --- exit statuses for a precondition a probe could not establish ------------
 *
 * A runtime probe exits 0 having printed `no-check-fired`, or dies by the signal
 * the mechanism under test raises. Anything else means the probe never put its
 * question, and the runtime detector withholds the verdict rather than reading
 * the run as `off`. These statuses say which precondition failed, so a withheld
 * cell names its cause instead of reading `unexpected termination`.
 *
 * Each is distinct from every other and from anything the mechanisms under test
 * produce. Those a detector reads by number are spelled a second time as
 * `PROBE_EXIT_*` in src/decode/runtime.rs, and a unit test there reads these
 * definitions back so the two cannot drift, and reads every probe source so that
 * no statement ending the program spells a status reserved here as an integer
 * literal or a local macro naming one (a character literal, a macro naming a macro
 * and a status carried in a variable are beyond it).
 */

/* malloc returned NULL: the host ran out of memory, a condition of the machine
 * alone. */
#define CHARD_EXIT_NO_ALLOCATION 77

/* fortify_known_object.c: neither guard array directly follows `dst`, so the bytes
 * the overflow would write are not inside an object this probe declares. */
#define CHARD_EXIT_LAYOUT 78

/* fortify_dynamic_object.c: `malloc_usable_size(dst)` or the position of `src`
 * is not the glibc chunk geometry the probe's margin is computed from. */
#define CHARD_EXIT_HEAP_GEOMETRY 79

/* fortify_dynamic_object.c: `__builtin_object_size(dst)` is statically known, so a
 * level-2 build would fire exactly like level 3 and the run cannot separate them. */
#define CHARD_EXIT_OPACITY_LOST 80

/* stack_clash.c and stack_exec_runtime.c: the probe declined to put its question
 * and printed `<TAG> probe-invalid=<reason>` on stdout first, naming why. Their
 * detectors read that line and not this status, so it has no `PROBE_EXIT_*` twin;
 * the test that reads this block back lists it with that reason. */
#define CHARD_EXIT_DECLINED 81

/* --- the fault reporter, for probes that must say which fault killed them ------
 *
 * A probe that defines CHARD_WANT_FAULT_REPORT before including this header gets
 * `chard_report_faults()`, to call at the top of `main` after CHARD_PRINT_REPORT,
 * and `chard_declare_fault_target(p)`, to name the one address the probe expects
 * a fault at. On SIGILL, SIGTRAP, SIGSEGV or SIGBUS the handler writes one line to
 * stderr and raises the signal again with its default action, so the process dies
 * by the signal it took:
 *
 *     chard-fault-v1 signal=4 code=2 sent=no arch=aarch64 pc=0x... addr=0x... word=0xd50323bf esr=0x72000000 at-target=undeclared
 *
 * `code` is si_code; `sent` is whether another process (or the probe) sent the signal
 * with kill or raise, which si_code <= 0 means, rather than an instruction faulting.
 * `pc` and `addr` are the faulting pc and si_addr.
 *
 * `word` is the instruction at the pc: one 32-bit word on aarch64; on x86 the bytes
 * there in memory order, packed little-endian (eight on x86_64, four on i386). It is
 * read only where si_addr is the pc, no further than the end of the pc's page, and
 * with process_vm_readv on the probe itself, which fails with EFAULT on an unreadable
 * address instead of faulting inside the handler, and needs no descriptor. Where the
 * read fails the line says `none`.
 *
 * `esr` is the ESR_EL1 value the kernel puts in the signal frame, `none` where it puts
 * none. `src/run.rs` (`RunRecord::fault_report`) parses the line and
 * `FaultReport::classify` classifies it; a report that cannot decide is `Undetermined`,
 * which a reading must withhold rather than count as a trap.
 *
 * Why a self-report: the parent's wait status carries the signal and nothing else,
 * and chard is safe Rust over std, which offers no waitid or ptrace. So the fault's
 * si_code and the faulting instruction can come only from the process that took it,
 * the way shadow_stack.c reports SEGV_CPERR.
 *
 * Why a declared target: on hardware a BTI fault and an undefined instruction arrive
 * the same way. Measured on 2026-10-09 on an Apple M2 under a Linux 7.0 guest: an
 * indirect branch to a non-landing-pad instruction on a PROT_BTI page, and a `udf`,
 * each delivered SIGILL with si_code ILL_ILLOPC (1) and no ESR record, with si_addr
 * the pc. qemu-user 10.2.2 does write an ESR record for it, of class 0x0d. A PAC
 * authentication failure under FEAT_FPAC arrived as SIGILL ILL_ILLOPN (2) with an ESR
 * record of class 0x1c, and `__builtin_trap()` as SIGTRAP TRAP_BRKPT (1) at a `brk`.
 * On x86_64 (Fedora 44, gcc 16.1.1, clang 22.1.8) a trap is SIGILL ILL_ILLOPN at
 * `ud2`, or at `ud1` with a 0x67 prefix from clang's sanitizer and -ftrapv traps, and
 * an `int3` is SIGTRAP SI_KERNEL (128) with si_addr 0.
 *
 * Requires _GNU_SOURCE defined before the first include (siginfo_t, REG_RIP and
 * process_vm_readv are not visible without it), and Linux, because the frame layout is: elsewhere both
 * calls are no-ops, the probe prints no line, and chard reads the bare signal as it
 * always has. Written for C89 compilers: no inline, declarations first.
 */
#if defined(CHARD_WANT_FAULT_REPORT)
#if defined(__linux__) && (defined(__aarch64__) || defined(__x86_64__) || defined(__i386__))
#if !defined(_GNU_SOURCE)
#  error "CHARD_WANT_FAULT_REPORT needs _GNU_SOURCE defined before the first include"
#endif
#include <signal.h>
#include <string.h>
#include <sys/uio.h>
#include <ucontext.h>
#include <unistd.h>

/* The ESR record's header and magic from the kernel's arm64 sigcontext ABI, spelled
 * here so the header does not include <asm/sigcontext.h> beside <signal.h>. */
#define CHARD_ESR_MAGIC 0x45535201u
struct chard_ctx_head {
    unsigned int magic;
    unsigned int size;
};

static volatile unsigned long chard_fault_target;

__attribute__((unused)) static void chard_declare_fault_target(const void *p)
{
    chard_fault_target = (unsigned long)p;
}

/* snprintf is not async-signal-safe; these are. */
static char *chard_fault_put(char *at, const char *s)
{
    while (*s)
        *at++ = *s++;
    return at;
}

static char *chard_fault_num(char *at, unsigned long v, int hex)
{
    char digits[24];
    int n = 0;
    unsigned base = hex ? 16 : 10;
    if (hex)
        at = chard_fault_put(at, "0x");
    do {
        digits[n++] = "0123456789abcdef"[v % base];
        v /= base;
    } while (v);
    while (n)
        *at++ = digits[--n];
    return at;
}

/* Copy `n` bytes at `from` without touching them directly: process_vm_readv on the
 * probe's own pid fails with EFAULT for an unreadable address instead of raising a
 * second fault, and uses no descriptor the probe could have closed or reused. */
static int chard_fault_peek(unsigned long from, unsigned char *to, int n)
{
    struct iovec local;
    struct iovec remote;
    local.iov_base = to;
    local.iov_len = (size_t)n;
    remote.iov_base = (void *)from;
    remote.iov_len = (size_t)n;
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == (ssize_t)n;
}

static void chard_fault_handler(int sig, siginfo_t *info, void *context)
{
    ucontext_t *uc = context;
    unsigned long pc;
    unsigned long esr = 0;
    unsigned long word = 0;
    unsigned char bytes[sizeof(unsigned long)] = { 0 };
    int have_esr = 0;
    int have_word = 0;
    int nbytes;
    int i;
    const char *arch;
    char line[320];
    char *at = line;
#if defined(__aarch64__)
    unsigned char *p = (unsigned char *)uc->uc_mcontext.__reserved;
    unsigned char *end = p + sizeof uc->uc_mcontext.__reserved;
    arch = "aarch64";
    nbytes = 4;
    pc = (unsigned long)uc->uc_mcontext.pc;
    while (p + sizeof(struct chard_ctx_head) <= end) {
        struct chard_ctx_head *head = (struct chard_ctx_head *)p;
        if (head->magic == 0 || head->size == 0 || head->size > (unsigned int)(end - p))
            break;
        if (head->magic == CHARD_ESR_MAGIC && head->size >= 16 && end - p >= 16) {
            memcpy(&esr, p + 8, sizeof esr);
            have_esr = 1;
        }
        p += head->size;
    }
#elif defined(__x86_64__)
    arch = "x86_64";
    nbytes = (int)sizeof(unsigned long);
    pc = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
#else
    arch = "x86";
    nbytes = (int)sizeof(unsigned long);
    pc = (unsigned long)uc->uc_mcontext.gregs[REG_EIP];
#endif
    /* On x86 the bytes read stop at the end of the pc's page: a trap in a page's last
     * bytes, before an unmapped page, still yields what it has. x86 pages are 4 KiB at
     * the smallest, and an aarch64 instruction never straddles a page. */
    if (4096 - (int)(pc % 4096) < nbytes)
        nbytes = 4096 - (int)(pc % 4096);
    if ((unsigned long)info->si_addr == pc && chard_fault_peek(pc, bytes, nbytes)) {
        for (i = nbytes - 1; i >= 0; i--)
            word = (word << 8) | bytes[i];
        have_word = 1;
    }
    at = chard_fault_put(at, "chard-fault-v1 signal=");
    at = chard_fault_num(at, (unsigned long)sig, 0);
    at = chard_fault_put(at, " code=");
    if (info->si_code < 0) {
        at = chard_fault_put(at, "-");
        at = chard_fault_num(at, (unsigned long)-(long)info->si_code, 0);
    } else {
        at = chard_fault_num(at, (unsigned long)info->si_code, 0);
    }
    at = chard_fault_put(at, info->si_code <= 0 ? " sent=yes" : " sent=no");
    at = chard_fault_put(at, " arch=");
    at = chard_fault_put(at, arch);
    at = chard_fault_put(at, " pc=");
    at = chard_fault_num(at, pc, 1);
    at = chard_fault_put(at, " addr=");
    at = chard_fault_num(at, (unsigned long)info->si_addr, 1);
    at = chard_fault_put(at, " word=");
    if (have_word)
        at = chard_fault_num(at, word, 1);
    else
        at = chard_fault_put(at, "none");
    at = chard_fault_put(at, " esr=");
    if (have_esr)
        at = chard_fault_num(at, esr, 1);
    else
        at = chard_fault_put(at, "none");
    at = chard_fault_put(at, " at-target=");
    if (chard_fault_target == 0)
        at = chard_fault_put(at, "undeclared");
    else
        at = chard_fault_put(at, pc == chard_fault_target ? "yes" : "no");
    *at++ = '\n';
    if (write(2, line, (size_t)(at - line)) < 0) {
        /* Nothing to do: the death below is the measurement either way. */
    }
    /* SA_RESETHAND restored the default action; raising applies it, so the death
     * is the signal the kernel delivered, as it would have been with no handler. */
    raise(sig);
}

__attribute__((unused)) static void chard_report_faults(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = chard_fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
}
#else
__attribute__((unused)) static void chard_declare_fault_target(const void *p) { (void)p; }
__attribute__((unused)) static void chard_report_faults(void) {}
#endif
#endif /* CHARD_WANT_FAULT_REPORT */

/* --- the translation read, for probes whose reading rests on the machine ---------
 *
 * A probe that defines CHARD_WANT_TRANSLATION_REPORT before including this header gets
 * `chard_report_translation()`, to call first in `main`. On Darwin it reads
 * `sysctl.proc_translated` and writes one line to stdout, before anything the probe
 * itself prints:
 *
 *     CHARD-TRANSLATION 0                     the process runs on the machine it was built for
 *     CHARD-TRANSLATION 1                     Rosetta 2 translates it
 *     CHARD-TRANSLATION unreadable errno:N    the read failed (ENOENT, 2, on an Intel Mac)
 *     CHARD-TRANSLATION unreadable size:N     the sysctl answered with another width
 *     CHARD-TRANSLATION unreadable value:N    the sysctl answered neither 0 nor 1
 *
 * Why the sysctl and nothing else: measured on 2026-10-08 on macOS 27.0.1 (Apple clang
 * 21.0.0, an Apple silicon Mac with Rosetta 2), inside a translated process `uname` and
 * `hw.machine` answer x86_64, the translation's own model, and `hw.optional.arm64` reads 1
 * either way; only this sysctl reads 1 translated and 0 native. A Mach-O artifact carries
 * nothing chard's ELF reader can hold to the kernel, so on Darwin this line is the one
 * instrument that tells a native run from a translated one. `decode::runtime::translation`
 * parses it and `report::emulation_limitation` reads it, on a macOS run alone.
 *
 * Elsewhere the call is a no-op and the probe prints no line: no other platform has the
 * sysctl, and a Linux or BSD reading is held to the kernel through the ELF record instead.
 * The line carries no `=`, since `decode::runtime::detect_stack_clash` searches the whole
 * stdout for its `name=` fields. Written with write(2), so it reaches stdout ahead of a
 * probe that writes the same way and of one that buffers through stdio, and survives a
 * probe that ends in `_exit`. Written for C89 compilers: declarations first.
 */
#if defined(CHARD_WANT_TRANSLATION_REPORT)
#if defined(__APPLE__)
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>

#define CHARD_TRANSLATION_MARKER "CHARD-TRANSLATION"

__attribute__((unused)) static void chard_report_translation(void)
{
    int translated = -1;
    size_t size = sizeof translated;
    char line[64];
    int n;
    errno = 0;
    if (sysctlbyname("sysctl.proc_translated", &translated, &size, NULL, 0) != 0) {
        n = snprintf(line, sizeof line, CHARD_TRANSLATION_MARKER " unreadable errno:%d\n",
                     errno);
    } else if (size != sizeof translated) {
        n = snprintf(line, sizeof line, CHARD_TRANSLATION_MARKER " unreadable size:%lu\n",
                     (unsigned long) size);
    } else if (translated == 0 || translated == 1) {
        n = snprintf(line, sizeof line, CHARD_TRANSLATION_MARKER " %d\n", translated);
    } else {
        n = snprintf(line, sizeof line, CHARD_TRANSLATION_MARKER " unreadable value:%d\n",
                     translated);
    }
    if (n > 0 && (size_t) n < sizeof line) {
        (void) !write(1, line, (size_t) n);
    }
}
#else
__attribute__((unused)) static void chard_report_translation(void) {}
#endif
#endif /* CHARD_WANT_TRANSLATION_REPORT */

#endif /* CHARD_SELFREPORT_H */
