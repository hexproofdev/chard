/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wbidi-chars=any probe (compiler-diag channel).
 *
 * The observable is a diagnostic on a Unicode bidirectional override sequence
 * carried in this file's own text - the Trojan Source shape, in which reordering
 * controls make the rendered source read differently from what the compiler
 * parses. Two of them are embedded below: one in a comment and one in a string
 * literal, each written as the raw UTF-8 bytes E2 80 AE (RIGHT-TO-LEFT OVERRIDE,
 * "RLO") and E2 80 AC (POP DIRECTIONAL FORMATTING, "PDF").
 *
 * The pairing is the whole design, and it is what makes this check measure the
 * flag the guide actually recommends. GCC enables bidi checking by default at the
 * weaker `unpaired` level, which fires only on a bidi context left open at the end
 * of a comment or literal. Each sequence here is deliberately *balanced* - every
 * RLO is closed by a PDF before its comment or literal ends - so `unpaired` has
 * nothing to say about it and stays silent, while `any`, which forbids the
 * characters outright, diagnoses both. A probe built from an unbalanced sequence
 * would warn under the stock default too and would report this protection present
 * on every GCC build, measured or not. Confirmed by compiling: an unbalanced
 * variant draws "unpaired UTF-8 bidirectional control character detected" from a
 * bare `gcc` with no flags at all, whereas the balanced text below draws nothing
 * from `-Wbidi-chars=none`, nothing from the `unpaired` default, and nothing from
 * `-Wall -Wextra`.
 *
 * This is a GCC-only option. Clang 22 rejects the spelling outright
 * ("unknown warning option"), and has no equivalent under any other name: neither
 * the balanced text below nor an unbalanced variant draws anything from clang at
 * `-Weverything`, nor from its `-Wunicode`, `-Wunicode-homoglyph`,
 * `-Wunicode-whitespace` or `-Wunicode-zero-width`. The Trojan Source lints Clang
 * does ship live in clang-tidy, not the compiler. On clang the two control arms
 * are therefore identical and the check must be gated off rather than reported.
 *
 * The observable holds at -O0: this is a lexer diagnostic and needs no
 * optimisation. Under `-Werror` the same sentence is emitted as an error and the
 * build stops, so severity is recorded but presence is read from the text.
 *
 * The unused variable and the in-source pragma below are a canary for the
 * diagnostic channel itself. `-fdiagnostics-format=sarif-file` sends stderr to a
 * file and `-w` suppresses warnings wholesale - both were confirmed to silence
 * this probe's stderr completely, canary included - and neither is countermanded
 * by the control flags, so a silent stderr could otherwise be read as "the flag is
 * off" when in truth nothing was listening. If neither the primary wording nor the
 * canary appears, the detector reports indeterminate rather than absent.
 * `-Wunused-variable` is chosen because it is not escalated by `-Werror`, so the
 * canary can never break a build, and because GCC tags every diagnostic with its
 * controlling option - [-Wunused-variable] here, [-Wbidi-chars=] for the
 * observable - so the two can never be confused for one another.
 */

#pragma GCC diagnostic warning "-Wunused-variable"

/* The observable, in a comment: ‮desrever si txet siht‬ and here it is not. */

static const char *chard_bidi_literal(void)
{
    /* The observable again, in a string literal. */
    static const char *s = "chard_bidi_‮desrever‬_marker";
    return s;
}

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    return chard_bidi_literal()[0] == 0;
}

