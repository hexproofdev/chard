// SPDX-License-Identifier: BSD-3-Clause

//! Kani proofs for [`super::align_up`], the alignment rule the module header calls the
//! one that must not be got wrong.
//!
//! ## Why this is not a no-panic harness
//!
//! Nothing here can panic: the body is one `checked_add`, one division by a value the
//! early return proved non-zero, and one multiply. A no-panic proof would be the
//! tautology the other proof warns about. The content is the *postcondition*, because the
//! documented failure of this function is silent and arithmetic rather than a crash,
//! `12 + align_up(namesz, align)` in place of `align_up(12 + namesz, align)` reads four
//! bytes into the middle of the first property and reports a `-fcf-protection=full` binary
//! as having no CET markings.
//!
//! ## What the four examples did not reach
//!
//! Before this, the whole rule rested on `align_up(16,8)`, `align_up(0,8)`,
//! `align_up(17,8)` and `align_up(5,1)`. Every one uses a power-of-two alignment, none is
//! anywhere near the overflow edge, and none states what the function is *for*. The
//! specification is three clauses, and `least` is the one an example cannot express:
//!
//! ```text
//! align_up(v, a) = Some(m)  ⟹  m % a == 0        (a multiple)
//!                           ∧  m >= v            (not below)
//!                           ∧  m - v < a         (the LEAST such)
//! ```
//!
//! Drop the third and `align_up` could return any multiple above `v` and still pass.
//! `12 + align_up(4, 8)` = 20 satisfies the first two clauses relative to nothing in
//! particular; it is the third, applied to the right argument, that pins the rule.
//!
//! ## The slice, and what it cost to find
//!
//! `value` is a full symbolic `u64`, including the overflow boundary. `align` is swept over
//! concrete powers of two, and that asymmetry is the whole reason these converge:
//!
//! | shape | result |
//! |---|---|
//! | symbolic `value`, symbolic `align` (unbounded) | 420s, **no verdict** |
//! | symbolic `value`, symbolic `align <= 64` | 420s, **no verdict** |
//! | symbolic `value`, **concrete** `align` swept | **4.11s, verified** |
//!
//! A symbolic divisor is the SAT-hard shape; a concrete one makes each `%` and `/` a
//! division-by-constant circuit, which the solver handles cheaply because the sweep
//! variable is concrete in each unrolled iteration.
//!
//! The sweep is not a dodge. `align` here is a note's `p_align`, which the ELF
//! specification requires to be a power of two, and 1, 4 and 8 are what occur in practice,
//! so the swept set is the domain rather than a sample of it. `value`, where the
//! interesting arithmetic lives, is not bounded at all.

use super::align_up;

/// The specification, over a fully symbolic `value` and every alignment that occurs.
#[kani::proof]
#[kani::unwind(8)]
fn align_up_is_least_multiple() {
    let value: u64 = kani::any();

    // Concrete divisors, symbolic dividend. A *symbolic* divisor is the SAT-hard shape and
    // does not converge here (measured: 420s, no verdict, both unsliced and with
    // `align <= 64`); a concrete one makes each `%` and `/` a division-by-constant circuit
    // the solver handles cheaply, because the sweep variable is concrete in each
    // unrolled iteration.
    //
    // These are the alignments an ELF note carries, `p_align`/`sh_addralign` are powers of
    // two, and 1, 4 and 8 are what occur in practice. `value` is not bounded at all, so the
    // overflow boundary stays in scope.
    for align in [1u64, 2, 4, 8, 16, 32, 64] {
        match align_up(value, align) {
            Some(m) => {
                if align <= 1 {
                    assert!(m == value);
                } else {
                    assert!(m % align == 0);
                    assert!(m >= value);
                    // The clause no example test states, and the one that makes this a
                    // specification rather than a sanity check.
                    assert!(m - value < align);
                }
            }
            None => {
                // Refusal has exactly one cause. If this arm is reachable for any other
                // reason, the doc comment on `align_up` is wrong.
                assert!(align > 1);
                assert!(value.checked_add(align - 1).is_none());
            }
        }
    }
}

/// The three failure modes `align_up`'s body has no path for really are unreachable,
/// **checked against `align_up` itself**, not against arithmetic that resembles it.
///
/// `align_up` carries one error path. The three others are not discharged by prose ("the
/// early return establishes `align >= 2`"), since prose is what this file exists to replace.
///
/// The harness drives the real function and asserts the internal quantities on its result.
/// One that asserted the three properties over loop constants and a free `bump`, calling no
/// chard function, would verify with `align_up` deleted from the crate, while `src/elf.rs`
/// cites it by name as the justification for an `arithmetic_side_effects` allow: a lint
/// suppression resting on a proof about nothing.
#[kani::proof]
#[kani::unwind(8)]
fn the_deleted_error_paths_were_unreachable() {
    let value: u64 = kani::any();

    for align in [2u64, 4, 8, 16, 32, 64] {
        // The body's own path, driven through the real function.
        let got = align_up(value, align);

        // was: `align.checked_sub(1).context("align underflow")?`
        // Reached only when the early return did not fire, which is what makes it safe.
        assert!(align.checked_sub(1).is_some());

        match got {
            Some(m) => {
                // The function returned, so `value + align - 1` did not overflow, which
                // is the only way it can refuse. The remaining two deleted paths are the
                // division and the multiplication that produced this `m`:
                //   was: `.checked_div(align).context("align is zero")?`
                //   was: `.checked_mul(align).context("align overflow")?`
                let bump = value + (align - 1);
                assert!(bump / align * align == m);
                assert!((bump / align).checked_mul(align).is_some());
                assert!(m <= bump);
            }
            None => {
                // The one surviving refusal, and it is the overflow.
                assert!(value.checked_add(align - 1).is_none());
            }
        }
    }
}

/// The off-by-four itself, stated over all inputs rather than at `namesz == 4`.
///
/// `tests/elf_notes.rs` pins the concrete case against a real `-fcf-protection=full`
/// build, which is the right kind of evidence and covers one point. This is the general
/// statement: padding the absolute offset and padding the name length are different
/// functions, and they agree only when the fixed 12-byte header is itself aligned.
#[kani::proof]
#[kani::unwind(8)]
fn absolute_and_relative_padding_differ_where_it_matters() {
    let namesz: u64 = kani::any();
    kani::assume(namesz <= 1024); // bounds the addition, not the property

    for align in [2u64, 4, 8, 16, 32, 64] {
        let (Some(absolute), Some(relative)) =
            (align_up(12 + namesz, align), align_up(namesz, align))
        else {
            continue;
        };

        // They coincide exactly when 12 is already a multiple of the alignment. At align 4
        // the tempting form looks right; at align 8 (the ELF64 `.note.gnu.property` case)
        // 12 is not a multiple, and that is the off-by-four. Where it is not a multiple the
        // two differ for every name length: the difference of the two roundings is a
        // multiple of the alignment, and 12 is not.
        if 12 % align == 0 {
            assert!(absolute == 12 + relative);
        } else {
            assert!(absolute != 12 + relative);
        }
    }
}
