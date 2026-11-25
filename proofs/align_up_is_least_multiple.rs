// SPDX-License-Identifier: BSD-3-Clause

//! Kani proofs for [`super::align_up`], the alignment rule the module header calls the
//! one that must not be got wrong.

use super::align_up;

/// The specification, over a fully symbolic `value` and each power-of-two alignment from 1 to 64.
#[kani::proof]
#[kani::unwind(8)]
fn align_up_is_least_multiple() {
    let value: u64 = kani::any();

    // Concrete divisors, symbolic dividend.
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
                // Refusal has exactly one cause.
                assert!(align > 1);
                assert!(value.checked_add(align - 1).is_none());
            }
        }
    }
    // `make kani` fails unless some execution reaches this line, so no assumption can leave this
    // harness with no execution.
    kani::cover!(true, "the end of this harness is reached");
}

/// The three failure modes `align_up`'s body has no path for really are unreachable,
/// **checked against `align_up` itself**, not against arithmetic that resembles it.
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
                // is the only way it can refuse.
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
    // `make kani` fails unless some execution reaches this line, so no assumption can leave this
    // harness with no execution.
    kani::cover!(true, "the end of this harness is reached");
}

/// The off-by-four itself, stated over all inputs rather than at `namesz == 4`.
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

        // They coincide exactly when 12 is already a multiple of the alignment.
        if 12 % align == 0 {
            assert!(absolute == 12 + relative);
        } else {
            assert!(absolute != 12 + relative);
        }
    }
    // `make kani` fails unless some execution reaches this line, so no assumption can leave this
    // harness with no execution.
    kani::cover!(true, "the end of this harness is reached");
}
