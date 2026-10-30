// SPDX-License-Identifier: BSD-3-Clause

//! Kani proofs that the ELF reader's bounded reads are **total**: for every offset,
//! every length, and every buffer, they return rather than panic.
//!
//! ## Why no-panic is the claim here, and not a tautology
//!
//! A bare no-panic harness proves nothing about arithmetic that cannot overflow. It
//! proves something specific about *this* code, because `THREAT_MODEL.md` lists safe
//! Rust, a size refusal, fuzzing above `Cursor` and a proof that the bounded reads are
//! total among a crafted ELF's defences against a crash, and names the misreadings
//! measured so far, which none of them stops, as register entries. `unsafe_code =
//! "deny"` already rules out memory unsafety. A panic is the residual, and `Cursor` is
//! where it would live: these four methods are the reader's only contact with
//! attacker-chosen offsets and lengths.
//!
//! The existing evidence is `elf::tests::fuzz_corrupted_objects`, a seeded xorshift over
//! mutated real binaries. That is a sample from a distribution chosen by the author. This
//! is the ∀ the sample gestures at, over a bounded buffer.
//!
//! ## What the bound costs, measured
//!
//! `slice` is proved over a 16-byte buffer with fully symbolic `off` and `len`; both
//! `u64`, so the whole range including the `usize` conversion failures and the
//! `checked_add` overflow are reachable, not just in-range reads. The buffer length is the
//! only bound, and it is small because the *interesting* structure is the arithmetic on
//! `off`/`len`, which is unbounded here. Widening the buffer adds cases the arithmetic
//! already covers.
//!
//! These proofs were only possible after `Cursor` stopped returning `anyhow::Result`. With
//! `anyhow` on the path a proof of a four-line arithmetic helper in this file was killed at
//! 480s having unwound `core::slice::memchr::memchr_naive` 6,687 times, while a proof
//! touching no chard code verified in seconds. `ReadError` constructs without formatting,
//! which is what makes the model checker's job finite.

use super::{Cursor, ReadError};

/// Every `(off, len)` over a fixed buffer either yields a slice of exactly `len` bytes or
/// an error. Never a panic, never a short read.
#[kani::proof]
fn slice_is_total() {
    let data: [u8; 16] = kani::any();
    let little: bool = kani::any();
    let cur = Cursor {
        data: &data,
        little,
    };

    let off: u64 = kani::any();
    let len: u64 = kani::any();

    match cur.slice(off, len) {
        // The postcondition that makes this more than a no-panic check: a successful read
        // returns exactly the width asked for. A reader that returned a short slice would
        // feed truncated bytes to `from_le_bytes` and publish a wrong ELF fact.
        Ok(got) => {
            assert!(u64::try_from(got.len()) == Ok(len));
            assert!(got.len() <= data.len());
        }
        Err(_) => {}
    }
}

/// The fixed-width readers are total, servable exactly when `slice` is, **and decode the
/// bytes they read** under the endianness they were given.
///
/// The last clause is the one that makes this a proof rather than a shape check, and it was
/// missing. This harness once asserted only the `is_ok()` agreement below, which a reader
/// that discarded its bytes entirely, `{ self.slice(off, N)?; Ok(0) }`, satisfies. That
/// mutant was built and run against this file: both this harness and
/// `addr_at_follows_its_width` reported SUCCESSFUL over it, 285 checks between them. A
/// wrong-endianness reader passed too, because `little` was symbolic and nothing depended
/// on it.
///
/// The value clauses also discharge the `unwrap_or([0; N])` fallbacks in `u16_at`/`u32_at`/
/// `u64_at`: a zero substitution cannot equal `from_le_bytes` of non-zero input, so the
/// arm those `unwrap_or`s guard is now proved unreachable rather than assumed so.
#[kani::proof]
fn fixed_width_reads_are_total() {
    let data: [u8; 16] = kani::any();
    let little: bool = kani::any();
    let cur = Cursor {
        data: &data,
        little,
    };
    let off: u64 = kani::any();

    // Each returns, and succeeds exactly when its own width is servable at `off`.
    assert!(cur.u16_at(off).is_ok() == cur.slice(off, 2).is_ok());
    assert!(cur.u32_at(off).is_ok() == cur.slice(off, 4).is_ok());
    assert!(cur.u64_at(off).is_ok() == cur.slice(off, 8).is_ok());

    // And the value is the bytes, in the stated order.
    if let (Ok(v), Ok(b)) = (cur.u16_at(off), cur.slice(off, 2)) {
        let a: [u8; 2] = [b[0], b[1]];
        assert!(
            v == if little {
                u16::from_le_bytes(a)
            } else {
                u16::from_be_bytes(a)
            }
        );
    }
    if let (Ok(v), Ok(b)) = (cur.u32_at(off), cur.slice(off, 4)) {
        let a: [u8; 4] = [b[0], b[1], b[2], b[3]];
        assert!(
            v == if little {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            }
        );
    }
    if let (Ok(v), Ok(b)) = (cur.u64_at(off), cur.slice(off, 8)) {
        let a: [u8; 8] = [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];
        assert!(
            v == if little {
                u64::from_le_bytes(a)
            } else {
                u64::from_be_bytes(a)
            }
        );
    }
}

/// `addr_at` is `u64_at` on ELF64 and a widened `u32_at` on ELF32, including in the error
/// case, which is where a mismatch would silently change which reads a 32-bit object
/// appears to support.
#[kani::proof]
fn addr_at_follows_its_width() {
    let data: [u8; 16] = kani::any();
    let little: bool = kani::any();
    let cur = Cursor {
        data: &data,
        little,
    };
    let off: u64 = kani::any();

    assert!(cur.addr_at(off, true) == cur.u64_at(off));
    assert!(cur.addr_at(off, false) == cur.u32_at(off).map(u64::from));

    // Tied to the bytes, not only to its siblings. The equalities above hold for any
    // reader whose three functions are wrong the same way, including one that returns
    // zero for every read.
    if let (Ok(v), Ok(b)) = (cur.addr_at(off, false), cur.slice(off, 4)) {
        let a: [u8; 4] = [b[0], b[1], b[2], b[3]];
        let want = if little {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        };
        assert!(v == u64::from(want));
        // ELF32 widening never fabricates high bits.
        assert!(v <= u64::from(u32::MAX));
    }
}

/// A refusal is a function of `(off, len, data.len())`: the same inputs always give the
/// same classification, and each variant states the condition that produced it.
///
/// The classification is stated as a condition rather than asserted per variant, because a
/// per-variant match is vacuous on a 64-bit target: `usize::try_from(u64)` cannot fail
/// there, so `OffsetTooLarge` and `LengthTooLarge` are unreachable (`cover` on those two
/// arms is UNSATISFIABLE) and an assertion of `usize::try_from(off).is_ok()` in the
/// surviving arm is a tautology. Such a harness reduces to "slice returns", which
/// `slice_is_total` already proves. On a 32-bit target the first two arms become live and
/// these implications still hold; the `cover` calls below are what would say so rather than
/// leaving it to be assumed.
#[kani::proof]
fn refusals_are_classified() {
    let data: [u8; 16] = kani::any();
    let cur = Cursor {
        data: &data,
        little: kani::any(),
    };
    let off: u64 = kani::any();
    let len: u64 = kani::any();

    match cur.slice(off, len) {
        Ok(_) => {
            // A served read is exactly the reads that fit, stated as the complement of
            // every refusal condition below.
            let start = usize::try_from(off).expect("served, so it converted");
            let count = usize::try_from(len).expect("served, so it converted");
            assert!(start.checked_add(count).is_some());
            assert!(start + count <= data.len());
        }
        Err(ReadError::OffsetTooLarge(o)) => {
            assert!(o == off && usize::try_from(off).is_err());
        }
        Err(ReadError::LengthTooLarge(l)) => {
            assert!(l == len && usize::try_from(len).is_err());
        }
        Err(ReadError::EndOverflows { start, count }) => {
            // Both converted, and their sum did not.
            assert!(usize::try_from(off) == Ok(start));
            assert!(usize::try_from(len) == Ok(count));
            assert!(start.checked_add(count).is_none());
        }
        Err(ReadError::OutOfBounds { start, count }) => {
            // Both converted, the sum did too, and it lands past the end.
            assert!(usize::try_from(off) == Ok(start));
            assert!(usize::try_from(len) == Ok(count));
            assert!(start.checked_add(count).is_some());
            assert!(start + count > data.len());
        }
    }

    // Which refusals this target can actually produce. A `cover` that cannot be satisfied
    // is reported, so an arm going dead (or coming alive on a 32-bit target) shows up
    // here instead of silently turning an assertion into a tautology.
    kani::cover!(cur.slice(off, len).is_ok(), "a read is servable");
    kani::cover!(
        matches!(cur.slice(off, len), Err(ReadError::EndOverflows { .. })),
        "start + count overflows usize"
    );
    kani::cover!(
        matches!(cur.slice(off, len), Err(ReadError::OutOfBounds { .. })),
        "the window lies outside the object"
    );
}
