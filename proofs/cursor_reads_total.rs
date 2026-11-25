// SPDX-License-Identifier: BSD-3-Clause

//! Kani proofs that the ELF reader's bounded reads are **total**: for every offset,
//! every length, and every buffer, they return rather than panic.

use super::{Cursor, ReadError};

/// Every `(off, len)` over a fixed buffer either yields the `len` bytes of the buffer at `off`
/// or an error. Never a panic, never a short read, never a window from elsewhere.
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
        // returns exactly the width asked for.
        Ok(got) => {
            assert!(u64::try_from(got.len()) == Ok(len));
            assert!(got.len() <= data.len());
            // And it is the window at `off`, the same address and length, compared as pointers
            // so no byte loop is unwound: every value clause in this file decodes the bytes
            // `slice` returns, so a slice of the right width from another offset would pass
            // them all.
            let at = usize::try_from(off)
                .ok()
                .and_then(|start| start.checked_add(got.len()).map(|end| (start, end)));
            let window = at.and_then(|(start, end)| data.get(start..end));
            assert!(window.is_some_and(|w| core::ptr::eq(w, got)));
        }
        Err(_) => {}
    }
    // `make kani` fails unless some execution reaches this line, so no assumption can leave this
    // harness with no execution.
    kani::cover!(true, "the end of this harness is reached");
}

/// The fixed-width readers are total, servable exactly when `slice` is, **and decode the
/// bytes they read** under the endianness they were given.
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
    // `make kani` fails unless some execution reaches this line, so no assumption can leave this
    // harness with no execution.
    kani::cover!(true, "the end of this harness is reached");
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

    // Tied to the bytes, not only to its siblings.
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
    // `make kani` fails unless some execution reaches this line, so no assumption can leave this
    // harness with no execution.
    kani::cover!(true, "the end of this harness is reached");
}

/// A refusal is a function of `(off, len, data.len())`: the same inputs always give the
/// same classification, and each variant states the condition that produced it.
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

    // Which refusals a 64-bit host can actually produce.
    kani::cover!(cur.slice(off, len).is_ok(), "a read is servable");
    kani::cover!(
        matches!(cur.slice(off, len), Err(ReadError::EndOverflows { .. })),
        "start + count overflows usize"
    );
    kani::cover!(
        matches!(cur.slice(off, len), Err(ReadError::OutOfBounds { .. })),
        "the window lies outside the object"
    );
    // `make kani` fails unless some execution reaches this line, so no assumption can leave this
    // harness with no execution.
    kani::cover!(true, "the end of this harness is reached");
}

/// `cstr_at`, `Cursor`'s sixth method, reads a name from inside its table: no NUL in it, at
/// `base + off`, never past the table's declared end, and cut only by a NUL, the table's end
/// or the buffer's end.
#[kani::proof]
#[kani::unwind(18)]
fn cstr_at_reads_inside_its_table() {
    let data: [u8; 16] = kani::any();
    let cur = Cursor {
        data: &data,
        little: kani::any(),
    };
    let base: u64 = kani::any();
    let off: u32 = kani::any();
    let table_len: u64 = kani::any();

    let got = cur.cstr_at(base, off, table_len);
    assert!(got.is_ok());
    let name = got.unwrap_or(&[]);
    assert!(name.iter().all(|&c| c != 0));

    let room = table_len.checked_sub(u64::from(off));
    let start = usize::try_from(base.saturating_add(u64::from(off))).ok();
    let stop = start.and_then(|s| s.checked_add(name.len()));
    if !name.is_empty() {
        let window = start.zip(stop).and_then(|(s, e)| data.get(s..e));
        assert!(window.is_some_and(|w| core::ptr::eq(w, name)));
        assert!(room.is_some_and(|room| u64::try_from(name.len()).is_ok_and(|l| l <= room)));
    }
    if let (Some(room), Some(s), Some(e)) = (room, start, stop) {
        if room > 0 && s < data.len() {
            let at_nul = data.get(e) == Some(&0);
            let at_table_end = u64::try_from(name.len()) == Ok(room);
            assert!(at_nul || at_table_end || e == data.len());
        }
    }
    kani::cover!(
        !name.is_empty() && stop.is_some_and(|e| data.get(e).is_some_and(|&c| c != 0)),
        "a name cut at its table's declared end, before a NUL, is read"
    );
    // `make kani` fails unless some execution reaches this line, so no assumption can leave this
    // harness with no execution.
    kani::cover!(true, "the end of this harness is reached");
}
