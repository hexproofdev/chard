// SPDX-License-Identifier: BSD-3-Clause

//! Kani proofs that the note walks take every offset from bytes inside their table, at the
//! padding rule the reader's module header warns about, and always move forward.

use super::{NoteSpan, PropertySpan, note_alignment, note_span, property_span};

/// A note the walk takes lies whole in its table and the file. Its descriptor starts at the
/// least multiple of the alignment, measured from the note's own start, that leaves room for
/// the 12-byte header and the name. The next note starts at or after the descriptor's end, so
/// two notes never overlap and the walk moves forward on every note it takes. At the two
/// alignments ELF uses, 4 and 8, the walk takes every note that fits.
#[kani::proof]
#[kani::unwind(13)]
fn a_note_lies_whole_in_its_table_and_the_walk_moves_on() {
    let pos: u64 = kani::any();
    let namesz: u32 = kani::any();
    let descsz: u32 = kani::any();
    let end: u64 = kani::any();
    let file_end: u64 = kani::any();
    // Only the notes `parse_notes` reaches: it walks while a 12-byte header fits before `end`.
    kani::assume(pos.saturating_add(12) <= end);
    kani::assume(file_end < 1 << 63);

    for declared in [
        0u64,
        2,
        4,
        5,
        8,
        12,
        16,
        64,
        4096,
        1 << 32,
        1 << 63,
        u64::MAX,
    ] {
        let align = note_alignment(declared);
        if let Ok(NoteSpan { desc_off, next }) =
            note_span(pos, namesz, descsz, align, end, file_end)
        {
            let head = 12 + u64::from(namesz);
            let rel = desc_off - pos;
            assert!(rel % align == 0 && rel >= head && rel - head < align);
            let desc_end = desc_off + u64::from(descsz);
            assert!(desc_end <= end && desc_end <= file_end);
            assert!(next.is_some_and(|next| next >= desc_end && next > pos));
        }
    }
    // And it takes every note that fits, at the two alignments ELF uses: where the descriptor
    // would lie, computed apart from `align_up`, is `None` exactly where `note_span` refuses.
    for align in [4u64, 8] {
        let fits = (12 + u64::from(namesz))
            .div_ceil(align)
            .checked_mul(align)
            .and_then(|rel| pos.checked_add(rel))
            .and_then(|off| off.checked_add(u64::from(descsz)).map(|e| (off, e)))
            .filter(|&(_, e)| e <= end && e <= file_end);
        let got = note_span(pos, namesz, descsz, align, end, file_end);
        assert!(got.is_ok() == fits.is_some());
        assert!(got.is_err() || got.map(|span| span.desc_off).ok() == fits.map(|(off, _)| off));
    }
    kani::cover!(
        note_span(pos, 4, descsz, 8, end, file_end).is_ok(),
        "a GNU-named note at the ELF64 alignment is taken"
    );
    // `make kani` fails unless some execution reaches this line, so no assumption can leave this
    // harness with no execution.
    kani::cover!(true, "the end of this harness is reached");
}

/// The walk takes a property exactly when it lies whole in its descriptor: its data follows the
/// 8-byte header, padded to the least multiple of the alignment, and the next property starts
/// after it and no later than the descriptor's end, so the walk moves forward on every property
/// it takes.
#[kani::proof]
#[kani::unwind(3)]
fn a_property_lies_whole_in_its_descriptor_and_the_walk_moves_on() {
    let pos: u64 = kani::any();
    let datasz: u32 = kani::any();
    let end: u64 = kani::any();
    // Only the properties `gnu_properties` reaches: it walks while 8 bytes are left before the
    // descriptor's end.
    kani::assume(end.saturating_sub(pos) >= 8);

    for align in [4u64, 8] {
        let got = property_span(pos, datasz, align, end);
        // Where the next property would start, computed apart from `align_up`: `None` where it
        // passes the descriptor's end.
        let fits = (pos + 8)
            .checked_add(u64::from(datasz).div_ceil(align) * align)
            .filter(|&next| next <= end);
        assert!(got.is_ok() == fits.is_some());
        if let (Ok(PropertySpan { data_off, next }), Some(want)) = (got, fits) {
            assert!(data_off == pos + 8 && next == want);
            let pad = next - data_off;
            assert!(pad % align == 0 && pad >= u64::from(datasz));
            assert!(pad - u64::from(datasz) < align);
            assert!(next > pos);
        }
    }
    // `make kani` fails unless some execution reaches this line, so no assumption can leave this
    // harness with no execution.
    kani::cover!(true, "the end of this harness is reached");
}
