// SPDX-License-Identifier: BSD-3-Clause

//! The runtime and compiler-diag detectors, and the helpers they share.
//!
//! `probe.rs` holds the corpus, the types a check is declared with, and the macro and
//! elf-static detectors. The detectors that read a run (`runtime`) or a build's
//! diagnostics (`diag`) live here with what both read (`common`), so that the code turning
//! that evidence into a [`crate::probe::Detection`] sits in files holding nothing else.
//!
//! Two properties of the layout are held by `tests/decode_layout.rs`. Each module's unit
//! tests sit in a sibling `*_tests.rs` file, so a module file carries no test code. No file
//! here opens a block comment, so stripping line comments strips every comment. Together
//! they make the source of this directory a stable input to a fingerprint over detector
//! code: a test edit or a comment edit leaves the stripped text unchanged.

pub mod common;
pub mod diag;
pub mod runtime;
