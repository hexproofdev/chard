// SPDX-License-Identifier: BSD-3-Clause

//! The seed, the case count and the generator every generated-input test draws from.
//!
//! A generated test is a property over a space, and it is worth only what a failure in it
//! can be acted on for: the seed that produced the failing input is printed with every
//! run and with every failure, and `CHARD_TEST_SEED` replays it. The default seed is
//! fixed, so the gate is deterministic; a run under another seed explores inputs the gate
//! never drew, and one that fails is a reproduction, not a flake. `CHARD_TEST_CASES`
//! raises or lowers how many inputs each test draws, for a longer run by hand.
//!
//! Both variables are read here and nowhere in `src/`: chard itself reads no
//! configuration from the environment beyond `PATH`, and a test's knob is the test's.
//!
//! The generator is splitmix64, written out rather than taken from a crate: the four
//! direct dependencies are a hard constraint, and a test needs a sequence it can replay,
//! not a statistically strong one.

// Each test binary that declares this module uses a different subset of it.
#![allow(dead_code)]

use std::io::Write as _;

/// The seed a run uses when `CHARD_TEST_SEED` is unset.
pub const DEFAULT_SEED: u64 = 0x00c4_a4d0_2026_0928;

/// The variable that replays a seed: decimal, or hexadecimal with `0x`.
pub const SEED_VAR: &str = "CHARD_TEST_SEED";

/// The variable that sets how many inputs each generated test draws.
pub const CASES_VAR: &str = "CHARD_TEST_CASES";

/// The seed for this run, and whether it came from the environment.
///
/// # Panics
///
/// On a `CHARD_TEST_SEED` that does not parse: a replay that silently fell back to the
/// default would report the default's result as the replay's.
#[must_use]
pub fn seed() -> (u64, bool) {
    let Some(raw) = std::env::var_os(SEED_VAR) else {
        return (DEFAULT_SEED, false);
    };
    let text = raw.to_string_lossy();
    let text = text.trim();
    let parsed = match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse::<u64>(),
    };
    let value = parsed.unwrap_or_else(|e| panic!("{SEED_VAR}={text:?} is not a u64: {e}"));
    (value, true)
}

/// How many inputs to draw: `CHARD_TEST_CASES` when set, `default` otherwise.
///
/// # Panics
///
/// On a value that does not parse, or on zero, since a property checked over no input is
/// the loop over nothing this project refuses.
#[must_use]
pub fn cases(default: usize) -> usize {
    let Some(raw) = std::env::var_os(CASES_VAR) else {
        return default;
    };
    let text = raw.to_string_lossy();
    let n: usize = text
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("{CASES_VAR}={text:?} is not a count: {e}"));
    assert!(n > 0, "{CASES_VAR}=0 would check the property over nothing");
    n
}

/// What a failure message says so the failing input can be drawn again.
#[must_use]
pub fn replay(seed: u64, case: usize) -> String {
    format!("seed {seed:#x}, case {case}; replay with {SEED_VAR}={seed:#x}")
}

/// Announce the seed on the real stderr, which libtest does not capture, so a passing
/// run records what it drew as plainly as a failing one.
pub fn announce(test: &str, seed: u64, from_env: bool, cases: usize, coverage: &str) {
    let origin = if from_env { SEED_VAR } else { "default" };
    let line = format!("\nchard: {test}: seed {seed:#x} ({origin}), {cases} cases; {coverage}\n");
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(line.as_bytes());
    let _ = stderr.flush();
}

/// splitmix64.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    /// The generator for one case: the run's seed and the case index mixed, so each
    /// case is drawn independently of how many values the cases before it consumed.
    #[must_use]
    pub fn for_case(seed: u64, case: usize) -> Self {
        let mut r = Self(seed ^ (u64::try_from(case).expect("a case index fits u64") << 32));
        r.next();
        r
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value in `0..n`. The modulo bias is immaterial at the sizes drawn here.
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "a draw from an empty range");
        self.next() % n
    }

    /// An index into a slice of `len`.
    pub fn index(&mut self, len: usize) -> usize {
        usize::try_from(self.below(u64::try_from(len).expect("a length fits u64")))
            .expect("an index below a usize length fits usize")
    }

    /// `true` with probability `num / den`.
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.index(items.len())]
    }
}
