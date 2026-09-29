//! The one deterministic RNG the randomized tests share (no `rand`
//! dev-dependency). Every generator seeds it the way its inputs were first
//! drawn, so the golden snapshots in `tests/equivalence/` keep
//! replaying the exact same cases.

/// xorshift64*.
pub(crate) struct Rng(pub(crate) u64);

impl Rng {
    /// Seed from a small counter, mixing it so seeds 0, 1, 2… diverge at once.
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub(crate) fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub(crate) fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    pub(crate) fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    pub(crate) fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}
