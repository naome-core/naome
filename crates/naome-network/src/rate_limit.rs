use std::time::Duration;

use tokio::time::Instant;

pub(super) struct TokenBucket {
    capacity: u32,
    refill_interval: Duration,
    tokens: u32,
    last_refill: Instant,
}

impl TokenBucket {
    pub(super) fn new(capacity: u32, refill_interval: Duration, now: Instant) -> Self {
        debug_assert!(capacity > 0);
        debug_assert!(!refill_interval.is_zero());
        Self {
            capacity,
            refill_interval,
            tokens: capacity,
            last_refill: now,
        }
    }

    pub(super) fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill);
        let intervals = elapsed.as_nanos() / self.refill_interval.as_nanos();
        if intervals != 0 {
            let elapsed_intervals = u32::try_from(intervals).unwrap_or(u32::MAX);
            self.tokens = self
                .tokens
                .saturating_add(elapsed_intervals)
                .min(self.capacity);
            if self.tokens < self.capacity {
                self.last_refill += self.refill_interval * elapsed_intervals;
            }
        }
        if self.tokens == 0 {
            return false;
        }
        if self.tokens == self.capacity {
            self.last_refill = now;
        }
        self.tokens -= 1;
        true
    }

    #[cfg(test)]
    pub(super) const fn tokens(&self) -> u32 {
        self.tokens
    }

    #[cfg(test)]
    pub(super) fn exhaust(&mut self, now: Instant) {
        self.tokens = 0;
        self.last_refill = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPACITY: u32 = 8;
    const REFILL_INTERVAL: Duration = Duration::from_secs(1);

    #[test]
    fn burst_refill_fractional_carry_and_cap_are_exact() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(CAPACITY, REFILL_INTERVAL, start);
        for _ in 0..CAPACITY {
            assert!(bucket.try_take(start));
        }
        assert!(!bucket.try_take(start));
        assert!(!bucket.try_take(start + REFILL_INTERVAL / 2));
        assert!(bucket.try_take(start + REFILL_INTERVAL));
        assert!(!bucket.try_take(start + REFILL_INTERVAL));

        let later = start + Duration::from_secs(10_000);
        for _ in 0..CAPACITY {
            assert!(bucket.try_take(later));
        }
        assert!(!bucket.try_take(later));

        let mut fractional = TokenBucket::new(CAPACITY, REFILL_INTERVAL, start);
        for _ in 0..CAPACITY {
            assert!(fractional.try_take(start));
        }
        assert!(fractional.try_take(start + REFILL_INTERVAL * 3 / 2));
        assert!(!fractional.try_take(start + REFILL_INTERVAL * 2 - Duration::from_nanos(1)));
        assert!(fractional.try_take(start + REFILL_INTERVAL * 2));
    }

    #[test]
    fn first_take_from_a_full_bucket_starts_the_refill_clock() {
        let start = Instant::now();
        let first_take = start + REFILL_INTERVAL - Duration::from_nanos(1);
        let mut bucket = TokenBucket::new(CAPACITY, REFILL_INTERVAL, start);
        for _ in 0..CAPACITY {
            assert!(bucket.try_take(first_take));
        }
        assert!(!bucket.try_take(first_take));
        assert!(!bucket.try_take(start + REFILL_INTERVAL));
        assert!(bucket.try_take(first_take + REFILL_INTERVAL));
    }
}
