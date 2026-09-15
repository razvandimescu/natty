use std::time::Instant;

use natty::wire::MAX_PAYLOAD;

/// Bytes-per-second budget with a one-second burst, never smaller than one
/// maximal frame. A rate of zero means uncapped.
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(bytes_per_sec: u32) -> Self {
        let rate = f64::from(bytes_per_sec);
        let burst = rate.max(MAX_PAYLOAD as f64);
        Self {
            rate,
            burst,
            tokens: burst,
            last: Instant::now(),
        }
    }

    pub fn take(&mut self, bytes: usize) -> bool {
        if self.rate == 0.0 {
            return true;
        }
        let now = Instant::now();
        let refill = now.duration_since(self.last).as_secs_f64() * self.rate;
        self.tokens = (self.tokens + refill).min(self.burst);
        self.last = now;
        if self.tokens < bytes as f64 {
            return false;
        }
        self.tokens -= bytes as f64;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_beyond_burst() {
        let mut bucket = TokenBucket::new(1000);
        assert!(bucket.take(MAX_PAYLOAD));
        assert!(!bucket.take(MAX_PAYLOAD));
    }

    #[test]
    fn zero_rate_is_uncapped() {
        let mut bucket = TokenBucket::new(0);
        assert!((0..100).all(|_| bucket.take(MAX_PAYLOAD)));
    }
}
