//! Per-key timer management

use std::time::{Duration, Instant};

/// Timer state for a managed key
#[derive(Debug, Clone)]
pub struct KeyTimer {
    /// When the key was loaded into memory
    loaded_at: Instant,
    /// When the key was last used for signing
    last_used: Instant,
    /// Duration before the key is locked
    timeout: Option<Duration>,
    /// Duration before the key is completely forgotten (from loaded_at)
    forget_after: Option<Duration>,
}

impl KeyTimer {
    pub fn new(timeout: Option<Duration>, forget_after: Option<Duration>) -> Self {
        let now = Instant::now();
        Self {
            loaded_at: now,
            last_used: now,
            timeout,
            forget_after,
        }
    }

    /// Update last_used timestamp (on signing)
    pub fn touch(&mut self) {
        self.last_used = Instant::now();
    }

    /// Reset all timers (on refresh)
    pub fn refresh(&mut self) {
        let now = Instant::now();
        self.loaded_at = now;
        self.last_used = now;
    }

    /// Check if the timeout has expired (should transition to Locked)
    pub fn is_timed_out(&self) -> bool {
        self.timeout
            .map(|t| self.last_used.elapsed() >= t)
            .unwrap_or(false)
    }

    /// Check if forget_after has expired (should transition to Forgotten)
    pub fn should_forget(&self) -> bool {
        self.forget_after
            .map(|t| self.loaded_at.elapsed() >= t)
            .unwrap_or(false)
    }

    /// Time remaining until timeout (None if no timeout or already expired)
    pub fn time_until_timeout(&self) -> Option<Duration> {
        self.timeout.and_then(|t| {
            let elapsed = self.last_used.elapsed();
            t.checked_sub(elapsed)
        })
    }

    /// Time remaining until forget (None if no forget_after or already expired)
    pub fn time_until_forget(&self) -> Option<Duration> {
        self.forget_after.and_then(|t| {
            let elapsed = self.loaded_at.elapsed();
            t.checked_sub(elapsed)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_timer_is_not_timed_out() {
        let timer = KeyTimer::new(Some(Duration::from_secs(60)), None);
        assert!(!timer.is_timed_out());
    }

    #[test]
    fn new_timer_should_not_forget() {
        let timer = KeyTimer::new(None, Some(Duration::from_secs(3600)));
        assert!(!timer.should_forget());
    }

    #[test]
    fn no_timeout_never_times_out() {
        let timer = KeyTimer::new(None, None);
        assert!(!timer.is_timed_out());
    }

    #[test]
    fn no_forget_after_never_forgets() {
        let timer = KeyTimer::new(None, None);
        assert!(!timer.should_forget());
    }

    #[test]
    fn zero_timeout_is_immediately_timed_out() {
        let timer = KeyTimer::new(Some(Duration::ZERO), None);
        assert!(timer.is_timed_out());
    }

    #[test]
    fn zero_forget_after_immediately_forgets() {
        let timer = KeyTimer::new(None, Some(Duration::ZERO));
        assert!(timer.should_forget());
    }

    #[test]
    fn touch_updates_last_used() {
        let mut timer = KeyTimer::new(Some(Duration::from_millis(5)), None);
        std::thread::sleep(Duration::from_millis(10));
        // Should be timed out now
        assert!(timer.is_timed_out());
        // Touch resets the timeout
        timer.touch();
        assert!(!timer.is_timed_out());
    }

    #[test]
    fn refresh_resets_all_timers() {
        let mut timer = KeyTimer::new(
            Some(Duration::from_millis(5)),
            Some(Duration::from_millis(5)),
        );
        std::thread::sleep(Duration::from_millis(10));
        assert!(timer.is_timed_out());
        assert!(timer.should_forget());
        timer.refresh();
        assert!(!timer.is_timed_out());
        assert!(!timer.should_forget());
    }

    #[test]
    fn time_until_timeout_some_when_not_expired() {
        let timer = KeyTimer::new(Some(Duration::from_secs(60)), None);
        let remaining = timer.time_until_timeout();
        assert!(remaining.is_some());
        assert!(remaining.unwrap() <= Duration::from_secs(60));
    }

    #[test]
    fn time_until_timeout_none_when_no_timeout() {
        let timer = KeyTimer::new(None, None);
        assert!(timer.time_until_timeout().is_none());
    }

    #[test]
    fn time_until_timeout_zero_or_none_when_expired() {
        let timer = KeyTimer::new(Some(Duration::ZERO), None);
        // With Duration::ZERO timeout, time_until_timeout is either None or Duration::ZERO
        match timer.time_until_timeout() {
            None => {}                                // expired
            Some(d) => assert_eq!(d, Duration::ZERO), // just at the boundary
        }
    }

    #[test]
    fn time_until_forget_some_when_not_expired() {
        let timer = KeyTimer::new(None, Some(Duration::from_secs(3600)));
        let remaining = timer.time_until_forget();
        assert!(remaining.is_some());
        assert!(remaining.unwrap() <= Duration::from_secs(3600));
    }

    #[test]
    fn time_until_forget_none_when_no_forget_after() {
        let timer = KeyTimer::new(None, None);
        assert!(timer.time_until_forget().is_none());
    }

    #[test]
    fn time_until_forget_zero_or_none_when_expired() {
        let timer = KeyTimer::new(None, Some(Duration::ZERO));
        match timer.time_until_forget() {
            None => {} // expired
            Some(d) => assert_eq!(d, Duration::ZERO), // just at the boundary
        }
    }
}
