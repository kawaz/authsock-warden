//! Memory protection utilities
//!
//! Provides mlock/munlock wrappers for pinning secret data in memory
//! (preventing swap to disk).

use tracing::warn;

/// Lock a memory region to prevent it from being swapped to disk.
///
/// Returns true if successful, false otherwise.
/// Failure is not fatal — it's one layer of defense in depth.
#[cfg(unix)]
pub fn mlock(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    if ret != 0 {
        warn!(
            len = len,
            "mlock failed (errno: {}). Secret data may be swapped to disk.",
            std::io::Error::last_os_error()
        );
        false
    } else {
        true
    }
}

/// Unlock a previously locked memory region.
#[cfg(unix)]
pub fn munlock(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let ret = unsafe { libc::munlock(ptr as *const libc::c_void, len) };
    ret == 0
}

#[cfg(not(unix))]
pub fn mlock(_ptr: *const u8, _len: usize) -> bool {
    warn!("mlock not supported on this platform");
    false
}

#[cfg(not(unix))]
pub fn munlock(_ptr: *const u8, _len: usize) -> bool {
    false
}

/// Get the system's memory page size.
#[cfg(unix)]
pub fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[cfg(not(unix))]
pub fn page_size() -> usize {
    4096 // Common default
}

/// Get the current mlock limit (RLIMIT_MEMLOCK).
#[cfg(unix)]
pub fn mlock_limit() -> Option<u64> {
    let mut rlimit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlimit) };
    if ret == 0 {
        Some(rlimit.rlim_cur)
    } else {
        None
    }
}

#[cfg(not(unix))]
pub fn mlock_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlock_zero_length() {
        assert!(mlock(std::ptr::null(), 0));
    }

    #[test]
    fn test_munlock_zero_length() {
        assert!(munlock(std::ptr::null(), 0));
    }

    #[cfg(unix)]
    #[test]
    fn test_mlock_small_allocation() {
        let data = vec![0u8; 64];
        let result = mlock(data.as_ptr(), data.len());
        // mlock may fail if RLIMIT_MEMLOCK is too low, that's OK
        if result {
            assert!(munlock(data.as_ptr(), data.len()));
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_page_size() {
        let ps = page_size();
        assert!(ps > 0);
        // Page size is always a power of 2
        assert!(ps.is_power_of_two());
    }

    #[cfg(unix)]
    #[test]
    fn test_mlock_limit() {
        let limit = mlock_limit();
        assert!(limit.is_some());
    }
}
