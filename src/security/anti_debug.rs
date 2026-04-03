//! Anti-debugging and injection detection
//!
//! Defense-in-depth protections applied at process startup.

use tracing::{info, warn};

/// Apply all anti-debug protections.
///
/// Called at process startup before any secrets are loaded.
/// Failures are logged as warnings but do not prevent startup
/// (defense in depth — each layer is optional).
pub fn apply_protections() {
    check_dyld_injection();
    deny_ptrace();
    disable_core_dumps();
}

/// Check for DYLD_INSERT_LIBRARIES injection (macOS).
///
/// If this environment variable is set, a library has been injected
/// into the process, which could intercept secret key operations.
fn check_dyld_injection() {
    if let Ok(val) = std::env::var("DYLD_INSERT_LIBRARIES") {
        warn!(
            dyld_insert = %val,
            "DYLD_INSERT_LIBRARIES is set — potential library injection detected. \
             Consider running with Hardened Runtime or SIP enabled."
        );
    }
    // Also check DYLD_LIBRARY_PATH which can redirect library loading
    if let Ok(val) = std::env::var("DYLD_LIBRARY_PATH") {
        warn!(
            dyld_path = %val,
            "DYLD_LIBRARY_PATH is set — library search path override detected."
        );
    }
}

/// Deny ptrace attachment (prevents debuggers from reading memory).
#[cfg(target_os = "macos")]
fn deny_ptrace() {
    // PT_DENY_ATTACH = 31
    let ret = unsafe { libc::ptrace(31, 0, std::ptr::null_mut::<libc::c_char>(), 0) };
    if ret == 0 {
        info!("ptrace denied — debugger attachment blocked");
    } else {
        warn!(
            "Failed to deny ptrace (errno: {})",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(target_os = "linux")]
fn deny_ptrace() {
    // PR_SET_DUMPABLE = 4, setting to 0 prevents ptrace
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if ret == 0 {
        info!("PR_SET_DUMPABLE set to 0 — ptrace/coredump restricted");
    } else {
        warn!(
            "Failed to set PR_SET_DUMPABLE (errno: {})",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn deny_ptrace() {
    warn!("ptrace denial not supported on this platform");
}

/// Disable core dumps to prevent secret leakage.
#[cfg(unix)]
fn disable_core_dumps() {
    let rlimit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlimit) };
    if ret == 0 {
        info!("Core dumps disabled");
    } else {
        warn!(
            "Failed to disable core dumps (errno: {})",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(unix))]
fn disable_core_dumps() {
    warn!("Core dump control not supported on this platform");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_protections_does_not_panic() {
        // Just verify it doesn't panic
        apply_protections();
    }

    #[test]
    fn test_dyld_detection() {
        // Setting DYLD vars in test doesn't actually inject anything
        // but we can verify the check runs without panicking
        check_dyld_injection();
    }
}
