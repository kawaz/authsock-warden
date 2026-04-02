//! Process identification and tree walking
//!
//! Provides platform-specific process inspection:
//! - macOS: proc_pidpath, sysctl(KERN_PROC) for parent PID, LOCAL_PEERPID for peer PID
//! - Linux: /proc/{pid}/exe, /proc/{pid}/status for parent PID, SO_PEERCRED for peer PID

use std::path::PathBuf;

/// Information about a single process
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name (basename of executable path)
    pub name: String,
    /// Full executable path (if available)
    pub path: Option<PathBuf>,
    /// Parent process ID
    pub ppid: Option<u32>,
}

/// A chain of processes from a starting PID up to init/launchd
#[derive(Debug, Clone)]
pub struct ProcessChain {
    /// Processes in order from the starting PID to the root
    pub chain: Vec<ProcessInfo>,
}

impl ProcessChain {
    /// Build a process chain by walking parent processes from the given PID
    pub fn from_pid(pid: u32) -> Self {
        let mut chain = Vec::new();
        let mut current_pid = Some(pid);
        let mut visited = std::collections::HashSet::new();

        while let Some(pid) = current_pid {
            // Prevent infinite loops
            if !visited.insert(pid) {
                break;
            }
            // PID 0 is the kernel, stop there
            if pid == 0 {
                break;
            }

            match get_process_info(pid) {
                Some(info) => {
                    current_pid = info.ppid;
                    chain.push(info);
                }
                None => break,
            }
        }

        Self { chain }
    }

    /// Check if any process in the chain matches the allowed list.
    ///
    /// Matches against the process name (basename of executable).
    /// An empty allowed list means "allow all".
    pub fn matches_any(&self, allowed_processes: &[String]) -> bool {
        if allowed_processes.is_empty() {
            return true;
        }
        self.chain
            .iter()
            .any(|info| allowed_processes.contains(&info.name))
    }

    /// Check if the chain contains a process with the given name
    pub fn contains_process(&self, name: &str) -> bool {
        self.chain.iter().any(|info| info.name == name)
    }

    /// Get the names of all processes in the chain
    pub fn process_names(&self) -> Vec<&str> {
        self.chain.iter().map(|info| info.name.as_str()).collect()
    }
}

/// Get process info for a given PID (platform-specific)
#[cfg(target_os = "macos")]
pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    get_process_info_macos(pid)
}

#[cfg(target_os = "linux")]
pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    get_process_info_linux(pid)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn get_process_info(_pid: u32) -> Option<ProcessInfo> {
    None
}

/// Get the PID of the peer process connected to a Unix domain socket
#[cfg(target_os = "macos")]
pub fn get_peer_pid(fd: std::os::unix::io::RawFd) -> Option<u32> {
    get_peer_pid_macos(fd)
}

#[cfg(target_os = "linux")]
pub fn get_peer_pid(fd: std::os::unix::io::RawFd) -> Option<u32> {
    get_peer_pid_linux(fd)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn get_peer_pid(_fd: std::os::unix::io::RawFd) -> Option<u32> {
    None
}

// --- macOS implementation ---

#[cfg(target_os = "macos")]
fn get_process_info_macos(pid: u32) -> Option<ProcessInfo> {
    let path = get_process_path_macos(pid);
    let name = path
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(String::from)
        .unwrap_or_else(|| format!("pid:{}", pid));
    let ppid = get_parent_pid_macos(pid);

    Some(ProcessInfo {
        pid,
        name,
        path,
        ppid,
    })
}

#[cfg(target_os = "macos")]
fn get_process_path_macos(pid: u32) -> Option<PathBuf> {
    use std::ffi::CStr;

    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let ret = unsafe {
        libc::proc_pidpath(
            pid as i32,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as u32,
        )
    };
    if ret > 0 {
        let c_str = unsafe { CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
        Some(PathBuf::from(c_str.to_string_lossy().into_owned()))
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn get_parent_pid_macos(pid: u32) -> Option<u32> {
    use std::mem;

    let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
    let ret = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            mem::size_of::<libc::proc_bsdinfo>() as i32,
        )
    };

    if ret > 0 {
        let ppid = info.pbi_ppid;
        if ppid > 0 { Some(ppid) } else { None }
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn get_peer_pid_macos(fd: std::os::unix::io::RawFd) -> Option<u32> {
    let mut pid: libc::pid_t = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret == 0 && pid > 0 {
        Some(pid as u32)
    } else {
        None
    }
}

// --- Linux implementation ---

#[cfg(target_os = "linux")]
fn get_process_info_linux(pid: u32) -> Option<ProcessInfo> {
    let exe_path = std::fs::read_link(format!("/proc/{}/exe", pid)).ok();
    let name = exe_path
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(String::from)
        .unwrap_or_else(|| {
            // Fallback: read /proc/{pid}/comm
            std::fs::read_to_string(format!("/proc/{}/comm", pid))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| format!("pid:{}", pid))
        });
    let ppid = get_parent_pid_linux(pid);

    Some(ProcessInfo {
        pid,
        name,
        path: exe_path,
        ppid,
    })
}

#[cfg(target_os = "linux")]
fn get_parent_pid_linux(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(ppid_str) = line.strip_prefix("PPid:\t") {
            return ppid_str.trim().parse().ok();
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn get_peer_pid_linux(fd: std::os::unix::io::RawFd) -> Option<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret == 0 && cred.pid > 0 {
        Some(cred.pid as u32)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_chain_matches_empty_allowed() {
        let chain = ProcessChain {
            chain: vec![ProcessInfo {
                pid: 1,
                name: "ssh".to_string(),
                path: None,
                ppid: None,
            }],
        };
        // Empty allowed list means "allow all"
        assert!(chain.matches_any(&[]));
    }

    #[test]
    fn test_process_chain_matches_direct() {
        let chain = ProcessChain {
            chain: vec![
                ProcessInfo {
                    pid: 100,
                    name: "ssh".to_string(),
                    path: None,
                    ppid: Some(50),
                },
                ProcessInfo {
                    pid: 50,
                    name: "git".to_string(),
                    path: None,
                    ppid: Some(1),
                },
            ],
        };
        assert!(chain.matches_any(&["ssh".to_string()]));
        assert!(chain.matches_any(&["git".to_string()]));
        assert!(!chain.matches_any(&["jj".to_string()]));
    }

    #[test]
    fn test_process_chain_matches_ancestor() {
        let chain = ProcessChain {
            chain: vec![
                ProcessInfo {
                    pid: 100,
                    name: "ssh".to_string(),
                    path: None,
                    ppid: Some(50),
                },
                ProcessInfo {
                    pid: 50,
                    name: "git".to_string(),
                    path: None,
                    ppid: Some(10),
                },
                ProcessInfo {
                    pid: 10,
                    name: "zsh".to_string(),
                    path: None,
                    ppid: Some(1),
                },
            ],
        };
        // ssh invoked by git invoked by zsh - "git" is in the chain
        assert!(chain.matches_any(&["git".to_string()]));
        // "zsh" is an ancestor
        assert!(chain.matches_any(&["zsh".to_string()]));
    }

    #[test]
    fn test_process_chain_no_match() {
        let chain = ProcessChain {
            chain: vec![ProcessInfo {
                pid: 100,
                name: "unknown".to_string(),
                path: None,
                ppid: None,
            }],
        };
        assert!(!chain.matches_any(&["ssh".to_string(), "git".to_string()]));
    }

    #[test]
    fn test_contains_process() {
        let chain = ProcessChain {
            chain: vec![
                ProcessInfo {
                    pid: 100,
                    name: "ssh".to_string(),
                    path: None,
                    ppid: Some(50),
                },
                ProcessInfo {
                    pid: 50,
                    name: "git".to_string(),
                    path: None,
                    ppid: None,
                },
            ],
        };
        assert!(chain.contains_process("ssh"));
        assert!(chain.contains_process("git"));
        assert!(!chain.contains_process("jj"));
    }

    #[test]
    fn test_process_names() {
        let chain = ProcessChain {
            chain: vec![
                ProcessInfo {
                    pid: 100,
                    name: "ssh".to_string(),
                    path: None,
                    ppid: Some(50),
                },
                ProcessInfo {
                    pid: 50,
                    name: "git".to_string(),
                    path: None,
                    ppid: None,
                },
            ],
        };
        assert_eq!(chain.process_names(), vec!["ssh", "git"]);
    }

    // Platform-specific tests
    #[cfg(target_os = "macos")]
    #[test]
    fn test_get_current_process_info() {
        let pid = std::process::id();
        let info = get_process_info(pid).expect("should get info for current process");
        assert_eq!(info.pid, pid);
        assert!(info.ppid.is_some());
        // The process path should exist
        assert!(info.path.is_some());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_process_chain_from_current_pid() {
        let pid = std::process::id();
        let chain = ProcessChain::from_pid(pid);
        assert!(!chain.chain.is_empty());
        assert_eq!(chain.chain[0].pid, pid);
        // Should have at least 2 entries (self + parent)
        assert!(chain.chain.len() >= 2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_get_peer_pid_from_unix_socket() {
        use std::os::unix::io::AsRawFd;

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
            let client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
            let (server_stream, _) = listener.accept().await.unwrap();

            // Get peer PID from the server side
            let peer_pid = get_peer_pid(server_stream.as_raw_fd());
            assert!(peer_pid.is_some(), "should get peer PID");
            // The peer PID should be our own PID (since client is in same process)
            assert_eq!(peer_pid.unwrap(), std::process::id());

            drop(client);
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_get_current_process_info() {
        let pid = std::process::id();
        let info = get_process_info(pid).expect("should get info for current process");
        assert_eq!(info.pid, pid);
        assert!(info.ppid.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_process_chain_from_current_pid() {
        let pid = std::process::id();
        let chain = ProcessChain::from_pid(pid);
        assert!(!chain.chain.is_empty());
        assert_eq!(chain.chain[0].pid, pid);
        assert!(chain.chain.len() >= 2);
    }
}
