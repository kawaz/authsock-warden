//! Process identification and tree walking
//!
//! Provides platform-specific process inspection:
//! - macOS: proc_pidpath, sysctl(KERN_PROC) for parent PID, LOCAL_PEERPID for peer PID
//! - Linux: /proc/{pid}/exe, /proc/{pid}/status for parent PID, SO_PEERCRED for peer PID

use std::path::PathBuf;

use serde::Serialize;

/// Information about a single process
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name (basename of executable path)
    pub name: String,
    /// Full executable path (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// Parent process ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    /// Real user ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Real group ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    /// Current working directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    /// Command line arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    /// Process start time (Unix epoch seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<u64>,
}

/// A chain of processes from a starting PID up to init/launchd
#[derive(Debug, Clone, Serialize)]
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
    let bsd = get_bsd_info_macos(pid);
    let cwd = get_cwd_macos(pid);
    let argv = get_argv_macos(pid);

    Some(ProcessInfo {
        pid,
        name,
        path,
        ppid: bsd.ppid,
        uid: bsd.uid,
        gid: bsd.gid,
        cwd,
        argv,
        start_time: bsd.start_time,
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
struct BsdInfoResult {
    ppid: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    start_time: Option<u64>,
}

/// Get PPID, UID, GID, and start time from proc_bsdinfo
#[cfg(target_os = "macos")]
fn get_bsd_info_macos(pid: u32) -> BsdInfoResult {
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
        BsdInfoResult {
            ppid: if info.pbi_ppid > 0 {
                Some(info.pbi_ppid)
            } else {
                None
            },
            uid: Some(info.pbi_ruid),
            gid: Some(info.pbi_rgid),
            start_time: if info.pbi_start_tvsec > 0 {
                Some(info.pbi_start_tvsec)
            } else {
                None
            },
        }
    } else {
        BsdInfoResult {
            ppid: None,
            uid: None,
            gid: None,
            start_time: None,
        }
    }
}

/// Get current working directory via PROC_PIDVNODEPATHINFO
#[cfg(target_os = "macos")]
fn get_cwd_macos(pid: u32) -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::mem;

    // proc_vnodepathinfo contains vip_path fields for cwd and root dir
    let mut pathinfo: libc::proc_vnodepathinfo = unsafe { mem::zeroed() };
    let ret = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            &mut pathinfo as *mut _ as *mut libc::c_void,
            mem::size_of::<libc::proc_vnodepathinfo>() as i32,
        )
    };

    if ret > 0 {
        let c_str =
            unsafe { CStr::from_ptr(pathinfo.pvi_cdir.vip_path.as_ptr() as *const libc::c_char) };
        let path = PathBuf::from(c_str.to_string_lossy().into_owned());
        if path.as_os_str().is_empty() {
            None
        } else {
            Some(path)
        }
    } else {
        None
    }
}

/// Get command line arguments via sysctl(KERN_PROCARGS2)
#[cfg(target_os = "macos")]
fn get_argv_macos(pid: u32) -> Option<Vec<String>> {
    use std::ffi::CStr;

    // First call to get buffer size
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as i32];
    let mut size: libc::size_t = 0;
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size == 0 {
        return None;
    }

    // Second call to get the data
    let mut buf = vec![0u8; size];
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return None;
    }
    buf.truncate(size);

    // Layout: [argc: i32] [exec_path\0] [padding\0...] [arg0\0] [arg1\0] ... [argN\0] [env...]
    if buf.len() < std::mem::size_of::<i32>() {
        return None;
    }
    let argc = i32::from_ne_bytes(buf[..4].try_into().ok()?) as usize;
    let rest = &buf[4..];

    // Skip exec_path (NUL-terminated)
    let exec_end = rest.iter().position(|&b| b == 0)?;
    let mut pos = exec_end + 1;

    // Skip NUL padding between exec_path and argv[0]
    while pos < rest.len() && rest[pos] == 0 {
        pos += 1;
    }

    // Read argc arguments
    let mut args = Vec::with_capacity(argc);
    for _ in 0..argc {
        if pos >= rest.len() {
            break;
        }
        let c_str = unsafe { CStr::from_ptr(rest[pos..].as_ptr() as *const libc::c_char) };
        let arg = c_str.to_string_lossy().into_owned();
        pos += c_str.to_bytes_with_nul().len();
        args.push(arg);
    }

    if args.is_empty() { None } else { Some(args) }
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
            std::fs::read_to_string(format!("/proc/{}/comm", pid))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| format!("pid:{}", pid))
        });
    let (ppid, start_time, uid, gid) = get_stat_info_linux(pid);
    let cwd = std::fs::read_link(format!("/proc/{}/cwd", pid)).ok();
    let argv = get_argv_linux(pid);

    Some(ProcessInfo {
        pid,
        name,
        path: exe_path,
        ppid,
        uid,
        gid,
        cwd,
        argv,
        start_time,
    })
}

/// Get PPID, start time, UID, and GID from /proc/{pid}/status and /proc/{pid}/stat
#[cfg(target_os = "linux")]
fn get_stat_info_linux(pid: u32) -> (Option<u32>, Option<u64>, Option<u32>, Option<u32>) {
    let status = match std::fs::read_to_string(format!("/proc/{}/status", pid)) {
        Ok(s) => s,
        Err(_) => return (None, None, None, None),
    };
    let mut ppid = None;
    let mut uid = None;
    let mut gid = None;
    for line in status.lines() {
        if let Some(ppid_str) = line.strip_prefix("PPid:\t") {
            ppid = ppid_str.trim().parse().ok();
        } else if let Some(uid_str) = line.strip_prefix("Uid:\t") {
            // Format: real effective saved filesystem
            uid = uid_str
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok());
        } else if let Some(gid_str) = line.strip_prefix("Gid:\t") {
            gid = gid_str
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok());
        }
    }
    // Start time from /proc/{pid}/stat field 22 (starttime in clock ticks)
    let start_time = std::fs::read_to_string(format!("/proc/{}/stat", pid))
        .ok()
        .and_then(|stat| {
            // Format: pid (comm) state ppid ... field22
            // Find closing ')' to skip comm which may contain spaces
            let after_comm = stat.find(')')?.checked_add(2)?;
            let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
            // field 22 is starttime, which is at index 19 (0-based after state)
            let ticks: u64 = fields.get(19)?.parse().ok()?;
            // Convert clock ticks to epoch seconds (approximate)
            let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
            if ticks_per_sec == 0 {
                return None;
            }
            // Get boot time from /proc/stat
            let proc_stat = std::fs::read_to_string("/proc/stat").ok()?;
            let btime: u64 = proc_stat
                .lines()
                .find(|l| l.starts_with("btime "))?
                .split_whitespace()
                .nth(1)?
                .parse()
                .ok()?;
            Some(btime + ticks / ticks_per_sec)
        });
    (ppid, start_time, uid, gid)
}

/// Get command line arguments from /proc/{pid}/cmdline
#[cfg(target_os = "linux")]
fn get_argv_linux(pid: u32) -> Option<Vec<String>> {
    let data = std::fs::read(format!("/proc/{}/cmdline", pid)).ok()?;
    if data.is_empty() {
        return None;
    }
    let args: Vec<String> = data
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    if args.is_empty() { None } else { Some(args) }
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
                uid: None,
                gid: None,
                cwd: None,
                argv: None,
                start_time: None,
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
                    uid: None,
                    gid: None,
                    cwd: None,
                    argv: None,
                    start_time: None,
                },
                ProcessInfo {
                    pid: 50,
                    name: "git".to_string(),
                    path: None,
                    ppid: Some(1),
                    uid: None,
                    gid: None,
                    cwd: None,
                    argv: None,
                    start_time: None,
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
                    uid: None,
                    gid: None,
                    cwd: None,
                    argv: None,
                    start_time: None,
                },
                ProcessInfo {
                    pid: 50,
                    name: "git".to_string(),
                    path: None,
                    ppid: Some(10),
                    uid: None,
                    gid: None,
                    cwd: None,
                    argv: None,
                    start_time: None,
                },
                ProcessInfo {
                    pid: 10,
                    name: "zsh".to_string(),
                    path: None,
                    ppid: Some(1),
                    uid: None,
                    gid: None,
                    cwd: None,
                    argv: None,
                    start_time: None,
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
                uid: None,
                gid: None,
                cwd: None,
                argv: None,
                start_time: None,
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
                    uid: None,
                    gid: None,
                    cwd: None,
                    argv: None,
                    start_time: None,
                },
                ProcessInfo {
                    pid: 50,
                    name: "git".to_string(),
                    path: None,
                    ppid: None,
                    uid: None,
                    gid: None,
                    cwd: None,
                    argv: None,
                    start_time: None,
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
                    uid: None,
                    gid: None,
                    cwd: None,
                    argv: None,
                    start_time: None,
                },
                ProcessInfo {
                    pid: 50,
                    name: "git".to_string(),
                    path: None,
                    ppid: None,
                    uid: None,
                    gid: None,
                    cwd: None,
                    argv: None,
                    start_time: None,
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
