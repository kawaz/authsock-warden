//! Unix socket server for SSH agent proxy
//!
//! This module provides a Unix socket server that listens for client
//! connections and spawns proxy handlers for each connection.

use crate::error::{Error, Result};
use crate::utils::socket::{prepare_socket_path, set_socket_permissions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tracing::{debug, error, info, trace, warn};

/// Unix socket server for accepting SSH agent client connections
pub struct Server {
    /// Path to the socket file
    socket_path: PathBuf,
    /// The listener (created on bind)
    listener: Option<UnixListener>,
}

impl Server {
    /// Create a new server that will listen on the specified path
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            listener: None,
        }
    }

    /// Get the socket path
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Bind the server to the socket path
    pub async fn bind(&mut self) -> Result<()> {
        prepare_socket_path(&self.socket_path).map_err(|e| Error::Socket(e.to_string()))?;

        // Set restrictive umask before bind to prevent TOCTOU window
        // where socket has default (umask-dependent) permissions
        let old_umask = unsafe { libc::umask(0o077) };
        let bind_result = UnixListener::bind(&self.socket_path);
        unsafe { libc::umask(old_umask) };

        let listener = bind_result.map_err(|e| {
            Error::Socket(format!(
                "Failed to bind to socket at {}: {}",
                self.socket_path.display(),
                e
            ))
        })?;

        set_socket_permissions(&self.socket_path).map_err(|e| Error::Socket(e.to_string()))?;

        info!(path = %self.socket_path.display(), "Server listening");
        self.listener = Some(listener);
        Ok(())
    }

    /// Accept the next client connection
    pub async fn accept(&self) -> Result<UnixStream> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| Error::Socket("Server is not bound".to_string()))?;

        let (stream, _addr) = listener
            .accept()
            .await
            .map_err(|e| Error::Socket(format!("Failed to accept connection: {}", e)))?;

        trace!("Accepted new client connection");
        Ok(stream)
    }

    /// Run the server with a connection handler
    ///
    /// Runs until the shutdown signal is received.
    pub async fn run<F, Fut>(
        &self,
        handler: F,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<()>
    where
        F: Fn(UnixStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| Error::Socket("Server is not bound".to_string()))?;

        let handler = Arc::new(handler);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Received shutdown signal, stopping server");
                        break;
                    }
                }

                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            trace!("Accepted new client connection");
                            let handler = Arc::clone(&handler);
                            tokio::spawn(async move {
                                if let Err(e) = handler(stream).await {
                                    debug!(error = %e, "Connection handler error");
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to accept connection");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn cleanup(&self) {
        if self.socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.socket_path) {
                warn!(
                    path = %self.socket_path.display(),
                    error = %e,
                    "Failed to remove socket file during cleanup"
                );
            } else {
                debug!(path = %self.socket_path.display(), "Removed socket file");
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_server_new() {
        let server = Server::new("/tmp/test.sock");
        assert_eq!(server.socket_path(), Path::new("/tmp/test.sock"));
    }

    #[tokio::test]
    async fn test_server_bind_and_cleanup() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");

        {
            let mut server = Server::new(&socket_path);
            server.bind().await.unwrap();
            assert!(socket_path.exists());
        }

        assert!(!socket_path.exists());
    }

    #[tokio::test]
    async fn test_server_removes_stale_socket() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");

        std::fs::write(&socket_path, b"stale").unwrap();
        assert!(socket_path.exists());

        let mut server = Server::new(&socket_path);
        server.bind().await.unwrap();

        assert!(socket_path.exists());
    }
}
