//! File descriptor signaling for GLib main loop integration
//!
//! This module provides a pipe-based mechanism for the async Rust code
//! to signal the main thread (GLib event loop) when events are ready.

use std::os::raw::c_int;
use std::os::unix::io::{AsRawFd, BorrowedFd, OwnedFd, RawFd};

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::unistd::{pipe, read};

/// A pipe used for signaling between threads
pub struct SignalPipe {
    read_fd: OwnedFd,
    write_fd: OwnedFd,
}

impl SignalPipe {
    /// Create a new signal pipe
    pub fn new() -> Result<Self, nix::Error> {
        let (read_fd, write_fd) = pipe()?;

        // Set non-blocking on read end
        let flags = fcntl(&read_fd, FcntlArg::F_GETFL)?;
        let flags = OFlag::from_bits_truncate(flags);
        fcntl(&read_fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;

        Ok(SignalPipe { read_fd, write_fd })
    }

    /// Get the read file descriptor for polling
    pub fn read_fd(&self) -> c_int {
        self.read_fd.as_raw_fd()
    }

    /// Create a writer handle that can be sent to other threads
    pub fn writer(&self) -> SignalWriter {
        SignalWriter {
            write_fd: self.write_fd.as_raw_fd(),
        }
    }

    /// Clear any pending signals (drain the pipe)
    pub fn clear(&self) {
        let mut buf = [0u8; 64];
        // Use BorrowedFd for read
        let borrowed = unsafe { BorrowedFd::borrow_raw(self.read_fd.as_raw_fd()) };
        while let Ok(n) = read(borrowed, &mut buf) {
            if n == 0 {
                break;
            }
        }
    }
}

/// Handle for writing to the signal pipe from another thread
#[derive(Clone, Copy)]
pub struct SignalWriter {
    write_fd: RawFd,
}

impl SignalWriter {
    /// Signal the reader that events are available
    pub fn signal(&self) -> Result<(), std::io::Error> {
        // Use libc directly for simplicity with raw fd
        let buf = [1u8];
        let ret = unsafe {
            libc::write(self.write_fd, buf.as_ptr() as *const libc::c_void, 1)
        };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

// Safety: The write_fd is only written to, and write() is thread-safe
unsafe impl Send for SignalWriter {}
unsafe impl Sync for SignalWriter {}
