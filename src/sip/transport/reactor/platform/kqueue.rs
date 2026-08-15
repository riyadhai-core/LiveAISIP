// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Apple and BSD kqueue backend.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use super::{Interest, OsReady, Poller};

pub(in crate::sip::transport::reactor) struct OsPoller {
    descriptor: OwnedFd,
    events: Box<[libc::kevent]>,
}

impl Poller for OsPoller {
    fn new(capacity: usize) -> io::Result<Self> {
        // SAFETY: `kqueue` has no arguments; a nonnegative result is a newly
        // owned descriptor.
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful `kqueue` transfers unique descriptor ownership.
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: `descriptor` is live and `F_SETFD` consumes only the integer
        // flag value. Ownership remains with `descriptor` on every outcome.
        if unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut events = Vec::new();
        events.try_reserve_exact(capacity).map_err(|_| {
            io::Error::new(io::ErrorKind::OutOfMemory, "kqueue event allocation failed")
        })?;
        events.resize_with(capacity, zero_kevent);
        Ok(Self {
            descriptor,
            events: events.into_boxed_slice(),
        })
    }

    fn add(&self, source: RawFd, key: usize, interest: Interest) -> io::Result<()> {
        self.modify(source, key, interest)
    }

    fn modify(&self, source: RawFd, key: usize, interest: Interest) -> io::Result<()> {
        if interest.readable {
            self.change(source, key, libc::EVFILT_READ, true)?;
        } else {
            self.change(source, key, libc::EVFILT_READ, false)?;
        }
        if interest.writable {
            self.change(source, key, libc::EVFILT_WRITE, true)
        } else {
            self.change(source, key, libc::EVFILT_WRITE, false)
        }
    }

    fn delete(&self, source: RawFd) -> io::Result<()> {
        let read = self.change(source, 0, libc::EVFILT_READ, false);
        let write = self.change(source, 0, libc::EVFILT_WRITE, false);
        read.and(write)
    }

    fn wait(&mut self, output: &mut Vec<OsReady>, timeout: Option<Duration>) -> io::Result<()> {
        let deadline = timeout.and_then(|duration| Instant::now().checked_add(duration));
        loop {
            let remaining = deadline.map(|deadline| {
                deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or(Duration::ZERO)
            });
            let timespec = remaining.map(duration_timespec);
            let timeout_pointer = timespec.as_ref().map_or(std::ptr::null(), |value| value);
            let maximum = i32::try_from(self.events.len()).unwrap_or(i32::MAX);
            // SAFETY: the event slice is initialized writable storage; change
            // pointers are null because this call only waits.
            let count = unsafe {
                libc::kevent(
                    self.descriptor.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    self.events.as_mut_ptr(),
                    maximum,
                    timeout_pointer,
                )
            };
            if count >= 0 {
                for event in &self.events[..usize::try_from(count).unwrap_or(0)] {
                    output.push(OsReady {
                        key: event.udata as usize,
                        readable: event.filter == libc::EVFILT_READ,
                        writable: event.filter == libc::EVFILT_WRITE,
                        terminal: event.flags & (libc::EV_EOF | libc::EV_ERROR) != 0,
                    });
                }
                return Ok(());
            }
            let source = io::Error::last_os_error();
            if source.kind() != io::ErrorKind::Interrupted {
                return Err(source);
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Ok(());
            }
        }
    }
}

impl OsPoller {
    fn change(&self, source: RawFd, key: usize, filter: i16, enable: bool) -> io::Result<()> {
        let ident = libc::uintptr_t::try_from(source)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative descriptor"))?;
        let flags = if enable {
            libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT
        } else {
            libc::EV_DELETE
        };
        let change = libc::kevent {
            ident,
            filter,
            flags,
            fflags: 0,
            data: 0,
            udata: key as *mut libc::c_void,
        };
        // SAFETY: `change` is initialized and borrowed for this call; no event
        // output is requested.
        let result = unsafe {
            libc::kevent(
                self.descriptor.as_raw_fd(),
                &raw const change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            let source = io::Error::last_os_error();
            if !enable && source.raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(source)
            }
        }
    }
}

fn zero_kevent() -> libc::kevent {
    libc::kevent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

fn duration_timespec(duration: Duration) -> libc::timespec {
    libc::timespec {
        tv_sec: libc::time_t::try_from(duration.as_secs()).unwrap_or(libc::time_t::MAX),
        tv_nsec: libc::c_long::from(duration.subsec_nanos()),
    }
}
