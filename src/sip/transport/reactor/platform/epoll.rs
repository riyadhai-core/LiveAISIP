// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Linux and Android epoll backend.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use super::{Interest, OsReady, Poller};

pub(in crate::sip::transport::reactor) struct OsPoller {
    descriptor: OwnedFd,
    events: Box<[libc::epoll_event]>,
    masks: EpollMasks,
}

#[derive(Clone, Copy)]
struct EpollMasks {
    input: u32,
    output: u32,
    error: u32,
    hangup: u32,
    remote_hangup: u32,
    one_shot: u32,
}

impl EpollMasks {
    fn from_platform() -> io::Result<Self> {
        Ok(Self {
            input: epoll_mask(libc::EPOLLIN)?,
            output: epoll_mask(libc::EPOLLOUT)?,
            error: epoll_mask(libc::EPOLLERR)?,
            hangup: epoll_mask(libc::EPOLLHUP)?,
            remote_hangup: epoll_mask(libc::EPOLLRDHUP)?,
            one_shot: epoll_mask(libc::EPOLLONESHOT)?,
        })
    }

    const fn terminal(self) -> u32 {
        self.error | self.hangup | self.remote_hangup
    }
}

impl Poller for OsPoller {
    fn new(capacity: usize) -> io::Result<Self> {
        let masks = EpollMasks::from_platform()?;
        // SAFETY: `epoll_create1` has no pointer arguments; a nonnegative
        // return value is a newly owned descriptor.
        let raw = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful `epoll_create1` transfers unique descriptor
        // ownership to this value.
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut events = Vec::new();
        events.try_reserve_exact(capacity).map_err(|_| {
            io::Error::new(io::ErrorKind::OutOfMemory, "epoll event allocation failed")
        })?;
        events.resize_with(capacity, || libc::epoll_event { events: 0, u64: 0 });
        Ok(Self {
            descriptor,
            events: events.into_boxed_slice(),
            masks,
        })
    }

    fn add(&self, source: RawFd, key: usize, interest: Interest) -> io::Result<()> {
        self.control(libc::EPOLL_CTL_ADD, source, key, interest)
    }

    fn modify(&self, source: RawFd, key: usize, interest: Interest) -> io::Result<()> {
        self.control(libc::EPOLL_CTL_MOD, source, key, interest)
    }

    fn delete(&self, source: RawFd) -> io::Result<()> {
        // SAFETY: descriptors are valid for the duration of the call; Linux
        // ignores the event pointer for `EPOLL_CTL_DEL`.
        let result = unsafe {
            libc::epoll_ctl(
                self.descriptor.as_raw_fd(),
                libc::EPOLL_CTL_DEL,
                source,
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(source)
            }
        }
    }

    fn wait(&mut self, output: &mut Vec<OsReady>, timeout: Option<Duration>) -> io::Result<()> {
        let deadline = timeout.and_then(|duration| Instant::now().checked_add(duration));
        loop {
            let milliseconds = epoll_timeout(timeout, deadline);
            let maximum = i32::try_from(self.events.len()).unwrap_or(i32::MAX);
            // SAFETY: the event slice is initialized writable storage and the
            // descriptor is an owned epoll instance.
            let count = unsafe {
                libc::epoll_wait(
                    self.descriptor.as_raw_fd(),
                    self.events.as_mut_ptr(),
                    maximum,
                    milliseconds,
                )
            };
            if count >= 0 {
                for event in &self.events[..usize::try_from(count).unwrap_or(0)] {
                    let flags = event.events;
                    output.push(OsReady {
                        key: usize::try_from(event.u64).unwrap_or(usize::MAX),
                        readable: flags & self.masks.input != 0,
                        writable: flags & self.masks.output != 0,
                        terminal: flags & self.masks.terminal() != 0,
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
    fn control(
        &self,
        operation: i32,
        source: RawFd,
        key: usize,
        interest: Interest,
    ) -> io::Result<()> {
        let mut flags = self.masks.one_shot | self.masks.terminal();
        if interest.readable {
            flags |= self.masks.input;
        }
        if interest.writable {
            flags |= self.masks.output;
        }
        let mut event = libc::epoll_event {
            events: flags,
            u64: u64::try_from(key).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "epoll key exceeds u64")
            })?,
        };
        // SAFETY: all descriptors are live and `event` is initialized for the
        // duration of the control call.
        let result = unsafe {
            libc::epoll_ctl(
                self.descriptor.as_raw_fd(),
                operation,
                source,
                &raw mut event,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

fn epoll_mask(value: i32) -> io::Result<u32> {
    u32::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "platform exposed a negative epoll event mask",
        )
    })
}

fn epoll_timeout(original: Option<Duration>, deadline: Option<Instant>) -> i32 {
    if original.is_none() {
        return -1;
    }
    let remaining = deadline
        .and_then(|deadline| deadline.checked_duration_since(Instant::now()))
        .unwrap_or(Duration::ZERO);
    if remaining.is_zero() {
        return 0;
    }
    let milliseconds = remaining.as_millis().saturating_add(1);
    i32::try_from(milliseconds).unwrap_or(i32::MAX)
}
