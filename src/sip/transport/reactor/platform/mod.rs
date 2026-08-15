// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Native one-shot readiness backends.

use std::io;
use std::os::fd::RawFd;
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod epoll;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
mod kqueue;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) use epoll::OsPoller;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
pub(super) use kqueue::OsPoller;

#[derive(Clone, Copy)]
pub(super) struct Interest {
    pub(super) readable: bool,
    pub(super) writable: bool,
}

impl Interest {
    pub(super) const READ: Self = Self {
        readable: true,
        writable: false,
    };
    pub(super) const READ_WRITE: Self = Self {
        readable: true,
        writable: true,
    };
}

#[derive(Clone, Copy, Debug)]
pub(super) struct OsReady {
    pub(super) key: usize,
    pub(super) readable: bool,
    pub(super) writable: bool,
    pub(super) terminal: bool,
}

pub(super) trait Poller: Sized {
    fn new(capacity: usize) -> io::Result<Self>;
    fn add(&self, source: RawFd, key: usize, interest: Interest) -> io::Result<()>;
    fn modify(&self, source: RawFd, key: usize, interest: Interest) -> io::Result<()>;
    fn delete(&self, source: RawFd) -> io::Result<()>;
    fn wait(&mut self, output: &mut Vec<OsReady>, timeout: Option<Duration>) -> io::Result<()>;
}
