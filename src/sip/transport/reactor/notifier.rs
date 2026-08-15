// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Independently callable native-reactor wake handle.

use std::fmt;
use std::io::{self, Write};
use std::os::unix::net::UnixStream;

/// One independently callable wake handle.
pub struct ReactorNotifier {
    pub(super) writer: UnixStream,
}

impl ReactorNotifier {
    /// Wakes a blocked reactor wait.
    ///
    /// Wake bytes are coalesced. A full nonblocking wake socket is success
    /// because it already guarantees pending readability.
    ///
    /// # Errors
    ///
    /// Preserves operating-system wake-socket write failure.
    pub fn notify(&self) -> io::Result<()> {
        let mut writer = &self.writer;
        match writer.write(&[1]) {
            Ok(_) => Ok(()),
            Err(source) if source.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(source) => Err(source),
        }
    }
}

impl fmt::Debug for ReactorNotifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReactorNotifier")
            .finish_non_exhaustive()
    }
}
