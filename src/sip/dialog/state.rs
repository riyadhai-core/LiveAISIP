// Copyright 2026 RiyadhAI LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `LiveAISIP`.
//!
//! A high-performance SIP server developed by `RiyadhAI LLC` for large-scale
//! realtime AI telephony workloads.

//! SIP dialog lifecycle state.
//!
//! This module models the small, deterministic lifecycle shared by early and
//! confirmed dialogs. Retransmitted provisional and successful responses are
//! deliberately idempotent, while a terminated dialog can never be revived.
//! Transaction timers, route sets, sequence numbers, and resource cleanup are
//! owned by their respective higher-level components.

use std::error::Error as StdError;
use std::fmt;

/// The lifecycle state of a SIP dialog.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum DialogState {
    /// A tagged provisional response established an early dialog.
    Early,
    /// A successful final response established a confirmed dialog.
    Confirmed,
    /// The dialog ended and cannot process further in-dialog work.
    Terminated,
}

impl DialogState {
    /// Creates an early-dialog state.
    #[must_use]
    pub const fn early() -> Self {
        Self::Early
    }

    /// Creates a confirmed-dialog state.
    ///
    /// This is used when a successful response establishes a dialog without a
    /// preceding tagged provisional response.
    #[must_use]
    pub const fn confirmed() -> Self {
        Self::Confirmed
    }

    /// Applies a tagged provisional response.
    ///
    /// Repeated provisional responses leave an early dialog unchanged. A
    /// provisional response received after confirmation is harmless and also
    /// leaves the state unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`DialogStateError::Terminated`] when the dialog has ended.
    pub fn on_provisional(&mut self) -> Result<(), DialogStateError> {
        match self {
            Self::Early | Self::Confirmed => Ok(()),
            Self::Terminated => Err(DialogStateError::Terminated),
        }
    }

    /// Confirms the dialog after a successful final response.
    ///
    /// Confirmation is idempotent so retransmitted 2xx responses cannot cause
    /// a false state-transition failure.
    ///
    /// # Errors
    ///
    /// Returns [`DialogStateError::Terminated`] when the dialog has ended.
    pub fn confirm(&mut self) -> Result<(), DialogStateError> {
        match self {
            Self::Early => {
                *self = Self::Confirmed;
                Ok(())
            }
            Self::Confirmed => Ok(()),
            Self::Terminated => Err(DialogStateError::Terminated),
        }
    }

    /// Terminates the dialog.
    ///
    /// Returns `true` only for the first transition. This makes repeated
    /// shutdown, timeout, and BYE cleanup paths safe without hiding whether
    /// resource teardown still needs to run.
    #[must_use]
    pub fn terminate(&mut self) -> bool {
        if matches!(self, Self::Terminated) {
            false
        } else {
            *self = Self::Terminated;
            true
        }
    }

    /// Verifies that the dialog can process an in-dialog operation.
    ///
    /// Both early and confirmed dialogs are active because methods such as
    /// PRACK and UPDATE may operate before confirmation.
    ///
    /// # Errors
    ///
    /// Returns [`DialogStateError::Terminated`] for an ended dialog.
    pub const fn ensure_active(self) -> Result<(), DialogStateError> {
        if matches!(self, Self::Terminated) {
            Err(DialogStateError::Terminated)
        } else {
            Ok(())
        }
    }

    /// Returns whether the dialog is early.
    #[must_use]
    pub const fn is_early(self) -> bool {
        matches!(self, Self::Early)
    }

    /// Returns whether the dialog is confirmed.
    #[must_use]
    pub const fn is_confirmed(self) -> bool {
        matches!(self, Self::Confirmed)
    }

    /// Returns whether the dialog is terminal.
    #[must_use]
    pub const fn is_terminated(self) -> bool {
        matches!(self, Self::Terminated)
    }
}

/// A rejected dialog lifecycle operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogStateError {
    /// The operation targeted a terminated dialog.
    Terminated,
}

impl fmt::Display for DialogStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Terminated => formatter.write_str("dialog is terminated"),
        }
    }
}

impl StdError for DialogStateError {}

#[cfg(test)]
mod tests {
    use super::{DialogState, DialogStateError};

    #[test]
    fn early_dialog_confirms_once_and_accepts_retransmission() {
        let mut state = DialogState::early();
        assert!(state.is_early());
        assert_eq!(state.on_provisional(), Ok(()));
        assert_eq!(state.confirm(), Ok(()));
        assert!(state.is_confirmed());
        assert_eq!(state.confirm(), Ok(()));
        assert!(state.is_confirmed());
    }

    #[test]
    fn dialog_can_begin_confirmed() {
        let state = DialogState::confirmed();
        assert!(state.is_confirmed());
        assert_eq!(state.ensure_active(), Ok(()));
    }

    #[test]
    fn termination_is_terminal_and_idempotent() {
        let mut state = DialogState::early();
        assert!(state.terminate());
        assert!(!state.terminate());
        assert!(state.is_terminated());
        assert_eq!(state.ensure_active(), Err(DialogStateError::Terminated));
        assert_eq!(state.on_provisional(), Err(DialogStateError::Terminated));
        assert_eq!(state.confirm(), Err(DialogStateError::Terminated));
    }

    #[test]
    fn late_provisional_does_not_demote_confirmed_dialog() {
        let mut state = DialogState::confirmed();
        assert_eq!(state.on_provisional(), Ok(()));
        assert!(state.is_confirmed());
    }
}
