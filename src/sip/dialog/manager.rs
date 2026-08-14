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

//! Capacity-bounded, actor-owned SIP dialog registry.
//!
//! The signaling actor exclusively owns this manager. Other tasks communicate
//! through bounded queues, keeping locks and asynchronous cancellation out of
//! the dialog hot path. Generation-fenced tokens prevent delayed work from
//! mutating a later dialog that reuses the same protocol identifier.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;

use super::core::Dialog;
use super::id::DialogId;

/// Hard maximum number of dialogs in one registry.
pub const MAX_DIALOGS: usize = 1_048_576;

/// Opaque generation-fenced handle to a registered dialog.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DialogToken {
    id: DialogId,
    generation: u64,
}

impl DialogToken {
    /// Returns the dialog identifier used for protocol matching.
    #[must_use]
    pub const fn id(&self) -> &DialogId {
        &self.id
    }

    /// Returns the opaque registration generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

impl fmt::Debug for DialogToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DialogToken")
            .field("id", &self.id)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

struct Entry {
    generation: u64,
    dialog: Dialog,
}

/// Actor-owned bounded dialog manager.
pub struct DialogManager {
    maximum: usize,
    next_generation: u64,
    shutting_down: bool,
    entries: HashMap<DialogId, Entry>,
}

impl DialogManager {
    /// Creates an empty registry with a validated capacity.
    ///
    /// # Errors
    ///
    /// Rejects zero capacity and values above [`MAX_DIALOGS`].
    pub fn new(maximum: usize) -> Result<Self, DialogManagerError> {
        if maximum == 0 || maximum > MAX_DIALOGS {
            return Err(DialogManagerError::InvalidCapacity {
                value: maximum,
                maximum: MAX_DIALOGS,
            });
        }
        Ok(Self {
            maximum,
            next_generation: 1,
            shutting_down: false,
            entries: HashMap::new(),
        })
    }

    /// Registers an active dialog transactionally.
    ///
    /// # Errors
    ///
    /// Rejects shutdown, a terminal dialog, duplicate identity, exhausted
    /// capacity or generation space, and allocation failure. Failure leaves
    /// the registry unchanged.
    pub fn insert(&mut self, dialog: Dialog) -> Result<DialogToken, DialogManagerError> {
        if self.shutting_down {
            return Err(DialogManagerError::ShuttingDown);
        }
        if dialog.state().is_terminated() {
            return Err(DialogManagerError::TerminatedDialog);
        }
        if self.entries.contains_key(dialog.id()) {
            return Err(DialogManagerError::Duplicate);
        }
        if self.entries.len() >= self.maximum {
            return Err(DialogManagerError::Capacity {
                maximum: self.maximum,
            });
        }
        let generation = self.next_generation;
        let Some(next_generation) = generation.checked_add(1) else {
            return Err(DialogManagerError::GenerationExhausted);
        };
        self.entries
            .try_reserve(1)
            .map_err(|_| DialogManagerError::AllocationFailed)?;

        let id = dialog.id().clone();
        let token = DialogToken {
            id: id.clone(),
            generation,
        };
        self.entries.insert(id, Entry { generation, dialog });
        self.next_generation = next_generation;
        Ok(token)
    }

    /// Returns a fresh token for the currently registered generation of an
    /// identifier.
    #[must_use]
    pub fn token_for(&self, id: &DialogId) -> Option<DialogToken> {
        self.entries.get(id).map(|entry| DialogToken {
            id: id.clone(),
            generation: entry.generation,
        })
    }

    /// Returns immutable access through an exact generation token.
    ///
    /// # Errors
    ///
    /// Distinguishes an unknown identifier from a stale generation.
    pub fn get(&self, token: &DialogToken) -> Result<&Dialog, DialogManagerError> {
        let entry = self
            .entries
            .get(&token.id)
            .ok_or(DialogManagerError::Unknown)?;
        verify_generation(entry, token)?;
        Ok(&entry.dialog)
    }

    /// Returns mutable access through an exact generation token.
    ///
    /// # Errors
    ///
    /// Distinguishes an unknown identifier from a stale generation.
    pub fn get_mut(&mut self, token: &DialogToken) -> Result<&mut Dialog, DialogManagerError> {
        let entry = self
            .entries
            .get_mut(&token.id)
            .ok_or(DialogManagerError::Unknown)?;
        verify_generation(entry, token)?;
        Ok(&mut entry.dialog)
    }

    /// Removes and returns the exact generation represented by a token.
    ///
    /// Unknown and stale tokens leave the registry unchanged.
    pub fn remove(&mut self, token: &DialogToken) -> Option<Dialog> {
        if self
            .entries
            .get(&token.id)
            .is_none_or(|entry| entry.generation != token.generation)
        {
            return None;
        }
        self.entries.remove(&token.id).map(|entry| entry.dialog)
    }

    /// Permanently prevents admission of new dialogs.
    ///
    /// Existing dialogs remain available so graceful BYE and cleanup work can
    /// complete.
    pub const fn begin_shutdown(&mut self) {
        self.shutting_down = true;
    }

    /// Returns whether shutdown admission fencing is active.
    #[must_use]
    pub const fn is_shutting_down(&self) -> bool {
        self.shutting_down
    }

    /// Returns the number of registered dialogs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no dialogs are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns configured capacity.
    #[must_use]
    pub const fn maximum(&self) -> usize {
        self.maximum
    }
}

impl fmt::Debug for DialogManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DialogManager")
            .field("dialogs", &self.entries.len())
            .field("maximum", &self.maximum)
            .field("shutting_down", &self.shutting_down)
            .finish_non_exhaustive()
    }
}

/// Dialog registry failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DialogManagerError {
    /// Capacity configuration was invalid.
    InvalidCapacity {
        /// Configured capacity.
        value: usize,
        /// Hard maximum capacity.
        maximum: usize,
    },
    /// Shutdown admission fencing is active.
    ShuttingDown,
    /// The dialog was already terminated.
    TerminatedDialog,
    /// Registry capacity was exhausted.
    Capacity {
        /// Configured maximum capacity.
        maximum: usize,
    },
    /// The same dialog identity is already registered.
    Duplicate,
    /// No current dialog has the token's identifier.
    Unknown,
    /// The token belongs to an older registration generation.
    StaleGeneration,
    /// The monotonic generation space was exhausted.
    GenerationExhausted,
    /// Bounded map allocation failed.
    AllocationFailed,
}

impl fmt::Display for DialogManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCapacity { .. } => "invalid SIP dialog registry capacity",
            Self::ShuttingDown => "SIP dialog registry is shutting down",
            Self::TerminatedDialog => "cannot register a terminated SIP dialog",
            Self::Capacity { .. } => "SIP dialog registry capacity is exhausted",
            Self::Duplicate => "SIP dialog is already registered",
            Self::Unknown => "SIP dialog is not registered",
            Self::StaleGeneration => "SIP dialog token is stale",
            Self::GenerationExhausted => "SIP dialog generation space is exhausted",
            Self::AllocationFailed => "SIP dialog registry allocation failed",
        })
    }
}

impl StdError for DialogManagerError {}

fn verify_generation(entry: &Entry, token: &DialogToken) -> Result<(), DialogManagerError> {
    if entry.generation == token.generation {
        Ok(())
    } else {
        Err(DialogManagerError::StaleGeneration)
    }
}

#[cfg(test)]
mod tests {
    use crate::sip::dialog::{Dialog, DialogId, DialogState, RouteSet};
    use crate::sip::headers::call_id::CallId;
    use crate::sip::parser::uri::parse_str;

    use super::{DialogManager, DialogManagerError, MAX_DIALOGS};

    fn dialog(call_id: &str) -> Dialog {
        let call_id = CallId::new(call_id).unwrap_or_else(|_| panic!("valid call id"));
        let id = DialogId::new(call_id, "local-tag", "remote-tag")
            .unwrap_or_else(|_| panic!("valid dialog id"));
        let target = parse_str("sip:peer@example.org").unwrap_or_else(|_| panic!("valid target"));
        Dialog::new(
            id,
            DialogState::confirmed(),
            RouteSet::empty(),
            target,
            1,
            None,
        )
        .unwrap_or_else(|_| panic!("valid dialog"))
    }

    #[test]
    fn capacity_configuration_is_bounded() {
        assert!(matches!(
            DialogManager::new(0),
            Err(DialogManagerError::InvalidCapacity { .. })
        ));
        assert!(matches!(
            DialogManager::new(MAX_DIALOGS + 1),
            Err(DialogManagerError::InvalidCapacity { .. })
        ));
    }

    #[test]
    fn insert_lookup_mutate_and_remove_are_generation_fenced() {
        let Ok(mut manager) = DialogManager::new(2) else {
            panic!("valid manager")
        };
        let Ok(token) = manager.insert(dialog("one@example.org")) else {
            panic!("insert")
        };
        let Some(found) = manager.token_for(token.id()) else {
            panic!("lookup")
        };
        assert_eq!(found, token);
        let Ok(value) = manager.get_mut(&token) else {
            panic!("current token")
        };
        assert!(value.terminate());
        assert!(manager.remove(&token).is_some());
        assert!(manager.is_empty());
        assert_eq!(manager.get(&token), Err(DialogManagerError::Unknown));
    }

    #[test]
    fn stale_token_cannot_reach_reused_identity() {
        let Ok(mut manager) = DialogManager::new(1) else {
            panic!("valid manager")
        };
        let first_dialog = dialog("reuse@example.org");
        let replacement = first_dialog.clone();
        let first = manager
            .insert(first_dialog)
            .unwrap_or_else(|_| panic!("first insert"));
        assert!(manager.remove(&first).is_some());
        let second = manager
            .insert(replacement)
            .unwrap_or_else(|_| panic!("second insert"));
        assert_ne!(first.generation(), second.generation());
        assert_eq!(
            manager.get(&first),
            Err(DialogManagerError::StaleGeneration)
        );
        assert!(manager.get(&second).is_ok());
        assert!(manager.remove(&first).is_none());
    }

    #[test]
    fn duplicate_and_capacity_fail_without_mutation() {
        let Ok(mut manager) = DialogManager::new(1) else {
            panic!("valid manager")
        };
        let original = dialog("one@example.org");
        let duplicate = original.clone();
        assert!(manager.insert(original).is_ok());
        assert_eq!(
            manager.insert(duplicate),
            Err(DialogManagerError::Duplicate)
        );
        assert_eq!(
            manager.insert(dialog("two@example.org")),
            Err(DialogManagerError::Capacity { maximum: 1 })
        );
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn shutdown_fences_only_new_admission() {
        let Ok(mut manager) = DialogManager::new(1) else {
            panic!("valid manager")
        };
        let token = manager
            .insert(dialog("one@example.org"))
            .unwrap_or_else(|_| panic!("insert"));
        manager.begin_shutdown();
        assert_eq!(
            manager.insert(dialog("two@example.org")),
            Err(DialogManagerError::ShuttingDown)
        );
        assert!(manager.get(&token).is_ok());
        assert!(manager.remove(&token).is_some());
    }

    #[test]
    fn terminal_dialog_is_not_admitted() {
        let Ok(mut manager) = DialogManager::new(1) else {
            panic!("valid manager")
        };
        let mut value = dialog("ended@example.org");
        assert!(value.terminate());
        assert_eq!(
            manager.insert(value),
            Err(DialogManagerError::TerminatedDialog)
        );
    }

    #[test]
    fn debug_output_is_redacted() {
        let Ok(mut manager) = DialogManager::new(1) else {
            panic!("valid manager")
        };
        let token = manager
            .insert(dialog("private-call@example.org"))
            .unwrap_or_else(|_| panic!("insert"));
        let debug = format!("{manager:?} {token:?}");
        assert!(!debug.contains("private-call"));
        assert!(!debug.contains("local-tag"));
        assert!(!debug.contains("remote-tag"));
    }
}
