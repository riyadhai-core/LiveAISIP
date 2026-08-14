// Copyright 2026 RiyadhAI LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Bounded generation-fenced call actor registry.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use super::context::{CallContext, CallContextError};
use super::events::{CallAction, CallEvent};

/// Maximum calls configurable in one registry.
pub const MAX_CALL_MANAGER_CAPACITY: usize = 1_000_000;

/// Generation-fenced capability for one actor instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CallToken {
    call_id: u64,
    generation: u64,
}

impl CallToken {
    /// Returns application call identifier.
    #[must_use]
    pub const fn call_id(self) -> u64 {
        self.call_id
    }

    /// Returns nonreused registry generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

struct Entry {
    generation: u64,
    context: CallContext,
}

/// Registry that routes events but never exposes mutable call state.
pub struct CallManager {
    calls: HashMap<u64, Entry>,
    capacity: usize,
    next_generation: u64,
    accepting: bool,
}

impl CallManager {
    /// Creates a bounded registry.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive capacity or allocation failure.
    pub fn new(capacity: usize) -> Result<Self, CallManagerError> {
        if capacity == 0 || capacity > MAX_CALL_MANAGER_CAPACITY {
            return Err(CallManagerError::InvalidCapacity);
        }
        let mut calls = HashMap::new();
        calls
            .try_reserve(capacity.min(1_024))
            .map_err(|_| CallManagerError::AllocationFailed)?;
        Ok(Self {
            calls,
            capacity,
            next_generation: 1,
            accepting: true,
        })
    }

    /// Admits one new actor under caller-assigned opaque ID.
    ///
    /// # Errors
    ///
    /// Rejects shutdown, duplicate ID, capacity, generation exhaustion or allocation failure.
    pub fn insert(
        &mut self,
        call_id: u64,
        context: CallContext,
    ) -> Result<CallToken, CallManagerError> {
        if !self.accepting {
            return Err(CallManagerError::ShuttingDown);
        }
        if self.calls.contains_key(&call_id) {
            return Err(CallManagerError::DuplicateCall);
        }
        if self.calls.len() == self.capacity {
            return Err(CallManagerError::AtCapacity);
        }
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(CallManagerError::GenerationExhausted)?;
        self.calls
            .try_reserve(1)
            .map_err(|_| CallManagerError::AllocationFailed)?;
        self.calls.insert(
            call_id,
            Entry {
                generation,
                context,
            },
        );
        Ok(CallToken {
            call_id,
            generation,
        })
    }

    /// Routes an event into one bounded actor mailbox.
    ///
    /// # Errors
    ///
    /// Rejects missing/stale actors or mailbox overflow.
    pub fn submit(&mut self, token: CallToken, event: CallEvent) -> Result<(), CallManagerError> {
        let entry = self.entry_mut(token)?;
        entry
            .context
            .submit(event)
            .map_err(|_| CallManagerError::MailboxFull)
    }

    /// Processes one queued event under the actor's exclusive authority.
    ///
    /// # Errors
    ///
    /// Rejects missing/stale actors or context processing failure.
    pub fn process_next(
        &mut self,
        token: CallToken,
        now: Duration,
    ) -> Result<Option<Vec<CallAction>>, CallManagerError> {
        self.entry_mut(token)?
            .context
            .process_next(now)
            .map_err(CallManagerError::Context)
    }

    /// Removes exact actor generation, preventing delayed work reaching reuse.
    pub fn remove(&mut self, token: CallToken) -> Option<CallContext> {
        if self
            .calls
            .get(&token.call_id)
            .is_some_and(|entry| entry.generation == token.generation)
        {
            self.calls.remove(&token.call_id).map(|entry| entry.context)
        } else {
            None
        }
    }

    /// Stops new admission while existing calls drain.
    pub const fn begin_shutdown(&mut self) {
        self.accepting = false;
    }

    /// Returns active call count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.calls.len()
    }

    /// Returns whether no calls remain.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.calls.is_empty()
    }

    fn entry_mut(&mut self, token: CallToken) -> Result<&mut Entry, CallManagerError> {
        let entry = self
            .calls
            .get_mut(&token.call_id)
            .ok_or(CallManagerError::UnknownCall)?;
        if entry.generation != token.generation {
            return Err(CallManagerError::StaleToken);
        }
        Ok(entry)
    }
}

impl fmt::Debug for CallManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallManager")
            .field("capacity", &self.capacity)
            .field("active_calls", &self.calls.len())
            .field("accepting", &self.accepting)
            .finish_non_exhaustive()
    }
}

/// Call registry failure.
#[derive(Debug)]
pub enum CallManagerError {
    /// Capacity setting was unsafe.
    InvalidCapacity,
    /// Registry allocation failed.
    AllocationFailed,
    /// Registry stopped new admissions.
    ShuttingDown,
    /// Call ID already active.
    DuplicateCall,
    /// Active call limit reached.
    AtCapacity,
    /// Generation counter cannot safely continue.
    GenerationExhausted,
    /// No actor has this call ID.
    UnknownCall,
    /// Token belongs to an older actor generation.
    StaleToken,
    /// Actor mailbox was full.
    MailboxFull,
    /// Actor processing failed.
    Context(CallContextError),
}

impl fmt::Display for CallManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("call manager operation failed")
    }
}

impl StdError for CallManagerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Context(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{CallManager, CallManagerError};
    use crate::call::context::CallContext;
    use crate::call::events::{CallCommand, CallEvent};

    fn context() -> CallContext {
        CallContext::new(Duration::ZERO, 4, 4).unwrap_or_else(|_| panic!("context"))
    }

    #[test]
    fn stale_token_cannot_reach_reused_call_id() {
        let mut manager = CallManager::new(1).unwrap_or_else(|_| panic!("manager"));
        let first = manager
            .insert(7, context())
            .unwrap_or_else(|_| panic!("insert"));
        assert!(manager.remove(first).is_some());
        let second = manager
            .insert(7, context())
            .unwrap_or_else(|_| panic!("insert"));
        assert_ne!(first.generation(), second.generation());
        assert!(matches!(
            manager.submit(first, CallEvent::Command(CallCommand::Start)),
            Err(CallManagerError::StaleToken)
        ));
        assert!(
            manager
                .submit(second, CallEvent::Command(CallCommand::Start))
                .is_ok()
        );
    }

    #[test]
    fn admission_and_shutdown_are_bounded() {
        let mut manager = CallManager::new(1).unwrap_or_else(|_| panic!("manager"));
        assert!(manager.insert(1, context()).is_ok());
        assert!(matches!(
            manager.insert(2, context()),
            Err(CallManagerError::AtCapacity)
        ));
        manager.begin_shutdown();
        assert!(matches!(
            manager.insert(2, context()),
            Err(CallManagerError::ShuttingDown)
        ));
    }
}
