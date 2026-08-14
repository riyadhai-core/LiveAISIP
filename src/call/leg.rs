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

//! Bounded early and confirmed dialog branches for one outbound INVITE.

use std::error::Error as StdError;
use std::fmt;

/// Maximum early/confirmed branches retained for one forked INVITE.
pub const MAX_FORKED_DIALOGS: usize = 16;
/// Maximum remote tag bytes used to identify one branch.
pub const MAX_DIALOG_BRANCH_ID_BYTES: usize = 256;

/// Remote To-tag identity for one fork branch.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DialogBranchId(Box<str>);

impl DialogBranchId {
    /// Creates a bounded branch identifier.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized or control-containing values.
    pub fn new(value: impl Into<Box<str>>) -> Result<Self, ForkError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_DIALOG_BRANCH_ID_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(ForkError::InvalidBranchId);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for DialogBranchId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DialogBranchId")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Per-branch lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchState {
    /// Provisional response established an early dialog.
    Early,
    /// A 2xx established a confirmed dialog.
    Confirmed,
    /// Branch was rejected or cleaned up.
    Terminated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Branch {
    id: DialogBranchId,
    state: BranchState,
}

/// Fixed-bound set of fork branches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkSet {
    branches: Vec<Branch>,
}

impl ForkSet {
    /// Creates an empty set with reserved maximum storage.
    ///
    /// # Errors
    ///
    /// Returns allocation failure.
    pub fn new() -> Result<Self, ForkError> {
        let mut branches = Vec::new();
        branches
            .try_reserve_exact(MAX_FORKED_DIALOGS)
            .map_err(|_| ForkError::AllocationFailed)?;
        Ok(Self { branches })
    }

    /// Inserts or updates an early branch.
    ///
    /// # Errors
    ///
    /// Rejects capacity and allocation failures.
    pub fn note_early(&mut self, id: DialogBranchId) -> Result<(), ForkError> {
        self.upsert(id, BranchState::Early)
    }

    /// Inserts or confirms a branch; retransmitted 2xx is idempotent.
    ///
    /// # Errors
    ///
    /// Rejects capacity and allocation failures.
    pub fn note_confirmed(&mut self, id: DialogBranchId) -> Result<(), ForkError> {
        self.upsert(id, BranchState::Confirmed)
    }

    /// Marks a known or newly observed final branch terminated.
    ///
    /// # Errors
    ///
    /// Rejects capacity and allocation failures.
    pub fn note_terminated(&mut self, id: DialogBranchId) -> Result<(), ForkError> {
        self.upsert(id, BranchState::Terminated)
    }

    /// Returns branch lifecycle.
    #[must_use]
    pub fn state(&self, id: &DialogBranchId) -> Option<BranchState> {
        self.branches
            .iter()
            .find(|branch| &branch.id == id)
            .map(|branch| branch.state)
    }

    /// Returns whether any nonterminated branch remains.
    #[must_use]
    pub fn has_live_branches(&self) -> bool {
        self.branches
            .iter()
            .any(|branch| branch.state != BranchState::Terminated)
    }

    /// Returns total retained branches.
    #[must_use]
    pub fn len(&self) -> usize {
        self.branches.len()
    }

    /// Returns whether no branches are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.branches.is_empty()
    }

    fn upsert(&mut self, id: DialogBranchId, state: BranchState) -> Result<(), ForkError> {
        if let Some(branch) = self.branches.iter_mut().find(|branch| branch.id == id) {
            branch.state = state;
            return Ok(());
        }
        if self.branches.len() == MAX_FORKED_DIALOGS {
            return Err(ForkError::BranchLimitExceeded);
        }
        self.branches.push(Branch { id, state });
        Ok(())
    }
}

/// Fork branch failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkError {
    /// Remote tag was unsafe or outside bounds.
    InvalidBranchId,
    /// Per-call branch limit was reached.
    BranchLimitExceeded,
    /// Fixed branch storage could not be reserved.
    AllocationFailed,
}

impl fmt::Display for ForkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("forked dialog state failed")
    }
}

impl StdError for ForkError {}
