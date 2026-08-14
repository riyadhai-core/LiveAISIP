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

//! Bounded REFER/Replaces construction and transfer subscription state.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::Write as _;

use super::events::TransferTarget;
use crate::sip::dialog::DialogId;
use crate::sip::types::header::{
    Header, HeaderName, HeaderNameError, HeaderValue, HeaderValueError,
};

/// Maximum generated Refer-To field bytes.
pub const MAX_REFER_TO_BYTES: usize = 16 * 1024;

/// Headers required by an outbound REFER request.
#[derive(Clone, Eq, PartialEq)]
pub struct TransferRequestHeaders {
    refer_to: Header,
}

impl TransferRequestHeaders {
    /// Builds a blind-transfer Refer-To header.
    ///
    /// # Errors
    ///
    /// Rejects an oversized value or allocation/header construction failure.
    pub fn blind(target: &TransferTarget) -> Result<Self, TransferError> {
        let value = format!("<{}>", target.uri());
        Self::from_value(&value)
    }

    /// Builds an attended-transfer Refer-To URI carrying an encoded Replaces
    /// dialog identifier.
    ///
    /// # Errors
    ///
    /// Rejects oversized generated values and allocation/header failures.
    pub fn attended(target: &TransferTarget, replaces: &DialogId) -> Result<Self, TransferError> {
        let target_text = target.uri().to_string();
        let separator = if target_text.contains('?') { '&' } else { '?' };
        let replaces_value = format!(
            "{};to-tag={};from-tag={}",
            replaces.call_id(),
            replaces.remote_tag(),
            replaces.local_tag()
        );
        let mut value = String::new();
        let reserve = target_text
            .len()
            .checked_add(replaces_value.len().saturating_mul(3))
            .and_then(|length| length.checked_add(14))
            .ok_or(TransferError::ValueTooLong)?;
        if reserve > MAX_REFER_TO_BYTES {
            return Err(TransferError::ValueTooLong);
        }
        value
            .try_reserve_exact(reserve)
            .map_err(|_| TransferError::AllocationFailed)?;
        write!(value, "<{target_text}{separator}Replaces=")
            .map_err(|_| TransferError::FormattingFailed)?;
        encode_query_component(&replaces_value, &mut value)?;
        value.push('>');
        Self::from_value(&value)
    }

    /// Returns the generated Refer-To field.
    #[must_use]
    pub const fn refer_to(&self) -> &Header {
        &self.refer_to
    }

    fn from_value(value: &str) -> Result<Self, TransferError> {
        if value.len() > MAX_REFER_TO_BYTES {
            return Err(TransferError::ValueTooLong);
        }
        let name = HeaderName::from_bytes(b"Refer-To").map_err(TransferError::HeaderName)?;
        let value =
            HeaderValue::from_bytes(value.as_bytes()).map_err(TransferError::HeaderValue)?;
        Ok(Self {
            refer_to: Header::new(name, value),
        })
    }
}

impl fmt::Debug for TransferRequestHeaders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransferRequestHeaders")
            .field("refer_to_bytes", &self.refer_to.value().len())
            .finish_non_exhaustive()
    }
}

fn encode_query_component(input: &str, output: &mut String) -> Result<(), TransferError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        if output.len() > MAX_REFER_TO_BYTES {
            return Err(TransferError::ValueTooLong);
        }
    }
    Ok(())
}

/// REFER subscription lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferState {
    /// REFER has been sent and awaits a final response.
    ReferPending,
    /// REFER was accepted and NOTIFY progress is expected.
    NotifyPending,
    /// Referenced operation completed successfully.
    Succeeded,
    /// REFER or the referenced operation failed.
    Failed,
}

impl TransferState {
    /// Returns whether no further transfer mutation is valid.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }
}

/// Result of one transfer-related NOTIFY.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferNotification {
    /// Status to send for the NOTIFY transaction.
    pub response_status: u16,
    /// Updated transfer lifecycle.
    pub state: TransferState,
    /// Status extracted from the message/sipfrag body.
    pub referred_status: u16,
}

/// One bounded outbound REFER subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferTracker {
    state: TransferState,
    notifications: u16,
}

impl TransferTracker {
    /// Creates state after REFER is emitted.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: TransferState::ReferPending,
            notifications: 0,
        }
    }

    /// Applies final REFER response status.
    ///
    /// # Errors
    ///
    /// Rejects provisional/invalid status, repeated finals, and terminal use.
    pub fn on_refer_response(&mut self, status: u16) -> Result<TransferState, TransferError> {
        if self.state != TransferState::ReferPending {
            return Err(TransferError::InvalidState);
        }
        self.state = match status {
            200..=299 => TransferState::NotifyPending,
            300..=699 => TransferState::Failed,
            _ => return Err(TransferError::InvalidStatus),
        };
        Ok(self.state)
    }

    /// Applies one validated message/sipfrag NOTIFY status.
    ///
    /// Every valid NOTIFY is acknowledged with 200, including terminal
    /// failure notifications. A terminated subscription cannot be reopened.
    ///
    /// # Errors
    ///
    /// Rejects use before REFER acceptance, invalid status, notification-count
    /// exhaustion, or use after terminal outcome.
    pub fn on_notify(
        &mut self,
        referred_status: u16,
        subscription_terminated: bool,
    ) -> Result<TransferNotification, TransferError> {
        if self.state != TransferState::NotifyPending {
            return Err(TransferError::InvalidState);
        }
        if !(100..=699).contains(&referred_status) {
            return Err(TransferError::InvalidStatus);
        }
        self.notifications = self
            .notifications
            .checked_add(1)
            .ok_or(TransferError::NotificationLimitExceeded)?;
        self.state = if (200..=299).contains(&referred_status) {
            TransferState::Succeeded
        } else if referred_status >= 300 || subscription_terminated {
            TransferState::Failed
        } else {
            TransferState::NotifyPending
        };
        Ok(TransferNotification {
            response_status: 200,
            state: self.state,
            referred_status,
        })
    }

    /// Returns current transfer lifecycle.
    #[must_use]
    pub const fn state(self) -> TransferState {
        self.state
    }

    /// Returns accepted NOTIFY count.
    #[must_use]
    pub const fn notifications(self) -> u16 {
        self.notifications
    }
}

impl Default for TransferTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Transfer construction or state failure.
#[derive(Debug)]
pub enum TransferError {
    /// Refer-To exceeded its hard bound.
    ValueTooLong,
    /// Fixed construction allocation failed.
    AllocationFailed,
    /// In-memory formatting failed.
    FormattingFailed,
    /// Refer-To header name construction failed.
    HeaderName(HeaderNameError),
    /// Refer-To header value construction failed.
    HeaderValue(HeaderValueError),
    /// Event was invalid for current transfer lifecycle.
    InvalidState,
    /// SIP or sipfrag status was outside the required range.
    InvalidStatus,
    /// More than `u16::MAX` NOTIFY messages were received.
    NotificationLimitExceeded,
}

impl fmt::Display for TransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP transfer operation failed")
    }
}

impl StdError for TransferError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::HeaderName(error) => Some(error),
            Self::HeaderValue(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TransferRequestHeaders, TransferState, TransferTracker};
    use crate::call::TransferTarget;
    use crate::sip::dialog::DialogId;
    use crate::sip::headers::call_id::CallId;

    #[test]
    fn constructs_blind_and_attended_refer_to() {
        let target =
            TransferTarget::parse("sip:agent@example.com").unwrap_or_else(|_| panic!("target"));
        let blind =
            TransferRequestHeaders::blind(&target).unwrap_or_else(|_| panic!("blind headers"));
        assert_eq!(
            blind.refer_to().value().as_bytes(),
            b"<sip:agent@example.com>"
        );

        let dialog = DialogId::new(
            CallId::new("private@example.com").unwrap_or_else(|_| panic!("call id")),
            "local",
            "remote",
        )
        .unwrap_or_else(|_| panic!("dialog"));
        let attended = TransferRequestHeaders::attended(&target, &dialog)
            .unwrap_or_else(|_| panic!("attended headers"));
        let value = attended.refer_to().value().as_bytes();
        assert!(value.starts_with(b"<sip:agent@example.com?Replaces="));
        assert!(value.windows(3).any(|window| window == b"%3B"));
        assert!(!format!("{attended:?}").contains("private@example.com"));
    }

    #[test]
    fn refer_and_notify_drive_terminal_outcome() {
        let mut transfer = TransferTracker::new();
        assert!(matches!(
            transfer.on_refer_response(202),
            Ok(TransferState::NotifyPending)
        ));
        let progress = transfer
            .on_notify(180, false)
            .unwrap_or_else(|_| panic!("progress"));
        assert_eq!(progress.response_status, 200);
        assert_eq!(progress.state, TransferState::NotifyPending);
        let complete = transfer
            .on_notify(200, true)
            .unwrap_or_else(|_| panic!("complete"));
        assert_eq!(complete.state, TransferState::Succeeded);
        assert!(transfer.on_notify(200, true).is_err());
    }
}
