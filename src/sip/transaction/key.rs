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

//! RFC 3261 transaction matching keys.
//!
//! Keys contain the topmost Via branch, sent-by host and port, and CSeq
//! method. RFC 3261 magic-cookie branches are mandatory at this modern
//! transaction boundary; legacy fallback matching is intentionally excluded.
//! For server matching only, ACK normalizes to INVITE so a non-2xx ACK reaches
//! its INVITE server transaction. CANCEL remains a distinct transaction.

use std::error::Error as StdError;
use std::fmt;

use crate::sip::types::method::Method;
use crate::sip::types::uri::Host;
use crate::sip::validation::request::ValidatedRequest;
use crate::sip::validation::response::ValidatedResponse;

/// Owned privacy-safe transaction lookup key.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct TransactionKey {
    branch: Box<str>,
    sent_by_host: Host,
    sent_by_port: Option<u16>,
    method: Method,
}

impl TransactionKey {
    /// Creates the key used to register an outbound client transaction.
    ///
    /// # Errors
    ///
    /// Requires an RFC 3261 branch cookie in the topmost Via.
    pub fn for_client_request(request: &ValidatedRequest) -> Result<Self, KeyError> {
        Self::from_parts(
            request.core_headers().topmost_via(),
            request.core_headers().cseq().method().clone(),
        )
    }

    /// Creates the key used to match a response to a client transaction.
    ///
    /// # Errors
    ///
    /// Requires an RFC 3261 branch cookie in the echoed topmost Via.
    pub fn for_client_response(response: &ValidatedResponse) -> Result<Self, KeyError> {
        Self::from_parts(
            response.core_headers().topmost_via(),
            response.core_headers().cseq().method().clone(),
        )
    }

    /// Creates the key used to match an inbound request to server state.
    ///
    /// ACK is normalized to INVITE. CANCEL and every other method retain their
    /// identity.
    ///
    /// # Errors
    ///
    /// Requires an RFC 3261 branch cookie in the topmost Via.
    pub fn for_server_request(request: &ValidatedRequest) -> Result<Self, KeyError> {
        let method = match request.core_headers().cseq().method() {
            Method::Ack => Method::Invite,
            method => method.clone(),
        };
        Self::from_parts(request.core_headers().topmost_via(), method)
    }

    fn from_parts(
        via: &crate::sip::headers::via::ViaEntry,
        method: Method,
    ) -> Result<Self, KeyError> {
        let branch = via.branch().ok_or(KeyError::MissingBranch)?;
        if !via.has_rfc3261_branch_cookie() {
            return Err(KeyError::LegacyBranch);
        }
        Ok(Self {
            branch: branch.into(),
            sent_by_host: via.sent_by_host().clone(),
            sent_by_port: via.sent_by_port(),
            method,
        })
    }

    /// Returns the transaction method after role-specific normalization.
    #[must_use]
    pub const fn method(&self) -> &Method {
        &self.method
    }

    /// Returns whether the key represents an INVITE transaction.
    #[must_use]
    pub const fn is_invite(&self) -> bool {
        matches!(self.method, Method::Invite)
    }
}

impl fmt::Debug for TransactionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionKey")
            .field("branch_bytes", &self.branch.len())
            .field("sent_by_port_present", &self.sent_by_port.is_some())
            .field("method", &self.method.as_str())
            .finish_non_exhaustive()
    }
}

/// Failure to construct a modern transaction key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyError {
    /// Topmost Via omitted branch.
    MissingBranch,
    /// Branch did not begin with the RFC 3261 magic cookie.
    LegacyBranch,
}

impl KeyError {
    /// Returns a stable low-cardinality classification.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::MissingBranch => "missing-branch",
            Self::LegacyBranch => "legacy-branch",
        }
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SIP transaction key error: {}", self.class())
    }
}

impl StdError for KeyError {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{KeyError, TransactionKey};
    use crate::sip::parser::message::parse;
    use crate::sip::types::method::Method;
    use crate::sip::validation;

    fn request(method: &str, branch: &str) -> validation::request::ValidatedRequest {
        let branch_parameter = if branch.is_empty() {
            String::new()
        } else {
            format!(";branch={branch}")
        };
        let bytes = format!(
            "{method} sip:x@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP host.example.com{branch_parameter}\r\n\
From: <sip:a@example.com>;tag=a\r\nTo: <sip:x@example.com>\r\n\
Call-ID: private@example.com\r\nCSeq: 1 {method}\r\n\
Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
        );
        let Ok(raw) = parse(Arc::from(bytes.into_bytes())) else {
            panic!("parse")
        };
        let Ok(request) = validation::request::validate(raw) else {
            panic!("validate")
        };
        request
    }

    #[test]
    fn client_and_server_keys_match_for_normal_method() {
        let request = request("BYE", "z9hG4bK-private");
        let Ok(client) = TransactionKey::for_client_request(&request) else {
            panic!("key")
        };
        let Ok(server) = TransactionKey::for_server_request(&request) else {
            panic!("key")
        };
        assert_eq!(client, server);
        assert_eq!(client.method(), &Method::Bye);
    }

    #[test]
    fn server_ack_normalizes_but_cancel_does_not() {
        let ack = request("ACK", "z9hG4bK-one");
        let cancel = request("CANCEL", "z9hG4bK-one");
        let Ok(ack_key) = TransactionKey::for_server_request(&ack) else {
            panic!("key")
        };
        let Ok(cancel_key) = TransactionKey::for_server_request(&cancel) else {
            panic!("key")
        };
        assert_eq!(ack_key.method(), &Method::Invite);
        assert_eq!(cancel_key.method(), &Method::Cancel);
        assert_ne!(ack_key, cancel_key);
    }

    #[test]
    fn rejects_missing_and_legacy_branches() {
        let missing = request("OPTIONS", "");
        assert!(matches!(
            TransactionKey::for_client_request(&missing),
            Err(KeyError::MissingBranch)
        ));
        let legacy = request("OPTIONS", "legacy");
        assert!(matches!(
            TransactionKey::for_client_request(&legacy),
            Err(KeyError::LegacyBranch)
        ));
    }

    #[test]
    fn debug_redacts_branch_and_host() {
        let request = request("INVITE", "z9hG4bK-private-secret");
        let Ok(key) = TransactionKey::for_client_request(&request) else {
            panic!("key")
        };
        let debug = format!("{key:?}");
        assert!(!debug.contains("private-secret"));
        assert!(!debug.contains("host.example.com"));
    }
}
