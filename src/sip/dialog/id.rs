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

//! Owned SIP dialog identifiers.
//!
//! A dialog is identified by its `Call-ID` and the local and remote tags. Tag
//! orientation is deliberately local to this user agent, making the key stable
//! across inbound and outbound in-dialog messages. Values are case-sensitive,
//! bounded, and redacted from diagnostic formatting.

use std::error::Error as StdError;
use std::fmt;

use crate::sip::headers::call_id::CallId;
use crate::sip::headers::from::MAX_FROM_TAG_BYTES;
use crate::sip::headers::to::MAX_TO_TAG_BYTES;
use crate::sip::validation::response::ValidatedResponse;

/// Maximum accepted dialog-tag size in bytes.
pub const MAX_DIALOG_TAG_BYTES: usize = if MAX_FROM_TAG_BYTES < MAX_TO_TAG_BYTES {
    MAX_FROM_TAG_BYTES
} else {
    MAX_TO_TAG_BYTES
};

/// An owned, role-oriented SIP dialog identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DialogId {
    call_id: CallId,
    local_tag: Box<str>,
    remote_tag: Box<str>,
}

impl DialogId {
    /// Creates a dialog identifier from validated components.
    ///
    /// # Errors
    ///
    /// Returns [`DialogIdError`] when either tag is empty, too long, or is not
    /// a SIP token.
    pub fn new(
        call_id: CallId,
        local_tag: impl Into<Box<str>>,
        remote_tag: impl Into<Box<str>>,
    ) -> Result<Self, DialogIdError> {
        let local_tag = local_tag.into();
        let remote_tag = remote_tag.into();
        validate_tag(&local_tag, TagRole::Local)?;
        validate_tag(&remote_tag, TagRole::Remote)?;

        Ok(Self {
            call_id,
            local_tag,
            remote_tag,
        })
    }

    /// Derives the dialog identifier established by a response to a locally
    /// initiated request.
    ///
    /// The request's `From` tag is local and the response's `To` tag is
    /// remote. Provisional responses without a `To` tag do not establish an
    /// early dialog and are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`DialogIdError::MissingTag`] when either required tag is
    /// absent.
    pub fn from_uac_response(response: &ValidatedResponse) -> Result<Self, DialogIdError> {
        let headers = response.core_headers();
        let local_tag = headers
            .from_header()
            .tag()
            .ok_or(DialogIdError::MissingTag(TagRole::Local))?;
        let remote_tag = headers
            .to_header()
            .tag()
            .ok_or(DialogIdError::MissingTag(TagRole::Remote))?;

        Self::new(headers.call_id().clone(), local_tag, remote_tag)
    }

    /// Returns the dialog's `Call-ID`.
    #[must_use]
    pub const fn call_id(&self) -> &CallId {
        &self.call_id
    }

    /// Returns the tag owned by this user agent.
    #[must_use]
    pub const fn local_tag(&self) -> &str {
        &self.local_tag
    }

    /// Returns the tag owned by the remote user agent.
    #[must_use]
    pub const fn remote_tag(&self) -> &str {
        &self.remote_tag
    }
}

impl fmt::Debug for DialogId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DialogId")
            .field("call_id_bytes", &self.call_id.len())
            .field("local_tag_bytes", &self.local_tag.len())
            .field("remote_tag_bytes", &self.remote_tag.len())
            .finish_non_exhaustive()
    }
}

/// The ownership side of a dialog tag.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TagRole {
    /// The tag owned by this user agent.
    Local,
    /// The tag owned by the remote user agent.
    Remote,
}

impl fmt::Display for TagRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Local => "local",
            Self::Remote => "remote",
        })
    }
}

/// A dialog-identifier construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DialogIdError {
    /// A required tag was absent.
    MissingTag(TagRole),
    /// A tag was present but empty.
    EmptyTag(TagRole),
    /// A tag exceeded the operational bound.
    TagTooLong {
        /// The tag's ownership side.
        role: TagRole,
        /// Observed byte length.
        length: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
    /// A tag contained a byte outside the SIP token grammar.
    InvalidTag {
        /// The tag's ownership side.
        role: TagRole,
        /// Offset of the invalid byte.
        index: usize,
    },
}

impl fmt::Display for DialogIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTag(role) => write!(formatter, "missing {role} dialog tag"),
            Self::EmptyTag(role) => write!(formatter, "{role} dialog tag is empty"),
            Self::TagTooLong {
                role,
                length,
                maximum,
            } => write!(
                formatter,
                "{role} dialog tag is {length} bytes; maximum is {maximum}"
            ),
            Self::InvalidTag { role, index } => {
                write!(
                    formatter,
                    "{role} dialog tag has an invalid byte at index {index}"
                )
            }
        }
    }
}

impl StdError for DialogIdError {}

fn validate_tag(tag: &str, role: TagRole) -> Result<(), DialogIdError> {
    if tag.is_empty() {
        return Err(DialogIdError::EmptyTag(role));
    }
    if tag.len() > MAX_DIALOG_TAG_BYTES {
        return Err(DialogIdError::TagTooLong {
            role,
            length: tag.len(),
            maximum: MAX_DIALOG_TAG_BYTES,
        });
    }
    if let Some(index) = tag.bytes().position(|byte| !is_token_byte(byte)) {
        return Err(DialogIdError::InvalidTag { role, index });
    }
    Ok(())
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::sip::parser::message::parse;
    use crate::sip::validation;

    use super::{DialogId, DialogIdError, MAX_DIALOG_TAG_BYTES, TagRole};

    fn response(to_tag: Option<&str>) -> validation::response::ValidatedResponse {
        let to = to_tag.map_or_else(
            || "<sip:service@example.net>".to_owned(),
            |tag| format!("<sip:service@example.net>;tag={tag}"),
        );
        let bytes = format!(
            "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP client.example.org;branch=z9hG4bK-redacted\r\n\
From: <sip:caller@example.org>;tag=LocalTag\r\n\
To: {to}\r\n\
Call-ID: private-call@example.org\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n"
        );
        let Ok(raw) = parse(Arc::from(bytes.into_bytes())) else {
            panic!("response must parse")
        };
        let Ok(response) = validation::response::validate(raw) else {
            panic!("response must validate")
        };
        response
    }

    #[test]
    fn derives_role_oriented_uac_identity() {
        let Ok(id) = DialogId::from_uac_response(&response(Some("RemoteTag"))) else {
            panic!("dialog id must build")
        };
        assert_eq!(id.call_id().as_str(), "private-call@example.org");
        assert_eq!(id.local_tag(), "LocalTag");
        assert_eq!(id.remote_tag(), "RemoteTag");
    }

    #[test]
    fn response_without_remote_tag_does_not_establish_dialog() {
        assert_eq!(
            DialogId::from_uac_response(&response(None)),
            Err(DialogIdError::MissingTag(TagRole::Remote))
        );
    }

    #[test]
    fn validates_both_tags_and_preserves_case() {
        let call_id = crate::sip::headers::call_id::CallId::new("id@example.org")
            .unwrap_or_else(|_| panic!("call id"));
        let Ok(upper) = DialogId::new(call_id.clone(), "AbC", "XyZ") else {
            panic!("valid tags")
        };
        let Ok(lower) = DialogId::new(call_id, "abc", "XyZ") else {
            panic!("valid tags")
        };
        assert_ne!(upper, lower);

        assert_eq!(
            DialogId::new(upper.call_id().clone(), "bad tag", "remote"),
            Err(DialogIdError::InvalidTag {
                role: TagRole::Local,
                index: 3,
            })
        );
        let long = "a".repeat(MAX_DIALOG_TAG_BYTES + 1);
        assert!(matches!(
            DialogId::new(upper.call_id().clone(), "local", long),
            Err(DialogIdError::TagTooLong {
                role: TagRole::Remote,
                ..
            })
        ));
    }

    #[test]
    fn debug_output_is_redacted() {
        let Ok(id) = DialogId::from_uac_response(&response(Some("SecretRemote"))) else {
            panic!("dialog id must build")
        };
        let debug = format!("{id:?}");
        assert!(!debug.contains("private-call"));
        assert!(!debug.contains("LocalTag"));
        assert!(!debug.contains("SecretRemote"));
        assert!(debug.contains("call_id_bytes"));
    }
}
