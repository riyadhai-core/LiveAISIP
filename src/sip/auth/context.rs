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

//! Stateful, scope-isolated SIP Digest authentication.

use super::challenge::{AuthChallenge, AuthParameter};
use super::digest::{DigestAuthorization, DigestCredentials, DigestError, DigestRequest};
use crate::sip::types::method::Method;
use std::error::Error as StdError;
use std::fmt;

/// Maximum stale-nonce recoveries per scope and call attempt.
pub const MAX_STALE_RECOVERIES: u8 = 2;
/// Maximum challenges evaluated in one response.
pub const MAX_AUTH_CHALLENGES: usize = 16;

/// Independent SIP authentication namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthScope {
    /// 401 / WWW-Authenticate / Authorization.
    Server,
    /// 407 / Proxy-Authenticate / Proxy-Authorization.
    Proxy,
}

#[derive(Clone)]
struct ScopeState {
    challenge: AuthChallenge,
    nonce_count: u32,
    stale_recoveries: u8,
}

/// Per-target authentication state with isolated 401 and 407 slots.
#[derive(Clone, Default)]
pub struct AuthContext {
    server: Option<ScopeState>,
    proxy: Option<ScopeState>,
}

impl AuthContext {
    /// Creates empty authentication state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            server: None,
            proxy: None,
        }
    }

    /// Selects and installs strongest supported Digest challenge for one scope.
    ///
    /// A stale replacement resets nonce count. Repeated non-stale nonce is
    /// treated as credential failure rather than retried forever.
    ///
    /// # Errors
    ///
    /// Rejects empty/excessive lists, unsupported challenges, repeated nonce,
    /// or stale retry exhaustion.
    pub fn install(
        &mut self,
        scope: AuthScope,
        challenges: &[AuthChallenge],
    ) -> Result<(), AuthContextError> {
        if challenges.is_empty() || challenges.len() > MAX_AUTH_CHALLENGES {
            return Err(AuthContextError::InvalidChallengeCount);
        }
        let selected = challenges
            .iter()
            .filter(|challenge| challenge.scheme().eq_ignore_ascii_case("Digest"))
            .filter_map(|challenge| {
                let strength = challenge_score(challenge);
                (strength != 0).then_some((strength, challenge))
            })
            .max_by_key(|(strength, _)| *strength)
            .map(|(_, challenge)| challenge)
            .ok_or(AuthContextError::NoSupportedChallenge)?;
        let nonce = selected
            .parameter("nonce")
            .ok_or(AuthContextError::MissingNonce)?
            .value();
        let stale = selected
            .parameter("stale")
            .is_some_and(|value| value.value().eq_ignore_ascii_case("true"));
        let previous = self.slot(scope);
        let stale_recoveries = match previous {
            Some(previous)
                if previous
                    .challenge
                    .parameter("nonce")
                    .is_some_and(|value| value.value() == nonce)
                    && !stale =>
            {
                return Err(AuthContextError::RepeatedChallenge);
            }
            Some(previous) if stale => previous
                .stale_recoveries
                .checked_add(1)
                .ok_or(AuthContextError::StaleLimitExceeded)?,
            _ => 0,
        };
        if stale_recoveries > MAX_STALE_RECOVERIES {
            return Err(AuthContextError::StaleLimitExceeded);
        }
        *self.slot_mut(scope) = Some(ScopeState {
            challenge: selected.clone(),
            nonce_count: 0,
            stale_recoveries,
        });
        Ok(())
    }

    /// Calculates next scoped authorization and increments nonce count only on success.
    ///
    /// # Errors
    ///
    /// Rejects absent challenge, count exhaustion and Digest calculation failure.
    pub fn authorize(
        &mut self,
        scope: AuthScope,
        credentials: &DigestCredentials,
        method: &Method,
        uri: &str,
        entity_body: &[u8],
        client_nonce: &str,
    ) -> Result<DigestAuthorization, AuthContextError> {
        let state = self
            .slot_mut(scope)
            .as_mut()
            .ok_or(AuthContextError::NoChallenge)?;
        let next = state
            .nonce_count
            .checked_add(1)
            .ok_or(AuthContextError::NonceCountExhausted)?;
        let authorization = DigestAuthorization::calculate(
            &state.challenge,
            credentials,
            DigestRequest {
                method,
                uri,
                entity_body,
                nonce_count: next,
                client_nonce,
            },
        )
        .map_err(AuthContextError::Digest)?;
        state.nonce_count = next;
        Ok(authorization)
    }

    /// Clears one scope without disturbing the other.
    pub fn clear(&mut self, scope: AuthScope) {
        *self.slot_mut(scope) = None;
    }

    /// Returns current nonce count for tests/telemetry.
    #[must_use]
    pub fn nonce_count(&self, scope: AuthScope) -> u32 {
        self.slot(scope).map_or(0, |state| state.nonce_count)
    }

    fn slot(&self, scope: AuthScope) -> Option<&ScopeState> {
        match scope {
            AuthScope::Server => self.server.as_ref(),
            AuthScope::Proxy => self.proxy.as_ref(),
        }
    }
    fn slot_mut(&mut self, scope: AuthScope) -> &mut Option<ScopeState> {
        match scope {
            AuthScope::Server => &mut self.server,
            AuthScope::Proxy => &mut self.proxy,
        }
    }
}

impl fmt::Debug for AuthContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthContext")
            .field("has_server_challenge", &self.server.is_some())
            .field("has_proxy_challenge", &self.proxy.is_some())
            .field("server_nonce_count", &self.nonce_count(AuthScope::Server))
            .field("proxy_nonce_count", &self.nonce_count(AuthScope::Proxy))
            .finish_non_exhaustive()
    }
}

fn challenge_score(challenge: &AuthChallenge) -> u8 {
    let algorithm = challenge.parameter("algorithm").map(AuthParameter::value);
    match algorithm {
        Some(value) if value.eq_ignore_ascii_case("SHA-256-sess") => 4,
        Some(value) if value.eq_ignore_ascii_case("SHA-256") => 3,
        None => 1,
        Some(value) if value.eq_ignore_ascii_case("MD5-sess") => 2,
        Some(value) if value.eq_ignore_ascii_case("MD5") => 1,
        _ => 0,
    }
}

/// Stateful authentication failure.
#[derive(Debug, Eq, PartialEq)]
pub enum AuthContextError {
    /// Challenge list was empty or excessive.
    InvalidChallengeCount,
    /// No supported Digest challenge was present.
    NoSupportedChallenge,
    /// Selected challenge lacked nonce.
    MissingNonce,
    /// Same non-stale challenge repeated after credentials were tried.
    RepeatedChallenge,
    /// Stale nonce recovery bound exceeded.
    StaleLimitExceeded,
    /// Scope has no installed challenge.
    NoChallenge,
    /// Nonce count exhausted without wrapping.
    NonceCountExhausted,
    /// Digest calculation failed.
    Digest(DigestError),
}
impl fmt::Display for AuthContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP authentication context failed")
    }
}
impl StdError for AuthContextError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Digest(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthContext, AuthContextError, AuthScope};
    use crate::sip::auth::{AuthChallenge, DigestAlgorithm, DigestCredentials};
    use crate::sip::types::method::Method;

    fn challenge(nonce: &str, stale: bool) -> AuthChallenge {
        let text = format!(
            "Digest realm=\"r\", nonce=\"{nonce}\", algorithm=SHA-256, qop=\"auth\", stale={stale}"
        );
        AuthChallenge::from_bytes(text.as_bytes()).unwrap_or_else(|_| panic!("challenge"))
    }

    #[test]
    fn server_and_proxy_counts_are_isolated() {
        let mut context = AuthContext::new();
        assert!(
            context
                .install(AuthScope::Server, &[challenge("s", false)])
                .is_ok()
        );
        assert!(
            context
                .install(AuthScope::Proxy, &[challenge("p", false)])
                .is_ok()
        );
        let credentials =
            DigestCredentials::new("u", "p").unwrap_or_else(|_| panic!("credentials"));
        assert!(
            context
                .authorize(
                    AuthScope::Server,
                    &credentials,
                    &Method::Invite,
                    "sip:x",
                    b"",
                    "c"
                )
                .is_ok()
        );
        assert_eq!(context.nonce_count(AuthScope::Server), 1);
        assert_eq!(context.nonce_count(AuthScope::Proxy), 0);
    }

    #[test]
    fn stale_resets_count_but_repeated_nonstale_stops_loop() {
        let mut context = AuthContext::new();
        assert!(
            context
                .install(AuthScope::Server, &[challenge("one", false)])
                .is_ok()
        );
        assert_eq!(
            context.install(AuthScope::Server, &[challenge("one", false)]),
            Err(AuthContextError::RepeatedChallenge)
        );
        assert!(
            context
                .install(AuthScope::Server, &[challenge("two", true)])
                .is_ok()
        );
        assert_eq!(context.nonce_count(AuthScope::Server), 0);
    }

    #[test]
    fn multiple_challenges_choose_strongest_supported_algorithm() {
        let md5 = AuthChallenge::from_bytes(
            b"Digest realm=\"r\", nonce=\"m\", algorithm=MD5, qop=\"auth\"",
        )
        .unwrap_or_else(|_| panic!("MD5 challenge"));
        let unsupported = AuthChallenge::from_bytes(
            b"Digest realm=\"r\", nonce=\"u\", algorithm=SHA-512, qop=\"auth\"",
        )
        .unwrap_or_else(|_| panic!("unsupported challenge"));
        let sha = challenge("s", false);
        let mut context = AuthContext::new();
        assert!(
            context
                .install(AuthScope::Server, &[md5, unsupported, sha])
                .is_ok()
        );
        let credentials =
            DigestCredentials::new("u", "p").unwrap_or_else(|_| panic!("credentials"));
        let authorization = context
            .authorize(
                AuthScope::Server,
                &credentials,
                &Method::Invite,
                "sip:x",
                b"",
                "c",
            )
            .unwrap_or_else(|_| panic!("authorization"));
        assert_eq!(authorization.algorithm(), DigestAlgorithm::Sha256);
    }
}
