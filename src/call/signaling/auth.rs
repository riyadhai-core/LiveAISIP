// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Digest-challenge extraction and retry-header policy.

use crate::sip::auth::{AuthChallenge, AuthScope};
use crate::sip::types::header::HeaderKind;
use crate::sip::validation::headers::{
    analyze_logical_value, materialize_logical_value, trim_horizontal_whitespace,
};
use crate::sip::validation::response::ValidatedResponse;

use super::error::SignalingError;

pub(super) const fn is_retry_managed_header(kind: HeaderKind) -> bool {
    matches!(
        kind,
        HeaderKind::Via
            | HeaderKind::From
            | HeaderKind::To
            | HeaderKind::CallId
            | HeaderKind::CSeq
            | HeaderKind::MaxForwards
            | HeaderKind::ContentLength
            | HeaderKind::ContentType
            | HeaderKind::Authorization
            | HeaderKind::ProxyAuthorization
    )
}

pub(super) fn collect_challenges(
    response: &ValidatedResponse,
    scope: AuthScope,
) -> Result<Vec<AuthChallenge>, SignalingError> {
    let expected = match scope {
        AuthScope::Server => HeaderKind::WwwAuthenticate,
        AuthScope::Proxy => HeaderKind::ProxyAuthenticate,
    };
    let mut challenges = Vec::new();
    for field in response.message().header_views() {
        if field.kind().copied() != Some(expected) {
            continue;
        }
        let analysis =
            analyze_logical_value(field.value()).map_err(SignalingError::HeaderNormalization)?;
        let logical =
            materialize_logical_value(analysis).map_err(SignalingError::HeaderNormalization)?;
        let value = trim_horizontal_whitespace(logical.as_ref());
        let challenge = AuthChallenge::from_bytes(value).map_err(SignalingError::Challenge)?;
        challenges
            .try_reserve_exact(1)
            .map_err(|_| SignalingError::AllocationFailed)?;
        challenges.push(challenge);
    }
    Ok(challenges)
}
