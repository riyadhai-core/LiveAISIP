// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Canonical signaling message construction and response classification.

use std::sync::Arc;

use crate::call::model::branch::DialogBranchId;
use crate::call::model::events::CallEvent;
use crate::sip::builder::request::RequestBuilder;
use crate::sip::builder::response::ResponseBuilder;
use crate::sip::identifier::generate_wire_token;
use crate::sip::parser::message;
use crate::sip::transport::flow::IngressMeta;
use crate::sip::types::method::Method;
use crate::sip::types::status::StatusCode;
use crate::sip::validation::request::ValidatedRequest;
use crate::sip::validation::response::ValidatedResponse;

use super::error::SignalingError;

pub(super) fn build_response(
    request: &ValidatedRequest,
    ingress: &IngressMeta,
    status: StatusCode,
) -> Result<Arc<[u8]>, SignalingError> {
    let headers = request.core_headers();
    let via = ingress
        .response_via(headers.via())
        .map_err(SignalingError::Flow)?;
    let mut to = headers.to_header().clone();
    if to.tag().is_none() {
        let tag = generate_wire_token().map_err(SignalingError::WireToken)?;
        to.set_tag(tag).map_err(SignalingError::To)?;
    }
    let reason = status.default_reason_phrase().unwrap_or("Response");
    let bytes = ResponseBuilder::new(
        status,
        reason.as_bytes(),
        &via,
        headers.from_header(),
        &to,
        headers.call_id(),
        headers.cseq(),
    )
    .map_err(SignalingError::ResponseBuild)?
    .serialize()
    .map_err(SignalingError::ResponseBuild)?;
    Ok(Arc::from(bytes.into_boxed_slice()))
}

pub(super) fn serialize_and_validate(
    builder: RequestBuilder,
) -> Result<ValidatedRequest, SignalingError> {
    let request = builder
        .build()
        .serialize()
        .map_err(SignalingError::Serialize)?;
    let raw =
        message::parse(Arc::from(request.into_boxed_slice())).map_err(SignalingError::Parse)?;
    crate::sip::validation::request::validate(raw).map_err(SignalingError::ValidateRequest)
}

pub(super) fn response_event(
    response: &ValidatedResponse,
) -> Result<Option<CallEvent>, SignalingError> {
    let status = response.response_line().status().as_u16();
    let method = response.core_headers().cseq().method();
    if status == 100 || !(100..=699).contains(&status) {
        return Ok(None);
    }
    let tag = response
        .core_headers()
        .to_header()
        .tag()
        .unwrap_or("untagged-final");
    let branch = DialogBranchId::new(tag).map_err(SignalingError::Branch)?;
    Ok(match (method, status) {
        (Method::Invite, 101..=199) => Some(CallEvent::Provisional {
            branch,
            has_sdp: !response.message().body().is_empty(),
        }),
        (Method::Invite, 200..=299) => Some(CallEvent::InviteAccepted { branch }),
        (Method::Invite, 300..=699) => Some(CallEvent::InviteRejected { branch, status }),
        (Method::Cancel, 200..=299) => Some(CallEvent::CancelAccepted),
        (Method::Bye, 200..=299) => Some(CallEvent::ByeCompleted { branch }),
        _ => None,
    })
}
