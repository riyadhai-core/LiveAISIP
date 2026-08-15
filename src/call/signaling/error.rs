// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Call-owned signaling failure taxonomy.

use std::error::Error as StdError;
use std::fmt;

/// Executable UDP signaling failure.
#[derive(Debug)]
pub enum SignalingError {
    /// A wildcard client bind could not be resolved to a concrete route source.
    OutboundBind(crate::net::address::OutboundBindError),
    /// Concrete remote endpoint was invalid.
    Destination(crate::sip::transport::destination::DestinationError),
    /// UDP socket, receive, parse, validation, or send failed.
    Driver(crate::sip::transport::udp_driver::UdpDriverError),
    /// Datagram exceeded UDP admission policy.
    Udp(crate::sip::transport::udp::UdpError),
    /// Client transaction construction failed.
    Client(crate::sip::transaction::client::ClientError),
    /// Server transaction construction failed.
    Server(crate::sip::transaction::server::ServerError),
    /// Transaction manager rejected an operation.
    Transactions(crate::sip::transaction::manager::ManagerError),
    /// Shared deadline scheduler rejected an operation.
    Deadlines(crate::call::execution::deadline::DeadlineError),
    /// Initial request was not INVITE.
    InitialRequestNotInvite,
    /// Initial INVITE omitted request-mandatory Max-Forwards.
    InitialInviteMissingMaxForwards,
    /// Initial INVITE was installed more than once.
    InitialInviteAlreadyInstalled,
    /// Start occurred before an initial INVITE was installed.
    InitialInviteMissing,
    /// Bounded transaction timer table filled.
    TimerCapacity,
    /// Fixed storage allocation failed.
    AllocationFailed,
    /// Monotonic deadline overflowed.
    TimeOverflow,
    /// Response dialog branch was invalid.
    Branch(crate::call::model::branch::ForkError),
    /// A generated Via value was invalid.
    Via(crate::sip::headers::via::ParseError),
    /// A generated `CSeq` value was invalid.
    CSeq(crate::sip::headers::cseq::ParseError),
    /// A generated request violated builder invariants.
    Build(crate::sip::builder::request::BuildError),
    /// Canonical generated request serialization failed.
    Serialize(crate::sip::serializer::message::SerializeError),
    /// Generated request parsing unexpectedly failed.
    Parse(crate::sip::parser::message::ParseError),
    /// Generated request semantic validation unexpectedly failed.
    ValidateRequest(crate::sip::validation::request::ValidationError),
    /// Cryptographically strong SIP wire-token generation failed.
    WireToken(crate::sip::identifier::WireTokenError),
    /// Inbound request transport metadata could not form a response Via.
    Flow(crate::sip::transport::flow::FlowError),
    /// Inbound response To-tag generation violated typed header bounds.
    To(crate::sip::headers::to::ParseError),
    /// Canonical inbound SIP response construction failed.
    ResponseBuild(crate::sip::builder::response::BuildError),
    /// Transport produced an internally inconsistent inbound message variant.
    InvalidInboundMessage,
    /// In-dialog action referenced an unknown fork branch.
    UnknownDialogBranch,
    /// A dialog-forming response or request had invalid identity.
    DialogId(crate::sip::dialog::DialogIdError),
    /// The authoritative dialog registry rejected an operation.
    Dialogs(crate::sip::dialog::DialogManagerError),
    /// Authoritative dialog state rejected an operation.
    Dialog(crate::sip::dialog::DialogError),
    /// The deterministic branch identity disagreed with the response To-tag.
    DialogBranchMismatch,
    /// The initial UAC From field lacked the required local tag.
    MissingLocalDialogTag,
    /// No further in-dialog `CSeq` could be represented.
    SequenceExhausted,
    /// Generated Via address was not reachable or did not match the socket port.
    InvalidAdvertisedAddress,
    /// A raw initial or challenge header could not be safely unfolded.
    HeaderNormalization(crate::sip::validation::headers::LogicalValueError),
    /// A preserved initial extension header name was invalid.
    HeaderName(crate::sip::types::header::HeaderNameError),
    /// A preserved initial extension header value was invalid.
    HeaderValue(crate::sip::types::header::HeaderValueError),
    /// A received authentication challenge was invalid.
    Challenge(crate::sip::auth::ChallengeParseError),
    /// Stateful Digest authentication rejected the challenge or calculation.
    Authentication(crate::sip::auth::AuthContextError),
    /// Calculated origin-server credentials violated an internal invariant.
    Authorization(crate::sip::headers::authorization::ParseError),
    /// Calculated proxy credentials violated an internal invariant.
    ProxyAuthorization(crate::sip::headers::proxy_authorization::ParseError),
    /// A dialog-forming response carried an invalid Contact field.
    Contact(crate::sip::headers::contact::ParseError),
    /// A dialog-forming response lacked one unambiguous remote Contact target.
    InvalidDialogContact,
    /// A dialog-forming response carried an invalid Record-Route field.
    RecordRoute(crate::sip::headers::record_route::ParseError),
    /// The aggregate dialog route set exceeded its operational bound.
    DialogRoute(crate::sip::dialog::route::DialogRouteError),
    /// Generated in-dialog Route fields violated their bounded grammar.
    Route(crate::sip::headers::route::ParseError),
}

impl fmt::Display for SignalingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("call-owned SIP signaling failed")
    }
}

impl StdError for SignalingError {}
