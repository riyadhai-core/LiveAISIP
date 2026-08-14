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

//! Serialized and atomic negotiated-media ownership.

use crate::sip::dialog::{Dialog, DialogError};
use crate::sip::sdp::{NegotiatedMedia, OfferAnswer, OfferAnswerError, OfferToken};
use crate::sip::types::uri::Uri;
use std::error::Error as StdError;
use std::fmt;
use std::net::SocketAddr;

/// Per-generation media worker lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaLifecycle {
    /// Packet, timer and AI work is accepted.
    Active,
    /// New AI transmit audio is fenced while committed work drains.
    Draining,
    /// Every media resource is retired.
    Closed,
}

/// Generation token attached to packet, timer and DSP work.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MediaWorkToken(u64);

impl MediaWorkToken {
    /// Returns opaque media generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.0
    }
}

/// Ordered graceful media shutdown operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaShutdownAction {
    /// Reject new AI transmit frames.
    FenceAiTransmit,
    /// Finish the single already-committed RTP packet.
    FlushCommittedRtp,
    /// Emit RTCP BYE while the control socket remains live.
    SendRtcpBye,
    /// Stop the deterministic ten-millisecond media clock.
    StopMediaClock,
    /// Close `NetEq`, resampler and APM state.
    CloseDsp,
    /// Destroy SRTP/SRTCP contexts.
    DestroySecurityContexts,
    /// Close bound RTP/RTCP sockets.
    CloseSockets,
    /// Release the bound port lease.
    ReleasePortLease,
    /// Wake and close native/Python audio queues last.
    CloseAudioQueues,
}

/// Builds the one legal media teardown sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaShutdownPlan {
    has_committed_packet: bool,
    rtcp_active: bool,
}

impl MediaShutdownPlan {
    /// Captures resources that require protocol-visible draining.
    #[must_use]
    pub const fn new(has_committed_packet: bool, rtcp_active: bool) -> Self {
        Self {
            has_committed_packet,
            rtcp_active,
        }
    }

    /// Returns the deterministic teardown order.
    #[must_use]
    pub fn actions(self) -> Vec<MediaShutdownAction> {
        let mut actions = Vec::with_capacity(9);
        actions.push(MediaShutdownAction::FenceAiTransmit);
        if self.has_committed_packet {
            actions.push(MediaShutdownAction::FlushCommittedRtp);
        }
        if self.rtcp_active {
            actions.push(MediaShutdownAction::SendRtcpBye);
        }
        actions.extend([
            MediaShutdownAction::StopMediaClock,
            MediaShutdownAction::CloseDsp,
            MediaShutdownAction::DestroySecurityContexts,
            MediaShutdownAction::CloseSockets,
            MediaShutdownAction::ReleasePortLease,
            MediaShutdownAction::CloseAudioQueues,
        ]);
        actions
    }
}

/// Immutable active-media generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveMedia {
    generation: u64,
    negotiated: NegotiatedMedia,
    remote_rtp: SocketAddr,
}

impl ActiveMedia {
    /// Returns monotonic reconfiguration generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Returns negotiated codec/direction/security/packetization.
    #[must_use]
    pub const fn negotiated(&self) -> &NegotiatedMedia {
        &self.negotiated
    }
    /// Returns signaling-authorized RTP destination.
    #[must_use]
    pub const fn remote_rtp(&self) -> SocketAddr {
        self.remote_rtp
    }
}

/// Dialog-scoped media controller; no other task may replace active media.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaController {
    offers: OfferAnswer,
    active: Option<ActiveMedia>,
    next_generation: u64,
    require_secure: bool,
    lifecycle: MediaLifecycle,
}

/// Single-owner dialog and media state committed as one reconfiguration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DialogMediaOwner {
    dialog: Dialog,
    media: MediaController,
}

impl DialogMediaOwner {
    /// Creates one atomic dialog/media ownership boundary.
    #[must_use]
    pub const fn new(dialog: Dialog, media: MediaController) -> Self {
        Self { dialog, media }
    }

    /// Returns immutable dialog state.
    #[must_use]
    pub const fn dialog(&self) -> &Dialog {
        &self.dialog
    }

    /// Returns immutable negotiated-media state.
    #[must_use]
    pub const fn media(&self) -> &MediaController {
        &self.media
    }

    /// Atomically applies a remote re-INVITE/UPDATE offer, optional Contact
    /// target refresh, negotiated SDP, and RTP endpoint.
    ///
    /// The live state remains untouched if glare, dialog validation, media
    /// security, endpoint validation, or generation allocation fails.
    ///
    /// # Errors
    ///
    /// Preserves dialog and media-control failures.
    pub fn apply_remote_reconfiguration(
        &mut self,
        remote_target: Option<Uri>,
        negotiated: NegotiatedMedia,
        remote_rtp: SocketAddr,
    ) -> Result<u64, DialogMediaError> {
        let mut next_dialog = self.dialog.clone();
        let mut next_media = self.media.clone();
        let token = next_media
            .begin_remote_offer()
            .map_err(DialogMediaError::Media)?;
        if let Some(target) = remote_target {
            next_dialog
                .update_remote_target(target)
                .map_err(DialogMediaError::Dialog)?;
        }
        let generation = next_media
            .apply_local_answer(token, negotiated, remote_rtp)
            .map_err(DialogMediaError::Media)?
            .generation();
        self.dialog = next_dialog;
        self.media = next_media;
        Ok(generation)
    }
}

impl MediaController {
    /// Creates stable media ownership policy.
    #[must_use]
    pub const fn new(require_secure: bool) -> Self {
        Self {
            offers: OfferAnswer::new(),
            active: None,
            next_generation: 1,
            require_secure,
            lifecycle: MediaLifecycle::Active,
        }
    }

    /// Begins a local offer.
    ///
    /// # Errors
    ///
    /// Rejects glare or generation exhaustion.
    pub fn begin_local_offer(&mut self) -> Result<OfferToken, MediaControlError> {
        self.offers
            .begin_local_offer()
            .map_err(MediaControlError::OfferAnswer)
    }

    /// Begins a remote re-INVITE/UPDATE offer.
    ///
    /// # Errors
    ///
    /// Rejects overlap; caller maps glare to SIP 491.
    pub fn begin_remote_offer(&mut self) -> Result<OfferToken, MediaControlError> {
        self.offers
            .begin_remote_offer()
            .map_err(MediaControlError::OfferAnswer)
    }

    /// Atomically commits remote answer to a local offer.
    ///
    /// # Errors
    ///
    /// Rejects stale negotiation, insecure downgrade, invalid endpoint or generation exhaustion.
    pub fn apply_remote_answer(
        &mut self,
        token: OfferToken,
        negotiated: NegotiatedMedia,
        remote_rtp: SocketAddr,
    ) -> Result<&ActiveMedia, MediaControlError> {
        self.validate_media(&negotiated, remote_rtp)?;
        self.offers
            .apply_remote_answer(token)
            .map_err(MediaControlError::OfferAnswer)?;
        self.replace(negotiated, remote_rtp)
    }

    /// Atomically commits local answer to a remote offer.
    ///
    /// # Errors
    ///
    /// Rejects stale negotiation, insecure downgrade, invalid endpoint or generation exhaustion.
    pub fn apply_local_answer(
        &mut self,
        token: OfferToken,
        negotiated: NegotiatedMedia,
        remote_rtp: SocketAddr,
    ) -> Result<&ActiveMedia, MediaControlError> {
        self.validate_media(&negotiated, remote_rtp)?;
        self.offers
            .apply_local_answer(token)
            .map_err(MediaControlError::OfferAnswer)?;
        self.replace(negotiated, remote_rtp)
    }

    /// Returns current immutable generation.
    #[must_use]
    pub const fn active(&self) -> Option<&ActiveMedia> {
        self.active.as_ref()
    }

    /// Returns current worker lifecycle.
    #[must_use]
    pub const fn lifecycle(&self) -> MediaLifecycle {
        self.lifecycle
    }

    /// Returns a generation token only while media accepts new work.
    #[must_use]
    pub fn work_token(&self) -> Option<MediaWorkToken> {
        (self.lifecycle == MediaLifecycle::Active)
            .then(|| {
                self.active
                    .as_ref()
                    .map(|media| MediaWorkToken(media.generation))
            })
            .flatten()
    }

    /// Checks that queued work still belongs to active media.
    #[must_use]
    pub fn accepts(&self, token: MediaWorkToken) -> bool {
        self.lifecycle == MediaLifecycle::Active
            && self
                .active
                .as_ref()
                .is_some_and(|media| media.generation == token.0)
    }

    /// Fences new work while preserving resources for ordered draining.
    pub fn begin_draining(&mut self) -> bool {
        if self.lifecycle != MediaLifecycle::Active {
            return false;
        }
        self.lifecycle = MediaLifecycle::Draining;
        true
    }

    /// Marks teardown complete. Repeated close is idempotent.
    pub fn close(&mut self) -> bool {
        if self.lifecycle == MediaLifecycle::Closed {
            return false;
        }
        self.lifecycle = MediaLifecycle::Closed;
        self.active = None;
        true
    }

    fn validate_media(
        &self,
        media: &NegotiatedMedia,
        endpoint: SocketAddr,
    ) -> Result<(), MediaControlError> {
        if endpoint.port() == 0 || endpoint.ip().is_unspecified() {
            return Err(MediaControlError::InvalidRemoteEndpoint);
        }
        if self.require_secure && !media.protocol().is_secure() {
            return Err(MediaControlError::SecurityDowngrade);
        }
        Ok(())
    }

    fn replace(
        &mut self,
        negotiated: NegotiatedMedia,
        remote_rtp: SocketAddr,
    ) -> Result<&ActiveMedia, MediaControlError> {
        if self.lifecycle != MediaLifecycle::Active {
            return Err(MediaControlError::NotActive);
        }
        if self.active.as_ref().is_some_and(|active| {
            active.negotiated == negotiated && active.remote_rtp == remote_rtp
        }) {
            return self
                .active
                .as_ref()
                .ok_or(MediaControlError::InternalInvariant);
        }
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .ok_or(MediaControlError::GenerationExhausted)?;
        self.active = Some(ActiveMedia {
            generation,
            negotiated,
            remote_rtp,
        });
        self.active
            .as_ref()
            .ok_or(MediaControlError::InternalInvariant)
    }
}

/// Media reconfiguration failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MediaControlError {
    /// Offer/answer arbiter rejected operation.
    OfferAnswer(OfferAnswerError),
    /// Endpoint was port zero or wildcard.
    InvalidRemoteEndpoint,
    /// Secure session attempted clear RTP replacement.
    SecurityDowngrade,
    /// Generation space exhausted.
    GenerationExhausted,
    /// Active snapshot invariant failed.
    InternalInvariant,
    /// Media is draining or closed and cannot be reconfigured.
    NotActive,
}
impl fmt::Display for MediaControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runtime media reconfiguration failed")
    }
}
impl StdError for MediaControlError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::OfferAnswer(error) => Some(error),
            _ => None,
        }
    }
}

/// Atomic dialog/media reconfiguration failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DialogMediaError {
    /// Dialog state rejected target refresh.
    Dialog(DialogError),
    /// Offer/answer or media policy rejected the update.
    Media(MediaControlError),
}

impl fmt::Display for DialogMediaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("dialog and media reconfiguration failed")
    }
}

impl StdError for DialogMediaError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Dialog(error) => Some(error),
            Self::Media(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::media::{
        DialogMediaOwner, MediaControlError, MediaController, MediaLifecycle, MediaShutdownAction,
        MediaShutdownPlan,
    };
    use crate::sip::dialog::{Dialog, DialogId, DialogState, RouteSet};
    use crate::sip::headers::call_id::CallId;
    use crate::sip::parser::uri::parse_str;
    use crate::sip::sdp::codec::Codec;
    use crate::sip::sdp::parser::parse;
    use crate::sip::sdp::{Direction, RtpMediaOffer};
    use std::net::SocketAddr;

    fn media(secure: bool) -> crate::sip::sdp::NegotiatedMedia {
        let profile = if secure { "RTP/SAVP" } else { "RTP/AVP" };
        let body =
            format!("v=0\r\no=- 1 1 IN IP4 host\r\ns=x\r\nt=0 0\r\nm=audio 4000 {profile} 0\r\n");
        let document = parse(body.as_bytes()).unwrap_or_else(|_| panic!("sdp"));
        let offer = RtpMediaOffer::from_section(&document.media_sections()[0], Direction::SendRecv)
            .unwrap_or_else(|_| panic!("offer"));
        let codec = Codec::from_bytes(b"0 PCMU/8000").unwrap_or_else(|_| panic!("codec"));
        offer
            .negotiate(&[codec], true, true, false)
            .unwrap_or_else(|_| panic!("media"))
    }

    #[test]
    fn commits_reconfiguration_atomically_and_rejects_glare() {
        let mut controller = MediaController::new(true);
        let token = controller
            .begin_local_offer()
            .unwrap_or_else(|_| panic!("offer"));
        assert!(controller.begin_remote_offer().is_err());
        let active = controller
            .apply_remote_answer(token, media(true), SocketAddr::from(([192, 0, 2, 1], 4000)))
            .unwrap_or_else(|_| panic!("apply"));
        assert_eq!(active.generation(), 1);
    }

    #[test]
    fn secure_media_can_never_downgrade() {
        let mut controller = MediaController::new(true);
        let token = controller
            .begin_local_offer()
            .unwrap_or_else(|_| panic!("offer"));
        assert_eq!(
            controller.apply_remote_answer(
                token,
                media(false),
                SocketAddr::from(([192, 0, 2, 1], 4000))
            ),
            Err(MediaControlError::SecurityDowngrade)
        );
        assert!(controller.active().is_none());
    }

    #[test]
    fn remote_target_and_media_commit_atomically() {
        let old_target = parse_str("sips:old.example").unwrap_or_else(|_| panic!("old target"));
        let new_target = parse_str("sips:new.example").unwrap_or_else(|_| panic!("new target"));
        let dialog_id = DialogId::new(
            CallId::new("call@example").unwrap_or_else(|_| panic!("call id")),
            "local",
            "remote",
        )
        .unwrap_or_else(|_| panic!("dialog id"));
        let dialog = Dialog::new(
            dialog_id,
            DialogState::confirmed(),
            RouteSet::empty(),
            old_target.clone(),
            1,
            None,
        )
        .unwrap_or_else(|_| panic!("dialog"));
        let mut owner = DialogMediaOwner::new(dialog, MediaController::new(true));

        assert!(
            owner
                .apply_remote_reconfiguration(
                    Some(new_target.clone()),
                    media(false),
                    SocketAddr::from(([192, 0, 2, 1], 4000)),
                )
                .is_err()
        );
        assert_eq!(owner.dialog().remote_target(), &old_target);
        assert!(owner.media().active().is_none());

        assert_eq!(
            owner.apply_remote_reconfiguration(
                Some(new_target.clone()),
                media(true),
                SocketAddr::from(([192, 0, 2, 1], 4000)),
            ),
            Ok(1)
        );
        assert_eq!(owner.dialog().remote_target(), &new_target);
        assert_eq!(
            owner.media().active().map(super::ActiveMedia::generation),
            Some(1)
        );
    }

    #[test]
    fn unchanged_effective_sdp_does_not_rebuild_media_generation() {
        let mut controller = MediaController::new(false);
        let endpoint = SocketAddr::from(([192, 0, 2, 1], 4000));
        let first = controller
            .begin_local_offer()
            .and_then(|token| controller.apply_remote_answer(token, media(false), endpoint))
            .map(super::ActiveMedia::generation)
            .unwrap_or_else(|_| panic!("first"));
        let second = controller
            .begin_local_offer()
            .and_then(|token| controller.apply_remote_answer(token, media(false), endpoint))
            .map(super::ActiveMedia::generation)
            .unwrap_or_else(|_| panic!("second"));
        assert_eq!(first, second);
    }

    #[test]
    fn changed_final_answer_replaces_early_media_and_fences_old_work() {
        let mut controller = MediaController::new(false);
        let early_endpoint = SocketAddr::from(([192, 0, 2, 1], 4000));
        let final_endpoint = SocketAddr::from(([192, 0, 2, 2], 5000));
        let early = controller
            .begin_local_offer()
            .and_then(|token| controller.apply_remote_answer(token, media(false), early_endpoint))
            .map(super::ActiveMedia::generation)
            .unwrap_or_else(|_| panic!("early media"));
        let early_token = controller.work_token().unwrap_or_else(|| panic!("token"));
        let final_generation = controller
            .begin_local_offer()
            .and_then(|token| controller.apply_remote_answer(token, media(false), final_endpoint))
            .map(super::ActiveMedia::generation)
            .unwrap_or_else(|_| panic!("final media"));

        assert!(final_generation > early);
        assert!(!controller.accepts(early_token));
        assert_eq!(
            controller.active().map(super::ActiveMedia::remote_rtp),
            Some(final_endpoint)
        );
    }

    #[test]
    fn generation_fences_stale_work_and_shutdown_order_is_fixed() {
        let mut controller = MediaController::new(false);
        let endpoint = SocketAddr::from(([192, 0, 2, 1], 4000));
        let offer = controller
            .begin_local_offer()
            .unwrap_or_else(|_| panic!("offer"));
        controller
            .apply_remote_answer(offer, media(false), endpoint)
            .unwrap_or_else(|_| panic!("activate"));
        let token = controller.work_token().unwrap_or_else(|| panic!("token"));
        assert!(controller.accepts(token));
        assert!(controller.begin_draining());
        assert_eq!(controller.lifecycle(), MediaLifecycle::Draining);
        assert!(!controller.accepts(token));
        assert!(controller.close());
        assert!(!controller.close());

        assert_eq!(
            MediaShutdownPlan::new(true, true).actions(),
            vec![
                MediaShutdownAction::FenceAiTransmit,
                MediaShutdownAction::FlushCommittedRtp,
                MediaShutdownAction::SendRtcpBye,
                MediaShutdownAction::StopMediaClock,
                MediaShutdownAction::CloseDsp,
                MediaShutdownAction::DestroySecurityContexts,
                MediaShutdownAction::CloseSockets,
                MediaShutdownAction::ReleasePortLease,
                MediaShutdownAction::CloseAudioQueues,
            ]
        );
    }
}
