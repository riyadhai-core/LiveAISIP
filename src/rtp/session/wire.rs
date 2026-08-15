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

//! Allocation-free clear-RTP wire execution.
//!
//! The call thread owns this executor, its
//! [`crate::rtp::session::send::RtpSendState`], the media socket pair, packet scratch, and
//! [`RtpSession`]. A local UDP send failure consumes
//! the attempted sequence number and timestamp: the next successful packet
//! exposes an ordinary RTP loss instead of reusing an identity whose delivery
//! may be ambiguous.

use std::error::Error as StdError;
use std::fmt;

use super::send::{RtpSendError, RtpSendState};
use super::{RtpSession, RtpSessionError};
use crate::rtp::security::PacketProtection;
use crate::rtp::transport::{Component, MediaPacketScratch, MediaSocketPair, SocketError};

/// Successful RTP wire-send metadata without payload or endpoint disclosure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpWireSendOutcome {
    sequence_number: u16,
    timestamp: u32,
    marker: bool,
    payload_octets: usize,
}

impl RtpWireSendOutcome {
    /// Returns the transmitted sequence number.
    #[must_use]
    pub const fn sequence_number(self) -> u16 {
        self.sequence_number
    }

    /// Returns the transmitted RTP timestamp.
    #[must_use]
    pub const fn timestamp(self) -> u32 {
        self.timestamp
    }

    /// Returns whether this packet began a talkspurt/discontinuity.
    #[must_use]
    pub const fn marker(self) -> bool {
        self.marker
    }

    /// Returns transmitted codec payload octets.
    #[must_use]
    pub const fn payload_octets(self) -> usize {
        self.payload_octets
    }
}

/// Call-owned encoder and clear-RTP UDP executor.
pub struct RtpWireSender {
    state: RtpSendState,
    packets_sent: u64,
    payload_octets_sent: u64,
    send_failures: u64,
}

impl RtpWireSender {
    /// Creates an executor from randomized, negotiated RTP send state.
    #[must_use]
    pub const fn new(state: RtpSendState) -> Self {
        Self {
            state,
            packets_sent: 0,
            payload_octets_sent: 0,
            send_failures: 0,
        }
    }

    /// Encodes and sends one clear RTP payload through the call-owned socket.
    ///
    /// The destination comes from the session's symmetric endpoint state, not
    /// from the application. Successful sends update RTCP sender accounting.
    ///
    /// # Errors
    ///
    /// Rejects clear transmission for secure media, invalid payload/storage,
    /// exhausted diagnostics, or any UDP send failure.
    pub fn send_plain(
        &mut self,
        session: &mut RtpSession,
        sockets: &MediaSocketPair,
        scratch: &mut MediaPacketScratch,
        payload: &[u8],
    ) -> Result<RtpWireSendOutcome, RtpWireSendError> {
        session
            .admit_outbound(PacketProtection::Plain)
            .map_err(RtpWireSendError::Session)?;
        let next_packets = self
            .packets_sent
            .checked_add(1)
            .ok_or(RtpWireSendError::CounterExhausted)?;
        let payload_octets =
            u64::try_from(payload.len()).map_err(|_| RtpWireSendError::CounterExhausted)?;
        let next_octets = self
            .payload_octets_sent
            .checked_add(payload_octets)
            .ok_or(RtpWireSendError::CounterExhausted)?;
        let destination = session.remote_rtp_destination();
        let packet = self
            .state
            .encode_next(payload, scratch.rtp_output())
            .map_err(RtpWireSendError::Encode)?;
        let outcome = RtpWireSendOutcome {
            sequence_number: packet.sequence_number(),
            timestamp: packet.timestamp(),
            marker: packet.marker(),
            payload_octets: packet.payload_octets(),
        };
        if let Err(error) = sockets.send_to(Component::Rtp, packet.bytes(), destination) {
            self.send_failures = self.send_failures.saturating_add(1);
            return Err(RtpWireSendError::Socket(error));
        }
        self.packets_sent = next_packets;
        self.payload_octets_sent = next_octets;
        session.note_rtp_sent(outcome.payload_octets);
        Ok(outcome)
    }

    /// Marks the next encoded packet as a talkspurt/discontinuity boundary.
    pub const fn mark_discontinuity(&mut self) {
        self.state.mark_discontinuity();
    }

    /// Returns successfully sent RTP packet count.
    #[must_use]
    pub const fn packets_sent(&self) -> u64 {
        self.packets_sent
    }

    /// Returns successfully sent codec payload octets.
    #[must_use]
    pub const fn payload_octets_sent(&self) -> u64 {
        self.payload_octets_sent
    }

    /// Returns local send failures.
    #[must_use]
    pub const fn send_failures(&self) -> u64 {
        self.send_failures
    }

    /// Returns the underlying sequence/timestamp state.
    #[must_use]
    pub const fn state(&self) -> &RtpSendState {
        &self.state
    }
}

impl fmt::Debug for RtpWireSender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtpWireSender")
            .field("state", &self.state)
            .field("packets_sent", &self.packets_sent)
            .field("payload_octets_sent", &self.payload_octets_sent)
            .field("send_failures", &self.send_failures)
            .finish_non_exhaustive()
    }
}

/// Clear-RTP encoding, policy, or UDP execution failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum RtpWireSendError {
    /// Negotiated session policy rejected transmission.
    Session(RtpSessionError),
    /// RTP serialization or state accounting failed.
    Encode(RtpSendError),
    /// Call-owned UDP transmission failed.
    Socket(SocketError),
    /// Successful-send diagnostics exhausted.
    CounterExhausted,
}

impl fmt::Display for RtpWireSendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RTP wire transmission failed")
    }
}

impl StdError for RtpWireSendError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Session(error) => Some(error),
            Self::Encode(error) => Some(error),
            Self::Socket(error) => Some(error),
            Self::CounterExhausted => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::time::Duration;

    use super::{RtpWireSendError, RtpWireSender};
    use crate::rtp::clock::RtpClockRate;
    use crate::rtp::liveness::MediaLiveness;
    use crate::rtp::packet::rtp::RtpPacket;
    use crate::rtp::security::MediaSecurityPolicy;
    use crate::rtp::session::RtpSession;
    use crate::rtp::session::receive::RtpReceiveConfig;
    use crate::rtp::session::send::{RtpSendConfig, RtpSendState};
    use crate::rtp::source::SourcePolicy;
    use crate::rtp::transport::symmetric::{SymmetricConfig, SymmetricEndpoints};
    use crate::rtp::transport::{MediaPacketScratch, MediaSocketPair, PortPool, SocketConfig};

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn media_sockets() -> (PortPool, MediaSocketPair) {
        for port in (42_000_u16..60_000).step_by(2) {
            let pool = PortPool::new(port, port).unwrap_or_else(|_| panic!("pool"));
            let lease = pool.allocate().unwrap_or_else(|| panic!("lease"));
            if let Ok(sockets) = MediaSocketPair::bind(
                lease,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                SocketConfig::default(),
            ) {
                return (pool, sockets);
            }
        }
        panic!("free RTP pair")
    }

    fn session(media_destination: SocketAddr, policy: MediaSecurityPolicy) -> RtpSession {
        let receive = RtpReceiveConfig::new(0, RtpClockRate::TELEPHONY_8_KHZ, None)
            .unwrap_or_else(|_| panic!("receive"));
        let control_destination = SocketAddr::new(
            media_destination.ip(),
            media_destination
                .port()
                .checked_add(1)
                .unwrap_or(media_destination.port()),
        );
        let endpoints = SymmetricEndpoints::new(
            media_destination,
            control_destination,
            SymmetricConfig::default(),
        )
        .unwrap_or_else(|_| panic!("endpoints"));
        let liveness = MediaLiveness::new(
            Duration::ZERO,
            Duration::from_secs(5),
            Duration::from_secs(10),
        )
        .unwrap_or_else(|_| panic!("liveness"));
        RtpSession::new(
            receive,
            SourcePolicy::default(),
            endpoints,
            policy,
            liveness,
            8,
        )
        .unwrap_or_else(|_| panic!("session"))
    }

    fn sender() -> RtpWireSender {
        let config =
            RtpSendConfig::pcmu_20ms(0x0102_0304).unwrap_or_else(|_| panic!("send config"));
        RtpWireSender::new(RtpSendState::new(config, 10, 20))
    }

    #[test]
    fn sends_pcma_or_pcmu_wire_packet_to_session_destination_without_allocation() {
        let receiver = UdpSocket::bind(localhost(0)).unwrap_or_else(|_| panic!("receiver"));
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap_or_else(|_| panic!("timeout"));
        let remote = receiver.local_addr().unwrap_or_else(|_| panic!("remote"));
        let (_pool, sockets) = media_sockets();
        let mut session = session(remote, MediaSecurityPolicy::PlainAllowed);
        let mut scratch = MediaPacketScratch::new(2_048).unwrap_or_else(|_| panic!("scratch"));
        let mut sender = sender();
        let outcome = sender
            .send_plain(&mut session, &sockets, &mut scratch, &[0x55; 160])
            .unwrap_or_else(|_| panic!("send"));
        let mut datagram = [0_u8; 256];
        let (length, _) = receiver
            .recv_from(&mut datagram)
            .unwrap_or_else(|_| panic!("receive"));
        let packet = RtpPacket::parse(&datagram[..length]).unwrap_or_else(|_| panic!("packet"));
        assert_eq!(packet.header().sequence_number(), 10);
        assert_eq!(packet.header().timestamp(), 20);
        assert_eq!(packet.payload(), &[0x55; 160]);
        assert!(outcome.marker());
        assert_eq!(sender.packets_sent(), 1);
        assert_eq!(sender.payload_octets_sent(), 160);
    }

    #[test]
    fn secure_session_rejects_clear_send_before_sequence_advances() {
        let receiver = UdpSocket::bind(localhost(0)).unwrap_or_else(|_| panic!("receiver"));
        let remote = receiver.local_addr().unwrap_or_else(|_| panic!("remote"));
        let (_pool, sockets) = media_sockets();
        let mut session = session(remote, MediaSecurityPolicy::SecureRequired);
        let mut scratch = MediaPacketScratch::new(2_048).unwrap_or_else(|_| panic!("scratch"));
        let mut sender = sender();
        assert!(matches!(
            sender.send_plain(&mut session, &sockets, &mut scratch, &[0x55; 160]),
            Err(RtpWireSendError::Session(_))
        ));
        assert_eq!(sender.state().next_sequence_number(), 10);
        assert_eq!(sender.packets_sent(), 0);
    }
}
