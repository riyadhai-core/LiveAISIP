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

//! Allocation-free UDP media packet classification.
//!
//! This is the mandatory boundary before SRTP/RTP or SRTCP/RTCP processing.
//! It recognizes only the negotiated RTP families and rejects other UDP bytes.
//! Cryptographic authentication still belongs to the SRTP layer.

use super::socket::Component;

const RTP_MINIMUM_BYTES: usize = 12;
const RTCP_MINIMUM_BYTES: usize = 4;

/// Classification of one RTP socket datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramClassification {
    /// RTP or SRTP; the fixed RTP header remains visible under SRTP.
    Rtp,
    /// RTCP or SRTCP; the fixed RTCP header remains visible under SRTCP.
    Rtcp,
    /// STUN packet, deliberately unsupported on the SIP media path.
    Stun,
    /// DTLS record, deliberately unsupported until DTLS-SRTP is negotiated.
    Dtls,
    /// TURN `ChannelData`, unsupported on a directly bound media socket.
    TurnChannelData,
    /// Datagram could not belong to an admitted packet family.
    Invalid,
}

/// Low-cardinality classifier counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DatagramClassifierStats {
    /// RTP-family datagrams.
    pub rtp: u64,
    /// RTCP-family datagrams.
    pub rtcp: u64,
    /// Rejected STUN datagrams.
    pub stun: u64,
    /// Rejected DTLS records.
    pub dtls: u64,
    /// Rejected TURN `ChannelData` datagrams.
    pub turn_channel_data: u64,
    /// Unrecognized or structurally impossible datagrams.
    pub invalid: u64,
}

/// Stateful accounting around an allocation-free classifier.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DatagramClassifier {
    stats: DatagramClassifierStats,
}

impl DatagramClassifier {
    /// Classifies one datagram received on a separate RTP or RTCP socket.
    pub fn classify(&mut self, component: Component, datagram: &[u8]) -> DatagramClassification {
        let classification = classify(component, datagram, false);
        self.account(classification);
        classification
    }

    /// Classifies one datagram on an RFC 5761 RTP/RTCP-multiplexed socket.
    pub fn classify_muxed(&mut self, datagram: &[u8]) -> DatagramClassification {
        let classification = classify(Component::Rtp, datagram, true);
        self.account(classification);
        classification
    }

    /// Returns lifetime counters.
    #[must_use]
    pub const fn stats(&self) -> DatagramClassifierStats {
        self.stats
    }

    fn account(&mut self, classification: DatagramClassification) {
        let counter = match classification {
            DatagramClassification::Rtp => &mut self.stats.rtp,
            DatagramClassification::Rtcp => &mut self.stats.rtcp,
            DatagramClassification::Stun => &mut self.stats.stun,
            DatagramClassification::Dtls => &mut self.stats.dtls,
            DatagramClassification::TurnChannelData => &mut self.stats.turn_channel_data,
            DatagramClassification::Invalid => &mut self.stats.invalid,
        };
        *counter = counter.saturating_add(1);
    }
}

fn classify(component: Component, datagram: &[u8], multiplexed: bool) -> DatagramClassification {
    if is_stun(datagram) {
        return DatagramClassification::Stun;
    }
    if datagram
        .first()
        .is_some_and(|byte| (20..=63).contains(byte))
    {
        return DatagramClassification::Dtls;
    }
    if is_turn_channel_data(datagram) {
        return DatagramClassification::TurnChannelData;
    }
    if datagram.len() < 2 || datagram[0] >> 6 != 2 {
        return DatagramClassification::Invalid;
    }

    let is_rtcp = if multiplexed {
        (192..=223).contains(&datagram[1])
    } else {
        component == Component::Rtcp
    };
    if is_rtcp {
        if datagram.len() < RTCP_MINIMUM_BYTES || !(192..=223).contains(&datagram[1]) {
            DatagramClassification::Invalid
        } else {
            DatagramClassification::Rtcp
        }
    } else if datagram.len() < RTP_MINIMUM_BYTES {
        DatagramClassification::Invalid
    } else {
        DatagramClassification::Rtp
    }
}

fn is_stun(datagram: &[u8]) -> bool {
    datagram.len() >= 20
        && datagram[0] & 0b1100_0000 == 0
        && datagram[4..8] == [0x21, 0x12, 0xa4, 0x42]
}

fn is_turn_channel_data(datagram: &[u8]) -> bool {
    datagram.len() >= 4 && datagram[0] & 0b1100_0000 == 0b0100_0000
}

#[cfg(test)]
mod tests {
    use super::{DatagramClassification, DatagramClassifier};
    use crate::rtp::transport::Component;

    #[test]
    fn separates_rtp_and_rtcp_on_dedicated_sockets() {
        let mut classifier = DatagramClassifier::default();
        let mut rtp = [0_u8; 12];
        rtp[0] = 0x80;
        rtp[1] = 0;
        assert_eq!(
            classifier.classify(Component::Rtp, &rtp),
            DatagramClassification::Rtp
        );
        let control_packet = [0x80, 200, 0, 0];
        assert_eq!(
            classifier.classify(Component::Rtcp, &control_packet),
            DatagramClassification::Rtcp
        );
        assert_eq!(classifier.stats().rtp, 1);
        assert_eq!(classifier.stats().rtcp, 1);
    }

    #[test]
    fn mux_classification_uses_reserved_rtcp_packet_type_range() {
        let mut classifier = DatagramClassifier::default();
        let mut rtp = [0_u8; 12];
        rtp[0] = 0x80;
        rtp[1] = 111;
        assert_eq!(classifier.classify_muxed(&rtp), DatagramClassification::Rtp);
        assert_eq!(
            classifier.classify_muxed(&[0x80, 201, 0, 0]),
            DatagramClassification::Rtcp
        );
    }

    #[test]
    fn rejects_or_identifies_non_media_before_parsing() {
        let mut classifier = DatagramClassifier::default();
        let mut stun = [0_u8; 20];
        stun[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(
            classifier.classify(Component::Rtp, &stun),
            DatagramClassification::Stun
        );
        assert_eq!(
            classifier.classify(Component::Rtp, &[22, 0]),
            DatagramClassification::Dtls
        );
        assert_eq!(
            classifier.classify(Component::Rtp, &[0x40, 0, 0, 0]),
            DatagramClassification::TurnChannelData
        );
        assert_eq!(
            classifier.classify(Component::Rtp, &[0x80, 0]),
            DatagramClassification::Invalid
        );
        assert_eq!(classifier.stats().invalid, 1);
    }
}
