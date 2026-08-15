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

//! Deterministic per-session RTCP report scheduling.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use crate::rtp::packet::rtcp::bye::{Goodbye, GoodbyeError};
use crate::rtp::packet::rtcp::receiver_report::{ReceiverReport, ReceiverReportError};
use crate::rtp::packet::rtcp::sdes::{
    SdesChunk, SdesItem, SdesItemType, SourceDescription, SourceDescriptionError,
};
use crate::rtp::packet::rtcp::sender_report::{RtcpSenderInfo, SenderReport, SenderReportError};

use super::receive::{RtpReceiveState, RtpStateError};

/// Maximum privacy-safe RTCP CNAME bytes retained per session.
pub const MAX_RTCP_CNAME_BYTES: usize = 128;

/// One scheduled compound-report payload.
pub enum ScheduledReport {
    /// Local endpoint sent RTP since its last report.
    Sender {
        /// Sender report with optional remote reception block.
        report: SenderReport,
        /// Mandatory local CNAME description.
        description: SourceDescription,
    },
    /// Local endpoint has not sent RTP since its last report.
    Receiver {
        /// Receiver report with optional remote reception block.
        report: ReceiverReport,
        /// Mandatory local CNAME description.
        description: SourceDescription,
    },
}

impl fmt::Debug for ScheduledReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScheduledReport")
            .field(
                "kind",
                &match self {
                    Self::Sender { .. } => "sender",
                    Self::Receiver { .. } => "receiver",
                },
            )
            .finish_non_exhaustive()
    }
}

/// RTCP scheduler configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtcpScheduleConfig {
    interval: Duration,
}

impl RtcpScheduleConfig {
    /// Creates fixed report cadence.
    ///
    /// # Errors
    ///
    /// Rejects a zero interval.
    pub const fn new(interval: Duration) -> Result<Self, RtcpSchedulerError> {
        if interval.is_zero() {
            return Err(RtcpSchedulerError::ZeroInterval);
        }
        Ok(Self { interval })
    }

    /// Returns report interval.
    #[must_use]
    pub const fn interval(self) -> Duration {
        self.interval
    }
}

impl Default for RtcpScheduleConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
        }
    }
}

/// Per-RTP-session report cadence, sender counters and CNAME ownership.
pub struct RtcpScheduler {
    config: RtcpScheduleConfig,
    local_ssrc: u32,
    cname: Box<[u8]>,
    next_report: Duration,
    sender_packets: u64,
    sender_octets: u64,
    sent_since_report: bool,
    reports_sent: u64,
}

impl RtcpScheduler {
    /// Creates the scheduler and pre-owns a bounded CNAME.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized/control-containing CNAME, deadline overflow,
    /// or allocation failure.
    pub fn new(
        config: RtcpScheduleConfig,
        local_ssrc: u32,
        cname: &[u8],
        now: Duration,
    ) -> Result<Self, RtcpSchedulerError> {
        validate_cname(cname)?;
        let next_report = now
            .checked_add(config.interval)
            .ok_or(RtcpSchedulerError::TimeOverflow)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(cname.len())
            .map_err(|_| RtcpSchedulerError::AllocationFailed)?;
        owned.extend_from_slice(cname);
        Ok(Self {
            config,
            local_ssrc,
            cname: owned.into_boxed_slice(),
            next_report,
            sender_packets: 0,
            sender_octets: 0,
            sent_since_report: false,
            reports_sent: 0,
        })
    }

    /// Accounts one successfully transmitted RTP payload.
    pub fn note_rtp_sent(&mut self, payload_octets: usize) {
        self.sender_packets = self.sender_packets.saturating_add(1);
        self.sender_octets = self
            .sender_octets
            .saturating_add(u64::try_from(payload_octets).unwrap_or(u64::MAX));
        self.sent_since_report = true;
    }

    /// Builds the due SR/RR plus SDES CNAME, or returns `None` before deadline.
    ///
    /// # Errors
    ///
    /// Preserves report construction, receiver-state and time failures.
    pub fn poll(
        &mut self,
        now: Duration,
        ntp_timestamp: u64,
        rtp_timestamp: u32,
        receive: Option<&mut RtpReceiveState>,
    ) -> Result<Option<ScheduledReport>, RtcpSchedulerError> {
        if now < self.next_report {
            return Ok(None);
        }
        let next = now
            .checked_add(self.config.interval)
            .ok_or(RtcpSchedulerError::TimeOverflow)?;
        let reception = match receive {
            Some(state) if state.bound_ssrc().is_some() && state.sequence().is_validated() => Some(
                state
                    .reception_report(now)
                    .map_err(RtcpSchedulerError::ReceiveState)?,
            ),
            _ => None,
        };
        let reports = reception.as_slice();
        let description = self.description()?;
        let report = if self.sent_since_report {
            let sender = RtcpSenderInfo::new(
                ntp_timestamp,
                rtp_timestamp,
                low_u32(self.sender_packets),
                low_u32(self.sender_octets),
            );
            ScheduledReport::Sender {
                report: SenderReport::new(self.local_ssrc, sender, reports, 0)
                    .map_err(RtcpSchedulerError::SenderReport)?,
                description,
            }
        } else {
            ScheduledReport::Receiver {
                report: ReceiverReport::new(self.local_ssrc, reports, 0)
                    .map_err(RtcpSchedulerError::ReceiverReport)?,
                description,
            }
        };
        self.next_report = next;
        self.sent_since_report = false;
        self.reports_sent = self.reports_sent.saturating_add(1);
        Ok(Some(report))
    }

    /// Builds a final BYE without changing report cadence.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or oversized reason and construction failures.
    pub fn goodbye(&self, reason: Option<&[u8]>) -> Result<Goodbye, RtcpSchedulerError> {
        Goodbye::new(&[self.local_ssrc], reason, 0).map_err(RtcpSchedulerError::Goodbye)
    }

    /// Returns next monotonic report deadline.
    #[must_use]
    pub const fn next_report_at(&self) -> Duration {
        self.next_report
    }

    /// Returns number of reports successfully constructed.
    #[must_use]
    pub const fn reports_sent(&self) -> u64 {
        self.reports_sent
    }

    fn description(&self) -> Result<SourceDescription, RtcpSchedulerError> {
        let item = SdesItem::new(SdesItemType::CanonicalName, &self.cname)
            .map_err(RtcpSchedulerError::SourceDescription)?;
        let chunk = SdesChunk::new(self.local_ssrc, &[item])
            .map_err(RtcpSchedulerError::SourceDescription)?;
        SourceDescription::new(&[chunk], 0).map_err(RtcpSchedulerError::SourceDescription)
    }
}

impl fmt::Debug for RtcpScheduler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtcpScheduler")
            .field("config", &self.config)
            .field("cname_bytes", &self.cname.len())
            .field("sender_packets", &self.sender_packets)
            .field("sender_octets", &self.sender_octets)
            .field("reports_sent", &self.reports_sent)
            .finish_non_exhaustive()
    }
}

fn validate_cname(cname: &[u8]) -> Result<(), RtcpSchedulerError> {
    if cname.is_empty()
        || cname.len() > MAX_RTCP_CNAME_BYTES
        || cname.iter().any(u8::is_ascii_control)
    {
        Err(RtcpSchedulerError::InvalidCname)
    } else {
        Ok(())
    }
}

fn low_u32(value: u64) -> u32 {
    let bytes = value.to_le_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// RTCP scheduler failure.
#[derive(Debug)]
pub enum RtcpSchedulerError {
    /// Report interval was zero.
    ZeroInterval,
    /// CNAME violated privacy-safe bounds.
    InvalidCname,
    /// Monotonic deadline overflowed.
    TimeOverflow,
    /// CNAME storage allocation failed.
    AllocationFailed,
    /// Receive statistics could not produce a report block.
    ReceiveState(RtpStateError),
    /// Sender Report construction failed.
    SenderReport(SenderReportError),
    /// Receiver Report construction failed.
    ReceiverReport(ReceiverReportError),
    /// SDES construction failed.
    SourceDescription(SourceDescriptionError),
    /// BYE construction failed.
    Goodbye(GoodbyeError),
}

impl fmt::Display for RtcpSchedulerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RTCP session scheduling failed")
    }
}

impl StdError for RtcpSchedulerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::ReceiveState(error) => Some(error),
            Self::SenderReport(error) => Some(error),
            Self::ReceiverReport(error) => Some(error),
            Self::SourceDescription(error) => Some(error),
            Self::Goodbye(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{RtcpScheduleConfig, RtcpScheduler, ScheduledReport};

    #[test]
    fn emits_rr_when_idle_and_sr_after_sending_rtp() {
        let Ok(mut scheduler) = RtcpScheduler::new(
            RtcpScheduleConfig::default(),
            7,
            b"runtime@example.invalid",
            Duration::ZERO,
        ) else {
            panic!("scheduler")
        };
        assert!(matches!(
            scheduler.poll(Duration::from_secs(4), 0, 0, None),
            Ok(None)
        ));
        assert!(matches!(
            scheduler.poll(Duration::from_secs(5), 0, 0, None),
            Ok(Some(ScheduledReport::Receiver { .. }))
        ));
        scheduler.note_rtp_sent(160);
        assert!(matches!(
            scheduler.poll(Duration::from_secs(10), 1, 80, None),
            Ok(Some(ScheduledReport::Sender { .. }))
        ));
        assert_eq!(scheduler.reports_sent(), 2);
    }

    #[test]
    fn creates_bye_and_redacts_identity() {
        let Ok(scheduler) = RtcpScheduler::new(
            RtcpScheduleConfig::default(),
            7,
            b"private-cname",
            Duration::ZERO,
        ) else {
            panic!("scheduler")
        };
        assert!(scheduler.goodbye(Some(b"normal")).is_ok());
        assert!(!format!("{scheduler:?}").contains("private-cname"));
    }
}
