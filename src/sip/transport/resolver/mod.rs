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

//! Bounded RFC 3263 destination planning.
//!
//! DNS I/O deliberately remains outside this module. A runtime resolver feeds
//! validated, TTL-cached answers into
//! [`ResolverRecords`](crate::sip::transport::resolver::ResolverRecords), while this policy
//! core applies URI transport constraints, SRV ordering, secure-transport
//! rules, address expansion, deduplication, and bounded failover.

use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use super::destination::{Destination, DestinationError, Protocol, TlsIdentity};

/// Maximum service records accepted for one resolution.
pub const MAX_SERVICE_RECORDS: usize = 64;
/// Maximum address records accepted for one resolution.
pub const MAX_ADDRESS_RECORDS: usize = 128;
/// Maximum concrete failover candidates retained.
pub const MAX_RESOLVED_CANDIDATES: usize = 32;

/// Request constraints derived from a SIP or SIPS URI.
#[derive(Clone, Eq, PartialEq)]
pub struct ResolutionRequest {
    domain: Box<str>,
    secure: bool,
    explicit_protocol: Option<Protocol>,
    explicit_port: Option<u16>,
    entropy: u64,
}

impl ResolutionRequest {
    /// Creates a request with an optional explicit transport and port.
    ///
    /// `entropy` makes weighted SRV ordering deterministic for a call attempt
    /// while permitting different calls to distribute across equal-priority
    /// records.
    ///
    /// # Errors
    ///
    /// Rejects an invalid domain, port zero, or a non-TLS transport for a
    /// secure URI.
    pub fn new(
        domain: &str,
        secure: bool,
        explicit_protocol: Option<Protocol>,
        explicit_port: Option<u16>,
        entropy: u64,
    ) -> Result<Self, ResolutionError> {
        let identity = TlsIdentity::dns(domain).map_err(ResolutionError::InvalidDestination)?;
        let Some(domain) = identity.as_dns() else {
            return Err(ResolutionError::InvalidDomain);
        };
        if explicit_port == Some(0) {
            return Err(ResolutionError::ZeroPort);
        }
        if secure && explicit_protocol.is_some_and(|protocol| protocol != Protocol::Tls) {
            return Err(ResolutionError::SecureDowngrade);
        }
        Ok(Self {
            domain: domain.into(),
            secure,
            explicit_protocol,
            explicit_port,
            entropy,
        })
    }

    /// Returns the normalized DNS domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns whether the URI requires TLS.
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        self.secure
    }
}

impl fmt::Debug for ResolutionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolutionRequest")
            .field("domain", &"[redacted]")
            .field("secure", &self.secure)
            .field("explicit_protocol", &self.explicit_protocol)
            .field("explicit_port", &self.explicit_port)
            .finish_non_exhaustive()
    }
}

/// One bounded SRV service answer.
#[derive(Clone, Eq, PartialEq)]
pub struct ServiceRecord {
    protocol: Protocol,
    naptr_order: u16,
    naptr_preference: u16,
    priority: u16,
    weight: u16,
    port: u16,
    target: Box<str>,
}

impl ServiceRecord {
    /// Creates a service record.
    ///
    /// # Errors
    ///
    /// Rejects port zero or an invalid DNS target.
    pub fn new(
        protocol: Protocol,
        priority: u16,
        weight: u16,
        port: u16,
        target: &str,
    ) -> Result<Self, ResolutionError> {
        Self::with_naptr(protocol, 0, 0, priority, weight, port, target)
    }

    /// Creates a service record with its RFC 3263 NAPTR ordering metadata.
    ///
    /// `naptr_order` and `naptr_preference` come from the record selecting
    /// this transport service; `priority` and `weight` come from SRV.
    ///
    /// # Errors
    ///
    /// Rejects port zero or an invalid DNS target.
    #[allow(clippy::too_many_arguments)]
    pub fn with_naptr(
        protocol: Protocol,
        naptr_order: u16,
        naptr_preference: u16,
        priority: u16,
        weight: u16,
        port: u16,
        target: &str,
    ) -> Result<Self, ResolutionError> {
        if port == 0 {
            return Err(ResolutionError::ZeroPort);
        }
        let identity = TlsIdentity::dns(target).map_err(ResolutionError::InvalidDestination)?;
        let Some(target) = identity.as_dns() else {
            return Err(ResolutionError::InvalidDomain);
        };
        Ok(Self {
            protocol,
            naptr_order,
            naptr_preference,
            priority,
            weight,
            port,
            target: target.into(),
        })
    }
}

impl fmt::Debug for ServiceRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceRecord")
            .field("protocol", &self.protocol)
            .field("naptr_order", &self.naptr_order)
            .field("naptr_preference", &self.naptr_preference)
            .field("priority", &self.priority)
            .field("weight", &self.weight)
            .field("port", &self.port)
            .field("target", &"[redacted]")
            .finish()
    }
}

/// One validated DNS address answer associated with a name.
#[derive(Clone, Eq, PartialEq)]
pub struct AddressRecord {
    target: Box<str>,
    address: IpAddr,
}

impl AddressRecord {
    /// Creates an address answer.
    ///
    /// # Errors
    ///
    /// Rejects an invalid target or an unspecified address.
    pub fn new(target: &str, address: IpAddr) -> Result<Self, ResolutionError> {
        if address.is_unspecified() {
            return Err(ResolutionError::UnspecifiedAddress);
        }
        let identity = TlsIdentity::dns(target).map_err(ResolutionError::InvalidDestination)?;
        let Some(target) = identity.as_dns() else {
            return Err(ResolutionError::InvalidDomain);
        };
        Ok(Self {
            target: target.into(),
            address,
        })
    }
}

impl fmt::Debug for AddressRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AddressRecord")
            .field("target", &"[redacted]")
            .field(
                "family",
                &if self.address.is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                },
            )
            .finish()
    }
}

/// DNS answers supplied by the runtime resolver and its bounded cache.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResolverRecords {
    /// SRV answers in resolver order before policy ordering.
    pub services: Vec<ServiceRecord>,
    /// A and AAAA answers.
    pub addresses: Vec<AddressRecord>,
}

/// Ordered concrete destinations for one call attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionPlan {
    candidates: Vec<Destination>,
    next: usize,
}

impl ResolutionPlan {
    /// Builds a bounded plan from validated DNS answers.
    ///
    /// # Errors
    ///
    /// Rejects excessive inputs, incompatible secure records, invalid
    /// destinations, and an empty result.
    pub fn build(
        request: &ResolutionRequest,
        records: &ResolverRecords,
    ) -> Result<Self, ResolutionError> {
        if records.services.len() > MAX_SERVICE_RECORDS {
            return Err(ResolutionError::TooManyServiceRecords);
        }
        if records.addresses.len() > MAX_ADDRESS_RECORDS {
            return Err(ResolutionError::TooManyAddressRecords);
        }

        let mut candidates = Vec::new();
        if let Some(port) = request.explicit_port {
            let protocol = request.explicit_protocol.unwrap_or(if request.secure {
                Protocol::Tls
            } else {
                Protocol::Udp
            });
            append_addresses(
                &mut candidates,
                request,
                records,
                &request.domain,
                protocol,
                port,
            )?;
        } else {
            let mut services: Vec<&ServiceRecord> = records
                .services
                .iter()
                .filter(|record| protocol_allowed(request, record.protocol))
                .collect();
            order_services(&mut services, request.entropy);
            for service in services {
                append_addresses(
                    &mut candidates,
                    request,
                    records,
                    &service.target,
                    service.protocol,
                    service.port,
                )?;
                if candidates.len() == MAX_RESOLVED_CANDIDATES {
                    break;
                }
            }

            if candidates.is_empty() && records.services.is_empty() {
                let protocols: Vec<Protocol> = if let Some(protocol) = request.explicit_protocol {
                    vec![protocol]
                } else if request.secure {
                    vec![Protocol::Tls]
                } else {
                    vec![Protocol::Udp, Protocol::Tcp]
                };
                for protocol in protocols {
                    append_addresses(
                        &mut candidates,
                        request,
                        records,
                        &request.domain,
                        protocol,
                        default_port(protocol),
                    )?;
                }
            }
        }

        if candidates.is_empty() {
            return Err(ResolutionError::NoUsableDestination);
        }
        Ok(Self {
            candidates,
            next: 0,
        })
    }

    /// Returns all ordered candidates without advancing failover state.
    #[must_use]
    pub fn candidates(&self) -> &[Destination] {
        &self.candidates
    }

    /// Returns the next untried destination and advances the cursor.
    pub fn next_candidate(&mut self) -> Option<&Destination> {
        let candidate = self.candidates.get(self.next)?;
        self.next += 1;
        Some(candidate)
    }

    /// Returns how many candidates have not yet been attempted.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.candidates.len().saturating_sub(self.next)
    }
}

fn protocol_allowed(request: &ResolutionRequest, protocol: Protocol) -> bool {
    if request.secure {
        return protocol == Protocol::Tls;
    }
    request
        .explicit_protocol
        .is_none_or(|explicit| explicit == protocol)
}

fn default_port(protocol: Protocol) -> u16 {
    if protocol == Protocol::Tls {
        5061
    } else {
        5060
    }
}

fn append_addresses(
    candidates: &mut Vec<Destination>,
    request: &ResolutionRequest,
    records: &ResolverRecords,
    target: &str,
    protocol: Protocol,
    port: u16,
) -> Result<(), ResolutionError> {
    if !protocol_allowed(request, protocol) {
        return Err(ResolutionError::SecureDowngrade);
    }
    for address in records
        .addresses
        .iter()
        .filter(|address| address.target.eq_ignore_ascii_case(target))
    {
        let remote = SocketAddr::new(address.address, port);
        let destination = match protocol {
            Protocol::Udp => Destination::udp(remote),
            Protocol::Tcp => Destination::tcp(remote),
            Protocol::Tls => Destination::tls(
                remote,
                TlsIdentity::dns(&request.domain).map_err(ResolutionError::InvalidDestination)?,
            ),
        }
        .map_err(ResolutionError::InvalidDestination)?;
        if !candidates.contains(&destination) {
            if candidates.len() == MAX_RESOLVED_CANDIDATES {
                return Ok(());
            }
            candidates.push(destination);
        }
    }
    Ok(())
}

fn order_services(services: &mut Vec<&ServiceRecord>, mut entropy: u64) {
    services.sort_by_key(|record| {
        (
            record.naptr_order,
            record.naptr_preference,
            record.priority,
            protocol_rank(record.protocol),
        )
    });
    let mut start = 0;
    while start < services.len() {
        let naptr_order = services[start].naptr_order;
        let naptr_preference = services[start].naptr_preference;
        let priority = services[start].priority;
        let protocol = services[start].protocol;
        let mut end = start + 1;
        while end < services.len()
            && services[end].naptr_order == naptr_order
            && services[end].naptr_preference == naptr_preference
            && services[end].priority == priority
            && services[end].protocol == protocol
        {
            end += 1;
        }
        weighted_order(&mut services[start..end], &mut entropy);
        start = end;
    }
}

fn weighted_order(records: &mut [&ServiceRecord], entropy: &mut u64) {
    for index in 0..records.len() {
        let total: u64 = records[index..]
            .iter()
            .map(|record| u64::from(record.weight))
            .sum();
        *entropy = entropy
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let selected = if total == 0 {
            index + usize::try_from(*entropy % (records.len() - index) as u64).unwrap_or(0)
        } else {
            let choice = *entropy % total;
            let mut cumulative = 0_u64;
            index
                + records[index..]
                    .iter()
                    .position(|record| {
                        cumulative = cumulative.saturating_add(u64::from(record.weight));
                        choice < cumulative
                    })
                    .unwrap_or(0)
        };
        records.swap(index, selected);
    }
}

const fn protocol_rank(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::Udp => 0,
        Protocol::Tcp => 1,
        Protocol::Tls => 2,
    }
}

/// Destination-resolution failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionError {
    /// Domain validation failed unexpectedly.
    InvalidDomain,
    /// A port was zero.
    ZeroPort,
    /// An address was unspecified.
    UnspecifiedAddress,
    /// DNS service-answer count exceeded its bound.
    TooManyServiceRecords,
    /// DNS address-answer count exceeded its bound.
    TooManyAddressRecords,
    /// Secure URI policy would have been downgraded.
    SecureDowngrade,
    /// No compatible address and transport remained.
    NoUsableDestination,
    /// Concrete destination validation failed.
    InvalidDestination(DestinationError),
}

impl fmt::Display for ResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIP destination resolution failed")
    }
}

impl StdError for ResolutionError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidDestination(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{
        AddressRecord, ResolutionError, ResolutionPlan, ResolutionRequest, ResolverRecords,
        ServiceRecord,
    };
    use crate::sip::transport::destination::Protocol;

    fn address(target: &str, last: u8) -> AddressRecord {
        AddressRecord::new(target, IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .unwrap_or_else(|_| panic!("address"))
    }

    #[test]
    fn service_priority_and_failover_are_bounded() {
        let request = ResolutionRequest::new("example.com", false, None, None, 17)
            .unwrap_or_else(|_| panic!("request"));
        let records = ResolverRecords {
            services: vec![
                ServiceRecord::new(Protocol::Tcp, 20, 1, 5070, "slow.example.com")
                    .unwrap_or_else(|_| panic!("service")),
                ServiceRecord::new(Protocol::Udp, 10, 1, 5060, "fast.example.com")
                    .unwrap_or_else(|_| panic!("service")),
            ],
            addresses: vec![
                address("slow.example.com", 2),
                address("fast.example.com", 1),
            ],
        };
        let mut plan =
            ResolutionPlan::build(&request, &records).unwrap_or_else(|_| panic!("resolution"));
        assert_eq!(plan.candidates()[0].protocol(), Protocol::Udp);
        assert_eq!(
            plan.next_candidate().map(|value| value.remote().port()),
            Some(5060)
        );
        assert_eq!(plan.remaining(), 1);
    }

    #[test]
    fn sips_never_accepts_plain_service_or_identity_downgrade() {
        assert_eq!(
            ResolutionRequest::new("example.com", true, Some(Protocol::Udp), None, 0),
            Err(ResolutionError::SecureDowngrade)
        );
        let request = ResolutionRequest::new("example.com", true, None, None, 0)
            .unwrap_or_else(|_| panic!("request"));
        let records = ResolverRecords {
            services: vec![
                ServiceRecord::new(Protocol::Tls, 0, 0, 5061, "edge.example.net")
                    .unwrap_or_else(|_| panic!("service")),
            ],
            addresses: vec![address("edge.example.net", 9)],
        };
        let plan =
            ResolutionPlan::build(&request, &records).unwrap_or_else(|_| panic!("resolution"));
        assert_eq!(plan.candidates()[0].protocol(), Protocol::Tls);
        assert_eq!(
            plan.candidates()[0]
                .tls_identity()
                .and_then(|identity| identity.as_dns()),
            Some("example.com")
        );
    }

    #[test]
    fn direct_address_fallback_and_deduplication_work() {
        let request = ResolutionRequest::new("example.com", false, None, None, 0)
            .unwrap_or_else(|_| panic!("request"));
        let duplicate = address("example.com", 3);
        let records = ResolverRecords {
            services: Vec::new(),
            addresses: vec![duplicate.clone(), duplicate],
        };
        let plan =
            ResolutionPlan::build(&request, &records).unwrap_or_else(|_| panic!("resolution"));
        assert_eq!(plan.candidates().len(), 2);
        assert_eq!(plan.candidates()[0].protocol(), Protocol::Udp);
        assert_eq!(plan.candidates()[1].protocol(), Protocol::Tcp);
    }

    #[test]
    fn naptr_order_precedes_srv_priority() {
        let request = ResolutionRequest::new("example.com", false, None, None, 1)
            .unwrap_or_else(|_| panic!("request"));
        let records = ResolverRecords {
            services: vec![
                ServiceRecord::with_naptr(Protocol::Udp, 20, 0, 0, 1, 5060, "later.example.com")
                    .unwrap_or_else(|_| panic!("service")),
                ServiceRecord::with_naptr(Protocol::Tcp, 10, 0, 100, 1, 5060, "first.example.com")
                    .unwrap_or_else(|_| panic!("service")),
            ],
            addresses: vec![
                address("later.example.com", 2),
                address("first.example.com", 1),
            ],
        };
        let plan =
            ResolutionPlan::build(&request, &records).unwrap_or_else(|_| panic!("resolution"));
        assert_eq!(plan.candidates()[0].protocol(), Protocol::Tcp);
    }

    #[test]
    fn rejects_unspecified_addresses_and_redacts_debug() {
        assert_eq!(
            AddressRecord::new("example.com", IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            Err(ResolutionError::UnspecifiedAddress)
        );
        let request = ResolutionRequest::new("secret.example", false, None, Some(5060), 0)
            .unwrap_or_else(|_| panic!("request"));
        assert!(!format!("{request:?}").contains("secret.example"));
    }
}
