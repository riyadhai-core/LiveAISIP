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

//! Shared verified Rustls client configuration.

use std::fmt;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};

use crate::sip::transport::tls::{TlsPolicy, TlsVersion};

use super::error::TlsDriverError;
use super::handshake::total_certificate_bytes;

/// Maximum trust anchors accepted by one client configuration.
pub const MAX_TRUST_ROOTS: usize = 4_096;
/// Maximum aggregate DER bytes accepted for explicit trust anchors.
pub const MAX_TRUST_ROOT_BYTES: usize = 8 * 1024 * 1024;

/// Shared verified client configuration, intended to be built once at startup.
#[derive(Clone)]
pub struct TlsClientConfig {
    pub(super) backend: Arc<ClientConfig>,
    pub(super) policy: TlsPolicy,
    trust_roots: usize,
    ignored_native_roots: usize,
    native_load_errors: usize,
}

impl TlsClientConfig {
    /// Loads the operating-system trust store and builds a verified client.
    ///
    /// Invalid individual native roots are ignored as recommended by Rustls,
    /// but successful trust anchors are required. Counts remain observable
    /// without disclosing certificate subjects or filesystem details.
    ///
    /// # Errors
    ///
    /// Returns an error when native roots cannot satisfy the configured bounds,
    /// no usable root exists, or the Rustls backend cannot be constructed.
    pub fn from_native_roots(policy: TlsPolicy) -> Result<Self, TlsDriverError> {
        let loaded = rustls_native_certs::load_native_certs();
        let native_load_errors = loaded.errors.len();
        if loaded.certs.len() > MAX_TRUST_ROOTS {
            return Err(TlsDriverError::TrustRootCountExceeded {
                attempted: loaded.certs.len(),
                maximum: MAX_TRUST_ROOTS,
            });
        }
        let total_bytes = total_certificate_bytes(&loaded.certs)?;
        if total_bytes > MAX_TRUST_ROOT_BYTES {
            return Err(TlsDriverError::TrustRootBytesExceeded {
                attempted: total_bytes,
                maximum: MAX_TRUST_ROOT_BYTES,
            });
        }

        let mut roots = RootCertStore::empty();
        let (trust_roots, ignored_native_roots) = roots.add_parsable_certificates(loaded.certs);
        if trust_roots == 0 {
            return Err(TlsDriverError::EmptyTrustStore);
        }
        Self::finish(
            policy,
            roots,
            trust_roots,
            ignored_native_roots,
            native_load_errors,
        )
    }

    /// Builds a verified client from explicit DER trust anchors.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, invalid, or over-budget roots, allocation
    /// failure, or an unsupported backend policy.
    pub fn from_der_roots<I, B>(policy: TlsPolicy, roots: I) -> Result<Self, TlsDriverError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut store = RootCertStore::empty();
        let mut count = 0_usize;
        let mut total_bytes = 0_usize;
        for root in roots {
            count = count
                .checked_add(1)
                .ok_or(TlsDriverError::TrustRootCountExceeded {
                    attempted: usize::MAX,
                    maximum: MAX_TRUST_ROOTS,
                })?;
            if count > MAX_TRUST_ROOTS {
                return Err(TlsDriverError::TrustRootCountExceeded {
                    attempted: count,
                    maximum: MAX_TRUST_ROOTS,
                });
            }
            let root = root.as_ref();
            total_bytes = total_bytes.checked_add(root.len()).ok_or(
                TlsDriverError::TrustRootBytesExceeded {
                    attempted: usize::MAX,
                    maximum: MAX_TRUST_ROOT_BYTES,
                },
            )?;
            if total_bytes > MAX_TRUST_ROOT_BYTES {
                return Err(TlsDriverError::TrustRootBytesExceeded {
                    attempted: total_bytes,
                    maximum: MAX_TRUST_ROOT_BYTES,
                });
            }
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(root.len())
                .map_err(|_| TlsDriverError::AllocationFailed)?;
            owned.extend_from_slice(root);
            store
                .add(CertificateDer::from(owned))
                .map_err(TlsDriverError::InvalidTrustRoot)?;
        }
        if count == 0 {
            return Err(TlsDriverError::EmptyTrustStore);
        }
        Self::finish(policy, store, count, 0, 0)
    }

    fn finish(
        policy: TlsPolicy,
        roots: RootCertStore,
        trust_roots: usize,
        ignored_native_roots: usize,
        native_load_errors: usize,
    ) -> Result<Self, TlsDriverError> {
        let versions = match policy.minimum_version() {
            TlsVersion::Tls12 => &[&rustls::version::TLS13, &rustls::version::TLS12][..],
            TlsVersion::Tls13 => &[&rustls::version::TLS13][..],
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let backend = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(TlsDriverError::BackendConfiguration)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            backend: Arc::new(backend),
            policy,
            trust_roots,
            ignored_native_roots,
            native_load_errors,
        })
    }

    /// Returns the TLS security policy encoded by this configuration.
    #[must_use]
    pub const fn policy(&self) -> TlsPolicy {
        self.policy
    }

    /// Returns successfully parsed trust-anchor count.
    #[must_use]
    pub const fn trust_root_count(&self) -> usize {
        self.trust_roots
    }

    /// Returns native certificates ignored as unparseable by Rustls.
    #[must_use]
    pub const fn ignored_native_root_count(&self) -> usize {
        self.ignored_native_roots
    }

    /// Returns native-store loading errors encountered beside usable roots.
    #[must_use]
    pub const fn native_load_error_count(&self) -> usize {
        self.native_load_errors
    }
}

impl fmt::Debug for TlsClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsClientConfig")
            .field("minimum_version", &self.policy.minimum_version())
            .field("trust_roots", &self.trust_roots)
            .field("ignored_native_roots", &self.ignored_native_roots)
            .field("native_load_errors", &self.native_load_errors)
            .finish_non_exhaustive()
    }
}
