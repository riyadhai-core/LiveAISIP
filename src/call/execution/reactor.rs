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

//! Call-owned kernel readiness wait for commands, signaling, and media.
//!
//! The reactor owns only duplicated descriptors. It never reads protocol bytes
//! and therefore cannot mutate call state outside [`CallRuntime`]. A call with
//! no active media blocks indefinitely until a command, SIP datagram, or exact
//! monotonic deadline wakes it; active media keeps its separate 10 ms deadline.

use std::error::Error as StdError;
use std::fmt;
use std::io;

use super::runtime::CallRuntime;

/// Readiness observed during one bounded kernel wait.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CallReady(u8);

impl CallReady {
    const COMMAND: u8 = 1 << 0;
    const SIGNALING: u8 = 1 << 1;
    const RTP: u8 = 1 << 2;
    const RTCP: u8 = 1 << 3;

    const fn from_mask(mask: u8) -> Self {
        Self(mask)
    }

    pub(crate) const fn command(self) -> bool {
        self.0 & Self::COMMAND != 0
    }

    pub(crate) const fn signaling(self) -> bool {
        self.0 & Self::SIGNALING != 0
    }

    pub(crate) const fn rtp(self) -> bool {
        self.0 & Self::RTP != 0
    }

    pub(crate) const fn rtcp(self) -> bool {
        self.0 & Self::RTCP != 0
    }

    #[cfg(test)]
    const fn merge(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Privacy-safe call-reactor construction or wait failure.
#[derive(Debug)]
pub enum CallReactorError {
    /// A protocol socket could not be duplicated for readiness observation.
    CloneSource(io::Error),
    /// The command wake source could not be created or drained.
    Wake(io::Error),
    /// The operating-system readiness wait failed.
    Wait(io::Error),
    /// A registered low-cardinality source reported a terminal condition.
    SourceFailed(&'static str),
    /// This platform cannot observe installed network sources.
    #[cfg(not(unix))]
    UnsupportedNetworkReadiness,
}

impl CallReactorError {
    pub(crate) const fn class(&self) -> &'static str {
        match self {
            Self::CloneSource(_) => "clone-source",
            Self::Wake(_) => "wake",
            Self::Wait(_) => "wait",
            Self::SourceFailed(_) => "source-failed",
            #[cfg(not(unix))]
            Self::UnsupportedNetworkReadiness => "unsupported-network-readiness",
        }
    }
}

impl fmt::Display for CallReactorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::SourceFailed(source) = self {
            return write!(formatter, "call reactor source failed: {source}");
        }
        write!(formatter, "call reactor error: {}", self.class())
    }
}

impl StdError for CallReactorError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::CloneSource(source) | Self::Wake(source) | Self::Wait(source) => Some(source),
            Self::SourceFailed(_) => None,
            #[cfg(not(unix))]
            Self::UnsupportedNetworkReadiness => None,
        }
    }
}

#[cfg(unix)]
mod platform {
    use std::io::{self, Read, Write};
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::rtp::transport::Component;

    use super::{CallReactorError, CallReady, CallRuntime};

    const WAKE_INDEX: usize = 0;
    const SIGNALING_INDEX: usize = 1;
    const RTP_INDEX: usize = 2;
    const RTCP_INDEX: usize = 3;
    const SOURCE_COUNT: usize = 4;
    const WAKE_DRAIN_BYTES: usize = 256;

    #[derive(Clone)]
    pub(crate) struct CallReactorNotifier {
        writer: Arc<UnixStream>,
    }

    impl CallReactorNotifier {
        pub(crate) fn notify(&self) -> io::Result<()> {
            let mut writer = self.writer.as_ref();
            match writer.write(&[1]) {
                Ok(_) => Ok(()),
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => Ok(()),
                Err(source) => Err(source),
            }
        }
    }

    impl std::fmt::Debug for CallReactorNotifier {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("CallReactorNotifier")
                .finish_non_exhaustive()
        }
    }

    pub(crate) struct CallReactor {
        wake_reader: UnixStream,
        signaling: Option<UdpSocket>,
        rtp: Option<UdpSocket>,
        rtcp: Option<UdpSocket>,
    }

    impl CallReactor {
        pub(crate) fn new(
            runtime: &CallRuntime,
        ) -> Result<(Self, CallReactorNotifier), CallReactorError> {
            let signaling = runtime
                .try_clone_signaling_readiness()
                .map_err(CallReactorError::CloneSource)?;
            let media_socket = runtime
                .try_clone_media_readiness(Component::Rtp)
                .map_err(CallReactorError::CloneSource)?;
            let control_socket = runtime
                .try_clone_media_readiness(Component::Rtcp)
                .map_err(CallReactorError::CloneSource)?;
            let (wake_reader, wake_writer) = UnixStream::pair().map_err(CallReactorError::Wake)?;
            wake_reader
                .set_nonblocking(true)
                .map_err(CallReactorError::Wake)?;
            wake_writer
                .set_nonblocking(true)
                .map_err(CallReactorError::Wake)?;
            let notifier = CallReactorNotifier {
                writer: Arc::new(wake_writer),
            };
            Ok((
                Self {
                    wake_reader,
                    signaling,
                    rtp: media_socket,
                    rtcp: control_socket,
                },
                notifier,
            ))
        }

        pub(crate) fn wait(
            &mut self,
            timeout: Option<Duration>,
        ) -> Result<CallReady, CallReactorError> {
            let deadline = timeout.and_then(|duration| Instant::now().checked_add(duration));
            loop {
                let remaining = deadline.map(|at| at.saturating_duration_since(Instant::now()));
                let mut sources = [
                    poll_source(self.wake_reader.as_raw_fd()),
                    optional_source(self.signaling.as_ref()),
                    optional_source(self.rtp.as_ref()),
                    optional_source(self.rtcp.as_ref()),
                ];
                // SAFETY: `sources` is valid writable storage for exactly
                // `SOURCE_COUNT` poll descriptors for the duration of the call.
                let result = unsafe {
                    libc::poll(
                        sources.as_mut_ptr(),
                        libc::nfds_t::try_from(SOURCE_COUNT).unwrap_or(libc::nfds_t::MAX),
                        timeout_milliseconds(remaining),
                    )
                };
                if result < 0 {
                    let source = io::Error::last_os_error();
                    if source.kind() == io::ErrorKind::Interrupted {
                        if deadline.is_some_and(|at| Instant::now() >= at) {
                            return Ok(CallReady::default());
                        }
                        continue;
                    }
                    return Err(CallReactorError::Wait(source));
                }
                if result == 0 {
                    return Ok(CallReady::default());
                }
                let wake = sources[WAKE_INDEX].revents;
                let signaling = sources[SIGNALING_INDEX].revents;
                let media_events = sources[RTP_INDEX].revents;
                let control_events = sources[RTCP_INDEX].revents;
                reject_failed_source(signaling, "signaling")?;
                reject_failed_source(media_events, "rtp")?;
                reject_failed_source(control_events, "rtcp")?;
                let command = wake != 0;
                if command {
                    self.drain_wake()?;
                }
                let ready = (if command { CallReady::COMMAND } else { 0 })
                    | (if is_readable(signaling) {
                        CallReady::SIGNALING
                    } else {
                        0
                    })
                    | (if is_readable(media_events) {
                        CallReady::RTP
                    } else {
                        0
                    })
                    | (if is_readable(control_events) {
                        CallReady::RTCP
                    } else {
                        0
                    });
                return Ok(CallReady::from_mask(ready));
            }
        }

        fn drain_wake(&mut self) -> Result<(), CallReactorError> {
            let mut storage = [0_u8; WAKE_DRAIN_BYTES];
            loop {
                match self.wake_reader.read(&mut storage) {
                    Ok(0) => return Ok(()),
                    Ok(_) => {}
                    Err(source) if source.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(source) => return Err(CallReactorError::Wake(source)),
                }
            }
        }
    }

    fn poll_source(descriptor: libc::c_int) -> libc::pollfd {
        libc::pollfd {
            fd: descriptor,
            events: libc::POLLIN,
            revents: 0,
        }
    }

    fn optional_source(socket: Option<&UdpSocket>) -> libc::pollfd {
        socket.map_or(
            libc::pollfd {
                fd: -1,
                events: 0,
                revents: 0,
            },
            |socket| poll_source(socket.as_raw_fd()),
        )
    }

    const fn is_readable(events: libc::c_short) -> bool {
        events & libc::POLLIN != 0
    }

    fn reject_failed_source(
        events: libc::c_short,
        source: &'static str,
    ) -> Result<(), CallReactorError> {
        if events & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(CallReactorError::SourceFailed(source));
        }
        Ok(())
    }

    fn timeout_milliseconds(timeout: Option<Duration>) -> libc::c_int {
        let Some(timeout) = timeout else {
            return -1;
        };
        if timeout.is_zero() {
            return 0;
        }
        let millis = timeout.as_millis();
        let rounded = if timeout.subsec_nanos() % 1_000_000 == 0 {
            millis
        } else {
            millis.saturating_add(1)
        };
        libc::c_int::try_from(rounded).unwrap_or(libc::c_int::MAX)
    }
}

#[cfg(not(unix))]
mod platform {
    use std::io;
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use crate::rtp::transport::Component;

    use super::{CallReactorError, CallReady, CallRuntime};

    #[derive(Clone, Debug)]
    pub(crate) struct CallReactorNotifier {
        wake: Arc<(Mutex<u64>, Condvar)>,
    }

    impl CallReactorNotifier {
        pub(crate) fn notify(&self) -> io::Result<()> {
            let (counter, condition) = self.wake.as_ref();
            let mut counter = counter.lock().unwrap_or_else(|error| error.into_inner());
            *counter = counter.wrapping_add(1);
            condition.notify_one();
            Ok(())
        }
    }

    pub(crate) struct CallReactor {
        wake: Arc<(Mutex<u64>, Condvar)>,
        observed: u64,
    }

    impl CallReactor {
        pub(crate) fn new(
            runtime: &CallRuntime,
        ) -> Result<(Self, CallReactorNotifier), CallReactorError> {
            let has_network = runtime
                .try_clone_signaling_readiness()
                .map_err(CallReactorError::CloneSource)?
                .is_some()
                || runtime
                    .try_clone_media_readiness(Component::Rtp)
                    .map_err(CallReactorError::CloneSource)?
                    .is_some()
                || runtime
                    .try_clone_media_readiness(Component::Rtcp)
                    .map_err(CallReactorError::CloneSource)?
                    .is_some();
            if has_network {
                return Err(CallReactorError::UnsupportedNetworkReadiness);
            }
            let wake = Arc::new((Mutex::new(0), Condvar::new()));
            Ok((
                Self {
                    wake: Arc::clone(&wake),
                    observed: 0,
                },
                CallReactorNotifier { wake },
            ))
        }

        pub(crate) fn wait(
            &mut self,
            timeout: Option<Duration>,
        ) -> Result<CallReady, CallReactorError> {
            let (counter, condition) = self.wake.as_ref();
            let guard = counter.lock().unwrap_or_else(|error| error.into_inner());
            let guard = match timeout {
                Some(timeout) => {
                    let (guard, _) = condition
                        .wait_timeout_while(guard, timeout, |value| *value == self.observed)
                        .unwrap_or_else(|error| error.into_inner());
                    guard
                }
                None => condition
                    .wait_while(guard, |value| *value == self.observed)
                    .unwrap_or_else(|error| error.into_inner()),
            };
            let command = *guard != self.observed;
            self.observed = *guard;
            Ok(CallReady::from_mask(if command {
                CallReady::COMMAND
            } else {
                0
            }))
        }
    }
}

pub(crate) use platform::{CallReactor, CallReactorNotifier};

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::time::Duration;

    use super::{CallReactor, CallReady};
    use crate::call::execution::runtime::{
        CallRuntime, CallRuntimeConfig, DEFAULT_CALL_DEADLINE_CAPACITY,
        DEFAULT_CALL_DIALOG_CAPACITY, DEFAULT_CALL_TRANSACTION_CAPACITY,
    };
    use crate::call::model::context::CallContext;
    #[cfg(unix)]
    use crate::call::signaling::UdpSignaling;
    #[cfg(unix)]
    use crate::rtp::transport::{Component, MediaSocketPair, PortPool, SocketConfig};
    use crate::runtime::admission::AdmissionLeaseGroup;
    #[cfg(unix)]
    use crate::sip::transport::udp::UdpConfig;
    #[cfg(unix)]
    use crate::sip::transport::udp_driver::UdpDriverConfig;

    fn runtime() -> CallRuntime {
        let context = CallContext::new(Duration::ZERO, 8).unwrap_or_else(|_| panic!("context"));
        CallRuntime::new(
            context,
            AdmissionLeaseGroup::new(),
            CallRuntimeConfig::new(
                DEFAULT_CALL_TRANSACTION_CAPACITY,
                DEFAULT_CALL_DIALOG_CAPACITY,
                DEFAULT_CALL_DEADLINE_CAPACITY,
                Duration::from_secs(1),
                false,
            ),
        )
        .unwrap_or_else(|_| panic!("runtime"))
    }

    #[cfg(unix)]
    fn media_pair() -> MediaSocketPair {
        for port in (42_000_u16..60_000).step_by(2) {
            let Ok(pool) = PortPool::new(port, port) else {
                continue;
            };
            let Some(lease) = pool.allocate() else {
                continue;
            };
            if let Ok(pair) = MediaSocketPair::bind(
                lease,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                SocketConfig::default(),
            ) {
                return pair;
            }
        }
        panic!("no loopback media pair available")
    }

    #[test]
    fn notifier_wakes_an_indefinite_call_wait() {
        let (mut reactor, notifier) =
            CallReactor::new(&runtime()).unwrap_or_else(|_| panic!("reactor"));
        let waiter = std::thread::spawn(move || reactor.wait(Some(Duration::from_secs(5))));
        assert!(notifier.notify().is_ok());
        let ready = waiter
            .join()
            .unwrap_or_else(|_| panic!("join"))
            .unwrap_or_else(|_| panic!("wait"));
        assert_eq!(ready, CallReady::from_mask(CallReady::COMMAND));
    }

    #[test]
    fn zero_timeout_returns_without_periodic_polling() {
        let (mut reactor, _notifier) =
            CallReactor::new(&runtime()).unwrap_or_else(|_| panic!("reactor"));
        let ready = reactor
            .wait(Some(Duration::ZERO))
            .unwrap_or_else(|_| panic!("wait"));
        assert_eq!(ready, CallReady::default());
    }

    #[cfg(unix)]
    #[test]
    fn one_wait_observes_command_sip_rtp_and_rtcp_readiness() {
        let signaling_peer =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("SIP peer"));
        let signaling = UdpSignaling::bind(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            signaling_peer
                .local_addr()
                .unwrap_or_else(|_| panic!("SIP peer address")),
            UdpDriverConfig::default(),
            UdpConfig::default(),
        )
        .unwrap_or_else(|_| panic!("signaling"));
        let signaling_address = signaling.local_addr();
        let media = media_pair();
        let media_address = media
            .local_addr(Component::Rtp)
            .unwrap_or_else(|_| panic!("RTP address"));
        let control_address = media
            .local_addr(Component::Rtcp)
            .unwrap_or_else(|_| panic!("RTCP address"));
        let runtime = runtime()
            .with_udp_signaling(signaling)
            .and_then(|runtime| runtime.with_media_sockets(media))
            .unwrap_or_else(|_| panic!("runtime resources"));
        let (mut reactor, notifier) =
            CallReactor::new(&runtime).unwrap_or_else(|_| panic!("reactor"));
        let media_peer =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|_| panic!("media peer"));

        assert!(signaling_peer.send_to(b"sip", signaling_address).is_ok());
        assert!(media_peer.send_to(b"rtp", media_address).is_ok());
        assert!(media_peer.send_to(b"rtcp", control_address).is_ok());
        assert!(notifier.notify().is_ok());

        let mut observed = CallReady::default();
        for _ in 0..4 {
            observed = observed.merge(
                reactor
                    .wait(Some(Duration::from_secs(1)))
                    .unwrap_or_else(|_| panic!("wait")),
            );
            if observed.command() && observed.signaling() && observed.rtp() && observed.rtcp() {
                break;
            }
        }
        assert!(observed.command());
        assert!(observed.signaling());
        assert!(observed.rtp());
        assert!(observed.rtcp());
    }
}
