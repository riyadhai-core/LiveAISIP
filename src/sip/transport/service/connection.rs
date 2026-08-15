// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Attached reliable-driver ownership and protocol-neutral operations.

use std::io;
use std::net::TcpStream;
use std::sync::Arc;

use crate::sip::transport::ReceivedMessage;
use crate::sip::transport::connection::ConnectionId;
use crate::sip::transport::destination::Protocol;
use crate::sip::transport::flow::FlowId;
use crate::sip::transport::tcp_driver::{TcpDriver, WriteProgress};
use crate::sip::transport::tls_driver::{TlsDriver, TlsShutdownProgress, TlsWriteProgress};

use super::error::ServiceError;
use super::model::ServiceShutdownProgress;

pub(super) enum ReliableDriver {
    Tcp(Box<[TcpDriver; 1]>),
    Tls(Box<[TlsDriver; 1]>),
}

impl ReliableDriver {
    pub(super) const fn protocol(&self) -> Protocol {
        match self {
            Self::Tcp(_) => Protocol::Tcp,
            Self::Tls(_) => Protocol::Tls,
        }
    }

    pub(super) const fn flow_id(&self) -> FlowId {
        match self {
            Self::Tcp(driver) => driver[0].flow_id(),
            Self::Tls(driver) => driver[0].flow_id(),
        }
    }

    pub(super) const fn peer_addr(&self) -> std::net::SocketAddr {
        match self {
            Self::Tcp(driver) => driver[0].peer_addr(),
            Self::Tls(driver) => driver[0].peer_addr(),
        }
    }

    pub(super) fn has_pending_write(&self) -> bool {
        match self {
            Self::Tcp(driver) => driver[0].pending_write_bytes() != 0,
            Self::Tls(driver) => driver[0].has_pending_write(),
        }
    }

    pub(super) fn wants_socket_write(&self) -> bool {
        match self {
            Self::Tcp(driver) => driver[0].pending_write_bytes() != 0,
            Self::Tls(driver) => {
                driver[0].has_pending_write() || driver[0].encrypted_write_pending()
            }
        }
    }

    pub(super) const fn nonblocking(&self) -> bool {
        match self {
            Self::Tcp(driver) => driver[0].config().nonblocking(),
            Self::Tls(driver) => driver[0].nonblocking(),
        }
    }

    pub(super) fn try_clone_socket(&self) -> io::Result<TcpStream> {
        match self {
            Self::Tcp(driver) => driver[0].try_clone_socket(),
            Self::Tls(driver) => driver[0].try_clone_socket(),
        }
    }

    pub(super) fn flush_transport(&mut self) -> Result<bool, ServiceError> {
        match self {
            Self::Tcp(_) => Ok(true),
            Self::Tls(driver) => driver[0].flush_encrypted_once().map_err(ServiceError::Tls),
        }
    }

    pub(super) fn start_send(&mut self, message: Arc<[u8]>) -> Result<bool, ServiceError> {
        match self {
            Self::Tcp(driver) => driver[0]
                .start_send(message)
                .map(|progress| matches!(progress, WriteProgress::Complete))
                .map_err(ServiceError::Tcp),
            Self::Tls(driver) => driver[0]
                .start_send(message)
                .map(|progress| matches!(progress, TlsWriteProgress::Complete))
                .map_err(ServiceError::Tls),
        }
    }

    pub(super) fn flush_send(&mut self) -> Result<bool, ServiceError> {
        match self {
            Self::Tcp(driver) => driver[0]
                .flush_send()
                .map(|progress| matches!(progress, WriteProgress::Complete))
                .map_err(ServiceError::Tcp),
            Self::Tls(driver) => driver[0]
                .flush_send()
                .map(|progress| matches!(progress, TlsWriteProgress::Complete))
                .map_err(ServiceError::Tls),
        }
    }

    pub(super) fn receive(&mut self) -> Result<ReceivedMessage, ServiceError> {
        match self {
            Self::Tcp(driver) => driver[0].receive().map_err(ServiceError::Tcp),
            Self::Tls(driver) => driver[0].receive().map_err(ServiceError::Tls),
        }
    }

    pub(super) fn shutdown(&mut self) -> Result<ServiceShutdownProgress, ServiceError> {
        match self {
            Self::Tcp(driver) => driver[0]
                .shutdown()
                .map(|()| ServiceShutdownProgress::Complete)
                .map_err(ServiceError::Tcp),
            Self::Tls(driver) => driver[0]
                .shutdown()
                .map(|progress| match progress {
                    TlsShutdownProgress::Complete => ServiceShutdownProgress::Complete,
                    TlsShutdownProgress::Pending => ServiceShutdownProgress::Pending,
                })
                .map_err(ServiceError::Tls),
        }
    }
}

pub(super) struct ActiveFlow {
    pub(super) driver: ReliableDriver,
    pub(super) inflight: Option<Arc<[u8]>>,
}

pub(super) fn flow_id(id: ConnectionId) -> Result<FlowId, ServiceError> {
    FlowId::new(id.get()).map_err(|_| ServiceError::InternalConnectionInvariant)
}

pub(super) fn box_one<T>(value: T) -> Result<Box<[T; 1]>, ServiceError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(1)
        .map_err(|_| ServiceError::AllocationFailed)?;
    values.push(value);
    values
        .into_boxed_slice()
        .try_into()
        .map_err(|_| ServiceError::InternalConnectionInvariant)
}
