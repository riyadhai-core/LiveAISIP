// Copyright 2026 RiyadhAI LLC
// Licensed under the Apache License, Version 2.0.

//! Dialog routing extraction and Route-header construction.

use crate::sip::dialog::route::{DialogRouteError, MAX_DIALOG_ROUTES, RouteSet};
use crate::sip::headers::contact::Contact;
use crate::sip::headers::record_route::{RecordRoute, RecordRouteEntry};
use crate::sip::headers::route::Route;
use crate::sip::types::address::Address;
use crate::sip::types::header::HeaderKind;
use crate::sip::types::uri::Uri;
use crate::sip::validation::headers::{
    analyze_logical_value, materialize_logical_value, trim_horizontal_whitespace,
};
use crate::sip::validation::response::ValidatedResponse;

use super::error::SignalingError;

pub(super) fn dialog_routing(
    response: &ValidatedResponse,
    fallback_target: &Uri,
) -> Result<(Uri, RouteSet), SignalingError> {
    let mut remote_target = None;
    let mut routes = Vec::new();
    for field in response.message().header_views() {
        let kind = field.kind().copied();
        if !matches!(kind, Some(HeaderKind::Contact | HeaderKind::RecordRoute)) {
            continue;
        }
        let analysis =
            analyze_logical_value(field.value()).map_err(SignalingError::HeaderNormalization)?;
        let logical =
            materialize_logical_value(analysis).map_err(SignalingError::HeaderNormalization)?;
        let value = trim_horizontal_whitespace(logical.as_ref());
        match kind {
            Some(HeaderKind::Contact) => {
                let contact = Contact::from_bytes(value).map_err(SignalingError::Contact)?;
                let entries = contact
                    .entries()
                    .ok_or(SignalingError::InvalidDialogContact)?;
                for entry in entries {
                    if remote_target.is_some() {
                        return Err(SignalingError::InvalidDialogContact);
                    }
                    remote_target = Some(entry.address().uri().clone());
                }
            }
            Some(HeaderKind::RecordRoute) => {
                let record_route =
                    RecordRoute::from_bytes(value).map_err(SignalingError::RecordRoute)?;
                let attempted = routes
                    .len()
                    .checked_add(record_route.entries().len())
                    .ok_or(SignalingError::DialogRoute(
                        DialogRouteError::TooManyRoutes {
                            count: usize::MAX,
                            maximum: MAX_DIALOG_ROUTES,
                        },
                    ))?;
                if attempted > MAX_DIALOG_ROUTES {
                    return Err(SignalingError::DialogRoute(
                        DialogRouteError::TooManyRoutes {
                            count: attempted,
                            maximum: MAX_DIALOG_ROUTES,
                        },
                    ));
                }
                routes
                    .try_reserve_exact(record_route.entries().len())
                    .map_err(|_| SignalingError::AllocationFailed)?;
                routes.extend(
                    record_route
                        .entries()
                        .iter()
                        .map(|entry| entry.uri().clone()),
                );
            }
            _ => {}
        }
    }
    let remote_target = remote_target.unwrap_or_else(|| fallback_target.clone());
    let route_set = RouteSet::for_uac(routes).map_err(SignalingError::DialogRoute)?;
    Ok((remote_target, route_set))
}

pub(super) fn route_header(routes: &[Uri]) -> Result<Route, SignalingError> {
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(routes.len())
        .map_err(|_| SignalingError::AllocationFailed)?;
    for uri in routes {
        entries.push(
            RecordRouteEntry::new(Address::name_addr(uri.clone()))
                .map_err(SignalingError::RecordRoute)?,
        );
    }
    Route::from_entries(entries).map_err(SignalingError::Route)
}
