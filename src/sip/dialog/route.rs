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

//! Bounded SIP dialog route sets and request routing plans.
//!
//! Route-set establishment is role-sensitive: a UAC preserves `Record-Route`
//! order from the response, while a UAS reverses the order received in the
//! request. Request calculation implements both loose routing (`lr`) and the
//! legacy strict-routing rewrite without mutating the stored dialog state.

use std::error::Error as StdError;
use std::fmt;

use crate::sip::types::uri::Uri;

/// Maximum number of route URIs retained by one dialog.
pub const MAX_DIALOG_ROUTES: usize = 64;

/// An immutable, role-oriented dialog route set.
#[derive(Clone, Eq, PartialEq)]
pub struct RouteSet {
    routes: Vec<Uri>,
}

impl RouteSet {
    /// Creates an empty route set for a dialog established without
    /// `Record-Route`.
    #[must_use]
    pub const fn empty() -> Self {
        Self { routes: Vec::new() }
    }

    /// Creates the route set for a locally initiated dialog.
    ///
    /// `routes` must be supplied in the wire order of the response's
    /// `Record-Route` values.
    ///
    /// # Errors
    ///
    /// Returns [`DialogRouteError::TooManyRoutes`] when the operational bound
    /// is exceeded.
    pub fn for_uac(routes: Vec<Uri>) -> Result<Self, DialogRouteError> {
        Self::from_ordered(routes)
    }

    /// Creates the route set for a remotely initiated dialog.
    ///
    /// `routes` must be supplied in the wire order of the request's
    /// `Record-Route` values. The order is reversed as required for a UAS.
    ///
    /// # Errors
    ///
    /// Returns [`DialogRouteError::TooManyRoutes`] when the operational bound
    /// is exceeded.
    pub fn for_uas(mut routes: Vec<Uri>) -> Result<Self, DialogRouteError> {
        check_count(routes.len())?;
        routes.reverse();
        Ok(Self { routes })
    }

    /// Creates a route set already oriented from the local user agent toward
    /// the remote target.
    ///
    /// # Errors
    ///
    /// Returns [`DialogRouteError::TooManyRoutes`] when the operational bound
    /// is exceeded.
    pub fn from_ordered(routes: Vec<Uri>) -> Result<Self, DialogRouteError> {
        check_count(routes.len())?;
        Ok(Self { routes })
    }

    /// Returns route URIs in local outbound order.
    #[must_use]
    pub fn as_slice(&self) -> &[Uri] {
        &self.routes
    }

    /// Returns the number of route URIs.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.routes.len()
    }

    /// Returns whether no route set was established.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Calculates the Request-URI and `Route` values for an in-dialog request.
    ///
    /// With no route set, or with a loose router first, the Request-URI remains
    /// the remote target. For strict routing, the first route becomes the
    /// Request-URI and the remote target is appended as the final `Route`.
    #[must_use]
    pub fn plan(&self, remote_target: &Uri) -> RoutingPlan {
        let Some(first) = self.routes.first() else {
            return RoutingPlan {
                request_uri: remote_target.clone(),
                routes: Vec::new(),
            };
        };

        if has_lr(first) {
            return RoutingPlan {
                request_uri: remote_target.clone(),
                routes: self.routes.clone(),
            };
        }

        let mut routes = Vec::with_capacity(self.routes.len());
        routes.extend(self.routes.iter().skip(1).cloned());
        routes.push(remote_target.clone());
        RoutingPlan {
            request_uri: first.clone(),
            routes,
        }
    }
}

impl Default for RouteSet {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for RouteSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteSet")
            .field("route_count", &self.routes.len())
            .field(
                "first_route_is_loose",
                &self.routes.first().is_some_and(has_lr),
            )
            .finish_non_exhaustive()
    }
}

/// The wire-routing inputs for one outbound in-dialog request.
#[derive(Clone, Eq, PartialEq)]
pub struct RoutingPlan {
    request_uri: Uri,
    routes: Vec<Uri>,
}

impl RoutingPlan {
    /// Returns the request's Request-URI.
    #[must_use]
    pub const fn request_uri(&self) -> &Uri {
        &self.request_uri
    }

    /// Returns ordered `Route` header URIs.
    #[must_use]
    pub fn routes(&self) -> &[Uri] {
        &self.routes
    }
}

impl fmt::Debug for RoutingPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoutingPlan")
            .field("request_uri_scheme", &self.request_uri.scheme())
            .field("route_count", &self.routes.len())
            .finish_non_exhaustive()
    }
}

/// A route-set construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogRouteError {
    /// The route set exceeded the configured count bound.
    TooManyRoutes {
        /// Observed route count.
        count: usize,
        /// Maximum accepted route count.
        maximum: usize,
    },
}

impl fmt::Display for DialogRouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyRoutes { count, maximum } => {
                write!(formatter, "dialog has {count} routes; maximum is {maximum}")
            }
        }
    }
}

impl StdError for DialogRouteError {}

fn check_count(count: usize) -> Result<(), DialogRouteError> {
    if count > MAX_DIALOG_ROUTES {
        Err(DialogRouteError::TooManyRoutes {
            count,
            maximum: MAX_DIALOG_ROUTES,
        })
    } else {
        Ok(())
    }
}

fn has_lr(uri: &Uri) -> bool {
    uri.as_sip().and_then(|uri| uri.parameter("lr")).is_some()
}

#[cfg(test)]
mod tests {
    use crate::sip::parser::uri::parse_str;

    use super::{DialogRouteError, MAX_DIALOG_ROUTES, RouteSet};

    fn uri(value: &str) -> crate::sip::types::uri::Uri {
        parse_str(value).unwrap_or_else(|_| panic!("valid test URI"))
    }

    #[test]
    fn direct_routing_uses_remote_target() {
        let target = uri("sip:callee@target.example");
        let plan = RouteSet::empty().plan(&target);
        assert_eq!(plan.request_uri(), &target);
        assert!(plan.routes().is_empty());
    }

    #[test]
    fn loose_routing_preserves_target_and_route_order() {
        let first = uri("sip:proxy-a.example;lr");
        let second = uri("sip:proxy-b.example;lr");
        let target = uri("sip:callee@target.example");
        let Ok(set) = RouteSet::for_uac(vec![first.clone(), second.clone()]) else {
            panic!("bounded route set")
        };
        let plan = set.plan(&target);
        assert_eq!(plan.request_uri(), &target);
        assert_eq!(plan.routes(), &[first, second]);
    }

    #[test]
    fn strict_routing_rewrites_request_uri_and_appends_target() {
        let strict = uri("sip:strict.example");
        let next = uri("sip:next.example;lr");
        let target = uri("sip:callee@target.example");
        let Ok(set) = RouteSet::for_uac(vec![strict.clone(), next.clone()]) else {
            panic!("bounded route set")
        };
        let plan = set.plan(&target);
        assert_eq!(plan.request_uri(), &strict);
        assert_eq!(plan.routes(), &[next, target]);
    }

    #[test]
    fn uas_reverses_record_route_wire_order() {
        let first = uri("sip:first.example;lr");
        let second = uri("sip:second.example;lr");
        let Ok(set) = RouteSet::for_uas(vec![first.clone(), second.clone()]) else {
            panic!("bounded route set")
        };
        assert_eq!(set.as_slice(), &[second, first]);
    }

    #[test]
    fn route_count_is_bounded() {
        let routes = (0..=MAX_DIALOG_ROUTES)
            .map(|index| uri(&format!("sip:p{index}.example;lr")))
            .collect();
        assert_eq!(
            RouteSet::for_uac(routes),
            Err(DialogRouteError::TooManyRoutes {
                count: MAX_DIALOG_ROUTES + 1,
                maximum: MAX_DIALOG_ROUTES,
            })
        );
    }

    #[test]
    fn diagnostics_do_not_expose_route_hosts_or_target() {
        let Ok(set) = RouteSet::for_uac(vec![uri("sip:secret-proxy.example;lr")]) else {
            panic!("bounded route set")
        };
        let plan = set.plan(&uri("sip:private-user@secret-target.example"));
        let debug = format!("{set:?} {plan:?}");
        assert!(!debug.contains("secret-proxy"));
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("secret-target"));
    }
}
