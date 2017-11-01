// Copyright 2017 Dmitry Tantsur <divius.inside@gmail.com>
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

//! Compute API (v2 with microversions) implementation.
//!
//! Currently supported functionality:
//!
//! * [server management](struct.ServerManager.html) (incomplete)
//!
//! # Examples
//!
//! ```rust,no_run
//! use openstack;
//!
//! let auth = openstack::auth::Identity::from_env()
//!     .expect("Unable to authenticate");
//! let session = openstack::Session::new(auth);
//! let servers = openstack::compute::v2::servers(&session);
//!
//! let server = servers.get("8a1c355b-2e1e-440a-8aa8-f272df72bc32")
//!     .expect("Unable to get a server");
//! ```
//!
//! Compute API supports version negotiation:
//!
//! ```rust,no_run
//! use openstack;
//!
//! let auth = openstack::auth::Identity::from_env()
//!     .expect("Unable to authenticate");
//! let mut session = openstack::Session::new(auth);
//! let version = session.negotiate_api_version::<openstack::compute::V2>(
//!     openstack::ApiVersionRequest::Exact(openstack::ApiVersion(2, 10))
//! ).expect("API version 2.10 is not supported");
//!
//! let servers = openstack::compute::v2::servers(&session);
//! ```

mod base;
mod servermanager;
mod protocol;

use std::fmt::Display;
use std::rc::Rc;

use futures::{future, Future, Stream};
use hyper::{Get, NotFound, Uri};

use super::super::{ApiError, ApiResult, ApiVersion};
use super::super::ApiError::{HttpError, EndpointNotFound};
use super::super::auth::AuthMethod;
use super::super::service::{ApiVersioning, Query, Service};
use super::super::http;

use self::base::ComputeService;
pub use self::protocol::{AddressType, ServerAddress, ServerSortKey,
                         ServerStatus};
pub use self::servermanager::{Server, ServerList, ServerManager,
                              ServerQuery, ServerSummary, FlavorRef, ImageRef};


#[derive(Clone, Debug)]
/// Compute service client.
pub struct Compute {
    service: Rc<ComputeService>
}

impl Compute {
    /// Create a new Compute service client.
    pub fn new<A: AuthMethod + 'static>(auth: A) -> ApiResult<Compute> {
        let maybe_ep = auth.get_endpoint(base::SERVICE_TYPE.to_string(), None);
        ApiResult::from_future(maybe_ep.and_then(|ep| {
             let secure = ep.scheme() == Some("https");
             let res1 = auth.request(http::Request::new(Get, ep.clone()));
             res1.or_else(|err| {
                 match err {
                    HttpError(NotFound, ..) => {
                        // TODO: try striping /
                        ApiResult::err(err)
                    },
                    err => ApiResult::err(err)
                 }
             }).and_then(|res| {
                 res.body().concat2().map_err(From::from)
             }).and_then(|chunk| {
                let (min, max) = match base::extract_info(&chunk) {
                    Ok(x) => x,
                    Err(e) => return ApiResult::err(e)
                };
                let service = ComputeService {
                    auth: Box::new(auth),
                    root: ep,
                    min_version: min,
                    max_version: max,
                    current_version: None
                };

                ApiResult::ok(Compute {
                    service: Rc::new(service)
                })
             })
        }))
    }

    /// Run a query against server list.
    ///
    /// Note that this method does not return results immediately, but rather
    /// a [ServerQuery](struct.ServerQuery.html) object that
    /// you can futher specify with e.g. filtering or sorting.
    pub fn find_servers(&self) -> ServerQuery {
        ServerQuery::new(self)
    }

    /// List all servers.
    pub fn list_servers(&self) -> ApiResult<ServerList> {
        self.find_servers().fetch()
    }

    /// Get a server.
    pub fn get_server<Id: Display>(&self, id: Id) -> ApiResult<Server> {
        get_server(&self.service, id)
    }
}

fn get_server<Id: Display>(service: &Rc<ComputeService>,
                           id: Id) -> ApiResult<Server> {
    trace!("Get compute server {}", id);
    let new_service = service.clone();
    let uri = format!("/servers/{}", id);
    ApiResult::from_future(
        service.get::<protocol::ServerRoot>(&uri, &Query::new())
            .and_then(|inner| {
                trace!("Received {:?}", inner.server);
                ApiResult::ok(Server {
                    service: new_service,
                    inner: inner.server
                })
            })
    )
}


impl ApiVersioning for Compute {
    fn supported_api_version_range(&self) -> (ApiVersion, ApiVersion) {
        (self.service.min_version, self.service.max_version)
    }

    fn set_api_version(&mut self, version: ApiVersion) -> Option<ApiVersion> {
        let maybe_version = if version >= self.service.min_version &&
                version <= self.service.max_version {
            Some(version)
        } else {
            None
        };

        if maybe_version.is_some() {
            self.service.current_version = maybe_version.clone()
        }

        maybe_version
    }
}
