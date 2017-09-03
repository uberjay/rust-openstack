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

//! Generic API bits for implementing new services.

use std::marker::PhantomData;

use futures::{future, Future, Poll};
use hyper::{Body, Client, Headers, Method, Request, Response, Uri};
use hyper::client::FutureResponse;
use hyper::header::Header;
use serde::{Deserialize, Serialize};
use serde_json;

use super::{ApiError, ApiResult, ApiVersion, ApiVersionRequest, Session};
use super::http;
use super::utils;


/// Trait of a service.
pub trait Service {
    /// Get basic service information.
    fn service_info(&self) -> &ServiceInfo;

    /// Build a full endpoint for this service, given a partial URI.
    fn get_endpoint(&self, parts: &Uri) -> Uri;

    /// Run an authenticated request against this service.
    fn request(&self, request: http::Request) -> http::ApiResponse;
}

/// Trait representing a service with API version support.
pub trait ApiVersioning : Service {
    /// Set the API version for future use.
    ///
    /// Returns a canonical form of the version or None if it's not compatible.
    fn set_api_version(&mut self, version: ApiVersion) -> Option<ApiVersion>;

    /// Negotiate an API version with the service.
    ///
    /// Negotiation is based on version information returned from the root
    /// endpoint. If no minimum version is returned, the current version is
    /// assumed to be the only supported version.
    ///
    /// The resulting API version may be cached for this instance.
    fn negotiate_api_version(&mut self, requested: ApiVersionRequest)
            -> Option<ApiVersion> {
        let info = self.service_info();
        info.pick_api_version(requested).and_then(|ver| {
            info!("Negotiated API version {} for {} API",
                  ver, self.catalog_type());
            self.set_api_version(ver)
        })
    }
}

/// Information about API endpoint.
#[derive(Clone, Debug)]
pub struct ServiceInfo {
    /// Root endpoint.
    pub root_url: Uri,
    /// Current API version (if supported).
    pub current_version: Option<ApiVersion>,
    /// Minimum API version (if supported).
    pub minimum_version: Option<ApiVersion>
}

/// Base implementation of a service.
///
/// This is not designed to be used directly, but rather through a specific
/// service wrapper.
#[derive(Debug)]
pub struct BaseService<'session> {
    session: &'session Session,
    endpoint_interface: Option<String>,
    info: ServiceInfo
}

/// Type of query parameters.
#[derive(Clone, Debug)]
pub struct Query(pub Vec<(String, String)>);


impl<'session> BaseService<'session> {
    /// Create a new base service object.
    pub fn new(session: &'session Session, service_info: ServiceInfo)
            -> BaseService<'session> {
        BaseService {
            session: session,
            endpoint_interface: None,
            info: service_info
        }
    }
}

impl<'session> Service for BaseService<'session> {
    fn service_info(&self) -> &ServiceInfo {
        &self.info
    }

    fn get_endpoint(&self, parts: &Uri) -> Uri {
        // TODO
        parts.clone()
    }

    fn request(&self, request: http::Request) -> http::ApiResponse {
        // TODO
    }
}

fn fetch_json<T>(resp: Response) -> ApiResult<T>
        where for<'de> T: Deserialize<'de> {
    serde_json::from_reader(resp).map_err(From::from)
}

impl<'session, Srv: ServiceType> ServiceWrapper<'session, Srv> {
    /// Create a new wrapper for the specific service.
    pub fn new(session: &'session Session) -> ServiceWrapper<'session, Srv> {
        ServiceWrapper {
            session: session,
            service_type: PhantomData,
            endpoint_interface: None
        }
    }

    /// Change the endpoint interface used for this wrapper.
    pub fn with_endpoint_interface(self, endpoint_interface: String)
            -> ServiceWrapper<'session, Srv> {
        ServiceWrapper {
            endpoint_interface: Some(endpoint_interface),
            .. self
        }
    }

    /// Construct and endpoint for the given service from the path.
    pub fn get_endpoint<P>(&self, path: P, query: Query) -> ApiResult<Uri>
            where P: IntoIterator, P::Item: AsRef<str> {
        let ep = self.endpoint_interface.clone();
        let info = self.session.get_service_info::<Srv>(ep)?;
        let mut uri = utils::url::extend(info.root_url, path);
        let _ = uri.query_pairs_mut().extend_pairs(query.0);
        Ok(uri)
    }

    /// Make an HTTP request to the given service.
    pub fn request<P>(&self, method: Method, path: P, query: Query)
            -> ApiResult<Request> where P: IntoIterator, P::Item: AsRef<str> {
        let uri = self.get_endpoint(path, query)?;
        let headers = self.session.service_headers::<Srv>();
        trace!("Sending HTTP {} request to {} with {:?}",
               method, uri, headers);
        let request = self.session.request(method, uri);
        request.headers_mut().extend(headers);
        request
    }

    /// Make an HTTP request with JSON body and JSON response.
    pub fn json<P, Req, Res>(&self, method: Method, path: P, query: Query,
                             body: &Req) -> ApiResult<Res>
            where Req: Serialize, for<'de> Res: Deserialize<'de>,
            P: IntoIterator, P::Item: AsRef<str> {
        let str_body = serde_json::to_string(body)?;
        let request = self.request(method, path, query)?;
        request.body(&str_body).fetch_json()
    }

    /// Make a GET request returning a JSON.
    pub fn get_json<P, Res>(&self, path: P, query: Query) -> ApiResult<Res>
            where for<'de> Res: Deserialize<'de>, P: IntoIterator, P::Item: AsRef<str> {
        self.request(Method::Get, path, query)?.fetch_json()
    }

    /// Make a POST request sending and returning a JSON.
    pub fn post_json<P, Req, Res>(&self, path: P, query: Query, body: &Req)
            -> ApiResult<Res> where Req: Serialize, for <'de> Res: Deserialize<'de>,
            P: IntoIterator, P::Item: AsRef<str> {
        self.json(Method::Post, path, query, body)
    }

    /// Make a POST request sending and returning a JSON.
    pub fn put_json<P, Req, Res>(&self, path: P, query: Query, body: &Req)
            -> ApiResult<Res> where Req: Serialize, for<'de> Res: Deserialize<'de>,
            P: IntoIterator, P::Item: AsRef<str> {
        self.json(Method::Put, path, query, body)
    }

    /// Make a PATCH request sending and returning a JSON.
    pub fn patch_json<P, Req, Res>(&self, path: P, query: Query, body: &Req)
            -> ApiResult<Res> where Req: Serialize, for<'de> Res: Deserialize<'de>,
            P: IntoIterator, P::Item: AsRef<str> {
        self.json(Method::Patch, path, query, body)
    }

    /// Make a DELETE request.
    pub fn delete<P>(&self, path: P, query: Query) -> ApiResult<Response>
            where P: IntoIterator, P::Item: AsRef<str> {
        self.request(Method::Delete, path, query)?.send()
    }
}

impl<'session, Srv: ServiceType> Clone for ServiceWrapper<'session, Srv> {
    fn clone(&self) -> ServiceWrapper<'session, Srv> {
        ServiceWrapper {
            session: self.session,
            service_type: PhantomData,
            endpoint_interface: self.endpoint_interface.clone()
        }
    }
}

impl ServiceInfo {
    /// Pick an API version.
    pub fn pick_api_version(&self, request: ApiVersionRequest)
            -> Option<ApiVersion> {
        match request {
            ApiVersionRequest::Minimum =>
                self.minimum_version,
            ApiVersionRequest::Latest =>
                self.current_version,
            ApiVersionRequest::Exact(req) => {
                self.current_version.and_then(|max| {
                    match self.minimum_version {
                        Some(min) if req >= min && req <= max => Some(req),
                        None if req == max => Some(req),
                        _ => None
                    }
                })
            },
            ApiVersionRequest::Choice(vec) => {
                if vec.is_empty() {
                    return None;
                }

                self.current_version.and_then(|max| {
                    match self.minimum_version {
                        Some(min) => vec.into_iter().filter(|x| {
                            *x >= min && *x <= max
                        }).max(),
                        None =>vec.into_iter().find(|x| *x == max)
                    }
                })
            }
        }
    }
}

impl Query {
    /// Empty query.
    pub fn new() -> Query {
        Query(Vec::new())
    }

    /// Add an item to the query.
    pub fn push<K, V>(&mut self, param: K, value: V)
            where K: Into<String>, V: ToString {
        self.0.push((param.into(), value.to_string()))
    }

    /// Add a strng item to the query.
    pub fn push_str<K, V>(&mut self, param: K, value: V)
            where K: Into<String>, V: Into<String> {
        self.0.push((param.into(), value.into()))
    }
}


#[cfg(test)]
pub mod test {
    use hyper::Url;

    use super::super::{ApiVersion, ApiVersionRequest};
    use super::ServiceInfo;

    fn service_info(min: Option<u16>, max: Option<u16>) -> ServiceInfo {
        ServiceInfo {
            root_url: Url::parse("http://127.0.0.1").unwrap(),
            minimum_version: min.map(|x| ApiVersion(2, x)),
            current_version: max.map(|x| ApiVersion(2, x)),
        }
    }

    #[test]
    fn test_pick_version_exact() {
        let info = service_info(Some(1), Some(24));
        let version = ApiVersion(2, 22);
        let result = info.pick_api_version(ApiVersionRequest::Exact(version))
            .unwrap();
        assert_eq!(result, version);
    }

    #[test]
    fn test_pick_version_exact_mismatch() {
        let info = service_info(Some(1), Some(24));
        let version = ApiVersion(2, 25);
        let res1 = info.pick_api_version(ApiVersionRequest::Exact(version));
        assert!(res1.is_none());
        let version2 = ApiVersion(1, 11);
        let res2 = info.pick_api_version(ApiVersionRequest::Exact(version2));
        assert!(res2.is_none());
    }

    #[test]
    fn test_pick_version_exact_current_only() {
        let info = service_info(None, Some(24));
        let version = ApiVersion(2, 24);
        let result = info.pick_api_version(ApiVersionRequest::Exact(version))
            .unwrap();
        assert_eq!(result, version);
    }

    #[test]
    fn test_pick_version_exact_current_only_mismatch() {
        let info = service_info(None, Some(24));
        let version = ApiVersion(2, 22);
        let result = info.pick_api_version(ApiVersionRequest::Exact(version));
        assert!(result.is_none());
    }

    #[test]
    fn test_pick_version_minimum() {
        let info = service_info(Some(1), Some(24));
        let result = info.pick_api_version(ApiVersionRequest::Minimum)
            .unwrap();
        assert_eq!(result, ApiVersion(2, 1));
    }

    #[test]
    fn test_pick_version_minimum_unknown() {
        let info = service_info(None, Some(24));
        let result = info.pick_api_version(ApiVersionRequest::Minimum);
        assert!(result.is_none());
    }

    #[test]
    fn test_pick_version_latest() {
        let info = service_info(Some(1), Some(24));
        let result = info.pick_api_version(ApiVersionRequest::Latest)
            .unwrap();
        assert_eq!(result, ApiVersion(2, 24));
    }

    #[test]
    fn test_pick_version_latest_unknown() {
        let info = service_info(Some(1), None);
        let result = info.pick_api_version(ApiVersionRequest::Latest);
        assert!(result.is_none());
    }

    #[test]
    fn test_pick_version_choice() {
        let info = service_info(Some(1), Some(24));
        let choice = vec![ApiVersion(2, 0), ApiVersion(2, 2),
                          ApiVersion(2, 22), ApiVersion(2, 25)];
        let result = info.pick_api_version(ApiVersionRequest::Choice(choice))
            .unwrap();
        assert_eq!(result, ApiVersion(2, 22));
    }

    #[test]
    fn test_pick_version_choice_mismatch() {
        let info = service_info(Some(1), Some(24));
        let choice = vec![ApiVersion(2, 0), ApiVersion(2, 25)];
        let result = info.pick_api_version(ApiVersionRequest::Choice(choice));
        assert!(result.is_none());
    }

    #[test]
    fn test_pick_version_choice_current_only() {
        let info = service_info(None, Some(24));
        let choice = vec![ApiVersion(2, 0), ApiVersion(2, 2),
                          ApiVersion(2, 24), ApiVersion(2, 25)];
        let result = info.pick_api_version(ApiVersionRequest::Choice(choice))
            .unwrap();
        assert_eq!(result, ApiVersion(2, 24));
    }

    #[test]
    fn test_pick_version_choice_current_only_mismatch() {
        let info = service_info(None, Some(24));
        let choice = vec![ApiVersion(2, 0), ApiVersion(2, 2),
                          ApiVersion(2, 22), ApiVersion(2, 25)];
        let result = info.pick_api_version(ApiVersionRequest::Choice(choice));
        assert!(result.is_none());
    }
}
