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
use hyper::header::{ContentType, Header};
use mime;
use serde::{Deserialize, Serialize};
use serde_json;

use super::{ApiError, ApiResult, ApiVersion, ApiVersionRequest};
use super::http;
use super::utils;


/// Trait of a service.
pub trait Service {
    /// Build a full endpoint for this service, given a partial URI.
    fn get_endpoint(&self, parts: &Uri) -> Uri;

    /// Run an authenticated request against this service.
    ///
    /// The request's URI may be relative to the service root endpoint.
    fn request(&self, request: http::Request) -> http::ApiResponse;

    /// Issue a request returning a JSON.
    fn fetch_json<T>(&self, request: http::Request) -> ApiResult<T>
            where for<'de> T: Deserialize<'de> + 'static {
        ApiResult::new(self.request(request))
    }

    /// Issue a request with JSON and receive a JSON back.
    fn json<Req, Res>(&self, request: http::Request, body: &Req)
            -> ApiResult<Res>
            where Req: Serialize, for<'de> Res: Deserialize<'de> + 'static {
        let str_body = match serde_json::to_string(body).map_err(From::from) {
            Ok(body) => body,
            Err(e) => return ApiResult::err(e)
        };
        request.set_body(str_body);
        request.headers_mut().set(ContentType(mime::APPLICATION_JSON));
        self.fetch_json(request)
    }
}

/// Trait representing a service with API version support.
pub trait ApiVersioning {
    /// Get supported versions range.
    fn supported_api_version_range(&self) -> (ApiVersion, ApiVersion);

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
        let (min, max) = self.supported_api_version_range();
        let version = match requested {
            ApiVersionRequest::Minimum =>
                min,
            ApiVersionRequest::Latest =>
                max,
            ApiVersionRequest::Exact(req) =>
                if req >= min && req <= max {
                    req
                } else {
                    return None;
                },
            ApiVersionRequest::Choice(vec) =>
                match vec.into_iter().filter(|x| {
                    *x >= min && *x <= max
                }).max() {
                    Some(x) => x,
                    None => return None
                }
        };

        self.set_api_version(version)
    }
}

/// Type of query parameters.
#[derive(Clone, Debug)]
pub struct Query(pub Vec<(String, String)>);


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
