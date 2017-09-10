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

//! Foundation bits exposing the Compute API.

use std::io::Read;
use std::str::FromStr;

use futures::{future, Future};
use hyper::{Get, NotFound, Uri};
use hyper::client::Response;
use hyper::header::Headers;
use serde_json;

use super::super::super::{ApiError, ApiResult, ApiVersion};
use super::super::super::ApiError::{HttpError, EndpointNotFound};
use super::super::super::auth::AuthMethod;
use super::super::super::service::{ApiVersioning, Service};
use super::super::super::http;
use super::protocol::{VersionRoot, VersionsRoot};


#[derive(Clone, Debug)]
pub struct ComputeV2 {
    auth: Box<AuthMethod>,
    root: Uri,
    min_version: ApiVersion,
    max_version: ApiVersion,
    current_version: Option<ApiVersion>
}


header! {
    (XOpenStackNovaApiVersion, "X-OpenStack-Nova-Api-Version") => [ApiVersion]
}

const SERVICE_TYPE: &'static str = "compute";
const VERSION_ID: &'static str = "v2.1";

impl ComputeV2 {
    /// Create a new Compute service client.
    pub fn new<A: AuthMethod>(auth: A) -> ApiResult<ComputeV2> {
        let maybe_ep = auth.get_endpoint(SERVICE_TYPE, None);
        maybe_ep.and_then(|ep| {
             let secure = ep.scheme() == Some("https");
             let res1 = auth.request(http::Request::new(Get, ep.clone()));
             res1.or_else(|err| {
                 match err {
                    Err(HttpError(NotFound, ..)) => {
                        // ...
                    },
                    err => future::err(err)
                 }
             }).map(|res| {
                let (min, max) = extract_info(res, secure)?;
                ComputeV2 {
                    auth: Box::new(auth),
                    root: ep,
                    min_version: min,
                    max_version: max
                }
             })
        })
    }
}

fn extract_info(mut resp: Response, secure: bool)
        -> Result<(ApiVersion, ApiVersion), ApiError> {
    let mut body = String::new();
    let _ = resp.read_to_string(&mut body)?;

    // First, assume it's a versioned URL.
    let mut info = match serde_json::from_str::<VersionRoot>(&body) {
        Ok(ver) => Ok((ver.min_version, ver.version)),
        Err(..) => {
            // Second, assume it's a root URL.
            let vers: VersionsRoot = serde_json::from_str(&body)?;
            match vers.versions.into_iter().find(|x| &x.id == VERSION_ID) {
                Some(ver) => Ok((ver.min_version, ver.version)),
                None => Err(EndpointNotFound(String::from(SERVICE_TYPE)))
            }
        }
    }?;

    // Nova returns insecure URLs even for secure protocol. WHY??
    if secure {
        let _ = info.root_url.set_scheme("https").unwrap();
    }

    Ok(info)
}

impl Service for ComputeV2 {
    fn get_endpoint(&self, parts: &Uri) -> Uri {
        let s = format!("{}/{}", self.root, parts);
        FromStr::from_str(&s).unwrap()
    }

    fn request(&self, request: http::Request) -> http::ApiResponse {
        if ! request.uri().is_absolute() {
            let new_uri = self.get_endpoint(&request.uri());
            request.set_uri(new_uri);
        }

        self.auth.request(request)
    }
}

impl ApiVersioning for ComputeV2 {
    fn supported_api_version_range(&self) -> (ApiVersion, ApiVersion) {
        (self.min_version, self.max_version)
    }

    fn set_api_version(&mut self, version: ApiVersion) -> Option<ApiVersion> {
        if version >= self.min_version && version <= self.max_version {
            self.current_version = Some(version);
            Some(version)
        } else {
            None
        }
    }
}


#[cfg(test)]
pub mod test {
    #![allow(missing_debug_implementations)]

    use hyper;
    use hyper::Url;

    use super::super::super::super::{ApiVersion, Session};
    use super::super::super::super::auth::NoAuth;
    use super::super::super::super::service::ServiceType;
    use super::super::super::super::session::test;
    use super::V2;

    // Copied from compute API reference.
    pub const ONE_VERSION_RESPONSE: &'static str = r#"
    {
        "version": {
            "id": "v2.1",
            "links": [
                {
                    "href": "http://openstack.example.com/v2.1/",
                    "rel": "self"
                },
                {
                    "href": "http://docs.openstack.org/",
                    "rel": "describedby",
                    "type": "text/html"
                }
            ],
            "media-types": [
                {
                    "base": "application/json",
                    "type": "application/vnd.openstack.compute+json;version=2.1"
                }
            ],
            "status": "CURRENT",
            "version": "2.42",
            "min_version": "2.1",
            "updated": "2013-07-23T11:33:21Z"
        }
    }"#;

    pub const SEVERAL_VERSIONS_RESPONSE: &'static str = r#"
    {
        "versions": [
            {
                "id": "v2.0",
                "links": [
                    {
                        "href": "http://openstack.example.com/v2/",
                        "rel": "self"
                    }
                ],
                "status": "SUPPORTED",
                "version": "",
                "min_version": "",
                "updated": "2011-01-21T11:33:21Z"
            },
            {
                "id": "v2.1",
                "links": [
                    {
                        "href": "http://openstack.example.com/v2.1/",
                        "rel": "self"
                    }
                ],
                "status": "CURRENT",
                "version": "2.42",
                "min_version": "2.1",
                "updated": "2013-07-23T11:33:21Z"
            }
        ]
    }"#;

    mock_connector_in_order!(MockOneVersion {
        String::from("HTTP/1.1 200 OK\r\nServer: Mock.Mock\r\n\
                     \r\n") + ONE_VERSION_RESPONSE
    });

    mock_connector_in_order!(MockSeveralVersions {
        String::from("HTTP/1.1 200 OK\r\nServer: Mock.Mock\r\n\
                     \r\n") + SEVERAL_VERSIONS_RESPONSE
    });

    mock_connector_in_order!(MockOneVersionWithTenant {
        String::from("HTTP/1.1 404 NOT FOUND\r\nServer: Mock.Mock\r\n\r\n{}")
        String::from("HTTP/1.1 200 OK\r\nServer: Mock.Mock\r\n\
                     \r\n") + ONE_VERSION_RESPONSE
    });

    mock_connector_in_order!(MockSeveralVersionsWithTenant {
        String::from("HTTP/1.1 404 NOT FOUND\r\nServer: Mock.Mock\r\n\r\n{}")
        String::from("HTTP/1.1 200 OK\r\nServer: Mock.Mock\r\n\
                     \r\n") + SEVERAL_VERSIONS_RESPONSE
    });

    mock_connector_in_order!(MockNotFound {
        String::from("HTTP/1.1 404 NOT FOUND\r\nServer: Mock.Mock\r\n\r\n{}")
        String::from("HTTP/1.1 404 NOT FOUND\r\nServer: Mock.Mock\r\n\r\n{}")
    });

    fn prepare_session(cli: hyper::Client) -> Session {
        let auth = NoAuth::new("http://127.0.2.1/v2.1").unwrap();
        test::new_with_params(auth, cli, None)
    }

    fn check_success(cli: hyper::Client, endpoint: &str) {
        let session = prepare_session(cli);
        let url = Url::parse(endpoint).unwrap();
        let info = V2::service_info(url, &session).unwrap();
        assert_eq!(info.root_url.as_str(),
                   "http://openstack.example.com/v2.1/");
        assert_eq!(info.current_version.unwrap(), ApiVersion(2, 42));
        assert_eq!(info.minimum_version.unwrap(), ApiVersion(2, 1));
    }

    #[test]
    fn test_one_version() {
        let cli = hyper::Client::with_connector(MockOneVersion::default());
        check_success(cli, "http://127.0.2.1/compute/v2.1");
    }

    #[test]
    fn test_one_version_with_tenant() {
        let cli = hyper::Client::with_connector(
            MockOneVersionWithTenant::default());
        check_success(cli, "http://127.0.2.1/compute/v2.1/tenant");
    }

    #[test]
    fn test_several_version() {
        let cli = hyper::Client::with_connector(
            MockSeveralVersions::default());
        check_success(cli, "http://127.0.2.1/");
    }

    #[test]
    fn test_several_version_with_tenant() {
        let cli = hyper::Client::with_connector(
            MockSeveralVersionsWithTenant::default());
        check_success(cli, "http://127.0.2.1/tenant");
    }
}
