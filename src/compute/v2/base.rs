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

use std::str::FromStr;

use hyper::Uri;
use serde_json;

use super::super::super::{ApiError, ApiVersion};
use super::super::super::ApiError::EndpointNotFound;
use super::super::super::auth::AuthMethod;
use super::super::super::service::Service;
use super::super::super::http;
use super::protocol::{VersionRoot, VersionsRoot};


#[derive(Clone, Debug)]
pub struct ComputeService {
    pub auth: Box<AuthMethod>,
    pub root: Uri,
    pub min_version: ApiVersion,
    pub max_version: ApiVersion,
    pub current_version: Option<ApiVersion>
}


header! {
    (XOpenStackNovaApiVersion, "X-OpenStack-Nova-Api-Version") => [ApiVersion]
}

pub const SERVICE_TYPE: &'static str = "compute";
const VERSION_ID: &'static str = "v2.1";

impl ComputeService {
    pub fn new<A>(auth: A, root: Uri, min_version: ApiVersion,
                  max_version: ApiVersion) -> ComputeService
            where A: AuthMethod + 'static {
        ComputeService {
            auth: Box::new(auth),
            root: root,
            min_version: min_version,
            max_version: max_version,
            current_version: None
        }
    }
}

pub fn extract_info(resp: &[u8]) -> Result<(ApiVersion, ApiVersion), ApiError> {
    // First, assume it's a versioned URL.
    match serde_json::from_slice::<VersionRoot>(resp) {
        Ok(ver) => Ok((ver.version.min_version, ver.version.version)),
        Err(..) => {
            // Second, assume it's a root URL.
            let vers: VersionsRoot = serde_json::from_slice(resp)?;
            match vers.versions.into_iter().find(|x| &x.id == VERSION_ID) {
                Some(ver) => Ok((ver.min_version, ver.version)),
                None => Err(EndpointNotFound(String::from(SERVICE_TYPE)))
            }
        }
    }
}

impl Service for ComputeService {
    fn get_endpoint(&self, parts: &Uri) -> Uri {
        let s = format!("{}/{}", self.root, parts);
        FromStr::from_str(&s).unwrap()
    }

    fn request(&self, mut request: http::Request) -> http::ApiResponse {
        if ! request.uri().is_absolute() {
            let new_uri = self.get_endpoint(&request.uri());
            request.set_uri(new_uri);
        }

        self.auth.request(request)
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
