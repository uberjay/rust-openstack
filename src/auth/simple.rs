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

//! Simple authentication methods.

use hyper::{Client, Method, Request, Uri};
use hyper_rustls::HttpsConnector;

use super::super::ApiResult;
use super::AuthMethod;

/// Authentication method that provides no authentication.
///
/// This method always returns a constant fake token, and a pre-defined
/// endpoint.
#[derive(Clone, Debug)]
pub struct NoAuth {
    endpoint: Uri
}

impl NoAuth {
    /// Create a new fake authentication method using a fixed endpoint.
    ///
    /// This endpoint will be returned in response to all get_endpoint calls
    /// of the [AuthMethod](trait.AuthMethod.html) trait.
    pub fn new(endpoint: Uri) -> NoAuth {
        NoAuth { endpoint: endpoint }
    }
}

impl AuthMethod for NoAuth {
    /// Create a request.
    fn request<'a>(&self, _client: &Client<HttpsConnector>,
                   method: Method, uri: Uri) -> ApiResult<Request> {
        Ok(Request::new(method, uri))
    }

    /// Get a predefined endpoint for all service types
    fn get_endpoint(&self, _client: &Client<HttpsConnector>,
                    _service_type: String,
                    _endpoint_interface: Option<String>,
                    _region: Option<String>) -> ApiResult<Uri> {
        Ok(self.endpoint.clone())
    }
}

#[cfg(test)]
pub mod test {
    #![allow(unused_results)]

    use super::super::super::utils;
    use super::super::AuthMethod;
    use super::NoAuth;

    #[test]
    fn test_noauth_new() {
        let a = NoAuth::new("http://127.0.0.1:8080/v1").unwrap();
        let e = a.endpoint;
        assert_eq!(e.scheme(), "http");
        assert_eq!(e.host_str().unwrap(), "127.0.0.1");
        assert_eq!(e.port().unwrap(), 8080u16);
        assert_eq!(e.path(), "/v1");
    }

    #[test]
    fn test_noauth_new_fail() {
        NoAuth::new("foo bar").err().unwrap();
    }

    #[test]
    fn test_noauth_get_endpoint() {
        let a = NoAuth::new("http://127.0.0.1:8080/v1").unwrap();
        let e = a.get_endpoint(&utils::http_client(),
                               String::from("foobar"), None, None).unwrap();
        assert_eq!(e.scheme(), "http");
        assert_eq!(e.host_str().unwrap(), "127.0.0.1");
        assert_eq!(e.port().unwrap(), 8080u16);
        assert_eq!(e.path(), "/v1");
    }
}
