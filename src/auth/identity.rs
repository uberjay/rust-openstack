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

//! OpenStack Identity V3 API support for access tokens.

use std::collections::hash_map::DefaultHasher;
use std::env;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::str::FromStr;

use futures::Future;
use hyper::{Body, Get, Method, Request, Response, Post, StatusCode, Uri};
use hyper::Error as HttpClientError;
use hyper::header::{ContentType, Headers};
use mime;
use tokio_core::reactor::Handle;

use super::super::{ApiError, ApiResult};
use super::super::identity::protocol;
use super::super::http;
use super::AuthMethod;

use ApiError::InvalidInput;


const MISSING_USER: &'static str = "User information required";
const MISSING_SCOPE: &'static str = "Unscoped tokens are not supported now";
const MISSING_ENV_VARS: &'static str =
    "Not all required environment variables were provided";


/// Plain authentication token without additional details.
#[derive(Clone)]
struct Token(pub String);

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        write!(f, "Token {{ hash: {} }}", hasher.finish())
    }
}

impl Hash for Token {
    fn hash<H>(&self, state: &mut H) where H: Hasher {
        self.0.hash(state);
    }
}


/// Authentication method factory using Identity API V3.
#[derive(Clone, Debug)]
pub struct Identity {
    client: http::Client,
    auth_uri: Uri,
    region: Option<String>,
    password_identity: Option<protocol::PasswordIdentity>,
    project_scope: Option<protocol::ProjectScope>
}

/// Password authentication using Identity API V3.
///
/// Has to be created via [Identity object](struct.Identity.html) methods.
#[derive(Clone, Debug)]
pub struct PasswordAuth {
    client: http::Client,
    auth_uri: Uri,
    region: Option<String>,
    body: String,
    token_endpoint: Uri,
    user: String
}

impl Identity {
    /// Get a reference to the auth URL.
    pub fn get_auth_uri(&self) -> &Uri {
        &self.auth_uri
    }

    /// Create a password authentication against the given Identity service.
    pub fn new(io_handle: &Handle, auth_uri: Uri) -> Identity {
        Identity {
            client: http::Client::new(io_handle),
            auth_uri: auth_uri,
            region: None,
            password_identity: None,
            project_scope: None,
        }
    }

    /// Create a password authentication against the given Identity service.
    pub fn new_with_region(io_handle: &Handle, auth_uri: Uri,
                           region: String) -> Identity {
        Identity {
            client: http::Client::new(io_handle),
            auth_uri: auth_uri,
            region: Some(region),
            password_identity: None,
            project_scope: None,
        }
    }

    /// Add authentication based on user name and password.
    pub fn with_user<S1, S2, S3>(self, user_name: S1, password: S2,
                                 domain_name: S3) -> Identity
            where S1: Into<String>, S2: Into<String>, S3: Into<String> {
        Identity {
            password_identity: Some(protocol::PasswordIdentity::new(user_name,
                                                                    password,
                                                                    domain_name)),
            .. self
        }
    }

    /// Request a token scoped to the given project.
    pub fn with_project_scope<S1, S2>(self, project_name: S1, domain_name: S2)
            -> Identity where S1: Into<String>, S2: Into<String> {
        Identity {
            project_scope: Some(protocol::ProjectScope::new(project_name,
                                                            domain_name)),
            .. self
        }
    }

    /// Create an authentication method based on provided information.
    pub fn create(self) -> Result<PasswordAuth, ApiError> {
        /// TODO: support more authentication methods (at least a token)
        let password_identity = match self.password_identity {
            Some(p) => p,
            None =>
                return Err(
                    InvalidInput(String::from(MISSING_USER))
                )
        };

        /// TODO: support unscoped tokens
        let project_scope = match self.project_scope {
            Some(p) => p,
            None =>
                return Err(
                    InvalidInput(String::from(MISSING_SCOPE))
                )
        };

        Ok(PasswordAuth::new(self.client, self.auth_uri, self.region,
                             password_identity, project_scope))
    }

    /// Create an authentication method from environment variables.
    pub fn from_env(io_handle: &Handle) -> Result<PasswordAuth, ApiError> {
        let client = http::Client::new(io_handle);
        let auth_uri = _get_env("OS_AUTH_URL")?;
        let id = match FromStr::from_str(&auth_uri) {
            Ok(uri) => Identity::new(io_handle, uri),
            Err(e) =>
                return Err(ApiError::ProtocolError(HttpClientError::Uri(e)))
        };

        let user_name = _get_env("OS_USERNAME")?;
        let password = _get_env("OS_PASSWORD")?;
        let project_name = _get_env("OS_PROJECT_NAME")?;

        let user_domain = env::var("OS_USER_DOMAIN_NAME")
            .unwrap_or(String::from("Default"));
        let project_domain = env::var("OS_PROJECT_DOMAIN_NAME")
            .unwrap_or(String::from("Default"));

        id.with_user(user_name, password, user_domain)
            .with_project_scope(project_name, project_domain)
            .create()
    }
}

#[inline]
fn _get_env(name: &str) -> Result<String, ApiError> {
    env::var(name).or(Err(InvalidInput(String::from(MISSING_ENV_VARS))))
}

impl PasswordAuth {
    /// Get a reference to the auth URL.
    pub fn get_auth_uri(&self) -> &Uri {
        &self.auth_uri
    }

    fn new(client: http::Client, auth_uri: Uri, region: Option<String>,
           password_identity: protocol::PasswordIdentity,
           project_scope: protocol::ProjectScope) -> PasswordAuth {
        let user = password_identity.password.user.name.clone();
        let body = protocol::ProjectScopedAuthRoot::new(password_identity,
                                                        project_scope);
        // TODO: allow /v3 postfix built into auth_uri?
        let token_endpoint = FromStr::from_str(
            &format!("{}/v3/auth/tokens", auth_uri)).unwrap();
        PasswordAuth {
            client: client,
            auth_uri: auth_uri,
            region: region,
            body: body.to_string().unwrap(),
            token_endpoint: token_endpoint,
            user: user
        }
    }

    fn get_token(&self) -> ApiResult<String> {
        let mut req = http::Request::new(Post, self.token_endpoint.clone());
        req.headers_mut().set(ContentType(mime::APPLICATION_JSON));
        req.set_body(self.body.clone());
        ApiResult::from_future(
            self.client.request(req).and_then(|resp| {
                token_from_response(resp)
            })
        )
    }

    fn get_catalog(&self) -> ApiResult<protocol::CatalogRoot> {
        // TODO: catalog caching
        let catalog_uri_s = format!("{}/v3/auth/catalog", self.auth_uri);
        let catalog_uri = FromStr::from_str(&catalog_uri_s).unwrap();
        trace!("Requesting a service catalog from {}", catalog_uri);
        let req = Request::new(Get, catalog_uri);
        ApiResult::new(self.request(req))
    }
}

fn token_from_response(mut resp: Response) -> Result<String, ApiError> {
    let token_value = match resp.status() {
        StatusCode::Ok | StatusCode::Created => {
            let header: Option<&protocol::SubjectTokenHeader> =
                resp.headers().get();
            match header {
                Some(ref value) => value.0.clone(),
                None => {
                    error!("No X-Subject-Token header received");
                    return Err(
                        ApiError::ProtocolError(HttpClientError::Header))
                }
            }
        },
        StatusCode::Unauthorized => {
            return Err(ApiError::HttpError(resp.status(), resp));
        },
        other => {
            return Err(ApiError::HttpError(resp.status(), resp));
        }
    };

    // TODO: detect expiration time
    // TODO: do something useful about the body
    Ok(token_value)
}


/// Find an endpoint in the service catalog.
pub fn find_endpoint(catalog: Vec<protocol::CatalogRecord>,
                     service_type: String,
                     endpoint_interface: String,
                     region: Option<String>)
        -> Result<protocol::Endpoint, ApiError> {
    let svc = match catalog.into_iter().find(
            |x| x.service_type == service_type) {
        Some(s) => s,
        None => return Err(ApiError::EndpointNotFound(service_type.clone()))
    };

    let maybe_endp: Option<protocol::Endpoint>;
    if let Some(rgn) = region {
        maybe_endp = svc.endpoints.into_iter().find(
            |x| x.interface == endpoint_interface && x.region == rgn);
    } else {
        maybe_endp = svc.endpoints.into_iter().find(
            |x| x.interface == endpoint_interface);
    }

    maybe_endp.ok_or(ApiError::EndpointNotFound(service_type.clone()))
}

impl AuthMethod for PasswordAuth {
    /// Create an authenticated request.
    fn request(&self, mut request: Request<Body>) -> http::ApiResponse {
        let maybe_token = self.get_token();
        // FIXME: is it possible to do it without cloning?
        let client = self.client.clone();
        ApiResult::with_response(maybe_token.and_then(move |token| {
            request.headers_mut().set(protocol::AuthTokenHeader(token));
            client.request(request)
        }))
    }

    /// Get a URL for the requested service.
    fn get_endpoint(&self, service_type: String,
                    endpoint_interface: Option<String>) -> ApiResult<Uri> {
        let real_interface = endpoint_interface.unwrap_or(
            String::from("public"));
        let region = self.region.clone();
        debug!("Requesting a catalog endpoint for service '{}', interface \
               '{}' from region {:?}",
               service_type, real_interface, self.region);
        ApiResult::from_future(self.get_catalog().and_then(|cat| {
            let endp = find_endpoint(cat.catalog,
                                     service_type, real_interface, region)?;
            info!("Received {:?}", endp);
            FromStr::from_str(&endp.url).map_err(From::from)
        }))
    }
}

#[cfg(test)]
pub mod test {
    #![allow(missing_debug_implementations)]
    #![allow(unused_results)]

    use hyper::{self, Url};
    use hyper::status::StatusCode;

    use super::super::super::{ApiError, ApiResult};
    use super::super::AuthMethod;
    use super::Identity;

    mock_connector!(MockToken {
        "http://127.0.1.1" => "HTTP/1.1 200 OK\r\n\
                               Server: Mock.Mock\r\n\
                               X-Subject-Token: abcdef\r\n
                               \r\n\
                               "
        "http://127.0.1.2" => "HTTP/1.1 401 Unauthorized\r\n\
                               Server: Mock.Mock\r\n\
                               \r\n\
                               boom"
        "http://127.0.1.3" => "HTTP/1.1 404 Not Found\r\n\
                               Server: Mock.Mock\r\n\
                               \r\n\
                               nothing found"
    });

    // Copied from keystone API reference.
    const EXAMPLE_CATALOG_RESPONSE: &'static str = r#"
    {
        "catalog": [
            {
                "endpoints": [
                    {
                        "id": "39dc322ce86c4111b4f06c2eeae0841b",
                        "interface": "public",
                        "region": "RegionOne",
                        "url": "http://localhost:5000"
                    },
                    {
                        "id": "ec642f27474842e78bf059f6c48f4e99",
                        "interface": "internal",
                        "region": "RegionOne",
                        "url": "http://localhost:5000"
                    },
                    {
                        "id": "c609fc430175452290b62a4242e8a7e8",
                        "interface": "admin",
                        "region": "RegionOne",
                        "url": "http://localhost:35357"
                    }
                ],
                "id": "4363ae44bdf34a3981fde3b823cb9aa2",
                "type": "identity",
                "name": "keystone"
            }
        ],
        "links": {
            "self": "https://example.com/identity/v3/catalog",
            "previous": null,
            "next": null
        }
    }"#;

    mock_connector!(MockCatalog {
        "http://127.0.2.1" => String::from("HTTP/1.1 200 OK\r\n\
                                            Server: Mock.Mock\r\n\
                                            X-Subject-Token: abcdef\r\n
                                            \r\n") + EXAMPLE_CATALOG_RESPONSE
    });

    #[test]
    fn test_identity_new() {
        let id = Identity::new("http://127.0.0.1:8080/").unwrap();
        let e = id.auth_uri;
        assert_eq!(e.scheme(), "http");
        assert_eq!(e.host_str().unwrap(), "127.0.0.1");
        assert_eq!(e.port().unwrap(), 8080u16);
        assert_eq!(e.path(), "/");
    }

    #[test]
    fn test_identity_new_invalid() {
        Identity::new("http://127.0.0.1 8080/").err().unwrap();
    }

    #[test]
    fn test_identity_create() {
        let id = Identity::new("http://127.0.0.1:8080/identity").unwrap()
            .with_user("user", "pa$$w0rd", "example.com")
            .with_project_scope("cool project", "example.com")
            .create().unwrap();
        assert_eq!(&id.auth_uri.to_string(), "http://127.0.0.1:8080/identity");
        assert_eq!(id.get_auth_uri().to_string(),
                   "http://127.0.0.1:8080/identity");
        assert_eq!(&id.body.auth.identity.password.user.name, "user");
        assert_eq!(&id.body.auth.identity.password.user.password, "pa$$w0rd");
        assert_eq!(&id.body.auth.identity.password.user.domain.name,
                   "example.com");
        assert_eq!(id.body.auth.identity.methods,
                   vec![String::from("password")]);
        assert_eq!(&id.body.auth.scope.project.name, "cool project");
        assert_eq!(&id.body.auth.scope.project.domain.name, "example.com");
        assert_eq!(&id.token_endpoint,
                   "http://127.0.0.1:8080/identity/v3/auth/tokens");
    }

    #[test]
    fn test_identity_create_no_scope() {
        Identity::new("http://127.0.0.1:8080/identity").unwrap()
            .with_user("user", "pa$$w0rd", "example.com")
            .create().err().unwrap();
    }

    #[test]
    fn test_identity_create_no_user() {
        Identity::new("http://127.0.0.1:8080/identity").unwrap()
            .with_project_scope("cool project", "example.com")
            .create().err().unwrap();
    }

    #[test]
    fn test_identity_get_token() {
        let id = Identity::new("http://127.0.1.1").unwrap()
            .with_user("user", "pa$$w0rd", "example.com")
            .with_project_scope("cool project", "example.com")
            .create().unwrap();
        let cli = hyper::Client::with_connector(MockToken::default());
        let token = id.get_token(&cli).unwrap();
        assert_eq!(&token, "abcdef");
    }

    #[test]
    fn test_identity_get_token_unauthorized() {
        let id = Identity::new("http://127.0.1.2").unwrap()
            .with_user("user", "pa$$w0rd", "example.com")
            .with_project_scope("cool project", "example.com")
            .create().unwrap();
        let cli = hyper::Client::with_connector(MockToken::default());
        match id.get_token(&cli).err().unwrap() {
            ApiError::HttpError(StatusCode::Unauthorized, ..) => (),
            other => panic!("Unexpected {}", other)
        };
    }

    #[test]
    fn test_identity_get_token_fail() {
        let id = Identity::new("http://127.0.1.3").unwrap()
            .with_user("user", "pa$$w0rd", "example.com")
            .with_project_scope("cool project", "example.com")
            .create().unwrap();
        let cli = hyper::Client::with_connector(MockToken::default());
        match id.get_token(&cli).err().unwrap() {
            ApiError::HttpError(hyper::NotFound, ..) => (),
            other => panic!("Unexpected {}", other)
        };
    }

    fn get_endpoint(service_type: &str, interface_endpoint: Option<&str>,
                    region: Option<&str>) -> ApiResult<Url> {
        let id = Identity::new("http://127.0.2.1").unwrap()
            .with_user("user", "pa$$w0rd", "example.com")
            .with_project_scope("cool project", "example.com")
            .create().unwrap();
        let cli = hyper::Client::with_connector(MockCatalog::default());
        id.get_endpoint(&cli, String::from(service_type),
                        interface_endpoint.map(String::from),
                        region.map(String::from))
    }

    #[test]
    fn test_identity_get_endpoint() {
        let e1 = get_endpoint("identity", None, None).unwrap();
        assert_eq!(&e1.to_string(), "http://localhost:5000/");
        let e2 = get_endpoint("identity", Some("admin"), None).unwrap();
        assert_eq!(&e2.to_string(), "http://localhost:35357/");

        match get_endpoint("foo", None, None).err().unwrap() {
            ApiError::EndpointNotFound(ref endp) =>
                assert_eq!(endp, "foo"),
            other => panic!("Unexpected {}", other)
        };

        match get_endpoint("identity", Some("unknown"), None).err().unwrap() {
            ApiError::EndpointNotFound(ref endp) =>
                assert_eq!(endp, "identity"),
            other => panic!("Unexpected {}", other)
        };
    }

    #[test]
    fn test_identity_get_endpoint_with_region() {
        let e1 = get_endpoint("identity", Some("admin"),
                              Some("RegionOne")).unwrap();
        assert_eq!(&e1.to_string(), "http://localhost:35357/");

        match get_endpoint("identity", None,
                           Some("unknown")).err().unwrap() {
            ApiError::EndpointNotFound(ref endp) =>
                assert_eq!(endp, "identity"),
            other => panic!("Unexpected {}", other)
        };
    }

    fn demo_service1() -> CatalogRecord {
        CatalogRecord {
            service_type: String::from("identity"),
            endpoints: vec![
                Endpoint {
                    interface: String::from("public"),
                    region: String::from("RegionOne"),
                    url: String::from("https://host.one/identity")
                },
                Endpoint {
                    interface: String::from("internal"),
                    region: String::from("RegionOne"),
                    url: String::from("http://192.168.22.1/identity")
                },
                Endpoint {
                    interface: String::from("public"),
                    region: String::from("RegionTwo"),
                    url: String::from("https://host.two:5000")
                }
            ]
        }
    }

    fn demo_service2() -> CatalogRecord {
        CatalogRecord {
            service_type: String::from("baremetal"),
            endpoints: vec![
                Endpoint {
                    interface: String::from("public"),
                    region: String::from("RegionOne"),
                    url: String::from("https://host.one/baremetal")
                },
                Endpoint {
                    interface: String::from("public"),
                    region: String::from("RegionTwo"),
                    url: String::from("https://host.two:6385")
                }
            ]
        }
    }

    pub fn demo_catalog() -> Vec<CatalogRecord> {
        vec![demo_service1(), demo_service2()]
    }

    fn find_endpoint<'a>(cat: &'a Vec<CatalogRecord>,
                         service_type: &str, interface_type: &str,
                         region: Option<&str>) -> ApiResult<&'a Endpoint> {
        super::find_endpoint(cat, String::from(service_type),
                             String::from(interface_type),
                             region.map(String::from))
    }

    #[test]
    fn test_find_endpoint() {
        let cat = demo_catalog();

        let e1 = find_endpoint(&cat, "identity", "public", None).unwrap();
        assert_eq!(&e1.url, "https://host.one/identity");

        let e2 = find_endpoint(&cat, "identity", "internal", None).unwrap();
        assert_eq!(&e2.url, "http://192.168.22.1/identity");

        let e3 = find_endpoint(&cat, "baremetal", "public", None).unwrap();
        assert_eq!(&e3.url, "https://host.one/baremetal");
    }

    #[test]
    fn test_find_endpoint_with_region() {
        let cat = demo_catalog();

        let e1 = find_endpoint(&cat, "identity", "public",
                               Some("RegionTwo")).unwrap();
        assert_eq!(&e1.url, "https://host.two:5000");

        let e2 = find_endpoint(&cat, "identity", "internal",
                               Some("RegionOne")).unwrap();
        assert_eq!(&e2.url, "http://192.168.22.1/identity");

        let e3 = find_endpoint(&cat, "baremetal", "public",
                               Some("RegionTwo")).unwrap();
        assert_eq!(&e3.url, "https://host.two:6385");
    }

    fn assert_not_found(result: ApiResult<&Endpoint>) {
        match result.err().unwrap() {
            ApiError::EndpointNotFound(..) => (),
            other => panic!("Unexpected error {}", other)
        }
    }

    #[test]
    fn test_find_endpoint_not_found() {
        let cat = demo_catalog();

        assert_not_found(find_endpoint(&cat, "foobar", "public", None));
        assert_not_found(find_endpoint(&cat, "identity", "public",
                                       Some("RegionFoo")));
        assert_not_found(find_endpoint(&cat, "baremetal", "internal", None));
        assert_not_found(find_endpoint(&cat, "identity", "internal",
                                       Some("RegionTwo")));
    }
}
