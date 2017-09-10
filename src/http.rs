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

//! Implementation details related to HTTP.

use std::marker::PhantomData;

use futures::{Async, future, Future, Poll, Stream};
use futures::future::AndThen;
use futures::stream::Concat2;
use hyper::{Body, Chunk, Client as HyperClient, Error as HyperError,
            Request as HyperRequest, Response};
use hyper::client::FutureResponse;
use hyper_rustls::HttpsConnector;
use serde::Deserialize;
use serde_json;
use tokio_core::reactor::Handle;

use super::ApiError;


/// Convenient redefinition of request.
pub type Request = HyperRequest<Body>;

/// Type of HTTP(s) client.
#[derive(Debug, Clone)]
pub struct Client {
    /// Instance of Hyper client used with this client instance.
    pub inner: HyperClient<HttpsConnector>
}

/// Result of an API call.
pub struct ApiResult<T> {
    inner: Box<Future<Item=T, Error=ApiError> + 'static>,
    _marker: PhantomData<T>
}

/// API raw response.
pub type ApiResponse = ApiResult<Response>;

/// Trait representing something that can be converted from a Body.
pub trait ParseBody: Sized {
    /// Parse the value from the Body.
    fn parse_body(body: &[u8]) -> Result<Self, ApiError>;
}


const DEFAULT_DNS_THREADS: usize = 4;

impl Client {
    /// Create an HTTP(s) client.
    pub fn new(io_handle: &Handle) -> Client {
        let connector = HttpsConnector::new(DEFAULT_DNS_THREADS, io_handle);
        Client {
            inner: HyperClient::configure()
                .connector(connector)
                .build(io_handle)
        }
    }

    /// Send a request.
    pub fn request(self, request: Request) -> ApiResponse {
        ApiResult::with_response(self.inner.request(request))
    }
}

impl ApiResult<Response> {
    /// New result directly from a response.
    pub fn with_response<F, E>(f: F) -> ApiResult<Response>
            where F: Future<Item=Response, Error=E> + 'static,
                  ApiError: From<E>, E: 'static {
        ApiResult {
            inner: Box::new(f.map_err(From::from).and_then(|resp| {
                let status = resp.status();
                if status.is_success() {
                    future::ok(resp)
                } else {
                    future::err(ApiError::HttpError(status, resp))
                }
            })),
            _marker: PhantomData
        }
    }
}

impl<T> ApiResult<T> where T: 'static {
    /// New successful result.
    pub fn ok(item: T) -> ApiResult<T> {
        ApiResult {
            inner: Box::new(future::ok(item)),
            _marker: PhantomData
        }
    }

    /// New error result.
    pub fn err(e: ApiError) -> ApiResult<T> {
        ApiResult {
            inner: Box::new(future::err(e)),
            _marker: PhantomData
        }
    }

    /// Build an ApiResult from another future.
    pub fn from_future<F>(f: F) -> ApiResult<T>
            where F: Future<Item=T, Error=ApiError> + 'static {
        ApiResult {
            inner: Box::new(f),
            _marker: PhantomData
        }
    }
}

impl<T> ApiResult<T> where T: ParseBody + 'static {
    /// New result from a response.
    pub fn new(response: ApiResponse) -> ApiResult<T> {
        ApiResult {
            inner: Box::new(response.and_then(|res| {
                res.body().concat2().map_err(From::from).and_then(|chunk| {
                    ParseBody::parse_body(&chunk)
                })
            })),
            _marker: PhantomData
        }
    }
}

impl<T> Future for ApiResult<T> {
    type Item = T;
    type Error = ApiError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.inner.poll()
    }
}

impl<T> ParseBody for T where for<'de> T: Deserialize<'de> {
    fn parse_body(body: &[u8]) -> Result<Self, ApiError> {
        serde_json::from_slice(body).map_err(From::from)
    }
}
