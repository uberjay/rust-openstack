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

//! Various utilities.

use std::cell::{Ref, RefCell};
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::str::FromStr;

use serde::{Deserialize, Deserializer};
use serde::de::Error as DeserError;

use super::ApiResult;


/// Deserialize value where empty string equals None.
#[allow(dead_code)]
pub fn empty_as_none<'de, D, T>(des: D) -> Result<Option<T>, D::Error>
        where D: Deserializer<'de>, T: FromStr, T::Err: Display {
    let s = String::deserialize(des)?;
    if s.is_empty() {
        Ok(None)
    } else {
        T::from_str(&s).map(Some).map_err(DeserError::custom)
    }
}
