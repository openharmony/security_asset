/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#![allow(dead_code)]

use asset_sdk::{AssetMap, ErrCode, Result, ReturnType, Tag, Value};

#[macro_export]
macro_rules! function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        type_name_of(f).rsplit("::").find(|&part| part != "f" && part != "{{closure}}").expect("Short function name")
    }};
}

pub(crate) const MIN_NUMBER_VALUE: u32 = 0;
pub(crate) const MAX_RETURN_LIMIT: u32 = 0x10000; // 65536
pub(crate) const MAX_AUTH_VALID_PERIOD: u32 = 600; // 10min

pub(crate) const MIN_ARRAY_SIZE: usize = 0;
pub(crate) const MAX_ARRAY_SIZE: usize = 1024;

pub(crate) const MAX_ALIAS_SIZE: usize = 256;
pub(crate) const MAX_LABEL_SIZE: usize = 512;

pub(crate) const AUTH_TOKEN_SIZE: usize = 148;
pub(crate) const CHALLENGE_SIZE: usize = 32;
pub(crate) const SYNC_TYPE_MIN_BITS: u32 = 0;
pub(crate) const SYNC_TYPE_MAX_BITS: u32 = 3;
pub(crate) const DELETE_TYPE_MIN_BITS: u32 = 1;
pub(crate) const DELETE_TYPE_MAX_BITS: u32 = 2;

pub(crate) const ACCESSIBILITY_MIN_BITS: u32 = 1;
pub(crate) const ACCESSIBILITY_MAX_BITS: u32 = 2;
pub(crate) const AUTH_TYPE_MIN_VALUE: u32 = 1;
pub(crate) const AUTH_TYPE_MAX_VALUE: u32 = 255;


pub(crate) fn get_bytes(attrs: &AssetMap, tag: Tag) -> Result<&Vec<u8>> {
    if let Some(Value::Bytes(bytes)) = attrs.get(&tag) {
        Ok(bytes)
    } else {
        Err(ErrCode::InvalidArgument)
    }
}

pub(crate) fn get_number(attrs: &AssetMap, tag: Tag) -> Result<u32> {
    if let Some(Value::Number(num)) = attrs.get(&tag) {
        Ok(*num)
    } else {
        Err(ErrCode::InvalidArgument)
    }
}

pub(crate) fn get_enum_variant<T: TryFrom<u32, Error = ErrCode>>(attrs: &AssetMap, tag: Tag) -> Result<T> {
    if let Some(Value::Number(num)) = attrs.get(&tag) {
        T::try_from(*num)
    } else {
        Err(ErrCode::InvalidArgument)
    }
}

pub(crate) fn get_bool(attrs: &AssetMap, tag: Tag) -> Result<bool> {
    if let Some(Value::Bool(b)) = attrs.get(&tag) {
        Ok(*b)
    } else {
        Err(ErrCode::InvalidArgument)
    }
}

pub(crate) fn remove_by_alias(alias: &[u8]) -> Result<()> {
    asset_sdk::Manager::build()?.remove(&AssetMap::from([(Tag::Alias, Value::Bytes(alias.to_vec()))]))
}

pub(crate) fn remove_all() -> Result<()> {
    asset_sdk::Manager::build()?.remove(&AssetMap::new())
}

pub(crate) fn query_all_by_alias(alias: &[u8]) -> Result<Vec<AssetMap>> {
    asset_sdk::Manager::build()?.query(&AssetMap::from([
        (Tag::Alias, Value::Bytes(alias.to_vec())),
        (Tag::ReturnType, Value::Number(ReturnType::All as u32)),
    ]))
}

pub(crate) fn query_attr_by_alias(alias: &[u8]) -> Result<Vec<AssetMap>> {
    asset_sdk::Manager::build()?.query(&AssetMap::from([
        (Tag::Alias, Value::Bytes(alias.to_vec())),
        (Tag::ReturnType, Value::Number(ReturnType::Attributes as u32)),
    ]))
}

pub(crate) fn add_default_asset(alias: &[u8], secret: &[u8]) -> Result<()> {
    asset_sdk::Manager::build()?.add(&AssetMap::from([
        (Tag::Alias, Value::Bytes(alias.to_vec())),
        (Tag::Secret, Value::Bytes(secret.to_vec())),
    ]))
}
