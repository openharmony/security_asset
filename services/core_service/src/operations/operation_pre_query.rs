/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! This crate implements the asset

use std::collections::HashSet;

use crate::{
    calling_info::CallingInfo,
    operations::operation_common::{
        construct_params_with_default, init_decrypt, construst_extra_params,
        db_adapter::construct_db_data,
    },
    operations::operation_query::batch_query,
};

use asset_common::{definition::{AssetMap, Result, Value, ErrCode, Tag}, loge, logi};
use asset_ipc_interface::IpcCode;

pub(crate) fn pre_query(input: &AssetMap, calling_info: &CallingInfo) -> Result<Vec<u8>> {
    let input_new = construct_params_with_default(input, &IpcCode::PreQuery)?;
    let inner_params = construst_extra_params(calling_info, &IpcCode::PreQuery)?;
    let data_vec = construct_db_data(&input_new, &inner_params)?;

    let all_data: Vec<AssetMap> = batch_query(calling_info, &data_vec)?;
    // get all secret key
    let mut secret_key_set = HashSet::new();
    for map in all_data.iter() {
        let auth_type = match map.get(&Tag::AuthType) {
            Some(Value::Number(res)) => res,
            _ => {
                loge!("get auth type failed!");
                return Err(ErrCode::SqliteError);
            },
        };
        let access_type = match map.get(&Tag::Accessibility) {
            Some(Value::Number(res)) => res,
            _ => {
                loge!("get access type failed!");
                return Err(ErrCode::SqliteError);
            },
        };
        secret_key_set.insert((*auth_type, *access_type));
    }
    // use secret key to get challenge
    let mut challenge_vec = Vec::new();
    // todo 遍历每一个密钥，获取challenge
    let challenge_seperator = b'_';
    for (idx, (auth_type, access_type)) in secret_key_set.iter().enumerate() {
        let tmp_challenge = init_decrypt(calling_info, input, auth_type, access_type)?;
        challenge_vec.extend(tmp_challenge);
        if idx < secret_key_set.len() - 1 {
            challenge_vec.push(challenge_seperator);
        }
        // todo 根据challenge等信息创建session
    }
    if challenge_vec.is_empty() {
        Err(ErrCode::NotFound)
    } else {
        logi!("get challenge successful!");
        Ok(challenge_vec)
    }
}