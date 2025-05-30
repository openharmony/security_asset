/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

//! This module is used to update the specified alias of Asset.

use asset_common::CallingInfo;
use asset_crypto_manager::crypto::Crypto;
use asset_db_operator::{
    database::build_db,
    types::{column, DbMap, DB_DATA_VERSION},
};
use asset_definition::{log_throw_error, AssetMap, ErrCode, Extension, LocalStatus, Result, SyncStatus, Tag, Value};
use asset_utils::time;

use crate::operations::common;

fn encrypt(calling_info: &CallingInfo, db_data: &DbMap) -> Result<Vec<u8>> {
    let secret_key = common::build_secret_key(calling_info, db_data)?;
    let secret = db_data.get_bytes_attr(&column::SECRET)?;
    let cipher = Crypto::encrypt(&secret_key, secret, &common::build_aad(db_data)?)?;
    Ok(cipher)
}

fn is_only_change_local_labels(update: &AssetMap) -> bool {
    let valid_tags = common::NORMAL_LOCAL_LABEL_ATTRS.to_vec();
    for tag in update.keys() {
        if !valid_tags.contains(tag) {
            return false;
        }
    }
    true
}

fn add_attrs(update: &AssetMap, db_data: &mut DbMap) -> Result<()> {
    if !is_only_change_local_labels(update) {
        add_system_attrs(db_data)?;
        add_normal_attrs(db_data);
    }
    db_data.insert(column::LOCAL_STATUS, Value::Number(LocalStatus::Local as u32));
    Ok(())
}

fn add_system_attrs(db_data: &mut DbMap) -> Result<()> {
    let time = time::system_time_in_millis()?;
    db_data.insert(column::UPDATE_TIME, Value::Bytes(time));
    Ok(())
}

fn add_normal_attrs(db_data: &mut DbMap) {
    db_data.insert(column::SYNC_STATUS, Value::Number(SyncStatus::SyncUpdate as u32));
}

const QUERY_REQUIRED_ATTRS: [Tag; 1] = [Tag::Alias];
const UPDATE_OPTIONAL_ATTRS: [Tag; 1] = [Tag::Secret];

fn check_arguments(query: &AssetMap, attrs_to_update: &AssetMap, calling_info: &CallingInfo) -> Result<()> {
    // Check attributes used to query.
    common::check_required_tags(query, &QUERY_REQUIRED_ATTRS)?;
    let mut valid_tags = common::CRITICAL_LABEL_ATTRS.to_vec();
    valid_tags.extend_from_slice(&common::NORMAL_LABEL_ATTRS);
    valid_tags.extend_from_slice(&common::NORMAL_LOCAL_LABEL_ATTRS);
    valid_tags.extend_from_slice(&common::ACCESS_CONTROL_ATTRS);
    common::check_tag_validity(query, &valid_tags)?;
    common::check_group_validity(query, calling_info)?;
    common::check_value_validity(query)?;
    common::check_system_permission(query)?;

    if attrs_to_update.is_empty() {
        return log_throw_error!(ErrCode::InvalidArgument, "[FATAL]The attributes to update is empty.");
    }
    // Check attributes to update.
    valid_tags = common::NORMAL_LABEL_ATTRS.to_vec();
    valid_tags.extend_from_slice(&common::NORMAL_LOCAL_LABEL_ATTRS);
    valid_tags.extend_from_slice(&common::ASSET_SYNC_ATTRS);
    valid_tags.extend_from_slice(&UPDATE_OPTIONAL_ATTRS);
    common::check_tag_validity(attrs_to_update, &valid_tags)?;
    common::check_value_validity(attrs_to_update)
}

fn upgrade_to_latest_version(origin_db_data: &mut DbMap, update_db_data: &mut DbMap) {
    origin_db_data.insert_attr(column::VERSION, DB_DATA_VERSION);
    update_db_data.insert_attr(column::VERSION, DB_DATA_VERSION);
}

pub(crate) fn update(calling_info: &CallingInfo, query: &AssetMap, update: &AssetMap) -> Result<()> {
    check_arguments(query, update, calling_info)?;

    let mut query_db_data = common::into_db_map(query);
    if query.get(&Tag::GroupId).is_some() {
        common::add_group(calling_info, &mut query_db_data);
    } else {
        common::add_owner_info(calling_info, &mut query_db_data);
    }
    let mut update_db_data = common::into_db_map(update);

    add_attrs(update, &mut update_db_data)?;

    let mut db = build_db(query, calling_info)?;
    let results = db.query_datas(&vec![], &query_db_data, None, true)?;
    if results.is_empty() {
        return log_throw_error!(ErrCode::NotFound, "[FATAL]The asset to update is not found.");
    }

    if update.contains_key(&Tag::Secret) {
        let mut results = db.query_datas(&vec![], &query_db_data, None, true)?;
        if results.len() != 1 {
            return log_throw_error!(
                ErrCode::NotFound,
                "query to-be-updated asset failed, found [{}] assets",
                results.len()
            );
        }

        let result = results.get_mut(0).unwrap();
        result.insert(column::SECRET, update[&Tag::Secret].clone());

        if common::need_upgrade(result)? {
            upgrade_to_latest_version(result, &mut update_db_data);
        }
        let cipher = encrypt(calling_info, result)?;
        update_db_data.insert(column::SECRET, Value::Bytes(cipher));
    }

    // call sql to update
    let update_num = db.update_datas(&query_db_data, true, &update_db_data)?;
    if update_num == 0 {
        return log_throw_error!(ErrCode::NotFound, "[FATAL]Update asset failed, update 0 asset.");
    }

    common::inform_asset_ext(calling_info, update);

    Ok(())
}
