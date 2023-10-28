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

//! This module is used to insert an Asset with a specified alias.

use asset_crypto_manager::crypto::{Crypto, SecretKey};
use asset_db_operator::{
    database::Database,
    database_table_helper::{
        do_transaction, DatabaseHelper, COLUMN_ACCESSIBILITY, COLUMN_ALIAS, COLUMN_AUTH_TYPE, COLUMN_CREATE_TIME,
        COLUMN_DELETE_TYPE, COLUMN_OWNER, COLUMN_OWNER_TYPE, COLUMN_REQUIRE_PASSWORD_SET, COLUMN_SECRET,
        COLUMN_SYNC_TYPE, COLUMN_UPDATE_TIME, COLUMN_VERSION, DB_DATA_VERSION,
    },
    types::DbMap,
};
use asset_definition::{
    Accessibility, AssetMap, AuthType, ConflictResolution, DeleteType, ErrCode, Extension, Result, SyncType, Tag, Value,
};
use asset_log::{loge, logi};

use crate::{calling_info::CallingInfo, operations::common};

fn generate_key_if_needed(secret_key: &SecretKey) -> Result<()> {
    match secret_key.exists() {
        Ok(true) => Ok(()),
        Ok(false) => {
            logi!("[INFO]The key does not exist, generate it.");
            if let Err(res) = secret_key.generate() {
                loge!("[FATAL]Generete key failed, res is [{}].", res);
                Err(ErrCode::CryptoError)
            } else {
                Ok(())
            }
        },
        _ => {
            loge!("HUKS failed to check whether the key exists.");
            Err(ErrCode::CryptoError)
        },
    }
}

fn encrypt(calling_info: &CallingInfo, db_data: &mut DbMap) -> Result<()> {
    let secret_key = common::build_secret_key(calling_info, db_data)?;
    generate_key_if_needed(&secret_key)?;

    let secret = db_data.get_bytes_attr(&COLUMN_SECRET)?;
    let cipher = Crypto::encrypt(&secret_key, secret, &common::build_aad(db_data))?;
    db_data.insert(COLUMN_SECRET, Value::Bytes(cipher));
    Ok(())
}

fn replace_db_record(calling_info: &CallingInfo, query_db_data: &DbMap, replace_db_data: &DbMap) -> Result<()> {
    let replace_callback = |db: &Database| -> bool {
        if db.delete_datas(query_db_data).is_err() {
            loge!("remove asset in replace operation failed!");
            return false;
        }
        if db.insert_datas(replace_db_data).is_err() {
            loge!("insert asset in replace operation failed!");
            return false;
        }
        true
    };

    if !do_transaction(calling_info.user_id(), replace_callback)? {
        loge!("do_transaction in replace_db_record failed!");
        return Err(ErrCode::DatabaseError);
    }
    Ok(())
}

fn resolve_conflict(calling_info: &CallingInfo, attrs: &AssetMap, query: &DbMap, db_data: &mut DbMap) -> Result<()> {
    match attrs.get(&Tag::ConflictResolution) {
        Some(Value::Number(num)) if *num == ConflictResolution::Overwrite as u32 => {
            encrypt(calling_info, db_data)?;
            replace_db_record(calling_info, query, db_data)
        },
        _ => {
            loge!("[FATAL][SA]The specified alias already exists.");
            Err(ErrCode::Duplicated)
        },
    }
}

fn get_query_condition(calling_info: &CallingInfo, attrs: &AssetMap) -> Result<DbMap> {
    let alias = attrs.get_bytes_attr(&Tag::Alias)?;
    let mut query = DbMap::new();
    query.insert(COLUMN_ALIAS, Value::Bytes(alias.clone()));
    query.insert(COLUMN_OWNER, Value::Bytes(calling_info.owner_info().clone()));
    query.insert(COLUMN_OWNER_TYPE, Value::Number(calling_info.owner_type()));
    Ok(query)
}

fn add_system_attrs(db_data: &mut DbMap) -> Result<()> {
    db_data.insert(COLUMN_VERSION, Value::Number(DB_DATA_VERSION));

    let time = common::get_system_time()?;
    db_data.insert(COLUMN_CREATE_TIME, Value::Bytes(time.clone()));
    db_data.insert(COLUMN_UPDATE_TIME, Value::Bytes(time));
    Ok(())
}

fn add_default_attrs(db_data: &mut DbMap) {
    db_data.entry(COLUMN_ACCESSIBILITY).or_insert(Value::Number(Accessibility::DeviceFirstUnlock as u32));
    db_data.entry(COLUMN_AUTH_TYPE).or_insert(Value::Number(AuthType::None as u32));
    db_data.entry(COLUMN_SYNC_TYPE).or_insert(Value::Number(SyncType::Never as u32));
    db_data.entry(COLUMN_REQUIRE_PASSWORD_SET).or_insert(Value::Bool(false));
    let delete_type = DeleteType::WhenUserRemoved as u32 | DeleteType::WhenPackageRemoved as u32;
    db_data.entry(COLUMN_DELETE_TYPE).or_insert(Value::Number(delete_type));
}

const REQUIRED_ATTRS: [Tag; 2] = [Tag::Secret, Tag::Alias];

const OPTIONAL_ATTRS: [Tag; 3] = [Tag::Secret, Tag::ConflictResolution, Tag::DeleteType];

fn check_arguments(attributes: &AssetMap) -> Result<()> {
    common::check_required_tags(attributes, &REQUIRED_ATTRS)?;

    let mut valid_tags = common::CRITICAL_LABEL_ATTRS.to_vec();
    valid_tags.extend_from_slice(&common::NORMAL_LABEL_ATTRS);
    valid_tags.extend_from_slice(&common::ACCESS_CONTROL_ATTRS);
    valid_tags.extend_from_slice(&OPTIONAL_ATTRS);
    common::check_tag_validity(attributes, &valid_tags)?;
    common::check_value_validity(attributes)
}

pub(crate) fn add(attributes: &AssetMap, calling_info: &CallingInfo) -> Result<()> {
    check_arguments(attributes)?;

    // Create database directory if not exists.
    asset_file_operator::create_user_db_dir(calling_info.user_id())?;

    // Fill all attributes to DbMap.
    let mut db_data = common::into_db_map(attributes);
    common::add_owner_info(calling_info, &mut db_data);
    add_system_attrs(&mut db_data)?;
    add_default_attrs(&mut db_data);

    let query = get_query_condition(calling_info, attributes)?;
    if DatabaseHelper::is_data_exists(calling_info.user_id(), &query)? {
        resolve_conflict(calling_info, attributes, &query, &mut db_data)
    } else {
        encrypt(calling_info, &mut db_data)?;
        let insert_num = DatabaseHelper::insert_datas(calling_info.user_id(), &db_data)?;
        logi!("insert {} data", insert_num);
        Ok(())
    }
}
