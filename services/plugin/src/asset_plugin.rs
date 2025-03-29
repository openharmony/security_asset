/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

use asset_common::{CallingInfo, Counter, Group, OwnerType, GROUP_SEPARATOR};
use asset_db_operator::{
    database::{get_path, Database},
    database_file_upgrade::construct_splited_db_name,
    types::{column, QueryOptions},
};
use asset_definition::{log_throw_error, ErrCode, Extension, Result, SyncType};
use asset_file_operator::de_operator::create_user_de_dir;
use asset_log::{loge, logi};
use asset_sdk::{
    plugin_interface::{ExtDbMap, IAssetPlugin, IAssetPluginCtx, RETURN_LIMIT, RETURN_OFFSET},
    Value,
};
use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
};

/// The asset_ext plugin.
#[derive(Default)]
pub struct AssetPlugin {
    lib: RefCell<Option<libloading::Library>>,
}

static ASSET_OLUGIN_LOCK: Mutex<()> = Mutex::new(());

unsafe impl Sync for AssetPlugin {}

impl AssetPlugin {
    fn new() -> Self {
        Self { lib: RefCell::new(None) }
    }

    /// Get the instance of AssetPlugin.
    pub fn get_instance() -> Arc<AssetPlugin> {
        static mut INSTANCE: Option<Arc<AssetPlugin>> = None;
        let _guard = ASSET_OLUGIN_LOCK.lock().unwrap();
        unsafe { INSTANCE.get_or_insert_with(|| Arc::new(AssetPlugin::new())).clone() }
    }

    /// Load the plugin.
    pub fn load_plugin(&self) -> Result<Box<dyn IAssetPlugin>> {
        unsafe {
            let _guard = ASSET_OLUGIN_LOCK.lock().unwrap();
            if self.lib.borrow().is_none() {
                logi!("start to load asset_ext plugin.");
                match libloading::Library::new("libasset_ext_ffi.z.so") {
                    Ok(lib) => *self.lib.borrow_mut() = Some(lib),
                    Err(err) => {
                        loge!("dlopen libasset_ext_ffi.z.so failed, err: {}", err);
                        return log_throw_error!(ErrCode::InvalidArgument, "dlopen failed {}", err);
                    },
                };
            }

            let Some(ref lib) = *self.lib.borrow() else {
                return log_throw_error!(ErrCode::InvalidArgument, "unexpect error");
            };

            let func = match lib
                .get::<libloading::Symbol<unsafe extern "C" fn() -> *mut dyn IAssetPlugin>>(b"_create_plugin")
            {
                Ok(func) => func,
                Err(err) => {
                    loge!("dlsym _create_plugin failed, err: {}", err);
                    return log_throw_error!(ErrCode::InvalidArgument, "dlsym failed {}", err);
                },
            };

            let plugin_ptr = func();
            if plugin_ptr.is_null() {
                loge!("_create_plugin return null.");
                return log_throw_error!(ErrCode::InvalidArgument, "_create_plugin return null.");
            }

            logi!("load asset_ext plugin success.");
            Ok(Box::from_raw(plugin_ptr))
        }
    }

    /// Unload plugin.
    pub fn unload_plugin(&self) {
        let _guard = ASSET_OLUGIN_LOCK.lock().unwrap();
        if self.lib.borrow().is_some() {
            *self.lib.borrow_mut() = None;
        }
    }
}

/// The asset_ext plugin context.
#[repr(C)]
pub struct AssetContext {
    /// The asset database's user id.
    pub user_id: i32,
}

fn get_db_name(user_id: i32, attributes: &ExtDbMap, is_ce: bool) -> std::result::Result<String, u32> {
    let owner_info = attributes.get_bytes_attr(&column::OWNER).map_err(|e| e.code as u32)?;
    let owner_type = attributes.get_enum_attr::<OwnerType>(&column::OWNER_TYPE).map_err(|e| e.code as u32)?;
    let calling_info = match attributes.get_bytes_attr(&column::GROUP_ID).map_err(|e| e.code as u32) {
        Ok(group) => {
            let mut parts = group.split(|&byte| byte == GROUP_SEPARATOR as u8);
            let developer_id: Vec<u8> = parts.next().unwrap().to_vec();
            let group_id: Vec<u8> = parts.next().unwrap().to_vec();
            CallingInfo::new(user_id, owner_type, owner_info.to_vec(), Some(Group { developer_id, group_id }))
        },
        _ => CallingInfo::new(user_id, owner_type, owner_info.to_vec(), None),
    };
    construct_splited_db_name(&calling_info, is_ce).map_err(|e| e.code as u32)
}

fn get_query_options(attrs: &ExtDbMap) -> QueryOptions {
    QueryOptions {
        offset: match attrs.get(RETURN_OFFSET) {
            Some(Value::Number(offset)) => Some(*offset),
            _ => None,
        },
        limit: match attrs.get(RETURN_LIMIT) {
            Some(Value::Number(limit)) => Some(*limit),
            _ => None,
        },
        order_by: None,
        order: None,
        amend: None,
    }
}

#[allow(dead_code)]
impl IAssetPluginCtx for AssetContext {
    /// Initializes the plugin before usage.
    fn init(&mut self, user_id: i32) -> std::result::Result<(), u32> {
        create_user_de_dir(user_id).map_err(|e| e.code as u32)?;
        self.user_id = user_id;
        Ok(())
    }

    /// Adds an asset to de db.
    fn add(&mut self, attributes: &ExtDbMap) -> std::result::Result<i32, u32> {
        let db_name = get_db_name(self.user_id, attributes, false)?;
        let mut db = Database::build_with_file_name(self.user_id, &db_name, false).map_err(|e| e.code as u32)?;
        db.insert_datas(attributes).map_err(|e| e.code as u32)
    }

    /// Adds an asset to ce db.
    fn ce_add(&mut self, attributes: &ExtDbMap) -> std::result::Result<i32, u32> {
        let db_name = get_db_name(self.user_id, attributes, true)?;
        let mut db = Database::build_with_file_name(self.user_id, &db_name, true).map_err(|e| e.code as u32)?;
        db.insert_datas(attributes).map_err(|e| e.code as u32)
    }

    /// Adds an asset with replace to de db.
    fn replace(&mut self, condition: &ExtDbMap, attributes: &ExtDbMap) -> std::result::Result<(), u32> {
        let db_name = get_db_name(self.user_id, attributes, false)?;
        let mut db = Database::build_with_file_name(self.user_id, &db_name, false).map_err(|e| e.code as u32)?;
        db.replace_datas(condition, false, attributes).map_err(|e| e.code as u32)
    }

    /// Adds an asset with replace to ce db.
    fn ce_replace(&mut self, condition: &ExtDbMap, attributes: &ExtDbMap) -> std::result::Result<(), u32> {
        let db_name = get_db_name(self.user_id, attributes, true)?;
        let mut db = Database::build_with_file_name(self.user_id, &db_name, true).map_err(|e| e.code as u32)?;
        db.replace_datas(condition, false, attributes).map_err(|e| e.code as u32)
    }

    /// Queries de db.
    fn query(&mut self, attributes: &ExtDbMap) -> std::result::Result<Vec<ExtDbMap>, u32> {
        let de_dbs = asset_file_operator::de_operator::get_de_user_dbs(self.user_id).map_err(|e| e.code as u32)?;
        let mut query_data = vec![];
        for db_name in de_dbs {
            let mut db = Database::build_with_file_name(self.user_id, &db_name, false).map_err(|e| e.code as u32)?;
            query_data.extend(db.query_datas(&vec![], attributes, None, false).map_err(|e| e.code as u32)?);
        }
        Ok(query_data)
    }

    /// Queries ce db.
    fn ce_query(&mut self, attributes: &ExtDbMap) -> std::result::Result<Vec<ExtDbMap>, u32> {
        let ce_dbs = asset_file_operator::ce_operator::get_ce_user_dbs(self.user_id).map_err(|e| e.code as u32)?;
        let mut query_data = vec![];
        for db_name in ce_dbs {
            let mut db = Database::build_with_file_name(self.user_id, &db_name, true).map_err(|e| e.code as u32)?;
            query_data.extend(db.query_datas(&vec![], attributes, None, false).map_err(|e| e.code as u32)?);
        }
        Ok(query_data)
    }

    fn query_temp(
        &mut self,
        db_name: &str,
        columns: &[&'static str],
        is_ce: bool,
    ) -> std::result::Result<Vec<ExtDbMap>, u32> {
        let mut db = Database::build_with_file_name(self.user_id, db_name, is_ce).map_err(|e| e.code as u32)?;
        let condition = ExtDbMap::new();
        let mut sql_where = String::from(" where ");
        sql_where.push_str(&format!("(SyncType & {0}) = {0} ", SyncType::TrustedDevice as u32));
        sql_where.push_str("and ");
        sql_where.push_str("SyncStatus <> 2 ");
        let query_options =
            QueryOptions { offset: None, limit: None, order: None, order_by: None, amend: Some(sql_where) };
        let query_data =
            db.query_datas(&columns.to_vec(), &condition, Some(&query_options), false).map_err(|e| e.code as u32)?;
        Ok(query_data)
    }

    /// Query db with attributes to a certain db. Normal, Group, CE.
    fn query_certain_db(
        &mut self,
        db_info: &ExtDbMap,
        attributes: &ExtDbMap,
        query_options: &ExtDbMap,
        is_ce: bool,
    ) -> std::result::Result<Vec<ExtDbMap>, u32> {
        let db_name = get_db_name(self.user_id, db_info, is_ce)?;
        let mut db = Database::build_with_file_name(self.user_id, &db_name, is_ce).map_err(|e| e.code as u32)?;
        db.query_datas(&vec![], attributes, Some(&get_query_options(query_options)), true).map_err(|e| e.code as u32)
    }

    /// Removes an asset from de db.
    fn remove(&mut self, attributes: &ExtDbMap) -> std::result::Result<i32, u32> {
        let de_dbs = asset_file_operator::de_operator::get_de_user_dbs(self.user_id).map_err(|e| e.code as u32)?;
        let mut total_remove_count = 0;
        for db_name in de_dbs {
            let mut db = Database::build_with_file_name(self.user_id, &db_name, false).map_err(|e| e.code as u32)?;
            total_remove_count += db.delete_datas(attributes, None, false).map_err(|e| e.code as u32)?;
        }
        Ok(total_remove_count)
    }

    /// Removes an asset from ce db.
    fn ce_remove(&mut self, attributes: &ExtDbMap) -> std::result::Result<i32, u32> {
        let ce_dbs = asset_file_operator::ce_operator::get_ce_user_dbs(self.user_id).map_err(|e| e.code as u32)?;
        let mut total_remove_count = 0;
        for db_name in ce_dbs {
            let mut db = Database::build_with_file_name(self.user_id, &db_name, true).map_err(|e| e.code as u32)?;
            total_remove_count += db.delete_datas(attributes, None, false).map_err(|e| e.code as u32)?;
        }
        Ok(total_remove_count)
    }

    /// Removes an asset from a certain db. Normal, Group, CE.
    fn remove_certain_db(
        &mut self,
        db_info: &ExtDbMap,
        attributes: &ExtDbMap,
        is_ce: bool,
    ) -> std::result::Result<i32, u32> {
        let db_name = get_db_name(self.user_id, db_info, is_ce)?;
        let mut db = Database::build_with_file_name(self.user_id, &db_name, is_ce).map_err(|e| e.code as u32)?;
        db.delete_datas(attributes, None, false).map_err(|e| e.code as u32)
    }

    /// Removes assets from de db with sepcific condition.
    fn remove_with_specific_cond(
        &mut self,
        specific_cond: &str,
        condition_value: &[Value],
    ) -> std::result::Result<i32, u32> {
        let de_dbs = asset_file_operator::de_operator::get_de_user_dbs(self.user_id).map_err(|e| e.code as u32)?;
        let mut total_remove_count = 0;
        for db_name in de_dbs {
            let mut db = Database::build_with_file_name(self.user_id, &db_name, false).map_err(|e| e.code as u32)?;
            total_remove_count +=
                db.delete_specific_condition_datas(specific_cond, condition_value).map_err(|e| e.code as u32)?;
        }
        Ok(total_remove_count)
    }

    /// Removes assets from ce db with sepcific condition.
    fn ce_remove_with_specific_cond(
        &mut self,
        specific_cond: &str,
        condition_value: &[Value],
    ) -> std::result::Result<i32, u32> {
        let ce_dbs = asset_file_operator::ce_operator::get_ce_user_dbs(self.user_id).map_err(|e| e.code as u32)?;
        let mut total_remove_count = 0;
        for db_name in ce_dbs {
            let mut db = Database::build_with_file_name(self.user_id, &db_name, true).map_err(|e| e.code as u32)?;
            total_remove_count +=
                db.delete_specific_condition_datas(specific_cond, condition_value).map_err(|e| e.code as u32)?;
        }
        Ok(total_remove_count)
    }

    /// Updates the attributes of an asset in de db.
    fn update(&mut self, attributes: &ExtDbMap, attrs_to_update: &ExtDbMap) -> std::result::Result<i32, u32> {
        let de_dbs = asset_file_operator::de_operator::get_de_user_dbs(self.user_id).map_err(|e| e.code as u32)?;
        let mut total_update_count = 0;
        for db_name in de_dbs {
            let mut db = Database::build_with_file_name(self.user_id, &db_name, false).map_err(|e| e.code as u32)?;
            total_update_count += db.update_datas(attributes, false, attrs_to_update).map_err(|e| e.code as u32)?;
        }
        Ok(total_update_count)
    }

    /// Updates the attributes of an asset in ce db.
    fn ce_update(&mut self, attributes: &ExtDbMap, attrs_to_update: &ExtDbMap) -> std::result::Result<i32, u32> {
        let ce_dbs = asset_file_operator::ce_operator::get_ce_user_dbs(self.user_id).map_err(|e| e.code as u32)?;
        let mut total_update_count = 0;
        for db_name in ce_dbs {
            let mut db = Database::build_with_file_name(self.user_id, &db_name, true).map_err(|e| e.code as u32)?;
            total_update_count += db.update_datas(attributes, false, attrs_to_update).map_err(|e| e.code as u32)?;
        }
        Ok(total_update_count)
    }

    /// Returns the storage path for de db.
    fn get_storage_path(&self) -> String {
        get_path()
    }

    /// Increase count
    fn increase_count(&mut self) {
        let counter = Counter::get_instance();
        counter.lock().unwrap().increase_count();
    }

    /// Decrease count
    fn decrease_count(&mut self) {
        let counter = Counter::get_instance();
        counter.lock().unwrap().decrease_count();
    }
}
