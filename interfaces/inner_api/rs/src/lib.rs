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

//! This create implement the asset

#![allow(dead_code)]

pub use asset_common::definition; // todo: definition迁移到SDK后，怎么解决Service的依赖

use std::ffi::{c_char, CString};

use hilog_rust::hilog;
use ipc_rust::RemoteObjRef;
use rust_samgr::get_service_proxy;

use asset_common::{
    logi, loge,
    definition::{AssetMap, Result, ErrCode},
};
use asset_ipc::iasset::{IAsset, SA_ID};

fn get_remote() -> Result<RemoteObjRef<dyn IAsset>> {
    let object = get_service_proxy::<dyn IAsset>(SA_ID);
    match object {
        Ok(remote) => Ok(remote),
        Err(e) => {
            loge!("[FATAL]get_remote failed {}!", @public(e));
            Err(ErrCode::ServiceUnvailable)
        }
    }
}

/// This manager provides the capabilities for life cycle management of sensitive user data (Asset) such as passwords
/// and tokens, including adding, removing, updating, and querying.
pub struct Manager {
    remote: RemoteObjRef<dyn IAsset>,
}

impl Manager {
    /// Build and initialize the Manager.
    pub fn build() -> Result<Self> {
        let remote = get_remote()?;
        Ok(Self { remote })
    }

    /// Add an Asset.
    pub fn add(&self, input: AssetMap) -> Result<()> {
        logi!("[YZT][RUST SDK]enter asset add");
        self.remote.add(&input)
    }
}
