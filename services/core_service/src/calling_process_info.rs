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

mod calling_owner_type;
mod calling_owner_user_id;

use asset_common::definition::Result;
use calling_owner_type::{OwnerType, get_calling_owner_type};
use calling_owner_user_id::get_calling_user_id;

use ipc_rust::get_calling_uid;

/// calling info
pub(crate) struct CallingInfo {
    owner_type: OwnerType,
    user_id: u32,
}

impl CallingInfo {
    /// x
    pub(crate) fn build() -> Result<Self> {
        let uid = get_calling_uid();
        Ok(CallingInfo {
            owner_type: get_calling_owner_type(uid),
            user_id: get_calling_user_id(uid)?
        })
    }

    /// x
    pub(crate) fn get_owner_type(&self) -> u32 {
        self.owner_type.get_type_num()
    }

    /// x
    pub(crate) fn get_owner_text(&self) -> &Vec<u8> {
        self.owner_type.get_owner_text()
    }

    /// x
    pub(crate) fn get_user_id(&self) -> u32 {
        self.user_id
    }
}