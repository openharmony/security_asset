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

//! This module is used to handle start event.

use std::collections::HashMap;

use asset_file_operator::delete_user_db_dir;
use asset_log::{loge, logi};
use system_ability_fwk::cxx_share::SystemAbilityOnDemandReason;

use crate::common_event::listener;

const USER_ID: &str = "userId";
const SANDBOX_APP_INDEX: &str = "sandbox_app_index";
const APP_ID: &str = "appId";

fn handle_package_removed(want: &HashMap<String, String>, is_sandbox: bool) {
    let Some(user_id) = want.get(USER_ID) else {
        loge!("[FATIL]Get removed owner info failed, get userId fail");
        return;
    };
    let Some(app_id) = want.get(APP_ID) else {
        loge!("[FATIL]Get removed owner info failed, get appId fail");
        return;
    };

    let mut app_index = 0;
    if is_sandbox {
        app_index = match want.get(SANDBOX_APP_INDEX) {
            Some(v) => match v.parse::<i32>() {
                Ok(parsed_value) => parsed_value,
                Err(_) => {
                    loge!("[FATAL]Get removed owner info failed, failed to parse appIndex");
                    return;
                },
            },
            None => {
                loge!("[FATIL]Get removed owner info failed, get appIndex fail");
                return;
            },
        }
    }
    let owner = format!("{}_{}", app_id, app_index);
    let user_id = match user_id.parse::<i32>() {
        Ok(parsed_value) => parsed_value,
        Err(_) => {
            loge!("[FATIL]Get removed user_id failed, failed to parse user_id");
            return;
        },
    };
    listener::delete_data_by_owner(user_id, owner.as_ptr(), owner.len() as u32);
}

pub(crate) fn handle_common_event(reason: SystemAbilityOnDemandReason) {
    let reason_name: String = reason.name;
    if reason_name == "usual.event.PACKAGE_REMOVED" {
        let want = reason.extra_data.want();
        handle_package_removed(&want, false);
    } else if reason_name == "usual.event.SANDBOX_PACKAGE_REMOVED" {
        let want = reason.extra_data.want();
        handle_package_removed(&want, true);
    } else if reason_name == "usual.event.USER_REMOVED" {
        logi!("on_start by user remove");
        let _ = delete_user_db_dir(reason.extra_data.code);
    } else if reason_name == "usual.event.CHARGING" {
        listener::backup_db();
    }
}