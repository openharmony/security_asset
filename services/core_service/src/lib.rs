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

//! This module implements the Asset service.

use std::{
    ffi::{c_char, CString},
    thread,
    time::{Duration, Instant},
};

use hilog_rust::{error, hilog, HiLogLabel, LogType};
use ipc_rust::{IRemoteBroker, RemoteObj};
use system_ability_fwk_rust::{define_system_ability, IMethod, ISystemAbility, RSystemAbility};

use asset_definition::{AssetMap, Result};
use asset_ipc::{IAsset, SA_ID};
use asset_log::logi;

mod calling_info;
mod operations;
mod stub;
mod sys_event;
mod trace_scope;

use calling_info::CallingInfo;
use stub::AssetStub;
use sys_event::sys_event_log;
use trace_scope::TraceScope;

const LOG_LABEL: HiLogLabel = HiLogLabel { log_type: LogType::LogCore, domain: 0xD002F70, tag: "Asset" };

define_system_ability!(
    sa: SystemAbility(on_start, on_stop),
);

const MAX_RETRY_TIME: u32 = 5;
const RETRY_INTERVAL: u64 = 1000;

extern "C" {
    fn SubscribeSystemEvent() -> bool;
    fn UnSubscribeSystemEvent() -> bool;
}

fn on_start<T: ISystemAbility + IMethod>(ability: &T) {
    let service = AssetStub::new_remote_stub(AssetService).expect("create AssetService failed");
    ability.publish(&service.as_object().expect("publish Asset service failed"), SA_ID);
    logi!("[INFO]Asset service on_start");
    thread::spawn(|| {
        for i in 0..MAX_RETRY_TIME {
            if unsafe { SubscribeSystemEvent() } {
                logi!("Subscribe system event success.");
                return;
            }
            logi!("Subscribe system event failed, retry {}", i + 1);
            thread::sleep(Duration::from_millis(RETRY_INTERVAL));
        }
    });
}

fn on_stop<T: ISystemAbility + IMethod>(_ability: &T) {
    logi!("[INFO]Asset service on_stop");
    unsafe {
        UnSubscribeSystemEvent();
    }
}

#[used]
#[link_section = ".init_array"]
static A: extern "C" fn() = {
    extern "C" fn init() {
        let r_sa = SystemAbility::new_system_ability(SA_ID, true).expect("create Asset service failed");
        r_sa.register();
    }
    init
};

struct AssetService;

impl IRemoteBroker for AssetService {}

impl IAsset for AssetService {
    fn add(&self, attributes: &AssetMap) -> Result<()> {
        let fun_name = "add";
        let start = Instant::now();
        let _trace = TraceScope::trace(fun_name);
        let calling_info = CallingInfo::build()?;
        sys_event_log(operations::add(attributes, &calling_info), &calling_info, start, fun_name)
    }

    fn remove(&self, query: &AssetMap) -> Result<()> {
        let fun_name = "remove";
        let start = Instant::now();
        let _trace = TraceScope::trace(fun_name);
        let calling_info = CallingInfo::build()?;
        sys_event_log(operations::remove(query, &calling_info), &calling_info, start, fun_name)
    }

    fn update(&self, query: &AssetMap, attributes_to_update: &AssetMap) -> Result<()> {
        let fun_name = "update";
        let start = Instant::now();
        let _trace = TraceScope::trace(fun_name);
        let calling_info = CallingInfo::build()?;
        sys_event_log(operations::update(query, attributes_to_update, &calling_info), &calling_info, start, fun_name)
    }

    fn pre_query(&self, query: &AssetMap) -> Result<Vec<u8>> {
        let fun_name = "pre_query";
        let start = Instant::now();
        let _trace = TraceScope::trace(fun_name);
        let calling_info = CallingInfo::build()?;
        sys_event_log(operations::pre_query(query, &calling_info), &calling_info, start, fun_name)
    }

    fn query(&self, query: &AssetMap) -> Result<Vec<AssetMap>> {
        let fun_name = "query";
        let start = Instant::now();
        let _trace = TraceScope::trace(fun_name);
        let calling_info = CallingInfo::build()?;
        sys_event_log(operations::query(query, &calling_info), &calling_info, start, fun_name)
    }

    fn post_query(&self, query: &AssetMap) -> Result<()> {
        let fun_name = "post_query";
        let start = Instant::now();
        let _trace = TraceScope::trace(fun_name);
        let calling_info = CallingInfo::build()?;
        sys_event_log(operations::post_query(query, &calling_info), &calling_info, start, fun_name)
    }
}
