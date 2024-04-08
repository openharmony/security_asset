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

//! This module implements the stub of the Asset service.

use ipc::{parcel::MsgParcel, remote::RemoteStub, IpcResult, IpcStatusCode};

use asset_definition::{AssetError, Result};
use asset_ipc::{deserialize_map, serialize_maps, IpcCode, IPC_SUCCESS, SA_NAME};
use asset_log::loge;

use crate::AssetService;

impl RemoteStub for AssetService {
    fn on_remote_request(&self, code: u32, data: &mut ipc::parcel::MsgParcel, reply: &mut ipc::parcel::MsgParcel) -> i32 {
        match on_remote_request(self, code, data, reply) {
            Ok(_) => IPC_SUCCESS as i32,
            Err(e) => e as i32,
        }
    }

    fn descriptor(&self) -> &'static str {
        SA_NAME
    }
}

fn on_remote_request(stub: &AssetService, code: u32, data: &mut MsgParcel, reply: &mut MsgParcel) -> IpcResult<()> {
    let ipc_code = IpcCode::try_from(code).map_err(asset_err_handle)?;
    let map = deserialize_map(data).map_err(asset_err_handle)?;
    match ipc_code {
        IpcCode::Add => reply_handle(stub.add(&map), reply),
        IpcCode::Remove => reply_handle(stub.remove(&map), reply),
        IpcCode::Update => {
            let update_map = deserialize_map(data).map_err(asset_err_handle)?;
            reply_handle(stub.update(&map, &update_map), reply)
        },
        IpcCode::PreQuery => match stub.pre_query(&map) {
            Ok(res) => {
                reply_handle(Ok(()), reply)?;
                reply.write::<Vec<u8>>(&res)
            },
            Err(e) => reply_handle(Err(e), reply),
        },
        IpcCode::Query => match stub.query(&map) {
            Ok(res) => {
                reply_handle(Ok(()), reply)?;
                serialize_maps(&res, reply).map_err(asset_err_handle)
            },
            Err(e) => reply_handle(Err(e), reply),
        },
        IpcCode::PostQuery => reply_handle(stub.post_query(&map), reply),
    }
}

fn asset_err_handle(e: AssetError) -> IpcStatusCode {
    loge!("[IPC]Asset error code = {}, msg is {}", e.code, e.msg);
    IpcStatusCode::InvalidValue
}

fn reply_handle(ret: Result<()>, reply: &mut MsgParcel) -> IpcResult<()> {
    match ret {
        Ok(_) => reply.write::<u32>(&IPC_SUCCESS),
        Err(e) => {
            reply.write::<u32>(&(e.code as u32))?;
            reply.write::<String>(&e.msg)
        }
    }
}
