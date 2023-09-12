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

use core::panic;

use asset_rust_sdk::definition::{AssetMap, Accessibility, Tag, InsertAttribute, AuthType, SyncType};

#[test]
fn test_for_add() {
    let mut input = AssetMap::new();
    input.insert_attr(Tag::Secret, Vec::from("alias".as_bytes())).unwrap();
    input.insert_attr(Tag::AuthType, AuthType::Any).unwrap();
    input.insert_attr(Tag::SyncType, SyncType::Never).unwrap();

    input.insert_attr(Tag::Accessibility, Accessibility::DeviceSecure).unwrap();
    input.insert_attr(Tag::Alias, Vec::from("alias".as_bytes())).unwrap();

    match asset_rust_sdk::Manager::build() {
        Ok(manager) => {
            if let Err(e) = manager.add(input) {
                panic!("test for add failed {}", e)
            }
        },
        Err(e) => panic!("test for add failed {}", e)
    }
}
