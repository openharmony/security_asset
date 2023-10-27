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

//! This module extends the function of Asset data structure.

use super::{
    AssetMap, DataType, Insert, IntoValue, Tag, Value,
};

/// The mask used to obtain the data type of Asset attribute value.
const DATA_TYPE_MASK: u32 = 0xF << 28;

impl IntoValue for Tag {
    fn data_type(&self) -> DataType {
        let mask = (*self as u32) & DATA_TYPE_MASK;
        match mask {
            _ if DataType::Bool as u32 == mask => DataType::Bool,
            _ if DataType::Number as u32 == mask => DataType::Number,
            _ if DataType::Bytes as u32 == mask => DataType::Bytes,
            _ => {
                panic!("Unexpected data type, it should be uint32 or bytes.");
            },
        }
    }

    fn into_value(self) -> Value {
        Value::Number(self as u32)
    }
}

impl IntoValue for Value {
    fn data_type(&self) -> DataType {
        match self {
            Value::Bool(_) => DataType::Bool,
            Value::Number(_) => DataType::Number,
            Value::Bytes(_) => DataType::Bytes,
        }
    }

    fn into_value(self) -> Value {
        self
    }
}

impl IntoValue for Vec<u8> {
    fn data_type(&self) -> DataType {
        DataType::Bytes
    }

    fn into_value(self) -> Value {
        Value::Bytes(self)
    }
}

impl IntoValue for bool {
    fn data_type(&self) -> DataType {
        DataType::Bool
    }

    fn into_value(self) -> Value {
        Value::Bool(self)
    }
}

impl IntoValue for u32 {
    fn data_type(&self) -> DataType {
        DataType::Number
    }

    fn into_value(self) -> Value {
        Value::Number(self)
    }
}

impl Insert for AssetMap {
    fn insert_attr(&mut self, key: Tag, value: impl IntoValue) {
        self.insert(key, value.into_value());
    }
}
