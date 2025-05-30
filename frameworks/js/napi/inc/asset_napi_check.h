/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef ASSET_NAPI_CHECK_H
#define ASSET_NAPI_CHECK_H

#include <vector>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "asset_system_type.h"

namespace OHOS {
namespace Security {
namespace Asset {

#define RETURN_JS_ERROR(env, errorCode, format, arg...)                                             \
do {                                                                                                \
    char msg[MAX_MESSAGE_LEN] = { 0 };                                                              \
    if ((sprintf_s(msg, MAX_MESSAGE_LEN, format, ##arg)) == -1) {                                   \
        LOGE("[FATAL][NAPI]Failed to create message string, truncation occurred when sprintf_s.");  \
        return CreateJsError((env), (errorCode));                                                   \
    }                                                                                               \
    LOGE("[FATAL][NAPI]%{public}s", (msg));                                                         \
    return CreateJsError((env), (errorCode), (msg));                                                \
} while (0)

const std::vector<uint32_t> CRITICAL_LABEL_TAGS = {
    SEC_ASSET_TAG_DATA_LABEL_CRITICAL_1,
    SEC_ASSET_TAG_DATA_LABEL_CRITICAL_2,
    SEC_ASSET_TAG_DATA_LABEL_CRITICAL_3,
    SEC_ASSET_TAG_DATA_LABEL_CRITICAL_4
};

const std::vector<uint32_t> NORMAL_LABEL_TAGS = {
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_1,
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_2,
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_3,
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_4
};

const std::vector<uint32_t> NORMAL_LOCAL_LABEL_TAGS = {
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_LOCAL_1,
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_LOCAL_2,
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_LOCAL_3,
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_LOCAL_4
};

const std::vector<uint32_t> ACCESS_CONTROL_TAGS = {
    SEC_ASSET_TAG_ALIAS,
    SEC_ASSET_TAG_ACCESSIBILITY,
    SEC_ASSET_TAG_AUTH_TYPE,
    SEC_ASSET_TAG_IS_PERSISTENT,
    SEC_ASSET_TAG_SYNC_TYPE,
    SEC_ASSET_TAG_REQUIRE_PASSWORD_SET,
    SEC_ASSET_TAG_REQUIRE_ATTR_ENCRYPTED,
    SEC_ASSET_TAG_GROUP_ID,
    SEC_ASSET_TAG_WRAP_TYPE,
    SEC_ASSET_TAG_USER_ID
};

const std::vector<uint32_t> ASSET_RETURN_ORDER_BY_TAGS = {
    SEC_ASSET_TAG_DATA_LABEL_CRITICAL_1,
    SEC_ASSET_TAG_DATA_LABEL_CRITICAL_2,
    SEC_ASSET_TAG_DATA_LABEL_CRITICAL_3,
    SEC_ASSET_TAG_DATA_LABEL_CRITICAL_4,
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_1,
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_2,
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_3,
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_4,
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_LOCAL_1,
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_LOCAL_2,
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_LOCAL_3,
    SEC_ASSET_TAG_DATA_LABEL_NORMAL_LOCAL_4
};

const std::vector<uint32_t> ASSET_SYNC_TAGS = {
    SEC_ASSET_TAG_OPERATION_TYPE
};

const std::vector<uint32_t> ASSET_ACCESSIBILITY_VEC = {
    SEC_ASSET_ACCESSIBILITY_DEVICE_POWERED_ON,
    SEC_ASSET_ACCESSIBILITY_DEVICE_FIRST_UNLOCKED,
    SEC_ASSET_ACCESSIBILITY_DEVICE_UNLOCKED
};

const std::vector<uint32_t> ASSET_AUTH_TYPE_VEC = {
    SEC_ASSET_AUTH_TYPE_NONE,
    SEC_ASSET_AUTH_TYPE_ANY
};

const std::vector<uint32_t> ASSET_CONFLICT_RESOLUTION_VEC = {
    SEC_ASSET_CONFLICT_OVERWRITE,
    SEC_ASSET_CONFLICT_THROW_ERROR
};

const std::vector<uint32_t> ASSET_RETURN_TYPE_VEC = {
    SEC_ASSET_RETURN_ALL,
    SEC_ASSET_RETURN_ATTRIBUTES
};

const std::vector<uint32_t> ASSET_WRAP_TYPE_VEC = {
    SEC_ASSET_WRAP_TYPE_NEVER,
    SEC_ASSET_WRAP_TYPE_TRUSTED_ACCOUNT
};

const std::unordered_map<uint32_t, const char *> TAG_MAP = {
    { SEC_ASSET_TAG_SECRET, "SECRET" },
    { SEC_ASSET_TAG_ALIAS, "ALIAS" },
    { SEC_ASSET_TAG_ACCESSIBILITY, "ACCESSIBILITY" },
    { SEC_ASSET_TAG_REQUIRE_PASSWORD_SET, "REQUIRE_PASSWORD_SET" },
    { SEC_ASSET_TAG_AUTH_TYPE, "AUTH_TYPE" },
    { SEC_ASSET_TAG_AUTH_VALIDITY_PERIOD, "AUTH_VALIDITY_PERIOD" },
    { SEC_ASSET_TAG_AUTH_CHALLENGE, "AUTH_CHALLENGE" },
    { SEC_ASSET_TAG_AUTH_TOKEN, "AUTH_TOKEN" },
    { SEC_ASSET_TAG_SYNC_TYPE, "SYNC_TYPE" },
    { SEC_ASSET_TAG_IS_PERSISTENT, "IS_PERSISTENT" },
    { SEC_ASSET_TAG_CONFLICT_RESOLUTION, "CONFLICT_RESOLUTION" },
    { SEC_ASSET_TAG_DATA_LABEL_CRITICAL_1, "DATA_LABEL_CRITICAL_1" },
    { SEC_ASSET_TAG_DATA_LABEL_CRITICAL_2, "DATA_LABEL_CRITICAL_2" },
    { SEC_ASSET_TAG_DATA_LABEL_CRITICAL_3, "DATA_LABEL_CRITICAL_3" },
    { SEC_ASSET_TAG_DATA_LABEL_CRITICAL_4, "DATA_LABEL_CRITICAL_4" },
    { SEC_ASSET_TAG_DATA_LABEL_NORMAL_1, "DATA_LABEL_NORMAL_1" },
    { SEC_ASSET_TAG_DATA_LABEL_NORMAL_2, "DATA_LABEL_NORMAL_2" },
    { SEC_ASSET_TAG_DATA_LABEL_NORMAL_3, "DATA_LABEL_NORMAL_3" },
    { SEC_ASSET_TAG_DATA_LABEL_NORMAL_4, "DATA_LABEL_NORMAL_4" },
    { SEC_ASSET_TAG_DATA_LABEL_NORMAL_LOCAL_1, "DATA_LABEL_NORMAL_LOCAL_1" },
    { SEC_ASSET_TAG_DATA_LABEL_NORMAL_LOCAL_2, "DATA_LABEL_NORMAL_LOCAL_2" },
    { SEC_ASSET_TAG_DATA_LABEL_NORMAL_LOCAL_3, "DATA_LABEL_NORMAL_LOCAL_3" },
    { SEC_ASSET_TAG_DATA_LABEL_NORMAL_LOCAL_4, "DATA_LABEL_NORMAL_LOCAL_4" },
    { SEC_ASSET_TAG_RETURN_TYPE, "RETURN_TYPE" },
    { SEC_ASSET_TAG_RETURN_LIMIT, "RETURN_LIMIT" },
    { SEC_ASSET_TAG_RETURN_OFFSET, "RETURN_OFFSET" },
    { SEC_ASSET_TAG_RETURN_ORDERED_BY, "RETURN_ORDERED_BY" },
    { SEC_ASSET_TAG_UPDATE_TIME, "UPDATE_TIME" },
    { SEC_ASSET_TAG_OPERATION_TYPE, "OPERATION_TYPE" },
    { SEC_ASSET_TAG_REQUIRE_ATTR_ENCRYPTED, "REQUIRE_ATTR_ENCRYPTED" },
    { SEC_ASSET_TAG_GROUP_ID, "GROUP_ID" },
    { SEC_ASSET_TAG_WRAP_TYPE, "WRAP_TYPE" },
    { SEC_ASSET_TAG_USER_ID, "USER_ID" },
};

napi_value CheckAssetRequiredTag(const napi_env env, const std::vector<AssetAttr> &attrs,
    const std::vector<uint32_t> &requiredTags, uint32_t errorCode);

napi_value CheckAssetTagValidity(const napi_env env, const std::vector<AssetAttr> &attrs,
    const std::vector<uint32_t> &validTags, uint32_t errorCode);

napi_value CheckAssetValueValidity(const napi_env env, const std::vector<AssetAttr> &attrs, uint32_t errorCode);

} // Asset
} // Security
} // OHOS

#endif // ASSET_NAPI_CHECK_H