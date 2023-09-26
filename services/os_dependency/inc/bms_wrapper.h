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

#ifndef BMS_WRAPPER
#define BMS_WRAPPER

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool GetCallingOwnerType(uint32_t callingTokenId, int32_t *ownerType);
bool GetCallingToken(uint32_t *tokenId);
const char * GetCallingProcessName(uint32_t tokenId);
const char * GetHapOwnerInfo(uint32_t tokenId, int32_t userId);
#ifdef __cplusplus
}
#endif

#endif