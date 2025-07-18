/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef FILE_OPERATOR_WRAPPER
#define FILE_OPERATOR_WRAPPER

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t GetRemainPartitionSize(const char *partitionName, double *partitionSize);
uint64_t GetDirSize(const char *dir);

#ifdef __cplusplus
}
#endif

#endif
