/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OPENSSL_WRAPPER_H
#define OPENSSL_WRAPPER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// The caller should ensure the memory safety, that the points should point at valid memory.
void Sha256(const uint8_t *input, uint32_t intputLen, uint8_t *output);

int32_t GenerateRandom(uint8_t *random, uint32_t randomLen);

#ifdef __cplusplus
}
#endif

#endif // OPENSSL_WRAPPER_H