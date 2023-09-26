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

import type { AsyncCallback } from './@ohos.base';

/**
 * This module provides the capabilities for life cycle management of sensitive user data (Asset) such as passwords
 * and tokens, including adding, removing, updating, and querying.
 *
 * @namespace asset
 * @syscap SystemCapability.Security.Asset
 * @since 11
 */
declare namespace asset {
  /**
   * Add an Asset.
   *
   * @param { AssetMap } attributes - a map object including attributes of the Asset to be added.
   * @param { AsyncCallback<void> } callback - the callback function for add operation.
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  function add(attributes: AssetMap, callback: AsyncCallback<void>): void;

  /**
   * Add an Asset.
   *
   * @param { AssetMap } attributes - a map object including attributes of the Asset to be added.
   * @returns { Promise<void> } the promise object returned by the function.
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  function add(attributes: AssetMap): Promise<void>;

  /**
   * Remove one or more Assets that match a search query.
   *
   * @param { AssetMap } query - a map object including attributes of the Asset to be removed.
   * @param { AsyncCallback<void> } callback - the callback function for remove operation.
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  function remove(query: AssetMap, callback: AsyncCallback<void>): void;

  /**
   * Remove one or more Assets that match a search query.
   *
   * @param { AssetMap } query - a map object including attributes of the Asset to be removed.
   * @returns { Promise<void> } the promise object returned by the function.
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  function remove(query: AssetMap): Promise<void>;

  /**
   * Update an Asset that matches a search query.
   *
   * @param { AssetMap } query - a map object including attributes of the Asset to be updated.
   * @param { AssetMap } attributesToUpdate - a map object including attributes with new values.
   * @param { AsyncCallback<void> } callback - the callback function for update operation.
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  function update(query: AssetMap, attributesToUpdate: AssetMap, callback: AsyncCallback<void>): void;

  /**
   * Update an Asset that matches a search query.
   *
   * @param { AssetMap } query - a map object including attributes of the Asset to be updated.
   * @param { AssetMap } attributesToUpdate - a map object including attributes with new values.
   * @returns { Promise<void> } the promise object returned by the function.
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  function update(query: AssetMap, attributesToUpdate: AssetMap): Promise<void>;

  /**
   * Preprocessing (e.g. get challenge) for querying one or more Assets that require user authentication.
   *
   * @param { AssetMap } query - a map object including attributes of the Asset to be queried.
   * @param { AsyncCallback<Uint8Array> } callback - the callback function for pre-query operation.
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  function preQuery(query: AssetMap, callback: AsyncCallback<Uint8Array>): void;

  /**
   * Preprocessing (e.g. get challenge) for querying one or more Assets that require user authentication.
   *
   * @param { AssetMap } query - a map object including attributes of the Asset to be queried.
   * @returns { Promise<Uint8Array> } the promise object returned by the function.
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  function preQuery(query: AssetMap): Promise<Uint8Array>;

  /**
   * Query one or more Assets that match a search query.
   *
   * @param { AssetMap } query - a map object including attributes of the Asset to be queried.
   * @param { AsyncCallback<Array<AssetMap>> } callback - the callback function for query operation.
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  function query(query: AssetMap, callback: AsyncCallback<Array<AssetMap>>): void;

  /**
   * Query one or more Assets that match a search query.
   *
   * @param { AssetMap } query - a map object including attributes of the Asset to be queried.
   * @returns { Promise<Array<AssetMap>> } the promise object returned by the function.
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  function query(query: AssetMap): Promise<Array<AssetMap>>;

  /**
   * Post-processing (e.g. release cached resource) for querying multiple Assets that require user authentication.
   *
   * @param { AssetMap } handle - a map object contains the handle returned by {@link preQuery}.
   * @param { AsyncCallback<void> } callback - the callback function for post-query operation.
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  function postQuery(handle: AssetMap, callback: AsyncCallback<void>): void;

  /**
   * Post-processing (e.g. release cached resource) for querying multiple Assets that require user authentication.
   *
   * @param { AssetMap } handle - a map object contains the handle returned by {@link preQuery}.
   * @returns { Promise<void> } the promise object returned by the function.
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  function postQuery(handle: AssetMap): Promise<void>;

  /**
   * Get the version of {@link asset} module.
   *
   * @returns { VersionInfo } the version info.
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  function getVersion(): Version;

  /**
   * The version structure returned by {@link getVersion} function.
   *
   * @typedef Version
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  export interface Version {
    /**
     * The major version.
     *
     * @type {number}
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    major: number,
    /**
     * The minor version.
     *
     * @type {number}
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    minor: number,
    /**
     * The patch version.
     *
     * @type {number}
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    patch: number,
  }

   /**
   * A Map type containing tag-value pairs that describe the attributes of an Asset.
   *
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  export type AssetMap = Map<Tag, Value>;

  /**
   * A type that indicates the secret or attribute value of an Asset tag.
   *
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  export type Value = boolean | number | Uint8Array;

  /**
   * An enum type indicates when the Asset is accessible.
   *
   * @enum { number }
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  export enum Accessibility {
    /**
     * The secret value in the Asset can only be accessed after the device is first unlocked.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    DEVICE_FIRST_UNLOCK = 1,
    /**
     * The secret value in the Asset can only be accessed while the device is unlocked.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    DEVICE_UNLOCK = 2,
  }

  /**
   * An enum type indicates the user authentication type for Asset access control.
   *
   * @enum { number }
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  export enum AuthType {
    /**
     * The access to an Asset doesn't require user authentication.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    NONE = 0x00,
    /**
     * The access to an Asset requires user authentication using either PIN/pattern/password or biometric traits.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    ANY = 0xFF,
  }

  /**
   * An enum type indicates the type of Asset synchronization.
   *
   * @enum { number }
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  export enum SyncType {
    /**
     * An Asset with this attribute value is never allowed to be transferred out.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    NEVER = 0,
    /**
     * An Asset with this attribute value can only be restored to the device from which it was transferred out.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    THIS_DEVICE = 1 << 0,
    /**
     * An Asset with this attribute value can only be transferred out to a device of trusted account.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    TRUSTED_ACCOUNT = 1 << 1,
    /**
     * An Asset with this attribute value can only be transferred out to a trusted device (user authorized).
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    TRUSTED_DEVICE = 1 << 2,
  }

  /**
   * An enum type indicates the strategy for conflict resolution when handling duplicated Asset alias.
   *
   * @enum { number }
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  export enum ConflictResolution {
    /**
     * Directly overwrite an Asset with duplicated alias when a conflict is detected.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    OVERWRITE = 0,
    /**
     * Throw an error so that the caller can take measures when a conflict is detected.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    THROW_ERROR = 1,
  }

  /**
   * An enum type indicates the return type of the queried Asset.
   *
   * @enum { number }
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  export enum ReturnType {
    /**
     * Specify that the return data should contain both secret value and attributes.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    ALL = 0,
    /**
     * Specify that the return data contains only attributes.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    ATTRIBUTES = 1,
  }

  /**
   * An enum type containing the data type definitions for Asset attribute value.
   *
   * @enum { number }
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  enum TagType {
    /**
     * The data type of Asset attribute value is bool.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    BOOL = 0x01 << 28,
    /**
     * The data type of Asset attribute value is uint32.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    UINT32 = 0x02 << 28,
    /**
     * The data type of Asset attribute value is byte array.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    BYTES = 0x03 << 28,
  }

  /**
   * An enum type containing the Asset attribute tags.
   *
   * @enum { number }
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  export enum Tag {
    /**
     * A tag whose value is a byte array indicating the sensitive user data such as passwords and tokens.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    SECRET = TagType.BYTES | 0x01,
    /**
     * A tag whose value is a byte array identifying an Asset.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    ALIAS = TagType.BYTES | 0x02,
    /**
     * A tag whose value is a 32-bit unsigned integer indicating when the Asset can be accessed.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    ACCESSIBILITY = TagType.UINT32 | 0x03,
    /**
     * A tag whose value is a bool indicating whether a screen lock password is set for the device.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    REQUIRE_PASSWORD_SET = TagType.BOOL | 0x04,
    /**
     * A tag whose value is a 32-bit unsigned integer indicating the user authentication type for Asset access control.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    AUTH_TYPE = TagType.UINT32 | 0x05,
    /**
     * A tag whose value is a 32-bit unsigned integer indicating the validity period in seconds of user authentication.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    AUTH_VALIDITY_PERIOD = TagType.UINT32 | 0x06,
    /**
     * A tag whose value is a byte array indicating the authentication challenge for anti-replay protection.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    AUTH_CHALLENGE = TagType.BYTES | 0x07,
    /**
     * A tag whose value is a byte array indicating the authentication token after a user is verified.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    AUTH_TOKEN = TagType.BYTES | 0x08,
    /**
     * A tag whose value is a 32-bit unsigned integer indicating the type of Asset synchronization.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    SYNC_TYPE = TagType.UINT32 | 0x10,
    /**
     * A tag whose value is a 32-bit unsigned integer indicating the strategy for resolving Asset conflicts.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    CONFLICT_RESOLUTION = TagType.UINT32 | 0x11,
    /**
     * A tag whose value is a byte array indicating the first user-defined Asset data label (not allow to update).
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    DATA_LABLE_CRITICAL_1 = TagType.BYTES | 0x20,
    /**
     * A tag whose value is a byte array indicating the second user-defined Asset data label (not allow to update).
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    DATA_LABLE_CRITICAL_2 = TagType.BYTES | 0x21,
    /**
     * A tag whose value is a byte array indicating the third user-defined Asset data label (not allow to update).
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    DATA_LABLE_CRITICAL_3 = TagType.BYTES | 0x22,
    /**
     * A tag whose value is a byte array indicating the fourth user-defined Asset data label (not allow to update).
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    DATA_LABLE_CRITICAL_4 = TagType.BYTES | 0x23,
    /**
     * A tag whose value is a byte array indicating the first user-defined Asset data label (allow to update).
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    DATA_LABLE_NORMAL_1 = TagType.BYTES | 0x24,
    /**
     * A tag whose value is a byte array indicating the second user-defined Asset data label (allow to update).
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    DATA_LABLE_NORMAL_2 = TagType.BYTES | 0x25,
    /**
     * A tag whose value is a byte array indicating the third user-defined Asset data label (allow to update).
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    DATA_LABLE_NORMAL_3 = TagType.BYTES | 0x26,
    /**
     * A tag whose value is a byte array indicating the fourth user-defined Asset data label (allow to update).
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    DATA_LABLE_NORMAL_4 = TagType.BYTES | 0x27,
    /**
     * A tag whose value is a 32-bit unsigned integer indicating the return type of the queried Asset.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    RETURN_TYPE = TagType.UINT32 | 0x30,
    /**
     * A tag whose value is a 32-bit unsigned integer indicating the maximum number of returned Assets in one query.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    RETURN_LIMIT = TagType.UINT32 | 0x31,
    /**
     * A tag whose value is a 32-bit unsigned integer indicating the offset of return data in batch query.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    RETURN_OFFSET = TagType.UINT32 | 0x32,
    /**
     * A tag whose value is a 32-bit unsigned integer indicating how the query results are sorted.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    RETURN_ORDER_BY = TagType.UINT32 | 0x33,
  }

  /**
   *  An enum type containing the Asset error codes.
   *
   * @enum { number }
   * @syscap SystemCapability.Security.Asset
   * @since 11
   */
  export enum ErrorCode {
    /**
     * The error code indicates that the caller doesn't have permission to operate.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    PERMISSION_DENIED = 201,
    /**
     * The error code indicates that the argument is invalid.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    INVALID_ARGUMENT = 401,
    /**
     * The error code indicates that the capability is not supported.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    NOT_SUPPORTED = 801,
    /**
     * The error code indicates that the Asset service is unavailable.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    SERVICE_UNAVAILABLE = 24000001,
    /**
     * The error code indicates that the queried Asset can not be found.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    NOT_FOUND = 24000002,
    /**
     * The error code indicates that the added Asset already exists.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    DUPLICATED = 24000003,
    /**
     * The error code indicates that the access to Asset is denied.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    ACCESS_DENIED = 24000004,
    /**
     * The error code indicates that the authentication token has expired.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    AUTH_TOKEN_EXPIRED = 24000005,
    /**
     * The error code indicates insufficient memory.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    OUT_OF_MEMRORY = 24000006,
    /**
     * The error code indicates that the Asset or encryption key is corrupted.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    DATA_CORRUPTED = 24000007,
    /**
     * The error code indicates that the ipc communication is failed.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    IPC_ERROR = 24000008,
    /**
     * The error code indicates that the Database operation is failed.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    DB_ERROR = 24000009,
    /**
     * The error code indicates that the operation of calling Bundle Manager service is failed.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    BMS_ERROR = 240000010,
    /**
     * The error code indicates that the cryptography operation is failed.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    CRYPTO_ERROR = 240000011,
    /**
     * The error code indicates that the operation of calling OS Account service is failed.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    ACCOUNT_ERROR = 240000012,
    /**
     * The error code indicates that the operation of calling Common Event service is failed.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    COMMON_EVENT_ERROR = 240000013,
    /**
     * The error code indicates that the operation of calling Access Token service is failed.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    ACCESS_TOKEN_ERROR = 240000014,
    /**
     * The error code indicates that the operation of file is failed.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    FILE_OPERATION_ERROR = 240000015,
    /**
     * The error code indicates that the operation of file is failed.
     *
     * @syscap SystemCapability.Security.Asset
     * @since 11
     */
    SYSTEM_TIME_GET_ERROR = 240000016,
  }
}

export default asset;
