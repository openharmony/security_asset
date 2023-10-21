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

//! This module is used to implement cryptographic algorithm operations, including key generation and usage.

use std::ptr::null;
use crate::huks_ffi::*;
use asset_common::{
    definition::{Accessibility, AuthType, ErrCode},
    loge,
    logi,
};

/// SecretKey struct
pub struct SecretKey {
    auth_type: AuthType,
    access_type: Accessibility,
    alias: Vec<u8>,
}

const MAX_ALIAS_SIZE: u32 = 64;

impl SecretKey {
    /// New a secret key
    pub fn new(user_id: i32, owner: &Vec<u8>, auth_type: AuthType, access_type: Accessibility) -> Self {
        let mut alias: Vec<u8> = Vec::with_capacity(MAX_ALIAS_SIZE as usize);
        alias.extend_from_slice(&user_id.to_le_bytes());
        alias.push(b'_');
        alias.extend(owner);
        alias.push(b'_');
        alias.extend_from_slice(&(auth_type as u32).to_le_bytes());
        alias.push(b'_');
        alias.extend_from_slice(&(access_type as u32).to_le_bytes());
        Self { auth_type, access_type, alias }
    }

    /// Check whether the secret key exists.
    pub fn exists(&self) -> Result<bool, HuksErrcode> {
        let ret = unsafe { KeyExist(self.alias.len() as u32, self.alias.as_ptr()) };
        match ret {
            HKS_SUCCESS => Ok(true),
            HKS_ERROR_NOT_EXIST => Ok(false),
            _ => Err(ret),
        }
    }

    /// Generate the secret key
    pub fn generate(&self) -> Result<(), HuksErrcode> {
        loge!("start to generate key!!!!");
        let ret = unsafe { GenerateKey(self.alias.len() as u32, self.alias.as_ptr()) };
        match ret {
            HKS_SUCCESS => Ok(()),
            _ => Err(ret),
        }
    }

    /// Delete the secret key.
    pub fn delete(&self) -> Result<bool, HuksErrcode> {
        // todo: zdy 不需要bool的返回值
        let ret = unsafe { DeleteKey(self.alias.len() as u32, self.alias.as_ptr()) };
        match ret {
            HKS_SUCCESS => Ok(true),
            _ => Err(ret),
        }
    }

    /// Determine whether user auth is required.
    pub fn need_user_auth(&self) -> bool {
        self.auth_type == AuthType::Any
    }

    /// Determine whether device unlock is required.
    pub fn need_device_unlock(&self) -> bool {
        self.access_type == Accessibility::DeviceUnlock
    }
}

/// Crypto struct
pub struct Crypto {
    /// Crypto secretkey
    key: SecretKey,
    /// crypto mode for crypto
    mode: HksKeyPurpose,
    /// chanllenge from HksInit
    challenge: Vec<u8>,
    /// handle from HksInit
    handle: Vec<u8>,
    /// challege position for huks
    challenge_pos: u32,
    /// timeout time, reserved
    _exp_time: u32,
}

impl Drop for Crypto {
    fn drop(&mut self) {
        // in param
        let data = CryptParam {
            key_len: 0,
            key_data: null(),
            crypto_mode: self.mode,
            aad_len: 0,
            aad: null(),
            data_in_len: 0,
            data_in: null(),
            data_out_len: 0,
            data_out: null(),
            challenge_pos: self.challenge_pos,
            challenge_len: 0,
            challenge_data: null(),
            handle_len: self.handle.len() as u32,
            handle_data: self.handle.as_mut_ptr(),
        };

        let ret =unsafe { DropCrypto(&data as *const CryptParam) };
        match ret {
            HKS_SUCCESS => logi!("crypto drop finish success\n"),
            _ =>  loge!("crypto drop finish failed ret {}", ret),
        }
    }
}

impl Crypto {
    /// New a crypto struct
    pub fn new(mode: HksKeyPurpose, key: SecretKey, challenge_pos: u32, exp_time: u32) -> Self {
        Self { key, mode, challenge: vec![0; CHALLENGE_LEN as usize], handle: vec![0; HANDLE_LEN as usize], challenge_pos, _exp_time: exp_time }
    }

    /// Start HuksInit
    pub fn init_crypto(&mut self) -> Result<(), ErrCode> {
        // in param
        let data = CryptParam {
            key_len: self.key.alias.len() as u32,
            key_data: self.key.alias.as_ptr(),
            crypto_mode: self.mode,
            aad_len: 0,
            aad: null(),
            data_in_len: 0,
            data_in: null(),
            data_out_len: 0,
            data_out: null(),
            challenge_pos: self.challenge_pos,
            challenge_len: self.challenge.len() as u32,
            challenge_data: self.challenge.as_mut_ptr(),
            handle_len: self.handle.len() as u32,
            handle_data: self.handle.as_mut_ptr(),
        };

        let ret =unsafe { InitCryptoWrapper(&data as *const CryptParam) };
        match ret {
            HKS_SUCCESS => Ok(()),
            _ => {
                loge!("crypto init failed ret {}", ret);
                Err(ErrCode::CryptoError)
            },
        }
    }

    /// Exec encrypt or decrypt
    pub fn exec_crypto(&mut self, msg: &Vec<u8>, aad: &Vec<u8>) -> Result<Vec<u8>, ErrCode> {
        // out param
        let mut cipher: Vec<u8> = vec![0; msg.len() + AEAD_SIZE as usize + NONCE_SIZE as usize];
        // in param
        let data = CryptParam {
            key_len: 0,
            key_data: null(),
            crypto_mode: self.mode,
            aad_len: aad.len() as u32,
            aad: aad.as_ptr(),
            data_in_len: msg.len() as u32,
            data_in: msg.as_ptr(),
            data_out_len: cipher.len() as u32,
            data_out: cipher.as_mut_ptr(),
            challenge_pos: self.challenge_pos,
            challenge_len: self.challenge.len() as u32,
            challenge_data: self.challenge.as_mut_ptr(),
            handle_len: self.handle.len() as u32,
            handle_data: self.handle.as_mut_ptr(),
        };

        let ret = unsafe { ExecCryptoWrapper(&data as *const CryptParam) };
        match ret {
            HKS_SUCCESS => Ok(cipher),
            _ => {
                loge!("execute crypto error ret {}", ret);
                Err(ErrCode::CryptoError)
            },
        }
    }

    /// Signle function call for encrypt
    pub fn encrypt(key: &SecretKey, msg: &Vec<u8>, aad: &Vec<u8>) -> Result<Vec<u8>, ErrCode> {
        // out param
        let mut cipher: Vec<u8> = vec![0; msg.len() + AEAD_SIZE as usize]; // todo : zdy 加上nonce的长度
        // in param
        let data = CryptParam {
            key_len: key.alias.len() as u32,
            key_data: key.alias.as_ptr(),
            aad_len: aad.len() as u32,
            aad: aad.as_ptr(),
            data_in_len: msg.len() as u32,
            data_in: msg.as_ptr(),
            data_out_len: cipher.len() as u32,
            data_out: cipher.as_mut_ptr(),
            challenge_pos: 0,
            challenge_len: 0,
            challenge_data: null(),
            crypto_mode: 0,
            handle_len: 0,
            handle_data: null(),
        };

        let ret = unsafe { EncryptWrapper(&data as *const CryptParam) };
        match ret {
            HKS_SUCCESS => Ok(cipher),
            _ => {
                loge!("encrypto error ret {}", ret);
                Err(ErrCode::CryptoError)
            },
        }
    }

    /// Signle function call for decrypt
    pub fn decrypt(key: &SecretKey, cipher: &Vec<u8>, aad: &Vec<u8>) -> Result<Vec<u8>, ErrCode> {
        if cipher.len() <= AEAD_SIZE as usize { // todo : zdy 加上nonce的长度
            loge!("invalid cipher\n");
            return Err(ErrCode::InvalidArgument);
        }
        // out param
        let mut plain: Vec<u8> = vec![0; cipher.len() - AEAD_SIZE as usize]; // todo : zdy 减去nonce的长度
        // in param
        let data = CryptParam {
            key_len: key.alias.len() as u32,
            key_data: key.alias.as_ptr(),
            aad_len: aad.len() as u32,
            aad: aad.as_ptr(),
            data_in_len: cipher.len() as u32,
            data_in: cipher.as_ptr(),
            data_out_len: plain.len() as u32,
            data_out: plain.as_mut_ptr(),
            challenge_pos: 0,
            challenge_len: 0,
            challenge_data: null(),
            crypto_mode: 0,
            handle_len: 0,
            handle_data: null(),
        };

        let ret = unsafe { DecryptWrapper(&data as *const CryptParam) };
        match ret {
            HKS_SUCCESS => Ok(plain),
            _ => {
                loge!("decrypto error ret {}", ret);
                Err(ErrCode::CryptoError)
            },
        }
    }
}

/// Crypto Manager struct
pub struct CryptoManager {
    crypto_vec: Vec<Crypto>,
}

/// default for crypto manager
impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}

/// concurrency is not handlled in these impl, plese handle it
impl CryptoManager {
    /// new crypto manager
    pub fn new() -> Self {
        Self { crypto_vec: vec![] }
    }

    /// add a crypto in manager, not allow insert crypto with same challenge
    pub fn add(&mut self, crypto: Crypto) ->Result<(), ErrCode>{
        for temp_crypto in self.crypto_vec.iter() {
            if crypto.challenge.as_slice() == temp_crypto.challenge.as_slice() {
                loge!("crypto manager not allow insert crypto with same challenge");
                return Err(ErrCode::CryptoError)
            }
        }
        self.crypto_vec.push(crypto);
        Ok(())
    }

    /// remove a crypto in manager
    pub fn remove(&mut self, challenge: &Vec<u8>) {
        for (index, crypto) in self.crypto_vec.iter().enumerate() {
            if challenge.as_slice() == crypto.challenge.as_slice() {
                self.crypto_vec.remove(index);
                break
            }
        }
        loge!("crypto not found\n");
    }

    /// find a crypto in manager, donnot use this function return value with add&remove
    pub fn find(&self, challenge: &Vec<u8>) -> Option<&Crypto> {
        for crypto in self.crypto_vec.iter() {
            if challenge.as_slice() == crypto.challenge.as_slice() {
                return Some(crypto)
            }
        }
        loge!("crypto not found\n");
        None
    }
}