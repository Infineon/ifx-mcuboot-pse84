/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2018-2019 JUUL Labs
 * Copyright (c) 2019 Arm Limited
 * Copyright (c) 2019-2025 Cypress Semiconductor Corporation (an Infineon company)
 *
 * Original license:
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef BOOTUTIL_ENC_KEY_H
#define BOOTUTIL_ENC_KEY_H

#include <stdbool.h>
#include <stdint.h>
#include <flash_map_backend.h>
#include "crypto/aes_ctr.h"
#include "image.h"
#include "enc_key_public.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BOOT_ENC_TLV_ALIGN_SIZE ALIGN_UP(BOOT_ENC_TLV_SIZE, BOOT_MAX_ALIGN)

#if defined(MCUBOOT_USE_ENC_IFX_SE)
#define IFX_ENC_BLOCK_SIZE                              (16 * 1024) 
#endif /* MCUBOOT_USE_ENC_IFX_SE */

struct enc_key_data {
    uint8_t valid;
    uint8_t aes_iv[BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE];
#if defined(MCUBOOT_USE_ENC_IFX_SE)
    ifx_aes_ctr_context aes_ctr;
#else
    bootutil_aes_ctr_context aes_ctr;
#endif /* MCUBOOT_USE_ENC_IFX_SE */
};

extern const struct bootutil_key bootutil_enc_key;
struct boot_status;

int boot_enc_init(struct enc_key_data *enc_state, uint8_t slot);
int boot_enc_drop(struct enc_key_data *enc_state, uint8_t slot);
#if defined(MCUBOOT_USE_ENC_IFX_SE)
int boot_enc_set_key(struct enc_key_data *enc_state, uint8_t slot,
        struct boot_status *bs);
#else
int boot_enc_set_key(struct enc_key_data *enc_state, uint8_t slot,
        const struct boot_status *bs);
#endif /* MCUBOOT_USE_ENC_IFX_SE */
int boot_enc_load(struct enc_key_data *enc_state, int image_index,
        const struct image_header *hdr, const struct flash_area *fap,
        struct boot_status *bs);
#if defined(MCUBOOT_USE_ENC_IFX_SE)
int boot_enc_decrypt(ifx_aes_ctr_context* ctx, const uint8_t *buf, uint8_t *enckey,
        uint32_t sz, uint8_t *enciv);
#else
int boot_enc_decrypt(const uint8_t *buf, uint8_t *enckey, uint32_t sz, uint8_t *enciv);
#endif /* MCUBOOT_USE_ENC_IFX_SE */
bool boot_enc_valid(struct enc_key_data *enc_state, int image_index,
        const struct flash_area *fap);
int boot_encrypt(struct enc_key_data *enc_state, int image_index,
        const struct flash_area *fap, uint32_t off, uint32_t sz,
        uint32_t blk_off, uint8_t *buf);
#ifdef MCUBOOT_ENC_IMAGES_XIP
int bootutil_img_encrypt(struct enc_key_data *enc_state, int image_index,
        struct image_header *hdr, const struct flash_area *fap, uint32_t off, uint32_t sz,
        uint32_t blk_off, uint8_t *buf);
#endif /* MCUBOOT_ENC_IMAGES_XIP */
void boot_enc_zeroize(struct enc_key_data *enc_state);

#ifdef __cplusplus
}
#endif

#endif /* BOOTUTIL_ENC_KEY_H */
