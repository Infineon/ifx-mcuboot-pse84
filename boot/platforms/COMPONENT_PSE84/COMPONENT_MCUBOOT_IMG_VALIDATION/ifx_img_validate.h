/*
 * Copyright (c) (2020-2022), Cypress Semiconductor Corporation (an Infineon company) or
 * an affiliate of Cypress Semiconductor Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
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

#ifndef IFX_IMG_VALIDATE_H
#define IFX_IMG_VALIDATE_H

#include "fault_injection_hardening.h"
#include "crypto.h"
#include "crypto_types.h"
#include "ifx_se_psacrypto.h"

#define BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE PSA_HASH_LENGTH(PSA_ALG_SHA_256)

#define BOOTUTIL_BUILT_IN_KEY_ID_LEN       (1u)

#ifdef MCUBOOT_SIGN_EC256
#define MCUBOOT_PSA_SIGN_KEY_ALG  (PSA_ALG_ECDSA(PSA_ALG_SHA_256))
#define MCUBOOT_PSA_SIGN_KEY_TYPE (PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1))
#define MCUBOOT_PSA_SIGN_KEY_BITS (256u)
#else
#error Unsupported signature type
#endif /* MCUBOOT_SIGN_EC256 */

/** SE RT Services user defined syscall context */
typedef void * ifx_se_context_t;

/**
 * Verifies the EC256 DSA signature.
 * Similar to bootutil_verify_sig(), but with different arguments.
 *
 * @param se_sha256   Active IFX SE hash operation with calculated digest
                      (deactivated on exit).
 * @param sig         Signature in DER format.
 * @param slen        Signature length in bytes.
 * @param key_id      PSA key identifier used for verification.
 *
 * @return            FIH_SUCCESS on success; FIH_FAILURE on failure.
 */
fih_int
bootutil_ifx_se_verify_sig(ifx_se_hash_operation_t *se_sha256,
                           const uint8_t *sig, size_t slen,
                           ifx_se_key_id_fih_t key_id);

/**
 * Verify the integrity of the image.
 * Similar to bootutil_img_validate(), but with different arguments and
 * return value.
 *
 * @param enc_state    Image decryption state.
 * @param image_index  Image index (>=0).
 * @param hdr          Pointer to image header structure.
 * @param fap          Pointer to image's flash area structure.
 * @param tmp_buf      Temporary buffer (to read image in chunks).
 * @param tmp_buf_sz   Size of temporary buffer (i.e., chunk size).
 * @param seed         Initial seed (NULL if not applicable).
 * @param seed_len     Size of initial seed (if seed != NULL).
 *
 * @return             FIH_SUCCESS on successful image validation;
 *                     FIH_FAILURE on failure.
 */
fih_uint
bootutil_ifx_se_img_validate(struct enc_key_data *enc_state, int image_index,
                            struct image_header *hdr,
                            const struct flash_area *fap,
                            uint8_t *tmp_buf, uint32_t tmp_buf_sz,
                            uint8_t *seed, int seed_len);

#endif /* IFX_IMG_VALIDATE_H */
