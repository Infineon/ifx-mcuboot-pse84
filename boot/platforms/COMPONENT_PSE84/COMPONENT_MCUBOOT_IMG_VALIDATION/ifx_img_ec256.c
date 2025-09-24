/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2016-2019 JUUL Labs
 * Copyright (c) 2017 Linaro LTD
 * Copyright (C) 2021 Arm Limited
 * Copyright (c) (2020-2022), Cypress Semiconductor Corporation (an Infineon company) or
 * an affiliate of Cypress Semiconductor Corporation.
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

#include "mcuboot_config.h"
#include "ifx_se_psacrypto.h"

#ifdef MCUBOOT_SIGN_EC256

#include <string.h>
#include <flash_map_backend.h>

#include "image.h"
#include "sign_key.h"

#define IFX_SE_SIG_RS_SIZE  (0x20u)
#define IFX_SIG_DER_PREFIX  (0x30u)
#define IFX_SIG_DER_MARKER  (0x02u)
#define IFX_DER_PREFIX_SIZE (1u)
#define IFX_SIG_LEN_SIZE    (1u)
#define IFX_DER_MARKER_SIZE (1u)
#define IFX_SIG_RS_LEN_SIZE (1u)
#define IFX_MIN_SIG_RS_SIZE (0x1Fu)
#define IFX_MAX_SIG_RS_SIZE (0x21u)
#define IFX_MIN_SIG_SIZE    (2u * (IFX_DER_MARKER_SIZE + \
                                   IFX_SIG_RS_LEN_SIZE + \
                                   IFX_MIN_SIG_RS_SIZE))
#define IFX_MAX_SIG_SIZE    (2u * (IFX_DER_MARKER_SIZE + \
                                   IFX_SIG_RS_LEN_SIZE + \
                                   IFX_MAX_SIG_RS_SIZE))
#define IFX_SE_PSA_SIG_SIZE (2u * IFX_SE_SIG_RS_SIZE)

/**
 * Converts the EC256 DSA signature from DER to PSA format.
 *
 * @param sign_in   Input buffer with signature in DER format.
 * @param in_size   Input buffer size in bytes.
 * @param sign_out  Output buffer for signature in PSA format.
 * @param out_size  Output buffer size in bytes.
 *
 * @return          FIH_SUCCESS on success; FIH_FAILURE on failure.
 */
static fih_int
signature_der_to_psa(const uint8_t *sign_in, size_t in_size,
                     uint8_t *sign_out, size_t out_size)
{
    fih_int fih_rc = FIH_FAILURE;

    /* DER signature representation
     *
     * 0x30 - DER prefix
     * 0xXX - Length of rest of Signature
     * 0x02 - Marker for r value
     * 0x21 - Length of r value (0x1F - 0x21)
     * XXXX...XX - r value, Big Endian
     * 0x02 - Marker for s value
     * 0x21 - Length of s value (0x1F - 0x21)
     * XXXX...XX - s value, Big Endian
     */
    size_t r_len    = 0u;
    size_t s_len    = 0u;
    size_t r_offset = 0u;
    size_t s_offset = 0u;
    size_t sign_idx = 0u;
    size_t sign_len = 0u;

    /* Check output buffer size, input length and prefix */
    if (out_size >= IFX_SE_PSA_SIG_SIZE &&
        in_size >= IFX_DER_PREFIX_SIZE + IFX_SIG_LEN_SIZE + IFX_MIN_SIG_SIZE &&
        IFX_SIG_DER_PREFIX == sign_in[sign_idx]) {
        sign_idx++;

        sign_len = sign_in[sign_idx];

        /* Check signature length */
        if (sign_len <= IFX_MAX_SIG_SIZE) {
            sign_idx++;

            (void)memset(sign_out, 0x00, IFX_SE_PSA_SIG_SIZE);

            /* Check r-marker */
            if (IFX_SIG_DER_MARKER == sign_in[sign_idx]) {
                sign_idx++;

                r_len = sign_in[sign_idx];
                sign_idx++;

                r_offset = sign_idx;
                sign_idx += r_len;

                /* Check s-marker */
                if (IFX_SIG_DER_MARKER == sign_in[sign_idx]) {
                    sign_idx++;

                    s_len = sign_in[sign_idx];
                    sign_idx++;

                    s_offset = sign_idx;

                    /* Check TLV length,
                     * check R and S size with optional trailing zero
                     */
                    if ((IFX_DER_MARKER_SIZE + IFX_SIG_RS_LEN_SIZE + r_len +
                        IFX_DER_MARKER_SIZE + IFX_SIG_RS_LEN_SIZE + s_len) == sign_len) {
                        /* ASN.1 signature representation
                        *
                        * ECDSASignature ::= SEQUENCE
                        * {
                        *      r   INTEGER,
                        *      s   INTEGER
                        * }
                        */
                        if (r_len > IFX_SE_SIG_RS_SIZE) {
                            r_offset += r_len - IFX_SE_SIG_RS_SIZE;
                            r_len = IFX_SE_SIG_RS_SIZE;	
                        }

                        if (s_len > IFX_SE_SIG_RS_SIZE) {
                            s_offset += s_len - IFX_SE_SIG_RS_SIZE;
                            s_len = IFX_SE_SIG_RS_SIZE;
                        }

                        (void)memcpy(sign_out + IFX_SE_SIG_RS_SIZE - r_len,
                                    sign_in + r_offset, r_len);

                        (void)memcpy(sign_out + IFX_SE_PSA_SIG_SIZE - s_len,
                                    sign_in + s_offset, s_len);

                        fih_rc = FIH_SUCCESS;
                    }
                }
            }
        }
    }

    FIH_RET(fih_rc);
}

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
                           ifx_se_key_id_fih_t key_id)
{
    uint8_t signature[IFX_SE_PSA_SIG_SIZE];
    ifx_se_fih_ptr_t sig_addr_fih = ifx_se_fih_ptr_encode(signature);
    ifx_se_fih_t sig_size_fih = ifx_se_fih_uint_encode(sizeof(signature));
    fih_int fih_rc = FIH_FAILURE;
    fih_int der_to_psa_status = FIH_FAILURE;
    ifx_se_status_t se_status_finish = IFX_SE_INVALID;
    ifx_se_status_t se_status_verify = IFX_SE_INVALID;

    FIH_CALL(signature_der_to_psa, der_to_psa_status, sig, slen, \
             signature, sizeof(signature));
    if (fih_eq(der_to_psa_status, FIH_SUCCESS)) {
        uint8_t hash[IFX_SE_HASH_LENGTH(IFX_SE_ALG_SHA_256)];
        ifx_se_fih_ptr_t hash_addr_fih = ifx_se_fih_ptr_encode(hash);
        ifx_se_fih_t hash_size_fih = ifx_se_fih_uint_encode(sizeof(hash));
        size_t hash_length = 0u;

        se_status_finish = ifx_se_hash_finish(se_sha256,
                                              hash_addr_fih,
                                              hash_size_fih,
                                              ifx_se_fih_ptr_encode(&hash_length),
                                              IFX_SE_NULL_CTX);

        if (ifx_se_fih_uint_eq(IFX_SE_SUCCESS, se_status_finish)) {
            if (sizeof(hash) != hash_length) {
                /* Should not get here */
                (void)ifx_se_destroy_key(key_id, IFX_SE_NULL_CTX);
                (void)ifx_se_hash_abort(se_sha256, IFX_SE_NULL_CTX);
                FIH_PANIC;
            }

            se_status_verify = ifx_se_verify_hash(key_id,
                                                  ifx_se_fih_uint_encode(IFX_SE_ALG_ECDSA(IFX_SE_ALG_SHA_256)),
                                                  hash_addr_fih,
                                                  hash_size_fih,
                                                  sig_addr_fih,
                                                  sig_size_fih,
                                                  IFX_SE_NULL_CTX);
        }

        (void)memset(hash, 0x00, sizeof(hash));
    }

    (void)memset(signature, 0x00, sizeof(signature));

    fih_rc = FIH_FAILURE;

    if (ifx_se_fih_uint_eq(IFX_SE_SUCCESS, se_status_finish)) {
        if (ifx_se_fih_uint_eq(IFX_SE_SUCCESS, se_status_verify))
        {
            fih_rc = FIH_SUCCESS;
        }
        else
        {
            fih_rc = FIH_FAILURE;
        }
    }
    else
    {
        fih_rc = FIH_FAILURE;
    }

    FIH_RET(fih_rc);
}

#endif /* MCUBOOT_SIGN_EC256 */
