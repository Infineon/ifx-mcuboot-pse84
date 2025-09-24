/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) (2020-2024), Cypress Semiconductor Corporation (an Infineon company) or
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

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include <flash_map_backend.h>

#include "image.h"
#include "sign_key.h"
#include "security_cnt.h"
#include "bootutil_log.h"

#include "crypto.h"
#include "crypto_values.h"
#include "crypto_platform.h"
#include "platform_alt.h"

/* rnok: Present in ifx-mbedtls, delete after switch */
/** The storage area located inside IFX SE Runtime Services */
#define PSA_KEY_LOCATION_IFX_SE                     ((psa_key_location_t)0x800001)


#include "ifx_img_validate.h"

#ifdef MCUBOOT_ENC_IMAGES
#include "enc_key.h"
#if defined(MCUBOOT_ENC_IMAGES_XIP_MULTI) || defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY)
#include "xip_encryption.h"
#endif /* defined(MCUBOOT_ENC_IMAGES_XIP_MULTI) || defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY) */
#endif /* MCUBOOT_ENC_IMAGES */

#ifdef MCUBOOT_SIGN_EC256

#if defined(MCUBOOT_SIGN_RSA) || \
    defined(MCUBOOT_SIGN_EC)  || \
    defined(MCUBOOT_SIGN_ED25519)
#error "Only a single signature type is supported!"
#endif /* defined(MCUBOOT_SIGN_RSA) ||
          defined(MCUBOOT_SIGN_EC)  ||
          defined(MCUBOOT_SIGN_ED25519) */

#define SIG_TLV_EXPECTED    IMAGE_TLV_ECDSA256
#define SIG_BUF_SIZE        128u
#define SIG_LEN_EXPECTED(x) (true) /* always, ASN.1 will validate */

#else
#error "Unsupported signature type"
#endif /* MCUBOOT_SIGN_EC256 */

#include "bootutil_priv.h"

/* Complex result masks for bootutil_psa_img_validate() */
#define IFX_SET_MASK_IMAGE_TLV_SHA256    0x0000002Eu
fih_uint IFX_FIH_MASK_IMAGE_TLV_SHA256 = FIH_UINT_INIT_GLOBAL(
        IFX_SET_MASK_IMAGE_TLV_SHA256);

#define IFX_SET_MASK_SIG_TLV_EXPECTED    0x00007400u
fih_uint IFX_FIH_MASK_SIG_TLV_EXPECTED = FIH_UINT_INIT_GLOBAL(
        IFX_SET_MASK_SIG_TLV_EXPECTED);

#define IFX_SET_MASK_IMAGE_TLV_SEC_CNT   0x005C0000u
fih_uint IFX_FIH_MASK_IMAGE_TLV_SEC_CNT = FIH_UINT_INIT_GLOBAL(
        IFX_SET_MASK_IMAGE_TLV_SEC_CNT);

#if defined MCUBOOT_SKIP_VALIDATE_SECONDARY_SLOT
#if defined MCUBOOT_VALIDATE_PRIMARY_SLOT
#error Boot slot validation cannot be enabled if upgrade slot validation is disabled
#endif
#endif

#define IFX_CHK_MASK_IMAGE_TLV_SHA256                   IFX_SET_MASK_IMAGE_TLV_SHA256

#if defined(MCUBOOT_SIGN_RSA)   || \
    defined(MCUBOOT_SIGN_EC)    || \
    defined(MCUBOOT_SIGN_EC256) || \
    defined(MCUBOOT_SIGN_ED25519)

    #if defined MCUBOOT_SKIP_VALIDATE_SECONDARY_SLOT
    #define IFX_CHK_MASK_SIG_TLV_EXPECTED               0u
    #else
    #define IFX_CHK_MASK_SIG_TLV_EXPECTED               IFX_SET_MASK_SIG_TLV_EXPECTED
    #endif /* MCUBOOT_SKIP_VALIDATE_SECONDARY_SLOT */
#else
#define IFX_CHK_MASK_SIG_TLV_EXPECTED                   0u
#endif /* defined(MCUBOOT_SIGN_RSA)   ||
          defined(MCUBOOT_SIGN_EC)    ||
          defined(MCUBOOT_SIGN_EC256) ||
          defined(MCUBOOT_SIGN_ED25519) */

#ifdef MCUBOOT_HW_ROLLBACK_PROT
#define IFX_CHK_MASK_IMAGE_TLV_SEC_CNT                  IFX_SET_MASK_IMAGE_TLV_SEC_CNT
#else
#define IFX_CHK_MASK_IMAGE_TLV_SEC_CNT                  0u
#endif /* MCUBOOT_HW_ROLLBACK_PROT */

fih_uint IFX_FIH_IMG_VALIDATE_COMPLEX_OK = FIH_UINT_INIT_GLOBAL( \
    IFX_CHK_MASK_IMAGE_TLV_SHA256  |                      \
    IFX_CHK_MASK_SIG_TLV_EXPECTED  |                      \
    IFX_CHK_MASK_IMAGE_TLV_SEC_CNT);

#undef IFX_SET_MASK_IMAGE_TLV_SHA256
#undef IFX_SET_MASK_SIG_TLV_EXPECTED
#undef IFX_SET_MASK_IMAGE_TLV_SEC_CNT

#undef IFX_CHK_MASK_IMAGE_TLV_SHA256
#undef IFX_CHK_MASK_SIG_TLV_EXPECTED
#undef IFX_CHK_MASK_IMAGE_TLV_SEC_CNT

#define PUB_KEY_SIZE_EC256 (1u+0x20u+0x20u)
#define PUB_KEY_DIGEST_SIZE_EC256 (0x20)

/**
 * Compute SHA256 over the image.
 *
 * @param psa_sha256   Initialized PSA hash operation with calculated digest
 *                     (active on exit).
 * @param enc_state    Image decryption state.
 * @param image_index  Image index (>=0).
 * @param hdr          Pointer to image header structure.
 * @param fap          Pointer to image's flash area structure.
 * @param tmp_buf      Temporary buffer (to read image in chunks).
 * @param tmp_buf_sz   Size of temporary buffer (i.e., chunk size).
 * @param seed         Initial seed (NULL if not applicable).
 * @param seed_len     Size of initial seed (if seed != NULL).
 *
 * @return             FIH_SUCCESS on success; FIH_FAILURE on failure.
 */
static fih_int
bootutil_ifx_se_img_hash(ifx_se_hash_operation_t *se_sha256,
                         struct enc_key_data *enc_state, int image_index,
                         const struct image_header *hdr,
                         const struct flash_area *fap,
                         uint8_t *tmp_buf, uint32_t tmp_buf_sz,
                         const uint8_t *seed, size_t seed_len)
{
    uint32_t blk_sz = 0u;
    uint32_t size = 0u;
    uint16_t hdr_size = 0u;
    uint32_t off = 0u;
    uint32_t blk_off = 0u;
    uint32_t tlv_off = 0u;

    ifx_se_status_t se_status = IFX_SE_INVALID;
    fih_int fih_rc = FIH_FAILURE;

#if (BOOT_IMAGE_NUMBER == 1) || \
    !defined(MCUBOOT_ENC_IMAGES) || defined(MCUBOOT_RAM_LOAD)
    (void)enc_state;
    (void)image_index;
    (void)hdr_size;
    (void)blk_off;
    (void)tlv_off;
#ifdef MCUBOOT_RAM_LOAD
    (void)blk_sz;
    (void)off;
    (void)fap;
    (void)tmp_buf;
    (void)tmp_buf_sz;
#endif /* MCUBOOT_RAM_LOAD */
#endif /* (BOOT_IMAGE_NUMBER == 1) ||
          !defined(MCUBOOT_ENC_IMAGES) || defined(MCUBOOT_RAM_LOAD) */

#if defined(MCUBOOT_ENC_IMAGES_XIP_MULTI) || defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY)
    (void)blk_off;
#endif /* defined(MCUBOOT_ENC_IMAGES_XIP_MULTI) || defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY) */

#ifdef MCUBOOT_ENC_IMAGES
    /* Encrypted images only exist in the secondary slot */
    if ((MUST_DECRYPT(fap, (uint32_t)image_index, hdr) &&
                             !boot_enc_valid(enc_state, image_index, fap)))
    {
        goto out;
    }
#endif /* MCUBOOT_ENC_IMAGES */

    se_status = ifx_se_hash_setup(se_sha256, 
                                  ifx_se_fih_uint_encode(IFX_SE_ALG_SHA_256), 
                                  IFX_SE_NULL_CTX);

    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, se_status)) {
        goto out;
    }

    /* In some cases (split image) the hash is seeded with data from
        * the loader image */
    if (seed != NULL && seed_len > 0u) {
        se_status = ifx_se_hash_update(se_sha256, ifx_se_fih_ptr_encode(seed),
                                     ifx_se_fih_uint_encode(seed_len), 
                                     IFX_SE_NULL_CTX);
    }

    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, se_status)) {
        goto out;
    }

    /* Hash is computed over image header and image itself. */
    size = hdr_size = hdr->ih_hdr_size;

    if (size <= UINT32_MAX - hdr->ih_img_size)
    {
        size += hdr->ih_img_size;
        tlv_off = size;

        /* If protected TLVs are present they are also hashed. */
        if (size <= UINT32_MAX - hdr->ih_protect_tlv_size)
        {
            size += hdr->ih_protect_tlv_size;
            if ((tmp_buf != NULL) && (tmp_buf_sz > 0U))
            {
                while (off < size)
                {
                    blk_sz = size - off;

                    if (blk_sz > tmp_buf_sz)
                    {
                        blk_sz = tmp_buf_sz;
                    }
#ifdef MCUBOOT_ENC_IMAGES
                    /* The only data that is encrypted in an image is
                     * the payload;
                     * both header and TLVs (when protected) are not.
                     */
                    if ((off < hdr_size) &&
                        ((off + blk_sz) > hdr_size))
                    {
                        /* read only the header */
                        blk_sz = hdr_size - off;
                    }

                    if ((off < tlv_off) &&
                        ((off + blk_sz) > tlv_off))
                    {
                        /* Read only up to the end of the image
                         * payload
                         */
                        blk_sz = tlv_off - off;
                    }
#endif /* MCUBOOT_ENC_IMAGES */
                    if (0 == flash_area_read(fap, off, tmp_buf, blk_sz))
                    {
#ifdef MCUBOOT_ENC_IMAGES
                        if (MUST_DECRYPT(fap, (uint32_t)image_index, hdr))
                        {
                            /* Only payload is encrypted (area between
                             * header and TLVs)
                             */
                            if (off >= hdr_size && off < tlv_off)
                            {
#if defined(MCUBOOT_ENC_IMAGES_XIP_MULTI) || defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY)
                                (void)boot_decrypt_xip(image_index, fap, off, blk_sz, tmp_buf);
#else
                                blk_off = (off - hdr_size) & 0xFu;
                                (void)boot_encrypt(
                                    enc_state, image_index,
                                    fap, off - hdr_size,
                                    blk_sz, blk_off, tmp_buf);
#endif /* defined(MCUBOOT_ENC_IMAGES_XIP_MULTI) || defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY) */
                            }
                        }
#endif /* MCUBOOT_ENC_IMAGES */
                    }
                    else
                    {
                        se_status = IFX_SE_SYSCALL_DATA_INVALID;
                        break;
                    }

                    if (ifx_se_fih_uint_eq(IFX_SE_SUCCESS, se_status))
                    {
                        se_status = ifx_se_hash_update(se_sha256, 
                                                       ifx_se_fih_ptr_encode(tmp_buf),
                                                       ifx_se_fih_uint_encode(blk_sz), 
                                                       IFX_SE_NULL_CTX);
                    }

                    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, se_status))
                    {
                        break;
                    }

                    off += blk_sz;
                }
            }
        }
    }

out:
    if (ifx_se_fih_uint_eq(IFX_SE_SUCCESS, se_status))
    {
        fih_rc = FIH_SUCCESS;
    }

    FIH_RET(fih_rc);
}

#if defined(SIG_TLV_EXPECTED)
#ifndef MCUBOOT_HW_KEY
/* NOTE: To be revised when doing FWSECURITY-2766/2767
 *
 * A EC256 public key is represented as:
 * - The byte 0x04;
 * - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
 * - `y_P` as a `ceiling(m/8)`-byte string, big-endian.
 * So its data length is 2m+1 where m is the curve size.
 */
static ifx_se_key_id_fih_t
ifx_se_bootutil_find_key(const uint8_t *data, uint16_t len,
    const uint8_t *copy_data, uint16_t copy_len)
{
    (void)len;
    (void)copy_len;
    ifx_se_key_id_fih_t key_id = {0};
    ifx_se_fih_uint owner = IFX_SE_FIH_UINT_INIT(0U);
    ifx_se_fih_uint id = IFX_SE_FIH_UINT_INIT(0U);

    /* Read key id from data */
    id.val = atoi((const char8 *)data) + IFX_SE_KEY_ID_BUILTIN_MIN;
    /* Read key id from copy data and use it to create FIH mask */
    id.msk = IFX_SE_FIH_VAL_MASK(atoi((const char8 *)copy_data) + IFX_SE_KEY_ID_BUILTIN_MIN);

    key_id = ifx_se_key_id_make(owner, id);

    return key_id;
}

#else

#define PUB_KEY_HASH_HANDLE 0x87u

/**
 * Helper function for importing public key data - plain or hash to a key storage
 *
 * @param key          Pointer to ECDSA public key in ANS1 format
 * @param key_len      Key length
 *
 * @return key_id      Imported key id
 */
static mbedtls_svc_key_id_t import_ecdsa_pub_key_data(const uint8_t *key, uint16_t key_len)
{
    mbedtls_svc_key_id_t key_id = mbedtls_svc_key_id_make(0, PSA_KEY_ID_NULL);
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;

    psa_status = psa_crypto_init();

    const uint8_t * asn1_key_body_start = key + key_len - PUB_KEY_SIZE_EC256;

    psa_key_attributes_t attrs = psa_key_attributes_init();

    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs,
                            MCUBOOT_PSA_SIGN_KEY_ALG);
    psa_set_key_type(&attrs,
                        MCUBOOT_PSA_SIGN_KEY_TYPE);
    psa_set_key_bits(&attrs,
                        MCUBOOT_PSA_SIGN_KEY_BITS);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
                            PSA_KEY_PERSISTENCE_VOLATILE, PSA_KEY_LOCATION_IFX_SE));


    psa_status = psa_import_key(&attrs,
            asn1_key_body_start, PUB_KEY_SIZE_EC256,
            &key_id);
    if (PSA_SUCCESS == psa_status) {
        psa_reset_key_attributes(&attrs);

        if (psa_status != PSA_SUCCESS) {
            key_id = mbedtls_svc_key_id_make(0, PSA_KEY_ID_NULL);
        }
    }
    else {
        /* do nothing*/
    }

    return key_id;
}

/**
 * Retrieve the hash of the corresponding public key for image authentication.
 *
 * @param[in]      image_index      Index of the image to be authenticated.
 * @param[out]     public_key_hash  Buffer to store the key-hash in.
 * @param[in,out]  key_hash_size    As input the size of the buffer. As output
 *                                  the actual key-hash length.
 *
 * @return                          0 on success; nonzero on failure.
 */
int boot_retrieve_public_key_hash(uint8_t image_index,
                                  uint8_t *public_key_hash,
                                  size_t *key_hash_size)
{
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    size_t keySize;
    mbedtls_svc_key_id_t key_id = mbedtls_svc_key_id_make(0, PUB_KEY_HASH_HANDLE);
    static uint8_t pub_key_hash_exported = 0;

    uint8_t ecc_pub_key_hash[32] =
    {0xBB, 0x86, 0x8A, 0x72, 0x7F, 0x0E, 0xF7, 0x5E,
    0x89, 0x0A, 0x6A, 0x52, 0xBC, 0xCD, 0x1D, 0x93,
    0x6F, 0xB3, 0x44, 0x38, 0xAF, 0xD6, 0xF2, 0x37,
    0xE8, 0xAF, 0x25, 0x98, 0x65, 0x74, 0x24, 0x46};

    (void)image_index;

    if (pub_key_hash_exported == 0) {

        /* lets first import public key hash to key storage */
        psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_id(&attrs, key_id);
        psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);
        psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
        psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
        psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
                                PSA_KEY_PERSISTENCE_VOLATILE, PSA_KEY_LOCATION_IFX_SE));

        psa_status = psa_import_key(&attrs, ecc_pub_key_hash,
                                    sizeof(ecc_pub_key_hash), &key_id);

        psa_reset_key_attributes(&attrs);

        if (PSA_SUCCESS != psa_status) {
            key_id = mbedtls_svc_key_id_make(0, PSA_KEY_ID_NULL);
        }
        else {
            BOOT_LOG_DBG("[MCUBOOT_HW_KEY] Public key hash imported to persistent storage with key id %u", (uint32_t)key_id);
        }

        pub_key_hash_exported = 1;
    }
    else {
        /* do nothing */
    }

    /* then try to export it back */
    psa_status = PSA_ERROR_GENERIC_ERROR;
    psa_status = psa_export_key(key_id, public_key_hash, *key_hash_size, &keySize);

    if (PSA_SUCCESS == psa_status) {
        BOOT_LOG_DBG("[MCUBOOT_HW_KEY] Public key hash exported from persistent storage by key id %u", (uint32_t)key_id);
    }
    else {
        BOOT_LOG_DBG("[MCUBOOT_HW_KEY] ERROR: Public key hash does not exported from persistent storage by key id %u", (uint32_t)key_id);
    }

    return 0;
}

extern unsigned int pub_key_len;

static mbedtls_svc_key_id_t
bootutil_find_key(uint8_t image_index, uint8_t *key, uint16_t key_len)
{
    (void)image_index;
    (void)key;
    (void)key_len;
    uint8_t hash[BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE];
    uint8_t key_hash[BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE];
    size_t hash_size = sizeof(hash);
    size_t key_hash_size = sizeof(key_hash);
    size_t hash_lenght;
    mbedtls_svc_key_id_t key_id = mbedtls_svc_key_id_make(0, PSA_KEY_ID_NULL);
    int rc = -1;

    fih_int fih_rc = FIH_INT_INIT(FIH_FALSE);
    psa_hash_operation_t psa_sha256 = PSA_HASH_OPERATION_INIT;
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;

    psa_status = psa_hash_setup(&psa_sha256, PSA_ALG_SHA_256);

    if (PSA_SUCCESS == psa_status) {
        psa_status = PSA_ERROR_GENERIC_ERROR;
        psa_status = psa_hash_update(&psa_sha256, key, key_len);
    }

    if (PSA_SUCCESS == psa_status) {
        psa_status = PSA_ERROR_GENERIC_ERROR;
        psa_status = psa_hash_finish(&psa_sha256, hash, hash_size, &hash_lenght);
    }

    if (PSA_SUCCESS == psa_status) {
        rc = boot_retrieve_public_key_hash(image_index, key_hash, &key_hash_size);
        if (rc != 0) {
            return PSA_KEY_ID_NULL;
        }
    }
    else {
        return PSA_KEY_ID_NULL;
    }

    /* Adding hardening to avoid this potential attack:
    *  - Image is signed with an arbitrary key and the corresponding public
    *    key is added as a TLV field.
    * - During public key validation (comparing against key-hash read from
    *   HW) a fault is injected to accept the public key as valid one.
    */
    FIH_CALL(boot_fih_memequal, fih_rc, hash, key_hash, key_hash_size);
    if (fih_eq(fih_rc, FIH_SUCCESS)) {
        bootutil_keys[0].key = key;
        pub_key_len = key_len;
        BOOT_LOG_DBG("[MCUBOOT_HW_KEY] Public key hashes compared equal, set store key to bootutil_keys[0]");
        key_id = import_ecdsa_pub_key_data(key, key_len);
     }

    return key_id;
}

#endif /* !MCUBOOT_HW_KEY */
#endif /* SIG_TLV_EXPECTED */

#ifdef MCUBOOT_HW_ROLLBACK_PROT
/**
 * Reads the value of an image's security counter.
 *
 * @param hdr           Pointer to the image header structure.
 * @param fap           Pointer to a description structure of the image's
 *                      flash area.
 * @param off           Offset of the security counter data.
 * @param len           Length of the security counter data.
 * @param security_cnt  Pointer to store the security counter value.
 *
 * @return              FIH_SUCCESS on success; FIH_FAILURE on failure.
 */
static fih_int
bootutil_ifx_se_read_img_sec_cnt(struct image_header *hdr,
                                 const struct flash_area *fap,
                                 uint32_t off,
                                 uint16_t len,
                                 fih_uint *img_security_cnt)
{
    uint32_t img_sec_cnt = 0u;
    fih_int fih_rc = FIH_FAILURE;

    if (len == sizeof(img_sec_cnt)) {
        int32_t rc = LOAD_IMAGE_DATA(hdr, fap, off, &img_sec_cnt, len);
        if (rc == 0) {

            uint32_t img_chk_cnt = 0u;

            *img_security_cnt = fih_uint_encode(img_sec_cnt);

            rc = LOAD_IMAGE_DATA(hdr, fap, off, &img_chk_cnt, len);
            if (rc == 0 && fih_uint_eq(fih_uint_encode(img_chk_cnt), *img_security_cnt)) {

                    fih_rc = fih_int_encode_zero_equality(
                                        (int32_t)(img_sec_cnt ^ img_chk_cnt));
            }
        }
    }
    else {
        (void)hdr;

    }

    FIH_RET(fih_rc);
}

/**
 * Reads the value of an image's security counter.
 *
 * @param hdr           Pointer to the image header structure.
 * @param fap           Pointer to a description structure of the image's
 *                      flash area.
 * @param security_cnt  Pointer to store the security counter value.
 *
 * @return              FIH_SUCCESS on success; FIH_FAILURE on failure.
 */
fih_int
bootutil_get_img_security_cnt(struct image_header *hdr,
                              const struct flash_area *fap,
                              fih_uint *img_security_cnt)
{
    struct image_tlv_iter it = {0};
    uint32_t off = 0u;
    uint16_t len = 0u;
    int32_t rc = -1;
    fih_int fih_rc = FIH_FAILURE;

    if ((NULL == hdr) ||
        (NULL == fap) ||
        (NULL == img_security_cnt)) {
        /* Invalid parameter. */
        goto out;
    }

    /* The security counter TLV is in the protected part of the TLV area. */
    if (0u == hdr->ih_protect_tlv_size) {
        goto out;
    }

    rc = bootutil_tlv_iter_begin(&it, hdr, fap, IMAGE_TLV_SEC_CNT, true);
    if (rc != 0) {
        goto out;
    }

    /* Traverse through the protected TLV area to find
     * the security counter TLV.
     */

    rc = bootutil_tlv_iter_next(&it, &off, &len, NULL);
    if (rc != 0) {
        /* Security counter TLV has not been found. */
        goto out;
    }

    FIH_CALL(bootutil_ifx_se_read_img_sec_cnt, fih_rc,
             hdr, fap, off, len, img_security_cnt);

out:
    FIH_RET(fih_rc);
}
#endif /* MCUBOOT_HW_ROLLBACK_PROT */

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
                             uint8_t *seed, int seed_len)
{
    ifx_se_hash_operation_t se_sha256 = IFX_SE_HASH_OPERATION_INIT;
    ifx_se_status_t se_hash_clone_status= IFX_SE_INVALID;
    ifx_se_status_t se_hash_verify_status = IFX_SE_INVALID;
    ifx_se_key_id_fih_t se_key_id = {0};
    uint32_t off = 0u;
    uint16_t len = 0u;
    uint16_t type = 0u;
#ifdef SIG_TLV_EXPECTED
#ifdef MCUBOOT_HW_KEY
    /* Few extra bytes for encoding and for public exponent. */
    uint8_t key_buf[SIG_BUF_SIZE + 24u];
    mbedtls_svc_key_id_t key_id = mbedtls_svc_key_id_make(0, PSA_KEY_ID_NULL);
#endif

    uint8_t buf[SIG_BUF_SIZE];
    uint16_t copy_len = 0u;
    uint8_t copy_buf[SIG_BUF_SIZE];
#endif /* SIG_TLV_EXPECTED */
    struct image_tlv_iter it = {0};
    fih_int fih_rc = FIH_FAILURE;
    /* fih_complex_result stores patterns of successful execution
     * of required checks
     */
    fih_uint fih_complex_result = FIH_UINT_ZERO;
#ifdef MCUBOOT_HW_ROLLBACK_PROT
    fih_uint security_cnt = FIH_UINT_MAX;
    fih_uint img_security_cnt = FIH_UINT_ZERO;
#endif /* MCUBOOT_HW_ROLLBACK_PROT */

    if (NULL == hdr || NULL == fap || seed_len < 0) {
        goto out;
    }

    FIH_CALL(bootutil_ifx_se_img_hash, fih_rc, &se_sha256, \
             enc_state, image_index, hdr, fap,              \
             tmp_buf, tmp_buf_sz, seed, (size_t)seed_len);
    if (!fih_eq(fih_rc, FIH_SUCCESS)) {
        goto out;
    }

    if (bootutil_tlv_iter_begin(&it, hdr, fap, IMAGE_TLV_ANY, false) != 0) {
        goto out;
    }

    /*
     * Traverse through all of the TLVs, performing any checks we know
     * and are able to do.
     */
    while (true) {
        int rc = bootutil_tlv_iter_next(&it, &off, &len, &type);
        if (rc < 0) {
            goto out;
        } else if (rc > 0) {
            break;
        } else if ((uint16_t)IMAGE_TLV_SHA256 == type) {
            /*
             * Verify the SHA256 image hash.  This must always be
             * present.
             */
            ifx_se_hash_operation_t se_sha256_temp = IFX_SE_HASH_OPERATION_INIT;

            if ((uint16_t)BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE != len) {
                goto out;
            }

            if (LOAD_IMAGE_DATA(hdr, fap, off, buf, len) != 0) {
                goto out;
            }

            /* Need a clone, since ifx_se_hash_verify() inactivates
             * the se_sha256
             */
            se_hash_clone_status = ifx_se_hash_clone(&se_sha256, &se_sha256_temp, IFX_SE_NULL_CTX);
            if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, se_hash_clone_status)) {
                goto out;
            }

            se_hash_verify_status = ifx_se_hash_verify(&se_sha256_temp, ifx_se_fih_ptr_encode(buf),
                                                    ifx_se_fih_uint_encode(len), IFX_SE_NULL_CTX);

            if (ifx_se_fih_uint_eq(IFX_SE_SUCCESS, se_hash_verify_status)) {
                if (ifx_se_fih_uint_eq(IFX_SE_SUCCESS, se_hash_clone_status)) {
                    /* Encode succesful completion pattern to complex_result */
                    fih_complex_result = fih_uint_or(fih_complex_result,
                                                     IFX_FIH_MASK_IMAGE_TLV_SHA256);
                }
            }

            if (fih_uint_not_eq(fih_uint_and(fih_complex_result, IFX_FIH_MASK_IMAGE_TLV_SHA256), IFX_FIH_MASK_IMAGE_TLV_SHA256))
            {
                BOOT_LOG_DBG(" * Invalid SHA256 digest of bootable image %d",
                             image_index);
                goto out;
            }
#ifdef SIG_TLV_EXPECTED
#ifndef MCUBOOT_HW_KEY
#ifdef MCUBOOT_BUILT_IN_KEYS
        } else if ((uint16_t)IMAGE_TLV_BUILT_IN_KEY_ID == type) {
            /*
             * check if TLV data fits to the buf and
             * reserved the last element for the termination char 0
             */
            if (((uint16_t)BOOTUTIL_BUILT_IN_KEY_ID_LEN != len) || (len >= SIG_BUF_SIZE)) {
                goto out;
            }
#else
        } else if ((uint16_t)IMAGE_TLV_KEYHASH == type) {
            /*
             * Determine which key we should be checking.
             */
            if (((uint16_t)BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE != len) || (len > SIG_BUF_SIZE)) {
                goto out;
            }
#endif /* MCUBOOT_BUILT_IN_KEYS */
            if (LOAD_IMAGE_DATA(hdr, fap, off, buf, len) != 0) {
                goto out;
            }

#ifdef MCUBOOT_BUILT_IN_KEYS
            *(buf + len) = 0; /* add termination char 0 */
#endif /* MCUBOOT_BUILT_IN_KEYS */
            copy_len = len;
            if (LOAD_IMAGE_DATA(hdr, fap, off, copy_buf, copy_len) != 0) {
                goto out;
            }

#ifdef MCUBOOT_BUILT_IN_KEYS
            *(copy_buf + len) = 0; /* add termination char 0 */
#endif /* MCUBOOT_BUILT_IN_KEYS */

            se_key_id = ifx_se_bootutil_find_key(buf, len, copy_buf, copy_len);
            /*
             * The key may not be found, which is acceptable.  There
             * can be multiple signatures, each preceded by a key.
             */
#else
        } else if ((uint16_t)IMAGE_TLV_PUBKEY == type) {
            /*
             * Determine which key we should be checking.
             */
            if (len > sizeof(key_buf)) {
                goto out;
            }

            if (LOAD_IMAGE_DATA(hdr, fap, off, key_buf, len) != 0) {
                goto out;
            }

            key_id = bootutil_find_key(image_index, key_buf, len);
            /*
             * The key may not be found, which is acceptable.  There
             * can be multiple signatures, each preceded by a key.
             */
            se_key_id = (ifx_se_key_id_fih_t)IFX_SE_KEY_ID_FIH_INIT_VALUE(0U, key_id);
#endif /* !MCUBOOT_HW_KEY */
        } else if ((uint16_t)SIG_TLV_EXPECTED == type) {
            fih_int valid_signature = FIH_FAILURE;
            ifx_se_hash_operation_t se_sha256_temp = IFX_SE_HASH_OPERATION_INIT;

            if (!SIG_LEN_EXPECTED(len) || len > sizeof(buf)) {
                goto out;
            }

            if (LOAD_IMAGE_DATA(hdr, fap, off, buf, len) != 0) {
                goto out;
            }

            /* Need a clone, since ifx_se_hash_finish() inactivates
             * the se_sha256
             */
            se_hash_clone_status = ifx_se_hash_clone(&se_sha256, &se_sha256_temp, IFX_SE_NULL_CTX);
            if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, se_hash_clone_status)) {
                goto out;
            }

            FIH_CALL(bootutil_ifx_se_verify_sig, valid_signature, \
                     &se_sha256_temp, buf, len, se_key_id);

            (void)ifx_se_hash_abort(&se_sha256_temp, IFX_SE_NULL_CTX);
            (void)ifx_se_destroy_key(se_key_id, IFX_SE_NULL_CTX);

            if (fih_eq(FIH_SUCCESS, valid_signature)) {
                /* Encode succesful completion pattern to complex_result */
                fih_complex_result = fih_uint_or(fih_complex_result,
                                                 IFX_FIH_MASK_SIG_TLV_EXPECTED);
            } else {
                BOOT_LOG_DBG(" * Invalid signature of bootable image %d",
                             image_index);
                goto out;
            }
#endif /* SIG_TLV_EXPECTED */
#ifdef MCUBOOT_HW_ROLLBACK_PROT
        /* NOTE: To be revised when doing FWSECURITY-2418 */
        } else if ((uint16_t)IMAGE_TLV_SEC_CNT == type) {
            FIH_CALL(bootutil_ifx_se_read_img_sec_cnt, fih_rc, \
                     hdr, fap, off, len, &img_security_cnt);
            if (!fih_eq(fih_rc, FIH_SUCCESS)) {
                goto out;
            }

            BOOT_LOG_DBG("NV Counter read from image = %" PRIu32,
                         fih_uint_decode(img_security_cnt));

            FIH_CALL(boot_nv_security_counter_get, fih_rc, \
                     image_index, &security_cnt);
            if (!fih_eq(fih_rc, FIH_SUCCESS)) {
                goto out;

            }

            BOOT_LOG_DBG("NV Counter read from device = %" PRIu32,
                         fih_uint_decode(security_cnt));

            /* Compare the new image's security counter value against the
             * stored security counter value.
             */
            if (fih_uint_ge(img_security_cnt, security_cnt)) {
                /* Encode succesful completion pattern to complex_result */
                fih_complex_result = fih_uint_or(fih_complex_result,
                                                 IFX_FIH_MASK_IMAGE_TLV_SEC_CNT);
            } else {
                /* The image's security counter is not accepted. */
                goto out;
            }
#endif /* MCUBOOT_HW_ROLLBACK_PROT */
        } else {
            /* Unknown type */
        }
    }

out:
    (void)ifx_se_destroy_key(se_key_id, IFX_SE_NULL_CTX);
    (void)ifx_se_hash_abort(&se_sha256, IFX_SE_NULL_CTX);

    FIH_RET(fih_complex_result);
}
