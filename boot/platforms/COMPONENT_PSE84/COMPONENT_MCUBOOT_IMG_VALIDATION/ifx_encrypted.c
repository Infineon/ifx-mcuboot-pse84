/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2018-2019 JUUL Labs
 * Copyright (c) 2019-2021 Arm Limited
 * Copyright (c) 2021-2025 Cypress Semiconductor Corporation (an Infineon company)
 */

#if defined(MCUBOOT_USE_ENC_IFX_SE)
#include "mcuboot_config/mcuboot_config.h"
#include "bootutil/bootutil_log.h"

#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "ifx_se_psacrypto.h"
#include "ifx_se_fih.h"

#include "bootutil/crypto/sha256.h"
#include "bootutil/image.h"
#include "bootutil/crypto/common.h"
#include "bootutil_priv.h"

#define IFX_AES128_KEY_LEN          (16)
/* EdgeProtectTools generates a 32-byte derived CMAC */
#define IFX_CMAC_SIZE               (32)
#define IFX_SE_ECP_256_KEY_SIZE     (IFX_SE_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(256u))
#define SHARED_KEY_LEN              (32)
/* EdgeProtectTools writes the key as an array of char */
#define PROVISIONED_KEY_LEN         (12)
#define EXPECTED_ENC_LEN            (BOOT_ENC_TLV_SIZE - 16)
#define EXPECTED_ENC_TLV            IMAGE_TLV_ENC_EC256
#define EXPECTED_ENC_EXT_LEN        (EXPECTED_ENC_LEN + BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE)
#define EC_PUBK_INDEX               (0)
#define EC_TAG_INDEX                (65)
#define EC_CIPHERKEY_INDEX          (65 + 16)
#define EC_PUBK_SIZE                (EC_TAG_INDEX - EC_PUBK_INDEX)
#define EC_TAG_SIZE                 (EC_CIPHERKEY_INDEX - EC_TAG_INDEX)
_Static_assert(EC_CIPHERKEY_INDEX + BOOT_ENC_KEY_SIZE == EXPECTED_ENC_LEN,
        "Please fix ECIES-P256 component indexes");

static int ifx_aes_ctr_set_key(ifx_aes_ctr_context *ctx, const uint8_t *key);
static int ifx_aes_ctr_encrypt(ifx_aes_ctr_context *ctx, uint8_t *counter, const uint8_t *m, 
    uint32_t mlen, size_t blk_off, uint8_t *c);
        
static int ifx_ecdh_p256_shared_secret(ifx_aes_ctr_context* ctx, const uint8_t *pub_key, 
    size_t pub_key_len, uint8_t *shared, size_t shared_len, size_t *out_len);
static int ifx_kdf_aes_cmac(const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len,
    const uint8_t *salt, size_t salt_len, uint8_t *okm, size_t *okm_len);
static int ifx_verify_mac(const uint8_t *derived_data, const uint8_t *tlv_data);
static int ifx_decrypt_img_enc_key(const uint8_t *derived_data, const uint8_t *eas_key_iv,
    const uint8_t *tlv_data, uint8_t *enckey);

/*
 * Initializes the AES-CTR context.
 *
 * @param ctx  Pointer to the AES-CTR context to initialize.
 */
static inline void ifx_aes_ctr_init(ifx_aes_ctr_context *ctx) {
    ctx->operation = ifx_se_cipher_operation_init();
    ctx->ecdh_key_id = 0xFFFFFFFF;
}

/*
 * Cleans up the AES-CTR context by aborting any ongoing cipher operations
 * and destroying the associated key in the secure element.
 *
 * @param ctx  Pointer to the AES-CTR context to clean up.
 */
static inline void ifx_aes_ctr_drop(ifx_aes_ctr_context *ctx) {
    ifx_se_cipher_abort(&ctx->operation, IFX_SE_NULL_CTX);
    ifx_se_destroy_key(ctx->key_handle, IFX_SE_NULL_CTX);
}

/*
 * Sets the AES-CTR key in the secure element.
 *
 * @param ctx  Pointer to the AES-CTR context.
 * @param key  Pointer to the AES key (128-bit).
 * @return     0 on success, -1 on failure.
 */
static int ifx_aes_ctr_set_key(ifx_aes_ctr_context *ctx, const uint8_t *key) {
    ifx_se_status_t status = IFX_SE_INVALID;
    ifx_se_key_attributes_t aes_attributes = IFX_SE_KEY_ATTRIBUTES_INIT;
    uint8_t tmp_buffer[IFX_AES128_KEY_LEN + IFX_CRC32_CRC_SIZE];

    /* Step 1: Set AES key attributes */
    ifx_se_set_key_usage_flags(&aes_attributes, IFX_SE_KEY_USAGE_DECRYPT | IFX_SE_KEY_USAGE_ENCRYPT);
    ifx_se_set_key_algorithm(&aes_attributes, IFX_SE_ALG_CTR);
    ifx_se_set_key_type(&aes_attributes, IFX_SE_KEY_TYPE_AES);
    ifx_se_set_key_bits(&aes_attributes, IFX_SE_BYTES_TO_BITS(IFX_AES128_KEY_LEN));
    ifx_se_set_key_lifetime(&aes_attributes, IFX_SE_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        IFX_SE_KEY_PERSISTENCE_VOLATILE, IFX_SE_KEY_LOCATION_SE));

    /* Step 2: Prepare the AES key and append CRC */
    memcpy(tmp_buffer, key, IFX_AES128_KEY_LEN);
    IFX_CRC32_CALC_APPEND(tmp_buffer, IFX_AES128_KEY_LEN);

    /* Step 3: Import the AES key into the secure element */
    status = ifx_se_import_key(&aes_attributes,
                               ifx_se_fih_ptr_encode(tmp_buffer),
                               ifx_se_fih_uint_encode(IFX_AES128_KEY_LEN + IFX_CRC32_CRC_SIZE),
                               ifx_se_fih_ptr_encode(&ctx->key_handle),
                               IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    return 0;

cleanup:
    /* Clean up resources in case of failure */
    ifx_aes_ctr_drop(ctx);
    return -1;
}

/*
 * Encrypts or decrypts data using AES-CTR mode.
 *
 * @param ctx      Pointer to the AES-CTR context.
 * @param counter  Pointer to the AES-CTR counter (IV).
 * @param m        Pointer to the input data (plaintext or ciphertext).
 * @param mlen     Length of the input data.
 * @param blk_off  Block offset within the data (not used in this implementation).
 * @param c        Pointer to the output buffer (ciphertext or plaintext).
 * @return         0 on success, -1 on failure.
 */
static int ifx_aes_ctr_encrypt(ifx_aes_ctr_context *ctx, uint8_t *counter, const uint8_t *m, 
                               uint32_t mlen, size_t blk_off, uint8_t *c) {
    
    ifx_se_status_t status = IFX_SE_INVALID;
    size_t out_size = 0;
    size_t finish_size = 0;
    (void)blk_off;

    /* Step 1: Initialize the cipher operation */
    ctx->operation = ifx_se_cipher_operation_init();

    /* Step 2: Set up the AES-CTR encryption/decryption operation */
    status = ifx_se_cipher_encrypt_setup(&ctx->operation,
                                         ctx->key_handle,
                                         ifx_se_fih_uint_encode(IFX_SE_ALG_CTR),
                                         IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 3: Set the AES-CTR IV (counter) */
    status = ifx_se_cipher_set_iv(&ctx->operation,
                                  ifx_se_fih_ptr_encode(counter),
                                  ifx_se_fih_uint_encode(BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE),
                                  IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 4: Process the input data (main encryption/decryption operation) */
    status = ifx_se_cipher_update(&ctx->operation,
                                  ifx_se_fih_ptr_encode(m),
                                  ifx_se_fih_uint_encode(mlen),
                                  ifx_se_fih_ptr_encode(c),
                                  ifx_se_fih_uint_encode(mlen),
                                  ifx_se_fih_ptr_encode(&out_size),
                                  IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 5: Finalize the encryption/decryption operation */
    status = ifx_se_cipher_finish(&ctx->operation,
                                  ifx_se_fih_ptr_encode(c + out_size),
                                  ifx_se_fih_uint_encode(mlen - out_size),
                                  ifx_se_fih_ptr_encode(&finish_size),
                                  IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    return 0;

cleanup:
    /* Clean up resources in case of failure */
    ifx_aes_ctr_drop(ctx);
    return -1;
}

/*
 * Computes the shared secret using ECDH (Elliptic Curve Diffie-Hellman) with P-256.
 *
 * @param ctx          Pointer to the AES-CTR context containing the provisioned key ID.
 * @param pub_key      The public key of the other party.
 * @param pub_key_len  Length of the public key.
 * @param shared       Buffer to store the computed shared secret.
 * @param shared_len   Length of the shared secret buffer.
 * @param out_len      Pointer to store the actual length of the shared secret.
 * @return             0 on success, -1 on failure.
 */
static int ifx_ecdh_p256_shared_secret(ifx_aes_ctr_context* ctx,
                                       const uint8_t *pub_key, size_t pub_key_len, 
                                       uint8_t *shared, size_t shared_len, size_t *out_len) {
    
    ifx_se_status_t status = IFX_SE_INVALID;
    ifx_se_key_id_fih_t ecdh_key_id = IFX_SE_KEY_ID_FIH_INIT_VALUE(0, 
        IFX_SE_KEY_ID_VENDOR_MIN + ctx->ecdh_key_id);
    ifx_se_key_attributes_t private_key_attributes = IFX_SE_KEY_ATTRIBUTES_INIT;

    /* Step 1: Initialize key attributes for the private key */
    ifx_se_set_key_usage_flags(&private_key_attributes, IFX_SE_KEY_USAGE_DERIVE);
    ifx_se_set_key_algorithm(&private_key_attributes, IFX_SE_ALG_ECDH);
    ifx_se_set_key_type(&private_key_attributes, IFX_SE_KEY_TYPE_ECC_KEY_PAIR(IFX_SE_ECC_FAMILY_SECP_R1));
    ifx_se_set_key_bits(&private_key_attributes, IFX_SE_BYTES_TO_BITS(IFX_SE_ECP_256_KEY_SIZE));
    ifx_se_set_key_lifetime(&private_key_attributes, IFX_SE_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        IFX_SE_KEY_PERSISTENCE_VOLATILE, IFX_SE_KEY_LOCATION_SE));

    /* Step 2: Perform the raw key agreement (ECDH) */
    status = ifx_se_raw_key_agreement(ifx_se_fih_uint_encode(IFX_SE_ALG_ECDH), 
                                      ecdh_key_id,
                                      ifx_se_fih_ptr_encode(pub_key), 
                                      ifx_se_fih_uint_encode(pub_key_len),
                                      ifx_se_fih_ptr_encode(shared), 
                                      ifx_se_fih_uint_encode(shared_len),
                                      ifx_se_fih_ptr_encode(out_len),
                                      IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 3: Clean up and return success */
    ifx_se_destroy_key(ecdh_key_id, IFX_SE_NULL_CTX);
    return 0;

cleanup:
    /* Clean up resources in case of failure */
    ifx_se_destroy_key(ecdh_key_id, IFX_SE_NULL_CTX);
    return -1;
}

/*
 * Key Derivation Function (KDF) using AES-CMAC as described in RFC 4493.
 *
 * @param ikm       Input keying material (shared secret).
 * @param ikm_len   Length of the input keying material.
 * @param info      Optional context and application-specific information.
 * @param info_len  Length of the info parameter.
 * @param salt      Optional salt value (a non-secret random value).
 * @param salt_len  Length of the salt parameter.
 * @param okm       Output keying material.
 * @param okm_len   On input, the requested length; on output, the generated length.
 * @return          0 on success, -1 on failure.
 */
static int ifx_kdf_aes_cmac(const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len,
                            const uint8_t *salt, size_t salt_len, uint8_t *okm, size_t *okm_len) {
    
    ifx_se_status_t status = IFX_SE_INVALID;
    ifx_se_key_derivation_operation_t derivation_op = ifx_se_key_derivation_operation_init();

    /* Step 1: Set up the key derivation operation */
    status = ifx_se_key_derivation_setup(&derivation_op,
                                         ifx_se_fih_uint_encode(IFX_SE_ALG_KDF_AES_CMAC),
                                         IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 2: Provide the input keying material (IKM) as the secret */
    status = ifx_se_key_derivation_input_bytes(&derivation_op,
                                               IFX_SE_KEY_DERIVATION_INPUT_SECRET,
                                               ifx_se_fih_ptr_encode(ikm),
                                               ifx_se_fih_uint_encode(ikm_len),
                                               IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 3: Provide the salt as the seed */
    status = ifx_se_key_derivation_input_bytes(&derivation_op,
                                               IFX_SE_KEY_DERIVATION_INPUT_SEED,
                                               ifx_se_fih_ptr_encode(salt),
                                               ifx_se_fih_uint_encode(salt_len),
                                               IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 4: Provide the optional info parameter as the label */
    status = ifx_se_key_derivation_input_bytes(&derivation_op,
                                               IFX_SE_KEY_DERIVATION_INPUT_LABEL,
                                               ifx_se_fih_ptr_encode(info),
                                               ifx_se_fih_uint_encode(info_len),
                                               IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 5: Generate the output keying material (OKM) */
    status = ifx_se_key_derivation_output_bytes(&derivation_op,
                                                ifx_se_fih_ptr_encode(okm),
                                                ifx_se_fih_uint_encode(*okm_len),
                                                IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 6: Clean up and return success */
    ifx_se_key_derivation_abort(&derivation_op, IFX_SE_NULL_CTX);
    return 0;

cleanup:
    /* Clean up resources in case of failure */
    ifx_se_key_derivation_abort(&derivation_op, IFX_SE_NULL_CTX);
    return -1;
}

/*
 * Verifies the MAC (Message Authentication Code) using AES-CMAC.
 *
 * @param derived_data  The derived key data used for MAC verification.
 * @param tlv_data      The TLV data containing the cipher key and MAC to verify.
 * @return              0 on success, -1 on failure.
 */
static int ifx_verify_mac(const uint8_t *derived_data, const uint8_t *tlv_data) {
    ifx_se_status_t status = IFX_SE_INVALID;
    ifx_se_key_id_fih_t mac_key_id = IFX_SE_KEY_ID_FIH_INIT;
    ifx_se_key_attributes_t mac_attributes = IFX_SE_KEY_ATTRIBUTES_INIT;
    ifx_se_mac_operation_t mac_op = {0};
    size_t mac_size = IFX_CMAC_SIZE;
    uint8_t tmp_buffer[mac_size + IFX_CRC32_CRC_SIZE];

    /* Step 1: Set MAC key attributes */
    ifx_se_set_key_usage_flags(&mac_attributes, IFX_SE_KEY_USAGE_VERIFY_MESSAGE);
    ifx_se_set_key_algorithm(&mac_attributes, IFX_SE_ALG_CMAC);
    ifx_se_set_key_type(&mac_attributes, IFX_SE_KEY_TYPE_AES);
    ifx_se_set_key_bits(&mac_attributes, IFX_SE_BYTES_TO_BITS(mac_size));
    ifx_se_set_key_lifetime(&mac_attributes, IFX_SE_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        IFX_SE_KEY_PERSISTENCE_VOLATILE, IFX_SE_KEY_LOCATION_SE));

    /* Step 2: Prepare the derived MAC key (located after derived key) and append CRC */
    memcpy(tmp_buffer, derived_data + BOOT_ENC_KEY_SIZE, mac_size);
    IFX_CRC32_CALC_APPEND(tmp_buffer, mac_size);

    /* Step 3: Import the derived MAC key */
    status = ifx_se_import_key(&mac_attributes,
                               ifx_se_fih_ptr_encode(tmp_buffer),
                               ifx_se_fih_uint_encode(mac_size + IFX_CRC32_CRC_SIZE),
                               ifx_se_fih_ptr_encode(&mac_key_id),
                               IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 4: Set up the MAC verification operation */
    status = ifx_se_mac_verify_setup(&mac_op,
                                     mac_key_id,
                                     ifx_se_fih_uint_encode(IFX_SE_ALG_CMAC),
                                     IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 5: Provide the cipher key from TLV data as the message to verify */
    status = ifx_se_mac_update(&mac_op,
                               ifx_se_fih_ptr_encode(tlv_data + EC_CIPHERKEY_INDEX),
                               ifx_se_fih_uint_encode(BOOT_ENC_KEY_SIZE),
                               IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 6: Verify that the TLV MAC matches the calculated MAC */
    status = ifx_se_mac_verify_finish(&mac_op,
                                      ifx_se_fih_ptr_encode(tlv_data + EC_TAG_INDEX),
                                      ifx_se_fih_uint_encode(EC_TAG_SIZE),
                                      IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 7: Clean up and return success */
    ifx_se_destroy_key(mac_key_id, IFX_SE_NULL_CTX);
    ifx_se_mac_abort(&mac_op, IFX_SE_NULL_CTX);
    return 0;

cleanup:
    /* Clean up resources in case of failure */
    ifx_se_destroy_key(mac_key_id, IFX_SE_NULL_CTX);
    ifx_se_mac_abort(&mac_op, IFX_SE_NULL_CTX);
    return -1;
}

/*
 * Extracts and decrypts the encrypted key using AES-CTR.
 *
 * @param derived_data  The derived key data used for decryption.
 * @param aes_key_iv    The AES-CTR initialization vector (IV).
 * @param tlv_data      The TLV data containing the encrypted key.
 * @param enckey        Buffer to store the decrypted key.
 * @return              0 on success, -1 on failure.
 */
static int ifx_decrypt_img_enc_key(const uint8_t *derived_data, const uint8_t *eas_key_iv,
                                   const uint8_t *tlv_data, uint8_t *enckey) {
    
    ifx_se_status_t status = IFX_SE_INVALID;
    ifx_se_key_id_fih_t aes_key_id = IFX_SE_KEY_ID_FIH_INIT;
    ifx_se_key_attributes_t aes_attributes = IFX_SE_KEY_ATTRIBUTES_INIT;
    ifx_se_cipher_operation_t cipher_op = ifx_se_cipher_operation_init();
    uint8_t tmp_buffer[IFX_AES128_KEY_LEN + IFX_CRC32_CRC_SIZE];
    size_t out_size = 0;
    size_t finish_size = 0;

    /* Step 1: Set AES key attributes */
    ifx_se_set_key_usage_flags(&aes_attributes, IFX_SE_KEY_USAGE_DECRYPT | IFX_SE_KEY_USAGE_ENCRYPT);
    ifx_se_set_key_algorithm(&aes_attributes, IFX_SE_ALG_CTR);
    ifx_se_set_key_type(&aes_attributes, IFX_SE_KEY_TYPE_AES);
    ifx_se_set_key_bits(&aes_attributes, IFX_SE_BYTES_TO_BITS(IFX_AES128_KEY_LEN));
    ifx_se_set_key_lifetime(&aes_attributes, IFX_SE_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        IFX_SE_KEY_PERSISTENCE_VOLATILE, IFX_SE_KEY_LOCATION_SE));

    /* Step 2: Prepare the derived AES key and append CRC */
    memcpy(tmp_buffer, derived_data, IFX_AES128_KEY_LEN);
    IFX_CRC32_CALC_APPEND(tmp_buffer, IFX_AES128_KEY_LEN);

    /* Step 3: Import the derived AES key */
    status = ifx_se_import_key(&aes_attributes,
                               ifx_se_fih_ptr_encode(tmp_buffer),
                               ifx_se_fih_uint_encode(IFX_AES128_KEY_LEN + IFX_CRC32_CRC_SIZE),
                               ifx_se_fih_ptr_encode(&aes_key_id),
                               IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 4: Set up the AES-CTR decryption operation */
    status = ifx_se_cipher_decrypt_setup(&cipher_op,
                                         aes_key_id,
                                         ifx_se_fih_uint_encode(IFX_SE_ALG_CTR),
                                         IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 5: Set the AES key IV (nonce) */
    status = ifx_se_cipher_set_iv(&cipher_op,
                                  ifx_se_fih_ptr_encode(eas_key_iv),
                                  ifx_se_fih_uint_encode(BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE),
                                  IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 6: Decrypt the encrypted key (first part) */
    status = ifx_se_cipher_update(&cipher_op,
                                  ifx_se_fih_ptr_encode(tlv_data + EC_CIPHERKEY_INDEX),
                                  ifx_se_fih_uint_encode(BOOTUTIL_CRYPTO_AES_CTR_KEY_SIZE),
                                  ifx_se_fih_ptr_encode(enckey),
                                  ifx_se_fih_uint_encode(BOOTUTIL_CRYPTO_AES_CTR_KEY_SIZE),
                                  ifx_se_fih_ptr_encode(&out_size),
                                  IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 7: Finalize the decryption (remaining part) */
    status = ifx_se_cipher_finish(&cipher_op,
                                  ifx_se_fih_ptr_encode(enckey + out_size),
                                  ifx_se_fih_uint_encode(BOOTUTIL_CRYPTO_AES_CTR_KEY_SIZE - out_size),
                                  ifx_se_fih_ptr_encode(&finish_size),
                                  IFX_SE_NULL_CTX);
    if (ifx_se_fih_uint_not_eq(IFX_SE_SUCCESS, status)) {
        goto cleanup;
    }

    /* Step 8: Clean up and return success */
    ifx_se_destroy_key(aes_key_id, IFX_SE_NULL_CTX);
    ifx_se_cipher_abort(&cipher_op, IFX_SE_NULL_CTX);
    return 0;

cleanup:
    /* Clean up resources in case of failure */
    ifx_se_destroy_key(aes_key_id, IFX_SE_NULL_CTX);
    ifx_se_cipher_abort(&cipher_op, IFX_SE_NULL_CTX);
    return -1;
}

/*
 * Initializes the AES-CTR context for a specific image slot.
 *
 * @param enc_state  Pointer to the encryption state structure.
 * @param slot       The slot index to initialize.
 * @return           0 on success.
 */
int boot_enc_init(struct enc_key_data *enc_state, uint8_t slot) {
    ifx_aes_ctr_init(&enc_state[slot].aes_ctr);
    return 0;
}

/*
 * Cleans up the AES-CTR context for a specific image slot.
 *
 * @param enc_state  Pointer to the encryption state structure.
 * @param slot       The slot index to clean up.
 * @return           0 on success.
 */
int boot_enc_drop(struct enc_key_data *enc_state, uint8_t slot) {
    ifx_aes_ctr_drop(&enc_state[slot].aes_ctr);

    /* Mark the slot as invalid */
    enc_state[slot].valid = 0;
    return 0;
}

/*
 * Clears the encryption state for all slots.
 *
 * @param enc_state  Pointer to the encryption state structure.
 */
void boot_enc_zeroize(struct enc_key_data *enc_state) {
    uint8_t slot;

    /* Step 1: Clean up the AES-CTR context for each slot */
    for (slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
        (void)boot_enc_drop(enc_state, slot);
    }

    /* Step 2: Clear the entire encryption state structure */
    (void)memset(enc_state, 0, sizeof(struct enc_key_data) * BOOT_NUM_SLOTS);
}

/*
 * Checks if the encryption state for a specific image slot is valid.
 *
 * @param enc_state   Pointer to the encryption state structure.
 * @param image_index Index of the image being checked.
 * @param fap         Pointer to the flash area structure.
 * @return            true if the encryption state is valid, false otherwise.
 */
bool boot_enc_valid(struct enc_key_data *enc_state, int image_index, const struct flash_area *fap) {
    int rc;

    /* Determine the slot corresponding to the flash area */
    rc = flash_area_id_to_multi_image_slot(image_index, flash_area_get_id(fap));
    if (rc < 0) {
        /* can't get proper slot number - skip encryption, */
        /* postpone the error for a upper layer */
        return false;
    }

    return enc_state[rc].valid;
}

/*
 * Sets the AES-CTR encryption key for a specific image slot.
 *
 * @param enc_state  Pointer to the encryption state structure.
 * @param slot       The slot index to set the key for.
 * @param bs         Pointer to the boot status structure containing the encryption key.
 * @return           0 on success, -1 on failure.
 */
int boot_enc_set_key(struct enc_key_data *enc_state, uint8_t slot, struct boot_status *bs) {
    int rc;

    /* Step 1: Check if the encryption key is already set */
    if (enc_state[slot].valid == 1) {
        return 0;
    }

    /* Step 2: Set the AES-CTR key for the specified slot */
    rc = ifx_aes_ctr_set_key(&enc_state[slot].aes_ctr, bs->enckey[slot]);
    if (rc != 0) {
        // If setting the key fails, clean up the encryption state for the slot
        (void)boot_enc_drop(enc_state, slot);
        return -1;
    }

    /* Step 3: Mark the slot as valid */
    enc_state[slot].valid = 1;

    /* Step 4: Clear the encryption key in the boot status structure */
    memset(bs->enckey[slot], BOOT_UNINITIALIZED_KEY_FILL, BOOT_ENC_KEY_ALIGN_SIZE);

    return 0;
}

/*
 * Encrypts or decrypts a block of data using AES-CTR mode.
 *
 * @param enc_state  Pointer to the encryption state structure.
 * @param image_index Index of the image being processed.
 * @param fap        Pointer to the flash area structure.
 * @param off        Offset within the flash area.
 * @param sz         Size of the data to be encrypted or decrypted.
 * @param blk_off    Block offset within the data (not used in this implementation).
 * @param buf        Pointer to the buffer containing the data to be processed.
 * @return           0 on success, -1 on failure.
 */
int boot_encrypt(struct enc_key_data *enc_state, int image_index, const struct flash_area *fap,
                 uint32_t off, uint32_t sz, uint32_t blk_off, uint8_t *buf) {
    
    struct enc_key_data *enc;
    uint8_t *nonce;
    uint8_t slot;
    int rc;

    /* boot_copy_region will call boot_encrypt with sz = 0 when skipping over
       the TLVs. */
    if (sz == 0) {
        return 0; // Nothing to encrypt or decrypt
    }

    /* Step 1: Determine the slot based on the flash area */
#if MCUBOOT_SWAP_USING_SCRATCH
    /* in this case scratch area contains encrypted source block that was copied
    from secondary slot */
    if (fap->fa_id == FLASH_AREA_IMAGE_SCRATCH) {
        rc = 1; // Scratch area corresponds to slot 1
    } else
#endif
    {
        rc = flash_area_id_to_multi_image_slot(image_index, fap->fa_id);
        if (rc < 0) {
            assert(0); // Invalid slot, should not happen
            return -1;
        }
    }
    slot = rc;

    /* Step 2: Validate the encryption state for the slot */
    enc = &enc_state[slot];
    assert(enc->valid == 1); // Ensure the encryption state is valid

    /* Step 3: Prepare the AES-CTR nonce (IV) */
    nonce = enc->aes_iv;
    off >>= 4; // Shift offset to align with AES block size
    nonce[12] = (uint8_t)(off >> 24);
    nonce[13] = (uint8_t)(off >> 16);
    nonce[14] = (uint8_t)(off >> 8);
    nonce[15] = (uint8_t)off;

    /* Step 4: Perform AES-CTR encryption or decryption */
    rc = ifx_aes_ctr_encrypt(&enc->aes_ctr, nonce, buf, sz, blk_off, buf);
    if (rc < 0) {
        /* If encryption fails, clean up the encryption state for the slot */
        boot_enc_drop(enc_state, slot);
    }

    return rc;
}

/*
 * Loads the encryption key for a specific image slot.
 *
 * @param enc_state   Pointer to the encryption state structure.
 * @param image_index Index of the image being processed.
 * @param hdr         Pointer to the image header.
 * @param fap         Pointer to the flash area structure.
 * @param bs          Pointer to the boot status structure.
 * @return            1 if the encryption key is already loaded, 
 *                    0 on success, or -1 on failure.
 */
int boot_enc_load(struct enc_key_data *enc_state, int image_index, const struct image_header *hdr,
                  const struct flash_area *fap, struct boot_status *bs) {
    
    uint32_t off;
    uint16_t len;
    struct image_tlv_iter it;
#ifdef MCUBOOT_SWAP_SAVE_ENCTLV
    uint8_t *tlv_buf;
#else
    uint8_t tlv_buf[EXPECTED_ENC_EXT_LEN];
#endif
    uint8_t key_buf[PROVISIONED_KEY_LEN];
    int32_t key_id;
    uint8_t slot;
    int rc;

    /* Step 1: Determine the slot corresponding to the flash area */
    rc = flash_area_id_to_multi_image_slot(image_index, flash_area_get_id(fap));
    if (rc < 0) {
        return rc;
    }
    slot = rc;

    /* Step 2: Check if the encryption key is already loaded */
    if (enc_state[slot].valid) {
        return 0;
    }

    /* Step 3: Initialize the AES-CTR context for the slot */
    boot_enc_init(enc_state, slot);

    /* Step 4: Read provisioned key ID TLV */
    rc = bootutil_tlv_iter_begin(&it, hdr, fap, IMAGE_TLV_ENV_KEY_ID, true);
    if (rc != 0) {
        return -1;
    }

    rc = bootutil_tlv_iter_next(&it, &off, &len, NULL);
    if (rc != 0 || len < 1 || len > sizeof(key_buf) - 1) {
        return -1;
    }

    memset(key_buf, 0, sizeof(key_buf));
    rc = flash_area_read(fap, off, key_buf, len);
    if (rc != 0) {
        return -1;
    }

    key_id = atoi((const char *)key_buf);
    if (key_id < 0 || 
        (key_id > 0 && (uint32_t)key_id > IFX_SE_KEY_ID_VENDOR_MAX - IFX_SE_KEY_ID_VENDOR_MIN)) {
        return -1;
    }

    /* Set provisioned key ID */
    enc_state[slot].aes_ctr.ecdh_key_id = (uint32_t)key_id;

    /* Step 5: Read encryption TLV */
    rc = bootutil_tlv_iter_begin(&it, hdr, fap, EXPECTED_ENC_TLV, false);
    if (rc != 0) {
        return -1;
    }

    rc = bootutil_tlv_iter_next(&it, &off, &len, NULL);
    if (rc != 0 || len < EXPECTED_ENC_LEN || len > EXPECTED_ENC_EXT_LEN) {
        return -1;
    }

#ifdef MCUBOOT_SWAP_SAVE_ENCTLV
    /* Use the boot status buffer to store the encryption TLV */
    tlv_buf = bs->enctlv[slot];
    memset(tlv_buf, BOOT_UNINITIALIZED_TLV_FILL, BOOT_ENC_TLV_ALIGN_SIZE);
#endif

    rc = flash_area_read(fap, off, tlv_buf, len);
    if (rc != 0) {
        return -1;
    }

    /* Step 6: Decrypt the encryption key */
    rc = boot_enc_decrypt(&enc_state[slot].aes_ctr, tlv_buf, bs->enckey[slot], len, enc_state[slot].aes_iv);
    if (rc != 0) {
        return -1;
    }

    return 0;
}

/*
 * Decrypt an encryption key TLV.
 *
 * @param ctx     Pointer to the AES-CTR context containing the provisioned key ID.
 * @param buf    An encryption TLV read from flash (build time fixed length).
 *               Contains ECC public key, Cipher MAC, Ciphertext and Salt.
 * @param sz     An encryption TLV buffer data size.
 * @param enckey An AES-128 or AES-256 key-sized buffer to store the plain key.
 * @param enciv  Buffer to store the AES-CTR initialization vector (IV).
 * @return       0 on success, -1 on failure.
 */
int boot_enc_decrypt(ifx_aes_ctr_context* ctx, const uint8_t *buf, uint8_t *enckey,
                     uint32_t sz, uint8_t *enciv) {
    
    uint8_t salt[BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE];
    uint8_t info[BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE] = "MCUBoot_ECIES_v1";
    uint8_t shared[SHARED_KEY_LEN];
    /* contains derived AES key, derived CMAC, encryption IV, image encryption IV */
    uint8_t derived_data[BOOTUTIL_CRYPTO_AES_CTR_KEY_SIZE + BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE + BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE * 2];
    uint8_t counter[BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE];
    size_t len, out_len;
    const uint8_t *my_salt = salt;
    uint8_t *aes_key_iv = NULL;
    uint8_t *image_iv = NULL;
    int rc = -1;

    /* Step 1: Compute the shared secret using ECDH */
    len = SHARED_KEY_LEN;
    out_len = len;
    rc = ifx_ecdh_p256_shared_secret(ctx, &buf[EC_PUBK_INDEX], EC_PUBK_SIZE, shared, SHARED_KEY_LEN, &out_len);
    if (rc != 0 || len != out_len) {
        return -1;
    }

    /* Step 2: Prepare for key derivation */
    memset(counter, 0, BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE);
    memset(salt, 0, BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE);

    len = BOOTUTIL_CRYPTO_AES_CTR_KEY_SIZE + BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE;

    if (sz > EXPECTED_ENC_LEN) {
        /* Use enhanced encryption scheme with randomly generated salt and AES IVs */
        len += BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE * 2;
        my_salt = &buf[EXPECTED_ENC_LEN];
        aes_key_iv = &derived_data[BOOTUTIL_CRYPTO_AES_CTR_KEY_SIZE + BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE];
        image_iv = &derived_data[BOOTUTIL_CRYPTO_AES_CTR_KEY_SIZE + BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE + BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE];
    }

    /* Step 3: Derive keys using AES-CMAC */
    out_len = len;
    rc = ifx_kdf_aes_cmac(shared, SHARED_KEY_LEN, info, BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE,
                          my_salt, BOOTUTIL_CRYPTO_SHA256_DIGEST_SIZE, derived_data, &out_len);
    if (rc != 0 || len != out_len) {
        return -1;
    }

    /* Step 4: Verify the MAC to ensure data integrity */
    rc = ifx_verify_mac(derived_data, buf);
    if (rc != 0) {
        return -1;
    }

    /* Step 5: Decrypt the image encrypted key */
    rc = ifx_decrypt_img_enc_key(derived_data, aes_key_iv, buf, enckey);
    if (rc != 0) {
        return -1;
    }

    /* Step 6: Copy the image IV for decryption */
    memcpy(enciv, image_iv, BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE);

    return 0;
}

#endif /* MCUBOOT_USE_ENC_IFX_SE */

/*
 * Avoid warning from -pedantic. This is included
 * because ISO C forbids an empty translation unit.
 */
typedef int encrypted_iso_c_forbids_empty_translation_units;
