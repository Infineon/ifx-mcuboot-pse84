/***************************************************************************//**
* \file xip_encryption.c
*
* \brief
* PSE84 XIP encryption support
*
********************************************************************************
* \copyright
* (c) 2024, Cypress Semiconductor Corporation (an Infineon company) or
* an affiliate of Cypress Semiconductor Corporation.
*
* SPDX-License-Identifier: Apache-2.0
*
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
*******************************************************************************/
#include "cy_smif.h"
#include "xip_encryption.h"
#include "bootutil_priv.h"

#define MCUBOOT_XIP_AES_KEY_LENGTH 16


/**
 * Sets key and initial vector in the SMIF crypto block.
 *
 */
void ifx_epb_set_xip_crypto_params(uint32_t * key, uint32_t * iv)
{
    if ((key != NULL) && (iv != NULL))
    {
        Cy_SMIF_SetCryptoKey(IFX_EPB_SMIF_HW, key);
        Cy_SMIF_SetCryptoIV(IFX_EPB_SMIF_HW, iv);
    }
}

#if defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY)
/**
 * Sets SMIF encryption key and SMIF encryption initial vector for the image.
 *
 */
int ifx_epb_set_xip_crypto_for_image_slot(uint32_t crypto_block_id,
                                              uint32_t image_index,
                                              uint32_t slot,
                                              uint32_t * key,
                                              uint32_t * iv)
{
    int rc = -1;
    if ((key != NULL) && (iv != NULL))
    {
        const struct flash_area *fap = NULL;
        int fa_id = flash_area_id_from_multi_image_slot(image_index, slot);

        rc = flash_area_open(fa_id, &fap);
        if (0 == flash_area_open(fa_id, &fap)) {

            rc = ifx_epb_set_xip_crypto_region_params(crypto_block_id,
                                                      fap->fa_off,
                                                      fap->fa_size,
                                                      key,
                                                      iv);
        }

    }

    return rc;
}
#endif /* defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY) */


/**
 * Sets key and initial vector for the XIP region using SMIF crypto block.
 *
 */
int ifx_epb_set_xip_crypto_region_params(uint32_t crypto_block_id,
                                                         uint32_t addr,
                                                         uint32_t len,
                                                         uint32_t * key,
                                                         uint32_t * iv)
{
    int rc = -1;
    if ((key != NULL) && (iv != NULL) && (len != 0u))
    {
        cy_stc_smif_crypto_region_config_t region_cfg = { 0 };

        /* Set AES key */
        memcpy(region_cfg.key, key, MCUBOOT_XIP_AES_KEY_LENGTH);

        /* Set AES IV
         * The  region_cfg.iv[0] is a counter, the rest 3 registers are nonce */
        memcpy(&region_cfg.iv[1], iv,       sizeof(region_cfg.iv[1]));
        memcpy(&region_cfg.iv[2], (iv + 1), sizeof(region_cfg.iv[2]));
        memcpy(&region_cfg.iv[3], (iv + 2), sizeof(region_cfg.iv[3]));

        /* Set start address of crypto region */
        memcpy(&(region_cfg.region_base_address), &addr, sizeof(addr));

        /* Set crypto region size */
         region_cfg.region_size = len;

        /* Init SMIF crypto block */
        if (CY_SMIF_SUCCESS == Cy_SMIF_SetCryptoKeyRegion(IFX_EPB_SMIF_HW,
                                                          crypto_block_id,
                                                          &region_cfg))   {
            rc = 0;
        }
    }

    return rc;
}


/**
 * Encrypts data from fap_src with off offset for fap_dst 
 * by SMIF crypto block and stores to encrypted data to the buf.
 *
 */
int boot_encrypt_xip(const struct flash_area *fap_src, const struct flash_area *fap_dst,
                    const uint32_t off, const uint32_t sz, uint8_t *buf)
{
    cy_en_smif_status_t smif_status = CY_SMIF_CMD_NOT_FOUND;
    uintptr_t prim_xip, sec_xip;

    /* boot_copy_region will call boot_encrypt with sz = 0 when skipping over
    the TLVs. */
    if (sz == 0) {
        return 0;
    }

    (void)flash_device_base(fap_src->fa_device_id, &sec_xip);
    (void)flash_device_base(fap_dst->fa_device_id, &prim_xip);

    SMIF_SET_CRYPTO_MODE(Enable);

    memcpy(buf, (uint8_t *)(sec_xip + fap_src->fa_off + off), sz);
    Cy_SMIF_SetMode(IFX_EPB_SMIF_HW, CY_SMIF_NORMAL);

    smif_status = Cy_SMIF_Encrypt(IFX_EPB_SMIF_HW,
                                    prim_xip + fap_dst->fa_off + off,
                                    buf, sz, &ifx_epb_smif_context);

    Cy_SMIF_SetMode(IFX_EPB_SMIF_HW, CY_SMIF_MEMORY);
    SMIF_SET_CRYPTO_MODE(Disable);

    if (smif_status == CY_SMIF_SUCCESS){
        return 0;
    }
    else {
        return -1;
    }
}


#if defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY)
/**
 * @brief Read decrypted data from fap with off offset and stores decrypted data to the buf.
 *
 */
int boot_decrypt_xip(int image_index,
                     const struct flash_area *fap,
                     const uint32_t off,
                     const uint32_t sz,
                     uint8_t *buf)
{
    int rc = -1;
    cy_en_smif_status_t smif_status = CY_SMIF_CMD_NOT_FOUND;
    uintptr_t flash_base = 0u, flash_base_enc = 0u;
    const struct flash_area *fap_enc = NULL;

    int area_id = flash_area_id_from_multi_image_slot(image_index, BOOT_PRIMARY_SLOT);
    rc = flash_area_open(area_id, &fap_enc);
    if (0 != rc) {
        return rc;
    }

    rc = flash_device_base(fap->fa_device_id, &flash_base);
    if (0 != rc) {
        return rc;
    }
    rc = flash_device_base(fap_enc->fa_device_id, &flash_base_enc);
    if (0 != rc) {
        return rc;
    }

    memcpy(buf, (uint8_t *)(flash_base + fap->fa_off + off), sz);

    SMIF_SET_CRYPTO_MODE(Enable);

    Cy_SMIF_SetMode(IFX_EPB_SMIF_HW, CY_SMIF_NORMAL);

    smif_status = Cy_SMIF_Encrypt(IFX_EPB_SMIF_HW,
                                  flash_base_enc + fap_enc->fa_off + off,
                                  buf, sz, &ifx_epb_smif_context);

    Cy_SMIF_SetMode(IFX_EPB_SMIF_HW, CY_SMIF_MEMORY);

    SMIF_SET_CRYPTO_MODE(Disable);

    if (smif_status == CY_SMIF_SUCCESS){
        rc = 0;
    }
    else {
        rc = -1;
    }

    return rc;
}
#else
/**
 * @brief Read decrypted data from fap with off offset and stores decrypted data to the buf.
 *
 */
int boot_decrypt_xip(int image_index,
                     const struct flash_area *fap,
                     const uint32_t off,
                     const uint32_t sz,
                     uint8_t *buf)
{
    (void)image_index;
    int rc = -1;
    uintptr_t flash_base = 0u;

    rc = flash_device_base(fap->fa_device_id, &flash_base);

    if (0 == rc) {
        SMIF_SET_CRYPTO_MODE(Enable);

        memcpy(buf, (uint8_t *)(flash_base + fap->fa_off + off), sz);

        SMIF_SET_CRYPTO_MODE(Disable);

        rc = 0;
    }

    return rc;
}
#endif /* defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY) */
