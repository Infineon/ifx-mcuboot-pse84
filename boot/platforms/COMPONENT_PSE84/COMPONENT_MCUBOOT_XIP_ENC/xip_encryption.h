/***************************************************************************//**
* \file xip_encryption.h
*
* \brief
* PSE84 XIP encryption support
*
********************************************************************************
* \copyright
* (c) 2024-2025, Cypress Semiconductor Corporation (an Infineon company) or
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

#ifndef XIP_ENCRYPTION_H
#define XIP_ENCRYPTION_H
#include "mcuboot_smif_config.h"
#include "flash_map_backend.h"
#include "fault_injection_hardening.h"

#define ICACHE_INVALIDATE()                             \
({                                                      \
    /* Invalidate the cache */                          \
    ICACHE0->CMD = ICACHE0->CMD | ICACHE_CMD_INV_Msk;   \
                                                        \
    /*Wait for invalidation complete */                 \
    while (ICACHE0->CMD & ICACHE_CMD_INV_Msk);          \
})

/* This macro allows to Enable/Disble crypto capabilities
 * of SMIF block. Allowed parameters for x: Enable, Disable
*/
#define SMIF_SET_CRYPTO_MODE(x)                         \
({                                                      \
    bool last_state = Cy_SMIF_GetCryptoState(IFX_EPB_SMIF_HW, IFX_EPB_MEM_SLOT_CONFIG->slaveSelect); \
    if (Cy_SMIF_SetCrypto##x(IFX_EPB_SMIF_HW, IFX_EPB_MEM_SLOT_CONFIG->slaveSelect) \
        != CY_SMIF_SUCCESS) { FIH_PANIC; }              \
    ICACHE_INVALIDATE(); \
    last_state; \
})

static inline bool Cy_SMIF_GetCryptoState(SMIF_Type *base, cy_en_smif_slave_select_t slaveId)
{
    bool state = false;
    uint32_t device_idx;

    if (CY_SMIF_SUCCESS == Cy_SMIF_ConvertSlaveSlotToIndex(slaveId, &device_idx))
    {
        state = ((SMIF_DEVICE_IDX_CTL(base, device_idx) & SMIF_DEVICE_CTL_CRYPTO_EN_Msk) == SMIF_DEVICE_CTL_CRYPTO_EN_Msk);
    }

    return state;
}

static inline void SMIF_CRYPTO_RESTORE(bool st)
{
    if (st) {
        SMIF_SET_CRYPTO_MODE(Enable);
    } else {
        SMIF_SET_CRYPTO_MODE(Disable);
    }
}

#define SMIF_CRYPTO_SECTION(x) \
for (bool _flag = false, _state = SMIF_SET_CRYPTO_MODE(x); _flag == false; _flag = true, SMIF_CRYPTO_RESTORE(_state))


/**
 * @brief Sets key and initial vector in the SMIF crypto block.
 * @param key AES128 key.
 * @param iv initial vector.
 *
 */
void ifx_epb_set_xip_crypto_params(uint32_t * key, uint32_t * iv);

/**
 * @brief Sets SMIF encryption key and SMIF encryption initial vector for the image.
 * @param crypto_block_id crypto_block_id which is used for this region
 * @param image_index image number.
 * @param slot image slot number.
 * @param key AES128 key.
 * @param iv initial vector.
 *
 * @return
*       - 0 if SMIF crypto block has been initialized successfully
 */
int ifx_epb_set_xip_crypto_for_image_slot(uint32_t crypto_block_id,
                                              uint32_t image_index,
                                              uint32_t slot,
                                              uint32_t * key,
                                              uint32_t * iv);


/**
 * @brief Sets key and initial vector for the XIP region using SMIF crypto block.
 * @param crypto_block_id crypto_block_id which is used for this region
 * @param addr start address of region.
 * @param len region length.
 * @param key AES128 key.
 * @param iv initial vector.
 * 
 * @return
 *       - 0 if SMIF crypto block has been initialized successfully
 */
int ifx_epb_set_xip_crypto_region_params(uint32_t crypto_block_id,
                                           uint32_t addr,
                                           uint32_t len,
                                           uint32_t * key,
                                           uint32_t * iv);


/**
 * @brief Encrypts data from fap_src with off offset for fap_dst
 *        by SMIF crypto block and stores to encrypted data to the buf.
 * @param fap_src source flash area.
 * @param fap_dst flash area.
 * @param off     data offset in the flash areas.
 * @param buf     buffer to return encrypted data
 * @param sz      size of encrypted data
 *
 * @return
 *       - 0 if encryption procedure has been finished successfully
 */
int boot_encrypt_xip(const struct flash_area *fap_src, const struct flash_area *fap_dst,
                     const uint32_t off, const uint32_t sz, uint8_t *buf);


/**
 * @brief Read decrypted data from fap with off offset and stores decrypted data to the buf.
 * @param image_index current image index
 * @param fap         flash area.
 * @param off         data offset in the flash area.
 * @param buf         buffer to return decrypted data
 * @param sz          size of decrypted data
 *
 * @return
 *       - 0 if decryption procedure has been finished successfully
 */
int boot_decrypt_xip(int image_index,
                     const struct flash_area *fap,
                     const uint32_t off,
                     const uint32_t sz,
                     uint8_t *buf);

#endif /* !defined(XIP_ENCRYPTION_H) */
