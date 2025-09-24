/*******************************************************************************
 * File Name: set_img_ok.c
 *
 *******************************************************************************
* Copyright 2023-2024, Cypress Semiconductor Corporation (an Infineon company)
* or an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
*
* This software, including source code, documentation and related
* materials ("Software") is owned by Cypress Semiconductor Corporation
* or one of its affiliates ("Cypress") and is protected by and subject to
* worldwide patent protection (United States and foreign),
* United States copyright laws and international treaty provisions.
* Therefore, you may use this Software only as provided in the license
* agreement accompanying the software package from which you
* obtained this Software ("EULA").
* If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
* non-transferable license to copy, modify, and compile the Software
* source code solely for use in connection with Cypress's
* integrated circuit products.  Any reproduction, modification, translation,
* compilation, or representation of this Software except as specified
* above is prohibited without the express written permission of Cypress.
*
* Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
* reserves the right to make changes to the Software without notice. Cypress
* does not assume any liability arising out of the application or use of the
* Software or any product or circuit described in the Software. Cypress does
* not authorize its products for use in any products where a malfunction or
* failure of the Cypress product may reasonably be expected to result in
* significant property damage, injury or death ("High Risk Product"). By
* including Cypress's product in a High Risk Product, the manufacturer
* of such system or application assumes all risk of such use and in doing
* so agrees to indemnify Cypress against all liability.
*******************************************************************************/

#if !(SWAP_DISABLED) && defined(UPGRADE_IMAGE)

#include "set_img_ok.h"
#include "cy_rram.h"
#include "mcuboot_smif_config.h"
#include "cy_smif.h"
#if defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY)
#include "xip_encryption.h"
#endif /* defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY) */


/**
 * @brief Function reads value of img_ok flag from address.
 *
 * @param address - address of img_ok flag in primary img trailer
 * @return int - value at address
 */
#if defined CY_BOOT_USE_EXTERNAL_FLASH
CY_RAMFUNC_BEGIN
#endif /* CY_BOOT_USE_EXTERNAL_FLASH */
static int read_img_ok_value(uint32_t address)
{
    int img_ok = IMG_OK_SET_UNDEFINED;

#if defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY)
    SMIF_SET_CRYPTO_MODE(Disable);
#endif /* MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY */

    img_ok = (int)*((uint8_t *)address);

#if defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY)
    SMIF_SET_CRYPTO_MODE(Enable);
#endif /* MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY */

    return img_ok;
}
#if defined CY_BOOT_USE_EXTERNAL_FLASH
CY_RAMFUNC_END
#endif /* CY_BOOT_USE_EXTERNAL_FLASH */


/**
 * @brief Function sets img_ok flag value to primary image trailer.
 *
 * @param address - address of img_ok flag in primary img trailer
 * @param value - value corresponding to img_ok set
 *
 * @return - operation status. 0 - set succesfully, -1 - failed to set.
 */
/* If the app is executed from external memory then
 * this has to be located in RAM */
#if defined CY_BOOT_USE_EXTERNAL_FLASH
CY_RAMFUNC_BEGIN
#endif /* CY_BOOT_USE_EXTERNAL_FLASH */
static int write_img_ok_value(uint32_t address, uint8_t value)
{
    int rc = IMG_OK_SET_FAILED;

#if defined CY_BOOT_USE_EXTERNAL_FLASH
    {
        const uint32_t trailer_row_abs_addr = address & ~(MEMORY_ALIGN-1);
        const uint32_t trailer_row_addr = (address - CY_XIP_PORT0_BASE) & ~(MEMORY_ALIGN-1);
        uint8_t trailer_ram_buff[MEMORY_ALIGN];

        for(uint32_t i = 0; i < MEMORY_ALIGN; i++) {
            trailer_ram_buff[i] = *(((uint8_t*)trailer_row_abs_addr) + i);
        }

        trailer_ram_buff[address & (MEMORY_ALIGN-1)] = value;

        if (CY_SMIF_SUCCESS == Cy_SMIF_MemEraseSector(IFX_EPB_SMIF_HW, IFX_EPB_MEM_SLOT_CONFIG,
                                                      trailer_row_addr, MEMORY_ALIGN, &ifx_epb_smif_context))
        {
            if (CY_SMIF_SUCCESS == Cy_SMIF_MemWrite(IFX_EPB_SMIF_HW, IFX_EPB_MEM_SLOT_CONFIG, trailer_row_addr,
                                                    trailer_ram_buff, MEMORY_ALIGN, &ifx_epb_smif_context)) {
                rc = IMG_OK_SET_SUCCESS;
            }
        }
    }

#else
    cy_en_rram_status_t rram_status = CY_RRAM_BAD_PARAM;


    rram_status = Cy_RRAM_WriteByteArray(RRAMC0, address, &value, 1U);
    if(rram_status == CY_RRAM_SUCCESS)
    {
        rc = IMG_OK_SET_SUCCESS;
    }
    else
    {
        rc = IMG_OK_SET_FAILED;
    }
#endif /* CY_BOOT_USE_EXTERNAL_FLASH */

    return rc;
}
#if defined CY_BOOT_USE_EXTERNAL_FLASH
CY_RAMFUNC_END
#endif /* CY_BOOT_USE_EXTERNAL_FLASH */


/**
 * @brief Public function to confirm that upgraded application is operable
 * after swap. Should be called from main code of user application.
 * It sets mcuboot flag img_ok in primary (boot) image trailer.
 * MCUBootApp checks img_ok flag at first reset after upgrade and
 * validates successful swap.
 *
 * @param address - address of img_ok flag in primary img trailer
 * @param value - value corresponding to img_ok set
 *
 * @return - operation status. 1 - already set, 0 - set succesfully,
 *                              -1 - failed to set.
 */
int set_img_ok(uint32_t address, uint8_t value)
{
    int32_t rc = IMG_OK_SET_FAILED;

    if (read_img_ok_value(address) != value) {
        rc = write_img_ok_value(address, value);
    }
    else {
        rc = IMG_OK_ALREADY_SET;
    }

    return rc;
}

#endif /* !(SWAP_DISABLED) && defined(UPGRADE_IMAGE) */
