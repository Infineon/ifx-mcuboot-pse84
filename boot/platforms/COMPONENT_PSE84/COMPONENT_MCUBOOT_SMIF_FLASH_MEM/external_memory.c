/*******************************************************************************
 * File Name: external_memory.c
 * Implementation of base functions to work with external memory.
 * 
 *******************************************************************************
* Copyright 2024, Cypress Semiconductor Corporation (an Infineon company) or
* an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
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
#include <stdint.h>

#include "bootutil/bootutil.h"
#include "cy_rram.h"
#include "mcuboot_smif_config.h"
#include "cy_smif.h"
#include "memorymap.h"

static uint32_t get_base_address(uint8_t fa_device_id)
{
    uint32_t base_address = 0;
    switch (fa_device_id) {
#if defined(CY_BOOT_USE_EXTERNAL_S_FLASH)
        case EXTERNAL_S_FLASH:
            base_address = CY_XIP_PORT0_S_SBUS_BASE;
            break;
#endif /* CY_BOOT_USE_EXTERNAL_S_FLASH */

#if defined(CY_BOOT_USE_EXTERNAL_NS_FLASH)
        case EXTERNAL_NS_FLASH:
            base_address = CY_XIP_PORT0_NS_SBUS_BASE;
            break;
#endif /* CY_BOOT_USE_EXTERNAL_NS_FLASH */

        default:
            assert(false);
            break;
    }

    return base_address;
}

static uint32_t get_min_erase_size(uint8_t fa_device_id)
{
    (void)fa_device_id;

    return IFX_EPB_MEM_SLOT_CONFIG->deviceCfg->eraseSize;
}

static uint8_t get_erase_val(uint8_t fa_device_id)
{
    return flash_devices[fa_device_id].erase_val;
}

static uint32_t get_align_size(uint8_t fa_device_id)
{
    (void)fa_device_id;

#if !defined(MCUBOOT_SWAP_USING_STATUS)
    return sizeof(uint32_t);
#else
    return IFX_EPB_MEM_SLOT_CONFIG->deviceCfg->eraseSize;
#endif
}

static int read(uint8_t fa_device_id, uintptr_t addr, void *data, uint32_t len)
{
    (void)fa_device_id;
    memcpy(data, (uint8_t*)addr, len);
    return 0;
}

static int write(uint8_t fa_device_id, uintptr_t addr, const void *data,
                 uint32_t len)
{
    int rc = -1;
    uint32_t offset = addr - get_base_address(fa_device_id);
    if (CY_SMIF_SUCCESS == Cy_SMIF_MemWrite(IFX_EPB_SMIF_HW, IFX_EPB_MEM_SLOT_CONFIG, offset,
                                            data, len, &ifx_epb_smif_context)) {
        rc = 0;
    }

    return rc;
}

static int erase(uint8_t fa_device_id, uintptr_t addr, uint32_t size)
{
    int rc = -1;
    cy_en_smif_status_t smif_status = CY_SMIF_GENERAL_ERROR;

    if (size > 0u) {
        uint32_t offset = addr - get_base_address(fa_device_id);
        smif_status = Cy_SMIF_MemEraseSector(IFX_EPB_SMIF_HW, IFX_EPB_MEM_SLOT_CONFIG,
                                                              offset, size, &ifx_epb_smif_context);
        if (CY_SMIF_SUCCESS == smif_status) {
            rc = 0;
        }
    }

    return rc;
}

static int open(uint8_t fa_device_id)
{
    (void)fa_device_id;

    return 0;
}

static void close(uint8_t fa_device_id)
{
    (void)fa_device_id;
}

const struct flash_area_interface external_mem_interface = {
    .open = &open,
    .close = &close,
    .read = &read,
    .write = &write,
    .erase = &erase,
    .get_erase_val = &get_erase_val,
    .get_erase_size = &get_min_erase_size,
    .get_align_size = &get_align_size,
    .get_base_address = &get_base_address};
