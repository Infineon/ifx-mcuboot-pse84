/*******************************************************************************
 * File Name: flash_map_backend_platform.h
 * API of the platform memory interface
 *******************************************************************************
* Copyright 2023-2025, Cypress Semiconductor Corporation (an Infineon company) or
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

#pragma once

#include <assert.h>
#include "mcuboot_config.h"
#include "flash_map_backend.h"
#include "memorymap.h"

static inline const struct flash_area_interface* flash_area_get_api(uint8_t fd_id)
{
#if defined(CY_BOOT_USE_INTERNAL_SRAM)
    extern const struct flash_area_interface internal_sram_interface;
#endif /* CY_BOOT_USE_INTERNAL_SRAM */

#if defined(CY_BOOT_USE_INTERNAL_FLASH)
    extern const struct flash_area_interface internal_mem_interface;
#endif /* CY_BOOT_USE_INTERNAL_FLASH */

#if defined(CY_BOOT_USE_EXTERNAL_FLASH)
    extern const struct flash_area_interface external_mem_interface;
#endif /* CY_BOOT_USE_EXTERNAL_FLASH */

    const struct flash_area_interface* interface = NULL;

    switch (fd_id) {
#if defined(CY_BOOT_USE_INTERNAL_SRAM)
        case INTERNAL_S_SRAM:
        case INTERNAL_NS_SRAM:
            interface = &internal_sram_interface;
            break; 
#endif /* CY_BOOT_USE_INTERNAL_SRAM */
#if defined(CY_BOOT_USE_INTERNAL_FLASH)
        case INTERNAL_RRAM:
            interface = &internal_mem_interface;
            break;
#endif /* CY_BOOT_USE_INTERNAL_FLASH */

#if defined(CY_BOOT_USE_EXTERNAL_FLASH)
#if defined(CY_BOOT_USE_EXTERNAL_S_FLASH)
        case EXTERNAL_S_FLASH:
            interface = &external_mem_interface;
            break;
#endif /* CY_BOOT_USE_EXTERNAL_S_FLASH */

#if defined(CY_BOOT_USE_EXTERNAL_NS_FLASH)
        case EXTERNAL_NS_FLASH:
            interface = &external_mem_interface;
            break;
#endif /* CY_BOOT_USE_EXTERNAL_NS_FLASH */
#endif /* CY_BOOT_USE_EXTERNAL_FLASH */

        default:
            assert(false);
            interface = NULL;
            break;
    }

    return interface;
}
