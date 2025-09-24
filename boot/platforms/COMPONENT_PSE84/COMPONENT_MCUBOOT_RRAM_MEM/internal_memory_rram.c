/*******************************************************************************
 * File Name: internal_memory_rram.c
 * Implementation of base functions to work with RRAM memory
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
#include "bootutil.h"
#include "cy_rram.h"
#include <stdint.h>

#include "flash_map_backend_platform.h"

static uint32_t get_base_address(uint8_t fa_device_id)
{
    return flash_devices[fa_device_id].address;
}

static uint32_t get_align_size(uint8_t fa_device_id)
{
    return flash_devices[fa_device_id].erase_size;
}

static uint32_t get_min_erase_size(uint8_t fa_device_id)
{
    return flash_devices[fa_device_id].erase_size;
}

static uint8_t get_erase_val(uint8_t fa_device_id)
{
    return flash_devices[fa_device_id].erase_val;
}
static int read(uint8_t fa_device_id, uintptr_t addr, void *dst, uint32_t len)
{
    (void) fa_device_id;

    int rc = -1;
    cy_en_rram_status_t rram_status = CY_RRAM_BAD_PARAM;

    if (0 != len && NULL != dst)
    {
        rram_status = Cy_RRAM_NvmReadByteArray(
                        RRAMC0, (uint32_t) addr, (uint8_t *)dst, (uint32_t)len);
        if(rram_status == CY_RRAM_SUCCESS)
        {
            rc = 0;
        }
    }

    return rc;
}

static int write(uint8_t fa_device_id, uintptr_t addr, const void *src, uint32_t len)
{
    (void) fa_device_id;

    int rc = -1;
    cy_en_rram_status_t rram_status = CY_RRAM_BAD_PARAM;


    if (0 != len && NULL != src)
    {
        rram_status = Cy_RRAM_WriteByteArray(RRAMC0, 
                        (uint32_t)addr, (const uint8_t *)src, (uint32_t)len);
        if(rram_status == CY_RRAM_SUCCESS)
        {
            rc = 0;
        }
    }

    return rc;
}

static int erase(uint8_t fa_device_id, uintptr_t addr, uint32_t len)
{
    (void) fa_device_id;

    int rc = -1;
    cy_en_rram_status_t rram_status = CY_RRAM_SUCCESS;
    
    uint8_t * data = malloc(len);
    if (data != NULL) {

        (void)memset(data, 0, len);

        if (len > 0u)
        {
            /* It is erase sector-only
            *
            * There is no power-safe way to erase flash partially
            * this leads upgrade slots have to be at least
            * eraseSectorSize far from each other;
            */

            rram_status = Cy_RRAM_WriteByteArray(RRAMC0, 
                        (uint32_t)addr, (const uint8_t *) data, (uint32_t)len);
            if(rram_status == CY_RRAM_SUCCESS)
            {
                rc = 0;
            }
        }

        free(data);
    }
    else {
        /* do nothing */
    }

    return rc;
}

static int open(uint8_t fa_device_id)
{
    (void) fa_device_id;

    return 0;
}

static void close(uint8_t fa_device_id)
{
    (void) fa_device_id;
}

const struct flash_area_interface internal_mem_interface = 
{
    .open             = &open,
    .close            = &close,
    .read             = &read,
    .write            = &write,
    .erase            = &erase,
    .get_erase_val    = &get_erase_val,
    .get_erase_size   = &get_min_erase_size,
    .get_align_size   = &get_align_size,
    .get_base_address = &get_base_address
};
