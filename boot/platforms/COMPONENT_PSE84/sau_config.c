/******************************************************************************
 * File Name: sau_config.c
 *
 *******************************************************************************
* Copyright 2023-2025, Cypress Semiconductor Corporation (an Infineon company)
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

#include "cy_device.h"
#include "partition_edge.h"
#include "sau_config.h"

/* SAU region number for MMIO NS M33SYS */
#define MMIO_NS_M33SYS_SAU_IDX    (0x00U)
/* SAU region number for non-secure sflash */
#define NON_SEC_SFLASH_NS_SAU_IDX (0x01U)


/*******************************************************************************
 * Function Name: sau_init
 ********************************************************************************
 * Initialize SAU for NS MMIO M33SYS range and non-secure sflash region.
 * It is needed for correct access to the NS addresses of peripheral registers
 * and non-secure sflash from the secure world.
 *
 *******************************************************************************/
void sau_init(void)
{
    TZ_SAU_Disable();
    __DSB(); /* Force Memory Writes before continuing */
    __ISB(); /* Flush and refill pipeline with updated permissions */

    /* Required  for correct access to Active PC mirror register from the secure world. 
     * The Active PC mirror register is used in the RRAM API.
     */
    SAU->RNR  = _VAL2FLD(SAU_RNR_REGION, MMIO_NS_M33SYS_SAU_IDX);
    SAU->RBAR = ((uint32_t)MMIO_NS_M33SYS_START) & SAU_RBAR_BADDR_Msk;
    SAU->RLAR = (((uint32_t)MMIO_NS_M33SYS_START + (uint32_t)MMIO_M33SYS_SIZE - 1U) &
                  SAU_RLAR_LADDR_Msk) |                    /* Limit address of SAU region */
                  _VAL2FLD(SAU_RLAR_ENABLE, 1);            /* 1 - Enable SAU region */

    TZ_SAU_Enable();

    __DSB(); /* Force Memory Writes before continuing */
    __ISB(); /* Flush and refill pipeline with updated permissions */
}
