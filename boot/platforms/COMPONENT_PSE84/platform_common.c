/******************************************************************************
 * File Name: platform_common.c
 *
 *******************************************************************************
* Copyright 2024-2025, Cypress Semiconductor Corporation (an Infineon company)
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
#include "platform_init.h"
#include "bootutil/bootutil_log.h"
#include "cybsp.h"

#if defined(CY_BOOT_USE_EXTERNAL_FLASH)
    #include "cycfg_qspi_memslot.h"
#endif

#include "cy_retarget_io.h"

#if MCUBOOT_LOG_LEVEL != MCUBOOT_LOG_LEVEL_OFF
static cy_stc_scb_uart_context_t    CYBSP_DEBUG_UART_context;           /** UART context */
static mtb_hal_uart_t               CYBSP_DEBUG_UART_hal_obj;           /** Debug UART HAL object  */
#endif /* MCUBOOT_LOG_LEVEL != MCUBOOT_LOG_LEVEL_OFF */

uintptr_t platform_remap_address(const uintptr_t addr)
{
    uintptr_t remap_addr = addr;

    /* SRAM Address */
#if defined(CY_SRAM_CBUS_BASE) || defined(CY_SOCMEM_RAM_CBUS_BASE) \
    || defined(CY_XIP_PORT0_CBUS_BASE) || defined(CY_RRAM_CBUS_BASE)
    uint32_t offset = 0;

    if ((addr >= CY_SRAM_BASE) &&
        (addr < (CY_SRAM_BASE + CY_SRAM_SIZE))) {
        offset = addr - CY_SRAM_BASE;
        remap_addr = CY_SRAM_CBUS_BASE + offset;
    } /* SOCMEM Address */
    else if ((addr >= CY_SOCMEM_RAM_BASE) &&
        (addr < (CY_SOCMEM_RAM_BASE + CY_SOCMEM_RAM_SIZE))) {

        offset = addr - CY_SOCMEM_RAM_BASE;
        remap_addr = CY_SOCMEM_RAM_CBUS_BASE + offset;
    }
    /* XIP is mapped with offset */
    else if ((addr >= CY_XIP_PORT0_BASE) &&
        (addr < (CY_XIP_PORT1_BASE + CY_XIP_PORT1_SIZE))) {
        offset = addr - CY_XIP_PORT0_BASE;
        remap_addr =  CY_XIP_PORT0_CBUS_BASE + offset;
    }
    else if ((addr >= CY_RRAM_BASE) &&
        (addr < (CY_RRAM_BASE + CY_RRAM_SIZE))) {
        offset = addr - CY_RRAM_BASE;
        remap_addr = CY_RRAM_CBUS_BASE + offset;
    }
    /* no remapping, addr not in range */
    else {
        remap_addr = addr;
    }
#endif
    
    return remap_addr;
}

#if MCUBOOT_LOG_LEVEL != MCUBOOT_LOG_LEVEL_OFF
cy_rslt_t platform_debug_log_init(void)
{
    cy_rslt_t result;

    /* Debug UART init */
    result = (cy_rslt_t)Cy_SCB_UART_Init(CYBSP_DEBUG_UART_HW, &CYBSP_DEBUG_UART_config, &CYBSP_DEBUG_UART_context);

    Cy_SCB_UART_Enable(CYBSP_DEBUG_UART_HW);

    if (result == CY_RSLT_SUCCESS)
    {
        /* Setup the HAL UART */
        result = mtb_hal_uart_setup(&CYBSP_DEBUG_UART_hal_obj, &CYBSP_DEBUG_UART_hal_config, &CYBSP_DEBUG_UART_context, NULL);
    }

    if (result == CY_RSLT_SUCCESS)
    {
        result = cy_retarget_io_init(&CYBSP_DEBUG_UART_hal_obj);
    }

    return result;
}

void platform_debug_log_deinit(void)
{
    /* Deinitialize retarget-io */
    cy_retarget_io_deinit();
}
#endif /* MCUBOOT_LOG_LEVEL != MCUBOOT_LOG_LEVEL_OFF */

cy_rslt_t platform_hw_init(void)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;
#if defined(CY_BOOT_USE_EXTERNAL_FLASH)
    /* Enable Power Domain 1 if SMIF is used */
    Cy_System_EnablePD1();
#endif /* defined(CY_BOOT_USE_EXTERNAL_FLASH) */

    return result;
}

void platform_hw_deinit(void)
{

}

cy_rslt_t platform_deep_sleep_prepare(void)
{
    // Ensure the system is set to deep sleep mode
    cy_en_syspm_deep_sleep_mode_t mode = Cy_SysPm_GetSysDeepSleepMode();
    if (CY_SYSPM_MODE_DEEPSLEEP != mode) {
        cy_en_syspm_status_t rc = Cy_SysPm_SetSysDeepSleepMode(CY_SYSPM_MODE_DEEPSLEEP);
        if (CY_SYSPM_SUCCESS != rc) {
            return CY_RSLT_TYPE_ERROR;
        }
    }

#if MCUBOOT_LOG_LEVEL != MCUBOOT_LOG_LEVEL_OFF
    // Manage the UART peripheral during transitions into deep sleep
    static cy_stc_syspm_callback_params_t syspmSleepAppParams;
    static cy_stc_syspm_callback_t syspmAppSleepCallbackHandler =
        {
            Cy_SCB_UART_DeepSleepCallback, CY_SYSPM_DEEPSLEEP, 0u, &syspmSleepAppParams,
            NULL, NULL, 0};

    syspmSleepAppParams.base = CYBSP_DEBUG_UART_hal_obj.base;
    syspmSleepAppParams.context = (void *)&(CYBSP_DEBUG_UART_context);
    
    if (!Cy_SysPm_RegisterCallback(&syspmAppSleepCallbackHandler)) {
        return CY_RSLT_TYPE_ERROR;
    }
#endif /* MCUBOOT_LOG_LEVEL != MCUBOOT_LOG_LEVEL_OFF */

    return CY_RSLT_SUCCESS;
}
