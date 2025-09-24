/******************************************************************************
 * File Name: platform_init.c
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

#include "platform_init.h"
#include "bootutil/bootutil.h"
#include "bootutil/bootutil_log.h"

#include "cybsp.h"
#if defined(COMPONENT_MCUBOOT_RNG)
#include "boot_rng.h"
#endif /* defined(COMPONENT_MCUBOOT_RNG) */



#if defined(CY_BOOT_USE_EXTERNAL_FLASH)
    #include "cycfg_qspi_memslot.h"
    #include "cybsp_hw_config.h"
    #include "mcuboot_smif_config.h"
    #include "cy_smif.h"
    #include "cy_smif_memslot.h"
    #include "cy_sysclk.h"
#endif

#include "sau_config.h"

#ifdef STAGE_RAM_APPS
#include "stage_ram_app.h"
#endif

#define SMIF_DATA_OCTAL         (0x08U)
#define SMIF_DATA_QUAD          (0x04U)

#if !defined(DATA_WIDTH_PINS)
#define DATA_WIDTH_PINS SMIF_DATA_QUAD
#endif


#ifdef SMIF_JEDEC_STANDARD_DEVICE_RESET_SUPPORT

#if defined(__GNUC__) || defined(__ARMCC_VERSION)
__attribute__((section(".cy_sram_code")))
#elif defined(__ICCARM__)
#pragma location=".cy_sram_code"
#endif
void Cy_SMIF_Reset_Memory(SMIF_Type *base, cy_en_smif_slave_select_t slaveSelect)
{

    /* RESET SEQUENCE - JESD252.01 - START */
    Cy_GPIO_Pin_FastInit(SMIF_SS_PORT(base, slaveSelect), SMIF_SS_PIN(base, slaveSelect), CY_GPIO_DM_STRONG, 1U, HSIOM_SEL_GPIO);
    Cy_GPIO_Pin_FastInit(SMIF_DQ0_PORT(base), 0U, CY_GPIO_DM_STRONG, 1U, HSIOM_SEL_GPIO);

    for(int i=0; i <4;i++)
    {
        Cy_GPIO_Inv(SMIF_DQ0_PORT(base), 0U);
        Cy_GPIO_Inv(SMIF_SS_PORT(base, slaveSelect), SMIF_SS_PIN(base, slaveSelect));
        Cy_SysLib_Delay(1);
        Cy_GPIO_Inv(SMIF_SS_PORT(base, slaveSelect), SMIF_SS_PIN(base, slaveSelect));
        Cy_SysLib_Delay(1);
    }
    /* RESET SEQUENCE - JESD252.01 - END */

    /* Mux the pins back to SMIF functionality */
    Cy_GPIO_Pin_FastInit(SMIF_SS_PORT(base, slaveSelect), SMIF_SS_PIN(base, slaveSelect), CY_GPIO_DM_STRONG, 1U, HSIOM_SEL_ACT_0);
    Cy_GPIO_Pin_FastInit(SMIF_DQ0_PORT(base), 0U, CY_GPIO_DM_STRONG, 1U, HSIOM_SEL_ACT_15);

}
#endif /* SMIF_JEDEC_STANDARD_DEVICE_RESET_SUPPORT */

#if defined(__GNUC__) || defined(__ARMCC_VERSION)
__attribute__((section(".cy_sram_code")))
#elif defined(__ICCARM__)
#pragma location=".cy_sram_code"
#endif
static cy_rslt_t platform_memory_init(void)
{
#if defined(CY_BOOT_USE_EXTERNAL_FLASH) || defined(STAGE_RAM_APPS)
    cy_rslt_t rc = CY_RSLT_TYPE_ERROR;
    cy_en_smif_status_t smif_status = CY_SMIF_GENERAL_ERROR;

    /* Create copy of smif config in RAM to have access to it during
     * thesmif reconfiguration. Required if the bootloader is
     * in the external flash */
    static cy_stc_smif_config_t smif_config_ram = { 0 };
    (void)memcpy(&smif_config_ram, &IFX_EPB_SMIF_CONFIG, sizeof(cy_stc_smif_config_t));

    do {

        /* Enable Power Domain 1 if SMIF is used */
        Cy_System_EnablePD1();

#if !defined(MCUBOOT_SMIF_CACHE_DISABLE)
        bool smif_cache_en_status = true;

        /* Deinit previous configuration of SMIF block */
        smif_status = Cy_SMIF_IsCacheEnabled(IFX_EPB_SMIF_CACHE_BLOCK, &smif_cache_en_status);
        if (CY_SMIF_SUCCESS != smif_status) {
            break;
        }

        if (smif_cache_en_status) {
            cy_stc_smif_cache_config_t cache_config =
            {
                 .enabled = true, /* Enable SMIF cache */
                 .cache_retention_on = false,
                 .cache_region_0 = {
                                       .enabled = true,
                                       .start_address = 0x70000000,
                                       .end_address = 0x74000000,
                                       .cache_attributes = CY_SMIF_CACHEABLE_WB_RA
                                   }
            };

            if (CY_SMIF_SUCCESS != Cy_SMIF_Clean_And_Invalidate_All_Cache(IFX_EPB_SMIF_CACHE_BLOCK)) {
                break;
            }

            if (CY_SMIF_SUCCESS != Cy_SMIF_InitCache(IFX_EPB_SMIF_CACHE_BLOCK, &cache_config)) {
                break;
            }
        }
#endif /* !defined(MCUBOOT_SMIF_CACHE_DISABLE) */

        /* Deinit previous configuration of SMIF block */
        Cy_SMIF_Disable(IFX_EPB_SMIF_HW);
        Cy_SMIF_DeInit(IFX_EPB_SMIF_HW);

        /* Reset SMIF memory before initialization */
        Cy_SMIF_Reset_Memory(IFX_EPB_SMIF_HW, IFX_EPB_MEM_SLOT_CONFIG->slaveSelect);

        /* Init SMIF block */
        smif_status = Cy_SMIF_Init(IFX_EPB_SMIF_HW,
                                   &smif_config_ram,
                                   IFX_EPB_SMIF_TIMEOUT_MS,  /* Timeout for all blocking functions of the SMIF driver */
                                   &ifx_epb_smif_context);

        if (CY_SMIF_SUCCESS != smif_status) {
            break;
        }

        Cy_SMIF_SetDataSelect(IFX_EPB_SMIF_HW,
                              IFX_EPB_MEM_SLOT_CONFIG->slaveSelect,
                              IFX_EPB_MEM_SLOT_CONFIG->dataSelect);

        /* Enable the operation of the SMIF block */
        Cy_SMIF_Enable(IFX_EPB_SMIF_HW, &ifx_epb_smif_context);

        smif_status = Cy_SMIF_MemInit(IFX_EPB_SMIF_HW,
                                      &IFX_EPB_MEM_BLOCK_CONFIG,
                                      &ifx_epb_smif_context);

        if (smif_status != CY_SMIF_SUCCESS) {
            break;
        }

        if ((IFX_EPB_MEM_SLOT_CONFIG->deviceCfg->readStsRegOeCmd != 0) &&
            (IFX_EPB_MEM_SLOT_CONFIG->deviceCfg->writeStsRegOeCmd != 0)) {

            /* OCTAL mode */
            cy_en_smif_data_rate_t data_rate = IFX_EPB_MEM_SLOT_CONFIG->deviceCfg->readCmd->dataRate;

            /* Enable Octal mode */
            smif_status = Cy_SMIF_MemOctalEnable(IFX_EPB_SMIF_HW,
                                                 IFX_EPB_MEM_SLOT_CONFIG,
                                                 data_rate,
                                                 &ifx_epb_smif_context);

            if (smif_status != CY_SMIF_SUCCESS) {
                 break;
            }

            if (CY_SMIF_DDR == data_rate) {
                /* Disable IP */
                Cy_SMIF_Disable(IFX_EPB_SMIF_HW);

                /* Set new Capture mode */
                smif_status = Cy_SMIF_SetRxCaptureMode(IFX_EPB_SMIF_HW,
                                                       CY_SMIF_SEL_XSPI_HYPERBUS_WITH_DQS,
                                                       IFX_EPB_MEM_SLOT_CONFIG->slaveSelect);
                if (smif_status != CY_SMIF_SUCCESS) {
                    break;
                }

                Cy_SMIF_Enable(IFX_EPB_SMIF_HW, &ifx_epb_smif_context);

                /* Switch the SMIF to XIP mode */
                Cy_SMIF_SetMode(IFX_EPB_SMIF_HW, CY_SMIF_MEMORY);
                BOOT_LOG_DBG("Octal memory enabled");
                BOOT_LOG_DBG("XIP: Enabled");
            }
        }
        else
        {
            /* QUAD mode */
            bool qe_status = false;
            smif_status = Cy_SMIF_MemIsQuadEnabled(IFX_EPB_SMIF_HW,
                                                   IFX_EPB_MEM_SLOT_CONFIG,
                                                   &qe_status,
                                                   &ifx_epb_smif_context);

            if (smif_status != CY_SMIF_SUCCESS) {
                break;
            }
            /* If not enabled, enable quad mode */
            if (!qe_status)  {
                /* Enable Quad mode */
                smif_status = Cy_SMIF_MemQuadEnable(IFX_EPB_SMIF_HW,
                                                    IFX_EPB_MEM_SLOT_CONFIG,
                                                    &ifx_epb_smif_context);
                if (smif_status != CY_SMIF_SUCCESS) {
                    break;
                }
            }
            /* Switch the SMIF to XIP mode */
            Cy_SMIF_SetMode(IFX_EPB_SMIF_HW, CY_SMIF_MEMORY);
            BOOT_LOG_DBG("Quad memory enabled");
            BOOT_LOG_DBG("XIP: Enabled");
        }

        rc = CY_RSLT_SUCCESS;

    } while (false);


    if (rc == CY_RSLT_SUCCESS) {
        BOOT_LOG_INF("External Memory initialized and switched to XIP");
    } else {
        BOOT_LOG_ERR("External Memory initialization FAILED: 0x%08" PRIx32, (uint32_t)rc);
    }

    return rc;
#else
    return CY_RSLT_SUCCESS;
#endif /* defined(CY_BOOT_USE_EXTERNAL_FLASH) || defined(STAGE_RAM_APPS) */
}

static cy_rslt_t platform_ram_app_init()
{
#ifdef STAGE_RAM_APPS
    cy_rslt_t rc = CY_RSLT_SUCCESS;
    ifx_stg_app_rslt_type_t stage_ram_app_result = IFX_STG_APP_RSLT_GEN_ERROR;

    BOOT_LOG_INF("Check staged SE RT Services upgrade...");

        stage_ram_app_result = stage_ram_app_handler();

        if (stage_ram_app_result == IFX_STG_APP_RSLT_UPGRADED) {
            BOOT_LOG_INF("SE RT Services upgraded succesfully.");
        } else if (stage_ram_app_result == IFX_STG_APP_RSLT_NO_IMAGE) {
            BOOT_LOG_DBG("No staged SE RT Services found");
        } else {
            BOOT_LOG_ERR(
                "SE RT Services upgraded failed with error code: 0x%08" PRIx32, (uint32_t)stage_ram_app_result);
        }

    return rc;
#else
    return CY_RSLT_SUCCESS;
#endif /* STAGE_RAM_APPS */
}

cy_rslt_t platform_init(void)
{
    cy_rslt_t rc = CY_RSLT_TYPE_ERROR;

    sau_init();
#if defined(COMPONENT_MCUBOOT_RNG)
    if (boot_trng_init()) {
    	rc = CY_RSLT_SUCCESS;
    }

    if (rc == CY_RSLT_SUCCESS)
#endif /* defined(COMPONENT_MCUBOOT_RNG) */
    {
        rc = platform_memory_init();
    }

    if (rc == CY_RSLT_SUCCESS)
    {
        rc = platform_ram_app_init();
    }

    return rc;
}

void platform_deinit(void)
{
    /* Init the smif cache after launching OEM app */
#if !defined(MCUBOOT_SMIF_CACHE_DISABLE) && defined(CY_BOOT_USE_EXTERNAL_FLASH)

    cy_stc_smif_cache_config_t cache_config =
    {
            .enabled = true, /* Enable SMIF cache */
            .cache_retention_on = false,
            .cache_region_0 = {
                                .enabled = true,
                                .start_address = 0x70000000,
                                .end_address = 0x74000000,
                                .cache_attributes = CY_SMIF_CACHEABLE_WB_RA
                              }
    };

    if (CY_SMIF_SUCCESS != Cy_SMIF_InitCache(IFX_EPB_SMIF_CACHE_BLOCK, &cache_config))
    {
        BOOT_LOG_DBG("SMIF Cache initialization failed");
    }
#endif /* !defined(MCUBOOT_SMIF_CACHE_DISABLE) && defined(CY_BOOT_USE_EXTERNAL_FLASH) */
}
