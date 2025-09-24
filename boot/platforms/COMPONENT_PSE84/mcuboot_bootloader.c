/******************************************************************************
 * File Name: mcuboot_bootloader.c
 *
 *******************************************************************************
* Copyright 2025, Cypress Semiconductor Corporation (an Infineon company)
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

#include <inttypes.h>

#include "bootutil/bootutil.h"
#include "bootutil_priv.h"
#include "bootutil/bootutil_log.h"
#include "bootutil/fault_injection_hardening.h"
#include "bootutil/image.h"
#include "bootutil/ramload.h"
#include "cleanup.h"
#include "cy_pdl.h"
#include "cy_wdt.h"
#include "cybsp.h"

#if defined(MCUBOOT_BUILT_IN_KEYS) || defined (MCUBOOT_HW_KEY) || defined (MCUBOOT_USE_PSA_CRYPTO)
#include "crypto.h"
#endif

#include "platform_init.h"
#include "memorymap.h"
#if defined(COMPONENT_MCUBOOT_XIP_ENC)
#include "xip_encryption.h"
#endif /* defined(COMPONENT_MCUBOOT_XIP_ENC) */

#if defined (MCUBOOT_WATCHDOG_ENABLED)

/* WDT time out for reset mode, in milliseconds. */
#if !defined(WDT_TIME_OUT_MS)
#define WDT_TIME_OUT_MS                   (4000u)
#endif /* !defined(WDT_TIME_OUT_MS) */

/* PILO frequency in Hz */
#define PILO_FREQ_HZ                      (32768u)

/* Number if bits used for comparison */
#define NUM_MATCH_BITS                    (14u)

/* Match count = Desired interrupt interval in seconds x PILO Frequency in Hz */
#define WDT_MATCH_COUNT                   ((WDT_TIME_OUT_MS/1000) * PILO_FREQ_HZ)

#endif /* MCUBOOT_WATCHDOG_ENABLED */

#define BOOT_MSG_FINISH              \
    "MCUBoot Bootloader finished.\r\n" \
    "[INF] Deinitializing hardware..."

#include "timestamp.h"

#define DELAY_BEFORE_DEEP_SLEEP_MS 1000

/*Specific for the core and the silicon vendor*/
#define VECTOR_TABLE_ALIGNMENT (0x400U)

#if defined (MCUBOOT_WATCHDOG_ENABLED)
/**
 ******************************************************************************
 * Function Name: initialize_wdt
 ******************************************************************************
 * Summary:
 * Configure the WDT instance
 *
 *
 *****************************************************************************/
static void initialize_wdt()
{
   /* Step 1- Unlock WDT */
   Cy_WDT_Unlock();

   /* Step 2- Init WDT with default parameters */
   Cy_WDT_Init();

   /* Step 3- Write the number of bit used for compare */
   Cy_WDT_SetMatchBits(NUM_MATCH_BITS);

   /* Step 4- Write match value */
   Cy_WDT_SetMatch(WDT_MATCH_COUNT);

   /* Step 5- Clear match event interrupt, if any */
   Cy_WDT_ClearInterrupt();

   /* Step 6- Reset WDT counter */
   Cy_WDT_ResetCounter();

   /* Step 6- Enable WDT */
   Cy_WDT_Enable();

   /* Step 7- Lock WDT configuration */
   Cy_WDT_Lock();
}
#endif /* MCUBOOT_WATCHDOG_ENABLED */


/******************************************************************************
 * Function Name: calc_app_addr
 ******************************************************************************
 * Summary:
 * Calculate start address of user application.
 *
 * Parameters:
 *  virtual_address - application virtual address
 *
 *  rsp - provided by the boot loader code; indicates where to jump
 *          to execute the main image;
 *
 *  app_address - physical address of application;
 *
 * Return:
 * fih_int
 *
 *****************************************************************************/
static inline __attribute__((always_inline)) 
fih_int calc_app_addr(uintptr_t virtual_address, 
                        const struct boot_rsp *rsp, fih_uint *app_address)
{
    fih_int fih_rc = FIH_FAILURE;

    uintptr_t image_base = platform_remap_address(virtual_address);

#if defined(MCUBOOT_RAM_LOAD)
    if (IS_RAM_BOOTABLE(rsp->br_hdr) == true) {
        if ((UINT32_MAX - rsp->br_hdr->ih_hdr_size) >= image_base) {
            *app_address =
                fih_uint_encode(image_base + rsp->br_hdr->ih_hdr_size);
            fih_rc = FIH_SUCCESS;
        }
    } else
#endif
    {
        if (((UINT32_MAX - rsp->br_image_off) >= image_base) &&
            ((UINT32_MAX - rsp->br_hdr->ih_hdr_size) >=
             (image_base + rsp->br_image_off))) {
            *app_address = fih_uint_encode(image_base + rsp->br_image_off +
                                           rsp->br_hdr->ih_hdr_size);
            fih_rc = FIH_SUCCESS;
        }
    }

    FIH_RET(fih_rc);
}


/******************************************************************************
 * Function Name: handle_error
 ******************************************************************************
 * Summary:
 * User defined error handling function.
 *
 *****************************************************************************/
static void handle_error(void)
{
    BOOT_LOG_ERR("handle_error!");
    /* Loop forever... */
    LOOP_FOREVER();
}

#if defined(MULTIPLE_EXECUTABLE_RAM_REGIONS)
/*******************************************************************************
 * Function Name: boot_get_image_exec_ram_info
 *******************************************************************************
 * Summary:
 * MCUBoot library port API for ram boot feature
 *
 ******************************************************************************/
int boot_get_image_exec_ram_info(uint32_t image_id, uint32_t *exec_ram_start,
                                 uint32_t *exec_ram_size)
{
    int rc = -1;

    if(image_id < BOOT_IMAGE_NUMBER) {
        *exec_ram_start = image_boot_config[image_id].address;
        *exec_ram_size = image_boot_config[image_id].size;

        return 0;
    }

    return rc;
}
#endif


/******************************************************************************
 * Function Name: hw_deinit
 ******************************************************************************
 * Summary:
 * Deinitialize hardware before launch user application.
 *
 *****************************************************************************/
static void hw_deinit(void)
{
#if MCUBOOT_LOG_LEVEL != MCUBOOT_LOG_LEVEL_OFF
    platform_debug_log_deinit();
#endif /* MCUBOOT_LOG_LEVEL != MCUBOOT_LOG_LEVEL_OFF */
    log_timestamp_deinit();
    platform_deinit();

    __disable_irq();
}

/******************************************************************************
 * Function Name: handle_invalid_app
 ******************************************************************************
 * Summary:
 * This function runs in case an application is invalid and sets
 * the system to deep sleep mode.
 *
 *****************************************************************************/
static void handle_invalid_app(void)
{
    BOOT_LOG_ERR("Handle invalid application...");

    if (platform_deep_sleep_prepare() != CY_RSLT_SUCCESS) {
        BOOT_LOG_INF("Deep Sleep prepare - Fail");
        handle_error();
    }

    BOOT_LOG_INF("Deep Sleep prepare - OK");

    // Disable watchdog to prevent wakeup from deep sleep mode
    Cy_WDT_Unlock();
    Cy_WDT_Disable();
    Cy_WDT_Lock();

    // Add delay before entering deep sleep to allow any ongoing activities to complete
    Cy_SysLib_Delay(DELAY_BEFORE_DEEP_SLEEP_MS);
    cy_en_syspm_status_t rc = Cy_SysPm_CpuEnterDeepSleep(CY_SYSPM_WAIT_FOR_INTERRUPT);
    if (CY_SYSPM_SUCCESS != rc) {
        BOOT_LOG_INF("Failed to enter deep sleep mode, error code 0x%08X, PM status 0x%08X", 
                     (uint32_t)rc, Cy_SysPm_ReadStatus());
        handle_error();
    }
}

/******************************************************************************
 * Function Name: run_next_app
 ******************************************************************************
 * Summary:
 * This function runs next app.
 *
 * Parameters:
 *  rsp - provided by the boot loader code; indicates where to jump
 *       to execute the main image
 *
 * Return:
 *  true - on success
 *
 *****************************************************************************/
static bool run_next_app(struct boot_rsp *rsp)
{
    uintptr_t image_base;
    int rc = 0;

    if (rsp != NULL) {
#if defined(MCUBOOT_RAM_LOAD)
#if !defined(MULTIPLE_EXECUTABLE_RAM_REGIONS)
        image_base = IMAGE_EXECUTABLE_RAM_START;
#else
        if (IS_RAM_BOOTABLE(rsp->br_hdr)) {
            BOOT_LOG_DBG(" > %s: application IS_RAM_BOOTABLE", __func__);
            rc = boot_get_image_exec_ram_info(0, (uint32_t *)&image_base,
                                            &(uint32_t){0});

            BOOT_LOG_DBG(" > %s: image_base = 0x%X ", __func__, (uint32_t)image_base);
        } else
#endif
#endif

#if !defined(MCUBOOT_RAM_LOAD) || defined(MCUBOOT_MULTI_MEMORY_LOAD)
        {
            BOOT_LOG_DBG(" > %s: !MCUBOOT_RAM_LOAD || MCUBOOT_MULTI_MEMORY_LOAD", __func__);
            rc = flash_device_base(rsp->br_flash_dev_id, &image_base);
            BOOT_LOG_DBG(" > %s: rc = %d, image_base = 0x%X", __func__, rc, (uint32_t)image_base);
        }
#endif

        if (0 == rc) {
            fih_int fih_rc = FIH_FAILURE;
            fih_uint app_addr = FIH_UINT_INIT(0U);

            FIH_CALL(calc_app_addr, fih_rc, image_base, rsp, &app_addr);
            if (!fih_eq(fih_rc, FIH_SUCCESS)) {
                BOOT_LOG_ERR(" > %s: calc_app_addr returned FIH_FALSE", __func__);
                return false;
            }

            /* Check Vector Table alignment */
            const uint32_t mask = (uint32_t)VECTOR_TABLE_ALIGNMENT - 1U;

            if (!fih_uint_eq(fih_uint_and(app_addr, fih_uint_encode(mask)), FIH_UINT_ZERO)) {
                BOOT_LOG_ERR(" > %s: Invalid Vector Table alignment", __func__);
                return false;
            }

            vect_tbl_start_t *p_vect_tbl_start =
                (vect_tbl_start_t *)fih_uint_decode(app_addr);

            if (0u != (p_vect_tbl_start->stack_pointer &
                       7U) || /* Check stack alignment */
                1u != ((uintptr_t)p_vect_tbl_start->reset_handler &
                       1U)) /* Check Thumb entry point */
            {
                BOOT_LOG_ERR(" > %s: misaligned stack or invalid entry point",
                             __func__);
                return false;
            }

            BOOT_LOG_INF("Starting User Application (wait)...");

            if (IS_ENCRYPTED(rsp->br_hdr)) {
                BOOT_LOG_DBG(" * User application is encrypted");
            }

            BOOT_LOG_DBG("Start slot Address: 0x%X",
                         (uint32_t)fih_uint_decode(app_addr));

            BOOT_LOG_INF(BOOT_MSG_FINISH);
            hw_deinit();

            /* Start user app */
            cleanup_and_boot(&app_addr);
        } else {
            BOOT_LOG_ERR("Flash device ID not found");
            return false;
        }
    }

    return false;
}

/******************************************************************************
 * Function Name: bootloader_init
 ******************************************************************************
 * Summary:
 * This is the initialization function of the bootloader.
 *
 *****************************************************************************/
void bootloader_init(void) {

    cy_rslt_t rc = CY_RSLT_SUCCESS;

#if MCUBOOT_LOG_LEVEL != MCUBOOT_LOG_LEVEL_OFF
    /* Initialize the timebase for output logs */
    log_timestamp_init();

    /* Initialize debug log hardware */
    rc = platform_debug_log_init();
    if (rc != CY_RSLT_SUCCESS) {
        LOOP_FOREVER();
    }
#endif /* MCUBOOT_LOG_LEVEL != MCUBOOT_LOG_LEVEL_OFF */
    
    BOOT_LOG_INF("MCUBoot Bootloader Started");

#if defined(MCUBOOT_BUILT_IN_KEYS) || defined (MCUBOOT_HW_KEY) || defined (MCUBOOT_USE_PSA_CRYPTO)
    if (PSA_SUCCESS != psa_crypto_init()) {
        handle_error();
    }
    BOOT_LOG_INF("PSA crypto init - OK");
#endif

    /* Initialize platform specific modules */
    rc = platform_init();
    if (rc != CY_RSLT_SUCCESS) {
        handle_error();
    }
    BOOT_LOG_INF("Platform init - OK");

#ifdef FIH_ENABLE_DELAY
    /*If random delay is used in FIH APIs then
     * fih_delay must be initialized */
    fih_delay_init();
#endif /* FIH_ENABLE_DELAY */

}


/******************************************************************************
 * Function Name: bootloader_run
 ******************************************************************************
 * Summary:
 * This is the main function of the bootloader.
 *
 *****************************************************************************/
void bootloader_run(void) {

    struct boot_rsp rsp[BOOT_IMAGE_NUMBER] = {0};
    cy_rslt_t rc = CY_RSLT_SUCCESS;
    fih_int fih_rc = FIH_FAILURE;
    /* Volatile to prevent optimizing security checks */
    volatile uint32_t id, id_rev;


#if !defined(MCUBOOT_RAM_LOAD) || defined(MCUBOOT_MULTI_MEMORY_LOAD)

    BOOT_LOG_INF("boot_go_for_image_id");
    
    /* Perform MCUboot */
    id_rev = (uint32_t)BOOT_IMAGE_NUMBER;
    for (id = 0U; id < (uint32_t)BOOT_IMAGE_NUMBER; id++) {
        BOOT_LOG_INF("Processing img id: %d", id);
        FIH_CALL(boot_go_for_image_id, fih_rc, &rsp[id], id);
        /* Fault Injection is detected */
        if ((id + id_rev) != (uint32_t)BOOT_IMAGE_NUMBER)
        {
            /* no return */
            LOOP_FOREVER();
        }

        if (!fih_eq(fih_rc, FIH_SUCCESS) || rsp[id].br_hdr == NULL) {
            handle_invalid_app();
        }

        id_rev--;
    }
#endif

#if defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY)

    /* Set SMIF crypto regions for boot slot of each image */
    for (id = 0U; id < (uint32_t)BOOT_IMAGE_NUMBER; id++) {
        if (0 != ifx_epb_set_xip_crypto_for_image_slot(id, /* crypto block id */
                                                       id, /* image number */
                                                       BOOT_PRIMARY_SLOT, /* slot */
                                                       rsp[id].xip_key, /* encryption key */
                                                       rsp[id].xip_iv) /* iv */ ) {
            handle_invalid_app();
        }
    }
    SMIF_SET_CRYPTO_MODE(Enable);

#endif /* defined(MCUBOOT_ENC_IMAGES_XIP_MULTI_KEY_MULTY) */

#if defined(MCUBOOT_RAM_LOAD)
    id_rev = (uint32_t)BOOT_IMAGE_NUMBER;
    for (id = 0U; id < (uint32_t)BOOT_IMAGE_NUMBER; id++) {
        if (IS_RAM_BOOTABLE(rsp[id].br_hdr) == true) {
            BOOT_LOG_INF("boot_go_for_image_id_ram");
            FIH_CALL(boot_go_for_image_id_ram, fih_rc, &rsp[id], id);
            /* Fault Injection is detected */
            if ((id + id_rev) != (uint32_t)BOOT_IMAGE_NUMBER)
            {
                /* no return */
                LOOP_FOREVER();
            }

            if (!fih_eq(fih_rc, FIH_SUCCESS)) {
                handle_invalid_app();
            }
        }

        id_rev--;
    }
#endif

    if (fih_eq(fih_rc, FIH_SUCCESS)) {
        BOOT_LOG_INF("User Application validated successfully");

#if defined(MCUBOOT_WATCHDOG_ENABLED)
        initialize_wdt();
#endif /* MCUBOOT_WATCHDOG_ENABLED */

        BOOT_LOG_INF("Running the first app");

        if (CY_RSLT_SUCCESS == rc) {
            if (!run_next_app(&rsp[0])) {
                BOOT_LOG_ERR("Running of next app failed!");
                handle_error();
            }
        } else {
            BOOT_LOG_ERR("Failed to init WDT");
        }
    } else {
        BOOT_LOG_ERR("MCUBoot Bootloader found none of bootable images");
        handle_invalid_app();
    }

    /* Loop forever... */
    while (true) {
        __WFI();
    }
}
