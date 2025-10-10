/******************************************************************************
 * File Name: stage_ram_app.h
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

#ifndef STAGE_RAM_APP_H
#define STAGE_RAM_APP_H

#include <stdbool.h>
#include <string.h>

#include "cy_device.h"
#include "ifx_se_crc32.h"
#include "flash_map_backend.h"
#include "image.h"
#include "bootutil/bootutil_log.h"

#define BOOT_DLM_CTL_REQUEST_RUN_RAM_APP        (0x03u)
#define BOOT_DLM_CTL_REQUEST_RESET              (0x01u)
#define RES_SOFT_CTL_REQUEST_SET                (0x01u)

#define STAGE_RAM_APP_SUCCESS                   (0xF2A00001u)
#define STAGE_RAM_APP_FAILED                    (0x45000008u)
#define STAGE_RAM_APP_UNSET                     (0x00000000u)

#define DLM_HEADER_SIZE                         (0x68u)

/* Start address of upgrade flags area in RRAM
 * This area is used for passing state of L2-boot through reset */
#define UPGRADE_FLAGS_AREA_START_OFFSET         (0x00000010U)
#define UPGRADE_FLAGS_AREA_START_ADDR           (CY_RRAM_BASE + UPGRADE_FLAGS_AREA_START_OFFSET)

/* This value defines size of checksum field
 * in upgrade flags area (in bytes) */
#define UPGRADE_FLAG_CRC_SIZE                   (IFX_CRC32_CRC_SIZE)

/* This value defines size of one upgrade flag field  (in bytes) */
#define UPGRADE_FLAG_SIZE                       (0x04U)

/* This value defines offset of pending OEM RAM App flag
 * which is used for indication to launch OEM RAM App
 * after reset*/
#define PENDING_OEM_RAM_APP_OFFSET              (0x00U)

/* This value defines offset of checksum(CRC32) for data
 * in the upgrade flags area. CRC algorithm: crc32d6a.
 * Initial valur of CRC algorithm: UPGRADE_FLAGS_AREA_START_ADDR */
#define UPGRADE_FLAGS_CRC_OFFSET                (0x0CU)

/* Upgrade area size including checksum */
#define UPGRADE_FLAGS_AREA_SIZE                 (UPGRADE_FLAGS_CRC_OFFSET + UPGRADE_FLAG_CRC_SIZE)

/* Pending OEM RAM App flag allowed values */
#define PENDING_OEM_RAM_APP_FLAG_STATE_SET      (0xA48E65B0U)
#define PENDING_OEM_RAM_APP_FLAG_STATE_CLEAR    (0x39B92974U)

/* Convert uint32_t pointer <-> uint8_t pointer */
typedef union
{
    uint32_t *p_uint32;
    uint8_t *p_uint8;
} puint32_puint8_t;

/* Result values for staging RAM App execution routines
*/
typedef enum
{
    /* SE RT Services upgraded successfully */
    IFX_STG_APP_RSLT_UPGRADED = 0x5A003820U,
    /* No image found in external memory staging area */
    IFX_STG_APP_RSLT_NO_IMAGE = 0x5A004821U,
    /* External memory operation error */
    IFX_STG_APP_RSLT_MEM_ERROR = 0x5A005823U,
    /* Staged application found in external memory */
    IFX_STG_APP_RSLT_STAGED = 0x5A006824U,
    /* Application copied from external memory to SRAM */
    IFX_STG_APP_RSLT_RAM_STAGED = 0x5A007825U,
    /* SE RT Services upgrade application returned failure */
    IFX_STG_APP_RSLT_UPGRADE_FAILURE = 0x5A008826U,
    /* Status of SE RT Services application execution is unset  */
    IFX_STG_APP_RSLT_CLEARED = 0x5A009827U,
    /* Failure at copying from staging area in external memory to SRAM */
    IFX_STG_APP_RSLT_RAM_COPY_ERROR = 0x5A00A828U,
    /* Failure while setting pending flag in upgrade flags area */
    IFX_STG_APP_RSLT_RAM_SET_PENDING_ERROR = 0x5A00B829U,
    /* General error code */
    IFX_STG_APP_RSLT_GEN_ERROR = 0x7A005858U
} ifx_stg_app_rslt_type_t;

/* Result values for RAM app pending status
*/
typedef enum
{
    IFX_STG_APP_STATUS_PENDED        = 0x3A008830U,
    IFX_STG_APP_STATUS_NOT_PENDED    = 0xAA009940U,
    IFX_STG_APP_STATUS_SUCCESS       = 0xDD89A561U,
    IFX_STG_APP_STATUS_ERROR         = 0xEE19CB28U
} ifx_stg_app_status_type_t;

struct ram_app_desc {
    uint32_t size;
    uint32_t load_addr;
};

/*******************************************************************************
 * Function Name: check_upgrade_flag_value
 *******************************************************************************
 * \brief This function returns the status of upgrade flag.
 *
 * \param flag_offset    The flag offset in the upgrade flags area(in bytes).
 * \param compared_val   The value to compare.
 * \return bool
 *     true  - flag is set;
 *     false - flag is not set.
 *
 ******************************************************************************/
static inline bool check_upgrade_flag_value(uint32_t flag_offset, uint32_t compared_val)
{
    bool rc = false;

    BOOT_LOG_DBG("check_upgrade_flag_value: offset=0x%x, expected_val=0x%x", flag_offset, compared_val);

    do
    {
        uint8_t data_arr[UPGRADE_FLAGS_AREA_SIZE] = { 0U };
        uint32 calc_crc32 = 0U;
        puint32_puint8_t p_crc32 = { .p_uint8 = &data_arr[UPGRADE_FLAGS_CRC_OFFSET] };
        puint32_puint8_t p_flag = { .p_uint8 = &data_arr[flag_offset] };

        /* Check if flag offset is valid */
        if (flag_offset > (UPGRADE_FLAGS_CRC_OFFSET - UPGRADE_FLAG_SIZE))
        {
            BOOT_LOG_ERR("Invalid flag offset: 0x%x > 0x%x", flag_offset,
                         (UPGRADE_FLAGS_CRC_OFFSET - UPGRADE_FLAG_SIZE));
            break;
        }

        /* Read upgrade flags area */
        if (Cy_RRAM_TSReadByteArray(RRAMC0, UPGRADE_FLAGS_AREA_START_ADDR, data_arr,
                                     UPGRADE_FLAGS_AREA_SIZE) != CY_RRAM_SUCCESS)
        {
            BOOT_LOG_ERR("Failed to read upgrade flags area from RRAM at 0x%x",
                         UPGRADE_FLAGS_AREA_START_ADDR);
            break;
        }

        /* Calculate checksum of upgrade flags*/
        calc_crc32 = ifx_se_crc32d6a(UPGRADE_FLAGS_AREA_SIZE - UPGRADE_FLAG_CRC_SIZE,
                                       data_arr, UPGRADE_FLAGS_AREA_START_ADDR);

        BOOT_LOG_DBG("CRC check: stored=0x%x, calculated=0x%x", *p_crc32.p_uint32, calc_crc32);

        /* Compare CRC */
        if (*p_crc32.p_uint32 != calc_crc32)
        {
            BOOT_LOG_WRN("CRC mismatch: stored=0x%x, calculated=0x%x", *p_crc32.p_uint32, calc_crc32);
            break;
        }

        BOOT_LOG_DBG("Flag value check: actual=0x%x, expected=0x%x", *p_flag.p_uint32, compared_val);

        /* Compare flag with input flag value */
        if (*p_flag.p_uint32 != compared_val)
        {
            BOOT_LOG_DBG("Flag value mismatch");
            break;
        }

        BOOT_LOG_DBG("Flag check successful");
        rc = true;

    } while (false);

    BOOT_LOG_DBG("check_upgrade_flag_value result: %s", rc ? "true" : "false");
    return rc;
}

/*******************************************************************************
 * Function Name: check_pending_oem_ram_app_flag
 *******************************************************************************
 * \brief This function returns the status of upgrade flag.
 *
 * \return bool
 *     true  - flag is set;
 *     false - flag is not set.
 *
 ******************************************************************************/
static inline bool check_pending_oem_ram_app_flag(void)
{
    return check_upgrade_flag_value(PENDING_OEM_RAM_APP_OFFSET, PENDING_OEM_RAM_APP_FLAG_STATE_SET);
}

/*******************************************************************************
 * Function Name: write_upgrade_flag
 *******************************************************************************
 * \brief This function writes upgrade flag to upgrade flags area in RRAM.
 *
 * \param flag_offset  offset(in bytes) from beginning of upgrade flags area
 *                     where flag is stored.
 * \param flag_val     value to write.
 *
 * \return
 *     IFX_STG_APP_STATUS_SUCCESS - the flag has been updated successfully;
 *     IFX_STG_APP_STATUS_ERROR   - some error occurred.
 *
 ******************************************************************************/
static inline ifx_stg_app_status_type_t write_upgrade_flag(uint32_t flag_offset, uint32_t flag_val)
{
    ifx_stg_app_status_type_t rc = IFX_STG_APP_STATUS_ERROR;

    BOOT_LOG_DBG("write_upgrade_flag: offset=0x%x, value=0x%x", flag_offset, flag_val);

    do
    {
        uint8_t data_arr[UPGRADE_FLAGS_AREA_SIZE] = { 0U };
        uint32 crc32 = 0U;

        puint32_puint8_t p_crc32 = {.p_uint32 = &crc32};
        puint32_puint8_t p_flag = {.p_uint32 = &flag_val};
        /* Check if flag offset is valid */
        if (flag_offset > (UPGRADE_FLAGS_CRC_OFFSET - UPGRADE_FLAG_SIZE))
        {
            BOOT_LOG_ERR("Invalid flag offset for write: 0x%x > 0x%x", flag_offset,
                         (UPGRADE_FLAGS_CRC_OFFSET - UPGRADE_FLAG_SIZE));
            break;
        }

        /* Read upgrade flags area */
        if (Cy_RRAM_TSReadByteArray(RRAMC0, UPGRADE_FLAGS_AREA_START_ADDR, data_arr,
                                    UPGRADE_FLAGS_AREA_SIZE) != CY_RRAM_SUCCESS)
        {
            BOOT_LOG_ERR("Failed to read upgrade flags area for write operation");
            break;
        }

        /* Modify the flag value in data buffer in SRAM */
        (void)memcpy(&data_arr[flag_offset], p_flag.p_uint8, UPGRADE_FLAG_SIZE);
        BOOT_LOG_DBG("Flag value updated in buffer at offset 0x%x", flag_offset);

        /* Calculate checksum of upgrade flags*/
        crc32 = ifx_se_crc32d6a(UPGRADE_FLAGS_AREA_SIZE - UPGRADE_FLAG_CRC_SIZE, data_arr,
                                                                                         UPGRADE_FLAGS_AREA_START_ADDR);
        BOOT_LOG_DBG("New CRC calculated: 0x%x", crc32);

        /* Modify the checksum in data buffer in SRAM */
        (void)memcpy(&data_arr[UPGRADE_FLAGS_CRC_OFFSET], p_crc32.p_uint8, UPGRADE_FLAG_CRC_SIZE);

        /* Write updated SRAM data buffer to RRAM */
        if (Cy_RRAM_TSWriteByteArray(RRAMC0, UPGRADE_FLAGS_AREA_START_ADDR, data_arr, UPGRADE_FLAGS_AREA_SIZE)
                                                                                                     != CY_RRAM_SUCCESS)
        {
            BOOT_LOG_ERR("Failed to write updated flags to RRAM");
            break;
        }
        BOOT_LOG_DBG("Updated flags written to RRAM successfully");

        /* Read and verify written upgrade flag */
        if (Cy_RRAM_TSReadByteArray(RRAMC0, UPGRADE_FLAGS_AREA_START_ADDR, data_arr, UPGRADE_FLAGS_AREA_SIZE)
                                                                                                     != CY_RRAM_SUCCESS)
        {
            BOOT_LOG_ERR("Failed to read back written flags for verification");
            break;
        }

        /* Calculate checksum of upgrade flags*/
        crc32 = ifx_se_crc32d6a(UPGRADE_FLAGS_AREA_SIZE - UPGRADE_FLAG_CRC_SIZE,
                                data_arr, UPGRADE_FLAGS_AREA_START_ADDR);

        /* Check CRC */
        p_crc32.p_uint8 = &data_arr[UPGRADE_FLAGS_CRC_OFFSET];
        if (*p_crc32.p_uint32 != crc32)
        {
            BOOT_LOG_ERR("CRC verification failed after write: stored=0x%x, calculated=0x%x",
                         *p_crc32.p_uint32, crc32);
            break;
        }

        /* Compare written flag value with input flag value */
        p_flag.p_uint8 = &data_arr[flag_offset];
        if (*p_flag.p_uint32 != flag_val)
        {
            BOOT_LOG_ERR("Flag verification failed: written=0x%x, expected=0x%x",
                         *p_flag.p_uint32, flag_val);
            break;
        }

        BOOT_LOG_DBG("Flag write and verification successful");
        rc = IFX_STG_APP_STATUS_SUCCESS;

    } while (false);

    BOOT_LOG_DBG("write_upgrade_flag result: 0x%x", rc);
    return rc;
}


/*******************************************************************************
 * Function Name: clear_pending_oem_ram_app_flag
 *******************************************************************************
 * \brief This function clears the CM33 OEM RAM App pending flag.
 *
 * \return
 *     IFX_STG_APP_STATUS_SUCCESS - the flag has been cleared successfully;
 *     IFX_STG_APP_STATUS_ERROR   - some error occurred.
 *
 ******************************************************************************/
static inline ifx_stg_app_status_type_t clear_pending_oem_ram_app_flag(void)
{
    return write_upgrade_flag(PENDING_OEM_RAM_APP_OFFSET, PENDING_OEM_RAM_APP_FLAG_STATE_CLEAR);
}


/*******************************************************************************
 * Function Name: set_pending_oem_ram_app_flag
 *******************************************************************************
 * \brief This function sets the CM33 OEM RAM App pending flag.
 *
 * \return
 *     IFX_STG_APP_STATUS_SUCCESS - the flag has been set successfully;
 *     IFX_STG_APP_STATUS_ERROR   - some error occurred.
 *
 ******************************************************************************/
static inline ifx_stg_app_status_type_t set_pending_oem_ram_app_flag(void)
{
    return  write_upgrade_flag(PENDING_OEM_RAM_APP_OFFSET, PENDING_OEM_RAM_APP_FLAG_STATE_SET);
}


/*******************************************************************************
 * Function Name: stage_ram_app_check_staging_area
 *******************************************************************************
 * \brief This function checks staging area and tries to find image magic of
 *        staged image. If it finds magic number, bootloader reads load_addr and 
 *        image size from staged image header in mcuboot format.
 *
 * \param desc pointer to an image descriptor structure 
 *
 * \return
 *     IFX_STG_APP_STATUS_SUCCESS      - the flag has been updated successfully;
 *     IFX_STG_APP_STATUS_ERROR        - some error occurred.
 *
 ******************************************************************************/
static inline cy_rslt_t stage_ram_app_check_staging_area(struct ram_app_desc * desc)
{
    ifx_stg_app_rslt_type_t result = IFX_STG_APP_RSLT_GEN_ERROR;

    BOOT_LOG_DBG("Checking staging area at address 0x%x", RAM_APP_STAGING_ADDR);

    struct image_header *hdr =
        (struct image_header *)(RAM_APP_STAGING_ADDR);

    BOOT_LOG_DBG("Image header magic: 0x%x (expected: 0x%x)", hdr->ih_magic, IMAGE_MAGIC);
    BOOT_LOG_DBG("Image header flags: 0x%x", hdr->ih_flags);

    if ((hdr->ih_magic != IMAGE_MAGIC) ||
        (hdr->ih_flags & IMAGE_F_NON_BOOTABLE)) {
        /* No image present or it is corrupted */
        BOOT_LOG_WRN("No valid image found in staging area (magic mismatch or non-bootable)");
        desc->size = 0u;
        desc->load_addr = 0u;
    }
    else
    {
        desc->size = hdr->ih_img_size;
        desc->load_addr = RAM_APP_STAGING_RAM_ADDR;

        BOOT_LOG_INF("Valid image found - size: 0x%x, load_addr: 0x%x", desc->size, desc->load_addr);
        result = IFX_STG_APP_RSLT_STAGED;
    }

    BOOT_LOG_DBG("stage_ram_app_check_staging_area result: 0x%x", result);
    return result;
}

/*******************************************************************************
 * Function Name: stage_ram_app_notify_app_staged
 *******************************************************************************
 * \brief This function performs defined procedure to inform ROM Boot, that
 *        application is placed in specified area and RAM and is ready to be
 *        processed.
 * 
 * \param load_addr address in SRAM where staged application is placed
 *
 * \return
 *     none
 *
 ******************************************************************************/
static inline void stage_ram_app_notify_app_staged(uint32_t load_addr)
{
    /* Notify BootROM for RAMApp staging started - code 0x03:
     *  BootROM copies RAM application from the staging area and validates
     *  it. If validation completed successfully BootROM launches RAM
     *  application, otherwise BootROM reports error in TST_DEBUG_STATUS
     *  register and continue boot.
     */
    SRSS->BOOT_DLM_CTL = _VAL2FLD(SRSS_BOOT_DLM_CTL_REQUEST, BOOT_DLM_CTL_REQUEST_RUN_RAM_APP);

    /* Set address of application descriptor or debug certificate depends on
     * BOOT_DLM_CTL.REQUEST:
     *  The application descriptor provides info about RAM application and its
     *  parameters layout in the staging area to BootROM and RAM application
     *  itself
     */
    SRSS->BOOT_DLM_CTL2 = _VAL2FLD(SRSS_BOOT_DLM_CTL2_APP_CTL, load_addr);

    /* Request the device reset after RAM application complete input parameters
     * processing. This bit is analyzed with APP_INPUT_AVAIL so to take effect
     * write both. 0 - No action, the device waits for input parameters. 1 -
     * Reset the device after input parameters processing complete.
     */
    SRSS->BOOT_DLM_CTL |= _VAL2FLD(SRSS_BOOT_DLM_CTL_RESET, BOOT_DLM_CTL_REQUEST_RESET);
}

/*******************************************************************************
 * Function Name: stage_ram_app_handler
 *******************************************************************************
 * \brief This function implements main logic of SE RT Services upgrade. It checks
 *        staging area in external memory for new apps. Performs notification routine
 *        for Boot ROM and analyses status codes of RAM App after its execution.
 *
 * \return
 *     result - status code of upgrade routine execution
 *
 ******************************************************************************/
static inline uint32_t stage_ram_app_handler(void)
{
    uint32_t ram_app_status = 0;
    int32_t rc = 0;
    ifx_stg_app_rslt_type_t result = IFX_STG_APP_RSLT_GEN_ERROR;
    ifx_stg_app_status_type_t pending_status = IFX_STG_APP_STATUS_NOT_PENDED;
    struct ram_app_desc desc;
    const struct flash_area *fap = NULL;

    BOOT_LOG_INF("Starting RAM app handler");

    do {
        /* Check RAM application pending status */
        if (check_pending_oem_ram_app_flag() == true)
        {
            pending_status = IFX_STG_APP_STATUS_PENDED;
            BOOT_LOG_INF("RAM app pending flag is SET - clearing it");

            (void)clear_pending_oem_ram_app_flag();
        }
        else
        {
            pending_status = IFX_STG_APP_STATUS_NOT_PENDED;
            BOOT_LOG_DBG("RAM app pending flag is NOT set");
        }

        /* Check status returned by RAM App */
        ram_app_status = SRSS->BOOT_DLM_STATUS;
        BOOT_LOG_DBG("RAM app status from BootROM: 0x%x", ram_app_status);
        
        /* If pended RAM App flag is set in upgrade flags area and RAM App execution status is success */
        if ((ram_app_status == STAGE_RAM_APP_SUCCESS) && (pending_status == IFX_STG_APP_STATUS_PENDED))
        {
            BOOT_LOG_INF("RAM app execution successful - cleaning up staging area");
            /* If successful status received - erase staging area in external memory */

            rc = flash_area_open(RAM_APP_STAGING_AREA_ID, &fap);
            if (rc != 0) 
            {
                BOOT_LOG_ERR("Failed to open staging area for cleanup: %d", rc);
                result = IFX_STG_APP_RSLT_MEM_ERROR;
            }
            else
            {
                rc = flash_area_erase(fap, 0u, fap->fa_size);
                if (rc != 0) 
                {
                    BOOT_LOG_ERR("Failed to erase staging area: %d", rc);
                    result = IFX_STG_APP_RSLT_MEM_ERROR;
                }
                else
                {
                    BOOT_LOG_DBG("Staging area erased successfully");
                    pending_status = clear_pending_oem_ram_app_flag();
                    result = IFX_STG_APP_RSLT_UPGRADED;
                    BOOT_LOG_INF("RAM app upgrade completed successfully");
                }
            }
            break;
        }
        /* If pended RAM App flag is set in upgrade flags area and RAM App execution status returned as failure */
        else if ((ram_app_status == STAGE_RAM_APP_FAILED) && (pending_status == IFX_STG_APP_STATUS_PENDED))
        {
            BOOT_LOG_ERR("RAM app execution failed");
            result = IFX_STG_APP_RSLT_UPGRADE_FAILURE;
            break;
        }
        /* If pended RAM App flag is unset in upgrade flags area and RAM App execution status returned as failure */
        else if ((ram_app_status == STAGE_RAM_APP_UNSET) && (pending_status == IFX_STG_APP_STATUS_NOT_PENDED))
        {
            BOOT_LOG_DBG("No pending RAM app - proceeding with normal flow");
            result = IFX_STG_APP_RSLT_CLEARED;
        }
        else
        {
            BOOT_LOG_ERR("Unexpected RAM app status combination: status=0x%x, pending=0x%x",
                         ram_app_status, pending_status);
            result = IFX_STG_APP_RSLT_GEN_ERROR;
            break;
        }

        /* Check application availability */
        if ((stage_ram_app_check_staging_area(&desc) == IFX_STG_APP_RSLT_STAGED) &&
            (result == IFX_STG_APP_RSLT_CLEARED))
        {
            BOOT_LOG_INF("New RAM app found in staging area");
            
            /* TODO: add more checks here */
            if ((desc.load_addr != 0) && (desc.size != 0))
            {
                BOOT_LOG_INF("Copying RAM app to SRAM: src=0x%x, dst=0x%x, size=0x%x",
                             RAM_APP_STAGING_ADDR, desc.load_addr, desc.size + DLM_HEADER_SIZE);

                /* Copy RAM app binary to SRAM staging area */
                (void)memcpy((void *)desc.load_addr, (
                        const void *)RAM_APP_STAGING_ADDR, 
                        (size_t)(desc.size + DLM_HEADER_SIZE));
                
                BOOT_LOG_DBG("RAM app copied to SRAM successfully");
                result = IFX_STG_APP_RSLT_RAM_STAGED;
            }
            else
            {
                BOOT_LOG_ERR("Invalid RAM app descriptor: load_addr=0x%x, size=0x%x",
                             desc.load_addr, desc.size);
                result = IFX_STG_APP_RSLT_NO_IMAGE;
            }
        }
        else
        {
            BOOT_LOG_DBG("No new RAM app to stage");
            result = IFX_STG_APP_RSLT_NO_IMAGE;
        }

        if (IFX_STG_APP_RSLT_RAM_STAGED == result)
        {
            BOOT_LOG_INF("Notifying BootROM about staged RAM app at 0x%x", desc.load_addr);
            /* Set status flags to notify BootROM */
            (void)stage_ram_app_notify_app_staged(desc.load_addr);

            /* Set pending RAM app flag to upgrade flags area */
            pending_status = set_pending_oem_ram_app_flag();

            if (pending_status == IFX_STG_APP_STATUS_SUCCESS)
            {
                BOOT_LOG_INF("Pending flag set - initiating soft reset for BootROM execution");
                /* Initiate soft reset to trigger BootROM flow - execution ends here */
                SRSS->RES_SOFT_CTL = _VAL2FLD(SRSS_RES_SOFT_CTL_TRIGGER_SOFT, RES_SOFT_CTL_REQUEST_SET);
            }
            else
            {
                BOOT_LOG_ERR("Failed to set pending flag: 0x%x", pending_status);
                result = IFX_STG_APP_RSLT_RAM_SET_PENDING_ERROR;
                break;
            }
        }
        else
        {
            /* return previous result */
        }

    } while (false);

    BOOT_LOG_INF("RAM app handler completed with result: 0x%x", result);
    return result;
}

#endif /* STAGE_RAM_APP_H */
