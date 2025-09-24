/*
 * Copyright (c) 2024 Infineon Technologies AG
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
 */
#include "boot_status.h"
#include "bootutil_priv.h"
#include "ifx_se_platform.h"
#include "ifx_se_syscall.h"


#ifdef MCUBOOT_SHARED_DATA_OFFSET
#include "memorymap.h"
#define MCUBOOT_SHARED_DATA_BASE (MCUBOOT_SHARED_DATA_OFFSET + flash_devices[INTERNAL_S_SRAM].address)
#else
#define MCUBOOT_SHARED_DATA_BASE 0x34001000
#endif

/* Error codes for using the shared memory area. */
#define SHARED_MEMORY_OK            (0)
#define SHARED_MEMORY_OVERFLOW      (1)
#define SHARED_MEMORY_OVERWRITE     (2)
#define SHARED_MEMORY_GEN_ERROR     (3)

/**
 * @var shared_memory_init_done
 *
 * @brief Indicates whether shared memory area was already initialized.
 *
 */
static bool shared_memory_init_done;

/* See in boot_record.h */
int
boot_add_data_to_shared_area(uint8_t major_type,
                             uint16_t minor_type,
                             size_t size,
                             const uint8_t *data,
                             const struct flash_area *fap)
{
    struct shared_data_tlv_entry tlv_entry = {0};
    uint16_t type = SET_TLV_TYPE(major_type, minor_type);
    struct shared_boot_data *boot_data;
    uint16_t boot_data_size;
    uintptr_t tlv_end = 0;
    uintptr_t offset = 0;
    (void)fap;

    if (data == NULL) {
        return SHARED_MEMORY_GEN_ERROR;
    }

    /* Shared data section must be aligned as 'void*' */
    if (((uintptr_t)MCUBOOT_SHARED_DATA_BASE & 3u) != 0u) {
        return SHARED_MEMORY_GEN_ERROR;
    }
    boot_data = (struct shared_boot_data *)MCUBOOT_SHARED_DATA_BASE;

    /* Check whether first time to call this function. If does then initialise
     * shared data area.
     */
    if (!shared_memory_init_done){
        /* First time here, check if previous stage left any data */
        if(boot_data->header.tlv_magic == SHARED_DATA_TLV_INFO_MAGIC){
            /* Data present from previous stage nothing to do */
        }
        else {
            /* Init the area */
            (void)memset((void *)MCUBOOT_SHARED_DATA_BASE, 0, MCUBOOT_SHARED_DATA_SIZE);
            boot_data->header.tlv_magic   = SHARED_DATA_TLV_INFO_MAGIC;
            boot_data->header.tlv_tot_len = (uint16_t)SHARED_DATA_HEADER_SIZE;
        }
        shared_memory_init_done = true;
    }

    tlv_end = MCUBOOT_SHARED_DATA_BASE + (uint32_t)(boot_data->header.tlv_tot_len);
    offset  = MCUBOOT_SHARED_DATA_BASE + SHARED_DATA_HEADER_SIZE; 

    while (offset < tlv_end) {
        /* Create local copy to avoid unaligned access */
        (void)memcpy((void*)&tlv_entry, (const void *)offset, SHARED_DATA_ENTRY_HEADER_SIZE);
        if (tlv_entry.tlv_type == type) {
            return SHARED_MEMORY_OVERWRITE;
        }

        offset += SHARED_DATA_ENTRY_SIZE(tlv_entry.tlv_len);
    }

    /* Add TLV entry */
    tlv_entry.tlv_type = type;

    if (size > (unsigned)UINT16_MAX - SHARED_DATA_ENTRY_HEADER_SIZE) {
        return SHARED_MEMORY_GEN_ERROR;
    }

    tlv_entry.tlv_len = (uint16_t)size;
    if (!boot_u16_safe_add(&boot_data_size, boot_data->header.tlv_tot_len,
                            (uint16_t)SHARED_DATA_ENTRY_SIZE(size))) {
        return SHARED_MEMORY_GEN_ERROR;
    }

    /* Verify overflow of shared area */
    if (boot_data_size > MCUBOOT_SHARED_DATA_SIZE) {
        return SHARED_MEMORY_OVERFLOW;
    }

    offset = tlv_end;
    (void)memcpy((void *)offset, (const void *)&tlv_entry, SHARED_DATA_ENTRY_HEADER_SIZE);

    offset += SHARED_DATA_ENTRY_HEADER_SIZE;
    (void)memcpy((void *)offset, (const void *)data, size);

    boot_data->header.tlv_tot_len = boot_data_size;

#if defined(USE_SHARED_DATA_WITH_SE_RT)
    /* Run SE RT only for boot status */
    if (TLV_MAJOR_IAS == major_type) {
        ifx_se_status_t if_se_rc = IFX_SE_INVALID;

        uint32_t sw_module = GET_IAS_MODULE(minor_type);
        if_se_rc = ifx_se_set_shared_data(ifx_se_fih_uint_encode(sw_module), ifx_se_fih_ptr_encode(data), ifx_se_fih_uint_encode(size), IFX_SE_NULL_CTX);

        if (ifx_se_fih_uint_not_eq(if_se_rc, IFX_SE_SUCCESS)) {
            return SHARED_MEMORY_GEN_ERROR;
        }
    }
#endif

    return SHARED_MEMORY_OK;
}
