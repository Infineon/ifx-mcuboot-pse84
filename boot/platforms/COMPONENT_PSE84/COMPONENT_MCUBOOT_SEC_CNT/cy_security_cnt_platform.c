/*
 * Copyright (c) 2020 Arm Limited.
 * Copyright (c) 2021 Infineon Technologies AG
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

#include "cy_security_cnt_platform.h"

#if defined MCUBOOT_HW_ROLLBACK_PROT

#include <stdint.h>

#include "ifx_se_platform.h"
#include "sysflash.h"

static uint8_t security_counter_layout[MCUBOOT_IMAGE_NUMBER] =
    {
        HW_ROLLBACK_NUMBER_IMG_1

#if defined(HW_ROLLBACK_NUMBER_IMG_2)
        ,
        HW_ROLLBACK_NUMBER_IMG_2
#endif

#if defined(HW_ROLLBACK_NUMBER_IMG_3)
        ,
        HW_ROLLBACK_NUMBER_IMG_3
#endif

#if defined(HW_ROLLBACK_NUMBER_IMG_4)
        ,
        HW_ROLLBACK_NUMBER_IMG_4
#endif

#if defined(HW_ROLLBACK_NUMBER_IMG_5)
        ,
        HW_ROLLBACK_NUMBER_IMG_5
#endif

#if defined(HW_ROLLBACK_NUMBER_IMG_6)
        ,
        HW_ROLLBACK_NUMBER_IMG_6
#endif
};

/**
 * Reads a data corresponding to security counter which is stored in
 * efuses of chip and converts it actual value of security counter
 *
 * @param image_id         Image id counter assisiated with
 * @param security_cnt     Pointer to a variable, where security counter value would be stored
 *
 * @return                 FIH_SUCCESS on success; FIH_FAILURE on failure.
 */
fih_int platform_security_counter_get(uint32_t image_id, fih_uint *security_cnt)
{
    fih_int fih_rc = FIH_FAILURE;
    ifx_se_status_t status = IFX_SE_SYSCALL_CORRUPTION_DETECTED;

    if (security_cnt != NULL) {
        ifx_se_fih_t counter_value = ifx_se_fih_uint_encode(UINT32_MAX);
        ifx_se_fih_t number = ifx_se_fih_uint_encode(security_counter_layout[image_id]);

        status =
            ifx_se_get_rollback_counter(number, ifx_se_fih_ptr_encode(&counter_value), IFX_SE_NULL_CTX);

        if (ifx_se_fih_uint_eq(status, IFX_SE_SUCCESS)) {
            memcpy((void*) security_cnt, (const void*) &counter_value, sizeof(*security_cnt));

            fih_rc = FIH_SUCCESS;
        }
    }

    FIH_RET(fih_rc);
}

/**
 * Updates the stored value of a given image's security counter with a new
 * security counter value if the new one is greater.
 *
 * @param image_id          Image id counter assisiated with
 * @param img_security_cnt  Counter value 
 * @param custom_data       Pointer to supplemental data (API), not used in this implementation 
 *
 * @return                  0 on success; nonzero on failure.
 */
int32_t platform_security_counter_update(uint32_t image_id, fih_uint img_security_cnt, uint8_t *custom_data)
{
    (void)custom_data;

    int32_t rc = -1;

    ifx_se_status_t status = IFX_SE_SYSCALL_CORRUPTION_DETECTED;
    ifx_se_fih_t number = ifx_se_fih_uint_encode(security_counter_layout[image_id]);
#if defined(MCUBOOT_FIH_PROFILE_OFF) || (defined(MCUBOOT_FIH_PROFILE_ON) && defined(MCUBOOT_FIH_PROFILE_LOW))
    ifx_se_fih_t value = ifx_se_fih_uint_encode(fih_uint_decode(img_security_cnt));
#else
    ifx_se_fih_t value = {0};
    memcpy((void*) &value, (const void*) &img_security_cnt, sizeof(value));
#endif
    status = ifx_se_update_rollback_counter(number, value, IFX_SE_NULL_CTX);

    if (ifx_se_fih_uint_eq(status, IFX_SE_SUCCESS)) {
        rc = 0;
    }

    return rc;
}

#endif /* defined MCUBOOT_HW_ROLLBACK_PROT */
