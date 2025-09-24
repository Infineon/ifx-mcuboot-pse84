/***************************************************************************//**
* \file mbedtls_entropy_poll_ifxse.c
*
* \brief
* mbedtls entropy collection from IFX SE RT Services
*
* \note
*
********************************************************************************
* \copyright
* Copyright (c) (2020-2023), Cypress Semiconductor Corporation (an Infineon company) or
* an affiliate of Cypress Semiconductor Corporation. All rights reserved.
* You may use this file only in accordance with the license, terms, conditions,
* disclaimers, and limitations in the end user license agreement accompanying
* the software package with which this file was provided.
*******************************************************************************/

#include <string.h>

#include "mbedtls/build_info.h"

#include "cy_device.h"

/*-----------------------------------------------------------*/
#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)

#if defined(IFX_PSA_RANDOM_BY_SE_DPA)

#include "mbedtls/entropy.h"
#include "mbedtls/platform.h"

#include "ifx_se_psacrypto.h"

int mbedtls_hardware_poll( void * data,
                           unsigned char * output,
                           size_t len,
                           size_t * olen )
{
    int ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    *olen = 0;

    (void)data;

    if( len == 0 )
        return( 0 );

    uint8_t *random_buf = mbedtls_calloc(1, len + IFX_CRC32_CRC_SIZE);
    if( random_buf != NULL )
    {
        ifx_se_status_t status = IFX_SE_SYSCALL_CORRUPTION_DETECTED;

        /* Get Random bytes */
        status = ifx_se_generate_random(
                    ifx_se_fih_ptr_encode(random_buf),
                    ifx_se_fih_uint_encode(len + IFX_CRC32_CRC_SIZE),
                    IFX_SE_NULL_CTX);

        if (IFX_SE_IS_STATUS_SUCCESS(status))
        {
            uint32_t crc;

            (void)memcpy((uint8_t*)&crc, random_buf + len, IFX_CRC32_CRC_SIZE);
            if( crc == IFX_CRC32_CALC(random_buf, len) )
            {
                (void)memcpy(output, random_buf, len);
                *olen = len;
                ret = 0;
            }
        }
        mbedtls_free(random_buf);
    }
    return (ret);
}
#endif /* IFX_PSA_RANDOM_BY_SE_DPA */

#endif /* MBEDTLS_ENTROPY_HARDWARE_ALT */
