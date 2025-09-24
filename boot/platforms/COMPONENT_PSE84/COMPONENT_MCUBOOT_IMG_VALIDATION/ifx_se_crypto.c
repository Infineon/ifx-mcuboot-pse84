/***************************************************************************//**
* \file ifx_se_crypto.c
*
* \brief
* mbedtls extrernal source of randomness from IFX SE RT Services
*
* \note
*
********************************************************************************
* \copyright
* Copyright (c) (2020-2024), Cypress Semiconductor Corporation (an Infineon company) or
* an affiliate of Cypress Semiconductor Corporation. All rights reserved.
* You may use this file only in accordance with the license, terms, conditions,
* disclaimers, and limitations in the end user license agreement accompanying
* the software package with which this file was provided.
*******************************************************************************/


#if defined(MBEDTLS_CONFIG_FILE)
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_USER_CONFIG_FILE)
#include MBEDTLS_USER_CONFIG_FILE
#endif

#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)

#include <string.h>
#include "psa/crypto.h"
#include "fault_injection_hardening.h"
#include "boot_rng.h"

/* Implementation of a function required if mbedtls option MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
 * enabled in configuration file.
*/

psa_status_t
mbedtls_psa_external_get_random(mbedtls_psa_external_random_context_t *context,
                                uint8_t                               *output,
                                size_t                                output_size,
                                size_t                                *output_length)
{
    psa_status_t ret = PSA_ERROR_NOT_SUPPORTED;
    uint32_t cnt = 0U;
    const uint32_t rnd_num_size =  boot_rng_get_rnd_num_length();

    *output_length = 0;

    (void)context;

    do {
        if((output_size == 0) || (output == NULL) || (output_length == NULL)) {
            break;
        }

        /*  Fill output buffer by random values */
        while(cnt < output_size)
        {
            uint32_t bytes2copy = rnd_num_size;
            uint32_t rnd_num;

            if (boot_trng_generate_random(&rnd_num) == false)
            {
                break;
            }

            if ((output_size - cnt) < rnd_num_size) {
                bytes2copy = output_size - cnt;
            }

            (void)memcpy(output + cnt, (void *)(&rnd_num), bytes2copy);

            cnt += bytes2copy;
        }

        *output_length = output_size;

        ret = PSA_SUCCESS;

    } while(false);

    return (ret);
}

#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */

#ifdef FIH_ENABLE_DELAY
/*******************************************************************************
 * Function Name: ifx_se_fih_delay
 *******************************************************************************
 * \brief Redefine weak FIH delay function for SE RT utils API.
 *
 * \return  always returns true or hang in FIH_PANIC.
 *
 ******************************************************************************/
bool ifx_se_fih_delay(void)
{
    return fih_delay();
}
#endif /* FIH_ENABLE_DELAY */
