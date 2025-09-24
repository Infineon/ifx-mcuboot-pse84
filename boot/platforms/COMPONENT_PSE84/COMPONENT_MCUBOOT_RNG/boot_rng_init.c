/*******************************************************************************
 * File Name: boot_rng_init.c
 *
 *******************************************************************************
 * Copyright 2024, Cypress Semiconductor Corporation (an Infineon company) or
 * an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
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

#include <stddef.h>
#include <stdint.h>

#include "boot_rng.h"
#include "cy_crypto_core_prng.h"
#include "cy_crypto_core_trng.h"

#define TRNG_MAX_BITS 32U

/*******************************************************************************
 * Function Name: boot_rng_init
 *******************************************************************************
 * \brief Implementation of boot_rng_init() for PSE84 architecture.
 *        It initializes and enable MXCRYPTO TRNG, initialize PRNG seed by
 *        TRNG value, disable MXCRYPTO TRNG.
 *
 * return true   if PRNG initialization is successful
 *        false  in other cases
 *
 ******************************************************************************/
bool boot_rng_init(void)
{
    bool ret = false;
    uint32_t rnd = 0U;

    do {
        /* Prevent RND double initialization */
        if (boot_rng_is_initialized()) {
            ret = true;
            break;
        }

        if (boot_trng_generate_random(&rnd)) {
            boot_rng_init_seed(rnd);
            boot_rng_initialization_done();
            ret = true;
        } else {
            break;
        }
    } while (false);

    return ret;
}

void boot_rng_deinit()
{
    /* Prevent RND double initialization */
    if (boot_rng_is_initialized()) {
        boot_rng_clear_initialization_done();
    }
}

bool boot_trng_init(void)
{
    bool ret = false;

    /* Enable HW Crypto block */
    if (CY_CRYPTO_SUCCESS == Cy_Crypto_Core_Enable(CRYPTO)) {
        /* Initialize TRNG with default configuration (max features ON) */
        Cy_Crypto_Core_Trng_Init(CRYPTO, NULL);

        if (CY_CRYPTO_SUCCESS == Cy_Crypto_Core_Trng_Start(CRYPTO, TRNG_MAX_BITS)) {
            ret = true;
        }
    }

    return ret;
}

void boot_trng_deinit(void)
{
    /* Clears all TRNG registers by set to hardware default values. */
    Cy_Crypto_Core_Trng_DeInit(CRYPTO);

    /* Clear crypto block: membuf, registers, stack */
    (void)Cy_Crypto_Core_Cleanup(CRYPTO);

    /* Disable HW Crypto block */
    (void)Cy_Crypto_Core_Disable(CRYPTO);
}

bool boot_trng_generate_random(uint32_t* rnd)
{
    return (CY_CRYPTO_SUCCESS == Cy_Crypto_Core_Trng_ReadData(CRYPTO, rnd));
}