/******************************************************************************
 * File Name: cleanup.h
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

#ifndef CLEANUP_H
#define CLEANUP_H

#include <stdint.h>

#if defined(__CC_ARM) || defined(__ARMCC_VERSION)
#define STACKLESS __STATIC_INLINE
#elif defined(__ICCARM__)
#define STACKLESS __stackless __STATIC_INLINE
#elif defined(__GNUC__)
#define STACKLESS __STATIC_INLINE
#endif

#define LOOP_FOREVER() \
    do {               \
        __ASM volatile("1: wfi \n"\
            "           b 1b \n"\
            "           b 1b \n"\
            "           b 1b \n"\
            "           b 1b \n"\
            "           b 1b \n"\
            "           b 1b \n"\
            "           b 1b");\
    } while (true)

typedef void (*reset_handler_t)(void);

typedef struct vect_tbl_start_s {
    uint32_t        stack_pointer;
    reset_handler_t reset_handler;
} vect_tbl_start_t;

/*******************************************************************************
 * Function Name: cleanup_helper
 ********************************************************************************
 * Summary:
 * Cleans ram region
 * This function used inside cleanup_and_boot function
 *
 * Parameters:
 *  l - region start pointer(lower address)
 *  r - region end pointer (higher address)
 *
 * Note:
 *   This function is critical to be "stackless".
 *   Two oncoming indices algorithm is used to prevent compiler optimization
 *     from calling memset function.
 *
 *******************************************************************************/
STACKLESS
void cleanup_helper(register uint8_t *l, register uint8_t *r)
{
    register uint8_t v = 0u;

    do {
        *l = v;
        ++l;

        --r;
        *r = v;
    } while (l < r);
    
    __COMPILER_BARRIER();
}

/*******************************************************************************
 * Function Name: cleanup_and_boot
 ********************************************************************************
 * Summary:
 * This function cleans all ram and boots target app
 *
 * Parameters:
 * p_vect_tbl_start - target app vector table address
 *
 *
 *******************************************************************************/
STACKLESS __NO_RETURN void cleanup_and_boot(register fih_uint *app_addr)
{
    vect_tbl_start_t *p_vect_tbl_start =
        (vect_tbl_start_t *)fih_uint_decode(*app_addr);
    SCB->VTOR = (uint32_t)(void*)p_vect_tbl_start;
    __DSB();

    /* Detect Fault Injection */
    if (fih_uint_decode(*app_addr) != SCB->VTOR)
    {
        LOOP_FOREVER();
    }

    __set_MSPLIM(0U);
    __DMB();

    /* Detect Fault Injection */
    if (0U != __get_MSPLIM())
    {
        LOOP_FOREVER();
    }

    __set_MSP(p_vect_tbl_start->stack_pointer);
    __DMB();

    /* Detect Fault Injection */
    if (((vect_tbl_start_t *)fih_uint_decode(*app_addr))->stack_pointer != __get_MSP())
    {
        LOOP_FOREVER();
    }

    /* Detect Fault Injection */
    if ((uint32_t)(void*)p_vect_tbl_start != SCB->VTOR)
    {
        LOOP_FOREVER();
    }

#if !defined(MCUBOOT_SKIP_CLEANUP_RAM)
#if defined(__CC_ARM) || defined(__ARMCC_VERSION)
    {
        extern uint8_t  Image$$CLEANUP_START$$Base[];
        extern uint8_t  Image$$CLEANUP_END$$Base[];

        cleanup_helper(Image$$CLEANUP_START$$Base, Image$$CLEANUP_END$$Base);
    }
#elif defined(__ICCARM__)
    {
        #pragma section = ".data"
        #pragma section = "CSTACK"

        cleanup_helper(__section_begin(".data"), __section_end("CSTACK"));
    }
#elif defined(__GNUC__)
    {
        extern uint8_t __data_start__[];
        extern uint8_t __StackTop[];

        cleanup_helper(__data_start__, __StackTop);
    }
#endif
#endif /* !defined(MCUBOOT_SKIP_CLEANUP_RAM) */
    /* Jump to next app */
    p_vect_tbl_start->reset_handler();
    
    /* Unreachable code */
    do {
        __WFI();
    } while (true);
}

#endif /* CLEANUP_H */
