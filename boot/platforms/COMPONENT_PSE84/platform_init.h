#pragma once

/**
 * @file platform.h
 *
 * @brief This file contains the declarations of platform initialization and deinitialization functions.
 */

#include "cy_result.h"

/**
 * @brief Initializes the low level platform peripherals.
 *
 * This function initializes the low level platform peripherals and returns a status code.
 *
 * @return The status code of the platform initialization.
 */
cy_rslt_t platform_ll_init(void);

/**
 * @brief Initializes the platform.
 *
 * This function initializes the platform and returns a status code.
 *
 * @return The status code of the platform initialization.
 */
cy_rslt_t platform_init(void);

/**
 * @brief Deinitializes the platform.
 *
 * This function deinitializes the platform.
 */
void platform_deinit(void);

#if MCUBOOT_LOG_LEVEL != MCUBOOT_LOG_LEVEL_OFF
/**
 * @brief Initializes the debug log uart output.
 *
 * This function initializes the platform SCB module for UART communication.
 */
cy_rslt_t platform_debug_log_init(void);

/**
 * @brief Deinitializes the debug log uart output.
 *
 * This function deinitializes the platform SCB module.
 */
void platform_debug_log_deinit(void);
#endif /* MCUBOOT_LOG_LEVEL != MCUBOOT_LOG_LEVEL_OFF */

/**
 * @brief Calculates the physical address based on platform memory layout
 *
 * @param[in] address   Application virtual address
 * @return Application physical address
 */
uintptr_t platform_remap_address(uintptr_t address);

/**
 * @brief Prepare platform settings for deep sleep mode.
 * 
 * This function sets the necessary settings for deep sleep mode.
 *
 * @return The status code of the deep sleep preparing.
 */
cy_rslt_t platform_deep_sleep_prepare(void);