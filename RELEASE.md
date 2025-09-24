# ifx-mcuboot-pse84

A middleware library for *PSOC&trade; Edge MCU E84 platform that is a fork of the MCUboot project https://github.com/mcu-tools/mcuboot
maintained by Infineon Technologies AG, with additional features and
platform support for Infineon microcontrollers.

### What's Included?
* Image validation with EC256 key.
* Up to 5 images support.
* RAMload to the CM33 SRAM
* Encrypted images with XIP on-the-fly decryption
* HW Security counters
* Dependency check
* Measured boot
* SE RAM App staging


### What Changed?
#### v1.0.0
* Initial release

### Supported Software and Tools
This version of the Retarget IO was validated for compatibility with the following Software and Tools:

| Software and Tools                        | Version |
| :---                                      | :----:  |
| ModusToolbox™ Software Environment        | 3.6.0   |
| GCC Compiler                              | 14.2.1  |
| IAR Compiler                              | 9.50.2  |
| ARM Compiler                              | 6.22    |

Minimum required ModusToolbox™ Software Environment: v3.6.0


---
© Cypress Semiconductor Corporation (an Infineon company) or an affiliate of Cypress Semiconductor Corporation, 2019-2025.
