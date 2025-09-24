/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
 /*******************************************************************************
*
* This software is a port of the open source MCUBoot project.
*
* This file was modified to fit PSoC6-based MCUBoot applications.
*
* Portions of this software, including source code, documentation and related
* materials ("Software"), are owned by Cypress Semiconductor
* Corporation or one of its subsidiaries ("Cypress") and is protected by
* and subject to worldwide patent protection (United States and foreign),
* United States copyright laws and international treaty provisions.
* Therefore, you may use this Software only as provided in the license
* agreement accompanying the software package from which you
* obtained this Software ("EULA").
*
* If no EULA applies, Cypress hereby grants you a personal, non-
* exclusive, non-transferable license to copy, modify, and compile the
* Software source code solely for use in connection with Cypress's
* integrated circuit products. Any reproduction, modification, translation,
* compilation, or representation of this Software except as specified
* above is prohibited without the express written permission of Cypress.
*
* Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO
* WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING,
* BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
* PARTICULAR PURPOSE. Cypress reserves the right to make
* changes to the Software without notice. Cypress does not assume any
* liability arising out of the application or use of the Software or any
* product or circuit described in the Software. Cypress does not
* authorize its products for use in any products where a malfunction or
* failure of the Cypress product may reasonably be expected to result in
* significant property damage, injury or death ("High Risk Product"). By
* including Cypress's product in a High Risk Product, the manufacturer
* of such system or application assumes all risk of such use and in doing
* so agrees to indemnify Cypress against all liability.
*
********************************************************************************/
#include <bootutil/sign_key.h>
#include "mcuboot_config.h"


const int bootutil_key_cnt = 1;

unsigned int pub_key_len;
 const struct bootutil_key bootutil_keys[] = {
    {
        .key = 0,
        .len = &pub_key_len,
    }
};


#if defined(MCUBOOT_ENCRYPT_EC256)

static unsigned int enc_priv_key_len = 138;

#if defined(CUSTOM_KEY_ENC_KEY_ADDR)

const struct bootutil_key bootutil_enc_key = {
    .key = (uint8_t*)CUSTOM_KEY_ENC_KEY_ADDR,
    .len = &enc_priv_key_len,
};

#else /* !defined(CUSTOM_KEY_ENC_KEY_ADDR) */

static const unsigned char enc_priv_key[] = {
  0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
  0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
  0xf6, 0x1e, 0x51, 0x9d, 0xf8, 0xfa, 0xdd, 0xa1, 0xb7, 0xd9, 0xa9, 0x64,
  0x64, 0x3b, 0x54, 0xd0, 0x3d, 0xd0, 0x1f, 0xe5, 0x78, 0xd9, 0x17, 0x98,
  0xa5, 0x28, 0xca, 0xcc, 0x6b, 0x67, 0x9e, 0x06, 0xa1, 0x44, 0x03, 0x42,
  0x00, 0x04, 0x8a, 0x44, 0x73, 0x00, 0x94, 0xc9, 0x80, 0x27, 0x31, 0x0d,
  0x23, 0x36, 0x6b, 0xe9, 0x69, 0x9f, 0xcb, 0xc5, 0x7c, 0xc8, 0x44, 0x1a,
  0x93, 0xe6, 0xee, 0x7d, 0x86, 0xa6, 0xae, 0x5e, 0x93, 0x72, 0x74, 0xd9,
  0xe1, 0x5a, 0x1c, 0x9b, 0x65, 0x1a, 0x2b, 0x61, 0x41, 0x28, 0x02, 0x73,
  0x84, 0x12, 0x97, 0x3a, 0x2d, 0xa2, 0xa0, 0x67, 0x77, 0x02, 0xda, 0x67,
  0x1a, 0x4b, 0xdd, 0xd7, 0x71, 0xcc,
};

const struct bootutil_key bootutil_enc_key = {
    .key = enc_priv_key,
    .len = &enc_priv_key_len,
};
#endif /* defined(CUSTOM_KEY_ENC_KEY_ADDR) */
#endif /* defined(MCUBOOT_ENCRYPT_EC256) */
