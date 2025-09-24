/**
 * \file ifx_psa_crypto_config.h
 * \brief PSA crypto configuration options (set of defines)
 *
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef CRYPTO_CONFIG_TEST_H
#define CRYPTO_CONFIG_TEST_H

/*
 * CBC-MAC is not yet supported via the PSA API in Mbed TLS.
 */
//#define PSA_WANT_ALG_CBC_MAC                     0
// #define PSA_WANT_ALG_CBC_NO_PADDING             0
// #define PSA_WANT_ALG_CBC_PKCS7                  0
// #define PSA_WANT_ALG_CCM                        0
// #define PSA_WANT_ALG_CMAC                       0
// #define PSA_WANT_ALG_CFB                        0
// #define PSA_WANT_ALG_CHACHA20_POLY1305          0
#define PSA_WANT_ALG_DETERMINISTIC_ECDSA

/*It's added to fix the warning 'unused-parameter iv_size'*/
#define PSA_WANT_ALG_ECB_NO_PADDING                1


#define MBEDTLS_PSA_BUILTIN_ALG_ECDH               1
#define PSA_WANT_ALG_CTR                           1
//#define PSA_WANT_ALG_ECDH                          1


#define PSA_WANT_ALG_ECDSA                         1
// #define PSA_WANT_ALG_GCM                        1

#define PSA_WANT_ALG_HKDF                          1
#define PSA_WANT_ALG_HKDF_EXTRACT                  1
#define PSA_WANT_ALG_HKDF_EXPAND                   1
#define PSA_WANT_ALG_HMAC                          1

// #define PSA_WANT_ALG_MD5                        0
// #define PSA_WANT_ALG_OFB                        0
/* PBKDF2-HMAC is not yet supported via the PSA API in Mbed TLS.
 * Note: when adding support, also adjust include/mbedtls/config_psa.h */
//#define PSA_WANT_ALG_PBKDF2_HMAC                 0
// #define PSA_WANT_ALG_RIPEMD160                  0
// #define PSA_WANT_ALG_RSA_OAEP                   0
// #define PSA_WANT_ALG_RSA_PKCS1V15_CRYPT         0
// #define PSA_WANT_ALG_RSA_PKCS1V15_SIGN          0
// #define PSA_WANT_ALG_RSA_PSS                    0
// #define PSA_WANT_ALG_SHA_1                      0
// #define PSA_WANT_ALG_SHA_224                    0
//#define PSA_WANT_ALG_SHA_256                       1
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_256            1
// #define PSA_WANT_ALG_SHA_384                    0
// #define PSA_WANT_ALG_SHA_512                    0

#define PSA_WANT_ALG_STREAM_CIPHER                 1

// #define PSA_WANT_ALG_TLS12_PRF                  0
// #define PSA_WANT_ALG_TLS12_PSK_TO_MS            0
/* PBKDF2-HMAC is not yet supported via the PSA API in Mbed TLS.
 * Note: when adding support, also adjust include/mbedtls/config_psa.h */
//#define PSA_WANT_ALG_XTS                         0

// #define PSA_WANT_ECC_BRAINPOOL_P_R1_256         0
// #define PSA_WANT_ECC_BRAINPOOL_P_R1_384         0
// #define PSA_WANT_ECC_BRAINPOOL_P_R1_512         0
// #define PSA_WANT_ECC_MONTGOMERY_255             0
// #define PSA_WANT_ECC_MONTGOMERY_448             0
// #define PSA_WANT_ECC_SECP_K1_192                0
/*
 * SECP224K1 is buggy via the PSA API in Mbed TLS
 * (https://github.com/Mbed-TLS/mbedtls/issues/3541). Thus, do not enable it by
 * default.
 */
//#define PSA_WANT_ECC_SECP_K1_224                 0
// #define PSA_WANT_ECC_SECP_K1_256                0
// #define PSA_WANT_ECC_SECP_R1_192                0
// #define PSA_WANT_ECC_SECP_R1_224                0
#define PSA_WANT_ECC_SECP_R1_256                   1
// #define PSA_WANT_ECC_SECP_R1_384                0
// #define PSA_WANT_ECC_SECP_R1_521                0


#define PSA_WANT_KEY_TYPE_DERIVE                   1
#define PSA_WANT_KEY_TYPE_HMAC                     1
#define PSA_WANT_KEY_TYPE_AES                      1

// #define PSA_WANT_KEY_TYPE_ARIA                  0
// #define PSA_WANT_KEY_TYPE_CAMELLIA              0
// #define PSA_WANT_KEY_TYPE_CHACHA20              0
// #define PSA_WANT_KEY_TYPE_DES                   0
// #define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR          0
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY           1

#define PSA_WANT_KEY_TYPE_RAW_DATA                 1

// #define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR          0
// #define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY        0

#endif /* CRYPTO_CONFIG_TEST_H */
