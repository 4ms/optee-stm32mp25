/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, STMicroelectronics - All Rights Reserved
 */

#ifndef __DRIVERS_CRYPTO_STM32_COMMON_H
#define __DRIVERS_CRYPTO_STM32_COMMON_H

#include <tee_api_types.h>

enum cipher_ip_id {
	CRYP_IP,
	SAES_IP,
};

TEE_Result stm32_register_authenc(void);
TEE_Result stm32_register_cipher(enum cipher_ip_id);
TEE_Result stm32_register_ecc(void);
TEE_Result stm32_register_hash(void);
TEE_Result stm32_register_hmac(void);

#endif /* __DRIVERS_CRYPTO_STM32_COMMON_H */
