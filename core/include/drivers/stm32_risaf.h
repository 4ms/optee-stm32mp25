/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022, STMicroelectronics - All Rights Reserved
 */

#ifndef __DRIVERS_STM32_RISAF_H__
#define __DRIVERS_STM32_RISAF_H__

#include <tee_api_types.h>
#include <types_ext.h>

TEE_Result stm32_risaf_reconfigure(paddr_t base);

#endif /*__DRIVERS_STM32_RISAF_H__*/
