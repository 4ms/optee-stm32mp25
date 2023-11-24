/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022, STMicroelectronics
 */

#ifndef __STM32MP25_PWR_H
#define __STM32MP25_PWR_H

#include <kernel/interrupt.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

vaddr_t stm32_pwr_base(void);

#endif /*__STM32MP25_PWR_H*/
