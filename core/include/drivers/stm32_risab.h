/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022, STMicroelectronics - All Rights Reserved
 */

#ifndef __DRIVERS_STM32_RISAB_H__
#define __DRIVERS_STM32_RISAB_H__

#define RISAB_NB_MAX_CID_SUPPORTED		U(7)

struct mem_region {
	uintptr_t base;
	size_t size;
};

#endif /*__DRIVERS_STM32_RISAB_H__*/
