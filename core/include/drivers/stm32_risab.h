/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022, STMicroelectronics - All Rights Reserved
 */

#ifndef __DRIVERS_STM32_RISAB_H__
#define __DRIVERS_STM32_RISAB_H__

#include <trace.h>

#define RISAB_NB_MAX_CID_SUPPORTED		U(7)

struct mem_region {
	uintptr_t base;
	size_t size;
};

#if TRACE_LEVEL >= TRACE_INFO
void stm32_risab_dump_erroneous_data(void);
#else /* TRACE_LEVEL >= TRACE_INFO */
static inline void stm32_risab_dump_erroneous_data(void)
{
}
#endif /* TRACE_LEVEL >= TRACE_INFO */

#endif /*__DRIVERS_STM32_RISAB_H__*/
