/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022, STMicroelectronics - All Rights Reserved
 */

#ifndef __DRIVERS_STM32_RISAF_H__
#define __DRIVERS_STM32_RISAF_H__

#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>

TEE_Result stm32_risaf_reconfigure(paddr_t base);

#if TRACE_LEVEL >= TRACE_INFO
void stm32_risaf_dump_erroneous_data(void);
#else /* TRACE_LEVEL >= TRACE_INFO */
static inline void stm32_risaf_dump_erroneous_data(void)
{
}
#endif /* TRACE_LEVEL >= TRACE_INFO */

#endif /*__DRIVERS_STM32_RISAF_H__*/
