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

void stm32_risab_clear_illegal_access_flags(void);

#ifdef CFG_TEE_CORE_DEBUG
void stm32_risab_dump_erroneous_data(void);
#else /* CFG_TEE_CORE_DEBUG */
static inline void stm32_risab_dump_erroneous_data(void)
{
}
#endif /* CFG_TEE_CORE_DEBUG */

/**
 * stm32_risaf_reconfigure_region() - Allows to reconfigure a previously
 *				    configured memory region.
 * @reg_base:	Base address of the region
 * @reg_len:	Size of the region
 * @conf:	When @config points to a NULL reference, the function grants
 *		access to OP-TEE  compartment and returns in @config a pointer
 *		to the previously apply configuration, to be later used in a
 *		call to the same API function.
 *		When @config points to a non-NULL reference, that reference is
 *		expected to be obtained from a previous call to this function
 *		and contains the configuration to be applied. In such case, the
 *		function set @config output value to a NULL reference.
 */
TEE_Result stm32_risab_reconfigure_region(uintptr_t reg_base, size_t reg_len,
					  void **conf);

#endif /*__DRIVERS_STM32_RISAB_H__*/
