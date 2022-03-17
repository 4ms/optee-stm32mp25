// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, STMicroelectronics
 */

#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stm32_sysconf.h>
#include <stm32_util.h>
#include <types_ext.h>

#define SYSCON_OFFSET(id)   ((id) & GENMASK_32(15, 0))
#define SYSCON_BANK(id)     (((id) & GENMASK_32(31, 16)) >> 16)

struct io_pa_va syscfg_base[SYSCON_NB_BANKS] = {
	{ .pa = A35SSC_BASE }
};

static vaddr_t stm32mp_syscfg_base(uint32_t id)
{
	uint32_t bank = SYSCON_BANK(id);

	assert(bank < SYSCON_NB_BANKS);

	return io_pa_or_va_secure(&syscfg_base[bank], 1);
}

void stm32mp_syscfg_write(uint32_t id, uint32_t value, uint32_t bitmsk)
{
	vaddr_t syconf_base = stm32mp_syscfg_base(id);

	io_mask32(syconf_base + SYSCON_OFFSET(id), value, bitmsk);
}

uint32_t stm32mp_syscfg_read(uint32_t id)
{
	return io_read32(stm32mp_syscfg_base(id) + SYSCON_OFFSET(id));
}
