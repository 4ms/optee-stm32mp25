// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, STMicroelectronics
 */

#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stm32_sysconf.h>
#include <stm32_util.h>
#include <types_ext.h>

#define SYSCON_OFFSET(id)   ((id) & GENMASK_32(15, 0))
#define SYSCON_BANK(id)     (((id) & GENMASK_32(31, 16)) >> 16)

struct io_pa_va syscfg_base[SYSCON_NB_BANKS] = {
	{ .pa = SYSCFG_BASE },
	{ .pa = A35SSC_BASE }
};

/* IO compensation CCR registers bit definition */
#define SYSCFG_CCCR_CS				BIT(9)
#define SYSCFG_CCCR_EN				BIT(8)
#define SYSCFG_CCCR_RAPSRC_MASK			GENMASK_32(7, 4)
#define SYSCFG_CCCR_RANSRC_MASK			GENMASK_32(3, 0)

/* IO compensation CCSR registers bit definition */
#define SYSCFG_CCSR_READY			BIT(8)
#define SYSCFG_CCSR_APSRC_MASK			GENMASK_32(7, 4)
#define SYSCFG_CCSR_ANSRC_MASK			GENMASK_32(3, 0)

#define SYSCFG_CCSR_READY_TIMEOUT_US		U(1000)

/*
 * SYSCFG IO compensation register offsets (base relative)
 */
static uint32_t syscfg_cccr_offset[SYSFG_NB_IO_ID] = {
	[SYSFG_VDDIO1_ID] = SYSCON_ID(SYSCON_SYSCFG, 0x4020U),
	[SYSFG_VDDIO2_ID] = SYSCON_ID(SYSCON_SYSCFG, 0x4018U),
	[SYSFG_VDDIO3_ID] = SYSCON_ID(SYSCON_SYSCFG, 0x4000U),
	[SYSFG_VDDIO4_ID] = SYSCON_ID(SYSCON_SYSCFG, 0x4008U),
	[SYSFG_VDD_IO_ID] = SYSCON_ID(SYSCON_SYSCFG, 0x4010U),
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

TEE_Result stm32mp25_syscfg_enable_io_compensation(enum syscfg_io_ids id)
{
	vaddr_t cccr_addr = stm32mp_syscfg_base(SYSCON_SYSCFG) +
			    SYSCON_OFFSET(syscfg_cccr_offset[id]);
	vaddr_t ccsr_addr = cccr_addr + 4U;
	uint64_t timeout_ref = 0;

	FMSG("Enable IO comp for id %u", id);

	if (io_read32(ccsr_addr) & SYSCFG_CCSR_READY)
		return TEE_SUCCESS;

	io_setbits32(cccr_addr, SYSCFG_CCCR_EN);

	timeout_ref = timeout_init_us(SYSCFG_CCSR_READY_TIMEOUT_US);

	while (!(io_read32(ccsr_addr) & SYSCFG_CCSR_READY))
		if (timeout_elapsed(timeout_ref))
			break;

	if (!(io_read32(ccsr_addr) & SYSCFG_CCSR_READY)) {
		EMSG("IO compensation cell not ready");
		return TEE_ERROR_GENERIC;
	}

	io_clrbits32(cccr_addr, SYSCFG_CCCR_CS);

	return TEE_SUCCESS;
}

TEE_Result stm32mp25_syscfg_disable_io_compensation(enum syscfg_io_ids id)
{
	vaddr_t cccr_addr = stm32mp_syscfg_base(SYSCON_SYSCFG) +
			    SYSCON_OFFSET(syscfg_cccr_offset[id]);
	vaddr_t ccsr_addr = cccr_addr + 4U;
	uint32_t value = 0;

	FMSG("Disable IO comp for id %u", id);

	if (!(io_read32(ccsr_addr) & SYSCFG_CCSR_READY))
		return TEE_SUCCESS;

	value = io_read32(ccsr_addr) & (SYSCFG_CCSR_APSRC_MASK |
		                        SYSCFG_CCSR_ANSRC_MASK);

	io_clrsetbits32(cccr_addr,
			SYSCFG_CCCR_RAPSRC_MASK | SYSCFG_CCCR_RANSRC_MASK,
			value);

	io_setbits32(cccr_addr, SYSCFG_CCCR_CS);

	io_clrbits32(cccr_addr, SYSCFG_CCCR_EN);

	return TEE_SUCCESS;
}

