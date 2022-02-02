// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019-2022, STMicroelectronics
 */

#include <config.h>
#include <drivers/clk.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <initcall.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <stm32_util.h>
#include <io.h>
#include <trace.h>
#include <types_ext.h>

/*
 * SYSCFG register offsets (base relative)
 */
#define SYSCFG_SRAM3ERASER			U(0x10)
#define SYSCFG_SRAM3KR				U(0x14)
#define SYSCFG_IOCTRLSETR			U(0x18)
#define SYSCFG_CMPCR				U(0x20)
#define SYSCFG_CMPENSETR			U(0x24)
#define SYSCFG_CMPENCLRR			U(0x28)
#define SYSCFG_CMPSD1CR				U(0x30)
#define SYSCFG_CMPSD1ENSETR			U(0x34)
#define SYSCFG_CMPSD1ENCLRR			U(0x38)
#define SYSCFG_CMPSD2CR				U(0x40)
#define SYSCFG_CMPSD2ENSETR			U(0x44)
#define SYSCFG_CMPSD2ENCLRR			U(0x48)
#define SYSCFG_IDC				U(0x380)
#define SYSCFG_IOSIZE				U(0x400)

/*
 * SYSCFG_SRAM3ERASE Register
 */
#define SYSCFG_SRAM3KR_KEY1			U(0xCA)
#define SYSCFG_SRAM3KR_KEY2			U(0x53)

#define SYSCFG_SRAM3ERASER_SRAM3EO		BIT(1)
#define SYSCFG_SRAM3ERASER_SRAM3ER		BIT(0)

#define SYSCFG_SRAM3ERASE_TIMEOUT_US		U(1000)

/*
 * SYSCFG_CMPCR Register
 */
#define SYSCFG_CMPCR_SW_CTRL			BIT(1)
#define SYSCFG_CMPCR_READY			BIT(8)
#define SYSCFG_CMPCR_RANSRC			GENMASK_32(19, 16)
#define SYSCFG_CMPCR_RANSRC_SHIFT		U(16)
#define SYSCFG_CMPCR_RAPSRC			GENMASK_32(23, 20)
#define SYSCFG_CMPCR_ANSRC_SHIFT		U(24)

#define SYSCFG_CMPCR_READY_TIMEOUT_US		U(1000)

#define CMPENSETR_OFFSET			U(0x4)
#define CMPENCLRR_OFFSET			U(0x8)

/*
 * SYSCFG_CMPENSETR Register
 */
#define SYSCFG_CMPENSETR_MPU_EN			BIT(0)

/*
 * SYSCFG_IDC Register
 */
#define SYSCFG_IDC_DEV_ID_MASK			GENMASK_32(11, 0)
#define SYSCFG_IDC_REV_ID_MASK			GENMASK_32(31, 16)
#define SYSCFG_IDC_REV_ID_SHIFT			U(16)

static vaddr_t get_syscfg_base(void)
{
	static struct io_pa_va base = { .pa = SYSCFG_BASE };

	return io_pa_or_va(&base, SYSCFG_IOSIZE);
}

uint32_t stm32mp_syscfg_get_chip_dev_id(void)
{
	if (IS_ENABLED(CFG_STM32MP13))
		return io_read32(get_syscfg_base() + SYSCFG_IDC) &
		       SYSCFG_IDC_DEV_ID_MASK;

	return 0;
}

static void enable_io_compensation(int cmpcr_offset)
{
	vaddr_t cmpcr_base = get_syscfg_base() + cmpcr_offset;
	uint64_t timeout_ref = 0;

	if (io_read32(cmpcr_base) & SYSCFG_CMPCR_READY)
		return;

	io_setbits32(cmpcr_base + CMPENSETR_OFFSET, SYSCFG_CMPENSETR_MPU_EN);

	timeout_ref = timeout_init_us(SYSCFG_CMPCR_READY_TIMEOUT_US);

	while (!(io_read32(cmpcr_base) & SYSCFG_CMPCR_READY))
		if (timeout_elapsed(timeout_ref)) {
			EMSG("IO compensation cell not ready");
			/* Allow an almost silent failure here */
			break;
		}

	io_clrbits32(cmpcr_base, SYSCFG_CMPCR_SW_CTRL);

	DMSG("SYSCFG.cmpcr = %#"PRIx32, io_read32(cmpcr_base));
}

static void disable_io_compensation(int cmpcr_offset)
{
	vaddr_t cmpcr_base = get_syscfg_base() + cmpcr_offset;
	uint32_t value_cmpcr = 0;
	uint32_t value_cmpcr2 = 0;

	value_cmpcr = io_read32(cmpcr_base);
	value_cmpcr2 = io_read32(cmpcr_base + CMPENSETR_OFFSET);
	if (!(value_cmpcr & SYSCFG_CMPCR_READY &&
	      value_cmpcr2 & SYSCFG_CMPENSETR_MPU_EN))
		return;

	value_cmpcr = io_read32(cmpcr_base) >> SYSCFG_CMPCR_ANSRC_SHIFT;

	io_clrbits32(cmpcr_base, SYSCFG_CMPCR_RANSRC | SYSCFG_CMPCR_RAPSRC);

	value_cmpcr <<= SYSCFG_CMPCR_RANSRC_SHIFT;
	value_cmpcr |= io_read32(cmpcr_base);

	io_write32(cmpcr_base, value_cmpcr | SYSCFG_CMPCR_SW_CTRL);

	DMSG("SYSCFG.cmpcr = %#"PRIx32, io_read32(cmpcr_base));

	io_setbits32(cmpcr_base + CMPENCLRR_OFFSET, SYSCFG_CMPENSETR_MPU_EN);
}

static bool iocomp_enabled;

void stm32mp_syscfg_enable_io_compensation(void)
{
	if (iocomp_enabled)
		return;

	if (clk_enable(stm32mp_rcc_clock_id_to_clk(CK_CSI)) ||
	    clk_enable(stm32mp_rcc_clock_id_to_clk(SYSCFG)))
		panic();

	enable_io_compensation(SYSCFG_CMPCR);

	if (IS_ENABLED(CFG_STM32MP13)) {
		enable_io_compensation(SYSCFG_CMPSD1CR);
		enable_io_compensation(SYSCFG_CMPSD2CR);
	}

	iocomp_enabled = true;
}

void stm32mp_syscfg_disable_io_compensation(void)
{
	if (!iocomp_enabled)
		return;

	disable_io_compensation(SYSCFG_CMPCR);

	if (IS_ENABLED(CFG_STM32MP13)) {
		disable_io_compensation(SYSCFG_CMPSD1CR);
		disable_io_compensation(SYSCFG_CMPSD2CR);
	}

	clk_disable(stm32mp_rcc_clock_id_to_clk(CK_CSI));
	clk_disable(stm32mp_rcc_clock_id_to_clk(SYSCFG));

	iocomp_enabled = false;
}

static TEE_Result stm32mp1_iocomp(void)
{
	stm32mp_syscfg_enable_io_comp();

	return TEE_SUCCESS;
}
driver_init(stm32mp1_iocomp);

TEE_Result stm32mp_syscfg_erase_sram3(void)
{
	vaddr_t base = get_syscfg_base();
	uint64_t timeout_ref = 0;

	if (!IS_ENABLED(CFG_STM32MP13))
		return TEE_ERROR_NOT_SUPPORTED;

	/* Unlock SYSCFG_SRAM3ERASER_SRAM3ER */
	io_write32(base + SYSCFG_SRAM3KR, SYSCFG_SRAM3KR_KEY1);
	io_write32(base + SYSCFG_SRAM3KR, SYSCFG_SRAM3KR_KEY2);

	/* Request SRAM3 erase */
	io_setbits32(base + SYSCFG_SRAM3ERASER, SYSCFG_SRAM3ERASER_SRAM3ER);

	/* Lock SYSCFG_SRAM3ERASER_SRAM3ER */
	io_write32(base + SYSCFG_SRAM3KR, 0);

	/* Wait end of SRAM3 erase */
	timeout_ref = timeout_init_us(SYSCFG_SRAM3ERASE_TIMEOUT_US);
	while (io_read32(base + SYSCFG_SRAM3ERASER) &
	       SYSCFG_SRAM3ERASER_SRAM3EO) {
		if (timeout_elapsed(timeout_ref))
			break;
	}

	/* Timeout may append due to a schedule after the while(test) */
	if (io_read32(base + SYSCFG_SRAM3ERASER) & SYSCFG_SRAM3ERASER_SRAM3EO)
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}
