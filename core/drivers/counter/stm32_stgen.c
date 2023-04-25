// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, STMicroelectronics
 */

#include <config.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/stm32_stgen.h>
#include <io.h>
#include <keep.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/thread.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stm32_util.h>
#include <util.h>

#define STGENC_CNTCR				U(0x0)
#define STGENC_CNTSR				U(0x4)
#define STGENC_CNTCVL				U(0x8)
#define STGENC_CNTCVU				U(0xC)
#define STGENC_CNTFID0				U(0x20)

/*
 * SMC function ID for STM32MP/TF-A monitor to set CNTFRQ to STGEN frequency.
 * No arguments.
 */
#define STM32_SIP_SMC_STGEN_SET_RATE		0x82000000

struct stm32_stgen_compat_data {
	bool intermediate_clock_parent;
};

struct stgen_pdata {
	struct clk *tsgen_clock;
	struct clk *tsgen_clock_source;
	struct clk *bus_clock;
	vaddr_t base;
};

static struct stgen_pdata stgen_d;

static void set_counter_value(uint64_t counter)
{
	io_write64(stgen_d.base + STGENC_CNTCVL, counter);
}

uint64_t stm32_stgen_get_counter_value(void)
{
	return io_read64(stgen_d.base + STGENC_CNTCVL);
}

/*
 * This function invokes EL3 monitor to update CNTFRQ with STGEN
 * frequency. Updating the CP15 register can only be done by the
 * highest EL on Armv8-A.
 */
static TEE_Result stm32mp_stgen_smc_config(void)
{
	/*
	 * STM32_SIP_SMC_STGEN_SET_RATE call API
	 *
	 * Argument a0: (input) SMCC ID
	 *		(output) status return code
	 */
	struct thread_smc_args stgen_conf_args = {
		.a0 = STM32_SIP_SMC_STGEN_SET_RATE
	};

	thread_smccc(&stgen_conf_args);

	if (stgen_conf_args.a0) {
		EMSG("STGEN configuration failed, error code: %llu",
		     (unsigned long long)stgen_conf_args.a0);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result parse_dt(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const fdt32_t *cuint = NULL;
	struct io_pa_va base = { };
	int lenp = 0;
	size_t reg_size = 0;

	cuint = fdt_getprop(fdt, node, "reg", NULL);
	if (!cuint)
		panic();

	base.pa = _fdt_reg_base_address(fdt, node);
	reg_size = _fdt_reg_size(fdt, node);
	stgen_d.base = io_pa_or_va_secure(&base, reg_size);

	assert(stgen_d.base != 0);

	res = clk_dt_get_by_name(fdt, node, "bus", &stgen_d.bus_clock);
	if (res == TEE_ERROR_DEFER_DRIVER_INIT)
		return TEE_ERROR_DEFER_DRIVER_INIT;
	else if (res)
		panic("No stgen bus clock available in device tree");

	res = clk_dt_get_by_name(fdt, node, "tsgen_clk", &stgen_d.tsgen_clock);
	if (res == TEE_ERROR_DEFER_DRIVER_INIT)
		return TEE_ERROR_DEFER_DRIVER_INIT;
	else if (res)
		panic("No tsgen clock available in device tree");

	cuint = fdt_getprop(fdt, node, "st,tsgen-clk-source", &lenp);
	if (!cuint) {
		DMSG("No tsgen clock source found");
		return TEE_SUCCESS;
	}

	lenp /= sizeof(uint32_t);
	if (lenp != 2)
		panic("Incorrect tsgen clock source");

	stgen_d.tsgen_clock_source =
		stm32mp_rcc_clock_id_to_clk(fdt32_to_cpu(cuint[1]));

	assert(stgen_d.tsgen_clock_source);

	return TEE_SUCCESS;
}

static TEE_Result stgen_probe(const void *fdt, int node,
			      const void *compat_data)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint64_t stgen_counter = 0;
	unsigned long clock_source_rate = 0;
	unsigned long initial_stgen_rate = 0;
	struct clk *tsgen_source = NULL;
	const struct stm32_stgen_compat_data *compat_d = compat_data;

	res = parse_dt(fdt, node);
	if (res)
		return res;

	/*
	 * Some SoCs may have intermediate clock signals between tsgen and
	 * desired tsgen clock source. Use tsgen_source to ease manipulation.
	 */
	tsgen_source = stgen_d.tsgen_clock;
	if (compat_d->intermediate_clock_parent) {
		tsgen_source = clk_get_parent(stgen_d.tsgen_clock);
		assert(tsgen_source);
	}

	res = clk_enable(stgen_d.tsgen_clock);
	if (res)
		return res;

	res = clk_enable(stgen_d.bus_clock);
	if (res) {
		clk_disable(stgen_d.tsgen_clock);
		return res;
	}

	/*
	 * Do nothing if tsgen_clock parent clock is already
	 * targeted clock source or if there is no STGEN source clock
	 */
	if (!stgen_d.tsgen_clock_source ||
	    clk_get_parent(tsgen_source) == stgen_d.tsgen_clock_source)
		goto end;

	initial_stgen_rate = clk_get_rate(stgen_d.tsgen_clock);

	/*
	 * Disable STGEN counter. At cold boot, we accept the counter delta
	 * due to STGEN reconfiguration
	 */
	io_clrbits32(stgen_d.base + STGENC_CNTCR, BIT(0));

	clock_source_rate = clk_get_rate(stgen_d.tsgen_clock_source);

	res = clk_set_parent(tsgen_source, stgen_d.tsgen_clock_source);
	if (res)
		panic("Couldn't set tsgen source");

	res = clk_set_rate(tsgen_source, clock_source_rate);
	if (res)
		panic("Couldn't set tsgen clock rate");

	io_write32(stgen_d.base + STGENC_CNTFID0, clock_source_rate);
	if (io_read32(stgen_d.base + STGENC_CNTFID0) != clock_source_rate)
		panic("Couldn't modify STGEN clock rate");

	/* Update counter value according to the new STGEN clock frequency */
	stgen_counter = stm32_stgen_get_counter_value();
	stgen_counter = stgen_counter * clock_source_rate / initial_stgen_rate;
	set_counter_value(stgen_counter);

	if (IS_ENABLED(CFG_WITH_ARM_TRUSTED_FW))
		stm32mp_stgen_smc_config();
end:
	io_setbits32(stgen_d.base + STGENC_CNTCR, BIT(0));

	return TEE_SUCCESS;
}

static const struct stm32_stgen_compat_data stm32_stgen_mp1 = {
	.intermediate_clock_parent = false,
};

static const struct stm32_stgen_compat_data stm32_stgen_mp2 = {
	.intermediate_clock_parent = true,
};

static const struct dt_device_match stm32_stgen_match_table[] = {
	{
		.compatible = "st,stm32mp1-stgen",
		.compat_data = &stm32_stgen_mp1
	},
	{
		.compatible = "st,stm32mp25-stgen",
		.compat_data = &stm32_stgen_mp2
	},
	{ }
};

DEFINE_DT_DRIVER(stm32_stgen_dt_driver) = {
	.name = "stm32_stgen",
	.match_table = stm32_stgen_match_table,
	.probe = stgen_probe,
};