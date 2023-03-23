// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, STMicroelectronics
 */
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/regulator.h>
#include <drivers/stm32mp1_pwr.h>
#include <initcall.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <stm32_util.h>
#include <trace.h>
#include <util.h>

struct cpu_dvfs {
	unsigned int freq_khz;
	unsigned int volt_mv;
};

struct cpu_opp {
	unsigned int current_opp;
	unsigned int opp_count;
	struct clk *clock;
	struct rdev *rdev;
	struct cpu_dvfs *dvfs;
};

static struct cpu_opp cpu_opp;

/* Mutex for protecting CPU OPP changes */
static struct mutex cpu_opp_mu = MUTEX_INITIALIZER;

#define MPU_RAM_LOW_SPEED_THRESHOLD 1320

size_t stm32mp1_cpu_opp_count(void)
{
	return cpu_opp.opp_count;
}

unsigned int stm32mp1_cpu_opp_level(size_t opp_index)
{
	assert(opp_index < cpu_opp.opp_count);

	return cpu_opp.dvfs[opp_index].freq_khz;
}

static TEE_Result _set_opp_clk_rate(unsigned int opp)
{
#ifdef CFG_STM32MP15
	return stm32mp1_set_opp_khz(cpu_opp.dvfs[opp].freq_khz);
#else
	return clk_set_rate(cpu_opp.clock, cpu_opp.dvfs[opp].freq_khz * 1000UL);
#endif
}

static TEE_Result opp_set_voltage(struct rdev *rdev, uint16_t volt_mv)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint16_t mv = 0;

	res = regulator_set_voltage(rdev, volt_mv);
	if (!res)
		return TEE_SUCCESS;

	if (res != TEE_ERROR_NOT_IMPLEMENTED) {
		EMSG("Failed to set voltage to %umV: %#"PRIx32, volt_mv, res);
		return res;
	}

	/* Fixed regulator management */
	if (regulator_get_voltage(rdev, &mv))
		return TEE_ERROR_GENERIC;

	if (mv != volt_mv)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result set_clock_then_voltage(unsigned int opp)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (_set_opp_clk_rate(opp)) {
		EMSG("Failed to set clock to %ukHz",
		     cpu_opp.dvfs[opp].freq_khz);
		return TEE_ERROR_GENERIC;
	}

#ifdef CFG_STM32MP13
	if (cpu_opp.dvfs[opp].volt_mv <= MPU_RAM_LOW_SPEED_THRESHOLD)
		io_setbits32(stm32_pwr_base(), PWR_CR1_MPU_RAM_LOW_SPEED);
#endif

	res = opp_set_voltage(cpu_opp.rdev, cpu_opp.dvfs[opp].volt_mv);
	if (res) {
		unsigned int current_opp = cpu_opp.current_opp;

		if (current_opp == cpu_opp.opp_count)
			panic();

		if (_set_opp_clk_rate(current_opp))
			EMSG("Failed to restore clock");

		return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result set_voltage_then_clock(unsigned int opp)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = opp_set_voltage(cpu_opp.rdev, cpu_opp.dvfs[opp].volt_mv);
	if (res)
		return res;

#ifdef CFG_STM32MP13
	if (cpu_opp.dvfs[opp].volt_mv > MPU_RAM_LOW_SPEED_THRESHOLD)
		io_clrbits32(stm32_pwr_base(), PWR_CR1_MPU_RAM_LOW_SPEED);
#endif

	if (_set_opp_clk_rate(opp)) {
		unsigned int current_opp = cpu_opp.current_opp;
		unsigned int previous_volt = 0U;

		EMSG("Failed to set clock");

		if (current_opp == cpu_opp.opp_count)
			panic();

		previous_volt = cpu_opp.dvfs[current_opp].volt_mv;

		opp_set_voltage(cpu_opp.rdev, previous_volt);

		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result stm32mp1_cpu_opp_set_level(unsigned int level)
{
	unsigned int current_level = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int opp = 0;

	mutex_lock(&cpu_opp_mu);

	/* Perf level relates straight to CPU frequency in kHz */
	current_level = cpu_opp.dvfs[cpu_opp.current_opp].freq_khz;

	if (level == current_level) {
		mutex_unlock(&cpu_opp_mu);
		return TEE_SUCCESS;
	}

	for (opp = 0; opp < cpu_opp.opp_count; opp++)
		if (level == cpu_opp.dvfs[opp].freq_khz)
			break;

	if (opp == cpu_opp.opp_count) {
		mutex_unlock(&cpu_opp_mu);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (level < current_level)
		res = set_clock_then_voltage(opp);
	else
		res = set_voltage_then_clock(opp);

	if (!res)
		cpu_opp.current_opp = opp;

	mutex_unlock(&cpu_opp_mu);

	return res;
}

TEE_Result stm32mp1_cpu_opp_read_level(unsigned int *level)
{
	if (cpu_opp.current_opp >= cpu_opp.opp_count)
		return TEE_ERROR_BAD_STATE;

	*level = cpu_opp.dvfs[cpu_opp.current_opp].freq_khz;

	return TEE_SUCCESS;
}

static TEE_Result cpu_opp_pm(enum pm_op op, unsigned int pm_hint __unused,
			     const struct pm_callback_handle *hdl __unused)
{
	unsigned long clk_cpu = 0;
	unsigned int opp = cpu_opp.current_opp;

	assert(op == PM_OP_SUSPEND || op == PM_OP_RESUME);

	if (op == PM_OP_RESUME) {
		FMSG("cpu opp resume opp to %u", opp);

		clk_cpu = clk_get_rate(cpu_opp.clock);
		assert(clk_cpu);
		if (cpu_opp.dvfs[opp].freq_khz * 1000U >= clk_cpu)
			return set_voltage_then_clock(opp);
		else
			return set_clock_then_voltage(opp);
	}

	return TEE_SUCCESS;
}
DECLARE_KEEP_PAGER(cpu_opp_pm);

static TEE_Result stm32mp1_cpu_opp_is_supported(const void *fdt, int subnode)
{
	const fdt32_t *cuint32 = NULL;
	uint32_t opp = 0;

	cuint32 = fdt_getprop(fdt, subnode, "opp-supported-hw", NULL);

	if (!cuint32) {
		DMSG("Can't find property opp-supported-hw");
		return TEE_ERROR_GENERIC;
	}

	opp = fdt32_to_cpu(*cuint32);
	if (!stm32mp_supports_cpu_opp(opp)) {
		EMSG("Invalid opp-supported-hw %#"PRIx32, opp);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32mp1_cpu_opp_get_dt_subnode(const void *fdt, int node)
{
	const fdt64_t *cuint64 = NULL;
	const fdt32_t *cuint32 = NULL;
	uint64_t freq_khz = 0;
	uint32_t volt_mv = 0;
	unsigned long clk_cpu = 0;
	unsigned int i = 0;
	int subnode = -1;
	TEE_Result res = TEE_ERROR_GENERIC;

	fdt_for_each_subnode(subnode, fdt, node)
		if (!stm32mp1_cpu_opp_is_supported(fdt, subnode))
			cpu_opp.opp_count++;

	cpu_opp.dvfs = calloc(1, cpu_opp.opp_count * sizeof(*cpu_opp.dvfs));
	if (!cpu_opp.dvfs)
		return TEE_ERROR_OUT_OF_MEMORY;

	cpu_opp.current_opp = cpu_opp.opp_count;

	fdt_for_each_subnode(subnode, fdt, node) {
		if (stm32mp1_cpu_opp_is_supported(fdt, subnode))
			continue;

		cuint64 = fdt_getprop(fdt, subnode, "opp-hz", NULL);
		if (!cuint64) {
			DMSG("Missing opp-hz");
			return TEE_ERROR_GENERIC;
		}

		freq_khz = fdt64_to_cpu(*cuint64) / 1000ULL;
		if (freq_khz > (uint64_t)UINT32_MAX) {
			DMSG("Invalid opp-hz %"PRIu64, freq_khz);
			return TEE_ERROR_GENERIC;
		}

		cuint32 = fdt_getprop(fdt, subnode, "opp-microvolt", NULL);
		if (!cuint32) {
			DMSG("Missing opp-microvolt");
			return TEE_ERROR_GENERIC;
		}

		volt_mv = fdt32_to_cpu(*cuint32) / 1000U;

		cpu_opp.dvfs[i].freq_khz = freq_khz;
		cpu_opp.dvfs[i].volt_mv = volt_mv;

		DMSG("Found OPP %u (%"PRIu64"kHz/%"PRIu32"mV) from DT",
		     i, freq_khz, volt_mv);

		if (fdt_getprop(fdt, subnode, "st,opp-default", NULL)) {
			assert(cpu_opp.current_opp == cpu_opp.opp_count);
			clk_cpu = clk_get_rate(cpu_opp.clock);
			assert(clk_cpu);
			if (freq_khz * 1000U > clk_cpu)
				res = set_voltage_then_clock(i);
			else
				res = set_clock_then_voltage(i);

			if (res)
				return res;

			cpu_opp.current_opp = i;
		}

		i++;
	}

	if (cpu_opp.current_opp == cpu_opp.opp_count)
		return TEE_ERROR_GENERIC;

	register_pm_driver_cb(cpu_opp_pm, NULL, "cpu-opp");

	return TEE_SUCCESS;
}

static TEE_Result get_cpu_parent(const void *fdt)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const struct fdt_property *prop = NULL;
	int node = fdt_node_offset_by_compatible(fdt, -1, "arm,cortex-a7");

	if (node < 0) {
		EMSG("Compatible \"arm,cortex-a7\" not found");
		panic();
	}

	res = clk_dt_get_by_index(fdt, node, 0, &cpu_opp.clock);
	if (res)
		return res;

	prop = fdt_get_property(fdt, node, "operating-points-v2", NULL);
	if (!prop) {
		EMSG("OPP table not defined by CPU");
		return TEE_ERROR_GENERIC;
	}

	cpu_opp.rdev = regulator_get_by_supply_name(fdt, node, "cpu");
	if (!cpu_opp.rdev)
		return TEE_ERROR_DEFER_DRIVER_INIT;

	return TEE_SUCCESS;
}

static TEE_Result
stm32mp1_cpu_opp_init(const void *fdt, int node,
		      const void *compat_data __unused)
{
	TEE_Result res = TEE_SUCCESS;
	uint16_t cpu_voltage __maybe_unused = 0;

	res = get_cpu_parent(fdt);
	if (res)
		return res;

#ifdef CFG_STM32MP15
	res = regulator_get_voltage(cpu_opp.rdev, &cpu_voltage);
	if (res)
		return res;

	if (stm32mp1_clk_compute_all_pll1_settings(cpu_voltage))
		panic();
#endif

	res = stm32mp1_cpu_opp_get_dt_subnode(fdt, node);

	return res;
}

static const struct dt_device_match stm32mp1_cpu_opp_match_table[] = {
	{ .compatible = "operating-points-v2" },
	{ }
};

DEFINE_DT_DRIVER(stm32mp1_opp_dt_driver) = {
	.name = "stm32mp1-cpu-opp",
	.match_table = stm32mp1_cpu_opp_match_table,
	.probe = &stm32mp1_cpu_opp_init,
};
