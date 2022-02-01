// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019-2020, STMicroelectronics
 */

#include <assert.h>
#include <config.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/tzc400.h>
#include <initcall.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

struct stm32mp_tzc_region {
	uint32_t cfg;
	uint32_t addr;
	uint32_t len;
};

struct stm32mp_tzc_platdata {
	const char *name;
	uintptr_t base;
	struct clk *clk[2];
	int irq;
	uint32_t mem_base;
	uint32_t mem_size;
	struct firewall_compat *tzc_compat;
	struct stm32mp_tzc_region *regions;
};

struct stm32mp_tzc_driver_data {
	uint32_t nb_filters;
	uint32_t nb_regions;
};

struct tzc_device {
	struct stm32mp_tzc_platdata pdata;
	struct stm32mp_tzc_driver_data *ddata;
	struct itr_handler *itr;
	struct tzc_region_config *reg;
	bool *reg_locked;
};

#define filter_mask(_width) GENMASK_32(((_width) - 1U), 0U)

static enum itr_return tzc_it_handler(struct itr_handler *handler __unused)
{
	EMSG("TZC permission failure");
	tzc_fail_dump();

	if (IS_ENABLED(CFG_STM32MP_PANIC_ON_TZC_PERM_VIOLATION))
		panic();
	else
		tzc_int_clear();

	return ITRR_HANDLED;
}
DECLARE_KEEP_PAGER(tzc_it_handler);

static int tzc_find_region(vaddr_t base, size_t size,
			   struct tzc_region_config *region_cfg)
{
	uint8_t i = 1;

	while (true) {
		if (tzc_get_region_config(i, region_cfg) != TEE_SUCCESS)
			return 0;

		if (region_cfg->base <= base &&
		    region_cfg->top >= (base + size - 1))
			return i;

		i++;
		region_cfg++;
	}
}

#ifdef CFG_CORE_RESERVED_SHM
static bool tzc_region_is_non_secure(struct tzc_device *tzc_dev,
				     struct tzc_region_config *region_cfg)
{
	uint32_t ns_cpu_mask = TZC_REGION_ACCESS_RDWR(STM32MP1_TZC_A7_ID);
	uint32_t filters_mask = filter_mask(tzc_dev->ddata->nb_filters);

	return region_cfg->sec_attr == TZC_REGION_S_NONE &&
		(region_cfg->ns_device_access & ns_cpu_mask) == ns_cpu_mask &&
		region_cfg->filters == filters_mask;
}
#endif

static bool tzc_region_is_secure(struct tzc_device *tzc_dev,
				 struct tzc_region_config *region_cfg)
{
	uint32_t filters_mask = filter_mask(tzc_dev->ddata->nb_filters);

	return region_cfg->sec_attr == TZC_REGION_S_RDWR &&
		region_cfg->ns_device_access == 0 &&
		region_cfg->filters == filters_mask;
}

static void stm32mp_tzc_check_boot_region(struct tzc_device *tzc_dev)
{
	int idx = 0;

	idx = tzc_find_region(CFG_TZDRAM_START, CFG_TZDRAM_SIZE,
			      &tzc_dev->reg[1]);
	if (!idx || !tzc_region_is_secure(tzc_dev, &tzc_dev->reg[idx]))
		panic("TZC: bad permissions on TEE RAM");

#ifdef CFG_CORE_RESERVED_SHM
	idx = tzc_find_region(CFG_SHMEM_START, CFG_SHMEM_SIZE,
			      &tzc_dev->reg[1]);
	if (!idx || !tzc_region_is_non_secure(tzc_dev, &tzc_dev->reg[idx]))
		panic("TZC: bad permissions on TEE reserved SHMEM");
#endif
}

static void tzc_set_driverdata(struct tzc_device *tzc_dev)
{
	struct stm32mp_tzc_driver_data *ddata = tzc_dev->ddata;
	uintptr_t base = tzc_dev->pdata.base;
	uint32_t regval = 0;

	clk_enable(tzc_dev->pdata.clk[0]);

	regval = io_read32(base + BUILD_CONFIG_OFF);
	ddata->nb_filters = ((regval >> BUILD_CONFIG_NF_SHIFT) &
			     BUILD_CONFIG_NF_MASK) + 1;
	ddata->nb_regions = ((regval >>	BUILD_CONFIG_NR_SHIFT) &
			     BUILD_CONFIG_NR_MASK);

	clk_disable(tzc_dev->pdata.clk[0]);

	DMSG("TZC400 Filters %"PRIu32" Regions %"PRIu32, ddata->nb_filters,
	     ddata->nb_regions);
}

static struct tzc_device *tzc_alloc(void)
{
	struct tzc_device *tzc_dev = NULL;
	struct stm32mp_tzc_driver_data *ddata = NULL;

	tzc_dev = calloc(1, sizeof(*tzc_dev));
	ddata = calloc(1, sizeof(*ddata));

	if (tzc_dev && ddata) {
		tzc_dev->ddata = ddata;
		return tzc_dev;
	}

	free(ddata);
	free(tzc_dev);

	return NULL;
}

static void tzc_free(struct tzc_device *tzc_dev)
{
	if (tzc_dev) {
		free(tzc_dev->ddata);
		free(tzc_dev);
	}
}

static TEE_Result stm32mp_tzc_parse_fdt(struct tzc_device *tzc_dev,
					const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dt_node_info dt_info = { };
	struct io_pa_va base = { };
	int offs = 0;

	_fdt_fill_device_info(fdt, &dt_info, node);
	if (dt_info.reg == DT_INFO_INVALID_REG ||
	    dt_info.reg_size == DT_INFO_INVALID_REG_SIZE ||
	    dt_info.clock == DT_INFO_INVALID_CLOCK ||
	    dt_info.interrupt == DT_INFO_INVALID_INTERRUPT)
		panic("Missing properties in TZC DT node");

	base.pa = dt_info.reg;
	tzc_dev->pdata.name = fdt_get_name(fdt, node, NULL);
	tzc_dev->pdata.base = io_pa_or_va_secure(&base, dt_info.reg_size);
	tzc_dev->pdata.irq = dt_info.interrupt;

	res = clk_dt_get_by_index(fdt, node, 0, tzc_dev->pdata.clk);
	if (res)
		return res;

	res = clk_dt_get_by_index(fdt, node, 1, tzc_dev->pdata.clk + 1);
	if (res || !tzc_dev->pdata.clk[1])
		DMSG("No secondary clock for %s",
		     fdt_get_name(fdt, node, NULL));

	/* Use memory node instead of that new one */
	offs = fdt_node_offset_by_prop_value(fdt, offs, "device_type",
					     "memory", sizeof("memory"));
	if (offs < 0)
		panic("No memory reference for TZC DT node");

	tzc_dev->pdata.mem_base = _fdt_reg_base_address(fdt, offs);
	tzc_dev->pdata.mem_size = _fdt_reg_size(fdt, offs);

	assert(tzc_dev->pdata.mem_base != (paddr_t)-1 &&
	       tzc_dev->pdata.mem_size != (size_t)-1);

	return TEE_SUCCESS;
}

static TEE_Result stm32mp1_tzc_probe(const void *fdt, int node,
				     const void *compt_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct tzc_device *tzc_dev = NULL;

	assert(fdt && node >= 0);

	tzc_dev = tzc_alloc();
	if (!tzc_dev)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = stm32mp_tzc_parse_fdt(tzc_dev, fdt, node);
	if (res)
		goto err;

	if (tzc_dev->ddata) {
		tzc_set_driverdata(tzc_dev);
		tzc_dev->reg = calloc(tzc_dev->ddata->nb_regions,
				      sizeof(*tzc_dev->reg));
		tzc_dev->reg_locked = calloc(tzc_dev->ddata->nb_regions,
					     sizeof(*tzc_dev->reg_locked));
		if (!tzc_dev->reg || !tzc_dev->reg_locked) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	}

	clk_enable(tzc_dev->pdata.clk[0]);
	if (tzc_dev->pdata.clk[1])
		clk_enable(tzc_dev->pdata.clk[1]);

	tzc_init((vaddr_t)tzc_dev->pdata.base);
	tzc_dump_state();

	stm32mp_tzc_check_boot_region(tzc_dev);

	tzc_dev->itr = itr_alloc_add(tzc_dev->pdata.irq, tzc_it_handler,
				     ITRF_TRIGGER_LEVEL, tzc_dev);
	if (!tzc_dev->itr)
		panic();

	itr_enable(tzc_dev->pdata.irq);
	tzc_set_action(TZC_ACTION_ERR);

	return TEE_SUCCESS;

err:
	free(tzc_dev->reg);
	tzc_free(tzc_dev);

	return res;
}

static const struct dt_device_match tzc_secu_match_table[] = {
	{ .compatible = "st,stm32mp1-tzc" },
	{ }
};

DEFINE_DT_DRIVER(tzc_stm32mp1_dt_driver) = {
	.name = "stm32mp1-tzc400",
	.type = DT_DRIVER_NOTYPE,
	.match_table = tzc_secu_match_table,
	.probe = stm32mp1_tzc_probe,
};
