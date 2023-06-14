// SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-3-Clause)
/*
 * Copyright (C) 2023, STMicroelectronics - All Rights Reserved
 */

#include <drivers/clk_dt.h>
#include <drivers/stm32_gpio.h>
#include <kernel/dt.h>
#include <stdio.h>
#include <tee_api_defines_extensions.h>

static TEE_Result stm32mp_rcc_probe(const void *fdt, int node,
				    const void *compat_data __unused)
{
	struct stm32_pinctrl_list *pinctrl_cfg = NULL;
	TEE_Result res = TEE_SUCCESS;
	struct clk *clk = NULL;
	int idx = 0;

	/* Apply pinctrl configuration if present */
	res = stm32_pinctrl_dt_get_by_index(fdt, node, 0, &pinctrl_cfg);
	if (res && res != TEE_ERROR_ITEM_NOT_FOUND) {
		if (res == TEE_ERROR_DEFER_DRIVER_INIT)
			return res;
		panic("Failed to get RCC pinctrl");
	}

	/* Enable clock(s) if present */
	while (!clk_dt_get_by_index(fdt, node, idx++, &clk)) {
		if (clk_enable(clk))
			panic("Can't enable RCC clock");
	}

	return TEE_SUCCESS;
}

static const struct dt_device_match stm32mp_rcc_match_table[] = {
	{ .compatible = "st,rcc" },
	{ }
};

DEFINE_DT_DRIVER(stm32mp_rcc_dt_driver) = {
	.name = "stm32mp-rcc",
	.match_table = stm32mp_rcc_match_table,
	.probe = stm32mp_rcc_probe,
};
