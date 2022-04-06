// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2022, STMicroelectronics
 */

#include <drivers/rstctrl.h>
#include <drivers/stm32_rstctrl.h>
#include <dt-bindings/reset/stm32mp25-resets.h>
#include <kernel/dt.h>

static TEE_Result reset_assert_setr(struct rstctrl *rstctrl,
				    unsigned int to_us __unused)
{
	return stm32_reset_assert_clr_offset(rstctrl, 0);
}

static TEE_Result reset_deassert_setr(struct rstctrl *rstctrl __unused,
				      unsigned int to_us __unused)
{
	return TEE_SUCCESS;
}

static struct rstctrl_ops stm32_rstctrl_setr_without_assert_ops = {
	.assert_level = reset_assert_setr,
	.deassert_level = reset_deassert_setr,
};

static struct rstctrl_ops *stm32_reset_mp25_find_ops(unsigned int id)
{
	switch (id) {
	case SYS_R:
	case C1_R:
	case C1P1POR_R:
	case C1P1_R:
	case C2_R:
		return &stm32_rstctrl_setr_without_assert_ops;
	default:
		return &stm32_rstctrl_ops;
	}
}

const struct stm32_reset_data stm32mp25_reset = {
	.reset_get_ops = stm32_reset_mp25_find_ops
};

static const struct dt_device_match stm32_rstctrl_match_table[] = {
	{ .compatible = "st,stm32mp25-rcc", .compat_data = &stm32mp25_reset },
	{ }
};

DEFINE_DT_DRIVER(stm32_rstctrl_dt_driver) = {
	.name = "stm32_rstctrl",
	.type = DT_DRIVER_RSTCTRL,
	.match_table = stm32_rstctrl_match_table,
	.probe = stm32_rstctrl_provider_probe,
};

