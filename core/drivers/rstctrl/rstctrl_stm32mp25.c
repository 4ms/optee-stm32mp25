// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2022, STMicroelectronics
 */

#include <drivers/rstctrl.h>
#include <drivers/stm32_risaf.h>
#include <drivers/stm32_rstctrl.h>
#include <dt-bindings/reset/stm32mp25-resets.h>
#include <kernel/dt.h>
#include <platform_config.h>

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

static TEE_Result reset_assert_do_nothing(struct rstctrl *rstctrl __unused,
					  unsigned int to_us __unused)
{
	return TEE_SUCCESS;
}

static TEE_Result reset_deassert_do_nothing(struct rstctrl *rstctrl __unused,
					    unsigned int to_us __unused)
{
	return TEE_SUCCESS;
}

static struct rstctrl_ops stm32_rstctrl_do_nothing_ops = {
	.assert_level = reset_assert_do_nothing,
	.deassert_level = reset_deassert_do_nothing,
};

#ifdef CFG_STM32MP25x_REVA
static TEE_Result stm32_reset_deassert_pcie_workaround(struct rstctrl *rstctrl,
						       unsigned int to_us)
{
	TEE_Result res = TEE_SUCCESS;

	res = stm32_reset_deassert(rstctrl, to_us);
	if (res)
		return res;

	return stm32_risaf_reconfigure(RISAF5_BASE);
}

static struct rstctrl_ops stm32_rstctrl_pcie_workaround_ops = {
	.assert_level = stm32_reset_assert,
	.deassert_level = stm32_reset_deassert_pcie_workaround,
};
#endif /* CFG_STM32MP25x_REVA */

static unsigned int rif_aware_reset[] = {
	DDRCP_R, DDRCAPB_R, DDRPHYCAPB_R, DDRCFG_R, DDR_R,
	IPCC1_R, IPCC2_R,
	HPDMA1_R, HPDMA2_R, HPDMA2_R, LPDMA_R,
	GPIOA_R, GPIOB_R, GPIOC_R, GPIOD_R,
	GPIOE_R, GPIOF_R, GPIOG_R, GPIOH_R,
	GPIOI_R, GPIOJ_R, GPIOK_R, GPIOZ_R,
	HSEM_R,
	FMC_R,
};

static bool stm32_rstctrl_is_rif_aware_ip(unsigned int id)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(rif_aware_reset); i++) {
		if (id == rif_aware_reset[i])
			return true;
	}

	return false;
}

static struct rstctrl_ops *stm32_reset_mp25_find_ops(unsigned int id)
{
	if (stm32_rstctrl_is_rif_aware_ip(id))
		return &stm32_rstctrl_do_nothing_ops;

	switch (id) {
	case SYS_R:
	case C1_R:
	case C1P1POR_R:
	case C1P1_R:
	case C2_R:
		return &stm32_rstctrl_setr_without_assert_ops;
	case HOLD_BOOT_C1_R:
	case HOLD_BOOT_C2_R:
		return &stm32_rstctrl_inverted_ops;
#ifdef CFG_STM32MP25x_REVA
	case PCIE_R:
		return &stm32_rstctrl_pcie_workaround_ops;
#endif /* CFG_STM32MP25x_REVA */
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

