// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022-2023, STMicroelectronics
 */

#include <config.h>
#include <drivers/regulator.h>
#include <drivers/stm32_exti.h>
#include <drivers/stm32_i2c.h>
#include <drivers/stm32mp25_pwr.h>
#include <drivers/stm32mp2_pmic.h>
#include <drivers/stpmic2.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <libfdt.h>
#include <platform_config.h>
#include <stdbool.h>
#include <stm32_util.h>
#include <trace.h>
#include <util.h>

#define PMIC_I2C_TRIALS			U(1)
#define PMIC_I2C_TIMEOUT_BUSY_MS	U(5)

/* Mutex for protecting PMIC accesses */
static struct mutex pmic_mu = MUTEX_INITIALIZER;

/*
 * Low power configurations:
 *
 * STM32_PM_DEFAULT
 *   "default" sub nodes in device-tree
 *   is applied at probe, and re-applied at PM resume.
 *   should support STOP1, LP-STOP1, STOP2, LP-STOP2
 *
 * STM32_PM_LPLV
 *   "lplv" sub nodes in device-tree
 *   should support STOP1, LPLV-STOP1, STOP2, LPLV-STOP2
 *
 * STM32_PM_STANDBY
 *   "standby" sub nodes in device-tree
 *   should support STANDBY1-DDR-SR
 *   is applied in pm suspend call back
 *
 * STM32_PM_OFF
 *   "off" sub nodes in device-tree
 *   should support STANDBY-DDR-OFF mode
 *   and should be applied before shutdown
 *
 */
#define STM32_PM_DEFAULT		0
#define STM32_PM_LPLV			1
#define STM32_PM_STANDBY		2
#define STM32_PM_OFF			3
#define STM32_PM_NB_SOC_MODES		4

static const char *plat_get_lp_mode_name(int mode __unused)
{
	switch (mode) {
	case STM32_PM_DEFAULT:
		return "default";
	case STM32_PM_LPLV:
		return "lplv";
	case STM32_PM_STANDBY:
		return "standby";
	case STM32_PM_OFF:
		return "off";
	default:
		EMSG("Invalid lp mode %d", mode);
		panic();
	}
}

#define STPMIC2_LP_STATE_OFF		BIT(0)
#define STPMIC2_LP_STATE_ON		BIT(1)
#define STPMIC2_LP_STATE_UNMODIFIED	BIT(2)
#define STPMIC2_LP_STATE_SET_VOLT	BIT(3)

struct regu_handle_s {
	struct pmic_handle_s *pmic;
	struct regul_desc desc;
	uint32_t id;
	uint16_t bypass_mv;
	uint8_t lp_state[STM32_PM_NB_SOC_MODES];
	uint16_t lp_mv[STM32_PM_NB_SOC_MODES];
};

static TEE_Result pmic_set_state(const struct regul_desc *desc, bool enable)
{
	struct regu_handle_s *regu = (struct regu_handle_s *)desc->driver_data;
	struct pmic_handle_s *pmic = regu->pmic;
	uint32_t id = regu->id;

	FMSG("%u:%s: set state to %u", id, desc->node_name, enable);

	return stpmic2_regulator_set_state(pmic, id, enable);
}

static TEE_Result pmic_get_state(const struct regul_desc *desc, bool *enabled)
{
	struct regu_handle_s *regu = (struct regu_handle_s *)desc->driver_data;
	struct pmic_handle_s *pmic = regu->pmic;
	uint32_t id = regu->id;

	FMSG("%u:%s: get state\n", id, desc->node_name);

	return stpmic2_regulator_get_state(pmic, id, enabled);
}

static TEE_Result pmic_get_voltage(const struct regul_desc *desc, uint16_t *mv)
{
	struct regu_handle_s *regu = (struct regu_handle_s *)desc->driver_data;
	struct pmic_handle_s *pmic = regu->pmic;
	uint32_t id = regu->id;
	uint16_t val = U(0);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (regu->bypass_mv != U(0)) {
		uint8_t arg = U(0);

		/* If the regul is in bypass mode, return bypass value */
		res = stpmic2_regulator_get_prop(pmic, id, STPMIC2_BYPASS,
						 &arg);
		if (res)
			return res;

		if (arg == PROP_BYPASS_SET) {
			*mv = regu->bypass_mv;
			return TEE_SUCCESS;
		}
	};

	res = stpmic2_regulator_get_voltage(pmic, id, &val);
	if (res)
		return res;

	*mv = val;

	FMSG("%s: get volt %"PRIu16"mV", desc->node_name, *mv);

	return res;
}

static TEE_Result pmic_set_voltage(const struct regul_desc *desc, uint16_t mv)
{
	struct regu_handle_s *regu = (struct regu_handle_s *)desc->driver_data;
	struct pmic_handle_s *pmic = regu->pmic;
	uint32_t id = regu->id;
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("%s: set volt to %"PRIu16"mV", desc->node_name, mv);

	if (mv == regu->bypass_mv) {
		res = stpmic2_regulator_set_prop(pmic, id, STPMIC2_BYPASS,
						 PROP_BYPASS_SET);
		/* do not set voltage in the register */
		return res;
	}

	res = stpmic2_regulator_set_voltage(pmic, id, mv);
	if (res)
		return res;

	/* disable bypass after set voltage ; wait settling time ? */
	if (regu->bypass_mv != U(0) && mv != regu->bypass_mv) {
		res = stpmic2_regulator_set_prop(pmic, id, STPMIC2_BYPASS,
						 PROP_BYPASS_RESET);
	}

	return res;
}

static TEE_Result pmic_list_voltages(const struct regul_desc *desc,
				     uint16_t **levels, size_t *count)
{
	struct regu_handle_s *regu = (struct regu_handle_s *)desc->driver_data;
	struct pmic_handle_s *pmic = regu->pmic;
	uint32_t id = regu->id;

	FMSG("%s: list volt", desc->node_name);

	/*
	 * TODO: add bypass voltage to the end of the list it is greater
	 */

	return stpmic2_regulator_levels_mv(pmic, id,
					   (const uint16_t **)levels, count);
}

/*
 * Set flag from regulator framework.
 * Only handle regultor standard flags
 */
static TEE_Result pmic_set_flag(const struct regul_desc *desc, uint16_t flag)
{
	struct regu_handle_s *regu = (struct regu_handle_s *)desc->driver_data;
	struct pmic_handle_s *pmic = regu->pmic;
	uint32_t id = regu->id;
	TEE_Result res = TEE_SUCCESS;

	FMSG("%s: set_flag %#"PRIx16, desc->node_name, flag);

	switch (flag) {
	case REGUL_PULL_DOWN:
		res = stpmic2_regulator_set_prop(pmic, id,
						 STPMIC2_PULL_DOWN, U(0));
		break;
	case REGUL_OCP:
		res = stpmic2_regulator_set_prop(pmic, id, STPMIC2_OCP, U(0));
		break;
	default:
		DMSG("Invalid flag %#"PRIx16, flag);
		panic();
	}

	return res;
}

static void driver_lock(const struct regul_desc *desc __unused)
{
	if (thread_get_id_may_fail() != THREAD_ID_INVALID)
		mutex_lock(&pmic_mu);
}

static void driver_unlock(const struct regul_desc *desc __unused)
{
	if (thread_get_id_may_fail() != THREAD_ID_INVALID)
		mutex_unlock(&pmic_mu);
}

static TEE_Result __maybe_unused
regu_prepare_suspend(const struct regul_desc *desc, uint8_t mode)
{
	struct regu_handle_s *regu = (struct regu_handle_s *)desc->driver_data;
	struct pmic_handle_s *pmic = regu->pmic;
	uint32_t id = regu->id;
	uint8_t state = regu->lp_state[mode];
	uint16_t mv = regu->lp_mv[mode];
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("%s: suspend state:%#"PRIx8" %"PRIu16"mV", desc->node_name,
	     state, mv);

	if (state & STPMIC2_LP_STATE_UNMODIFIED)
		return TEE_SUCCESS;

	if ((state & STPMIC2_LP_STATE_OFF) != U(0)) {
		res = stpmic2_lp_set_state(pmic, id, false);
		if (res)
			return res;
	}

	if ((state & STPMIC2_LP_STATE_ON) != U(0)) {
		res = stpmic2_lp_set_state(pmic, id, true);
		if (res)
			return res;

		if ((state & STPMIC2_LP_STATE_SET_VOLT) != U(0)) {
			res = stpmic2_lp_set_voltage(pmic, id, mv);
			if (res)
				return res;
		}
	}

	return TEE_SUCCESS;
}

static const struct regul_ops pmic_ops = {
	.set_state = pmic_set_state,
	.get_state = pmic_get_state,
	.set_voltage = pmic_set_voltage,
	.get_voltage = pmic_get_voltage,
	.list_voltages = pmic_list_voltages,
	.set_flag = pmic_set_flag,
	.lock = driver_lock,
	.unlock = driver_unlock,
};

#define DEFINE_REGU(name) { \
	.node_name = name, \
	.driver_data = NULL, \
	.ops = &pmic_ops, \
	.ramp_delay_uv_per_us = U(2200), \
	.enable_ramp_delay_us = U(1000), \
}

static const struct regul_desc pmic_reguls[STPMIC2_NB_REG] = {
	[STPMIC2_BUCK1] = DEFINE_REGU("buck1"),
	[STPMIC2_BUCK2] = DEFINE_REGU("buck2"),
	[STPMIC2_BUCK3] = DEFINE_REGU("buck3"),
	[STPMIC2_BUCK4] = DEFINE_REGU("buck4"),
	[STPMIC2_BUCK5] = DEFINE_REGU("buck5"),
	[STPMIC2_BUCK6] = DEFINE_REGU("buck6"),
	[STPMIC2_BUCK7] = DEFINE_REGU("buck7"),

	[STPMIC2_LDO1] = DEFINE_REGU("ldo1"),
	[STPMIC2_LDO2] = DEFINE_REGU("ldo2"),
	[STPMIC2_LDO3] = DEFINE_REGU("ldo3"),
	[STPMIC2_LDO4] = DEFINE_REGU("ldo4"),
	[STPMIC2_LDO5] = DEFINE_REGU("ldo5"),
	[STPMIC2_LDO6] = DEFINE_REGU("ldo6"),
	[STPMIC2_LDO7] = DEFINE_REGU("ldo7"),
	[STPMIC2_LDO8] = DEFINE_REGU("ldo8"),

	[STPMIC2_REFDDR] = DEFINE_REGU("refddr"),
};
DECLARE_KEEP_PAGER(pmic_reguls);

struct regul_property {
	const char *name;
	uint16_t prop;
};

static const struct regul_property prop_table[] = {
	{
		.name = "st,mask-reset",
		.prop = STPMIC2_MASK_RESET,
	},
	{
		.name = "st,regulator-bypass",
		.prop = STPMIC2_BYPASS,
	},
	{
		.name = "st,pwrctrl_enable",
		.prop = STPMIC2_PWRCTRL_EN,
	},
	{
		.name = "st,pwrctrl_reset",
		.prop = STPMIC2_PWRCTRL_RS,
	},
	{
		.name = "st,pwrctrl_sel",
		.prop = STPMIC2_PWRCTRL_SEL,
	},
	{
		.name = "st,regulator-bypass-microvolt",
		.prop = STPMIC2_BYPASS_UV,
	},
};

TEE_Result stpmic2_set_prop(const struct regul_desc *desc,
			    enum stpmic2_prop_id prop, uint32_t value)
{
	struct regu_handle_s *regu = (struct regu_handle_s *)desc->driver_data;
	struct pmic_handle_s *pmic = regu->pmic;
	uint32_t id = regu->id;

	assert(desc);

	FMSG("%s: set_prop 0x%x val=%u\n", desc->node_name, prop, value);

	if (prop == STPMIC2_BYPASS_UV) {
		regu->bypass_mv = (uint16_t)(value / U(1000));
		return TEE_SUCCESS;
	}

	return stpmic2_regulator_set_prop(pmic, id, prop, value);
}

static TEE_Result parse_properties(const void *fdt,
				   const struct regul_desc *desc, int node)
{
	const fdt32_t *cuint = NULL;
	const struct regul_property *p = NULL;

	for (p = prop_table; p < (prop_table + ARRAY_SIZE(prop_table)); p++) {
		cuint = fdt_getprop(fdt, node, p->name, NULL);
		if (cuint) {
			TEE_Result res = TEE_SUCCESS;

			FMSG("%s: %#"PRIx32, desc->node_name, p->prop);

			res = stpmic2_set_prop(desc, p->prop,
					       fdt32_to_cpu(*cuint));
			if (res)
				return res;
		}
	}

	return TEE_SUCCESS;
}

static void parse_low_power_mode(const void *fdt,
				 const struct regul_desc *desc,
				 int node, int mode)
{
	struct regu_handle_s *regu = (struct regu_handle_s *)desc->driver_data;
	const fdt32_t *cuint = NULL;

	regu->lp_state[mode] = 0;

	if (fdt_getprop(fdt, node, "regulator-off-in-suspend", NULL)) {
		FMSG("%s: mode:%d OFF", desc->node_name, mode);
		regu->lp_state[mode] |= STPMIC2_LP_STATE_OFF;
	} else if (fdt_getprop(fdt, node, "regulator-on-in-suspend", NULL)) {
		FMSG("%s: mode:%d ON", desc->node_name, mode);
		regu->lp_state[mode] |= STPMIC2_LP_STATE_ON;
	} else {
		regu->lp_state[mode] |= STPMIC2_LP_STATE_UNMODIFIED;
	}

	cuint = fdt_getprop(fdt, node, "regulator-suspend-microvolt", NULL);
	if (cuint) {
		uint16_t mv = (uint16_t)(fdt32_to_cpu(*cuint) / 1000U);

		FMSG("%s: mode:%d suspend mv=%"PRIu16, desc->node_name,
		     mode, mv);

		regu->lp_state[mode] |= STPMIC2_LP_STATE_SET_VOLT;
		regu->lp_mv[mode] = mv;
	}
}

static void parse_low_power_modes(const void *fdt,
				  const struct regul_desc *desc, int node)
{
	int mode = 0;

	for (mode = 0; mode < STM32_PM_NB_SOC_MODES; mode++) {
		const char *lp_mode_name = plat_get_lp_mode_name(mode);

		if (lp_mode_name) {
			int n = 0;

			/* Get the configs from regulator_state_node subnode */
			n = fdt_subnode_offset(fdt, node, lp_mode_name);
			if (n >= 0)
				parse_low_power_mode(fdt, desc, n, mode);
		}
	}
}

#ifdef CFG_PM
static TEE_Result stpmic2_regu_pm(enum pm_op op, uint32_t pm_hint __unused,
				  const struct pm_callback_handle *pm_handle)
{
	struct regul_desc *desc = (struct regul_desc *)pm_handle->handle;
	TEE_Result res = TEE_SUCCESS;

	if (op == PM_OP_SUSPEND)
		res = regu_prepare_suspend(desc, STM32_PM_STANDBY);

	else if (op == PM_OP_RESUME)
		res = regu_prepare_suspend(desc, STM32_PM_DEFAULT);

	return res;
}
#endif

static TEE_Result register_pmic_regulator(const void *fdt,
					  struct pmic_handle_s *pmic,
					  const char *regu_name, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct regu_handle_s *regu = NULL;
	struct regul_desc *desc = NULL;
	size_t id = U(0);

	FMSG("Stpmic2 register %s", regu_name);

	for (id = U(0); id < STPMIC2_NB_REG; id++)
		if (!strcmp(pmic_reguls[id].node_name, regu_name))
			break;

	assert(id < ARRAY_SIZE(pmic_reguls));

	regu = calloc(1, sizeof(*regu));
	if (!regu)
		panic();

	regu->pmic = pmic;
	regu->id = id;
	desc = &regu->desc;

	memcpy(desc, pmic_reguls + id, sizeof(*desc));
	desc->driver_data = regu;

	res = regulator_register(desc, node);
	if (res) {
		EMSG("Failed to register %s", regu_name);
		free(regu);
		return res;
	}

	res = parse_properties(fdt, desc, node);
	if (res) {
		EMSG("Failed to parse properties for %s", regu_name);
		free(regu);
	}

	parse_low_power_modes(fdt, desc, node);

	res = regu_prepare_suspend(desc, STM32_PM_DEFAULT);
	if (res) {
		EMSG("Failed to prepare regu suspend %s", regu_name);
		free(regu);
	}

#ifdef CFG_PM
	register_pm_core_service_cb(stpmic2_regu_pm, desc, desc->node_name);
#endif

	return res;
}

static TEE_Result parse_regulator_fdt_nodes(const void *fdt, int node,
					    struct pmic_handle_s *pmic)
{
	int regulators_node = 0;
	int regu_node = 0;

	regulators_node = fdt_subnode_offset(fdt, node, "regulators");
	if (regulators_node < 0)
		panic();

	fdt_for_each_subnode(regu_node, fdt, regulators_node) {
		TEE_Result res = TEE_ERROR_GENERIC;
		int status = _fdt_get_status(fdt, regu_node);
		const char *regu_name = NULL;

		assert(status >= 0);
		if (status == DT_STATUS_DISABLED)
			continue;

		regu_name = fdt_get_name(fdt, regu_node, NULL);
		assert(regu_name);

		res = register_pmic_regulator(fdt, pmic, regu_name, regu_node);
		if (res) {
			EMSG("Failed to register %s", regu_name);
			return res;
		}
	}

	return TEE_SUCCESS;
}

#ifdef CFG_STM32_PWR_IRQ
static enum itr_return stpmic2_irq_handler(struct itr_handler *handler)
{
	struct pmic_handle_s *pmic = handler->data;

	FMSG("Stpmic2 irq");

	stpmic2_handle_irq(pmic);

	return ITRR_HANDLED;
}

static TEE_Result initialize_pmic2_irq(const void *fdt, int node,
				       struct pmic_handle_s *pmic)
{
	struct itr_handler *hdl = NULL;
	const fdt32_t *cuint = NULL;

	FMSG("Init stpmic2 irq");

	cuint = fdt_getprop(fdt, node, "st,wakeup-pin-number", NULL);
	if (cuint) {
		TEE_Result res = TEE_ERROR_GENERIC;
		size_t it = U(0);

		it = fdt32_to_cpu(*cuint) - U(1);

		res = stm32mp25_pwr_itr_alloc_add(it, stpmic2_irq_handler,
						  PWR_WKUP_FLAG_FALLING |
						  PWR_WKUP_FLAG_THREADED,
						  pmic, &hdl);
		if (res)
			return res;

		stm32mp25_pwr_itr_enable(hdl->it);
	}

	/* Enable ponkey irq */
	if (stpmic2_set_irq_mask(pmic, IT_PONKEY_F, false))
		return TEE_ERROR_GENERIC;

	if (stpmic2_set_irq_mask(pmic, IT_PONKEY_R, false))
		return TEE_ERROR_GENERIC;

	/* Unmask all over-current interrupts */
	if (stpmic2_register_write(pmic, INT_MASK_R3, 0x00))
		return TEE_ERROR_GENERIC;

	if (stpmic2_register_write(pmic, INT_MASK_R4, 0x00))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
#endif

static void initialize_pmic2_i2c(const void *fdt, int node,
				 struct pmic_handle_s *pmic,
				 struct i2c_handle_s *i2c)
{
	const fdt32_t *cuint = NULL;
	uint32_t pmic_i2c_addr = U(0);

	cuint = fdt_getprop(fdt, node, "reg", NULL);
	if (!cuint)
		panic("PMIC configuration failed on reg property");

	pmic_i2c_addr = fdt32_to_cpu(*cuint) << 1;
	if (pmic_i2c_addr > UINT16_MAX)
		panic("PMIC configuration failed on i2c address translation");

	if (!stm32_i2c_is_device_ready(i2c, pmic_i2c_addr,
				       PMIC_I2C_TRIALS,
				       PMIC_I2C_TIMEOUT_BUSY_MS)) {
		panic("PMIC2 I2C init failed");
	}

	pmic->pmic_i2c_handle = i2c;
	pmic->pmic_i2c_addr = pmic_i2c_addr;
}

/*
 * PMIC and resource initialization
 */
static void initialize_pmic2(const void *fdt, int node,
			     struct pmic_handle_s *pmic,
			     struct i2c_handle_s *i2c)
{
	uint8_t ver = U(0);
	uint8_t pid = U(0);

	FMSG("Initialize stpmic2");

	initialize_pmic2_i2c(fdt, node, pmic, i2c);

	if (stpmic2_get_product_id(pmic, &pid) ||
	    stpmic2_get_version(pmic, &ver))
		panic("Failed to access PMIC");

	IMSG("PMIC pid=%#"PRIx8" version=%#"PRIx8, pid, ver);
	stpmic2_dump_regulators(pmic);
}

static TEE_Result stm32_pmic2_probe(const void *fdt, int node,
				    const void *compat_data __unused)
{
	struct i2c_handle_s *i2c = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct pmic_handle_s *pmic = NULL;

	FMSG("Probe stpmic2");

	res = i2c_dt_get_by_subnode(fdt, node, &i2c);
	if (res)
		return res;

	pmic = calloc(1, sizeof(*pmic));
	if (!pmic)
		panic();

	initialize_pmic2(fdt, node, pmic, i2c);

#ifdef CFG_STM32_PWR_IRQ
	res = initialize_pmic2_irq(fdt, node, pmic);
	if (res) {
		free(pmic);
		return res;
	}
#endif

	res = parse_regulator_fdt_nodes(fdt, node, pmic);
	if (res)
		panic();

	return TEE_SUCCESS;
}

static const struct dt_device_match stm32_pmic2_match_table[] = {
	{ .compatible = "st,stpmic2" },
	{ }
};

DEFINE_DT_DRIVER(stm32_pmic2_dt_driver) = {
	.name = "stm32_pmic2",
	.match_table = stm32_pmic2_match_table,
	.probe = stm32_pmic2_probe,
};

