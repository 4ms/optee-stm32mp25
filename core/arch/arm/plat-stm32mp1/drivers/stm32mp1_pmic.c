// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2017-2021, STMicroelectronics
 */

#include <config.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/regulator.h>
#include <drivers/stm32_i2c.h>
#include <drivers/stm32mp1_pmic.h>
#include <drivers/stpmic1.h>
#include <drivers/stpmic1_regulator.h>
#include <io.h>
#include <keep.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <kernel/thread.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdbool.h>
#include <stm32_util.h>
#include <trace.h>
#include <util.h>

#define MODE_STANDBY                    8

#define PMIC_I2C_TRIALS			1
#define PMIC_I2C_TIMEOUT_BUSY_MS	5

#define PMIC_REGU_SUPPLY_NAME_LEN	12

#define PMIC_REGU_COUNT			14

/* Expect a single PMIC instance */
static struct i2c_handle_s i2c_handle;
static uint32_t pmic_i2c_addr;

/* CPU voltage supplier if found */
static char cpu_supply_name[PMIC_REGU_SUPPLY_NAME_LEN];

/* Mutex for protecting PMIC accesses */
static struct mutex pmic_mu = MUTEX_INITIALIZER;

static TEE_Result register_pmic_regulator(const char *regu_name, int node);

static int dt_get_pmic_node(void *fdt)
{
	static int node = -FDT_ERR_BADOFFSET;

	if (node == -FDT_ERR_BADOFFSET)
		node = fdt_node_offset_by_compatible(fdt, -1, "st,stpmic1");

	return node;
}

static int pmic_status = -1;

static unsigned int pmic_dt_status(void)
{
	unsigned int __maybe_unused mask = DT_STATUS_OK_NSEC | DT_STATUS_OK_SEC;

	if (pmic_status < 0) {
		int status = DT_STATUS_DISABLED;
		void *fdt = get_embedded_dt();
		int node = dt_get_pmic_node(fdt);

		if (node >= 0)
			status = _fdt_get_status(fdt, node);

		assert(status >= 0 && !((unsigned int)status & !mask));
		pmic_status = status;
	}

	return (unsigned int)pmic_status;
}

static bool pmic_is_secure(void)
{
	assert(pmic_status != -1);

	if (IS_ENABLED(CFG_STM32MP13))
		return pmic_status & DT_STATUS_OK_SEC;
	else
		return pmic_status == DT_STATUS_OK_SEC;
}

bool stm32mp_with_pmic(void)
{
	assert(pmic_status != -1);

	return pmic_status & DT_STATUS_OK_SEC;
}

/* Return a libfdt compliant status value */
static int save_cpu_supply_name(void)
{
	void *fdt = NULL;
	int node = 0;
	const fdt32_t *cuint = NULL;
	const char *name = NULL;

	fdt = get_embedded_dt();
	if (!fdt)
		panic();

	node = fdt_path_offset(fdt, "/cpus/cpu@0");
	if (node < 0)
		return -FDT_ERR_NOTFOUND;

	cuint = fdt_getprop(fdt, node, "cpu-supply", NULL);
	if (!cuint)
		return -FDT_ERR_NOTFOUND;

	node = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(*cuint));
	if (node < 0)
		return -FDT_ERR_NOTFOUND;

	name = fdt_get_name(fdt, node, NULL);
	assert(strnlen(name, sizeof(cpu_supply_name)) <
	       sizeof(cpu_supply_name));

	strncpy(cpu_supply_name, name, sizeof(cpu_supply_name));

	return 0;
}

const char *stm32mp_pmic_get_cpu_supply_name(void)
{
	return cpu_supply_name;
}

/* Preallocate not that much regu references */
static char *nsec_access_regu_name[PMIC_REGU_COUNT];

bool stm32mp_nsec_can_access_pmic_regu(const char *name)
{
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(nsec_access_regu_name); n++)
		if (nsec_access_regu_name[n] &&
		    !strcmp(nsec_access_regu_name[n], name))
			return true;

	return false;
}

static void register_nsec_regu(const char *name_ref)
{
	size_t n = 0;

	assert(!stm32mp_nsec_can_access_pmic_regu(name_ref));

	for (n = 0; n < ARRAY_SIZE(nsec_access_regu_name); n++) {
		if (!nsec_access_regu_name[n]) {
			nsec_access_regu_name[n] = strdup(name_ref);

			if (!nsec_access_regu_name[n])
				panic();
			break;
		}
	}

	assert(stm32mp_nsec_can_access_pmic_regu(name_ref));
}

static void parse_regulator_fdt_nodes(void)
{
	int pmic_node = 0;
	int regulators_node = 0;
	int regu_node = 0;
	void *fdt = NULL;

	fdt = get_embedded_dt();
	if (!fdt)
		panic();

	pmic_node = dt_get_pmic_node(fdt);
	if (pmic_node < 0)
		panic();

	regulators_node = fdt_subnode_offset(fdt, pmic_node, "regulators");
	if (regulators_node < 0)
		panic();

	fdt_for_each_subnode(regu_node, fdt, regulators_node) {
		int status = _fdt_get_status(fdt, regu_node);
		const char *regu_name = NULL;
		size_t __maybe_unused n = 0;

		assert(status >= 0);
		if (status == DT_STATUS_DISABLED)
			continue;

		regu_name = fdt_get_name(fdt, regu_node, NULL);

		assert(stpmic1_regulator_is_valid(regu_name));

		if (status & DT_STATUS_OK_NSEC)
			register_nsec_regu(regu_name);

		if (register_pmic_regulator(regu_name, regu_node))
			panic();
	}

	if (save_cpu_supply_name())
		DMSG("No CPU supply provided");
}

/*
 * Get PMIC and its I2C bus configuration from the device tree.
 * Return 0 on success, 1 if no PMIC node found and a negative value otherwise
 */
static int dt_pmic_i2c_config(struct dt_node_info *i2c_info,
			      struct stm32_pinctrl_list **pinctrl,
			      struct stm32_i2c_init_s *init)
{
	int pmic_node = 0;
	int i2c_node = 0;
	void *fdt = NULL;
	const fdt32_t *cuint = NULL;

	fdt = get_embedded_dt();
	if (!fdt)
		return -FDT_ERR_NOTFOUND;

	pmic_node = dt_get_pmic_node(fdt);
	if (pmic_node < 0)
		return 1;

	cuint = fdt_getprop(fdt, pmic_node, "reg", NULL);
	if (!cuint)
		return -FDT_ERR_NOTFOUND;

	pmic_i2c_addr = fdt32_to_cpu(*cuint) << 1;
	if (pmic_i2c_addr > UINT16_MAX)
		return -FDT_ERR_BADVALUE;

	i2c_node = fdt_parent_offset(fdt, pmic_node);
	if (i2c_node < 0)
		return -FDT_ERR_NOTFOUND;

	_fdt_fill_device_info(fdt, i2c_info, i2c_node);
	if (!i2c_info->reg)
		return -FDT_ERR_NOTFOUND;

	if (stm32_i2c_get_setup_from_fdt(fdt, i2c_node, init, pinctrl))
		panic();

	return 0;
}

/*
 * PMIC and resource initialization
 */

/* Return true if PMIC is available, false if not found, panics on errors */
static bool initialize_pmic_i2c(void)
{
	int ret = 0;
	struct dt_node_info i2c_info = { };
	struct i2c_handle_s *i2c = &i2c_handle;
	struct stm32_pinctrl_list *pinctrl = NULL;
	struct stm32_i2c_init_s i2c_init = { };

	ret = dt_pmic_i2c_config(&i2c_info, &pinctrl, &i2c_init);
	if (ret < 0) {
		EMSG("I2C configuration failed %d", ret);
		panic();
	}
	if (ret)
		return false;

	/* Initialize PMIC I2C */
	i2c->base.pa = i2c_info.reg;
	i2c->base.va = (vaddr_t)phys_to_virt(i2c->base.pa, MEM_AREA_IO_SEC, 1);
	assert(i2c->base.va);
	i2c->dt_status = i2c_info.status;
	i2c->clock = i2c_init.clock;
	i2c->i2c_state = I2C_STATE_RESET;
	i2c_init.own_address1 = pmic_i2c_addr;
	i2c_init.analog_filter = true;
	i2c_init.digital_filter_coef = 0;

	i2c->pinctrl = pinctrl;

	if (i2c_handle.dt_status != pmic_dt_status())
		panic("PMIC and its I2C bus must have the same enable state");

	if (!i2c->clock)
		panic();

	/* 1st access to PMIC */
	stm32mp_pm_get_pmic();

	ret = stm32_i2c_init(i2c, &i2c_init);
	if (ret) {
		EMSG("I2C init 0x%" PRIxPA ": %d", i2c_info.reg, ret);
		panic();
	}

	if (!stm32_i2c_is_device_ready(i2c, pmic_i2c_addr,
				       PMIC_I2C_TRIALS,
				       PMIC_I2C_TIMEOUT_BUSY_MS))
		panic();

	stpmic1_bind_i2c(i2c, pmic_i2c_addr);

	stm32mp_pm_put_pmic();

	return true;
}

#ifdef CFG_REGULATOR_DRIVERS
static TEE_Result pmic_set_state(const struct regul_desc *desc, bool enable)
{
	int ret = 0;

	FMSG("%s: set state to %u", desc->node_name, enable);

	if (enable)
		ret = stpmic1_regulator_enable(desc->node_name);
	else
		ret = stpmic1_regulator_disable(desc->node_name);

	if (ret)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result pmic_get_state(const struct regul_desc *desc, bool *enabled)
{
	FMSG("%s: get state", desc->node_name);

	*enabled = stpmic1_is_regulator_enabled(desc->node_name);

	return TEE_SUCCESS;
}

static TEE_Result pmic_get_voltage(const struct regul_desc *desc, uint16_t *mv)
{
	int ret = 0;

	FMSG("%s: get volt", desc->node_name);

	ret = stpmic1_regulator_voltage_get(desc->node_name);
	if (ret < 0)
		return TEE_ERROR_GENERIC;

	*mv = ret;

	return TEE_SUCCESS;
}

static TEE_Result pmic_set_voltage(const struct regul_desc *desc, uint16_t mv)
{
	FMSG("%s: set volt", desc->node_name);

	if (stpmic1_regulator_voltage_set(desc->node_name, mv))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result pmic_list_voltages(const struct regul_desc *desc,
				     uint16_t **levels, size_t *count)
{
	FMSG("%s: list volt", desc->node_name);

	if (stpmic1_regulator_levels_mv(desc->node_name,
					(const uint16_t **)levels, count))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result pmic_set_flag(const struct regul_desc *desc, uint16_t flag)
{
	int ret = 0;

	FMSG("%s: set_flag %#"PRIx16, desc->node_name, flag);

	switch (flag) {
	case REGUL_OCP:
		ret = stpmic1_regulator_icc_set(desc->node_name);
		break;
	case REGUL_ACTIVE_DISCHARGE:
		ret = stpmic1_active_discharge_mode_set(desc->node_name);
		break;
	case REGUL_PULL_DOWN:
		ret = stpmic1_regulator_pull_down_set(desc->node_name);
		break;
	case REGUL_MASK_RESET:
		ret = stpmic1_regulator_mask_reset_set(desc->node_name);
		break;
	case REGUL_SINK_SOURCE:
		ret = stpmic1_regulator_sink_mode_set(desc->node_name);
		break;
	case REGUL_ENABLE_BYPASS:
		ret = stpmic1_regulator_bypass_mode_set(desc->node_name);
		break;
	default:
		DMSG("Invalid flag %#"PRIx16, flag);
		panic();
	}

	if (ret)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static void driver_lock(const struct regul_desc *desc __unused)
{
	if (thread_get_id_may_fail() != THREAD_ID_INVALID)
		mutex_lock(&pmic_mu);

	stm32mp_get_pmic();
}

static void driver_unlock(const struct regul_desc *desc __unused)
{
	if (thread_get_id_may_fail() != THREAD_ID_INVALID)
		mutex_unlock(&pmic_mu);

	stm32mp_put_pmic();
}

static TEE_Result driver_suspend(const struct regul_desc *desc, uint8_t state,
				 uint16_t mv)
{
	int ret = 0;

	FMSG("%s: suspend state:%"PRIu8", %"PRIu16" mV", desc->node_name,
	     state, mv);

	if (!stpmic1_regu_has_lp_cfg(desc->node_name))
		return TEE_SUCCESS;

	ret = stpmic1_lp_copy_reg(desc->node_name);
	if (ret)
		return TEE_ERROR_GENERIC;

	if ((state & LP_STATE_OFF) != 0U) {
		ret = stpmic1_lp_reg_on_off(desc->node_name, 0);
		if (ret)
			return TEE_ERROR_GENERIC;
	}

	if ((state & LP_STATE_ON) != 0U) {
		ret = stpmic1_lp_reg_on_off(desc->node_name, 1);
		if (ret)
			return TEE_ERROR_GENERIC;
	}

	if ((state & LP_STATE_SET_VOLT) != 0U) {
		ret = stpmic1_lp_set_voltage(desc->node_name, mv);
		if (ret)
			return TEE_ERROR_GENERIC;
	}

	return 0;
}

const struct regul_ops pmic_ops = {
	.set_state = pmic_set_state,
	.get_state = pmic_get_state,
	.set_voltage = pmic_set_voltage,
	.get_voltage = pmic_get_voltage,
	.list_voltages = pmic_list_voltages,
	.set_flag = pmic_set_flag,
	.lock = driver_lock,
	.unlock = driver_unlock,
	.suspend = driver_suspend,
};

#define DEFINE_REGU(name) { \
	.node_name = name, \
	.ops = &pmic_ops, \
	.ramp_delay_uv_per_us = 2200, \
	.enable_ramp_delay_us = 1000, \
}

static const struct regul_desc pmic_reguls[] = {
	DEFINE_REGU("buck1"),
	DEFINE_REGU("buck2"),
	DEFINE_REGU("buck3"),
	DEFINE_REGU("buck4"),
	DEFINE_REGU("ldo1"),
	DEFINE_REGU("ldo2"),
	DEFINE_REGU("ldo3"),
	DEFINE_REGU("ldo4"),
	DEFINE_REGU("ldo5"),
	DEFINE_REGU("ldo6"),
	DEFINE_REGU("vref_ddr"),
	DEFINE_REGU("boost"),
	DEFINE_REGU("pwr_sw1"),
	DEFINE_REGU("pwr_sw2"),
};
DECLARE_KEEP_PAGER(pmic_reguls);

static TEE_Result register_pmic_regulator(const char *regu_name, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(pmic_reguls); i++)
		if (!strcmp(pmic_reguls[i].node_name, regu_name))
			break;

	assert(i < ARRAY_SIZE(pmic_reguls));

	res = regulator_register(pmic_reguls + i, node);
	if (res)
		EMSG("Failed to register %s, error: %#"PRIx32, regu_name, res);

	return res;
}
#endif /* CFG_REGULATOR_DRIVERS */

/*
 * Automated suspend/resume at system suspend/resume is expected
 * only when the PMIC is secure. If it is non secure, only atomic
 * execution context can get/put the PMIC resources.
 */
static TEE_Result pmic_pm(enum pm_op op, uint32_t pm_hint __unused,
			  const struct pm_callback_handle *pm_handle __unused)
{
	if (op == PM_OP_SUSPEND)
		stm32_i2c_suspend(&i2c_handle);
	else
		stm32_i2c_resume(&i2c_handle);

	return TEE_SUCCESS;
}
DECLARE_KEEP_PAGER(pmic_pm);

/* stm32mp_get/put_pmic allows secure atomic sequences to use non secure PMIC */
void stm32mp_get_pmic(void)
{
	if (!pmic_is_secure()) {
		stm32_i2c_resume(&i2c_handle);
		stm32_pinctrl_load_config(i2c_handle.pinctrl);
	}
}

void stm32mp_put_pmic(void)
{
	if (!pmic_is_secure())
		stm32_i2c_suspend(&i2c_handle);
}

/* stm32mp_pm_get/put_pmic enforces get/put PMIC accesses */
void stm32mp_pm_get_pmic(void)
{
	stm32_i2c_resume(&i2c_handle);
}

void stm32mp_pm_put_pmic(void)
{
	stm32_i2c_suspend(&i2c_handle);
}

static void register_non_secure_pmic(void)
{
	unsigned int __maybe_unused clock_id = 0;

	/* Allow this function to be called when STPMIC1 not used */
	if (!i2c_handle.base.pa)
		return;

	if (stm32_pinctrl_set_secure_cfg(i2c_handle.pinctrl, false))
		panic();

#ifdef CFG_STM32MP1_SHARED_RESOURCES
	stm32mp_register_non_secure_periph_iomem(i2c_handle.base.pa);
	/*
	 * Non secure PMIC can be used by secure world during power state
	 * transition when non-secure world is suspended. Therefore secure
	 * the I2C clock parents, if not specifically the I2C clock itself.
	 */
	clock_id = stm32mp_rcc_clk_to_clock_id(i2c_handle.clock);
	stm32mp_register_clock_parents_secure(clock_id);
#endif /* CFG_STM32MP1_SHARED_RESOURCES */
}

static TEE_Result initialize_pmic(void)
{
	unsigned long pmic_version = 0;

	if (pmic_dt_status() == DT_STATUS_DISABLED ||
	    !initialize_pmic_i2c()) {
		DMSG("No PMIC");
		register_non_secure_pmic();
		return TEE_SUCCESS;
	}

	stm32mp_get_pmic();

	if (stpmic1_get_version(&pmic_version))
		panic("Failed to access PMIC");

	DMSG("PMIC version = 0x%02lx", pmic_version);
	stpmic1_dump_regulators();

	if (stpmic1_powerctrl_on())
		panic("Failed to enable pmic pwr control");

	if (!pmic_is_secure())
		register_non_secure_pmic();

	register_pm_core_service_cb(pmic_pm, NULL, "stm32mp1-pmic");

	parse_regulator_fdt_nodes();

	stm32mp_put_pmic();

	return TEE_SUCCESS;
}
service_init(initialize_pmic);
