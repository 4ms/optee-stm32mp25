// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020-2022, STMicroelectronics
 */
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/counter.h>
#include <drivers/stm32_lptimer.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <tee_api_types.h>
#include <trace.h>
#include <util.h>

/* LPTIM offset register */
#define _LPTIM_ISR		U(0x000)
#define _LPTIM_ICR		U(0x004)
#define _LPTIM_IER		U(0x008)
#define _LPTIM_CFGR		U(0x00C)
#define _LPTIM_CR		U(0x010)
#define _LPTIM_CMP		U(0x014)
#define _LPTIM_ARR		U(0x018)
#define _LPTIM_CNT		U(0x01C)
#define _LPTIM_CFGR2		U(0x024)
#define _LPTIM_HWCFGR		U(0x3F0)
#define _LPTIM_VERR		U(0x3F4)

/* LPTIM_IXX register fields */
#define _LPTIM_IXX_CMPM		BIT(0)
#define _LPTIM_IXX_ARRM		BIT(1)
#define _LPTIM_IXX_EXTTRIG	BIT(2)
#define _LPTIM_IXX_CMPOK	BIT(3)
#define _LPTIM_IXX_ARROK	BIT(4)
#define _LPTIM_IXX_UP		BIT(5)
#define _LPTIM_IXX_DOWN		BIT(6)

/* LPTIM_CFGR register fields */
#define _LPTIM_CFGR_CKSEL		BIT(0)
#define _LPTIM_CFGR_CKPOL_MASK		GENMASK_32(2, 1)
#define _LPTIM_CFGR_CKPOL_SHIFT		1
#define _LPTIM_CFGR_CKFLT_MASK		GENMASK_32(4, 3)
#define _LPTIM_CFGR_CKFLT_SHIFT		3
#define _LPTIM_CFGR_TRGFLT_MASK		GENMASK_32(7, 6)
#define _LPTIM_CFGR_TRGFLT_SHIFT	6
#define _LPTIM_CFGR_PRESC_MASK		GENMASK_32(11, 9)
#define _LPTIM_CFGR_PRESC_SHIFT		9
#define _LPTIM_CFGR_TRIGSEL_MASK	GENMASK_32(15, 13)
#define _LPTIM_CFGR_TRIGSEL_SHIFT	13
#define _LPTIM_CFGR_TRIGEN_MASK		GENMASK_32(18, 17)
#define _LPTIM_CFGR_TRIGEN_SHIFT	17
#define _LPTIM_CFGR_TIMOUT		BIT(19)
#define _LPTIM_CFGR_WAVE		BIT(20)
#define _LPTIM_CFGR_WAVEPOL		BIT(21)
#define _LPTIM_CFGR_PRELOAD		BIT(22)
#define _LPTIM_CFGR_COUNTMODE		BIT(23)
#define _LPTIM_CFGR_ENC			BIT(24)

/* LPTIM_CR register fields */
#define _LPTIM_CR_ENABLE		BIT(0)
#define _LPTIM_CR_SNGSTRT		BIT(1)
#define _LPTIM_CR_CNTSTRT		BIT(2)
#define _LPTIM_CR_COUNTRST		BIT(3)
#define _LPTIM_CR_RSTARE		BIT(4)

/* LPTIM_CMP register fields */
#define _LPTIM_CMP_MASK			GENMASK_32(15, 0)
#define _LPTIM_CMP_SHIFT		0

/* LPTIM_ARR register fields */
#define _LPTIM_ARR_MASK			GENMASK_32(15, 0)
#define _LPTIM_ARR_SHIFT		0

/* LPTIM_CNT register fields */
#define _LPTIM_CNT_MASK			GENMASK_32(15, 0)
#define _LPTIM_CNT_SHIFT		0

/* LPTIM_CFGR2 register fields */
#define _LPTIM_CFGR2_IN1SEL_MASK	GENMASK_32(1, 0)
#define _LPTIM_CFGR2_IN1SEL_SHIFT	0
#define _LPTIM_CFGR2_IN2SEL_MASK	GENMASK_32(5, 4)
#define _LPTIM_CFGR2_IN2SEL_SHIFT	4

/* LPTIM_HWCFGR register fields */
#define _LPTIM_HWCFGR_CFG1_MASK		GENMASK_32(7, 0)
#define _LPTIM_HWCFGR_CFG1_SHIFT	0
#define _LPTIM_HWCFGR_CFG2_MASK		GENMASK_32(15, 8)
#define _LPTIM_HWCFGR_CFG2_SHIFT	8
#define _LPTIM_HWCFGR_CFG3_MASK		GENMASK_32(19, 16)
#define _LPTIM_HWCFGR_CFG3_SHIFT	16
#define _LPTIM_HWCFGR_CFG4_MASK		GENMASK_32(31, 24)
#define _LPTIM_HWCFGR_CFG4_SHIFT	24

/* LPTIM_VERR register fields */
#define _LPTIM_VERR_MINREV_MASK		GENMASK_32(3, 0)
#define _LPTIM_VERR_MINREV_SHIFT	0
#define _LPTIM_VERR_MAJREV_MASK		GENMASK_32(7, 4)
#define _LPTIM_VERR_MAJREV_SHIFT	4

#define _LPTIM_FLD_PREP(field, value) (((uint32_t)(value) << (field ## _SHIFT)) & (field ## _MASK))
#define _LPTIM_FLD_GET(field, value)  (((uint32_t)(value) & (field ## _MASK)) >> (field ## _SHIFT))

/*
 * no common errno between component
 * define lptimer internal errno
 */
#define LPTIM_ERR_NOMEM		12	/* Out of memory */
#define LPTIM_ERR_NODEV		19	/* No such device */
#define LPTIM_ERR_INVAL		22	/* Invalid argument */
#define LPTIM_ERR_NOTSUP	45	/* Operation not supported */

struct lptimer_device {
	const void *fdt;
	int node;
	struct stm32_lptimer_platdata pdata;
	struct lptimer_driver_data *ddata;
	struct counter_device *counter_dev;
	struct itr_handler *itr;
};

static TEE_Result stm32_lpt_counter_set_alarm(struct counter_device *counter)
{
	struct lptimer_device *lpt_dev = counter_priv(counter);
	uintptr_t base = lpt_dev->pdata.base;
	uint32_t cr = 0;

	cr = io_read32(base + _LPTIM_CR);
	/*
	 * LPTIM_CMP & ARR register must only be modified
	 * when the LPTIM is enabled
	 */
	io_setbits32(base + _LPTIM_CR, _LPTIM_CR_ENABLE);
	io_write32(base + _LPTIM_CMP, counter->alarm.ticks);
	io_write32(base + _LPTIM_ARR, counter->alarm.ticks);

	/*
	 * LPTIM_IER register must only be modified
	 * when the LPTIM is disabled
	 */
	io_clrbits32(base + _LPTIM_CR, _LPTIM_CR_ENABLE);
	/* enable, Compare match Interrupt */
	io_setbits32(base + _LPTIM_IER, _LPTIM_IXX_CMPM);

	/* restore cr */
	io_write32(base + _LPTIM_CR, cr);

	counter->alarm.is_enabled = true;

	return TEE_SUCCESS;
}

static TEE_Result stm32_lpt_counter_cancel_alarm(struct counter_device *counter)
{
	struct lptimer_device *lpt_dev = counter_priv(counter);
	uintptr_t base = lpt_dev->pdata.base;
	uint32_t cr = 0;

	cr = io_read32(base + _LPTIM_CR);

	/*
	 * LPTIM_IER register must only be modified
	 * when the LPTIM is disabled
	 */
	io_clrbits32(base + _LPTIM_CR, _LPTIM_CR_ENABLE);
	io_clrbits32(base + _LPTIM_IER, _LPTIM_CR_ENABLE);

	/*
	 * LPTIM_CMP & ARR registers must only be modified
	 * when the LPTIM is enabled
	 */
	io_setbits32(base + _LPTIM_CR, _LPTIM_CR_ENABLE);
	io_write32(base + _LPTIM_CMP, 0);
	io_write32(base + _LPTIM_ARR, 0);

	/* restore cr */
	io_write32(base + _LPTIM_CR, cr);

	counter->alarm.is_enabled = false;

	return TEE_SUCCESS;
}

static int _stm32_lpt_counter_get_value(struct lptimer_device *lpt_dev)
{
	uintptr_t base = lpt_dev->pdata.base;
	uint32_t cnt = 0;
	uint32_t cnt_prev = 0;

	/*
	 * Note: a read access can be considered reliable when the
	 * values of the two consecutive read accesses are equal
	 */
	cnt = io_read32(base + _LPTIM_CNT);
	do {
		cnt_prev = cnt;
		cnt = io_read32(base + _LPTIM_CNT);
	} while (cnt_prev != cnt);

	return cnt;
}

static TEE_Result stm32_lpt_counter_get_value(struct counter_device *counter,
					      uint32_t *ticks)
{
	struct lptimer_device *lpt_dev = counter_priv(counter);

	if (!ticks)
		return TEE_ERROR_BAD_PARAMETERS;

	*ticks = _stm32_lpt_counter_get_value(lpt_dev);
	return TEE_SUCCESS;
}

static TEE_Result stm32_lpt_counter_stop(struct counter_device *counter)
{
	struct lptimer_device *lpt_dev = counter_priv(counter);
	uintptr_t base = lpt_dev->pdata.base;

	io_write32(base + _LPTIM_CR, 0);
	io_write32(base + _LPTIM_CMP, 0);
	io_write32(base + _LPTIM_ARR, 0);

	clk_disable(lpt_dev->pdata.clock);

	return TEE_SUCCESS;
}

static TEE_Result stm32_lpt_counter_start(struct counter_device *counter)
{
	struct lptimer_device *lpt_dev = counter_priv(counter);
	struct stm32_lptimer_platdata *pdata = &lpt_dev->pdata;
	struct lptimer_ext_input_cfg *ext_input = &pdata->ext_input;
	struct lptimer_ext_trigger_cfg *ext_trigger = &pdata->ext_trigger;
	uintptr_t base = pdata->base;
	uint32_t cfgr = 0;
	uint32_t cfgr2 = 0;

	if (ext_input->num) {
		cfgr += _LPTIM_CFGR_COUNTMODE;

		cfgr2 += _LPTIM_FLD_PREP(_LPTIM_CFGR2_IN1SEL,
					 ext_input->mux[0]);
		if (ext_input->num == 2)
			cfgr2 += _LPTIM_FLD_PREP(_LPTIM_CFGR2_IN2SEL,
						 ext_input->mux[1]);
	}

	if (ext_trigger->num) {
		cfgr += _LPTIM_FLD_PREP(_LPTIM_CFGR_TRIGSEL, ext_trigger->mux);
		cfgr += _LPTIM_FLD_PREP(_LPTIM_CFGR_TRIGEN,
					ext_trigger->polarity);
		cfgr |= _LPTIM_CFGR_TIMOUT;
	}

	clk_enable(lpt_dev->pdata.clock);

	/*
	 * LPTIM CFGR2 & IER registers must only be modified
	 * when the LPTIM is disabled
	 */
	io_write32(base + _LPTIM_CR, 0);
	io_write32(base + _LPTIM_CFGR, cfgr);
	io_write32(base + _LPTIM_CFGR2, cfgr2);
	io_write32(base + _LPTIM_CR, _LPTIM_CR_ENABLE);
	/* LPTIM_CR_CNTSTRT can be set only when the LPTIM is enable */
	io_write32(base + _LPTIM_CR, _LPTIM_CR_ENABLE | _LPTIM_CR_CNTSTRT);

	return TEE_SUCCESS;
}

static const struct counter_ops stm32_lpt_counter_ops = {
	.start = stm32_lpt_counter_start,
	.stop = stm32_lpt_counter_stop,
	.get_value = stm32_lpt_counter_get_value,
	.set_alarm = stm32_lpt_counter_set_alarm,
	.cancel_alarm = stm32_lpt_counter_cancel_alarm,
};

static enum itr_return stm32_lptimer_itr(struct itr_handler *h)
{
	struct lptimer_device *lpt_dev = h->data;
	uintptr_t base = lpt_dev->pdata.base;
	uint32_t isr = 0;

	isr = io_read32(base + _LPTIM_ISR);

	if (isr & _LPTIM_IXX_CMPM) {
		uint32_t ticks = _stm32_lpt_counter_get_value(lpt_dev);
		void *priv = lpt_dev->counter_dev->alarm.priv;

		lpt_dev->counter_dev->alarm.callback(ticks, priv);
	}

	io_write32(base + _LPTIM_ICR, isr);

	return ITRR_HANDLED;
}

static void stm32_lptimer_set_driverdata(struct lptimer_device *lpt_dev)
{
	struct lptimer_driver_data *ddata = lpt_dev->ddata;
	uintptr_t base = lpt_dev->pdata.base;
	uint32_t regval = 0;

	clk_enable(lpt_dev->pdata.clock);

	regval = io_read32(base + _LPTIM_HWCFGR);
	ddata->nb_ext_input = _LPTIM_FLD_GET(_LPTIM_HWCFGR_CFG1, regval);
	ddata->nb_ext_trigger = _LPTIM_FLD_GET(_LPTIM_HWCFGR_CFG2, regval);
	ddata->encoder = _LPTIM_FLD_GET(_LPTIM_HWCFGR_CFG3, regval) != 0;

	regval = io_read8(base + _LPTIM_VERR);

	DMSG("LPTIM version %"PRIu32".%"PRIu32,
	     _LPTIM_FLD_GET(_LPTIM_VERR_MAJREV, regval),
	     _LPTIM_FLD_GET(_LPTIM_VERR_MINREV, regval));

	DMSG("HW cap: ext_input:%"PRIu8" ext trigger:%"PRIu8" encoder:%s",
	     ddata->nb_ext_input, ddata->nb_ext_trigger,
	     ddata->encoder ? "true" : "false");

	clk_disable(lpt_dev->pdata.clock);
}

#ifdef CFG_EMBED_DTB
#define LPTIMER_COUNTER_COMPAT	"st,stm32-lptimer-counter"

struct dt_id_attr {
	/* The effective size of the array is meaningless here */
	fdt32_t id_attr[1];
};

/* external-input = < polarity mux1 mux2 > */
static int stm32_lptimer_ext_input_dt(struct lptimer_device *lpt_dev)
{
	struct lptimer_ext_input_cfg *ext_input = &lpt_dev->pdata.ext_input;
	struct lptimer_driver_data *ddata = lpt_dev->ddata;
	const uint32_t *cuint = NULL;
	int len = 0;

	cuint = fdt_getprop(lpt_dev->fdt, lpt_dev->node,
			    "external-input", &len);
	ext_input->num = 0;
	ext_input->mux[0] = 0;
	ext_input->mux[1] = 0;

	if (!cuint)
		return 0;

	len /= sizeof(uint32_t);
	if (len < 2 || len > 3)
		return -LPTIM_ERR_INVAL;

	ext_input->num = len - 1;
	ext_input->polarity = fdt32_to_cpu(*cuint++);
	ext_input->mux[0] = fdt32_to_cpu(*cuint++);

	if (ext_input->num == 2)
		ext_input->mux[1] = fdt32_to_cpu(*cuint);

	if (ext_input->mux[0] >= ddata->nb_ext_input ||
	    ext_input->mux[1] >= ddata->nb_ext_input)
		return -LPTIM_ERR_INVAL;

	DMSG("external input nb:%"PRIu8" pol:%"PRIu8" mux[0]:%"PRIu8" mux[1]:%"PRIu8,
	     ext_input->num, ext_input->polarity,
	     ext_input->mux[0], ext_input->mux[1]);

	return 0;
}

/* external-trigger = < polarity mux > */
static int stm32_lptimer_ext_trigger_dt(struct lptimer_device *lpt_dev)
{
	struct stm32_lptimer_platdata *pdata = &lpt_dev->pdata;
	struct lptimer_driver_data *ddata = lpt_dev->ddata;
	struct lptimer_ext_trigger_cfg *ext_trigger = &pdata->ext_trigger;
	const uint32_t *cuint = NULL;
	int len = 0;

	cuint = fdt_getprop(lpt_dev->fdt, lpt_dev->node,
			    "external-trigger", &len);
	ext_trigger->num = 0;

	if (!cuint)
		return 0;

	len /= sizeof(uint32_t);
	if (len != 2)
		return -LPTIM_ERR_INVAL;

	ext_trigger->polarity = fdt32_to_cpu(*cuint++);
	ext_trigger->mux = fdt32_to_cpu(*cuint);
	ext_trigger->num = 1;

	if (ext_trigger->mux >= ddata->nb_ext_trigger)
		return -LPTIM_ERR_INVAL;

	DMSG("external trigger pol:%"PRId8" mux:%"PRId8,
	     ext_trigger->polarity, ext_trigger->mux);

	return 0;
}

static TEE_Result stm32_lptimer_parse_fdt(struct lptimer_device *lpt_dev)
{
	struct stm32_lptimer_platdata *pdata = &lpt_dev->pdata;
	struct dt_node_info dt_info = { };
	static struct io_pa_va base;
	const void *fdt = lpt_dev->fdt;
	int node = lpt_dev->node;
	TEE_Result res = TEE_ERROR_GENERIC;
	int len = 0;
	int err = 0;

	assert(lpt_dev && lpt_dev->fdt);

	_fdt_fill_device_info(fdt, &dt_info, node);
	if (dt_info.status == DT_STATUS_DISABLED ||
	    dt_info.reg == DT_INFO_INVALID_REG ||
	    dt_info.clock == DT_INFO_INVALID_CLOCK ||
	    dt_info.interrupt == DT_INFO_INVALID_INTERRUPT)
		return -LPTIM_ERR_INVAL;

	pdata->name = fdt_get_name(fdt, node, &len);
	pdata->phandle = fdt_get_phandle(fdt, node);
	base.pa = dt_info.reg;
	pdata->base = io_pa_or_va_secure(&base, 1);
	pdata->irq = dt_info.interrupt;

	res = clk_dt_get_by_index(fdt, node, 0, &pdata->clock);
	if (res)
		return res;

	stm32_lptimer_set_driverdata(lpt_dev);

	err = stm32_lptimer_ext_trigger_dt(lpt_dev);
	if (err)
		return err;

	err = stm32_lptimer_ext_input_dt(lpt_dev);
	if (err)
		return err;

	node = fdt_subnode_offset(fdt, node, "counter");
	if (node >= 0 &&
	    !fdt_node_check_compatible(fdt, node, LPTIMER_COUNTER_COMPAT) &&
	    _fdt_get_status(fdt, node) != DT_STATUS_DISABLED)
		pdata->mode = LPTIMER_MODE_COUNTER;

	return 0;
}

__weak
TEE_Result stm32_lptimer_get_platdata(struct stm32_lptimer_platdata *pdata __unused)
{
	/* In DT config, the platform datas are fill by DT file */
	return TEE_SUCCESS;
}

#else
static TEE_Result stm32_lptimer_parse_fdt(struct lptimer_device *lpt_dev __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * This function could be overridden by platform to define
 * pdata of lptimer driver
 */
__weak TEE_Result stm32_lptimer_get_platdata(struct stm32_lptimer_platdata *pdata __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /*CFG_EMBED_DTB*/

static struct lptimer_device *stm32_lptimer_alloc(void)
{
	struct lptimer_device *lpt_dev = NULL;
	struct lptimer_driver_data *lpt_ddata = NULL;

	lpt_dev = calloc(1, sizeof(*lpt_dev));
	lpt_ddata = calloc(1, sizeof(*lpt_ddata));

	if (lpt_dev && lpt_ddata) {
		lpt_dev->ddata = lpt_ddata;
		return lpt_dev;
	}

	free(lpt_dev);
	free(lpt_ddata);

	return NULL;
}

static void stm32_lptimer_free(struct lptimer_device *lpt_dev)
{
	if (lpt_dev) {
		itr_free(lpt_dev->itr);

		if (lpt_dev->counter_dev)
			counter_dev_free(lpt_dev->counter_dev);

		free(lpt_dev->ddata);
		free(lpt_dev);
	}
}

static TEE_Result probe_lpt_device(struct lptimer_device *lpt_dev)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(lpt_dev);

	res = stm32_lptimer_get_platdata(&lpt_dev->pdata);
	if (res)
		return res;

	res = stm32_lptimer_parse_fdt(lpt_dev);
	if (res)
		return res;

	lpt_dev->itr = itr_alloc_add(lpt_dev->pdata.irq, stm32_lptimer_itr,
				     ITRF_TRIGGER_LEVEL, lpt_dev);
	if (!lpt_dev->itr)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (lpt_dev->pdata.mode & LPTIMER_MODE_COUNTER) {
		lpt_dev->counter_dev = counter_dev_alloc();
		lpt_dev->counter_dev->ops = &stm32_lpt_counter_ops;
		lpt_dev->counter_dev->max_ticks = _LPTIM_CNT_MASK;
		lpt_dev->counter_dev->priv = lpt_dev;
		lpt_dev->counter_dev->name = lpt_dev->pdata.name;
		lpt_dev->counter_dev->phandle = lpt_dev->pdata.phandle;

		res = counter_dev_register(lpt_dev->counter_dev);
	}

	return res;
}

static TEE_Result stm32_lptimer_probe(const void *fdt, int node,
				      const void *compat_data __unused)
{
	struct lptimer_device *lpt_dev = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	lpt_dev = stm32_lptimer_alloc();
	if (!lpt_dev)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (lpt_dev) {
		lpt_dev->fdt = fdt;
		lpt_dev->node = node;
		res = probe_lpt_device(lpt_dev);
	}

	if (res)
		stm32_lptimer_free(lpt_dev);

	return res;
}

static const struct dt_device_match stm32_lptimer_match_table[] = {
	{ .compatible = "st,stm32-lptimer" },
	{ }
};

DEFINE_DT_DRIVER(stm32_lptimer_dt_driver) = {
	.name = "stm32-lptimer",
	.match_table = stm32_lptimer_match_table,
	.probe = stm32_lptimer_probe,
};
