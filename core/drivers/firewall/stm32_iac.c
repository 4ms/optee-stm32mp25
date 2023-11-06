// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, STMicroelectronics
 */
#include <drivers/stm32_iac.h>
#include <dt-bindings/soc/stm32mp25-rifsc.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <util.h>

/* IAC offset register */
#define _IAC_IER0		U(0x000)
#define _IAC_ISR0		U(0x080)
#define _IAC_ICR0		U(0x100)
#define _IAC_IISR0		U(0x36C)

#define _IAC_HWCFGR2		U(0x3EC)
#define _IAC_HWCFGR1		U(0x3F0)
#define _IAC_VERR		U(0x3F4)

/* IAC_HWCFGR2 register fields */
#define _IAC_HWCFGR2_CFG1_MASK	GENMASK_32(3, 0)
#define _IAC_HWCFGR2_CFG1_SHIFT	0
#define _IAC_HWCFGR2_CFG2_MASK	GENMASK_32(7, 4)
#define _IAC_HWCFGR2_CFG2_SHIFT	4

/* IAC_HWCFGR1 register fields */
#define _IAC_HWCFGR1_CFG1_MASK	GENMASK_32(3, 0)
#define _IAC_HWCFGR1_CFG1_SHIFT	0
#define _IAC_HWCFGR1_CFG2_MASK	GENMASK_32(7, 4)
#define _IAC_HWCFGR1_CFG2_SHIFT	4
#define _IAC_HWCFGR1_CFG3_MASK	GENMASK_32(11, 8)
#define _IAC_HWCFGR1_CFG3_SHIFT	8
#define _IAC_HWCFGR1_CFG4_MASK	GENMASK_32(15, 12)
#define _IAC_HWCFGR1_CFG4_SHIFT	12
#define _IAC_HWCFGR1_CFG5_MASK	GENMASK_32(24, 16)
#define _IAC_HWCFGR1_CFG5_SHIFT	16

/* IAC_VERR register fields */
#define _IAC_VERR_MINREV_MASK	GENMASK_32(3, 0)
#define _IAC_VERR_MINREV_SHIFT	0
#define _IAC_VERR_MAJREV_MASK	GENMASK_32(7, 4)
#define _IAC_VERR_MAJREV_SHIFT	4

/* Periph id per register */
#define _PERIPH_IDS_PER_REG	32

#define _IAC_FLD_PREP(field, value)	(((uint32_t)(value) << (field ## _SHIFT)) & (field ## _MASK))
#define _IAC_FLD_GET(field, value)	(((uint32_t)(value) & (field ## _MASK)) >> (field ## _SHIFT))

/*
 * no common errno between component
 * define iac internal errno
 */
#define	IAC_ERR_NOMEM		12	/* Out of memory */
#define IAC_ERR_NODEV		19	/* No such device */
#define IAC_ERR_INVAL		22	/* Invalid argument */
#define IAC_ERR_NOTSUP		45	/* Operation not supported */

struct iac_device {
	const void *fdt;
	int node;
	struct stm32_iac_platdata pdata;
	struct iac_driver_data *ddata;
	struct itr_handler *itr;
};

static void stm32_iac_get_hwdata(struct iac_device *iac_dev)
{
	struct iac_driver_data *ddata = iac_dev->ddata;
	uintptr_t base = iac_dev->pdata.base;
	uint32_t regval = 0;

	regval = io_read32(base + _IAC_HWCFGR1);
	ddata->num_ilac = _IAC_FLD_GET(_IAC_HWCFGR1_CFG5, regval);
	ddata->rif_en = _IAC_FLD_GET(_IAC_HWCFGR1_CFG1, regval) != 0;
	ddata->sec_en = _IAC_FLD_GET(_IAC_HWCFGR1_CFG2, regval) != 0;
	ddata->priv_en = _IAC_FLD_GET(_IAC_HWCFGR1_CFG3, regval) != 0;

	ddata->version = io_read32(base + _IAC_VERR);

	DMSG("IAC version %"PRIu32".%"PRIu32,
	     _IAC_FLD_GET(_IAC_VERR_MAJREV, ddata->version),
	     _IAC_FLD_GET(_IAC_VERR_MINREV, ddata->version));

	DMSG("HW cap: enabled[rif:sec:priv]:[%s:%s:%s] num ilac:[%"PRIu8"]",
	     ddata->rif_en ? "true" : "false",
	     ddata->sec_en ? "true" : "false",
	     ddata->priv_en ? "true" : "false",
	     ddata->num_ilac);
}

#ifdef CFG_EMBED_DTB
struct dt_id_attr {
	/* The effective size of the array is meaningless here */
	fdt32_t id_attr[1];
};

static int stm32_iac_parse_fdt(struct iac_device *iac_dev)
{
	struct stm32_iac_platdata *pdata = &iac_dev->pdata;
	struct dt_node_info dt_info = { };
	static struct io_pa_va base;
	const void *fdt = iac_dev->fdt;
	int node = iac_dev->node;

	assert(iac_dev && iac_dev->fdt);

	_fdt_fill_device_info(fdt, &dt_info, node);
	if (dt_info.status == DT_STATUS_DISABLED ||
	    dt_info.reg == DT_INFO_INVALID_REG ||
	    dt_info.interrupt == DT_INFO_INVALID_INTERRUPT)
		return -IAC_ERR_NODEV;

	base.pa = dt_info.reg;
	pdata->base = io_pa_or_va_secure(&base, 1);
	pdata->irq = dt_info.interrupt;

	return 0;
}

__weak int stm32_iac_get_platdata(struct stm32_iac_platdata *pdata __unused)
{
	/* In DT config, the platform datas are fill by DT file */
	return 0;
}

#else
static int stm32_iac_parse_fdt(struct stm32_iac_platdata *pdata)
{
	return -IAC_ERR_NOTSUP;
}

/*
 * This function could be overridden by platform to define
 * pdata of iac driver
 */
__weak int stm32_iac_get_platdata(struct stm32_iac_platdata *pdata)
{
	return -IAC_ERR_NODEV;
}
#endif /*CFG_EMBED_DTB*/

#define IAC_EXCEPT_MSB_BIT(x)		((x) * _PERIPH_IDS_PER_REG + \
					 _PERIPH_IDS_PER_REG - 1)
#define IAC_EXCEPT_LSB_BIT(x)		((x) * _PERIPH_IDS_PER_REG)
#define IAC_FIRST_ILAC_IN_REG(x)	(__builtin_ffs((x)) - 1)
#define IAC_ILAC_ID(reg_val, offset)	(IAC_FIRST_ILAC_IN_REG(reg_val) + \
					 IAC_EXCEPT_LSB_BIT(offset))

__weak __noreturn void access_violation_action(void)
{
	DMSG("Ooops...");
	panic();
}

static const uint32_t iac_fbd_periph[] = {
	STM32MP25_RIFSC_PWR_ID, STM32MP25_RIFSC_GPIOA_ID,
	STM32MP25_RIFSC_GPIOB_ID, STM32MP25_RIFSC_GPIOC_ID,
	STM32MP25_RIFSC_GPIOD_ID, STM32MP25_RIFSC_GPIOE_ID,
	STM32MP25_RIFSC_GPIOF_ID, STM32MP25_RIFSC_GPIOG_ID,
	STM32MP25_RIFSC_GPIOH_ID, STM32MP25_RIFSC_GPIOI_ID,
	STM32MP25_RIFSC_GPIOJ_ID, STM32MP25_RIFSC_GPIOK_ID,
	STM32MP25_RIFSC_GPIOZ_ID
};

static enum itr_return stm32_iac_itr(struct itr_handler *h)
{
	struct iac_device *iac_dev = h->data;
	struct iac_driver_data *ddata = iac_dev->ddata;
	uintptr_t base = iac_dev->pdata.base;
	unsigned int nreg = DIV_ROUND_UP(ddata->num_ilac, _PERIPH_IDS_PER_REG);
	bool do_panic = false;
	unsigned int i = 0;
	unsigned int j = 0;
	uint32_t isr = 0;

	for (i = 0; i < nreg; i++) {
		uint32_t offset = sizeof(uint32_t) * i;
		uint8_t tries = 0;

		isr = io_read32(base + _IAC_ISR0 + offset);
		isr &= io_read32(base + _IAC_IER0 + offset);

		if (!isr)
			continue;

		for (j = 0; j < ARRAY_SIZE(iac_fbd_periph); j++) {
			uint32_t fbd_bit = BIT(iac_fbd_periph[j] %
					       _PERIPH_IDS_PER_REG);

			if (!(isr & fbd_bit) ||
			    IAC_ILAC_ID(isr, i) != iac_fbd_periph[j])
				continue;

			/* This IAC shouldn't lead to a panic */
			IMSG("-------------------------");
			IMSG("| Discarded IAC ID: %3u |", iac_fbd_periph[j]);
			IMSG("-------------------------");

			io_write32(base + _IAC_ICR0 + offset,
				   BIT(IAC_FIRST_ILAC_IN_REG(isr)));

			isr = io_read32(base + _IAC_ISR0 + offset);
			isr &= io_read32(base + _IAC_IER0 + offset);
		}

		/* A legit IAC occurred, platform will panic */
		if (isr) {
			do_panic = true;
			EMSG("IAC exceptions [%d:%d]: %#x",
			     IAC_EXCEPT_MSB_BIT(i), IAC_EXCEPT_LSB_BIT(i), isr);
		}

		while (isr && tries < _PERIPH_IDS_PER_REG) {
			EMSG("IAC exception ID: %d", IAC_ILAC_ID(isr, i));

			io_write32(base + _IAC_ICR0 + offset,
				   BIT(IAC_FIRST_ILAC_IN_REG(isr)));

			isr = io_read32(base + _IAC_ISR0 + offset);
			isr &= io_read32(base + _IAC_IER0 + offset);

			tries++;
		}
	}

	if (do_panic && IS_ENABLED(CFG_STM32_PANIC_ON_IAC_EVENT))
		access_violation_action();

	return ITRR_HANDLED;
}

static void stm32_iac_setup(struct iac_device *iac_dev)
{
	struct iac_driver_data *ddata = iac_dev->ddata;
	uintptr_t base = iac_dev->pdata.base;
	int nreg = DIV_ROUND_UP(ddata->num_ilac, _PERIPH_IDS_PER_REG);
	int i = 0;

	for (i = 0; i < nreg; i++) {
		vaddr_t reg_ofst = base + sizeof(uint32_t) * i;

		//clear status flags
		io_write32(reg_ofst + _IAC_ICR0, ~0x0);
		//enable all peripherals of nreg
		io_write32(reg_ofst + _IAC_IER0, ~0x0);
	}
}

static TEE_Result probe_iac_device(struct iac_device *iac_dev)
{
	int err = 0;

	assert(iac_dev);

	err = stm32_iac_get_platdata(&iac_dev->pdata);
	if (err)
		return TEE_ERROR_GENERIC;

	err = stm32_iac_parse_fdt(iac_dev);
	if (err)
		return TEE_ERROR_GENERIC;

	stm32_iac_get_hwdata(iac_dev);
	stm32_iac_setup(iac_dev);

	iac_dev->itr = itr_alloc_add(iac_dev->pdata.irq, stm32_iac_itr,
				     ITRF_TRIGGER_LEVEL, iac_dev);
	if (!iac_dev->itr)
		return TEE_ERROR_BAD_PARAMETERS;

	itr_enable(iac_dev->itr->it);

	return TEE_SUCCESS;
}

static struct iac_device *stm32_iac_alloc(void)
{
	struct iac_device *iac_dev;
	struct iac_driver_data *iac_ddata;

	iac_dev = calloc(1, sizeof(*iac_dev));
	iac_ddata = calloc(1, sizeof(*iac_ddata));

	if (iac_dev && iac_ddata) {
		iac_dev->ddata = iac_ddata;
		return iac_dev;
	}

	return NULL;
}

static void stm32_iac_free(struct iac_device *iac_dev)
{
	if (iac_dev->itr)
		itr_free(iac_dev->itr);

	if (iac_dev) {
		free(iac_dev->ddata);
		free(iac_dev);
	}
}

static TEE_Result stm32_iac_probe(const void *fdt, int node,
				  const void *compat_data __unused)
{
	struct iac_device *iac_dev = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	iac_dev = stm32_iac_alloc();
	if (!iac_dev)
		return TEE_ERROR_OUT_OF_MEMORY;

	iac_dev->fdt = fdt;
	iac_dev->node = node;
	res = probe_iac_device(iac_dev);

	if (res)
		stm32_iac_free(iac_dev);

	return res;
}

static const struct dt_device_match stm32_iac_match_table[] = {
	{ .compatible = "st,stm32mp25-iac" },
	{ }
};

DEFINE_DT_DRIVER(stm32_iac_dt_driver) = {
	.name = "stm32-iac",
	.match_table = stm32_iac_match_table,
	.probe = stm32_iac_probe,
};
