// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021, STMicroelectronics
 */

#include <drivers/stm32_rifsc.h>
#include <dt-bindings/soc/stm32mp25-rifsc.h>
#include <io.h>
#include <kernel/dt.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <util.h>

/* RIFSC offset register */
#define _RIFSC_RISC_SECCFGR0		U(0x10)
#define _RIFSC_RISC_PRIVCFGR0		U(0x30)
#define _RIFSC_RISC_PER0_CIDCFGR	U(0x100)
#define _RIFSC_RIMC_ATTR0		U(0xC10)

#define _RIFSC_HWCFGR3			U(0xFE8)
#define _RIFSC_HWCFGR2			U(0xFEC)
#define _RIFSC_HWCFGR1			U(0xFF0)
#define _RIFSC_VERR			U(0xFF4)

/* RIFSC_HWCFGR2 register fields */
#define _RIFSC_HWCFGR2_CFG1_MASK	GENMASK_32(15, 0)
#define _RIFSC_HWCFGR2_CFG1_SHIFT	0
#define _RIFSC_HWCFGR2_CFG2_MASK	GENMASK_32(23, 16)
#define _RIFSC_HWCFGR2_CFG2_SHIFT	16
#define _RIFSC_HWCFGR2_CFG3_MASK	GENMASK_32(31, 24)
#define _RIFSC_HWCFGR2_CFG3_SHIFT	24

/* RIFSC_HWCFGR1 register fields */
#define _RIFSC_HWCFGR1_CFG1_MASK	GENMASK_32(3, 0)
#define _RIFSC_HWCFGR1_CFG1_SHIFT	0
#define _RIFSC_HWCFGR1_CFG2_MASK	GENMASK_32(7, 4)
#define _RIFSC_HWCFGR1_CFG2_SHIFT	4
#define _RIFSC_HWCFGR1_CFG3_MASK	GENMASK_32(11, 8)
#define _RIFSC_HWCFGR1_CFG3_SHIFT	8
#define _RIFSC_HWCFGR1_CFG4_MASK	GENMASK_32(15, 12)
#define _RIFSC_HWCFGR1_CFG4_SHIFT	12
#define _RIFSC_HWCFGR1_CFG5_MASK	GENMASK_32(19, 16)
#define _RIFSC_HWCFGR1_CFG5_SHIFT	16
#define _RIFSC_HWCFGR1_CFG6_MASK	GENMASK_32(23, 20)
#define _RIFSC_HWCFGR1_CFG6_SHIFT	20

/* RIFSC_VERR register fields */
#define _RIFSC_VERR_MINREV_MASK		GENMASK_32(3, 0)
#define _RIFSC_VERR_MINREV_SHIFT	0
#define _RIFSC_VERR_MAJREV_MASK		GENMASK_32(7, 4)
#define _RIFSC_VERR_MAJREV_SHIFT	4

/* Periph id per register */
#define _PERIPH_IDS_PER_REG		32
#define _OFST_PERX_CIDCFGR		U(0x8)

#define RIFSC_RISC_CFEN_MASK		BIT(0)
#define RIFSC_RISC_SEM_EN_MASK		BIT(1)
#define RIFSC_RISC_SCID_MASK		GENMASK_32(6, 4)
#define RIFSC_RISC_SEC_MASK		BIT(8)
#define RIFSC_RISC_PRIV_MASK		BIT(9)
#define RIFSC_RISC_LOCK_MASK		BIT(10)
#define RIFSC_RISC_SEML_MASK		GENMASK_32(23, 16)
#define RIFSC_RISC_PER_ID_MASK		GENMASK_32(31, 24)

#define RIFSC_RISC_PERx_CID_MASK	(RIFSC_RISC_CFEN_MASK | \
					 RIFSC_RISC_SEM_EN_MASK | \
					 RIFSC_RISC_SCID_MASK | \
					 RIFSC_RISC_SEML_MASK)

#define RIFSC_RIMC_MODE_MASK		BIT(2)
#define RIFSC_RIMC_MCID_MASK		GENMASK_32(6, 4)
#define RIFSC_RIMC_MSEC_MASK		BIT(8)
#define RIFSC_RIMC_MPRIV_MASK		BIT(9)
#define RIFSC_RIMC_M_ID_MASK		GENMASK_32(23, 16)

#define RIFSC_RIMC_ATTRx_MASK		(RIFSC_RIMC_MODE_MASK | \
					 RIFSC_RIMC_MCID_MASK | \
					 RIFSC_RIMC_MSEC_MASK | \
					 RIFSC_RIMC_MPRIV_MASK)

/* max entries */
#define MAX_RIMU	16
#define MAX_RISUP	128

#define _RIF_FLD_PREP(field, value)	(((uint32_t)(value) << (field ## _SHIFT)) & (field ## _MASK))
#define _RIF_FLD_GET(field, value)	(((uint32_t)(value) & (field ## _MASK)) >> (field ## _SHIFT))

struct rifsc_driver_data {
	uint32_t version;
	uint8_t nb_rimu;
	uint8_t nb_risup;
	uint8_t nb_risal;
	bool rif_en;
	bool sec_en;
	bool priv_en;
};

struct rifsc_platdata {
	uintptr_t base;
	struct rifsc_driver_data *drv_data;
	struct risup_cfg *risup;
	int nrisup;
	struct rimu_cfg *rimu;
	int nrimu;
};

struct dt_id_attr {
	/* The effective size of the array is meaningless here */
	fdt32_t id_attr[1];
};

static struct rifsc_driver_data rifsc_drvdata;
static struct rifsc_platdata rifsc_pdata;

static void stm32_rifsc_get_driverdata(struct rifsc_platdata *pdata)
{
	uint32_t regval = 0;

	regval = io_read32(pdata->base + _RIFSC_HWCFGR1);
	rifsc_drvdata.rif_en = _RIF_FLD_GET(_RIFSC_HWCFGR1_CFG1, regval) != 0;
	rifsc_drvdata.sec_en = _RIF_FLD_GET(_RIFSC_HWCFGR1_CFG2, regval) != 0;
	rifsc_drvdata.priv_en = _RIF_FLD_GET(_RIFSC_HWCFGR1_CFG3, regval) != 0;

	regval = io_read32(pdata->base + _RIFSC_HWCFGR2);
	rifsc_drvdata.nb_risup = _RIF_FLD_GET(_RIFSC_HWCFGR2_CFG1, regval);
	rifsc_drvdata.nb_rimu = _RIF_FLD_GET(_RIFSC_HWCFGR2_CFG2, regval);
	rifsc_drvdata.nb_risal = _RIF_FLD_GET(_RIFSC_HWCFGR2_CFG3, regval);

	pdata->drv_data = &rifsc_drvdata;

	regval = io_read8(pdata->base + _RIFSC_VERR);

	DMSG("RIFSC version %"PRIu32".%"PRIu32,
	     _RIF_FLD_GET(_RIFSC_VERR_MAJREV, regval),
	     _RIF_FLD_GET(_RIFSC_VERR_MINREV, regval));

	DMSG("HW cap: enabled[rif:sec:priv]:[%s:%s:%s] nb[risup|rimu|risal]:[%"PRIu8",%"PRIu8",%"PRIu8"]",
	     rifsc_drvdata.rif_en ? "true" : "false",
	     rifsc_drvdata.sec_en ? "true" : "false",
	     rifsc_drvdata.priv_en ? "true" : "false",
	     rifsc_drvdata.nb_risup,
	     rifsc_drvdata.nb_rimu,
	     rifsc_drvdata.nb_risal);
}

static TEE_Result stm32_rifsc_dt_conf_risup(const void *fdt, int node,
					    int *nrisup,
					    struct risup_cfg **risups)
{
	const struct dt_id_attr *conf_list = NULL;
	int i = 0;
	int len = 0;

	conf_list = (const struct dt_id_attr *)fdt_getprop(fdt, node,
							   "st,protreg", &len);
	if (!conf_list) {
		IMSG("No RISUP configuration in DT");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	*nrisup = len / sizeof(uint32_t);
	*risups = calloc(*nrisup, sizeof(**risups));
	if (!*risups)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < *nrisup; i++) {
		uint32_t value = fdt32_to_cpu(conf_list->id_attr[i]);
		struct risup_cfg *risup = *risups + i;

		risup->id = _RIF_FLD_GET(RIFSC_RISC_PER_ID, value);
		risup->sec = (bool)_RIF_FLD_GET(RIFSC_RISC_SEC, value);
		risup->priv = (bool)_RIF_FLD_GET(RIFSC_RISC_PRIV, value);
		risup->cid_attr = _RIF_FLD_GET(RIFSC_RISC_PERx_CID, value);
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_rifsc_dt_conf_rimu(const void *fdt, int node,
					   struct rifsc_platdata *pdata)
{
	const struct dt_id_attr *conf_list = NULL;
	int i = 0;
	int len = 0;

	conf_list = (const struct dt_id_attr *)fdt_getprop(fdt, node,
							   "st,rimu", &len);
	if (!conf_list) {
		IMSG("No RIMU configuration in DT");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	len = len / sizeof(uint32_t);

	pdata->nrimu = len;
	pdata->rimu = calloc(len, sizeof(*pdata->rimu));
	if (!pdata->rimu)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < len; i++) {
		uint32_t value = fdt32_to_cpu(conf_list->id_attr[i]);
		struct rimu_cfg *rimu = pdata->rimu + i;

		rimu->id = _RIF_FLD_GET(RIFSC_RIMC_M_ID, value);
		rimu->attr = _RIF_FLD_GET(RIFSC_RIMC_ATTRx, value);
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_rifsc_parse_fdt(const void *fdt, int node,
					struct rifsc_platdata *pdata)
{
	static struct io_pa_va base;
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t reg_size = 0;

	base.pa = _fdt_reg_base_address(fdt, node);
	if (base.pa == DT_INFO_INVALID_REG)
		return TEE_ERROR_BAD_PARAMETERS;

	reg_size = _fdt_reg_size(fdt, node);
	if (reg_size == DT_INFO_INVALID_REG_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	pdata->base = io_pa_or_va_secure(&base, reg_size);

	res = stm32_rifsc_dt_conf_risup(fdt, node, &pdata->nrisup,
					&pdata->risup);
	if (res)
		return res;

	res = stm32_rifsc_dt_conf_rimu(fdt, node, pdata);
	if (res)
		return res;

	return TEE_SUCCESS;
}

static TEE_Result stm32_risup_cfg(struct rifsc_platdata *pdata,
				  struct risup_cfg *risup)
{
	struct rifsc_driver_data *drv_data = pdata->drv_data;
	uintptr_t offset = sizeof(uint32_t) * (risup->id / _PERIPH_IDS_PER_REG);
	uint32_t shift = risup->id % _PERIPH_IDS_PER_REG;

	if (!risup || risup->id >= drv_data->nb_risup)
		return TEE_ERROR_BAD_PARAMETERS;

	if (drv_data->sec_en)
		io_clrsetbits32(pdata->base + _RIFSC_RISC_SECCFGR0 + offset,
				BIT(shift), risup->sec << shift);

	if (drv_data->priv_en)
		io_clrsetbits32(pdata->base + _RIFSC_RISC_PRIVCFGR0 + offset,
				BIT(shift), risup->priv << shift);

	if (drv_data->rif_en) {
		offset = _OFST_PERX_CIDCFGR * risup->id;
		io_write32(pdata->base + _RIFSC_RISC_PER0_CIDCFGR + offset,
			   risup->cid_attr);
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_risup_setup(struct rifsc_platdata *pdata)
{
	struct rifsc_driver_data *drv_data = pdata->drv_data;
	int i = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	for (i = 0; i < pdata->nrisup && i < drv_data->nb_risup; i++) {
		struct risup_cfg *risup = pdata->risup + i;

		res = stm32_risup_cfg(pdata, risup);
		if (res) {
			EMSG("risup cfg(%d/%d) error", i + 1, pdata->nrisup);
			return res;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_rimu_cfg(struct rifsc_platdata *pdata,
				 struct rimu_cfg *rimu)
{
	struct rifsc_driver_data *drv_data = pdata->drv_data;
	uintptr_t offset =  _RIFSC_RIMC_ATTR0 + (sizeof(uint32_t) * rimu->id);

	if (!rimu || rimu->id >= drv_data->nb_rimu)
		return TEE_ERROR_BAD_PARAMETERS;

	if (drv_data->rif_en)
		io_write32(pdata->base + offset, rimu->attr);

	return TEE_SUCCESS;
}

static TEE_Result stm32_rimu_setup(struct rifsc_platdata *pdata)
{
	struct rifsc_driver_data *drv_data = pdata->drv_data;
	int i = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	for (i = 0; i < pdata->nrimu && i < drv_data->nb_rimu; i++) {
		struct rimu_cfg *rimu = pdata->rimu + i;

		res = stm32_rimu_cfg(pdata, rimu);
		if (res) {
			EMSG("rimu cfg(%d/%d) error", i + 1, pdata->nrimu);
			return res;
		}
	}

	return 0;
}

static TEE_Result
stm32_rifsc_get_data_config(const void *fdt, int node,
			    int *ndata, void **data_cfg)
{
	if (stm32_rifsc_dt_conf_risup(fdt, node, ndata,
				      (struct risup_cfg **)data_cfg))
		return TEE_ERROR_ITEM_NOT_FOUND;

	return TEE_SUCCESS;
}

static TEE_Result
stm32_rifsc_set_data_config(int ndata, void *data_cfg)
{
	struct rifsc_platdata *pdata = &rifsc_pdata;
	struct rifsc_driver_data *drv_data = pdata->drv_data;
	int i = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	for (i = 0; i < ndata && i < drv_data->nb_risup; i++) {
		struct risup_cfg *risup = (struct risup_cfg *)data_cfg + i;

		res = stm32_risup_cfg(pdata, risup);
		if (res) {
			EMSG("risup cfg(%d/%d) error", i + 1, ndata);
			return res;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result
stm32_rifsc_put_data_config(int ndata __unused, void *data_cfg)
{
	free(data_cfg);

	return TEE_SUCCESS;
}

static const struct stm32_firewall_ops stm32_rifsc_fw_ops = {
	.get_data_config = stm32_rifsc_get_data_config,
	.set_data_config = stm32_rifsc_set_data_config,
	.put_data_config = stm32_rifsc_put_data_config,
};

static TEE_Result stm32_rifsc_probe(const void *fdt, int node,
				    const void *compat_data)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = stm32_rifsc_parse_fdt(fdt, node, &rifsc_pdata);
	if (res)
		return res;

	if (!rifsc_pdata.drv_data)
		stm32_rifsc_get_driverdata(&rifsc_pdata);

	res = stm32_risup_setup(&rifsc_pdata);
	if (res)
		return res;

	res = stm32_rimu_setup(&rifsc_pdata);
	if (res)
		return res;

	return res;
}

static const struct dt_device_match rifsc_match_table[] = {
	{ .compatible = "st,stm32mp25-rifsc", .compat_data = rifsc_compat },
	{ }
};

DEFINE_DT_DRIVER(rifsc_dt_driver) = {
	.name = "stm32-rifsc",
	.match_table = rifsc_match_table,
	.probe = stm32_rifsc_probe,
};
