// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021-2022, STMicroelectronics
 */

#include <assert.h>
#include <config.h>
#include <crypto/crypto.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/stm32_exti.h>
#include <drivers/stm32_gpio.h>
#include <drivers/stm32_rtc.h>
#include <drivers/stm32_tamp.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <sm/psci.h>
#include <stdbool.h>
#include <stm32_util.h>


/* STM32 Registers */
#define _TAMP_CR1			0x00U
#define _TAMP_CR2			0x04U
#define _TAMP_CR3			0x08U
#define _TAMP_FLTCR			0x0CU
#define _TAMP_ATCR1			0x10U
#define _TAMP_ATSEEDR			0x14U
#define _TAMP_ATOR			0x18U
#define _TAMP_ATCR2			0x1CU
#define _TAMP_SECCFGR			0x20U
#define _TAMP_SMCR			0x20U
#define _TAMP_PRIVCFGR			0x24U
#define _TAMP_IER			0x2CU
#define _TAMP_SR			0x30U
#define _TAMP_MISR			0x34U
#define _TAMP_SMISR			0x38U
#define _TAMP_SCR			0x3CU
#define _TAMP_COUNTR			0x40U
#define _TAMP_COUNT2R			0x44U
#define _TAMP_OR			0x50U
#define _TAMP_ERCFGR			0X54U
#define _TAMP_BKPRIFR(x)		(0x70U + 0x4U * ((x) - 1))
#define _TAMP_CIDCFGR(x)		(0x80U + 0x4U * (x))
#define _TAMP_BKPxR(x)			(0x100U + 0x4U * ((x) - 1))
#define _TAMP_HWCFGR2			0x3ECU
#define _TAMP_HWCFGR1			0x3F0U
#define _TAMP_VERR			0x3F4U
#define _TAMP_IPIDR			0x3F8U
#define _TAMP_SIDR			0x3FCU

/* _TAMP_CR1 bit fields */
#define _TAMP_CR1_ITAMP(id)		BIT((id) - INT_TAMP1 + 16U)
#define _TAMP_CR1_ETAMP(id)		BIT((id) - EXT_TAMP1)

/* _TAMP_CR2 bit fields */
#define _TAMP_CR2_ETAMPTRG(id)		BIT((id) - EXT_TAMP1 + 24U)
#define _TAMP_CR2_BKERASE		BIT(23)
#define _TAMP_CR2_BKBLOCK		BIT(22)
#define _TAMP_CR2_ETAMPMSK_MAX_ID	3U
#define _TAMP_CR2_ETAMPMSK(id)		BIT((id) - EXT_TAMP1 + 16U)
#define _TAMP_CR2_ETAMPNOER(id)		BIT((id) - EXT_TAMP1)

/* _TAMP_CR3 bit fields */
#define _TAMP_CR3_ITAMPNOER_ALL		GENMASK_32(12, 0)
#define _TAMP_CR3_ITAMPNOER(id)		BIT((id) - INT_TAMP1)

/* _TAMP_FLTCR bit fields */
#define _TAMP_FLTCR_TAMPFREQ_MASK	GENMASK_32(2, 0)
#define _TAMP_FLTCR_TAMPFREQ_SHIFT	0U
#define _TAMP_FLTCR_TAMPFLT_MASK	GENMASK_32(4, 3)
#define _TAMP_FLTCR_TAMPFLT_SHIFT	3U
#define _TAMP_FLTCR_TAMPPRCH_MASK	GENMASK_32(6, 5)
#define _TAMP_FLTCR_TAMPPRCH_SHIFT	5U
#define _TAMP_FLTCR_TAMPPUDIS		BIT(7)

/* _TAMP_ATCR bit fields */
#define _TAMP_ATCR1_ATCKSEL_MASK	GENMASK_32(19, 16)
#define _TAMP_ATCR1_ATCKSEL_SHIFT	16U
#define _TAMP_ATCR1_ATPER_MASK		GENMASK_32(26, 24)
#define _TAMP_ATCR1_ATPER_SHIFT		24U
#define _TAMP_ATCR1_ATOSHARE		BIT(30)
#define _TAMP_ATCR1_FLTEN		BIT(31)
#define _TAMP_ATCR1_COMMON_MASK		GENMASK_32(31, 16)
#define _TAMP_ATCR1_ETAMPAM(id)		BIT((id) - EXT_TAMP1)
#define _TAMP_ATCR1_ATOSEL_MASK(id)	GENMASK_32(((id) - EXT_TAMP1 + 1) *    \
						   2U + 7U,                    \
						   ((id) - EXT_TAMP1) * 2U + 8U)
#define _TAMP_ATCR1_ATOSEL(id, od)	SHIFT_U32(((od) - OUT_TAMP1),          \
					 (((id) - EXT_TAMP1) * 2U + 8U))

/* _TAMP_ATOR bit fields */
#define _TAMP_PRNG			GENMASK_32(7, 0)
#define _TAMP_SEEDF			BIT(14)
#define _TAMP_INITS			BIT(15)

/* _TAMP_IER bit fields */
#define _TAMP_IER_ITAMP(id)		BIT((id) - INT_TAMP1 + 16U)
#define _TAMP_IER_ETAMP(id)		BIT((id) - EXT_TAMP1)

/* _TAMP_SR bit fields */
#define _TAMP_SR_ETAMPXF_MASK		GENMASK_32(7, 0)
#define _TAMP_SR_ITAMPXF_MASK		GENMASK_32(31, 16)
#define _TAMP_SR_ITAMP(id)		BIT((id) - INT_TAMP1 + 16U)
#define _TAMP_SR_ETAMP(id)		BIT((id) - EXT_TAMP1)

/* _TAMP_SCR bit fields */
#define _TAMP_SCR_ITAMP(id)		BIT((id) - INT_TAMP1 + 16U)
#define _TAMP_SCR_ETAMP(id)		BIT((id) - EXT_TAMP1)

/* _TAMP_SECCFGR bit fields */
#define _TAMP_SECCFGR_BKPRWSEC_MASK	GENMASK_32(7, 0)
#define _TAMP_SECCFGR_BKPRWSEC_SHIFT	0U
#define _TAMP_SECCFGR_CNT2SEC		BIT(14)
#define _TAMP_SECCFGR_CNT2SEC_SHIFT	14U
#define _TAMP_SECCFGR_CNT1SEC		BIT(15)
#define _TAMP_SECCFGR_CNT1SEC_SHIFT	15U
#define _TAMP_SECCFGR_BKPWSEC_MASK	GENMASK_32(23, 16)
#define _TAMP_SECCFGR_BKPWSEC_SHIFT	16U
#define _TAMP_SECCFGR_BHKLOCK		BIT(30)
#define _TAMP_SECCFGR_TAMPSEC		BIT(31)
#define _TAMP_SECCFGR_TAMPSEC_SHIFT	31U
#define _TAMP_SECCFGR_BUT_BKP_MASK	(GENMASK_32(31, 30) | \
					 GENMASK_32(15, 14))
#define _TAMP_SECCFGR_RIF_TAMP_SEC	BIT(0)
#define _TAMP_SECCFGR_RIF_COUNT_1	BIT(1)
#define _TAMP_SECCFGR_RIF_COUNT_2	BIT(2)

/* _TAMP_SMCR bit fields */
#define _TAMP_SMCR_BKPRWDPROT_MASK	GENMASK_32(7, 0)
#define _TAMP_SMCR_BKPRWDPROT_SHIFT	0U
#define _TAMP_SMCR_BKPWDPROT_MASK	GENMASK_32(23, 16)
#define _TAMP_SMCR_BKPWDPROT_SHIFT	16U
#define _TAMP_SMCR_DPROT		BIT(31)

/*
 * _TAMP_PRIVCFGR bit fields
 */
#define _TAMP_PRIVCFG_CNT2PRIV		BIT(14)
#define _TAMP_PRIVCFG_CNT1PRIV		BIT(15)
#define _TAMP_PRIVCFG_BKPRWPRIV		BIT(29)
#define _TAMP_PRIVCFG_BKPWPRIV		BIT(30)
#define _TAMP_PRIVCFG_TAMPPRIV		BIT(31)
#define _TAMP_PRIVCFGR_MASK		(GENMASK_32(31, 29) | \
					 GENMASK_32(15, 14))
#define _TAMP_PRIVCFGR_RIF_TAMP_PRIV	BIT(0)
#define _TAMP_PRIVCFGR_RIF_R1		BIT(1)
#define _TAMP_PRIVCFGR_RIF_R2		BIT(2)

/* _TAMP_ATCR2 bit fields */
#define _TAMP_ATCR2_ATOSEL_MASK(id)	GENMASK_32(((id) - EXT_TAMP1 + 1) *    \
						   3U + 7U,                    \
						   ((id) - EXT_TAMP1) * 3U + 8U)
#define _TAMP_ATCR2_ATOSEL(id, od)	SHIFT_U32(((od) - OUT_TAMP1),          \
						 (((id) - EXT_TAMP1) * 3U + 8U))

/* _TAMP_OR bit fields */
#define _TAMP_OR_IN1RMP_PF10		0U
#define _TAMP_OR_IN1RMP_PC13		BIT(0)
#define _TAMP_OR_IN2RMP_PA6		0U
#define _TAMP_OR_IN2RMP_PI1		BIT(1)
#define _TAMP_OR_IN3RMP_PC0		0U
#define _TAMP_OR_IN3RMP_PI2		BIT(2)
#define _TAMP_OR_IN4RMP_PG8		0U
#define _TAMP_OR_IN4RMP_PI3		BIT(3)

#define _TAMP_OR_OUT3RMP_PI8		0U
#define _TAMP_OR_OUT3RMP_PC13		BIT(0)

/* _TAMP_ERCFGR bit fields */
#define _TAMP_ERCFGR_ERCFG0		BIT(0)
#define _TAMP_ERCFGR_ERCFG_MASK		BIT(0)

/* _TAMP_HWCFGR2 bit fields */
#define _TAMP_HWCFGR2_OR		GENMASK_32(7, 0)
#define _TAMP_HWCFGR2_TZ		GENMASK_32(11, 8)
#define _TAMP_HWCFGR2_RIF		GENMASK_32(19, 16)
#define _TAMP_HWCFGR2_CID_WIDTH		GENMASK_32(23, 20)
#define _TAMP_HWCFGR2_NDEV_SECRETS	GENMASK_32(31, 24)

/* _TAMP_HWCFGR1 bit fields */
#define _TAMP_HWCFGR1_BKPREG		GENMASK_32(7, 0)
#define _TAMP_HWCFGR1_TAMPER		GENMASK_32(11, 8)
#define _TAMP_HWCFGR1_ACTIVE		GENMASK_32(15, 12)
#define _TAMP_HWCFGR1_INTERN		GENMASK_32(31, 16)
#define _TAMP_HWCFGR1_ITAMP_MAX_ID	16U
#define _TAMP_HWCFGR1_ITAMP(id)		BIT((id) - INT_TAMP1 + 16U)

/* _TAMP_VERR bit fields */
#define _TAMP_VERR_MINREV		GENMASK_32(3, 0)
#define _TAMP_VERR_MAJREV		GENMASK_32(7, 4)

/*
 * CIDCFGR register bitfields
 */
#define _TAMP_CIDCFGR_SCID_MASK		GENMASK_32(6, 4)
#define _TAMP_CIDCFGR_CONF_MASK		(_CIDCFGR_CFEN |	 \
					 _CIDCFGR_SEMEN |	 \
					 _TAMP_CIDCFGR_SCID_MASK)

/* _TAMP_BKPRIFR */
#define _TAMP_BKPRIFR_1_MASK		GENMASK_32(7, 0)
#define _TAMP_BKPRIFR_2_MASK		GENMASK_32(7, 0)
#define _TAMP_BKPRIFR_3_MASK		(GENMASK_32(23, 16) | GENMASK_32(7, 0))
#define _TAMP_BKPRIFR_ZONE3_RIF2_SHIFT	16U

#define SEED_TIMEOUT_US			1000U

/* Define TAMPER modes from DT */
#define TAMP_TRIG_ON			BIT(16)
#define TAMP_ACTIVE			BIT(17)
#define TAMP_IN_DT			BIT(18)

#define TAMP_EXTI_WKUP			18U

/*
 * RIF miscellaneous
 */
#define TAMP_RIF_RESOURCES		3U
#define TAMP_NB_MAX_CID_SUPPORTED	7U

enum stm32_tamp_out_id {
	OUT_TAMP1 = LAST_TAMP,
	OUT_TAMP2,
	OUT_TAMP3,
	OUT_TAMP4,
	OUT_TAMP5,
	OUT_TAMP6,
	OUT_TAMP7,
	OUT_TAMP8,
	INVALID_OUT_TAMP = INVALID_TAMP
};

struct stm32_tamp_conf {
	const uint32_t id;
	uint32_t out_id;
	uint32_t mode;
	uint32_t (*func)(int id);
};

struct stm32_tamp_pin_map {
	uint32_t id;
	uint8_t bank;
	uint8_t pin;
	bool out;
	uint32_t conf;
};

struct stm32_tamp_instance {
	struct stm32_tamp_platdata pdata;
	struct itr_handler *itr;
	uint32_t hwconf1;
	uint32_t hwconf2;
};

static struct stm32_tamp_conf int_tamp_mp13[] = {
	{ .id = INT_TAMP1 }, { .id = INT_TAMP2 }, { .id = INT_TAMP3 },
	{ .id = INT_TAMP4 }, { .id = INT_TAMP5 }, { .id = INT_TAMP6 },
	{ .id = INT_TAMP7 }, { .id = INT_TAMP8 }, { .id = INT_TAMP9 },
	{ .id = INT_TAMP10 }, { .id = INT_TAMP11 },
	{ .id = INT_TAMP12 }, { .id = INT_TAMP13 },
};

static struct stm32_tamp_conf int_tamp_mp15[] = {
	{ .id = INT_TAMP1 }, { .id = INT_TAMP2 }, { .id = INT_TAMP3 },
	{ .id = INT_TAMP4 }, { .id = INT_TAMP5 }, { .id = INT_TAMP8 },
};

static struct stm32_tamp_conf ext_tamp_mp13[] = {
	{ .id = EXT_TAMP1 }, { .id = EXT_TAMP2 }, { .id = EXT_TAMP3 },
	{ .id = EXT_TAMP4 }, { .id = EXT_TAMP5 }, { .id = EXT_TAMP6 },
	{ .id = EXT_TAMP7 }, { .id = EXT_TAMP8 },
};

static struct stm32_tamp_conf ext_tamp_mp15[] = {
	{ .id = EXT_TAMP1 }, { .id = EXT_TAMP2 }, { .id = EXT_TAMP3 },
};

#define GPIO_BANK(port)	 ((port) - 'A')

static const struct stm32_tamp_pin_map pin_map_mp13[] = {
	{
		.id = EXT_TAMP1, .bank = GPIO_BANK('C'), .pin = 13,
		.out = false, .conf = _TAMP_OR_IN1RMP_PC13
	},
	{
		.id = EXT_TAMP2, .bank = GPIO_BANK('I'), .pin = 1,
		.out = false, .conf = _TAMP_OR_IN2RMP_PI1
	},
	{
		.id = EXT_TAMP3, .bank = GPIO_BANK('I'), .pin = 2,
		.out = false, .conf = _TAMP_OR_IN3RMP_PI2
	},
	{
		.id = EXT_TAMP4, .bank = GPIO_BANK('I'), .pin = 3,
		.out = false, .conf = _TAMP_OR_IN4RMP_PI3
	},
};

static const struct stm32_tamp_pin_map pin_map_mp15[] = {
	{
		.id = OUT_TAMP3, .bank = GPIO_BANK('C'), .pin = 13,
		.out = true, .conf = _TAMP_OR_OUT3RMP_PC13
	},
};

/* Expects at most a single instance */
static struct stm32_tamp_instance stm32_tamp;

static enum itr_return stm32_tamp_it_handler(struct itr_handler *h);

static void apply_rif_config(void)
{
	vaddr_t base = io_pa_or_va(&stm32_tamp.pdata.base, 1);
	bool is_tdcid = false;
	uint32_t seccfgr = 0;
	uint32_t privcfgr = 0;
	uint32_t access_mask_sec_reg = 0;
	uint32_t access_mask_priv_reg = 0;
	unsigned int i = 0;

	if (stm32_rifsc_check_tdcid(&is_tdcid))
		panic();

	/* Build access masks for _TAMP_PRIVCFGR and _TAMP_SECCFGR */
	for (i = 0; i < TAMP_RIF_RESOURCES; i++) {
		if (BIT(i) & stm32_tamp.pdata.conf_data.access_mask[0]) {
			switch (i) {
			case 0:
				access_mask_sec_reg |= _TAMP_SECCFGR_TAMPSEC;
				access_mask_priv_reg |= _TAMP_PRIVCFG_TAMPPRIV;
				break;
			case 1:
				access_mask_sec_reg |= _TAMP_SECCFGR_CNT1SEC;
				access_mask_priv_reg |= _TAMP_PRIVCFG_CNT1PRIV;
				access_mask_priv_reg |= _TAMP_PRIVCFG_BKPRWPRIV;
				break;
			case 2:
				access_mask_sec_reg |= _TAMP_SECCFGR_CNT2SEC;
				access_mask_priv_reg |= _TAMP_PRIVCFG_CNT2PRIV;
				access_mask_priv_reg |= _TAMP_PRIVCFG_BKPWPRIV;
				break;
			default:
				panic();
			}
		}
	}

	/*
	 * When TDCID, OP-TEE should be the one to set the CID filtering
	 * configuration. Clearing previous configuration prevents
	 * undesired events during the only legitimate configuration.
	 */
	if (is_tdcid) {
		for (i = 0; i < TAMP_RIF_RESOURCES; i++)
			if (BIT(i) & stm32_tamp.pdata.conf_data.access_mask[0])
				io_clrbits32(base + _TAMP_CIDCFGR(i),
					     _TAMP_CIDCFGR_CONF_MASK);
	}

	seccfgr = stm32_tamp.pdata.conf_data.sec_conf[0];
	seccfgr = (seccfgr & _TAMP_SECCFGR_RIF_TAMP_SEC ?
		   _TAMP_SECCFGR_TAMPSEC : 0) |
		  (seccfgr & _TAMP_SECCFGR_RIF_COUNT_1 ?
		   _TAMP_SECCFGR_CNT1SEC : 0) |
		  (seccfgr & _TAMP_SECCFGR_RIF_COUNT_2 ?
		   _TAMP_SECCFGR_CNT2SEC : 0);

	privcfgr = stm32_tamp.pdata.conf_data.priv_conf[0];
	privcfgr = (privcfgr & _TAMP_PRIVCFGR_RIF_TAMP_PRIV ?
		    _TAMP_PRIVCFG_TAMPPRIV : 0) |
		   (privcfgr & _TAMP_PRIVCFGR_RIF_R1 ?
		    (_TAMP_PRIVCFG_CNT1PRIV | _TAMP_PRIVCFG_BKPRWPRIV) : 0) |
		   (privcfgr & _TAMP_PRIVCFGR_RIF_R2 ?
		    (_TAMP_PRIVCFG_CNT2PRIV | _TAMP_PRIVCFG_BKPWPRIV) : 0);

	/* Security and privilege RIF configuration */
	io_clrsetbits32(base + _TAMP_PRIVCFGR,
			_TAMP_PRIVCFGR_MASK & access_mask_sec_reg, privcfgr);
	io_clrsetbits32(base + _TAMP_SECCFGR,
			_TAMP_SECCFGR_BUT_BKP_MASK & access_mask_priv_reg,
			seccfgr);

	if (!is_tdcid)
		return;

	for (i = 0; i < TAMP_RIF_RESOURCES; i++) {
		if (!(BIT(i) & stm32_tamp.pdata.conf_data.access_mask[0]))
			continue;

		io_clrsetbits32(base + _TAMP_CIDCFGR(i),
				_TAMP_CIDCFGR_CONF_MASK,
				stm32_tamp.pdata.conf_data.cid_confs[i]);
	}
}

static TEE_Result stm32_tamp_apply_bkpr_rif_conf(void)
{
	struct stm32_bkpregs_conf *bkpregs_conf =
			stm32_tamp.pdata.bkpregs_conf;
	vaddr_t base = io_pa_or_va(&stm32_tamp.pdata.base, 1);
	int i = 0;

	if (!bkpregs_conf)
		panic("No backup register configuration");

	for (i = 0; i < 4; i++) {
		if (bkpregs_conf->rif_offsets[i] >
		    (stm32_tamp.hwconf1 & _TAMP_HWCFGR1_BKPREG))
			return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Fill the 3 TAMP_BKPRIFRx registers */
	io_clrsetbits32(base + _TAMP_BKPRIFR(1), _TAMP_BKPRIFR_1_MASK,
			bkpregs_conf->rif_offsets[0]);
	io_clrsetbits32(base + _TAMP_BKPRIFR(2), _TAMP_BKPRIFR_2_MASK,
			bkpregs_conf->rif_offsets[1]);
	io_clrsetbits32(base + _TAMP_BKPRIFR(3), _TAMP_BKPRIFR_3_MASK,
			bkpregs_conf->rif_offsets[2] |
			(bkpregs_conf->rif_offsets[3] <<
			 _TAMP_BKPRIFR_ZONE3_RIF2_SHIFT));

	DMSG("Backup registers mapping :");
	DMSG("********START of zone 1********");
	DMSG("Protection Zone 1-RIF1 begins at register: 0");
	DMSG("Protection Zone 1-RIF2 begins at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[0]);
	DMSG("Protection Zone 1-RIF2 ends at register: %"PRIu32,
	     bkpregs_conf->nb_zone1_regs ? bkpregs_conf->nb_zone1_regs - 1 : 0);
	DMSG("********END of zone 1********");
	DMSG("********START of zone 2********");
	DMSG("Protection Zone 2-RIF1 begins at register: %"PRIu32,
	     bkpregs_conf->nb_zone1_regs);
	DMSG("Protection Zone 2-RIF2 begins at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[1]);
	DMSG("Protection Zone 2-RIF2 ends at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[1] > bkpregs_conf->nb_zone1_regs ?
	     bkpregs_conf->nb_zone2_regs - 1 : 0);
	DMSG("********END of zone 2********");
	DMSG("********START of zone 3********");
	DMSG("Protection Zone 3-RIF1 begins at register: %"PRIu32,
	     bkpregs_conf->nb_zone2_regs);
	DMSG("Protection Zone 3-RIF0 begins at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[2]);
	DMSG("Protection Zone 3-RIF2 begins at register: %"PRIu32,
	     bkpregs_conf->rif_offsets[3]);
	DMSG("Protection Zone 3-RIF2 ends at the last register: 128");
	DMSG("********END of zone 3********");

	return TEE_SUCCESS;
}

static void stm32_tamp_set_secret_list(struct stm32_tamp_instance *tamp,
				       uint32_t secret_list_conf)
{
	vaddr_t base = io_pa_or_va(&tamp->pdata.base, 1);

	if (tamp->pdata.compat &&
	    (tamp->pdata.compat->tags & TAMP_HAS_REGISTER_ERCFGR)) {

		io_clrsetbits32(base + _TAMP_ERCFGR,
				_TAMP_ERCFGR_ERCFG_MASK,
				secret_list_conf & _TAMP_ERCFGR_ERCFG_MASK);
	}
}

static void stm32_tamp_set_secure(struct stm32_tamp_instance *tamp,
				  uint32_t mode)
{
	vaddr_t base = io_pa_or_va(&tamp->pdata.base, 1);

	if (tamp->pdata.compat &&
	    (tamp->pdata.compat->tags & TAMP_HAS_REGISTER_SECCFGR)) {
		io_clrsetbits32(base + _TAMP_SECCFGR,
				_TAMP_SECCFGR_BUT_BKP_MASK,
				mode & _TAMP_SECCFGR_BUT_BKP_MASK);
	} else {
		/*
		 * Note: MP15 doesn't use SECCFG register
		 * and inverts the secure bit
		 */
		if (mode & _TAMP_SECCFGR_TAMPSEC)
			io_clrbits32(base + _TAMP_SMCR, _TAMP_SMCR_DPROT);
		else
			io_setbits32(base + _TAMP_SMCR, _TAMP_SMCR_DPROT);
	}
}

static void stm32_tamp_set_privilege(struct stm32_tamp_instance *tamp,
				     uint32_t mode)
{
	vaddr_t base = io_pa_or_va(&tamp->pdata.base, 1);

	if (tamp->pdata.compat &&
	    (tamp->pdata.compat->tags & TAMP_HAS_REGISTER_PRIVCFGR))
		io_clrsetbits32(base + _TAMP_PRIVCFGR, _TAMP_PRIVCFGR_MASK,
				mode & _TAMP_PRIVCFGR_MASK);
}

static void stm32_tamp_set_pins(vaddr_t base, uint32_t mode)
{
	io_setbits32(base + _TAMP_OR, mode);
}

static TEE_Result stm32_tamp_set_seed(vaddr_t base)
{
	/* Need RNG access. */
	uint64_t timeout_ref = 0;
	int idx = 0;

	for (idx = 0; idx < 4; idx++) {
		uint32_t rnd = 0;

		if (crypto_rng_read((uint8_t *)&rnd, sizeof(uint32_t)))
			return TEE_ERROR_BAD_STATE;

		io_write32(base + _TAMP_ATSEEDR, rnd);
	}

	timeout_ref = timeout_init_us(SEED_TIMEOUT_US);
	while (io_read32(base + _TAMP_ATOR) & _TAMP_SEEDF)
		if (timeout_elapsed(timeout_ref))
			break;

	if (io_read32(base + _TAMP_ATOR) & _TAMP_SEEDF)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static bool is_int_tamp_id_valid(enum stm32_tamp_id id)
{
	return (id - INT_TAMP1 < _TAMP_HWCFGR1_ITAMP_MAX_ID) &&
	       (stm32_tamp.hwconf1 & _TAMP_HWCFGR1_ITAMP(id));
}

static bool is_ext_tamp_id_valid(enum stm32_tamp_id id)
{
	return (stm32_tamp.pdata.compat) &&
	       (id - EXT_TAMP1 <= stm32_tamp.pdata.compat->ext_tamp_size);
}

static TEE_Result stm32_tamp_set_int_config(struct stm32_tamp_compat *tcompat,
					    uint32_t itamp_index, uint32_t *cr1,
					    uint32_t *cr3, uint32_t *ier)
{
	enum stm32_tamp_id id = INVALID_TAMP;
	struct stm32_tamp_conf *tamp_int = NULL;

	if (!tcompat)
		return TEE_ERROR_BAD_PARAMETERS;

	tamp_int = &tcompat->int_tamp[itamp_index];
	id = tamp_int->id;

	if (!is_int_tamp_id_valid(id))
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * If there is no callback
	 * this tamper is disabled, we reset its configuration.
	 */
	if (!tamp_int->func) {
		*cr1 &= ~_TAMP_CR1_ITAMP(id);
		*ier &= ~_TAMP_IER_ITAMP(id);
		if (tcompat->tags & TAMP_HAS_REGISTER_CR3)
			*cr3 &= ~_TAMP_CR3_ITAMPNOER(id);

		FMSG("INT_TAMP%d disabled", id - INT_TAMP1 + 1);
		return TEE_SUCCESS;
	}

	*cr1 |= _TAMP_CR1_ITAMP(id);
	*ier |= _TAMP_IER_ITAMP(id);

	if (tcompat->tags & TAMP_HAS_REGISTER_CR3) {
		if (tamp_int->mode & TAMP_NOERASE)
			*cr3 |= _TAMP_CR3_ITAMPNOER(id);
		else
			*cr3 &= ~_TAMP_CR3_ITAMPNOER(id);
	}

	DMSG("INT_TAMP%d enabled as a %s tamper", id - INT_TAMP1 + 1,
	     (tamp_int->mode & TAMP_NOERASE) ? "potential" : "full");
	return TEE_SUCCESS;
}

static TEE_Result stm32_tamp_set_ext_config(struct stm32_tamp_compat *tcompat,
					    uint32_t etamp_index,
					    uint32_t *cr1, uint32_t *cr2,
					    uint32_t *atcr1, uint32_t *atcr2,
					    uint32_t *ier)
{
	enum stm32_tamp_id id = INVALID_TAMP;
	struct stm32_tamp_conf *tamp_ext = NULL;

	if (!tcompat)
		return TEE_ERROR_BAD_PARAMETERS;

	tamp_ext = &tcompat->ext_tamp[etamp_index];
	id = tamp_ext->id;

	/* Exit if not a valid TAMP_ID */
	if (!is_ext_tamp_id_valid(id))
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * If there is no callback or this TAMPER wasn't defined in DT,
	 * this tamper is disabled, we reset its configuration.
	 */
	if (!tamp_ext->func || !(tamp_ext->mode & TAMP_IN_DT)) {
		*cr1 &= ~_TAMP_CR1_ETAMP(id);
		*cr2 &= ~_TAMP_CR2_ETAMPMSK(id);
		*cr2 &= ~_TAMP_CR2_ETAMPTRG(id);
		*cr2 &= ~_TAMP_CR2_ETAMPNOER(id);
		*ier &= ~_TAMP_IER_ETAMP(id);

		FMSG("EXT_TAMP%d disabled", id - EXT_TAMP1 + 1);
		return TEE_SUCCESS;
	}

	*cr1 |= _TAMP_CR1_ETAMP(id);

	if (tamp_ext->mode & TAMP_TRIG_ON)
		*cr2 |= _TAMP_CR2_ETAMPTRG(id);
	else
		*cr2 &= ~_TAMP_CR2_ETAMPTRG(id);

	if (tamp_ext->mode & TAMP_ACTIVE) {
		*atcr1 |= _TAMP_ATCR1_ETAMPAM(id);

		/* Configure output pin if ATOSHARE is selected */
		if (*atcr1 & _TAMP_ATCR1_ATOSHARE) {
			if (tcompat->tags & TAMP_HAS_REGISTER_ATCR2)
				*atcr2 = (*atcr2 &
					  ~_TAMP_ATCR2_ATOSEL_MASK(id)) |
					_TAMP_ATCR2_ATOSEL(id,
							   tamp_ext->out_id);
			else
				*atcr1 = (*atcr1 &
					  ~_TAMP_ATCR1_ATOSEL_MASK(id)) |
					_TAMP_ATCR1_ATOSEL(id,
							   tamp_ext->out_id);
		}
	} else {
		*atcr1 &= ~_TAMP_ATCR1_ETAMPAM(id);
	}

	if (tamp_ext->mode & TAMP_NOERASE)
		*cr2 |= _TAMP_CR2_ETAMPNOER(id);
	else
		*cr2 &= ~_TAMP_CR2_ETAMPNOER(id);

	if (id < _TAMP_CR2_ETAMPMSK_MAX_ID) {
		/*
		 * Only external TAMP 1, 2 and 3 can be masked
		 * and we may want them masked at startup.
		 */
		if (tamp_ext->mode & TAMP_EVT_MASK) {
			/*
			 * ETAMP(id) event generates a trigger event. This
			 * ETAMP(id) is masked and internally cleared by
			 * hardware.
			 * The secrets are not erased.
			 */
			*ier &= ~_TAMP_IER_ETAMP(id);
			*cr2 |= _TAMP_CR2_ETAMPMSK(id);
		} else {
			/*
			 * normal ETAMP interrupt:
			 * ETAMP(id) event generates a trigger event and
			 * TAMP(id) must be cleared by software to allow
			 * next tamper event detection.
			 */
			*ier |= _TAMP_IER_ETAMP(id);
			*cr2 &= ~_TAMP_CR2_ETAMPMSK(id);
		}
	} else {
		/* Other than 1,2,3 external TAMP, we want its interrupt */
		*ier |= _TAMP_IER_ETAMP(id);
	}

	DMSG("EXT_TAMP%d enabled as a %s %s tamper trig_%s%s",
	     id - EXT_TAMP1 + 1,
	     (tamp_ext->mode & TAMP_ACTIVE) ? "active" : "passive",
	     (tamp_ext->mode & TAMP_NOERASE) ? "potential" : "full",
	     (tamp_ext->mode & TAMP_TRIG_ON) ? "on" : "off",
	     (tamp_ext->mode & TAMP_EVT_MASK) ? " (masked)" : "");

	if (tamp_ext->mode & TAMP_ACTIVE)
		DMSG("   linked with OUT_TAMP%d",
		     tamp_ext->out_id - OUT_TAMP1 + 1);

	return TEE_SUCCESS;
}

static void parse_bkpregs_dt_conf(struct stm32_tamp_platdata *pdata,
				  const void *fdt, int node)
{
	const fdt32_t *cuint = NULL;
	unsigned int bkpregs_count = 0;
	int lenp = 0;

	cuint = fdt_getprop(fdt, node, "st,backup-zones", &lenp);
	if (!cuint) {
		IMSG("Default configuration for backup registers");
		return;
	}

	pdata->bkpregs_conf = calloc(1, sizeof(*pdata->bkpregs_conf));
	if (!pdata->bkpregs_conf)
		panic("No memory available for backup registers RIF config");

	/*
	 * When TAMP does not support RIF, the backup registers can
	 * be splited in 3 zones. These zones have specific read/write
	 * access permissions based on the secure status of the accesser.
	 * When RIF is supported, these zones can additionally be splited
	 * in subzones that have CID filtering. Zones/Subzones can be empty and
	 * are contiguous.
	 */
	if (!(pdata->compat->tags & TAMP_HAS_RIF_SUPPORT)) {
		/* 3 zones, 2 offsets to apply */
		if (lenp != sizeof(uint32_t) * 3)
			panic("Incorrect bkpregs configuration");

		pdata->bkpregs_conf->nb_zone1_regs = fdt32_to_cpu(cuint[0]);
		bkpregs_count = fdt32_to_cpu(cuint[0]);

		pdata->bkpregs_conf->nb_zone2_regs = bkpregs_count +
						     fdt32_to_cpu(cuint[1]);
	} else {
		/*
		 * Zone 3
		 * ----------------------|
		 * Protection Zone 3-RIF2|Read non-
		 * ----------------------|secure
		 * Protection Zone 3-RIF0|Write non-
		 * ----------------------|secure
		 * Protection Zone 3-RIF1|
		 * ----------------------|
		 *
		 * Zone 2
		 * ----------------------|
		 * Protection Zone 2-RIF2|Read non-
		 * ----------------------|secure
		 * Protection Zone 2-RIF1|Write secure
		 * ----------------------|
		 *
		 * Zone 1
		 * ----------------------|
		 * Protection Zone 1-RIF2|Read secure
		 * ----------------------|Write secure
		 * Protection Zone 1-RIF1|
		 * ----------------------|
		 *
		 * (BHK => First 8 registers)
		 */
		pdata->bkpregs_conf->rif_offsets = calloc(4, sizeof(uint32_t));
		if (!pdata->bkpregs_conf->rif_offsets)
			panic();

		/*
		 * 3 zones with 7 subzones in total(6 offsets):
		 * - 2 zone offsets
		 * - 4 subzones offsets
		 */
		if (lenp != sizeof(uint32_t) * 7)
			panic("Incorrect bkpregs configuration");

		/* Backup registers zone 1 */
		pdata->bkpregs_conf->rif_offsets[0] = fdt32_to_cpu(cuint[0]);
		pdata->bkpregs_conf->nb_zone1_regs = fdt32_to_cpu(cuint[0]) +
						     fdt32_to_cpu(cuint[1]);

		bkpregs_count = pdata->bkpregs_conf->nb_zone1_regs;

		/* Backup registers zone 2 */
		pdata->bkpregs_conf->rif_offsets[1] = bkpregs_count +
						      fdt32_to_cpu(cuint[2]);
		pdata->bkpregs_conf->nb_zone2_regs = bkpregs_count +
						     fdt32_to_cpu(cuint[2]) +
						     fdt32_to_cpu(cuint[3]);

		bkpregs_count = pdata->bkpregs_conf->nb_zone2_regs;

		/* Backup registers zone 3 */
		pdata->bkpregs_conf->rif_offsets[2] = bkpregs_count +
						      fdt32_to_cpu(cuint[4]);
		pdata->bkpregs_conf->rif_offsets[3] = bkpregs_count +
						      fdt32_to_cpu(cuint[4]) +
						      fdt32_to_cpu(cuint[5]);
	}
}

/*
 * stm32_tamp_set_secure_bkprwregs: Configure backup registers zone.
 * registers in zone 1: read/write only in secure mode
 *              zone 2: write only in secure mode, read in secure and
 *                       non-secure mode
 *              zone 3: read/write in secure and non-secure mode
 *
 * return TEE_ERROR_NOT_SUPPORTED:  if zone 1 and/or zone 2 definition are out
 *                                  of range.
 *        TEE_ERROR_BAD_PARAMETERS: if bkpregs_cond is NULL.
 *        TEE_SUCCESS             : if OK.
 */
static TEE_Result stm32_tamp_set_secure_bkpregs(void)
{
	struct stm32_bkpregs_conf *bkpregs_conf =
			stm32_tamp.pdata.bkpregs_conf;
	uint32_t first_z2 = 0;
	uint32_t first_z3 = 0;
	vaddr_t base = io_pa_or_va(&stm32_tamp.pdata.base, 1);

	if (!bkpregs_conf)
		return TEE_ERROR_BAD_PARAMETERS;

	first_z2 = bkpregs_conf->nb_zone1_regs;
	first_z3 = bkpregs_conf->nb_zone2_regs;

	if ((first_z2 > (stm32_tamp.hwconf1 & _TAMP_HWCFGR1_BKPREG)) ||
	    (first_z3 > (stm32_tamp.hwconf1 & _TAMP_HWCFGR1_BKPREG)))
		return TEE_ERROR_BAD_PARAMETERS;

	if (stm32_tamp.pdata.compat &&
	    (stm32_tamp.pdata.compat->tags & TAMP_HAS_REGISTER_SECCFGR)) {
		io_clrsetbits32(base + _TAMP_SECCFGR,
				_TAMP_SECCFGR_BKPRWSEC_MASK,
				(first_z2 << _TAMP_SECCFGR_BKPRWSEC_SHIFT) &
				_TAMP_SECCFGR_BKPRWSEC_MASK);

		io_clrsetbits32(base + _TAMP_SECCFGR,
				_TAMP_SECCFGR_BKPWSEC_MASK,
				(first_z3 << _TAMP_SECCFGR_BKPWSEC_SHIFT) &
				_TAMP_SECCFGR_BKPWSEC_MASK);
	} else {
		io_clrsetbits32(base + _TAMP_SMCR,
				_TAMP_SMCR_BKPRWDPROT_MASK,
				(first_z2 << _TAMP_SMCR_BKPRWDPROT_SHIFT) &
				_TAMP_SMCR_BKPRWDPROT_MASK);

		io_clrsetbits32(base + _TAMP_SMCR,
				_TAMP_SMCR_BKPWDPROT_MASK,
				(first_z3 << _TAMP_SMCR_BKPWDPROT_SHIFT) &
				_TAMP_SMCR_BKPWDPROT_MASK);
	}

	return TEE_SUCCESS;
}

/*
 * Count number of 1 in bitmask
 * Cannot use __builtin_popcount(): libgcc.a for ARMV7 use hardfloat ABI,
 * but optee is compiled with softfloat ABI.
 */
static int popcount(uint32_t bitmask)
{
	int nb = 0;

	while (bitmask) {
		if (bitmask & 1)
			nb++;
		bitmask >>= 1;
	}

	return nb;
}

static void stm32_tamp_set_atper(uint32_t pins_out_bits, uint32_t *atcr1)
{
	uint32_t conf = 0;

	switch (popcount(pins_out_bits)) {
	case 0:
		fallthrough;
	case 1:
		conf = 0;
		break;
	case 2:
		conf = 1;
		break;
	case 3:
		fallthrough;
	case 4:
		conf = 2;
		break;
	default:
		conf = 3;
		break;
	}

	*atcr1 |= (conf << _TAMP_ATCR1_ATPER_SHIFT) & _TAMP_ATCR1_ATPER_MASK;
}

TEE_Result stm32_tamp_set_config(void)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t i = 0;
	uint32_t cr1 = 0;
	uint32_t cr2 = 0;
	uint32_t cr3 = 0;
	uint32_t atcr1 = 0;
	uint32_t atcr2 = 0;
	uint32_t fltcr = 0;
	uint32_t ier = 0;

	vaddr_t base = io_pa_or_va(&stm32_tamp.pdata.base, 1);

	if (!stm32_tamp.pdata.compat ||
	    !stm32_tamp.pdata.compat->int_tamp ||
	    !stm32_tamp.pdata.compat->ext_tamp)
		return TEE_ERROR_BAD_STATE;

	/* Set passive filter configuration */
	fltcr = stm32_tamp.pdata.passive_conf;

	/* Set active mode configuration */
	atcr1 = stm32_tamp.pdata.active_conf & _TAMP_ATCR1_COMMON_MASK;
	stm32_tamp_set_atper(stm32_tamp.pdata.out_pins, &atcr1);

	for (i = 0U; i < stm32_tamp.pdata.compat->int_tamp_size; i++) {
		ret = stm32_tamp_set_int_config(stm32_tamp.pdata.compat, i,
						&cr1, &cr3, &ier);
		if (ret)
			return ret;
	}

	for (i = 0U; i < stm32_tamp.pdata.compat->ext_tamp_size; i++) {
		ret = stm32_tamp_set_ext_config(stm32_tamp.pdata.compat, i,
						&cr1, &cr2, &atcr1, &atcr2,
						&ier);
		if (ret)
			return ret;
	}

	/*
	 * We apply configuration all in a row:
	 * As for active ext tamper "all the needed tampers must be enabled in
	 * the same write access".
	 */
	io_write32(base + _TAMP_FLTCR, fltcr);
	FMSG("Set passive conf %08x", fltcr);

	/* Active configuration applied only if not already done. */
	if (((io_read32(base + _TAMP_ATOR) & _TAMP_INITS) != _TAMP_INITS)) {
		io_write32(base + _TAMP_ATCR1, atcr1);
		FMSG("Set active conf1 %08x", atcr1);

		if (stm32_tamp.pdata.compat->tags & TAMP_HAS_REGISTER_ATCR2) {
			io_write32(base + _TAMP_ATCR2, atcr2);
			FMSG("Set active conf2 %08x", atcr2);
		}
	}

	io_write32(base + _TAMP_CR1, cr1);
	io_write32(base + _TAMP_CR2, cr2);
	if (stm32_tamp.pdata.compat->tags & TAMP_HAS_REGISTER_CR3)
		io_write32(base + _TAMP_CR3, cr3);

	/* If active tamper we reinit the seed. */
	if (stm32_tamp.pdata.active_conf) {
		if (stm32_tamp_set_seed(base) != TEE_SUCCESS) {
			EMSG("Active tamper: SEED not initialized");
			return TEE_ERROR_BAD_STATE;
		}
	}

	/*
	 * We installed callback,
	 * we force managing TAMPER events that could have occurred while boot.
	 */
	stm32_tamp_it_handler(stm32_tamp.itr);

	/* Enable interrupts. */
	io_write32(base + _TAMP_IER, ier);

	return TEE_SUCCESS;
}

/*
 * If ETAMP(id) event generates a trigger event, this
 * ETAMP(id) is masked and internally cleared by hardware.
 * The secrets are not erased.
 */
TEE_Result stm32_tamp_set_mask(enum stm32_tamp_id id)
{
	vaddr_t base = io_pa_or_va(&stm32_tamp.pdata.base, 1);

	/* Only EXT_TAMP1, EXT_TAMP2, EXT_TAMP3 can be masked. */
	if (id < EXT_TAMP1 || id > (EXT_TAMP1 + _TAMP_CR2_ETAMPMSK_MAX_ID))
		return TEE_ERROR_BAD_PARAMETERS;

	/* We cannot mask the event if pending. */
	if (io_read32(base + _TAMP_SR) & _TAMP_SR_ETAMP(id))
		return TEE_ERROR_BAD_STATE;

	/* We disable the IT */
	io_clrbits32(base + _TAMP_IER, _TAMP_IER_ETAMP(id));
	/* We mask the event */
	io_setbits32(base + _TAMP_CR2, _TAMP_CR2_ETAMPMSK(id));

	return TEE_SUCCESS;
}

/*
 * Move to a normal ETAMP interrupt:
 * ETAMP(id) event generates a trigger event and
 * ETAMP(id) must be cleared by software to allow
 * next tamper event detection.
 */
TEE_Result stm32_tamp_unset_mask(enum stm32_tamp_id id)
{
	vaddr_t base = io_pa_or_va(&stm32_tamp.pdata.base, 1);

	/* Only EXT_TAMP1, EXT_TAMP2, EXT_TAMP3 can be masked. */
	if (id < EXT_TAMP1 || id > (EXT_TAMP1 + _TAMP_CR2_ETAMPMSK_MAX_ID))
		return TEE_ERROR_BAD_PARAMETERS;

	/* We unmask the event */
	io_clrbits32(base + _TAMP_CR2, _TAMP_CR2_ETAMPMSK(id));
	/* We enable the IT */
	io_setbits32(base + _TAMP_IER, _TAMP_IER_ETAMP(id));

	return TEE_SUCCESS;
}

TEE_Result stm32_tamp_write_mcounter(int cnt_idx)
{
	vaddr_t base = io_pa_or_va(&stm32_tamp.pdata.base, 1);

	if (cnt_idx < 0 || !stm32_tamp.pdata.compat ||
	    cnt_idx > stm32_tamp.pdata.compat->nb_monotonic_counter)
		return TEE_ERROR_BAD_PARAMETERS;

	io_write32(base + _TAMP_COUNTR + cnt_idx * sizeof(uint32_t), 1U);

	return TEE_SUCCESS;
}

uint32_t stm32_tamp_read_mcounter(int cnt_idx)
{
	vaddr_t base = io_pa_or_va(&stm32_tamp.pdata.base, 1);

	if (cnt_idx < 0 || !stm32_tamp.pdata.compat ||
	    cnt_idx > stm32_tamp.pdata.compat->nb_monotonic_counter)
		return 0U;

	return io_read32(base + _TAMP_COUNTR + cnt_idx * sizeof(uint32_t));
}

static TEE_Result stm32_tamp_configure_int(struct stm32_tamp_conf *tamp_int,
					   uint32_t mode,
					   uint32_t (*cb)(int id))
{
	if (mode & TAMP_EVT_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	tamp_int->mode |= (mode & TAMP_MODE_MASK);
	tamp_int->func = cb;

	return TEE_SUCCESS;
}

static TEE_Result stm32_tamp_configure_ext(struct stm32_tamp_conf *tamp_ext,
					   uint32_t mode,
					   uint32_t (*cb)(int id))
{
	enum stm32_tamp_id id = tamp_ext->id;

	if (mode & TAMP_EVT_MASK &&
	    (id < EXT_TAMP1 || id > (EXT_TAMP1 + _TAMP_CR2_ETAMPMSK_MAX_ID)))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!(tamp_ext->mode & TAMP_IN_DT))
		return TEE_ERROR_ITEM_NOT_FOUND;

	tamp_ext->mode |= (mode & TAMP_MODE_MASK);
	tamp_ext->func = cb;

	return TEE_SUCCESS;
}

TEE_Result stm32_tamp_activate_tamp(enum stm32_tamp_id id, uint32_t mode,
				    uint32_t (*cb)(int id))
{
	size_t i = 0;
	struct stm32_tamp_conf *tamp_conf = NULL;

	if (!stm32_tamp.pdata.compat)
		return TEE_ERROR_BAD_STATE;

	if (!cb)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Find internal Tamp struct */
	for (i = 0U; i < stm32_tamp.pdata.compat->int_tamp_size; i++)
		if (stm32_tamp.pdata.compat->int_tamp[i].id == id) {
			tamp_conf = &stm32_tamp.pdata.compat->int_tamp[i];
			return stm32_tamp_configure_int(tamp_conf, mode, cb);
		}

	/* Find external Tamp struct */
	for (i = 0U; i < stm32_tamp.pdata.compat->ext_tamp_size; i++)
		if (stm32_tamp.pdata.compat->ext_tamp[i].id == id) {
			tamp_conf = &stm32_tamp.pdata.compat->ext_tamp[i];
			return stm32_tamp_configure_ext(tamp_conf, mode, cb);
		}

	return TEE_ERROR_BAD_PARAMETERS;
}

bool stm32_tamp_are_secrets_blocked(void)
{
	if (stm32_tamp.pdata.compat &&
	    (stm32_tamp.pdata.compat->tags & TAMP_HAS_CR2_SECRET_STATUS)) {
		vaddr_t base = io_pa_or_va(&stm32_tamp.pdata.base, 1);

		return (((io_read32(base + _TAMP_CR2) &
			  _TAMP_CR2_BKBLOCK) == _TAMP_CR2_BKBLOCK) ||
			io_read32(base + _TAMP_SR));
	} else {
		return false;
	}
}

void stm32_tamp_block_secrets(void)
{
	vaddr_t base = io_pa_or_va(&stm32_tamp.pdata.base, 1);

	if (stm32_tamp.pdata.compat &&
	    (stm32_tamp.pdata.compat->tags & TAMP_HAS_CR2_SECRET_STATUS))
		io_setbits32(base + _TAMP_CR2, _TAMP_CR2_BKBLOCK);
}

void stm32_tamp_unblock_secrets(void)
{
	vaddr_t base = io_pa_or_va(&stm32_tamp.pdata.base, 1);

	if (stm32_tamp.pdata.compat &&
	    (stm32_tamp.pdata.compat->tags & TAMP_HAS_CR2_SECRET_STATUS))
		io_clrbits32(base + _TAMP_CR2, _TAMP_CR2_BKBLOCK);
}

void stm32_tamp_erase_secrets(void)
{
	vaddr_t base = io_pa_or_va(&stm32_tamp.pdata.base, 1);

	if (stm32_tamp.pdata.compat &&
	    (stm32_tamp.pdata.compat->tags & TAMP_HAS_CR2_SECRET_STATUS))
		io_setbits32(base + _TAMP_CR2, _TAMP_CR2_BKERASE);
}

void stm32_tamp_lock_boot_hardware_key(void)
{
	vaddr_t base = io_pa_or_va(&stm32_tamp.pdata.base, 1);

	if (stm32_tamp.pdata.compat &&
	    (stm32_tamp.pdata.compat->tags & TAMP_HAS_REGISTER_SECCFGR))
		io_setbits32(base + _TAMP_SECCFGR, _TAMP_SECCFGR_BHKLOCK);
}

static enum itr_return stm32_tamp_it_handler(struct itr_handler *h)
{
	struct stm32_tamp_instance *tamp = h->data;
	vaddr_t base = io_pa_or_va(&tamp->pdata.base, 1);
	uint32_t it = io_read32(base + _TAMP_SR);
	uint32_t int_it = it & _TAMP_SR_ITAMPXF_MASK;
	uint32_t ext_it = it & _TAMP_SR_ETAMPXF_MASK;
	size_t i = 0;
	struct stm32_rtc_time tamp_ts = { };
	bool ts_enabled = false;

	if (stm32_rtc_is_timestamp_enable(&ts_enabled))
		panic();

	if (ts_enabled && it) {
		stm32_rtc_get_timestamp(&tamp_ts);
		FMSG("Tamper Event Occurred");
		FMSG("Date: %u/%u\n \t Time: %u:%u:%u",
		     tamp_ts.day, tamp_ts.month, tamp_ts.hour,
		     tamp_ts.min, tamp_ts.sec);
	}

	while (int_it && i < stm32_tamp.pdata.compat->int_tamp_size) {
		uint32_t id = tamp->pdata.compat->int_tamp[i].id;

		if (int_it & _TAMP_SR_ITAMP(id)) {
			uint32_t ret = 0;

			int_it &= ~_TAMP_SR_ITAMP(id);

			if (tamp->pdata.compat->int_tamp[i].func)
				ret = tamp->pdata.compat->int_tamp[i].func(id);

			if (ret & TAMP_CB_ACK)
				io_setbits32(base + _TAMP_SCR,
					     _TAMP_SCR_ITAMP(id));

#ifndef CFG_STM32MP25
			if (ret & TAMP_CB_RESET)
				psci_system_reset();
#endif
		}
		i++;
	}

	i = 0;
	/* External tamper interrupt */
	while (ext_it && i < stm32_tamp.pdata.compat->ext_tamp_size) {
		uint32_t id = tamp->pdata.compat->ext_tamp[i].id;

		if (ext_it & _TAMP_SR_ETAMP(id)) {
			uint32_t ret = 0;

			ext_it &= ~_TAMP_SR_ETAMP(id);

			if (tamp->pdata.compat->ext_tamp[i].func)
				ret = tamp->pdata.compat->ext_tamp[i].func(id);

			if (ret & TAMP_CB_ACK)
				io_setbits32(base + _TAMP_SCR,
					     _TAMP_SCR_ETAMP(id));

#ifndef CFG_STM32MP25
			if (ret & TAMP_CB_RESET)
				psci_system_reset();
#endif
		}
		i++;
	}

	return ITRR_HANDLED;
}

#ifdef CFG_EMBED_DTB
static void stm32_tamp_configure_pin(uint32_t id,
				     struct stm32_pinctrl *pinctrl, bool out,
				     struct stm32_tamp_platdata *pdata)
{
	size_t i = 0;
	struct stm32_tamp_compat *compat = pdata->compat;

	if (!compat)
		return;

	/* Configure option registers */
	for (i = 0U; i < compat->pin_map_size; i++)
		if (id == compat->pin_map[i].id &&
		    pinctrl->bank == compat->pin_map[i].bank &&
		    pinctrl->pin == compat->pin_map[i].pin &&
		    !out == !compat->pin_map[i].out) {
			pdata->pins_conf |= compat->pin_map[i].conf;
			break;
		}

	/* TAMPER pins are always secure (without effect, but keep coherency) */
	if (stm32_gpio_set_secure_cfg(pinctrl->bank, pinctrl->pin, true))
		panic();
}

static
TEE_Result stm32_tamp_configure_pin_from_dt(const void *fdt, int node,
					    struct stm32_tamp_platdata *pdata)
{
	TEE_Result res = TEE_SUCCESS;
	struct stm32_pinctrl *pinctrl[2] = { };
	struct stm32_pinctrl_list *pinctrl_list = NULL;
	size_t i = 0U;
	enum stm32_tamp_id id = INVALID_TAMP;
	enum stm32_tamp_out_id out_id = INVALID_OUT_TAMP;
	struct stm32_tamp_conf *tamp_ext = NULL;
	const fdt32_t *cuint = NULL;
	const fdt32_t *tampid = NULL;
	int lenp = 0;
	int pinnode = -1;
	bool active = false;

	if (_fdt_get_status(fdt, node) == DT_STATUS_DISABLED)
		return 0;

	/*
	 * First pin in the "pinctrl-0" node is the EXT_TAMP.
	 * If two pins are defined, first is a pin for an active tamper and the
	 * second is the OUT pin linked with the first.
	 * If only one found, this is a pin for a passive tamper.
	 */
	res = stm32_pinctrl_dt_get_by_index(fdt, node, 0, &pinctrl_list);
	if (res)
		return res;

	pinctrl[0] = STAILQ_FIRST(pinctrl_list);
	pinctrl[1] = STAILQ_NEXT(pinctrl[0], link);

	cuint = fdt_getprop(fdt, node, "pinctrl-0", &lenp);
	if (!pinctrl[0] || !cuint || (pinctrl[1] &&
				      (lenp / sizeof(*cuint)) < 2))
		return TEE_ERROR_BAD_PARAMETERS;

	if (pinctrl[1]) {
		pinnode = fdt_node_offset_by_phandle(fdt,
						     fdt32_to_cpu(cuint[1]));
		tampid = fdt_getprop(fdt, fdt_first_subnode(fdt, pinnode),
				     "st,tamp_id", NULL);
		if (!tampid)
			return TEE_ERROR_BAD_PARAMETERS;

		active = true;
		out_id = OUT_TAMP1 + fdt32_to_cpu(*tampid) - 1;
		if (out_id - OUT_TAMP1 > pdata->compat->ext_tamp_size)
			return TEE_ERROR_BAD_PARAMETERS;

		stm32_tamp_configure_pin(out_id, pinctrl[1], true, pdata);
	}

	/* We now configure first pin */
	pinnode = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(cuint[0]));
	tampid = fdt_getprop(fdt, fdt_first_subnode(fdt, pinnode),
			     "st,tamp_id", NULL);
	if (!tampid)
		return TEE_ERROR_BAD_PARAMETERS;

	id = fdt32_to_cpu(*tampid) + EXT_TAMP1 - 1;

	/* Find external Tamp struct */
	for (i = 0U; i < pdata->compat->ext_tamp_size; i++) {
		if (pdata->compat->ext_tamp[i].id == id) {
			tamp_ext = &pdata->compat->ext_tamp[i];
			break;
		}
	}

	if (!tamp_ext)
		return TEE_ERROR_BAD_PARAMETERS;

	if (active) {
		tamp_ext->mode |= TAMP_ACTIVE;
		tamp_ext->out_id = out_id;
		pdata->out_pins |= BIT(tamp_ext->out_id - OUT_TAMP1);

		if (out_id - OUT_TAMP1 != id - EXT_TAMP1)
			pdata->active_conf |= _TAMP_ATCR1_ATOSHARE;
	} else {
		if (fdt_getprop(fdt, node, "st,trig_on", NULL))
			tamp_ext->mode |= TAMP_TRIG_ON;
	}

	tamp_ext->mode |= TAMP_IN_DT;

	stm32_tamp_configure_pin(id, pinctrl[0], false, pdata);

	return TEE_SUCCESS;
}

static int stm32_tamp_parse_passive_conf(const void *fdt, int node,
					 struct stm32_tamp_platdata *pdata)
{
	const fdt32_t *cuint = NULL;
	uint32_t precharge = 0U;
	uint32_t nb_sample = 0U;
	uint32_t clk_div = 32768U;
	uint32_t conf = 0U;

	cuint = fdt_getprop(fdt, node, "st,tamp_passive_precharge", NULL);
	if (cuint)
		precharge = fdt32_to_cpu(*cuint);

	cuint = fdt_getprop(fdt, node, "st,tamp_passive_nb_sample", NULL);
	if (cuint)
		nb_sample = fdt32_to_cpu(*cuint);

	cuint = fdt_getprop(fdt, node, "st,tamp_passive_sample_clk_div", NULL);
	if (cuint)
		clk_div = fdt32_to_cpu(*cuint);

	DMSG("Passive conf from dt: precharge=%"PRId32", nb_sample=%"PRId32
	     ", clk_div=%"PRId32, precharge, nb_sample, clk_div);

	switch (precharge) {
	case 0:
		/* No precharge, => we disable the pull-up */
		conf |= _TAMP_FLTCR_TAMPPUDIS;
		break;
	case 1:
		/* Precharge for one cycle value stay 0 */
		break;
	case 2:
		/* Precharge passive pin 2 cycles */
		conf |= 1 << _TAMP_FLTCR_TAMPPRCH_SHIFT;
		break;
	case 4:
		/* Precharge passive pin 4 cycles */
		conf |= 2 << _TAMP_FLTCR_TAMPPRCH_SHIFT;
		break;
	case 8:
		/* Precharge passive pin 8 cycles */
		conf |= 3 << _TAMP_FLTCR_TAMPPRCH_SHIFT;
		break;
	default:
		return -1;
	}

	switch (nb_sample) {
	case 0:
		/* Activation on edge, no pull-up: value stay 0 */
		break;
	case 2:
		/*
		 * Tamper event is activated after 2 consecutive samples at
		 * active level.
		 */
		conf |= 1 << _TAMP_FLTCR_TAMPFLT_SHIFT;
		break;
	case 4:
		/*
		 * Tamper event is activated after 4 consecutive samples at
		 * active level.
		 */
		conf |= 2 << _TAMP_FLTCR_TAMPFLT_SHIFT;
		break;
	case 8:
		/*
		 * Tamper event is activated after 8 consecutive samples at
		 * active level.
		 */
		conf |= 3 << _TAMP_FLTCR_TAMPFLT_SHIFT;
		break;
	default:
		return -1;
	}

	switch (clk_div) {
	case 32768:
		/* RTCCLK / 32768 (1 Hz when RTCCLK = 32768 Hz): stay 0 */
		break;
	case 16384:
		/* RTCCLK / 16384 (2 Hz when RTCCLK = 32768 Hz) */
		conf |= 1 << _TAMP_FLTCR_TAMPFREQ_SHIFT;
		break;
	case 8192:
		/* RTCCLK / 8192  (4 Hz when RTCCLK = 32768 Hz) */
		conf |= 2 << _TAMP_FLTCR_TAMPFREQ_SHIFT;
		break;
	case 4096:
		/* RTCCLK / 4096  (8 Hz when RTCCLK = 32768 Hz) */
		conf |= 3 << _TAMP_FLTCR_TAMPFREQ_SHIFT;
		break;
	case 2048:
		/* RTCCLK / 2048  (16 Hz when RTCCLK = 32768 Hz) */
		conf |= 4 << _TAMP_FLTCR_TAMPFREQ_SHIFT;
		break;
	case 1024:
		/* RTCCLK / 1024  (32 Hz when RTCCLK = 32768 Hz) */
		conf |= 5 << _TAMP_FLTCR_TAMPFREQ_SHIFT;
		break;
	case 512:
		/* RTCCLK / 512   (64 Hz when RTCCLK = 32768 Hz) */
		conf |= 6 << _TAMP_FLTCR_TAMPFREQ_SHIFT;
		break;
	case 256:
		/* RTCCLK / 256   (128 Hz when RTCCLK = 32768 Hz) */
		conf |= 7 << _TAMP_FLTCR_TAMPFREQ_SHIFT;
		break;
	default:
		return -1;
	}

	pdata->passive_conf = conf;

	return 0;
}

static int stm32_tamp_parse_active_conf(const void *fdt, int node,
					struct stm32_tamp_platdata *pdata)
{
	const fdt32_t *cuint = NULL;
	uint32_t clk_div = 1U;
	uint32_t conf = 0U;

	cuint = fdt_getprop(fdt, node, "st,tamp_active_filter", NULL);
	if (cuint)
		conf |= _TAMP_ATCR1_FLTEN;

	/*
	 * Here we will select a divisor for the RTCCLK.
	 * Note that RTCCLK is also divided by (RTC_PRER_PREDIV_A - 1).
	 */
	cuint = fdt_getprop(fdt, node, "st,tamp_active_clk_div", NULL);
	if (cuint)
		clk_div = fdt32_to_cpu(*cuint);

	DMSG("Active conf from dt: %s clk_div=%"PRId32,
	     (conf & _TAMP_ATCR1_FLTEN) ? "filter" : "no filter", clk_div);

	switch (clk_div) {
	case 1:
		/* RTCCLK / 32768 (1 Hz when RTCCLK = 32768 Hz): stay 0 */
		break;
	case 2:
		/* RTCCLK / 16384 (2 Hz when RTCCLK = 32768 Hz) */
		conf |= 1 << _TAMP_ATCR1_ATCKSEL_SHIFT;
		break;
	case 4:
		/* RTCCLK / 8192  (4 Hz when RTCCLK = 32768 Hz) */
		conf |= 2 << _TAMP_ATCR1_ATCKSEL_SHIFT;
		break;
	case 8:
		/* RTCCLK / 4096  (8 Hz when RTCCLK = 32768 Hz) */
		conf |= 3 << _TAMP_ATCR1_ATCKSEL_SHIFT;
		break;
	case 16:
		/* RTCCLK / 2048  (16 Hz when RTCCLK = 32768 Hz) */
		conf |= 4 << _TAMP_ATCR1_ATCKSEL_SHIFT;
		break;
	case 32:
		/* RTCCLK / 1024  (32 Hz when RTCCLK = 32768 Hz) */
		conf |= 5 << _TAMP_ATCR1_ATCKSEL_SHIFT;
		break;
	case 64:
		/* RTCCLK / 512   (64 Hz when RTCCLK = 32768 Hz) */
		conf |= 6 << _TAMP_ATCR1_ATCKSEL_SHIFT;
		break;
	case 128:
		/* RTCCLK / 256   (128 Hz when RTCCLK = 32768 Hz) */
		conf |= 7 << _TAMP_ATCR1_ATCKSEL_SHIFT;
		break;
	case 2048:
		if (pdata->compat &&
		    (pdata->compat->tags & TAMP_SIZE_ATCR1_ATCKSEL_IS_4)){
			/* RTCCLK/2048 when (PREDIV_A+1) = 128 and (PREDIV_S+1)
			 * is a multiple of 16. */
			conf |=  11 << _TAMP_ATCR1_ATCKSEL_SHIFT;
			break;
		}

		return -1;
	default:
		return -1;
	}

	pdata->active_conf = conf;

	return 0;
}

static TEE_Result stm32_tamp_parse_fdt(struct stm32_tamp_platdata *pdata,
				       const void *fdt, int node,
				       const void *compat)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int pinnode = -FDT_ERR_NOTFOUND;
	int subnode = -FDT_ERR_NOTFOUND;
	struct dt_node_info dt_tamp = {};
	bool __unused is_tdcid = false;

	_fdt_fill_device_info(fdt, &dt_tamp, node);

	if (dt_tamp.reg == DT_INFO_INVALID_REG ||
	    dt_tamp.reg_size == DT_INFO_INVALID_REG_SIZE ||
	    dt_tamp.interrupt == DT_INFO_INVALID_INTERRUPT) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	pdata->compat = (struct stm32_tamp_compat *)compat;

	if (stm32_tamp.pdata.compat->tags & TAMP_HAS_RIF_SUPPORT) {
		res = stm32_rifsc_check_tdcid(&is_tdcid);
		if (res)
			return res;
	}

	pdata->it = dt_tamp.interrupt;
	pdata->base.pa = dt_tamp.reg;
	io_pa_or_va_secure(&pdata->base, dt_tamp.reg_size);

	res = clk_dt_get_by_index(fdt, node, 0, &pdata->clock);
	if (res)
		return res;

	pdata->pins_conf = 0;

	stm32_tamp_parse_passive_conf(fdt, node, pdata);
	stm32_tamp_parse_active_conf(fdt, node, pdata);

	fdt_for_each_subnode(subnode, fdt, node) {
		if (fdt_getprop(fdt, node, "pinctrl-0", NULL)) {
			res = stm32_tamp_configure_pin_from_dt(fdt, subnode,
							       pdata);
			if (res)
				return res;
			pinnode = subnode;
		}
	}

	if (pinnode < 0 && pinnode != -FDT_ERR_NOTFOUND)
		return TEE_ERROR_BAD_PARAMETERS;

	if (fdt_getprop(fdt, node, "wakeup-source", NULL))
		pdata->is_wakeup_source = true;

	if (pdata->compat->tags & TAMP_HAS_RIF_SUPPORT) {
		const fdt32_t *cuint = NULL;
		uint32_t rif_conf = 0;
		unsigned int i = 0;
		int lenp = 0;

		cuint = fdt_getprop(fdt, node, "st,protreg", &lenp);
		if (!cuint)
			panic("No RIF configuration available");

		pdata->nb_resources = (unsigned int)(lenp / sizeof(uint32_t));
		assert(pdata->nb_resources <= TAMP_RIF_RESOURCES);

		pdata->conf_data.cid_confs = calloc(TAMP_RIF_RESOURCES,
						    sizeof(uint32_t));
		pdata->conf_data.sec_conf = calloc(1, sizeof(uint32_t));
		pdata->conf_data.priv_conf = calloc(1, sizeof(uint32_t));
		pdata->conf_data.access_mask = calloc(1, sizeof(uint32_t));
		if (!pdata->conf_data.cid_confs || !pdata->conf_data.sec_conf ||
		    !pdata->conf_data.priv_conf ||
		    !pdata->conf_data.access_mask)
			panic("Not enough memory capacity for TAMP RIF config");

		for (i = 0; i < pdata->nb_resources; i++) {
			rif_conf = fdt32_to_cpu(cuint[i]);

			stm32_rif_parse_cfg(rif_conf, &pdata->conf_data,
					    TAMP_NB_MAX_CID_SUPPORTED,
					    TAMP_RIF_RESOURCES);
		}
	}

	parse_bkpregs_dt_conf(pdata, fdt, node);

	if (pdata->is_wakeup_source && IS_ENABLED(CFG_STM32_EXTI)) {
		pdata->exti =
			dt_driver_device_from_node_idx_prop("wakeup-parent",
							    fdt, node, 0,
							    DT_DRIVER_NOTYPE,
							    &res);
		if (res == TEE_ERROR_DEFER_DRIVER_INIT)
			return TEE_ERROR_DEFER_DRIVER_INIT;
		if (res)
			panic("DT property 'wakeup-source' requires 'wakeup-parent'");
	}

	return TEE_SUCCESS;
}

__weak
TEE_Result stm32_tamp_get_platdata(struct stm32_tamp_platdata *pdata __unused)
{
	/* In DT config, the platform data are filled by DT file */
	return TEE_SUCCESS;
}
#else /* CFG_EMBED_DTB */
static
TEE_Result stm32_tamp_parse_fdt(struct stm32_tamp_platdata *pdata,
				const void *fdt, int node, const void *compat)
{
	/* Do nothing, there is no fdt to parse in this case */
	return TEE_SUCCESS;
}

/* This function can be overridden by platform to define pdata of tamp driver */
__weak
TEE_Result stm32_tamp_get_platdata(struct stm32_tamp_platdata *pdata __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /* CFG_EMBED_DTB */

static TEE_Result stm32_tamp_probe(const void *fdt, int node,
				   const void *compat_data)
{
	uint32_t __maybe_unused revision = 0;
	TEE_Result res = TEE_SUCCESS;
	vaddr_t base = 0;
	int subnode = -FDT_ERR_NOTFOUND;

	res = stm32_tamp_get_platdata(&stm32_tamp.pdata);
	if (res)
		return res;

	res = stm32_tamp_parse_fdt(&stm32_tamp.pdata, fdt, node, compat_data);
	if (res)
		return res;

	/* Init Tamp clock */
	clk_enable(stm32_tamp.pdata.clock);

	base = io_pa_or_va(&stm32_tamp.pdata.base, 1);

	stm32_tamp.hwconf1 = io_read32(base + _TAMP_HWCFGR1);
	stm32_tamp.hwconf2 = io_read32(base + _TAMP_HWCFGR2);

	revision = io_read32(base + _TAMP_VERR);
	FMSG("STM32 TAMPER V%"PRIx32".%"PRIu32,
	     (revision & _TAMP_VERR_MAJREV) >> 4, revision & _TAMP_VERR_MINREV);

	if (!(stm32_tamp.hwconf2 & _TAMP_HWCFGR2_TZ)) {
		EMSG("TAMP doesn't support TrustZone");
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}

	stm32_tamp_set_pins(base, stm32_tamp.pdata.pins_conf);

	/*
	 * Select extra IP to add in the deleted/blocked IP in case of
	 * tamper event
	 *
	 * No IP added.
	 */
	stm32_tamp_set_secret_list(&stm32_tamp, 0);

	if (stm32_tamp.pdata.compat->tags & TAMP_HAS_RIF_SUPPORT) {
		apply_rif_config();

		if (stm32_tamp.pdata.bkpregs_conf) {
			res = stm32_tamp_apply_bkpr_rif_conf();
			if (res)
				goto err;
		}
	} else {
		/*
		 * Select access in secure or unsecure
		 *
		 * IP is always SECURE, on mp13 both counter can be accessed
		 * from secure and unsecure world.
		 */
		stm32_tamp_set_secure(&stm32_tamp, _TAMP_SECCFGR_TAMPSEC);

		/*
		 * Select access in privileged mode or unprivileged mode
		 *
		 * TAMP ip need secure access,
		 * backup register zone 1 can be read/written only from secure
		 * backup register zone 2 can be written only from secure.
		 * monotic counter can be read/written from secure and unsecure.
		 */
		stm32_tamp_set_privilege(&stm32_tamp, _TAMP_PRIVCFG_TAMPPRIV |
					 _TAMP_PRIVCFG_BKPRWPRIV |
					 _TAMP_PRIVCFG_BKPWPRIV);
	}

	if (stm32_tamp.pdata.bkpregs_conf) {
		res = stm32_tamp_set_secure_bkpregs();
		if (res)
			goto err;
	}

	stm32_tamp.itr = itr_alloc_add(stm32_tamp.pdata.it,
				       stm32_tamp_it_handler,
				       ITRF_TRIGGER_LEVEL, &stm32_tamp);
	if (!stm32_tamp.itr) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto err;
	}

	if (stm32_tamp.pdata.is_wakeup_source) {
		if (IS_ENABLED(CFG_STM32_EXTI))
			stm32_exti_enable_wake(stm32_tamp.pdata.exti,
					       TAMP_EXTI_WKUP);
		else
			IMSG("TAMP event are not configured as wakeup source");
	}

	itr_enable(stm32_tamp.itr->it);


	fdt_for_each_subnode(subnode, fdt, node) {
		res = dt_driver_maybe_add_probe_node(fdt, subnode);
		if (res) {
			EMSG("Failed on node %s with %#" PRIx32,
			     fdt_get_name(fdt, subnode, NULL), res);
			panic();
		}
	}

	return TEE_SUCCESS;

err:
	if (stm32_tamp.pdata.compat->tags & TAMP_HAS_RIF_SUPPORT) {
		free(stm32_tamp.pdata.bkpregs_conf->rif_offsets);
		free(stm32_tamp.pdata.conf_data.cid_confs);
		free(stm32_tamp.pdata.conf_data.sec_conf);
		free(stm32_tamp.pdata.conf_data.priv_conf);
		free(stm32_tamp.pdata.conf_data.access_mask);
	}

	free(stm32_tamp.pdata.bkpregs_conf);

	return res;
}

static const struct stm32_tamp_compat mp13_compat = {
		.nb_monotonic_counter = 2,
		.tags = TAMP_HAS_REGISTER_SECCFGR |
			TAMP_HAS_REGISTER_PRIVCFGR |
			TAMP_HAS_REGISTER_ERCFGR |
			TAMP_HAS_REGISTER_CR3 |
			TAMP_HAS_REGISTER_ATCR2 |
			TAMP_HAS_CR2_SECRET_STATUS |
			TAMP_SIZE_ATCR1_ATCKSEL_IS_4,
		.int_tamp = int_tamp_mp13,
		.int_tamp_size = ARRAY_SIZE(int_tamp_mp13),
		.ext_tamp = ext_tamp_mp13,
		.ext_tamp_size = ARRAY_SIZE(ext_tamp_mp13),
		.pin_map = pin_map_mp13,
		.pin_map_size = ARRAY_SIZE(pin_map_mp13),
};

static const struct stm32_tamp_compat mp15_compat = {
		.nb_monotonic_counter = 1,
		.tags = 0,
		.int_tamp = int_tamp_mp15,
		.int_tamp_size = ARRAY_SIZE(int_tamp_mp15),
		.ext_tamp = ext_tamp_mp15,
		.ext_tamp_size = ARRAY_SIZE(ext_tamp_mp15),
		.pin_map = pin_map_mp15,
		.pin_map_size = ARRAY_SIZE(pin_map_mp15),
};

static const struct stm32_tamp_compat mp25_compat = {
		.tags = TAMP_HAS_REGISTER_SECCFGR |
			TAMP_HAS_REGISTER_PRIVCFGR |
			TAMP_HAS_RIF_SUPPORT |
			TAMP_HAS_REGISTER_ERCFGR |
			TAMP_HAS_REGISTER_CR3 |
			TAMP_HAS_REGISTER_ATCR2 |
			TAMP_HAS_CR2_SECRET_STATUS,
};

static const struct dt_device_match stm32_tamp_match_table[] = {
	{ .compatible = "st,stm32mp25-tamp", .compat_data = &mp25_compat },
	{ .compatible = "st,stm32mp13-tamp", .compat_data = &mp13_compat },
	{ .compatible = "st,stm32-tamp", .compat_data = &mp15_compat },
	{ }
};

DEFINE_DT_DRIVER(stm32_tamp_dt_driver) = {
	.name = "stm32-tamp",
	.match_table = stm32_tamp_match_table,
	.probe = stm32_tamp_probe,
};
