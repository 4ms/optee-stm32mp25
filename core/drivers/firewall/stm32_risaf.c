// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2023, STMicroelectronics - All Rights Reserved
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/stm32_risaf.h>
#include <dt-bindings/soc/stm32mp25-risaf.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/tee_misc.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

/* RISAF general registers (base relative) */
#define _RISAF_CR			U(0x00)
#define _RISAF_SR			U(0x04)
#define _RISAF_IASR			U(0x08)
#define _RISAF_IAESR0			U(0x20)
#define _RISAF_IADDR0			U(0x24)
#define _RISAF_IAESR1			U(0x28)
#define _RISAF_IADDR1			U(0x2C)
#define _RISAF_KEYR			U(0x30)
#define _RISAF_HWCFGR			U(0xFF0)
#define _RISAF_VERR			U(0xFF4)
#define _RISAF_IPIDR			U(0xFF8)
#define _RISAF_SIDR			U(0xFFC)

/* RISAF general register field description */
/* _RISAF_CR register fields */
#define _RISAF_CR_GLOCK			BIT(0)
/* _RISAF_SR register fields */
#define _RISAF_SR_KEYVALID		BIT(0)
#define _RISAF_SR_KEYRDY		BIT(1)
#define _RISAF_SR_ENCDIS		BIT(2)
/* _RISAF_HWCFGR register fields */
#define _RISAF_HWCFGR_CFG1_SHIFT	U(0)
#define _RISAF_HWCFGR_CFG1_MASK		GENMASK_32(7, 0)
#define _RISAF_HWCFGR_CFG2_SHIFT	U(8)
#define _RISAF_HWCFGR_CFG2_MASK		GENMASK_32(15, 8)
#define _RISAF_HWCFGR_CFG3_SHIFT	U(16)
#define _RISAF_HWCFGR_CFG3_MASK		GENMASK_32(23, 16)
#define _RISAF_HWCFGR_CFG4_SHIFT	U(24)
#define _RISAF_HWCFGR_CFG4_MASK		GENMASK_32(31, 24)
/* _RISAF_VERR register fields */
#define _RISAF_VERR_MINREV_SHIFT	U(0)
#define _RISAF_VERR_MINREV_MASK		GENMASK_32(3, 0)
#define _RISAF_VERR_MAJREV_SHIFT	U(4)
#define _RISAF_VERR_MAJREV_MASK		GENMASK_32(7, 4)

/* RISAF region registers (base relative) */
#define _RISAF_REG_BASE			U(0x40)
#define _RISAF_REG_SIZE			U(0x40)
#define _RISAF_REG(n)			(_RISAF_REG_BASE + \
					 (((n) - 1) * _RISAF_REG_SIZE))
#define _RISAF_REG_CFGR_OFFSET		U(0x0)
#define _RISAF_REG_CFGR(n)		(_RISAF_REG(n) + _RISAF_REG_CFGR_OFFSET)
#define _RISAF_REG_STARTR_OFFSET	U(0x4)
#define _RISAF_REG_STARTR(n)		(_RISAF_REG(n) + \
					 _RISAF_REG_STARTR_OFFSET)
#define _RISAF_REG_ENDR_OFFSET		U(0x8)
#define _RISAF_REG_ENDR(n)		(_RISAF_REG(n) + _RISAF_REG_ENDR_OFFSET)
#define _RISAF_REG_CIDCFGR_OFFSET	U(0xC)
#define _RISAF_REG_CIDCFGR(n)		(_RISAF_REG(n) + \
					 _RISAF_REG_CIDCFGR_OFFSET)

/* RISAF region register field description */
/* _RISAF_REG_CFGR(n) register fields */
#define _RISAF_REG_CFGR_BREN_SHIFT	U(0)
#define _RISAF_REG_CFGR_BREN		BIT(_RISAF_REG_CFGR_BREN_SHIFT)
#define _RISAF_REG_CFGR_SEC_SHIFT	U(8)
#define _RISAF_REG_CFGR_SEC		BIT(_RISAF_REG_CFGR_SEC_SHIFT)
#define _RISAF_REG_CFGR_ENC_SHIFT	U(15)
#define _RISAF_REG_CFGR_ENC		BIT(_RISAF_REG_CFGR_ENC_SHIFT)
#define _RISAF_REG_CFGR_PRIVC_SHIFT	U(16)
#define _RISAF_REG_CFGR_PRIVC_MASK	GENMASK_32(23, 16)
#define _RISAF_REG_CFGR_ALL_MASK	(_RISAF_REG_CFGR_BREN | \
					 _RISAF_REG_CFGR_SEC | \
					 _RISAF_REG_CFGR_ENC | \
					 _RISAF_REG_CFGR_PRIVC_MASK)

/* _RISAF_REG_CIDCFGR(n) register fields */
#define _RISAF_REG_CIDCFGR_RDENC_SHIFT	U(0)
#define _RISAF_REG_CIDCFGR_RDENC_MASK	GENMASK_32(7, 0)
#define _RISAF_REG_CIDCFGR_WRENC_SHIFT	U(16)
#define _RISAF_REG_CIDCFGR_WRENC_MASK	GENMASK_32(23, 16)
#define _RISAF_REG_CIDCFGR_ALL_MASK	(_RISAF_REG_CIDCFGR_RDENC_MASK | \
					 _RISAF_REG_CIDCFGR_WRENC_MASK)

/* Device Tree related definitions */
#define DT_RISAF_REG_ID_MASK		U(0xF)
#define DT_RISAF_EN_MASK		BIT(DT_RISAF_EN_SHIFT)
#define DT_RISAF_SEC_MASK		BIT(DT_RISAF_SEC_SHIFT)
#define DT_RISAF_ENC_MASK		BIT(DT_RISAF_ENC_SHIFT)
#define DT_RISAF_PRIV_MASK		GENMASK_32(15, 8)
#define DT_RISAF_READ_MASK		GENMASK_32(23, 16)
#define DT_RISAF_WRITE_MASK		GENMASK_32(31, 24)

#define _RISAF_GET_REGION_ID(cfg)	((cfg) & DT_RISAF_REG_ID_MASK)
#define _RISAF_GET_REGION_CFG(cfg) \
	(((((cfg) & DT_RISAF_EN_MASK) >> DT_RISAF_EN_SHIFT) << \
	  _RISAF_REG_CFGR_BREN_SHIFT) | \
	 ((((cfg) & DT_RISAF_SEC_MASK) >> DT_RISAF_SEC_SHIFT) << \
	  _RISAF_REG_CFGR_SEC_SHIFT) | \
	 ((((cfg) & DT_RISAF_ENC_MASK) >> DT_RISAF_ENC_SHIFT) << \
	  _RISAF_REG_CFGR_ENC_SHIFT) | \
	 ((((cfg) & DT_RISAF_PRIV_MASK) >> DT_RISAF_PRIV_SHIFT) << \
	  _RISAF_REG_CFGR_PRIVC_SHIFT))
#define _RISAF_GET_REGION_CID_CFG(cfg) \
	(((((cfg) & DT_RISAF_WRITE_MASK) >> DT_RISAF_WRITE_SHIFT) << \
	  _RISAF_REG_CIDCFGR_WRENC_SHIFT) | \
	 ((((cfg) & DT_RISAF_READ_MASK) >> DT_RISAF_READ_SHIFT) << \
	  _RISAF_REG_CIDCFGR_RDENC_SHIFT))

struct stm32_risaf_region {
	uint32_t cfg;
	uint32_t addr;
	uint32_t len;
};

struct stm32_risaf_pdata {
	struct io_pa_va base;
	struct clk *clock;
	struct stm32_risaf_region *regions;
#if TRACE_LEVEL >= TRACE_INFO
	char risaf_name[20];
#endif
	unsigned int nregions;
	uint32_t mem_base;
	uint32_t mem_size;
	bool enc_supported;
};

struct stm32_risaf_ddata {
	uint32_t mask_regions;
	uint32_t max_base_regions;
};

struct stm32_risaf_instance {
	struct stm32_risaf_pdata pdata;
	struct stm32_risaf_ddata *ddata;

	SLIST_ENTRY(stm32_risaf_instance) link;
};

#if TRACE_LEVEL >= TRACE_DEBUG
struct stm32_risaf_version {
	uint32_t major;
	uint32_t minor;
	uint32_t ip_id;
	uint32_t size_id;
};
#endif

/**
 * struct stm32_risaf_compat_data describes RISAF associated data
 * for compatible list.
 *
 * @supported_encryption:	identify risaf encryption capabilities.
 */
struct stm32_risaf_compat_data {
	bool supported_encryption;
};

static const struct stm32_risaf_compat_data stm32_risaf_compat = {
	.supported_encryption = false,
};

static const struct stm32_risaf_compat_data stm32_risaf_enc_compat = {
	.supported_encryption = true,
};

static SLIST_HEAD(, stm32_risaf_instance) risaf_list =
		SLIST_HEAD_INITIALIZER(risaf_list);

static vaddr_t risaf_base(struct stm32_risaf_instance *risaf)
{
	return io_pa_or_va_secure(&risaf->pdata.base, 1);
}

#if TRACE_LEVEL >= TRACE_INFO
void stm32_risaf_dump_erroneous_data(void)
{
	struct stm32_risaf_instance *risaf = NULL;

	SLIST_FOREACH(risaf, &risaf_list, link) {
		vaddr_t base = io_pa_or_va_secure(&risaf->pdata.base, 1);

		if (clk_enable(risaf->pdata.clock))
			panic("Can't enable RISAF clock");

		/* Check if faulty address on this RISAF */
		if (!io_read32(base + _RISAF_IASR)) {
			clk_disable(risaf->pdata.clock);
			continue;
		}

		EMSG("\n\nDUMPING DATA FOR %s\n\n", risaf->pdata.risaf_name);
		EMSG("=====================================================");
		EMSG("Status register (IAESR0): %#"PRIx32,
		     io_read32(base + _RISAF_IAESR0));

		/* Reserved if dual port feature not available */
		if (io_read32(base + _RISAF_IAESR1))
			EMSG("Status register Dual Port (IAESR1) %#"PRIx32,
			     io_read32(base + _RISAF_IAESR1));

		EMSG("-----------------------------------------------------");
		EMSG("Faulty address (IADDR0): %#"PRIxPA,
		     risaf->pdata.mem_base +
		     (paddr_t)io_read32(base + _RISAF_IADDR0));

		/* Reserved if dual port feature not available */
		if (io_read32(base + _RISAF_IADDR1))
			EMSG("Dual port faulty address (IADDR1): %#"PRIxPA,
			     risaf->pdata.mem_base +
			     (paddr_t)io_read32(base + _RISAF_IADDR1));

		EMSG("=====================================================\n");

		clk_disable(risaf->pdata.clock);
	};
}
#endif

static __maybe_unused
bool risaf_is_hw_encryption_enabled(struct stm32_risaf_instance *risaf)
{
	return (io_read32(risaf_base(risaf) + _RISAF_SR) &
		_RISAF_SR_ENCDIS) != _RISAF_SR_ENCDIS;
}

static TEE_Result check_region_address(struct stm32_risaf_instance *risaf,
				       struct stm32_risaf_region *region)
{
	uint32_t granularity = 0;
	uint32_t end_paddr = 0;

	assert(region->len != 0U);

	if (region->addr < (uint32_t)risaf->pdata.mem_base) {
		EMSG("RISAF %#"PRIxPTR": region start address lower than memory base",
		     risaf->pdata.base.pa);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Get physical end address */
	end_paddr = (uint32_t)risaf->pdata.mem_base +
		    (risaf->pdata.mem_size - 1U);
	if (region->addr > end_paddr ||
	    ((region->addr - 1U + region->len) > end_paddr)) {
		EMSG("RISAF %#"PRIxPTR": start/end address higher than physical end",
		     risaf->pdata.base.pa);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Get IP region granularity */
	granularity = io_read32(risaf_base(risaf) + _RISAF_HWCFGR);
	granularity = BIT((granularity & _RISAF_HWCFGR_CFG3_MASK) >>
			  _RISAF_HWCFGR_CFG3_SHIFT);
	if (((region->addr % granularity) != 0U) ||
	    ((region->len % granularity) != 0U)) {
		EMSG("RISAF %#"PRIxPTR": start/end address granularity not respected",
		     risaf->pdata.base.pa);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result risaf_configure_region(struct stm32_risaf_instance *risaf,
					 uint32_t region_id, uint32_t cfg,
					 uint32_t cid_cfg, uint32_t saddr,
					 uint32_t eaddr)
{
	vaddr_t base = risaf_base(risaf);
	uint32_t mask = risaf->ddata->mask_regions;

	io_clrbits32(base + _RISAF_REG_CFGR(region_id), _RISAF_REG_CFGR_BREN);

#ifndef CFG_STM32MP25x_REVA
	io_clrsetbits32(base + _RISAF_REG_STARTR(region_id), mask,
			(saddr - risaf->pdata.mem_base) & mask);
	io_clrsetbits32(base + _RISAF_REG_ENDR(region_id), mask,
			(eaddr - risaf->pdata.mem_base) & mask);
#else /* CFG_STM32MP25x_REVA */
	io_clrsetbits32(base + _RISAF_REG_STARTR(region_id), mask, saddr & mask);
	io_clrsetbits32(base + _RISAF_REG_ENDR(region_id), mask, eaddr & mask);
#endif /* CFG_STM32MP25x_REVA */
	io_clrsetbits32(base + _RISAF_REG_CIDCFGR(region_id),
			_RISAF_REG_CIDCFGR_ALL_MASK,
			cid_cfg & _RISAF_REG_CIDCFGR_ALL_MASK);

	io_clrsetbits32(base + _RISAF_REG_CFGR(region_id),
			_RISAF_REG_CFGR_ALL_MASK,
			cfg & _RISAF_REG_CFGR_ALL_MASK);

	if ((cfg & _RISAF_REG_CFGR_ENC) == _RISAF_REG_CFGR_ENC) {
		if (!risaf->pdata.enc_supported) {
			EMSG("RISAF %#"PRIxPTR": encryption feature error",
			     risaf->pdata.base.pa);
			return TEE_ERROR_GENERIC;
		}

		if ((cfg & _RISAF_REG_CFGR_SEC) != _RISAF_REG_CFGR_SEC) {
			EMSG("RISAF %#"PRIxPTR": encryption on non secure area",
			     risaf->pdata.base.pa);
			return TEE_ERROR_GENERIC;
		}
	}

	DMSG("RISAF %#"PRIxPTR": region %02d - start 0x%08x - end 0x%08x - cfg 0x%08x - cidcfg 0x%08x",
	     risaf->pdata.base.pa, region_id,
	     io_read32(base + _RISAF_REG_STARTR(region_id)),
	     io_read32(base + _RISAF_REG_ENDR(region_id)),
	     io_read32(base + _RISAF_REG_CFGR(region_id)),
	     io_read32(base + _RISAF_REG_CIDCFGR(region_id)));

	return TEE_SUCCESS;
}

static void
risaf_print_version(struct stm32_risaf_instance *risaf __maybe_unused)
{
#if TRACE_LEVEL >= TRACE_DEBUG
	vaddr_t base = risaf_base(risaf);
	struct stm32_risaf_version version;

	version = (struct stm32_risaf_version) {
		.major = (io_read32(base + _RISAF_VERR) &
			  _RISAF_VERR_MAJREV_MASK) >> _RISAF_VERR_MAJREV_SHIFT,
		.minor = (io_read32(base + _RISAF_VERR) &
			  _RISAF_VERR_MINREV_MASK) >> _RISAF_VERR_MINREV_SHIFT,
		.ip_id = io_read32(base + _RISAF_IPIDR),
		.size_id = io_read32(base + _RISAF_SIDR)
	};

	IMSG("RISAF %#"PRIxPTR" version %d.%d, ip0x%x size0x%x",
	     risaf->pdata.base.pa, version.major, version.minor, version.ip_id,
	     version.size_id);
#endif
}

/*
 * @brief  Lock the RISAF IP registers for a given instance.
 * @param  risaf: RISAF instance.
 * @retval 0 if OK, negative value else.
 */
static __maybe_unused
int stm32_risaf_lock(struct stm32_risaf_instance *risaf)
{
	assert(risaf);

	io_setbits32(risaf_base(risaf) + _RISAF_CR, _RISAF_CR_GLOCK);

	return 0;
}

/*
 * @brief  Get the RISAF lock state for a given instance.
 * @param  risaf: RISAF instance.
 *         state: lock state, true if locked, false else.
 * @retval 0 if OK, negative value else.
 */
static __maybe_unused
int stm32_risaf_is_locked(struct stm32_risaf_instance *risaf, bool *state)
{
	assert(risaf);

	*state = (io_read32(risaf_base(risaf) + _RISAF_CR) &
		  _RISAF_CR_GLOCK) == _RISAF_CR_GLOCK;

	return 0;
}

static TEE_Result stm32_risaf_init_ddata(struct stm32_risaf_instance *risaf)
{
	vaddr_t base = risaf_base(risaf);
	uint32_t hwcfgr = 0;
	uint32_t mask_lsb = 0;
	uint32_t mask_msb = 0;

	risaf->ddata = calloc(1, sizeof(*risaf->ddata));
	if (!risaf->ddata)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Get address mask depending on RISAF instance HW configuration */
	hwcfgr =  io_read32(base + _RISAF_HWCFGR);
	mask_lsb = (hwcfgr & _RISAF_HWCFGR_CFG3_MASK) >>
		   _RISAF_HWCFGR_CFG3_SHIFT;
	mask_msb = mask_lsb + ((hwcfgr & _RISAF_HWCFGR_CFG4_MASK) >>
			       _RISAF_HWCFGR_CFG4_SHIFT) - 1U;
	risaf->ddata->mask_regions = GENMASK_32(mask_msb, mask_lsb);
	risaf->ddata->max_base_regions = (hwcfgr & _RISAF_HWCFGR_CFG1_MASK) >>
					 _RISAF_HWCFGR_CFG1_SHIFT;

	return TEE_SUCCESS;
}

TEE_Result stm32_risaf_reconfigure(paddr_t base)
{
	struct stm32_risaf_instance *risaf = NULL;

	SLIST_FOREACH(risaf, &risaf_list, link) {
		struct stm32_risaf_region *regions = risaf->pdata.regions;
		TEE_Result res = TEE_ERROR_GENERIC;
		unsigned int i = 0;

		if (base != risaf->pdata.base.pa)
			continue;

		res = clk_enable(risaf->pdata.clock);
		if (res)
			return res;

		for (i = 0; i < risaf->pdata.nregions; i++) {
			uint32_t id = _RISAF_GET_REGION_ID(regions[i].cfg);
			uint32_t cfg = _RISAF_GET_REGION_CFG(regions[i].cfg);
			uint32_t cid_cfg =
				_RISAF_GET_REGION_CID_CFG(regions[i].cfg);
			uint32_t start_addr = regions[i].addr;
			uint32_t end_addr = start_addr + regions[i].len - 1U;

			if (risaf_configure_region(risaf, id, cfg, cid_cfg,
						   start_addr, end_addr))
				panic();
		}

		clk_disable(risaf->pdata.clock);
	}

	return TEE_SUCCESS;
}

static TEE_Result stm32_risaf_probe(const void *fdt, int node,
				    const void *compat_data)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dt_node_info dt_info = { };
	struct stm32_risaf_instance *risaf = NULL;
	struct stm32_risaf_region *regions = NULL;
	unsigned int nregions = 0;
	int len = 0;
	unsigned int i = 0;
	const fdt32_t *cuint = NULL;
	const fdt32_t *conf_list = NULL;
	const struct stm32_risaf_compat_data *compat = compat_data;

	risaf = calloc(1, sizeof(*risaf));
	if (!risaf)
		return TEE_ERROR_OUT_OF_MEMORY;

	_fdt_fill_device_info(fdt, &dt_info, node);
	if (dt_info.reg == DT_INFO_INVALID_REG ||
	    dt_info.reg_size == DT_INFO_INVALID_REG_SIZE) {
		free(risaf);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	risaf->pdata.base.pa = dt_info.reg;
	io_pa_or_va_secure(&risaf->pdata.base, dt_info.reg_size);

	risaf->pdata.enc_supported = compat->supported_encryption;

	res = clk_dt_get_by_index(fdt, node, 0, &risaf->pdata.clock);
	if (!risaf->pdata.clock)
		goto err;

	conf_list = fdt_getprop(fdt, node, "memory-region", &len);
	if (!conf_list) {
		IMSG("RISAF %#"PRIxPTR": No configuration in DT, use default",
		     risaf->pdata.base.pa);
		free(risaf);
		return TEE_SUCCESS;
	}

#if TRACE_LEVEL >= TRACE_INFO
	strncpy(risaf->pdata.risaf_name, fdt_get_name(fdt, node, NULL), 19);
#endif

	res = clk_enable(risaf->pdata.clock);
	if (res)
		goto err;

	res = stm32_risaf_init_ddata(risaf);
	if (res)
		goto err_clk;

	risaf_print_version(risaf);

	cuint = fdt_getprop(fdt, node, "st,mem-map", NULL);
	if (!cuint)
		panic();

	risaf->pdata.mem_base = fdt32_to_cpu(*cuint);
	risaf->pdata.mem_size = fdt32_to_cpu(*(cuint + 1));

	nregions = (unsigned int)len / sizeof(uint32_t);

	regions = calloc(nregions, sizeof(*regions));
	if (nregions && !regions) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err_ddata;
	}

	for (i = 0; i < nregions; i++) {
		int pnode = 0;
		const fdt32_t *prop = NULL;
		uint32_t id = 0;
		uint32_t cfg = 0;
		uint32_t cid_cfg = 0;
		uint32_t start_addr = 0;
		uint32_t end_addr = 0;

		pnode =
		fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(*(conf_list + i)));
		if (pnode < 0)
			continue;

		prop = fdt_getprop(fdt, pnode, "reg", NULL);
		if (!prop)
			continue;

		regions[i].addr = fdt32_to_cpu(prop[0]);
		regions[i].len = fdt32_to_cpu(prop[1]);

		if (!regions[i].len)
			continue;

		/* Skip 'op_tee' region, in which OP-TEE code is executed */
		if (regions[i].addr == TZDRAM_BASE &&
#ifdef CFG_CORE_RESERVED_SHM
			regions[i].len == (TZDRAM_SIZE + TEE_SHMEM_SIZE)) {
#else
			regions[i].len == TZDRAM_SIZE) {
#endif
			continue;
		}

		prop = fdt_getprop(fdt, pnode, "st,protreg", NULL);
		if (!prop)
			continue;

		regions[i].cfg = fdt32_to_cpu(*prop);

		DMSG("RISAF %#"PRIxPTR": cfg 0x%08x - addr 0x%08x - len 0x%08x",
		     risaf->pdata.base.pa, regions[i].cfg, regions[i].addr,
		     regions[i].len);

		if (check_region_address(risaf, &regions[i]))
			panic();

		id = _RISAF_GET_REGION_ID(regions[i].cfg);
		assert(id < risaf->ddata->max_base_regions);

		cfg = _RISAF_GET_REGION_CFG(regions[i].cfg);

		cid_cfg = _RISAF_GET_REGION_CID_CFG(regions[i].cfg);

		start_addr = regions[i].addr;
		end_addr = start_addr + regions[i].len - 1U;

		if (risaf_configure_region(risaf, id, cfg, cid_cfg,
					   start_addr, end_addr))
			panic();
	}

	clk_disable(risaf->pdata.clock);

	risaf->pdata.regions = regions;
	risaf->pdata.nregions = nregions;

	SLIST_INSERT_HEAD(&risaf_list, risaf, link);

	return TEE_SUCCESS;
err_ddata:
	free(risaf->ddata);
err_clk:
	clk_disable(risaf->pdata.clock);
err:
	free(risaf);
	return res;
}

static const struct dt_device_match risaf_match_table[] = {
	{
		.compatible = "st,stm32mp25-risaf",
		.compat_data = (void *)&stm32_risaf_compat,
	},
	{
		.compatible = "st,stm32mp25-risaf-enc",
		.compat_data = (void *)&stm32_risaf_enc_compat,
	},
	{ }
};

DEFINE_DT_DRIVER(risaf_dt_driver) = {
	.name = "stm32-risaf",
	.match_table = risaf_match_table,
	.probe = stm32_risaf_probe,
};