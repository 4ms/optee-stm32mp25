// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, STMicroelectronics
 */

#include <assert.h>
#include <config.h>
#include <drivers/rstctrl.h>
#include <drivers/stm32_remoteproc.h>
#include <kernel/cache_helpers.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <stm32_sysconf.h>

#define INITVTOR_MASK	GENMASK_32(31, 7)

#define TIMEOUT_US_1MS	1000U

/**
 * struct stm32_rproc_mem describes memory regions used.
 *
 * @addr:	address of the region.
 * @size:	size of the region.
 */
struct stm32_rproc_mem {
	paddr_t addr;
	size_t size;
	int sec_mem;
};

/**
 * struct stm32_rproc_instance describes rproc instance context.
 *
 * @cdata:	pointer to the device compatible data.
 * @link:	the node in the rproc_list.
 * @regions:	memory regions used
 * @mcu_rst:	reset control
 * @hold_boot:	hold boot control
 * @nregions:   number of memory regions
 * sboot_addr:	secure boot address
 * nsboot_addr: non secure boot address
 * ns_loading:	specify if the firmware is loaded by the OPTEE or by the
 *		non secure context
 */
struct stm32_rproc_instance {
	const struct stm32_rproc_compat_data *cdata;
	SLIST_ENTRY(stm32_rproc_instance) link;
	struct stm32_rproc_mem *regions;
	struct rstctrl *mcu_rst;
	struct rstctrl *hold_boot;
	size_t nregions;
	paddr_t sboot_addr;
	paddr_t nsboot_addr;
	unsigned int ns_loading;
};

/**
 * struct stm32_rproc_compat_data describes rproc associated data
 * for compatible list.
 *
 * @firmware_id:	identify the remoteproc firmware to load.
 */
struct stm32_rproc_compat_data {
	uint32_t firmware_id;
};

static SLIST_HEAD(, stm32_rproc_instance) rproc_list =
		SLIST_HEAD_INITIALIZER(rproc_list);

void *stm32_rproc_get(uint32_t fw_id)
{
	struct stm32_rproc_instance *rproc = NULL;

	SLIST_FOREACH(rproc, &rproc_list, link) {
		if (rproc->cdata->firmware_id == fw_id) {
			if (!rproc->ns_loading)
				return rproc;
			else
				return NULL;
		}
	}

	return NULL;
}

TEE_Result stm32_rproc_start(uint32_t firmware_id)
{
	struct stm32_rproc_instance *rproc = stm32_rproc_get(firmware_id);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!rproc || !rproc->hold_boot)
		return TEE_ERROR_CORRUPT_OBJECT;

	if (!rproc->sboot_addr && !rproc->nsboot_addr)
		return TEE_ERROR_BAD_STATE;

	if (rproc->sboot_addr)
		stm32mp_syscfg_write(A35SSC_M33_TZEN_CR,
				     A35SSC_M33_TZEN_CR_CFG_SECEXT,
				     A35SSC_M33_TZEN_CR_CFG_SECEXT);

	/*
	 * The firmware is started by deasserting the hold boot and
	 * asserting back to avoid auto restart on a crash.
	 * No need to release the MCU reset as it is automatically released by
	 * the hardware.
	 */
	res = rstctrl_deassert_to(rproc->hold_boot, TIMEOUT_US_1MS);
	if (res)
		return res;

	res = rstctrl_assert_to(rproc->hold_boot, TIMEOUT_US_1MS);
	if (res)
		return res;

	return TEE_SUCCESS;
}

static TEE_Result __stm32_rproc_stop(struct stm32_rproc_instance *rproc)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!rproc || !rproc->hold_boot || !rproc->mcu_rst)
		return TEE_ERROR_CORRUPT_OBJECT;

	res = rstctrl_assert_to(rproc->hold_boot, TIMEOUT_US_1MS);
	if (res)
		return res;

	res = rstctrl_assert_to(rproc->mcu_rst, TIMEOUT_US_1MS);
	if (res)
		return res;

	 /* Disable the trustzone */
	stm32mp_syscfg_write(A35SSC_M33_TZEN_CR, 0,
			     A35SSC_M33_TZEN_CR_CFG_SECEXT);

	rproc->sboot_addr = 0;
	rproc->nsboot_addr = 0;

	return TEE_SUCCESS;
}

TEE_Result stm32_rproc_stop(uint32_t firmware_id)
{
	struct stm32_rproc_instance *rproc = stm32_rproc_get(firmware_id);

	return __stm32_rproc_stop(rproc);
}

TEE_Result stm32_rproc_da_to_pa(uint32_t firmware_id, paddr_t da, size_t size,
				paddr_t *pa)
{
	struct stm32_rproc_instance *rproc = stm32_rproc_get(firmware_id);
	struct stm32_rproc_mem *mems = NULL;
	unsigned int i = 0;

	if (!rproc)
		return TEE_ERROR_CORRUPT_OBJECT;

	mems = rproc->regions;

	for (i = 0; i < rproc->nregions; i++) {
		if (da >= mems[i].addr &&
		    (da + size) <= (mems[i].addr + mems[i].size)) {
			*pa = da;

			DMSG("da = %lx", *pa);
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result stm32_rproc_map(uint32_t firmware_id, paddr_t pa, size_t size,
			   void **va)
{
	struct stm32_rproc_instance *rproc = stm32_rproc_get(firmware_id);
	struct stm32_rproc_mem *mems = NULL;
	unsigned int i = 0;

	if (!rproc)
		return TEE_ERROR_CORRUPT_OBJECT;

	mems = rproc->regions;

	for (i = 0; i < rproc->nregions; i++) {
		if (pa < mems[i].addr ||
		    (pa + size) > (mems[i].addr + mems[i].size))
			continue;

		/*
		 * Only secure part is tested, the non-secure is not tested
		 * as it is not possible to distinguish the FW memory from
		 * the shared memory. The shared memory could be used by
		 * the secure firmware.
		 */
		if (mems[i].sec_mem && !rproc->sboot_addr)
			return	TEE_ERROR_CORRUPT_OBJECT;
		/*
		 * TODO: get memory RIF access right to determine the type.
		 * The type is forced  to MEM_AREA_RAM_NSEC
		 */
		if (mems[i].sec_mem) {
			if (!core_mmu_add_mapping(MEM_AREA_RAM_SEC, pa, size)) {
				EMSG("Can't map region %#"PRIxPA" size %zu",
				     pa, size);
				return TEE_ERROR_GENERIC;
			}
			*va = (void *)core_mmu_get_va(pa, MEM_AREA_RAM_SEC,
						      size);
		} else {
			if (!core_mmu_add_mapping(MEM_AREA_RAM_NSEC,
						  pa, size)) {
				EMSG("Can't map region %#"PRIxPA" size %zu",
				     pa, size);
				return TEE_ERROR_GENERIC;
			}
			*va = (void *)core_mmu_get_va(pa, MEM_AREA_RAM_NSEC,
						      size);
		}

		if (!*va)
			return TEE_ERROR_ACCESS_DENIED;

		return TEE_SUCCESS;
	}

	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result stm32_rproc_unmap(uint32_t firmware_id, paddr_t pa, size_t size)
{
	struct stm32_rproc_instance *rproc = stm32_rproc_get(firmware_id);
	struct stm32_rproc_mem *mems = NULL;
	void *va = NULL;
	unsigned int i = 0;

	if (!rproc)
		return TEE_ERROR_CORRUPT_OBJECT;

	mems = rproc->regions;

	for (i = 0; i < rproc->nregions; i++) {
		if (pa < mems[i].addr ||
		    (pa + size) >= (mems[i].addr + mems[i].size))
			continue;

		/*
		 * TODO: get memory RIF access right to determine the type.
		 * The type is forced to MEM_AREA_RAM_NSEC
		 */

		if (mems[i].sec_mem) {
			va = (void *)core_mmu_get_va(pa, MEM_AREA_RAM_SEC,
						     size);
			if (!va)
				return TEE_ERROR_ACCESS_DENIED;

			/* Flush the cache before unmapping the memory */
			dcache_clean_range(va, size);

			if (core_mmu_remove_mapping(MEM_AREA_RAM_SEC,
						    va, size)) {
				EMSG("Can't map region %#"PRIxPA" size %zu",
				     pa, size);
				return TEE_ERROR_GENERIC;
			}
		} else {
			va = (void *)core_mmu_get_va(pa, MEM_AREA_RAM_NSEC,
						     size);
			if (!va)
				return TEE_ERROR_ACCESS_DENIED;

			/* Flush the cache before unmapping the memory */
			dcache_clean_range(va, size);

			if (core_mmu_remove_mapping(MEM_AREA_RAM_NSEC,
						    va, size)) {
				EMSG("Can't unmap region %#"PRIxPA" size %zu",
				     pa, size);
				return TEE_ERROR_GENERIC;
			}
		}

		return TEE_SUCCESS;
	}

	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result stm32_rproc_mem_protect(uint32_t firmware_id,
				   bool secure_access __unused)
{
	struct stm32_rproc_instance *rproc = stm32_rproc_get(firmware_id);

	if (!rproc)
		return TEE_ERROR_CORRUPT_OBJECT;

	/* TODO implement */

	return TEE_SUCCESS;
}

TEE_Result stm32_rproc_set_boot_address(uint32_t firmware_id,
					paddr_t address, bool secure)
{
	struct stm32_rproc_instance *rproc = stm32_rproc_get(firmware_id);
	struct stm32_rproc_mem *regions = NULL;
	size_t i = 0;

	if (!rproc)
		return TEE_ERROR_CORRUPT_OBJECT;

	regions = rproc->regions;

	/* Check that the boot address is in declared regions */
	for (i = 0; i < rproc->nregions; i++) {
		if (address < regions[i].addr ||
		    address > regions[i].addr + regions[i].size)
			continue;

		if ((!secure && regions[i].sec_mem) ||
		    (secure && !regions[i].sec_mem))
			return	TEE_ERROR_CORRUPT_OBJECT;

		if (secure) {
			stm32mp_syscfg_write(A35SSC_M33_INITSVTOR_CR,
					     address, INITVTOR_MASK);
			rproc->sboot_addr = address;

		} else {
			stm32mp_syscfg_write(A35SSC_M33_INITNSVTOR_CR,
					     address, INITVTOR_MASK);
			rproc->nsboot_addr = address;
		}
		DMSG("Cortex-M33 %ssecure Fw boot address: %#"PRIxPA,
		     secure ? "" : "non-", address);
		return TEE_SUCCESS;
	}

	return TEE_ERROR_CORRUPT_OBJECT;
}

static TEE_Result stm32_rproc_parse_mems(struct stm32_rproc_instance *rproc,
					 const void *fdt, int node)
{
	const fdt32_t *list = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct stm32_rproc_mem *regions = NULL;
	int len = 0;
	int nregions = 0;
	int i = 0;

	list = fdt_getprop(fdt, node, "memory-region", &len);
	if (!list) {
		DMSG(" No memory regions found in DT");
		return TEE_SUCCESS;
	}

	/* Get device tree memory region reserved for the Cortex-M an the IPC*/

	nregions = len / sizeof(uint32_t);

	regions = calloc(nregions, sizeof(*regions));
	if (!regions)
		return TEE_ERROR_OUT_OF_MEMORY;

	rproc->nregions = 0;
	for (i = 0; i < nregions; i++) {
		int pnode = 0;
		uint32_t sec_mem = 0;

		pnode = fdt_node_offset_by_phandle(fdt,
						   fdt32_to_cpu(*(list + i)));
		if (pnode < 0)
			continue;

		regions[i].addr = _fdt_reg_base_address(fdt, pnode);
		regions[i].size = _fdt_reg_size(fdt, pnode);

		if (regions[i].addr <= 0 || regions[i].size <= 0)
			return TEE_ERROR_CORRUPT_OBJECT;

		/* TODO suppress temporary property and use firewall */
		res = _fdt_read_uint32_index(fdt, node, "st,s-memory-region",
					     i, &sec_mem);
		if (res)
			return res;

		regions[i].sec_mem = fdt32_to_cpu(sec_mem);

		DMSG("register %s region %#"PRIxPA" size %#zx",
		     regions[i].sec_mem ? "sec" : " none sec",
		     regions[i].addr, regions[i].size);

		rproc->nregions++;
	}

	rproc->regions = regions;

	return TEE_SUCCESS;
}

static void stm32_rproc_cleanup(struct stm32_rproc_instance *rproc)
{
	if (rproc->regions)
		free(rproc->regions);

	free(rproc);
}

static TEE_Result stm32_rproc_probe(const void *fdt, int node,
				    const void *comp_data __unused)
{
	struct stm32_rproc_instance *rproc = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t m33_cr_right = A35SSC_M33_TZEN_CR_M33CFG_SEC |
				A35SSC_M33_TZEN_CR_M33CFG_PRIV;

	rproc = calloc(1, sizeof(*rproc));
	if (!rproc)
		return TEE_ERROR_OUT_OF_MEMORY;

	rproc->cdata = comp_data;

	/* Get memory regions */
	res = stm32_rproc_parse_mems(rproc, fdt, node);
	if (res)
		goto err;

	/* Resets: optional for non authenticated firmware*/

	res = rstctrl_dt_get_by_name(fdt, node, "mcu_rst", &rproc->mcu_rst);
	if (res == TEE_ERROR_DEFER_DRIVER_INIT)
		goto err;

	res = rstctrl_dt_get_by_name(fdt, node, "hold_boot", &rproc->hold_boot);
	if (res == TEE_ERROR_DEFER_DRIVER_INIT)
		goto err;

	/* Ensure that the MCU is HOLD */
	if (rproc->mcu_rst) {
		res = __stm32_rproc_stop(rproc);
		if (res)
			goto err;
	}

	if (!IS_ENABLED(CFG_RPROC_PTA)) {
		/*
		 * The remote firmware will be loaded by the non secure
		 * Provide access rights to A35SSC_M33 registers
		 * to the non secure context
		 */
		rproc->ns_loading = 1;
		m33_cr_right = A35SSC_M33_TZEN_CR_M33CFG_PRIV;
	}

	stm32mp_syscfg_write(A35SSC_M33CFG_ACCESS_CR, m33_cr_right,
			     A35SSC_M33_TZEN_CR_M33CFG_SEC |
			     A35SSC_M33_TZEN_CR_M33CFG_PRIV);

	if (!rproc->ns_loading) {
		res = __stm32_rproc_stop(rproc);
		if (res)
			goto err;
	}

	SLIST_INSERT_HEAD(&rproc_list, rproc, link);

	return TEE_SUCCESS;

err:
	stm32_rproc_cleanup(rproc);
	return res;
}

static const struct stm32_rproc_compat_data stm32_rproc_compat = {
	.firmware_id = STM32_M33_FW_ID
};

static const struct dt_device_match stm32_rproc_match_table[] = {
	{
		.compatible = "st,stm32mp25-rproc",
		.compat_data = (void *)&stm32_rproc_compat
	},
	{ }
};

DEFINE_DT_DRIVER(stm32_rproc_dt_driver) = {
	.name = "stm32-rproc",
	.match_table = stm32_rproc_match_table,
	.probe = &stm32_rproc_probe,
};
