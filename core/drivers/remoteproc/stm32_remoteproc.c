// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, STMicroelectronics
 */

#include <assert.h>
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
 */
struct stm32_rproc_instance {
	const struct stm32_rproc_compat_data *cdata;
	SLIST_ENTRY(stm32_rproc_instance) link;
	struct stm32_rproc_mem *regions;
	struct rstctrl *mcu_rst;
	struct rstctrl *hold_boot;
	size_t nregions;
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
		if (rproc->cdata->firmware_id == fw_id)
			return rproc;
	}

	return NULL;
}

TEE_Result stm32_rproc_start(uint32_t firmware_id)
{
	struct stm32_rproc_instance *rproc = stm32_rproc_get(firmware_id);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!rproc || !rproc->hold_boot)
		return TEE_ERROR_CORRUPT_OBJECT;

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
		 * TODO: get memory RIF access right to determine the type.
		 * The type is forced  to MEM_AREA_RAM_NSEC
		 */

		if (!core_mmu_add_mapping(MEM_AREA_RAM_NSEC, pa, size)) {
			EMSG("Can't map region %#"PRIxPA" size %zu", pa, size);
			return TEE_ERROR_GENERIC;
		}

		*va = (void *)core_mmu_get_va(pa, MEM_AREA_RAM_NSEC, size);
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

		va = (void *)core_mmu_get_va(pa, MEM_AREA_RAM_NSEC, size);
		if (!va)
			return TEE_ERROR_ACCESS_DENIED;

		if (core_mmu_remove_mapping(MEM_AREA_RAM_NSEC, va, size)) {
			EMSG("Can't unmap region %#"PRIxPA" size %zu",
			     pa, size);
			return TEE_ERROR_GENERIC;
		}
		/* Flush the cache before unmapping the memory */
		dcache_clean_range(va, size);

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

static TEE_Result stm32_rproc_parse_mems(struct stm32_rproc_instance *rproc,
					 const void *fdt, int node)
{
	const fdt32_t *list = NULL;
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
		const fdt32_t *prop = NULL;

		pnode = fdt_node_offset_by_phandle(fdt,
						   fdt32_to_cpu(*(list + i)));
		if (pnode < 0)
			continue;

		prop = fdt_getprop(fdt, pnode, "reg", NULL);
		if (!prop)
			continue;

		regions[i].addr = fdt32_to_cpu(prop[0]);
		regions[i].size = fdt32_to_cpu(prop[1]);

		DMSG("register region %#"PRIxPA" size %#zx", regions[i].addr,
		     regions[i].size);

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
	const fdt32_t *fdt_tz = NULL;
	const fdt32_t *fdt_fw_addr = NULL;
	struct stm32_rproc_instance *rproc = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t tz = 0;

	rproc = calloc(1, sizeof(*rproc));
	if (!rproc)
		return TEE_ERROR_OUT_OF_MEMORY;

	rproc->cdata = comp_data;

	/*
	 * Allow only OPTEE to configure M33 config registers.
	 * TODO: give access right to non-secure in case OPTEE  does not manage
	 * the M33 FW load.
	 */

	stm32mp_syscfg_write(A35SSC_M33CFG_ACCESS_CR,
			     A35SSC_M33_TZEN_CR_M33CFG_SEC |
			     A35SSC_M33_TZEN_CR_M33CFG_PRIV,
			     A35SSC_M33_TZEN_CR_M33CFG_SEC |
			     A35SSC_M33_TZEN_CR_M33CFG_PRIV);

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

	/* TrustZone */
	fdt_tz = fdt_getprop(fdt, node, "st,trustzone", NULL);
	if (fdt_tz)
		tz = fdt32_to_cpu(*fdt_tz);

	IMSG("Cortex-M33 TrustZone %sable", tz ? "en" : "dis");

	if (fdt_tz)
		stm32mp_syscfg_write(A35SSC_M33_TZEN_CR,
				     tz ? A35SSC_M33_TZEN_CR_CFG_SECEXT : 0,
				     A35SSC_M33_TZEN_CR_CFG_SECEXT);

	/*
	 * Secure firmware boot address:
	 * This address is the default boot address of the secure firmware.
	 * It should point to a memory region that will contain the secure
	 * firmware.
	 */
	if (tz) {
		fdt_fw_addr = fdt_getprop(fdt, node, "st,s_fw_boot_addr", NULL);
		if (fdt_fw_addr) {
			stm32mp_syscfg_write(A35SSC_M33_INITSVTOR_CR,
					     fdt32_to_cpu(*fdt_fw_addr),
					     INITVTOR_MASK);
			DMSG("Cortex-M33 secure Fw boot address: %#x",
			     fdt32_to_cpu(*fdt_fw_addr));
		}
	}

	/*
	 * Non-secure firmware boot address
	 * This address is the default boot address of the non secure firmware.
	 * It must point to a memory region that will contain the non secure
	 * firmware.
	 * Notice that, if the trustZone is disable, the non secure firmware can
	 * be loaded by an other component than OP-TEE (e.g U-boot, Linux).
	 */

	fdt_fw_addr = fdt_getprop(fdt, node, "st,ns_fw_boot_addr", NULL);
	if (fdt_fw_addr) {
		stm32mp_syscfg_write(A35SSC_M33_INITNSVTOR_CR,
				     fdt32_to_cpu(*fdt_fw_addr), INITVTOR_MASK);
		DMSG("Cortex-M33 non-secure Fw boot address: %#x",
		     fdt32_to_cpu(*fdt_fw_addr));
	}

	res = __stm32_rproc_stop(rproc);
	if (res)
		goto err;

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
