// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2018-2022, STMicroelectronics
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/rstctrl.h>
#include <drivers/stm32_rng.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <rng_support.h>
#include <stdbool.h>
#include <stm32_util.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>

#define RNG_CR			0x00U
#define RNG_SR			0x04U
#define RNG_DR			0x08U

#define RNG_CR_RNGEN		BIT(2)
#define RNG_CR_IE		BIT(3)
#define RNG_CR_CED		BIT(5)

#define RNG_SR_DRDY		BIT(0)
#define RNG_SR_CECS		BIT(1)
#define RNG_SR_SECS		BIT(2)
#define RNG_SR_CEIS		BIT(5)
#define RNG_SR_SEIS		BIT(6)

#define RNG_TIMEOUT_US		U(100000)
#define RNG_RESET_TIMEOUT_US	U(1000)

struct stm32_rng_instance {
	struct io_pa_va base;
	struct clk *clock;
	struct rstctrl *rstctrl;
	unsigned int lock;
	unsigned int refcount;
	bool release_post_boot;
};

/* Expect at most a single RNG instance */
static struct stm32_rng_instance *stm32_rng;

/*
 * Extracts from the STM32 RNG specification:
 *
 * When a noise source (or seed) error occurs, the RNG stops generating
 * random numbers and sets to “1” both SEIS and SECS bits to indicate
 * that a seed error occurred. (...)

 * The following sequence shall be used to fully recover from a seed
 * error after the RNG initialization:
 * 1. Clear the SEIS bit by writing it to “0”.
 * 2. Read out 12 words from the RNG_DR register, and discard each of
 * them in order to clean the pipeline.
 * 3. Confirm that SEIS is still cleared. Random number generation is
 * back to normal.
 */
static void conceal_seed_error(vaddr_t rng_base)
{
	if (io_read32(rng_base + RNG_SR) & (RNG_SR_SECS | RNG_SR_SEIS)) {
		size_t i = 0;

		io_mask32(rng_base + RNG_SR, 0, RNG_SR_SEIS);

		for (i = 12; i != 0; i--)
			(void)io_read32(rng_base + RNG_DR);

		if (io_read32(rng_base + RNG_SR) & RNG_SR_SEIS)
			panic("RNG noise");
	}
}

#define RNG_FIFO_BYTE_DEPTH		16u

static TEE_Result read_available(vaddr_t rng_base, uint8_t *out, size_t *size)
{
	uint8_t *buf = NULL;
	size_t req_size = 0;
	size_t len = 0;

	conceal_seed_error(rng_base);

	if (!(io_read32(rng_base + RNG_SR) & RNG_SR_DRDY)) {
		FMSG("RNG not ready");
		return TEE_ERROR_NO_DATA;
	}

	if (io_read32(rng_base + RNG_SR) & RNG_SR_SEIS) {
		FMSG("RNG noise error");
		return TEE_ERROR_NO_DATA;
	}

	buf = out;
	req_size = MIN(RNG_FIFO_BYTE_DEPTH, *size);
	len = req_size;

	/* RNG is ready: read up to 4 32bit words */
	while (len) {
		uint32_t data32 = io_read32(rng_base + RNG_DR);
		size_t sz = MIN(len, sizeof(uint32_t));

		memcpy(buf, &data32, sz);
		buf += sz;
		len -= sz;
	}

	*size = req_size;

	return TEE_SUCCESS;
}

static void gate_rng(bool enable, struct stm32_rng_instance *dev)
{
	vaddr_t rng_cr = io_pa_or_va(&dev->base, 1) + RNG_CR;
	uint32_t exceptions = may_spin_lock(&dev->lock);

	if (enable) {
		/* incr_refcnt return non zero if resource shall be enabled */
		if (incr_refcnt(&dev->refcount)) {
			FMSG("enable RNG");
			clk_enable(dev->clock);
			io_write32(rng_cr, 0);
			io_write32(rng_cr, RNG_CR_RNGEN | RNG_CR_CED);
		}
	} else {
		/* decr_refcnt return non zero if resource shall be disabled */
		if (decr_refcnt(&dev->refcount)) {
			FMSG("disable RNG");
			io_write32(rng_cr, 0);
			clk_disable(dev->clock);
		}
	}

	may_spin_unlock(&dev->lock, exceptions);
}

TEE_Result stm32_rng_read(uint8_t *out, size_t size)
{
	TEE_Result rc = TEE_ERROR_GENERIC;
	bool burst_timeout = false;
	uint64_t timeout_ref = 0;
	uint32_t exceptions = 0;
	uint8_t *out_ptr = out;
	vaddr_t rng_base = 0;
	size_t out_size = 0;

	if (!stm32_rng) {
		DMSG("No RNG");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	gate_rng(true, stm32_rng);
	rng_base = io_pa_or_va(&stm32_rng->base, 1);

	/* Arm timeout */
	timeout_ref = timeout_init_us(RNG_TIMEOUT_US);
	burst_timeout = false;

	while (out_size < size) {
		/* Read by chunks of the size the RNG FIFO depth */
		size_t sz = size - out_size;

		exceptions = may_spin_lock(&stm32_rng->lock);

		rc = read_available(rng_base, out_ptr, &sz);

		/* Raise timeout only if we failed to get some samples */
		assert(!rc || rc == TEE_ERROR_NO_DATA);
		if (rc)
			burst_timeout = timeout_elapsed(timeout_ref);

		may_spin_unlock(&stm32_rng->lock, exceptions);

		if (burst_timeout) {
			rc = TEE_ERROR_GENERIC;
			goto out;
		}

		if (!rc) {
			out_size += sz;
			out_ptr += sz;
			/* Re-arm timeout */
			timeout_ref = timeout_init_us(RNG_TIMEOUT_US);
			burst_timeout = false;
		}
	}

out:
	assert(!rc || rc == TEE_ERROR_GENERIC);
	gate_rng(false, stm32_rng);

	return rc;
}

#ifdef CFG_WITH_SOFTWARE_PRNG
/* Override weak plat_rng_init with platform handler to seed PRNG */
void plat_rng_init(void)
{
	uint8_t seed[RNG_FIFO_BYTE_DEPTH] = { };

	if (stm32_rng_read(seed, sizeof(seed)))
		panic();

	if (crypto_rng_init(seed, sizeof(seed)))
		panic();

	DMSG("PRNG seeded with RNG");
}
#else
TEE_Result hw_get_random_bytes(void *out, size_t size)
{
	return stm32_rng_read(out, size);
}
#endif

#ifdef CFG_EMBED_DTB
static TEE_Result stm32_rng_parse_fdt(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dt_node_info dt_rng = { };

	_fdt_fill_device_info(fdt, &dt_rng, node);
	if (dt_rng.reg == DT_INFO_INVALID_REG)
		return TEE_ERROR_BAD_PARAMETERS;

	stm32_rng->base.pa = dt_rng.reg;
	stm32_rng->base.va = io_pa_or_va_secure(&stm32_rng->base,
						dt_rng.reg_size);
	assert(stm32_rng->base.va);

	res = rstctrl_dt_get_by_index(fdt, node, 0, &stm32_rng->rstctrl);
	if (res != TEE_SUCCESS && res != TEE_ERROR_ITEM_NOT_FOUND)
		return res;

	res = clk_dt_get_by_index(fdt, node, 0, &stm32_rng->clock);
	if (res)
		return res;

	/* RNG is also assigned to non-secure world and not used for PM */
	stm32_rng->release_post_boot = IS_ENABLED(CFG_WITH_SOFTWARE_PRNG) &&
				       !IS_ENABLED(CFG_PM);

	return TEE_SUCCESS;
}

static TEE_Result stm32_rng_probe(const void *fdt, int offs,
				  const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	/* Expect a single RNG instance */
	assert(!stm32_rng);

	stm32_rng = calloc(1, sizeof(*stm32_rng));
	if (!stm32_rng)
		panic();

	res = stm32_rng_parse_fdt(fdt, offs);
	if (res)
		goto err;

	res = clk_enable(stm32_rng->clock);
	if (res)
		goto err;

	if (stm32_rng->rstctrl &&
	    rstctrl_assert_to(stm32_rng->rstctrl, RNG_RESET_TIMEOUT_US))
		goto err;

	if (stm32_rng->rstctrl &&
	    rstctrl_deassert_to(stm32_rng->rstctrl, RNG_RESET_TIMEOUT_US))
		goto err;

	clk_disable(stm32_rng->clock);

	if (IS_ENABLED(CFG_STM32MP15)) {
		vaddr_t base_pa = stm32_rng->base.pa;

		if (IS_ENABLED(CFG_WITH_SOFTWARE_PRNG))
			stm32mp_register_non_secure_periph_iomem(base_pa);
		else
			stm32mp_register_secure_periph_iomem(base_pa);
	}

	return TEE_SUCCESS;

err:
	free(stm32_rng);
	stm32_rng = NULL;

	return res;
}

static const struct dt_device_match rng_match_table[] = {
	{ .compatible = "st,stm32-rng" },
	{ .compatible = "st,stm32mp13-rng" },
	{ }
};

DEFINE_DT_DRIVER(stm32_rng_dt_driver) = {
	.name = "stm32_rng",
	.match_table = rng_match_table,
	.probe = stm32_rng_probe,
};

static TEE_Result stm32_rng_release(void)
{
	if (stm32_rng && stm32_rng->release_post_boot) {
		DMSG("Release RNG driver");
		assert(!stm32_rng->refcount);
		free(stm32_rng);
		stm32_rng = NULL;
	}

	return TEE_SUCCESS;
}

release_init_resource(stm32_rng_release);
#endif /*CFG_EMBED_DTB*/
