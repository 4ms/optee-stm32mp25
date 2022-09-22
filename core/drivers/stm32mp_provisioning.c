// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, STMicroelectronics
 */

#include <arm.h>
#include <config.h>
#include <drivers/stm32_bsec.h>
#include <dt-bindings/soc/stm32mp-provisioning.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stm32_util.h>
#include <trace.h>

static TEE_Result provisioning_subnode(const void *fdt, int node)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int child = -1;

	fdt_for_each_subnode(child, fdt, node) {
		const int *cuint = NULL;
		int len = 0;
		uint32_t phandle = 0;
		uint32_t otp_lock = 0;
		uint32_t otp_id = 0;
		size_t otp_bit_len = 0;
		size_t otp_len_word = 0;
		unsigned int i = 0;

		cuint = fdt_getprop(fdt, child, "nvmem-cells", NULL);
		if (!cuint)
			panic();

		phandle = fdt32_to_cpu(*cuint);
		res = stm32_bsec_find_otp_by_phandle(phandle, &otp_id,
						     NULL, &otp_bit_len);
		if (res)
			panic("Phandle not found");

		cuint = fdt_getprop(fdt, child, "st,shadow-lock", &len);
		if (cuint && len > 0)
			otp_lock = fdt32_to_cpu(*cuint);

		cuint = fdt_getprop(fdt, child, "st,shadow-value", &len);
		if (!cuint || len < 0 || (len % sizeof(uint32_t) != 0))
			panic();

		otp_len_word = otp_bit_len / (sizeof(uint32_t) * CHAR_BIT);
		if (otp_bit_len % (sizeof(uint32_t) * CHAR_BIT))
			otp_len_word++;

		if ((unsigned int)len / sizeof(uint32_t) != otp_len_word)
			panic("Invalid OTP size");

		for (i = 0; i < otp_len_word; i++) {
			uint32_t shadow_val = 0;
			uint32_t otp_val = 0;
			bool lock = false;

			if (stm32_bsec_read_sw_lock(otp_id + i, &lock))
				panic();

			if (lock)
				panic("Shadow write lock");

			shadow_val = fdt32_to_cpu(*cuint++);

			if (stm32_bsec_shadow_read_otp(&otp_val, otp_id + i))
				panic();

			if (otp_val)
				IMSG("Override the OTP %u initial value",
				     otp_id);

			if (stm32_bsec_write_otp(otp_val | shadow_val,
						 otp_id + i))
				panic();

			switch (otp_lock) {
			case STICKY_LOCK_SW:
				if (stm32_bsec_set_sw_lock(otp_id + i))
					panic();
				break;
			case STICKY_LOCK_SR:
				if (stm32_bsec_set_sr_lock(otp_id + i))
					panic();
				break;
			case STICKY_LOCK_SWSR:
				if (stm32_bsec_set_sw_lock(otp_id + i) ||
				    stm32_bsec_set_sr_lock(otp_id + i))
					panic();
				break;
			case STICKY_NO_LOCK:
			default:
				break;
			}

			stm32_bsec_shadow_read_otp(&otp_val, otp_id + i);
			DMSG("Read SHADOW %x", otp_val);
		}
	}

	return res;
}

#ifdef CFG_DT
static TEE_Result provisioning_probe(void)
{
	const void *fdt = get_embedded_dt();
	int node = -1;

	if (!fdt)
		panic();

	node = fdt_node_offset_by_compatible(fdt, 0, "st,provisioning");
	if (node < 0)
		return TEE_SUCCESS;

	return provisioning_subnode(fdt, node);
}
#else
static TEE_Result provisioning_probe(void)
{
	return TEE_SUCCESS;
}
#endif

early_init(provisioning_probe);
