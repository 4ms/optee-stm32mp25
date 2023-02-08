// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021-2023, STMicroelectronics
 */

#include <drivers/stm32_exti.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <kernel/pm.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <sys/queue.h>
#include <tee_api_types.h>

/* Registers */
#define _EXTI_RTSR(n)		(0x000U + (n) * 0x20U)
#define _EXTI_FTSR(n)		(0x004U + (n) * 0x20U)
#define _EXTI_RPR(n)		(0x00cU + (n) * 0x20U)
#define _EXTI_FPR(n)		(0x010U + (n) * 0x20U)
#define _EXTI_SECCFGR(n)	(0x014U + (n) * 0x20U)
#define _EXTI_CR(n)		(0x060U + (n) * 4U)
#define _EXTI_C1IMR(n)		(0x080U + (n) * 0x10U)

#define _EXTI_MAX_CR		4U
#define _EXTI_BANK_NR		3U

struct stm32_exti_pdata {
	vaddr_t base;
	unsigned int lock;
	uint32_t wake_active[_EXTI_BANK_NR];
	uint32_t mask_cache[_EXTI_BANK_NR];
#ifdef CFG_PM
	uint32_t rtsr_cache[_EXTI_BANK_NR];
	uint32_t ftsr_cache[_EXTI_BANK_NR];
	uint32_t seccfgr_cache[_EXTI_BANK_NR];
	uint32_t port_sel_cache[_EXTI_MAX_CR];
#endif
	SLIST_ENTRY(stm32_exti_pdata) link;
};

static SLIST_HEAD(, stm32_exti_pdata) stm32_exti_list =
	SLIST_HEAD_INITIALIZER(stm32_exti_list);

static uint32_t stm32_exti_get_bank(uint32_t exti_line)
{
	uint32_t bank = 0;

	if (exti_line <= 31)
		bank = 0;
	else if (exti_line <= 63)
		bank = 1;
	else if (exti_line <= 95)
		bank = 2;
	else
		panic();

	return bank;
}

void stm32_exti_set_type(struct stm32_exti_pdata *exti, uint32_t exti_line,
			 uint32_t type)
{
	uint32_t mask = BIT(exti_line % 32);
	uint32_t r_trig = 0;
	uint32_t f_trig = 0;
	uint32_t exceptions = 0;
	unsigned int i = 0;

	switch (type) {
	case EXTI_TYPE_RISING:
		r_trig |= mask;
		f_trig &= ~mask;
		break;
	case EXTI_TYPE_FALLING:
		r_trig &= ~mask;
		f_trig |= mask;
		break;
	case EXTI_TYPE_BOTH:
		r_trig |= mask;
		f_trig |= mask;
		break;
	default:
		panic();
	}

	i = stm32_exti_get_bank(exti_line);

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	io_mask32(exti->base + _EXTI_RTSR(i), r_trig, mask);
	io_mask32(exti->base + _EXTI_FTSR(i), f_trig, mask);

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

void stm32_exti_mask(struct stm32_exti_pdata *exti, uint32_t exti_line)
{
	uint32_t val = 0;
	uint32_t mask = BIT(exti_line % 32);
	uint32_t exceptions = 0;
	unsigned int i = 0;

	i = stm32_exti_get_bank(exti_line);

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	val = io_read32(exti->base + _EXTI_C1IMR(i));
	val &= ~mask;
	io_write32(exti->base + _EXTI_C1IMR(i), val);
	exti->mask_cache[i] = val;

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

void stm32_exti_unmask(struct stm32_exti_pdata *exti, uint32_t exti_line)
{
	uint32_t val = 0;
	uint32_t mask = BIT(exti_line % 32);
	uint32_t exceptions = 0;
	unsigned int i = 0;

	i = stm32_exti_get_bank(exti_line);

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	val = io_read32(exti->base + _EXTI_C1IMR(i));
	val |= mask;
	io_write32(exti->base + _EXTI_C1IMR(i), val);
	exti->mask_cache[i] = val;

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

void stm32_exti_enable_wake(struct stm32_exti_pdata *exti, uint32_t exti_line)
{
	uint32_t mask = BIT(exti_line % 32);
	uint32_t exceptions = 0;
	unsigned int i = 0;

	i = stm32_exti_get_bank(exti_line);

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	exti->wake_active[i] |= mask;

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

void stm32_exti_disable_wake(struct stm32_exti_pdata *exti, uint32_t exti_line)
{
	uint32_t mask = BIT(exti_line % 32);
	uint32_t exceptions = 0;
	unsigned int i = 0;

	i = stm32_exti_get_bank(exti_line);

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	exti->wake_active[i] &= ~mask;

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

void stm32_exti_clear(struct stm32_exti_pdata *exti, uint32_t exti_line)
{
	uint32_t mask = BIT(exti_line % 32);
	uint32_t exceptions = 0;
	unsigned int i = 0;

	i = stm32_exti_get_bank(exti_line);

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	io_mask32(exti->base + _EXTI_RPR(i), mask, mask);
	io_mask32(exti->base + _EXTI_FPR(i), mask, mask);

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

void stm32_exti_set_tz(struct stm32_exti_pdata *exti, uint32_t exti_line)
{
	uint32_t mask = BIT(exti_line % 32);
	uint32_t exceptions = 0;
	unsigned int i = 0;

	i = stm32_exti_get_bank(exti_line);

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	io_mask32(exti->base + _EXTI_SECCFGR(i), mask, mask);

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

void stm32_exti_set_gpio_port_sel(struct stm32_exti_pdata *exti, uint8_t bank,
				  uint8_t pin)
{
	uint32_t reg = _EXTI_CR(pin / 4);
	uint32_t shift = (pin % 4) * 8;
	uint32_t val = bank << shift;
	uint32_t mask = 0xff << shift;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&exti->lock);

	io_mask32(exti->base + reg, val, mask);

	cpu_spin_unlock_xrestore(&exti->lock, exceptions);
}

#ifdef CFG_PM
static void stm32_exti_pm_suspend(struct stm32_exti_pdata *exti)
{
	uint32_t base = exti->base;
	uint32_t mask = 0;
	uint32_t i = 0;

	for (i = 0; i < _EXTI_BANK_NR; i++) {
		/* Save ftsr, rtsr and seccfgr registers */
		exti->ftsr_cache[i] = io_read32(base + _EXTI_FTSR(i));
		exti->rtsr_cache[i] = io_read32(base + _EXTI_RTSR(i));
		exti->seccfgr_cache[i] = io_read32(base + _EXTI_SECCFGR(i));

		/* Let enabled only the wakeup sources set */
		mask = exti->wake_active[i];
		io_mask32(base + _EXTI_C1IMR(i), mask, mask);
	}

	/* Save EXTI port selection */
	for (i = 0; i < _EXTI_MAX_CR; i++)
		exti->port_sel_cache[i] = io_read32(base + _EXTI_CR(i));
}

static void stm32_exti_pm_resume(struct stm32_exti_pdata *exti)
{
	uint32_t base = exti->base;
	uint32_t i = 0;

	for (i = 0; i < _EXTI_BANK_NR; i++) {
		/* Restore ftsr, rtsr and seccfgr registers */
		io_write32(base + _EXTI_FTSR(i), exti->ftsr_cache[i]);
		io_write32(base + _EXTI_RTSR(i), exti->rtsr_cache[i]);
		io_write32(base + _EXTI_SECCFGR(i), exti->seccfgr_cache[i]);

		/* Restore imr */
		io_write32(base + _EXTI_C1IMR(i), exti->mask_cache[i]);
	}

	/* Restore EXTI port selection */
	for (i = 0; i < _EXTI_MAX_CR; i++)
		io_write32(base + _EXTI_CR(i), exti->port_sel_cache[i]);
}

static TEE_Result
stm32_exti_pm(enum pm_op op, unsigned int pm_hint,
	      const struct pm_callback_handle *pm_handle __unused)
{
	struct stm32_exti_pdata *exti = NULL;

	if (!IS_ENABLED(CFG_STM32MP13) && !IS_ENABLED(CFG_STM32MP15) &&
	    pm_hint != PM_HINT_CONTEXT_STATE)
		return TEE_SUCCESS;

	SLIST_FOREACH(exti, &stm32_exti_list, link) {
		if (op == PM_OP_SUSPEND)
			stm32_exti_pm_suspend(exti);
		else
			stm32_exti_pm_resume(exti);
	}

	return TEE_SUCCESS;
}
#endif

static struct stm32_exti_pdata *
stm32_exti_get_handle(struct dt_driver_phandle_args *pargs __unused,
		      void *data, TEE_Result *res)
{
	*res = TEE_SUCCESS;
	return data;
}

static TEE_Result stm32_exti_probe(const void *fdt, int node,
				   const void *comp_data __unused)
{
	struct stm32_exti_pdata *exti = NULL;
	struct dt_node_info dt_info = { };
	struct io_pa_va base = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	exti = calloc(1, sizeof(*exti));
	if (!exti)
		panic("Out of memory");

	exti->lock = SPINLOCK_UNLOCK;

	_fdt_fill_device_info(fdt, &dt_info, node);

	base.pa = dt_info.reg;

	exti->base = io_pa_or_va_secure(&base, dt_info.reg_size);
	assert(exti->base);

	res = dt_driver_register_provider(fdt, node,
					  (get_of_device_func)
					  stm32_exti_get_handle,
					  (void *)exti, DT_DRIVER_NOTYPE);
	if (res)
		goto err;

	SLIST_INSERT_HEAD(&stm32_exti_list, exti, link);

#ifdef CFG_PM
	register_pm_core_service_cb(stm32_exti_pm, NULL, "stm32-exti");
#endif

	return TEE_SUCCESS;

err:
	free(exti);
	return res;
}

static const struct dt_device_match stm32_exti_match_table[] = {
	{ .compatible = "st,stm32mp1-exti" },
	{ .compatible = "st,stm32mp13-exti" },
	{ }
};

DEFINE_DT_DRIVER(stm32_exti_dt_driver) = {
	.name = "stm32-exti",
	.match_table = stm32_exti_match_table,
	.probe = &stm32_exti_probe,
};
