// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021, STMicroelectronics
 */

#include <drivers/stm32_exti.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/pm.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <tee_api_types.h>

/* Registers */
#define _EXTI_CR1	0x60U
#define _EXTI_CR2	0x64U
#define _EXTI_CR3	0x68U
#define _EXTI_CR4	0x6CU

struct stm32_exti_bank {
	uint32_t imr_ofst;
	uint32_t rtsr_ofst;
	uint32_t ftsr_ofst;
	uint32_t rpr_ofst;
	uint32_t fpr_ofst;
	uint32_t tzenr_ofst;
	uint32_t wakeup;
	uint32_t imr_cache;
	uint32_t rtsr_bkp;
	uint32_t ftsr_bkp;
	uint32_t tz_bkp;
};

#ifdef CFG_PM
static uint32_t port_sel_bkp[4];
#endif

struct stm32_exti_priv {
	vaddr_t base;
};

static struct stm32_exti_priv stm32_exti;

static struct stm32_exti_bank stm32mp1_exti_b1 = {
	.imr_ofst	= 0x80,
	.rtsr_ofst	= 0x00,
	.ftsr_ofst	= 0x04,
	.rpr_ofst	= 0x0C,
	.fpr_ofst	= 0x10,
	.tzenr_ofst	= 0x14,
};

static struct stm32_exti_bank stm32mp1_exti_b2 = {
	.imr_ofst	= 0x90,
	.rtsr_ofst	= 0x20,
	.ftsr_ofst	= 0x24,
	.rpr_ofst	= 0x2C,
	.fpr_ofst	= 0x30,
	.tzenr_ofst	= 0x34,
};

static struct stm32_exti_bank stm32mp1_exti_b3 = {
	.imr_ofst	= 0xA0,
	.rtsr_ofst	= 0x40,
	.ftsr_ofst	= 0x44,
	.rpr_ofst	= 0x4C,
	.fpr_ofst	= 0x50,
	.tzenr_ofst	= 0x54,
};

static struct stm32_exti_bank *stm32mp1_exti_banks[] = {
	&stm32mp1_exti_b1,
	&stm32mp1_exti_b2,
	&stm32mp1_exti_b3,
};

/* EXTI access protection */
static unsigned int lock = SPINLOCK_UNLOCK;

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

void stm32_exti_set_type(uint32_t exti_line, uint32_t type)
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

	exceptions = cpu_spin_lock_xsave(&lock);

	io_mask32(stm32_exti.base + stm32mp1_exti_banks[i]->rtsr_ofst, r_trig,
		  mask);
	io_mask32(stm32_exti.base + stm32mp1_exti_banks[i]->ftsr_ofst, f_trig,
		  mask);

	cpu_spin_unlock_xrestore(&lock, exceptions);
}

void stm32_exti_mask(uint32_t exti_line)
{
	uint32_t val = 0;
	uint32_t mask = BIT(exti_line % 32);
	uint32_t exceptions = 0;
	unsigned int i = 0;

	i = stm32_exti_get_bank(exti_line);

	exceptions = cpu_spin_lock_xsave(&lock);

	val = io_read32(stm32_exti.base + stm32mp1_exti_banks[i]->imr_ofst);
	val &= ~mask;
	io_write32(stm32_exti.base + stm32mp1_exti_banks[i]->imr_ofst, val);
	stm32mp1_exti_banks[i]->imr_cache = val;

	cpu_spin_unlock_xrestore(&lock, exceptions);
}

void stm32_exti_unmask(uint32_t exti_line)
{
	uint32_t val = 0;
	uint32_t mask = BIT(exti_line % 32);
	uint32_t exceptions = 0;
	unsigned int i = 0;

	i = stm32_exti_get_bank(exti_line);

	exceptions = cpu_spin_lock_xsave(&lock);

	val = io_read32(stm32_exti.base + stm32mp1_exti_banks[i]->imr_ofst);
	val |= mask;
	io_write32(stm32_exti.base + stm32mp1_exti_banks[i]->imr_ofst, val);
	stm32mp1_exti_banks[i]->imr_cache = val;

	cpu_spin_unlock_xrestore(&lock, exceptions);
}

void stm32_exti_enable_wake(uint32_t exti_line)
{
	uint32_t mask = BIT(exti_line % 32);
	uint32_t exceptions = 0;
	unsigned int i = 0;

	i = stm32_exti_get_bank(exti_line);

	exceptions = cpu_spin_lock_xsave(&lock);

	stm32mp1_exti_banks[i]->wakeup |= mask;

	cpu_spin_unlock_xrestore(&lock, exceptions);
}

void stm32_exti_disable_wake(uint32_t exti_line)
{
	uint32_t mask = BIT(exti_line % 32);
	uint32_t exceptions = 0;
	unsigned int i = 0;

	i = stm32_exti_get_bank(exti_line);

	exceptions = cpu_spin_lock_xsave(&lock);

	stm32mp1_exti_banks[i]->wakeup &= ~mask;

	cpu_spin_unlock_xrestore(&lock, exceptions);
}

void stm32_exti_clear(uint32_t exti_line)
{
	uint32_t mask = BIT(exti_line % 32);
	uint32_t exceptions = 0;
	unsigned int i = 0;

	i = stm32_exti_get_bank(exti_line);

	exceptions = cpu_spin_lock_xsave(&lock);

	io_mask32(stm32_exti.base + stm32mp1_exti_banks[i]->rpr_ofst, mask,
		  mask);
	io_mask32(stm32_exti.base + stm32mp1_exti_banks[i]->fpr_ofst, mask,
		  mask);

	cpu_spin_unlock_xrestore(&lock, exceptions);
}

void stm32_exti_set_tz(uint32_t exti_line)
{
	uint32_t mask = BIT(exti_line % 32);
	uint32_t exceptions = 0;
	unsigned int i = 0;

	i = stm32_exti_get_bank(exti_line);

	exceptions = cpu_spin_lock_xsave(&lock);

	io_mask32(stm32_exti.base + stm32mp1_exti_banks[i]->tzenr_ofst, mask,
		  mask);

	cpu_spin_unlock_xrestore(&lock, exceptions);
}

void stm32_exti_set_gpio_port_sel(uint8_t bank, uint8_t pin)
{
	uint32_t reg = _EXTI_CR1 + (pin / 4) * 4;
	uint32_t shift = (pin % 4) * 8;
	uint32_t val = bank << shift;
	uint32_t mask = 0xff << shift;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&lock);

	io_mask32(stm32_exti.base + reg, val, mask);

	cpu_spin_unlock_xrestore(&lock, exceptions);
}

#ifdef CFG_PM
static void stm32_exti_pm_suspend(void)
{
	uint32_t mask = 0;
	uint32_t base_cr = 0;
	uint32_t i = 0;

	/* Save ftsr, rtsr and tzen registers */
	stm32mp1_exti_b1.ftsr_bkp = io_read32(stm32_exti.base +
					      stm32mp1_exti_b1.ftsr_ofst);
	stm32mp1_exti_b1.rtsr_bkp = io_read32(stm32_exti.base +
					      stm32mp1_exti_b1.rtsr_ofst);
	stm32mp1_exti_b1.tz_bkp = io_read32(stm32_exti.base +
					    stm32mp1_exti_b1.tzenr_ofst);

	stm32mp1_exti_b2.ftsr_bkp = io_read32(stm32_exti.base +
					      stm32mp1_exti_b2.ftsr_ofst);
	stm32mp1_exti_b2.rtsr_bkp = io_read32(stm32_exti.base +
					      stm32mp1_exti_b2.rtsr_ofst);
	stm32mp1_exti_b2.tz_bkp = io_read32(stm32_exti.base +
					    stm32mp1_exti_b2.tzenr_ofst);

	stm32mp1_exti_b3.ftsr_bkp = io_read32(stm32_exti.base +
					      stm32mp1_exti_b3.ftsr_ofst);
	stm32mp1_exti_b3.rtsr_bkp = io_read32(stm32_exti.base +
					      stm32mp1_exti_b3.rtsr_ofst);
	stm32mp1_exti_b3.tz_bkp = io_read32(stm32_exti.base +
					    stm32mp1_exti_b3.tzenr_ofst);

	/* Let enabled only the wakeup sources set*/
	mask = stm32mp1_exti_b1.wakeup;
	io_mask32(stm32_exti.base + stm32mp1_exti_b1.imr_ofst, mask, mask);
	mask = stm32mp1_exti_b2.wakeup;
	io_mask32(stm32_exti.base + stm32mp1_exti_b2.imr_ofst, mask, mask);
	mask = stm32mp1_exti_b3.wakeup;
	io_mask32(stm32_exti.base + stm32mp1_exti_b3.imr_ofst, mask, mask);

	/* Save EXTI port selection */
	for (i = 0; i < 4; i++) {
		base_cr = stm32_exti.base + _EXTI_CR1;
		port_sel_bkp[i] = io_read32(base_cr + i * 4);
	}
}

static void stm32_exti_pm_resume(void)
{
	uint32_t base_cr = 0;
	uint32_t i = 0;

	/* Restore ftsr and rtsr registers */
	io_write32(stm32_exti.base + stm32mp1_exti_b1.ftsr_ofst,
		   stm32mp1_exti_b1.ftsr_bkp);
	io_write32(stm32_exti.base + stm32mp1_exti_b2.ftsr_ofst,
		   stm32mp1_exti_b2.ftsr_bkp);
	io_write32(stm32_exti.base + stm32mp1_exti_b3.ftsr_ofst,
		   stm32mp1_exti_b3.ftsr_bkp);
	io_write32(stm32_exti.base + stm32mp1_exti_b1.rtsr_ofst,
		   stm32mp1_exti_b1.rtsr_bkp);
	io_write32(stm32_exti.base + stm32mp1_exti_b2.rtsr_ofst,
		   stm32mp1_exti_b2.rtsr_bkp);
	io_write32(stm32_exti.base + stm32mp1_exti_b3.rtsr_ofst,
		   stm32mp1_exti_b3.rtsr_bkp);
	io_write32(stm32_exti.base + stm32mp1_exti_b1.tzenr_ofst,
		   stm32mp1_exti_b1.tz_bkp);
	io_write32(stm32_exti.base + stm32mp1_exti_b2.tzenr_ofst,
		   stm32mp1_exti_b2.tz_bkp);
	io_write32(stm32_exti.base + stm32mp1_exti_b3.tzenr_ofst,
		   stm32mp1_exti_b3.tz_bkp);

	/* Restore imr */
	io_write32(stm32_exti.base + stm32mp1_exti_b1.imr_ofst,
		   stm32mp1_exti_b1.imr_cache);
	io_write32(stm32_exti.base + stm32mp1_exti_b2.imr_ofst,
		   stm32mp1_exti_b2.imr_cache);
	io_write32(stm32_exti.base + stm32mp1_exti_b3.imr_ofst,
		   stm32mp1_exti_b3.imr_cache);

	/* Restore EXTI port selection */
	for (i = 0; i < 4; i++) {
		base_cr = stm32_exti.base + _EXTI_CR1;
		io_write32(base_cr + i * 4, port_sel_bkp[i]);
	}
}

static TEE_Result
stm32_exti_pm(enum pm_op op, unsigned int pm_hint __unused,
	      const struct pm_callback_handle *pm_handle __unused)
{
	if (op == PM_OP_SUSPEND)
		stm32_exti_pm_suspend();
	else
		stm32_exti_pm_resume();

	return TEE_SUCCESS;
}
#endif

#ifdef CFG_EMBED_DTB
static TEE_Result stm32_exti_probe(const void *fdt, int node,
				   const void *comp_data __unused)
{
	struct dt_node_info dt_info = { };
	struct io_pa_va base = { };

	_fdt_fill_device_info(fdt, &dt_info, node);

	base.pa = dt_info.reg;

	stm32_exti.base = io_pa_or_va_secure(&base, dt_info.reg_size);
	assert(stm32_exti.base);

#ifdef CFG_PM
	register_pm_core_service_cb(stm32_exti_pm, NULL, "stm32-exti");
#endif

	return TEE_SUCCESS;
}

static const struct dt_device_match stm32_exti_match_table[] = {
	{ .compatible = "st,stm32mp13-exti" },
	{ }
};

DEFINE_DT_DRIVER(stm32_exti_dt_driver) = {
	.name = "stm32-exti",
	.match_table = stm32_exti_match_table,
	.probe = &stm32_exti_probe,
};
#endif
