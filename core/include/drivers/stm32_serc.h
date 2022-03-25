/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020, STMicroelectronics
 */
#ifndef __DRIVERS_STM32_SERC_H__
#define __DRIVERS_STM32_SERC_H__

#include <types_ext.h>

struct serc_driver_data {
	uint32_t version;
	uint8_t num_ilac;
};

struct stm32_serc_platdata {
	uintptr_t base;
	struct clk *clock;
	int irq;
};

/*
 * Platform can define an access violation action to trap cpu/reset core or system
 * after an eventual debug trace.
 */
void access_violation_action(void);

int stm32_serc_get_platdata(struct stm32_serc_platdata *pdata);
#endif /* __DRIVERS_STM32_SERC_H__ */
