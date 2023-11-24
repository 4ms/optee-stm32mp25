/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020, STMicroelectronics
 */
#ifndef __DRIVERS_STM32_IAC_H__
#define __DRIVERS_STM32_IAC_H__

#include <types_ext.h>

struct iac_driver_data {
	uint32_t version;
	uint8_t num_ilac;
	bool rif_en;
	bool sec_en;
	bool priv_en;
};

struct stm32_iac_platdata {
	uintptr_t base;
	int irq;
};

/*
 * Platform can define an access violation action to trap cpu/reset core or system
 * after an eventual debug trace.
 */
void access_violation_action(void);

int stm32_iac_get_platdata(struct stm32_iac_platdata *pdata);
#endif /* __DRIVERS_STM32_IAC_H__ */
