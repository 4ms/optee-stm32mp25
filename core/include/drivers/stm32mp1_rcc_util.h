/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) STMicroelectronics 2022 - All Rights Reserved
 */

#ifndef __DRIVERS_STM32MP1_RCC_UTIL_H__
#define __DRIVERS_STM32MP1_RCC_UTIL_H__

/* Platform util for the RCC drivers */
vaddr_t stm32_rcc_base(void);

#ifdef CFG_DRIVERS_CLK
/* Helper from platform RCC clock driver */
struct clk *stm32mp_rcc_clock_id_to_clk(unsigned long clock_id);
#endif

#ifdef CFG_STM32MP15_CLK
/* Export stm32mp1_clk_ops to make it pager resisdent for STM32MP15 */
extern const struct clk_ops stm32mp1_clk_ops;
#endif

#ifdef CFG_DRIVERS_RSTCTRL
/* Helper from platform RCC reset driver */
struct rstctrl *stm32mp_rcc_reset_id_to_rstctrl(unsigned int binding_id);
#endif

#ifdef CFG_STM32MP1_SHARED_RESOURCES
/* Register parent clocks of @clock (ID used in clock DT bindings) as secure */
void stm32mp_register_clock_parents_secure(unsigned long clock_id);
#else
static inline
void stm32mp_register_clock_parents_secure(unsigned long clock_id __unused)
{
}
#endif

/* Protect the MCU clock subsytem */
void stm32mp1_clk_mcuss_protect(bool enable);

#endif /*__DRIVERS_STM32MP1_RCC_UTIL_H__*/
