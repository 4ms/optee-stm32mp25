/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022, STMicroelectronics
 */

#ifndef __STM32_CPU_OPP__
#define __STM32_CPU_OPP__

/* Return the number of CPU operating points */
size_t stm32_cpu_opp_count(void);

/* Get level value identifying CPU operating point @opp_index */
unsigned int stm32_cpu_opp_level(size_t opp_index);

/* Request to switch to CPU operating point related to @level */
TEE_Result stm32_cpu_opp_set_level(unsigned int level);

/* Get level related to current CPU operating point */
TEE_Result stm32_cpu_opp_read_level(unsigned int *level);

#endif /*__STM32_CPU_OPP__*/
