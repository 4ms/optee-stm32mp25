// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, STMicroelectronics
 */

#include <kernel/misc.h>
#include <kernel/pm.h>
#include <kernel/thread.h>
#include <sm/psci.h>
#include <stm32mp_pm.h>

/**
 * @brief   Handler for system off
 *
 * @param[in] a0   Unused
 * @param[in] a1   Unused
 *
 * @retval 0       if OK, other value else and TF-A will panic
 */
unsigned long thread_system_off_handler(unsigned long a0 __unused,
					unsigned long a1 __unused)
{
	/* TODO: configure targeted mode in PMIC for system OFF */
	/* stpmic2_configure_power_off(); */

	return 0;
}

/**
 * @brief   Handler for cpu resume
 *
 * @param[in] a0   Max power level powered down
 * @param[in] a1   Unused
 *
 * @retval 0       if OK, other value else and TF-A will panic
 */
unsigned long thread_cpu_resume_handler(unsigned long a0,
					unsigned long a1 __unused)
{
	TEE_Result retstatus = TEE_SUCCESS;

	/* a0 is the highest power level which was powered down. */
	if (a0 < PM_D2_LPLV_LEVEL)
		retstatus = pm_change_state(PM_OP_RESUME,
					    PM_HINT_CLOCK_STATE);
	else
		retstatus = pm_change_state(PM_OP_RESUME,
					    PM_HINT_CONTEXT_STATE);

	/*
	 * Returned value to the TF-A.
	 * If it is not 0, the system will panic
	 */
	if (retstatus == TEE_SUCCESS)
		return 0;
	else
		return 1;
}

/**
 * @brief   Handler for cpu suspend
 *
 * @param[in] a0   Max power level to power down
 * @param[in] a1   Unused
 *
 * @retval 0       if OK, other value else and TF-A will panic
 */
unsigned long thread_cpu_suspend_handler(unsigned long a0,
					 unsigned long a1 __unused)
{
	TEE_Result retstatus = TEE_SUCCESS;

	/* TODO: configure targeted mode in PMIC for next power level */
	/* stpmic2_configure_low_power(a0); */

	/* a0 is the highest power level which was powered down. */
	if (a0 < PM_D2_LPLV_LEVEL)
		retstatus = pm_change_state(PM_OP_SUSPEND,
					    PM_HINT_CLOCK_STATE);
	else
		retstatus = pm_change_state(PM_OP_SUSPEND,
					    PM_HINT_CONTEXT_STATE);

	/*
	 * Returned value to the TF-A.
	 * If it is not 0, the system will panic
	 */
	if (retstatus == TEE_SUCCESS)
		return 0;
	else
		return 1;
}
