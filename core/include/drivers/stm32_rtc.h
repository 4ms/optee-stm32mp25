/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2017-2018, STMicroelectronics - All Rights Reserved
 * Copyright (c) 2017, ARM Limited and Contributors. All rights reserved.
 */

#ifndef __PLAT_RTC_H__
#define __PLAT_RTC_H__

#include <stdbool.h>

struct stm32_rtc_calendar {
	uint32_t ssr;
	uint32_t tr;
	uint32_t dr;
};

enum months {
	JANUARY = 1,
	FEBRUARY,
	MARCH,
	APRIL,
	MAY,
	JUNE,
	JULY,
	AUGUST,
	SEPTEMBER,
	OCTOBER,
	NOVEMBER,
	DECEMBER,
	NB_MONTHS = 12
};

struct stm32_rtc_time {
	uint32_t hour;
	uint32_t min;
	uint32_t sec;
	uint32_t wday;
	uint32_t day;
	enum months month;
	uint32_t year;
};

/* Get calendar formatted time from RTC device */
void stm32_rtc_get_calendar(struct stm32_rtc_calendar *calendar);

/* Return time diff in milliseconds between current and reference time */
unsigned long long stm32_rtc_diff_calendar(struct stm32_rtc_calendar *cur,
					   struct stm32_rtc_calendar *ref);

/* Enable tamper and secure timestamp access in RTC */
void stm32_rtc_set_tamper_timestamp(void);

/* Return true if and only if RTC timestamp is enable */
bool stm32_rtc_is_timestamp_enable(void);

/* Get RTC timestamp for current time */
void stm32_rtc_get_timestamp(struct stm32_rtc_time *tamp_ts);

#endif /* __PLAT_RTC_H__ */
