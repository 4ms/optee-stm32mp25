/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020, STMicroelectronics
 */
#ifndef __STM32_RIFSC_H
#define __STM32_RIFSC_H

#include <types_ext.h>
#include <util.h>

struct risup_cfg {
	uint32_t id;
	bool sec;
	bool priv;
	uint32_t cid_attr;
};

struct rimu_cfg {
	uint32_t id;
	uint32_t attr;
};

#endif /* __STM32_RIFSC_H */
