/* SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause) */
/*
 * Copyright (C) 2020-2021, STMicroelectronics - All Rights Reserved
 */

#ifndef _DT_BINDINGS_STM32MP25_RIF_H
#define _DT_BINDINGS_STM32MP25_RIF_H

/* RIF CIDs */
#define RIF_CID0		0x0
#define RIF_CID1		0x1
#define RIF_CID2		0x2
#define RIF_CID3		0x3
#define RIF_CID4		0x4
#define RIF_CID5		0x5
#define RIF_CID6		0x6
#define RIF_CID7		0x7

/* RIF semaphore list */
#define EMPTY_SEMWL		0x0
#define RIF_CID0_BF		(1 << RIF_CID0)
#define RIF_CID1_BF		(1 << RIF_CID1)
#define RIF_CID2_BF		(1 << RIF_CID2)
#define RIF_CID3_BF		(1 << RIF_CID3)
#define RIF_CID4_BF		(1 << RIF_CID4)
#define RIF_CID5_BF		(1 << RIF_CID5)
#define RIF_CID6_BF		(1 << RIF_CID6)
#define RIF_CID7_BF		(1 << RIF_CID7)

/* RIF secure levels */
#define RIF_NSEC		0x0
#define RIF_SEC			0x1

/* RIF privilege levels */
#define RIF_NPRIV		0x0
#define RIF_PRIV		0x1

/* RIF semaphore modes */
#define RIF_SEM_DIS		0x0
#define RIF_SEM_EN		0x1

/* RIF CID filtering modes */
#define RIF_CFDIS		0x0
#define RIF_CFEN		0x1

/* RIF lock states */
#define RIF_UNLOCK		0x0
#define RIF_LOCK		0x1

/* Used when a field in a macro has no impact */
#define RIF_UNUSED		0x0

#define RIF_EXTI1_RESOURCE(x)   (x)

#define RIF_EXTI2_RESOURCE(x)   (x)

#define RIF_FMC_CTRL(x)		(x)

#define RIF_IOPORT_PIN(x)	(x)

#define RIF_HPDMA_CHANNEL(x)	(x)

#define RIF_IPCC_CPU1_CHANNEL(x)        (x - 1)

#define RIF_IPCC_CPU2_CHANNEL(x)        (((x) - 1) + 16)

#define RIF_PWR_RESOURCE(x)	(x)

#define RIF_HSEM_RESOURCE(x)	(x)

/* Shareable PWR resources, RIF_PWR_RESOURCE_WIO(0) doesn't exist */
#define RIF_PWR_RESOURCE_WIO(x)	((x) + 6)

#define RIF_RCC_RESOURCE(x)	(x)

#define RIF_RTC_RESOURCE(x)	(x)

#define RIF_TAMP_RESOURCE(x)	(x)

#endif /* _DT_BINDINGS_STM32MP25_RIF_H */
