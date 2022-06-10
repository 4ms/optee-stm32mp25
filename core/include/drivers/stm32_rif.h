/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2022, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_RIF_H
#define __DRIVERS_STM32_RIF_H

#include <drivers/stm32mp_dt_bindings.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <util.h>

/*
 * CIDCFGR register
 */
#define _CIDCFGR_CFEN			BIT(0)
#define _CIDCFGR_SEMEN			BIT(1)
#define _CIDCFGR_SEMWL(x)		BIT(SEMWL_SHIFT + (x))

/*
 * SEMCR register
 */
#define _SEMCR_MUTEX			BIT(0)
#define _SEMCR_SEMCID_SHIFT		U(4)
#define _SEMCR_SEMCID_MASK		GENMASK_32(6, 4)

/*
 * Miscellaneous
 */
#define MAX_CID_BITFIELD		U(3)
#define MAX_CID_SUPPORTED		U(7)

#define SCID_SHIFT			U(4)
#define SEMWL_SHIFT			U(16)
#define RIF_ID_SHIFT			U(24)

#define RIF_ID_MASK			GENMASK_32(31, 24)
#define RIF_CHANNEL_ID(x)		((RIF_ID_MASK & (x)) >> RIF_ID_SHIFT)

#define RIFPROT_SEC			BIT(8)
#define RIFPROT_PRIV			BIT(9)
#define RIFPROT_LOCK			BIT(10)

#define SCID_OK(cidcfgr, scid_m, cid)	(((cidcfgr) & (scid_m)) ==	\
					 ((cid) << (SCID_SHIFT)) &&	\
					 !((cidcfgr) & (_CIDCFGR_SEMEN)))

#define SEM_EN_AND_OK(cidcfgr, wl)	(((cidcfgr) & _CIDCFGR_CFEN) &&  \
					 ((cidcfgr) & _CIDCFGR_SEMEN) && \
					 ((cidcfgr) & _CIDCFGR_SEMWL(wl)))
#ifdef CFG_STM32_RIF
#define SEM_MODE_INCORRECT(cidcfgr)	(!((cidcfgr) & _CIDCFGR_CFEN) ||  \
					 !((cidcfgr) & _CIDCFGR_SEMEN) || \
					 (!((cidcfgr) &			  \
					    _CIDCFGR_SEMWL(RIF_CID1)) &&  \
					  ((cidcfgr) & _CIDCFGR_SEMEN)))
#else /* CFG_STM32_RIF */
#define SEM_MODE_INCORRECT(cidcfgr)	(cidcfgr)
#endif /* CFG_STM32_RIF */

/*
 * Structure containing RIF configuration data
 * @access_mask: Mask of the registers which will be configured.
 * @sec_conf: Secure configuration registers.
 * @priv_conf: Privilege configuration registers.
 * @cid_confs: CID filtering configuration register value for an IP channel
 *             (i.e: GPIO pins, FMC controllers)
 * @lock_conf: RIF configuration locking registers
 *
 * For a hardware block having 56 channels, there will be 56 cid_confs
 * registers and 2 sec_conf and priv_conf registers
 */
struct rif_conf_data {
	uint32_t *access_mask;
	uint32_t *sec_conf;
	uint32_t *priv_conf;
	uint32_t *cid_confs;
	uint32_t *lock_conf;
};

/*
 * Check every possible configuration where accessing RIF
 * is possible :
 * -When no CID filtering is enabled on a controller
 * -When CID filtering is enabled on a controller, semaphore
 *  is disabled, and static CID corresponds to Cortex A35
 * -When CID filtering is enabled on a controller, semaphore
 *  is enabled and is not taken, and Cortex A35 CID is
 *  white-listed
 * -When CID filtering is enabled on a controller, semaphore
 *  is enabled and is taken, and Cortex A35 CID is
 *  white-listed and semaphore is already taken by Cortex A35
 */
#ifdef CFG_STM32_RIF
TEE_Result stm32_rif_check_access(uint32_t cidcfgr,
				  uint32_t semcr,
				  unsigned int nb_cid_supp,
				  unsigned int cid_to_check);
#else
static inline TEE_Result
		stm32_rif_check_access(uint32_t cidcfgr __unused,
				       uint32_t semcr __unused,
				       unsigned int nb_cid_supp __unused,
				       unsigned int cid_to_check __unused)
{
	return TEE_SUCCESS;
}
#endif

/*
 * Parse RIF config from Device Tree extracted information
 * @rif_conf: Configuration read in the device tree
 * @conf_data: Buffer containing the RIF configuration to apply for an IP
 * @sec_conf: Buffer containing the secure RIF configuration for an IP
 * @priv_conf: Buffer containing the CID RIF configurations for an IP channels
 *             (i.e: GPIO pins, FMC controllers)
 * @nb_cid_supp: Number of supported CID for the IP
 * @nb_channel: Number of channels for the IP
 */
#ifdef CFG_STM32_RIF
void stm32_rif_parse_cfg(uint32_t rif_conf,
			 struct rif_conf_data *conf_data,
			 unsigned int nb_cid_supp,
			 unsigned int nb_channel);
#else
static inline void
		stm32_rif_parse_cfg(uint32_t rif_conf __unused,
				    struct rif_conf_data *conf_data __unused,
				    unsigned int nb_cid_supp __unused,
				    unsigned int nb_channel __unused)
{
}
#endif

#ifdef CFG_STM32_RIF
/* RIF semaphore functions */
bool stm32_rif_is_semaphore_available(vaddr_t addr);
TEE_Result stm32_rif_acquire_semaphore(vaddr_t addr,
				       unsigned int nb_cid_supp);
TEE_Result stm32_rif_release_semaphore(vaddr_t addr,
				       unsigned int nb_cid_supp);
#else
static inline bool stm32_rif_is_semaphore_available(vaddr_t addr __unused)
{
	return true;
}

static inline TEE_Result
		stm32_rif_acquire_semaphore(vaddr_t addr __unused,
					    unsigned int nb_cid_supp __unused)
{
	return TEE_SUCCESS;
}

static inline TEE_Result
		stm32_rif_release_semaphore(vaddr_t addr __unused,
					    unsigned int nb_cid_supp __unused)
{
	return TEE_SUCCESS;
}
#endif

#endif /* __DRIVERS_STM32_RIF_H */
