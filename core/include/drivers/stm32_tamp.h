/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021-2023, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_TAMP_H__
#define __DRIVERS_STM32_TAMP_H__

#include <compiler.h>
#include <drivers/clk.h>
#include <mm/core_memprot.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

/* Tamper ident */
enum stm32_tamp_id {
	INT_TAMP1 = 0,
	INT_TAMP2,
	INT_TAMP3,
	INT_TAMP4,
	INT_TAMP5,
	INT_TAMP6,
	INT_TAMP7,
	INT_TAMP8,
	INT_TAMP9,
	INT_TAMP10,
	INT_TAMP11,
	INT_TAMP12,
	INT_TAMP13,
	INT_TAMP14,
	INT_TAMP15,
	INT_TAMP16,

	EXT_TAMP1,
	EXT_TAMP2,
	EXT_TAMP3,
	EXT_TAMP4,
	EXT_TAMP5,
	EXT_TAMP6,
	EXT_TAMP7,
	EXT_TAMP8,

	LAST_TAMP,
	INVALID_TAMP = 0xFFFF,
};

/* Callback return bitmask values */
#define TAMP_CB_ACK		BIT(0)
#define TAMP_CB_RESET		BIT(1)
#define TAMP_CB_ACK_AND_RESET	(TAMP_CB_RESET | TAMP_CB_ACK)

/*
 * struct stm32_bkpregs_conf - Interface for stm32_tamp_set_secure_bkpregs()
 * @nb_zone1_regs - Number of backup registers in zone 1
 * @nb_zone2_regs - Number of backup registers in zone 2
 *
 * TAMP backup registers access permissions
 *
 * Zone 1: read/write in secure state, no access in non-secure state
 * Zone 2: read/write in secure state, read-only in non-secure state
 * Zone 3: read/write in secure state, read/write in non-secure state
 *
 * Protection zone 1
 * If nb_zone1_regs == 0 no backup register are in zone 1.
 * Otherwise backup registers from TAMP_BKP0R to TAMP_BKP<x>R are in zone 1,
 * with <x> = (@nb_zone1_regs - 1).
 *
 * Protection zone 2
 * If nb_zone2_regs == 0 no backup register are in zone 2.
 * Otherwise backup registers from TAMP_BKP<y>R ro TAMP_BKP<z>R are in zone 2,
 * with <y> = @nb_zone1_regs and <z> = (@nb_zone1_regs1 + @nb_zone2_regs - 1).
 *
 * Protection zone 3
 * Backup registers from TAMP_BKP<t>R to last backup register are in zone 3,
 * with <t> = (@nb_zone1_regs1 + @nb_zone2_regs).
 */
struct stm32_bkpregs_conf {
	uint32_t nb_zone1_regs;
	uint32_t nb_zone2_regs;
};

/* Define TAMPER modes */
#define TAMP_ERASE		0x0U
#define TAMP_NOERASE		BIT(1)
#define TAMP_NO_EVT_MASK	0x0U
#define TAMP_EVT_MASK		BIT(2)
#define TAMP_MODE_MASK		GENMASK_32(15, 0)

/*
 * stm32_tamp_write_mcounter: Increment monotonic counter[counter_idx].
 */
TEE_Result stm32_tamp_write_mcounter(int counter_idx);
uint32_t stm32_tamp_read_mcounter(int counter_idx);

bool stm32_tamp_are_secrets_blocked(void);
void stm32_tamp_block_secrets(void);
void stm32_tamp_unblock_secrets(void);
void stm32_tamp_erase_secrets(void);
void stm32_tamp_lock_boot_hardware_key(void);

/*
 * stm32_tamp_activate_tamp: Configure and activate one tamper (internal or
 * external).
 *
 * id: tamper id
 * mode: bitmask from TAMPER modes define:
 *       TAMP_ERASE/TAMP_NOERASE:
 *            TAMP_ERASE: when this tamp event raises secret will be erased.
 *            TAMP_NOERASE: when this event raises secured IPs will be locked
 *            until the acknowledge. If the callback confirms the TAMPER, it
 *            can manually erase secrets with stm32_tamp_erase_secrets().
 *       TAMP_NO_EVT_MASK/TAMP_EVT_MASK:
 *            TAMP_NO_EVT_MASK: normal behavior.
 *            TAMP_EVT_MASK: if the event is triggered, the event is masked and
 *            internally cleared by hardware. Secrets are not erased. Only
 *            applicable for EXT_TAMP1,2,3. This defines only the status at
 *            boot. To change mask while runtime stm32_tamp_set_mask() and
 *            stm32_tamp_unset_mask can be used.
 * callback: function to call when tamper is raised (cannot be NULL),
 *           called in interrupt context,
 *           Callback function returns a bitmask defining the action to take by
 *           the driver:
 *           TAMP_CB_RESET: will reset the board.
 *           TAMP_CB_ACK: this specific tamp is acknowledged (in case
 *           of no-erase tamper, blocked secret are unblocked).
 *
 * return: TEE_ERROR_BAD_PARAMETERS:
 *                   if 'id' is not a valid tamp id,
 *                   if callback is NULL,
 *                   if TAMP_EVT_MASK mode is set for a non supported 'id'.
 *         TEE_ERROR BAD_STATE
 *                   if driver wasn't previously initialized.
 *         TEE_ERROR ITEM_NOT_FOUND
 *                   if the activated external tamper wasn't previously
 *                   defined in the device tree.
 *         else TEE_SUCCESS.
 */
TEE_Result stm32_tamp_activate_tamp(enum stm32_tamp_id id, uint32_t mode,
				    uint32_t (*callback)(int id));

TEE_Result stm32_tamp_set_mask(enum stm32_tamp_id id);
TEE_Result stm32_tamp_unset_mask(enum stm32_tamp_id id);

/*
 * stm32_tamp_set_secure_bkpregs: Configure backup registers zone.
 * @conf - Configuration to be programmed
 */
TEE_Result stm32_tamp_set_secure_bkpregs(struct stm32_bkpregs_conf
					 *bkpregs_conf);

/*
 * stm32_tamp_set_config: Apply configuration.
 * Default one if no previous call to any of:
 * stm32_tamp_configure_passive()
 * stm32_tamp_configure_active()
 * stm32_tamp_configure_internal()
 * stm32_tamp_configure_external()
 * stm32_tamp_configure_secret_list()
 *
 */
TEE_Result stm32_tamp_set_config(void);

/* Compatibility tags */
#define TAMP_HAS_REGISTER_SECCFGR	BIT(0)
#define TAMP_HAS_REGISTER_PRIVCFGR	BIT(1)
#define TAMP_HAS_REGISTER_ERCFGR	BIT(2)
#define TAMP_HAS_REGISTER_ATCR2		BIT(3)
#define TAMP_HAS_REGISTER_CR3		BIT(4)
#define TAMP_HAS_CR2_SECRET_STATUS	BIT(5)
#define TAMP_SIZE_ATCR1_ATCKSEL_IS_4	BIT(7)

struct stm32_tamp_compat {
	int nb_monotonic_counter;
	uint32_t tags;
	struct stm32_tamp_conf *int_tamp;
	uint32_t int_tamp_size;
	struct stm32_tamp_conf *ext_tamp;
	uint32_t ext_tamp_size;
	const struct stm32_tamp_pin_map *pin_map;
	uint32_t pin_map_size;
};

struct stm32_tamp_platdata {
	struct io_pa_va base;
	struct clk *clock;
	int it;
	uint32_t passive_conf;
	uint32_t active_conf;
	uint32_t pins_conf;
	uint32_t out_pins;
	bool is_wakeup_source;
	struct stm32_tamp_compat *compat;
};

TEE_Result stm32_tamp_get_platdata(struct stm32_tamp_platdata *pdata);

#endif /* __DRIVERS_STM32_TAMP_H__ */
