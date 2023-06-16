/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2017-2021, STMicroelectronics
 */

#ifndef __STM32_BSEC_H
#define __STM32_BSEC_H

#include <compiler.h>
#include <stdint.h>
#include <tee_api.h>
#include <types_ext.h>

/* BSEC_DEBUG */
#define BSEC_HDPEN			BIT(4)
#define BSEC_SPIDEN			BIT(5)
#define BSEC_SPINDEN			BIT(6)
#define BSEC_DBGSWGEN			BIT(10)
#define BSEC_DEBUG_ALL			(BSEC_HDPEN | \
					 BSEC_SPIDEN | \
					 BSEC_SPINDEN | \
					 BSEC_DBGSWGEN)

#define BSEC_BITS_PER_WORD		(8U * sizeof(uint32_t))
#define BSEC_BYTES_PER_WORD		(sizeof(uint32_t))

/*
 * Structure and API function for BSEC driver to get some platform data.
 *
 * @base: BSEC interface registers physical base address
 * @shadow: BSEC shadow base address
 * @upper_start: Base ID for the BSEC upper words in the platform
 * @max_id: Max value for BSEC word ID for the platform
 */
struct stm32_bsec_static_cfg {
	paddr_t base;
	paddr_t shadow;
	unsigned int upper_start;
	unsigned int max_id;
};

void plat_bsec_get_static_cfg(struct stm32_bsec_static_cfg *cfg);

/*
 * Load OTP from SAFMEM and provide its value
 * @value: Output read value
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_shadow_read_otp(uint32_t *value, uint32_t otp_id);

/*
 * Read an OTP data value
 * @value: Output read value
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_read_otp(uint32_t *value, uint32_t otp_id);

/*
 * Write value in BSEC data register
 * @value: Value to write
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_write_otp(uint32_t value, uint32_t otp_id);

/*
 * Program a bit in SAFMEM without BSEC data refresh
 * @value: Value to program.
 * @otp_id: OTP number.
 * Return a TEE_Result compliant return value
 */
#ifdef CFG_STM32_BSEC_WRITE
TEE_Result stm32_bsec_program_otp(uint32_t value, uint32_t otp_id);
#else
static inline TEE_Result stm32_bsec_program_otp(uint32_t value __unused,
						uint32_t otp_id __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

/*
 * Permanent lock of OTP in SAFMEM
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
#ifdef CFG_STM32_BSEC_WRITE
TEE_Result stm32_bsec_permanent_lock_otp(uint32_t otp_id);
#else
static inline TEE_Result stm32_bsec_permanent_lock_otp(uint32_t otp_id __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

/*
 * Enable/disable debug service
 * @value: Value to write
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_write_debug_conf(uint32_t value);

/* Return debug configuration read from BSEC */
uint32_t stm32_bsec_read_debug_conf(void);

/*
 * Write shadow-read lock
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_set_sr_lock(uint32_t otp_id);

/*
 * Read shadow-read lock
 * @otp_id: OTP number
 * @locked: (out) true if shadow-read is locked, false if not locked.
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_read_sr_lock(uint32_t otp_id, bool *locked);

/*
 * Write shadow-write lock
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_set_sw_lock(uint32_t otp_id);

/*
 * Read shadow-write lock
 * @otp_id: OTP number
 * @locked: (out) true if shadow-write is locked, false if not locked.
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_read_sw_lock(uint32_t otp_id, bool *locked);

/*
 * Write shadow-program lock
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_set_sp_lock(uint32_t otp_id);

/*
 * Read shadow-program lock
 * @otp_id: OTP number
 * @locked: (out) true if shadow-program is locked, false if not locked.
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_read_sp_lock(uint32_t otp_id, bool *locked);

/*
 * Read permanent lock status
 * @otp_id: OTP number
 * @locked: (out) true if permanent lock is locked, false if not locked.
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_read_permanent_lock(uint32_t otp_id, bool *locked);

/*
 * Return true if OTP can be read checking ID and invalid state
 * @otp_id: OTP number
 */
bool stm32_bsec_can_access_otp(uint32_t otp_id);

/*
 * Return true if non-secure world is allowed to read the target OTP
 * @otp_id: OTP number
 */
bool stm32_bsec_nsec_can_access_otp(uint32_t otp_id);

/*
 * Find and get OTP location from its name.
 * @name: sub-node name to look up.
 * @otp_id: pointer to read OTP number or NULL.
 * @otp_bit_offset: pointer to read offset in OTP in bits or NULL.
 * @otp_bit_len: pointer to read OTP length in bits or NULL.
 * Return a TEE_Result compliant status
 */
TEE_Result stm32_bsec_find_otp_in_nvmem_layout(const char *name,
					       uint32_t *otp_id,
					       uint8_t *otp_bit_offset,
					       size_t *otp_bit_len);

/*
 * Find and get OTP location from its phandle.
 * @phandle: sub-node phandle to look up.
 * @otp_id: pointer to read OTP number or NULL.
 * @otp_bit_offset: pointer to read offset in OTP in bits or NULL.
 * @otp_bit_len: pointer to read OTP length in bits or NULL.
 * Return a TEE_Result compliant status
 */
TEE_Result stm32_bsec_find_otp_by_phandle(const uint32_t phandle,
					  uint32_t *otp_id,
					  uint8_t *otp_bit_offset,
					  size_t *otp_bit_len);

/*
 * get BSEC global state.
 * @state: global state
 *           [1:0] BSEC state
 *             00b: Sec Open
 *             01b: Sec Closed
 *             11b: Invalid
 *           [8]: Hardware Key set = 1b
 * Return a TEE_Result compliant status
 */
TEE_Result stm32_bsec_get_state(uint32_t *state);

#define BSEC_STATE_SEC_OPEN	U(0x0)
#define BSEC_STATE_SEC_CLOSED	U(0x1)
#define BSEC_STATE_INVALID	U(0x3)

#define BSEC_HARDWARE_KEY	BIT(8)

#endif /*__STM32_BSEC_H*/
