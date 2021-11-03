/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2017-2021, STMicroelectronics
 */

#ifndef __STM32_BSEC_H
#define __STM32_BSEC_H

#include <compiler.h>
#include <stdint.h>
#include <tee_api.h>

#define BSEC_BITS_PER_WORD		(8U * sizeof(uint32_t))
#define BSEC_BYTES_PER_WORD		(sizeof(uint32_t))

/*
 * Load OTP from SAFMEM and provide its value
 * @value: Output read value
 * @otp_id: OTP number
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_shadow_read_otp(uint32_t *value, uint32_t otp_id);

/*
 * Copy SAFMEM OTP to BSEC data.
 * @otp_id: OTP number.
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_shadow_register(uint32_t otp_id);

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
TEE_Result stm32_bsec_permanent_lock_otp(uint32_t otp_id);

/*
 * Enable/disable debug service
 * @value: Value to write
 * Return a TEE_Result compliant return value
 */
#ifdef CFG_STM32_BSEC_WRITE
TEE_Result stm32_bsec_write_debug_conf(uint32_t value);
#else
static inline TEE_Result stm32_bsec_write_debug_conf(uint32_t value __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

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
 * Lock Upper OTP or Global programming or debug enable
 * @service: Service to lock, see header file
 * Return a TEE_Result compliant return value
 */
TEE_Result stm32_bsec_otp_lock(uint32_t service);

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
