// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, STMicroelectronics
 */

#include <assert.h>
#include <config.h>
#include <drivers/stm32_bsec.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/pm.h>
#include <kernel/boot.h>
#include <kernel/spinlock.h>
#include <limits.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <pta_bsec.h>
#include <util.h>

/* BSEC REGISTER OFFSET (base relative) */
#define BSEC_FVR(i)			(U(0x000) + 4U * (i))
#define BSEC_SPLOCK(i)			(U(0x800) + 4U * (i))
#define BSEC_SWLOCK(i)			(U(0x840) + 4U * (i))
#define BSEC_SRLOCK(i)			(U(0x880) + 4U * (i))
#define BSEC_OTPVLDR(i)			(U(0x8C0) + 4U * (i))
#define BSEC_SFSR(i)			(U(0x940) + 4U * (i))
#define BSEC_OTPCR			U(0xC04)
#define BSEC_WDR			U(0xC08)
#define BSEC_LOCKR			U(0xE10)
#define BSEC_DENR			U(0xE20)
#define BSEC_SR				U(0xE40)
#define BSEC_OTPSR			U(0xE44)
#define BSEC_VERR			U(0xFF4)
#define BSEC_IPIDR			U(0xFF8)

/* BSEC_SR register fields */
#define BSEC_SR_BUSY			BIT(0)
#define BSEC_SR_HVALID			BIT(1)
#define BSEC_SR_STATE_MASK		GENMASK_32(31, 26)
#define BSEC_SR_STATE_SHIFT		26U
#define BSEC_SR_STATE_OPEN		U(0x16)
#define BSEC_SR_STATE_CLOSED		U(0x0D)

/* BSEC_OTPCR register fields */
#define BSEC_OTPCR_PROG			BIT(13)
#define BSEC_OTPCR_PPLOCK		BIT(14)

/* BSEC_OTPSR register fields */
#define BSEC_OTPSR_BUSY			BIT(0)
#define BSEC_OTPSR_FUSEOK		BIT(1)
#define BSEC_OTPSR_HIDEUP		BIT(2)
#define BSEC_OTPSR_OTPNVIR		BIT(4)
#define BSEC_OTPSR_OTPERR		BIT(5)
#define BSEC_OTPSR_OTPSEC		BIT(6)
#define BSEC_OTPSR_PROGFAIL		BIT(16)
#define BSEC_OTPSR_DISTURBF		BIT(17)
#define BSEC_OTPSR_DEDF			BIT(18)
#define BSEC_OTPSR_SECF			BIT(19)
#define BSEC_OTPSR_PPLF			BIT(20)
#define BSEC_OTPSR_PPLMF		BIT(21)
#define BSEC_OTPSR_AMEF			BIT(22)

/* BSEC_LOCKR register fields */
#define BSEC_LOCKR_GWLOCK_MASK		BIT(0)
#define BSEC_LOCKR_GWLOCK_SHIFT		0U
#define BSEC_LOCKR_DENLOCK_MASK		BIT(1)
#define BSEC_LOCKR_DENLOCK_SHIFT	1U
#define BSEC_LOCKR_HKLOCK_MASK		BIT(2)
#define BSEC_LOCKR_HKLOCK_SHIFT		2U

/* BSEC_DENR register fields */
#define BSEC_DENR_DBGENA		BIT(1)
#define BSEC_DENR_NIDENA		BIT(2)
#define BSEC_DENR_DDBGEN		BIT(3)
#define BSEC_DENR_HDPEN			BIT(4)
#define BSEC_DENR_SPIDENA		BIT(5)
#define BSEC_DENR_SPNIDENA		BIT(6)
#define BSEC_DENR_SHDBGEN		BIT(7)
#define BSEC_DENR_DBGENM		BIT(8)
#define BSEC_DENR_NIDENM		BIT(9)
#define BSEC_DENR_SPIDENM		BIT(10)
#define BSEC_DENR_SPNIDENM		BIT(11)
#define BSEC_DENR_CFGSDIS		BIT(12)
#define BSEC_DENR_CP15SDIS_MASK		GENMASK_32(14, 13)
#define BSEC_DENR_CP15SDIS_SHIFT	13U
#define BSEC_DENR_ALL_MASK		GENMASK_32(14, 1)
#define BSEC_DENR_WRITE_CONF		U(0xDEB60000)

/* BSEC_SR register fields */
#define BSEC_SR_HVALID			BIT(1)
#define BSEC_SR_NVSTATES_MASK		GENMASK_32(31, 26)
#define BSEC_SR_NVSTATES_SHIFT		26U
#define BSEC_SR_NVSTATES_OPEN		U(0x16)
#define BSEC_SR_NVSTATES_CLOSED		U(0x0D)
#define BSEC_SR_NVSTATES_OTP_LOCKED	U(0x23)

/* BSEC_VERR register fields */
#define BSEC_VERR_MASK			GENMASK_32(7, 0)

/* 32 bit by OTP bank in each register */
#define BSEC_OTP_MASK			GENMASK_32(4, 0)
#define BSEC_OTP_BANK_SHIFT		5U

#define BSEC_IP_VERSION_1_0		U(0x10)
#define BSEC_IP_ID_3			U(0x100033)

#define MAX_NB_TRIES			3U

/* Timeout when polling on status */
#define BSEC_TIMEOUT_US			U(10000)

#define OTP_ACCESS_SIZE			12U

#define HIDEUP_ERROR	(LOCK_SHADOW_R | LOCK_SHADOW_W | LOCK_SHADOW_P |\
			 LOCK_ERROR)

/* OTP18 = BOOTROM_CONFIG_0-3: Security life-cycle word 2 */
#define OTP_SECURE_BOOT			18U
#ifdef CFG_STM32MP25x_REVA
#define OTP_CLOSED_SECURE		BIT(0)
#else
#define OTP_CLOSED_SECURE		GENMASK_32(3, 0)
#endif

struct nvmem_cell {
	char *name;
	uint32_t phandle;
	uint32_t otp_id;
	uint8_t bit_offset;
	size_t bit_len;
};

struct bsec_dev {
	struct io_pa_va base;
	unsigned int upper_base;
	unsigned int max_id;
	unsigned int lock;
	struct bsec_shadow *shadow;
#ifdef CFG_DT
	struct nvmem_cell *cells;
	size_t cell_count;
#endif
};

/* Magic use to indicated valid SHADOW = 'B' 'S' 'E' 'C' */
#define BSEC_MAGIC			0x42534543

struct bsec_shadow {
	uint32_t magic;
	uint32_t state;
	uint32_t value[OTP_MAX_SIZE];
	uint32_t status[OTP_MAX_SIZE];
};

/* Only 1 instance of BSEC is expected per platform */
static struct bsec_dev bsec_dev = {
	.lock = SPINLOCK_UNLOCK
};

static uint32_t bsec_lock(void)
{
	if (!bsec_dev.lock || !cpu_mmu_enabled())
		return 0;

	return cpu_spin_lock_xsave(&bsec_dev.lock);
}

static void bsec_unlock(uint32_t exceptions)
{
	if (!bsec_dev.lock || !cpu_mmu_enabled())
		return;

	cpu_spin_unlock_xrestore(&bsec_dev.lock, exceptions);
}

static vaddr_t bsec_base(void)
{
	return io_pa_or_va_secure(&bsec_dev.base, 1);
}

static uint32_t bsec_get_otp_status(void)
{
	return io_read32(bsec_base() + BSEC_OTPSR);
}

static TEE_Result bsec_poll_otp_status_busy(uint32_t *status)
{
	uint64_t timeout_ref = timeout_init_us(BSEC_TIMEOUT_US);

	while (!timeout_elapsed(timeout_ref))
		if (!(bsec_get_otp_status() & BSEC_OTPSR_BUSY))
			break;

	*status = bsec_get_otp_status();
	if (*status & BSEC_OTPSR_BUSY)
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}

/* get bank: id of U32 register associated to the OTP */
static uint32_t otp_bank(uint32_t otp)
{
	assert(otp <= bsec_dev.max_id);

	return ((otp & ~BSEC_OTP_MASK) >> BSEC_OTP_BANK_SHIFT);
}

/* get bit in the bank associated to the OTP */
static uint32_t otp_bit(uint32_t otp)
{
	return BIT(otp & BSEC_OTP_MASK);
}

static bool is_bsec_write_locked(void)
{
	return (io_read32(bsec_base() + BSEC_LOCKR) &
		BSEC_LOCKR_GWLOCK_MASK);
}

static TEE_Result shadow_otp(unsigned int otp)
{
	unsigned int i = 0U;
	TEE_Result result = TEE_ERROR_GENERIC;
	uint32_t status = 0U;

	/* if shadow is not allowed */
	if (bsec_dev.shadow->status[otp] & LOCK_SHADOW_R) {
		bsec_dev.shadow->status[otp] |= LOCK_ERROR;
		bsec_dev.shadow->value[otp] = 0x0U;

		return TEE_ERROR_GENERIC;
	}

	bsec_dev.shadow->status[otp] &= ~LOCK_ERROR;
	for (i = 0U; i < MAX_NB_TRIES; i++) {
		io_write32(bsec_base() + BSEC_OTPCR, otp);

		result = bsec_poll_otp_status_busy(&status);
		if (result)
			panic("BSEC busy timeout");
		/* Retry on error */
		if (status & (BSEC_OTPSR_AMEF | BSEC_OTPSR_DISTURBF |
			      BSEC_OTPSR_DEDF))
			continue;
		/* break for OTP correctly shadowed */
		break;
	}
	if (status & BSEC_OTPSR_PPLF)
		bsec_dev.shadow->status[otp] |= LOCK_PERM;
	if (i == MAX_NB_TRIES || status & (BSEC_OTPSR_PPLMF | BSEC_OTPSR_AMEF |
					   BSEC_OTPSR_DISTURBF |
					   BSEC_OTPSR_DEDF)) {
		bsec_dev.shadow->status[otp] |= LOCK_ERROR;
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static void check_reset_error(void)
{
	uint32_t status = bsec_get_otp_status();

	if (status & BSEC_OTPSR_OTPSEC)
		DMSG("BSEC reset single error correction detected");

	if ((status & BSEC_OTPSR_OTPNVIR) != BSEC_OTPSR_OTPNVIR)
		DMSG("BSEC virgin OTP word 0");

	if (status & BSEC_OTPSR_HIDEUP)
		DMSG("BSEC upper fuse not accessible");

	if (status & BSEC_OTPSR_OTPERR)
		panic("BSEC shadow error detected");

	if ((status & BSEC_OTPSR_FUSEOK) != BSEC_OTPSR_FUSEOK)
		panic("BSEC reset operations not completed");

	if (is_bsec_write_locked())
		panic("BSEC global write lock");
}

static bool is_fuse_shadowed(uint32_t otp)
{
	uint32_t bank = otp_bank(otp);
	uint32_t mask = otp_bit(otp);
	uint32_t bank_value = 0U;

	bank_value = io_read32(bsec_base() + BSEC_SFSR(bank));

	if (bank_value & mask)
		return true;

	return false;
}

/*
 * bsec_read_otp: read an OTP data value.
 * val: read value.
 * otp: OTP number.
 * return value: TEE_SUCCESS if no error.
 */
TEE_Result stm32_bsec_read_otp(uint32_t *val, uint32_t otp)
{
	TEE_Result result = TEE_ERROR_GENERIC;

	assert(val && otp <= bsec_dev.max_id);

	/* for non-secure OTP: only return the shadow value */
	if (!(bsec_dev.shadow->status[otp] & STATUS_SECURE)) {
		*val = bsec_dev.shadow->value[otp];

		return TEE_SUCCESS;
	}

	/* for secure OTP, reload fuse word */
	*val = 0U;
	result = shadow_otp(otp);
	if (!result)
		*val = io_read32(bsec_base() + BSEC_FVR(otp));

	return result;
}

/*
 * bsec_shadow_read_otp: Load OTP from SAFMEM and provide its value
 * val: read value.
 * otp: OTP number.
 * return value: TEE_SUCCESS if no error.
 */
TEE_Result stm32_bsec_shadow_read_otp(uint32_t *val, uint32_t otp)
{
	TEE_Result result = TEE_SUCCESS;

	assert(val && otp <= bsec_dev.max_id);

	/* for non-secure OTP: only return the shadow value */
	if (!(bsec_dev.shadow->status[otp] & STATUS_SECURE)) {
		*val = bsec_dev.shadow->value[otp];

		return TEE_SUCCESS;
	}

	/* for secure OTP, reload fuse word if not shadowed */
	*val = 0U;
	if (!is_fuse_shadowed(otp))
		result = shadow_otp(otp);
	if (!result)
		*val = io_read32(bsec_base() + BSEC_FVR(otp));

	return result;
}

/*
 * bsec_write_otp: write value in BSEC data register.
 * val: value to write.
 * otp: OTP number.
 * return value: TEE_SUCCESS if no error.
 */
TEE_Result stm32_bsec_write_otp(uint32_t val, uint32_t otp)
{
	uint32_t exceptions = 0U;
	bool value = false;

	assert(otp <= bsec_dev.max_id);

	if (is_bsec_write_locked())
		return TEE_ERROR_ACCESS_DENIED;

	/* for HW shadowed OTP, update value in FVR register */
	if (is_fuse_shadowed(otp)) {
		stm32_bsec_read_sw_lock(otp, &value);
		if (value) {
			DMSG("BSEC: OTP %"PRIu32" is locked, write ignored",
			     otp);
			return TEE_ERROR_ACCESS_DENIED;
		}

		exceptions = bsec_lock();

		io_write32(bsec_base() + BSEC_FVR(otp), val);

		bsec_unlock(exceptions);
	} else if ((bsec_dev.shadow->status[otp] & STATUS_SECURE)) {
		/* update of secure and not-shadowed OTP is not allowed */
		return TEE_ERROR_ACCESS_DENIED;
	}

	/* Update the shadow memory when it is allowed */
	if (!(bsec_dev.shadow->status[otp] & STATUS_SECURE)) {
		bsec_dev.shadow->value[otp] = val;
		bsec_dev.shadow->status[otp] &= ~LOCK_ERROR;
	}

	return TEE_SUCCESS;
}

#ifdef CFG_STM32_BSEC_WRITE
static TEE_Result check_program_error(uint32_t otp __maybe_unused,
				      uint32_t status __maybe_unused)
{
	if (status & BSEC_OTPSR_PROGFAIL) {
		EMSG("BSEC program %"PRIu32" error %#"PRIx32, otp, status);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result stm32_bsec_program_otp(uint32_t val, uint32_t otp)
{
	TEE_Result result = TEE_ERROR_GENERIC;
	unsigned int i = 0U;
	bool value = false;
	uint32_t exceptions = 0U;
	uint32_t fvr = 0U;

	assert(otp <= bsec_dev.max_id);

	if (is_bsec_write_locked())
		return TEE_ERROR_ACCESS_DENIED;

	result = stm32_bsec_read_sp_lock(otp, &value);
	if (result) {
		EMSG("BSEC: %"PRIu32" Sticky-prog bit read Error %"PRIu32,
		     otp, result);
		return result;
	}

	if (value) {
		DMSG("BSEC: OTP locked, prog will be ignored");
		return TEE_ERROR_ACCESS_DENIED;
	}

	exceptions = bsec_lock();

	bsec_dev.shadow->value[otp] = 0x0U;
	bsec_dev.shadow->status[otp] |= LOCK_ERROR;

	for (i = 0U; i < MAX_NB_TRIES; i++) {
		uint32_t status = 0U;

		io_write32(bsec_base() + BSEC_WDR, val);
		io_write32(bsec_base() + BSEC_OTPCR, otp | BSEC_OTPCR_PROG);

		result = bsec_poll_otp_status_busy(&status);
		if (result)
			panic("BSEC busy timeout");

		result = check_program_error(otp, status);
		if (!result)
			break;
	}
	if (i == MAX_NB_TRIES) {
		result = TEE_ERROR_GENERIC;
		EMSG("BSEC program %"PRIu32" retry", otp);
	}

	/* update the shadow */
	if (!result) {
		stm32_bsec_read_sr_lock(otp, &value);
		/* if reload is locked: directly write in shadow register */
		if (value) {
			stm32_bsec_read_sw_lock(otp, &value);
			/*
			 * update value in FVR register for HW shadowed OTP
			 * if they are not shadow wrtite locked
			 */
			if (is_fuse_shadowed(otp) && !value) {
				io_write32(bsec_base() + BSEC_FVR(otp), val);
				fvr = io_read32(bsec_base() + BSEC_FVR(otp));
			} else {
				fvr = val;
			}
		} else {
			shadow_otp(otp); /* reload the fuse word */
			fvr = io_read32(bsec_base() + BSEC_FVR(otp));
		}
		if (fvr != val)
			EMSG("BSEC shadow %"PRIu32" invalid: %08x, write= %08x",
			     otp, fvr, val);

		/* update the shadow memory if allowed */
		if (!(bsec_dev.shadow->status[otp] & STATUS_SECURE)) {
			bsec_dev.shadow->value[otp] = fvr;
			bsec_dev.shadow->status[otp] &= ~LOCK_ERROR;
		}
	}

	bsec_unlock(exceptions);

	return result;
}
#endif

TEE_Result stm32_bsec_write_debug_conf(uint32_t val)
{
	TEE_Result result = TEE_ERROR_GENERIC;
	uint32_t exceptions = 0U;

	if (is_bsec_write_locked())
		return TEE_ERROR_ACCESS_DENIED;

	exceptions = bsec_lock();

	io_clrsetbits32(bsec_base() + BSEC_DENR, BSEC_DENR_ALL_MASK,
			val | BSEC_DENR_WRITE_CONF);


	if (stm32_bsec_read_debug_conf() == val)
		result = TEE_SUCCESS;

	bsec_unlock(exceptions);

	return result;
}

uint32_t stm32_bsec_read_debug_conf(void)
{
	return io_read32(bsec_base() + BSEC_DENR) & BSEC_DENR_ALL_MASK;
}

/*
 * bsec_get_version: return BSEC version.
 */
static uint32_t bsec_get_version(void)
{
	return io_read32(bsec_base() + BSEC_VERR) & BSEC_VERR_MASK;
}

/*
 * bsec_get_id: return BSEC ID.
 */
static uint32_t bsec_get_id(void)
{
	return io_read32(bsec_base() + BSEC_IPIDR);
}

/*
 * bsec_set_sr_lock: set shadow-read lock.
 * otp: OTP number.
 * return value: TEE_SUCCESS if no error.
 */
TEE_Result stm32_bsec_set_sr_lock(uint32_t otp)
{
	TEE_Result result = TEE_ERROR_GENERIC;
	uint32_t bank = otp_bank(otp);
	uint32_t bank_value = 0U;
	uint32_t mask = otp_bit(otp);
	uint32_t exceptions = 0U;

	assert(otp <= bsec_dev.max_id);

	if (is_bsec_write_locked())
		return TEE_ERROR_ACCESS_DENIED;

	exceptions = bsec_lock();

	bank_value = io_read32(bsec_base() + BSEC_SRLOCK(bank));

	if (bank_value & mask) {
		/* The lock is already set */
		result = TEE_SUCCESS;
	} else {
		bank_value = bank_value | mask;

		/*
		 * We can write 0 in all other OTP bits with no effect,
		 * even if the lock is activated.
		 */
		io_write32(bsec_base() + BSEC_SRLOCK(bank), bank_value);
		bsec_dev.shadow->status[otp] |= LOCK_SHADOW_R;
		result = TEE_SUCCESS;
	}

	bsec_unlock(exceptions);

	return result;
}

TEE_Result stm32_bsec_read_sr_lock(uint32_t otp, bool *value)
{
	assert(value && otp <= bsec_dev.max_id);

	*value = bsec_dev.shadow->status[otp] & LOCK_SHADOW_R;

	return TEE_SUCCESS;
}

/*
 * bsec_set_sw_lock: set shadow-write lock.
 * otp: OTP number.
 * return value: TEE_SUCCESS if no error.
 */
TEE_Result stm32_bsec_set_sw_lock(uint32_t otp)
{
	TEE_Result result = TEE_ERROR_GENERIC;
	uint32_t bank = otp_bank(otp);
	uint32_t mask = otp_bit(otp);
	uint32_t bank_value = 0U;
	uint32_t exceptions = 0U;

	assert(otp <= bsec_dev.max_id);

	if (is_bsec_write_locked())
		return TEE_ERROR_ACCESS_DENIED;

	exceptions = bsec_lock();

	bank_value = io_read32(bsec_base() + BSEC_SWLOCK(bank));

	if (bank_value & mask) {
		/* The lock is already set */
		result = TEE_SUCCESS;
	} else {
		bank_value = bank_value | mask;

		/*
		 * We can write 0 in all other OTP bits with no effect,
		 * even if the lock is activated.
		 */
		io_write32(bsec_base() + BSEC_SWLOCK(bank), bank_value);
		bsec_dev.shadow->status[otp] |= LOCK_SHADOW_W;
		result = TEE_SUCCESS;
	}

	bsec_unlock(exceptions);

	return result;
}

TEE_Result stm32_bsec_read_sw_lock(uint32_t otp, bool *value)
{
	assert(value && otp <= bsec_dev.max_id);

	*value = bsec_dev.shadow->status[otp] & LOCK_SHADOW_W;

	/* Fuse words 364 to 375 are accessible only in ROM code */
	if (otp >= 364)
		*value = LOCK_SHADOW_W;

	return TEE_SUCCESS;
}

TEE_Result stm32_bsec_set_sp_lock(uint32_t otp)
{
	TEE_Result result = TEE_ERROR_GENERIC;
	uint32_t bank = otp_bank(otp);
	uint32_t bank_value = 0U;
	uint32_t mask = otp_bit(otp);
	uint32_t exceptions = 0U;

	assert(otp <= bsec_dev.max_id);

	if (is_bsec_write_locked())
		return TEE_ERROR_ACCESS_DENIED;

	exceptions = bsec_lock();

	bank_value = io_read32(bsec_base() + BSEC_SPLOCK(bank));

	if (bank_value & mask) {
		/* The lock is already set */
		result = TEE_SUCCESS;
	} else {
		bank_value = bank_value | mask;

		/*
		 * We can write 0 in all other OTP bits with no effect,
		 * even if the lock is activated.
		 */
		io_write32(bsec_base() + BSEC_SPLOCK(bank), bank_value);
		bsec_dev.shadow->status[otp] |= LOCK_SHADOW_P;
		result = TEE_SUCCESS;
	}

	bsec_unlock(exceptions);

	return result;
}

TEE_Result stm32_bsec_read_sp_lock(uint32_t otp, bool *value)
{
	assert(value && otp <= bsec_dev.max_id);

	*value = bsec_dev.shadow->status[otp] & LOCK_SHADOW_P;

	return TEE_SUCCESS;
}

#ifdef CFG_STM32_BSEC_WRITE
TEE_Result stm32_bsec_permanent_lock_otp(uint32_t otp)
{
	TEE_Result result = TEE_ERROR_GENERIC;
	unsigned int i = 0U;
	uint32_t exceptions = 0U;

	assert(otp <= bsec_dev.max_id);

	if (is_bsec_write_locked())
		return TEE_ERROR_ACCESS_DENIED;

	exceptions = bsec_lock();

	io_write32(bsec_base() + BSEC_WDR, 0U);

	for (i = 0U; i < MAX_NB_TRIES; i++) {
		uint32_t status = 0U;

		io_write32(bsec_base() + BSEC_OTPCR,
			   otp | BSEC_OTPCR_PPLOCK | BSEC_OTPCR_PROG);

		result = bsec_poll_otp_status_busy(&status);
		if (result)
			panic("BSEC busy timeout");

		result = check_program_error(otp, status);
		if (!result)
			break;
	}
	if (i == MAX_NB_TRIES) {
		result = TEE_ERROR_GENERIC;
		EMSG("BSEC program %"PRIu32" retry", otp);
	}

	if (!result)
		bsec_dev.shadow->status[otp] |= LOCK_PERM;

	bsec_unlock(exceptions);

	return result;
}
#endif

TEE_Result stm32_bsec_read_permanent_lock(uint32_t otp, bool *value)
{
	assert(value);
	if (otp > bsec_dev.max_id)
		return TEE_ERROR_BAD_PARAMETERS;

	*value = bsec_dev.shadow->status[otp] & LOCK_PERM;

	return TEE_SUCCESS;
}

bool stm32_bsec_can_access_otp(uint32_t otp)
{
	if (bsec_dev.shadow->magic != BSEC_MAGIC)
		return false;

	if (bsec_dev.shadow->state == BSEC_STATE_INVALID)
		return false;

	if (otp < bsec_dev.upper_base)
		return true;

	/* manage HIDEUP */
	if ((bsec_dev.shadow->status[otp] & HIDEUP_ERROR) == HIDEUP_ERROR)
		return false;

	return true;
}

bool stm32_bsec_nsec_can_access_otp(uint32_t otp)
{
	if (bsec_dev.shadow->magic != BSEC_MAGIC)
		return false;

	if (bsec_dev.shadow->state == BSEC_STATE_INVALID)
		return false;

	/* lower OTP are accessible by non secure */
	if (otp < bsec_dev.upper_base)
		return true;

	/* manage HIDEUP */
	if ((bsec_dev.shadow->status[otp] & HIDEUP_ERROR) == HIDEUP_ERROR)
		return false;

	/* upper OTP with provisioning tag and not locked are accessible */
	if ((bsec_dev.shadow->status[otp] & STATUS_PROVISIONING) ==
	     STATUS_PROVISIONING &&
	    (bsec_dev.shadow->status[otp] & LOCK_PERM) != LOCK_PERM)
		return true;

	return false;
}

TEE_Result stm32_bsec_get_state(uint32_t *state)
{
	assert(state);

	if (bsec_dev.shadow->magic == BSEC_MAGIC)
		*state = bsec_dev.shadow->state;
	else
		*state = BSEC_STATE_INVALID;

	return TEE_SUCCESS;
}

static uint32_t init_state(uint32_t status)
{
	uint32_t bsec_sr = 0U, nvstates = 0U, state = 0U;

	bsec_sr = io_read32(bsec_base() + BSEC_SR);

	state = BSEC_STATE_INVALID;
	if (status & BSEC_OTPSR_FUSEOK) {
		/* NVSTATES is only valid if FUSEOK */
		nvstates = (bsec_sr & BSEC_SR_NVSTATES_MASK) >>
			   BSEC_SR_NVSTATES_SHIFT;

		/* Only 1 supported state = CLOSED */
		if (nvstates != BSEC_SR_NVSTATES_CLOSED) {
			state = BSEC_STATE_INVALID;
			EMSG("BSEC invalid nvstates %#x\n", nvstates);
		} else {
			state = BSEC_STATE_SEC_OPEN;
			if (bsec_dev.shadow->value[OTP_SECURE_BOOT] &
			    OTP_CLOSED_SECURE)
				state = BSEC_STATE_SEC_CLOSED;
		}
	}

	return state;
}

static void stm32_bsec_shadow_load(uint32_t status)
{
	unsigned int otp = 0U, bank = 0U;
	uint32_t exceptions = 0U;
	uint32_t srlock[OTP_ACCESS_SIZE] = { 0U };
	uint32_t swlock[OTP_ACCESS_SIZE] = { 0U };
	uint32_t splock[OTP_ACCESS_SIZE] = { 0U };
	uint32_t sfsr[OTP_ACCESS_SIZE] = { 0U };
	uint32_t otpvldr[OTP_ACCESS_SIZE] = { 0U };
	uint32_t mask = 0U;
	unsigned int max_id = bsec_dev.max_id;

	memset(bsec_dev.shadow, 0, sizeof(*bsec_dev.shadow));
	bsec_dev.shadow->magic = BSEC_MAGIC;
	bsec_dev.shadow->state = BSEC_STATE_INVALID;

	exceptions = bsec_lock();

	/* HIDEUP: read and write not possible in upper region */
	if (status & BSEC_OTPSR_HIDEUP) {
		for (otp = bsec_dev.upper_base;
		     otp <= bsec_dev.max_id ; otp++) {
			bsec_dev.shadow->status[otp] |= HIDEUP_ERROR;
			bsec_dev.shadow->value[otp] = 0x0U;
		}
		max_id = bsec_dev.upper_base - 1;
	}

	for (bank = 0U; bank < OTP_ACCESS_SIZE; bank++) {
		srlock[bank] = io_read32(bsec_base() + BSEC_SRLOCK(bank));
		swlock[bank] = io_read32(bsec_base() + BSEC_SWLOCK(bank));
		splock[bank] = io_read32(bsec_base() + BSEC_SPLOCK(bank));
		sfsr[bank] = io_read32(bsec_base() + BSEC_SFSR(bank));
		otpvldr[bank] = io_read32(bsec_base() + BSEC_OTPVLDR(bank));
	}

	for (otp = 0U; otp <= max_id ; otp++) {
		bank = otp_bank(otp);
		mask = otp_bit(otp);

		if (srlock[bank] & mask)
			bsec_dev.shadow->status[otp] |= LOCK_SHADOW_R;
		if (swlock[bank] & mask)
			bsec_dev.shadow->status[otp] |= LOCK_SHADOW_W;
		if (splock[bank] & mask)
			bsec_dev.shadow->status[otp] |= LOCK_SHADOW_P;

		if (bsec_dev.shadow->status[otp] & STATUS_SECURE)
			continue;

		/* Fuse words 364 to 375 are accessible only in ROM code */
		if (otp >= 364) {
			bsec_dev.shadow->status[otp] |= LOCK_SHADOW_R;
			continue;
		}

		/* request shadow if not yet done or not valid */
		if (!(sfsr[bank] & mask) || !(otpvldr[bank] & mask))
			shadow_otp(otp);

		bsec_dev.shadow->value[otp] = io_read32(bsec_base() +
					      BSEC_FVR(otp));
	}

	bsec_unlock(exceptions);
}

static void stm32_bsec_shadow_init(bool force_load)
{
	uint32_t status = bsec_get_otp_status();

	/* update shadow when forced or invalid */
	if (force_load || bsec_dev.shadow->magic != BSEC_MAGIC)
		stm32_bsec_shadow_load(status);

	/* always update status */
	bsec_dev.shadow->state = init_state(status);
	if ((bsec_dev.shadow->state & BSEC_STATE_MASK) == BSEC_STATE_INVALID)
		panic("BSEC invalid state");
}

TEE_Result stm32_bsec_find_otp_in_nvmem_layout(const char *name,
					       uint32_t *otp_id,
					       uint8_t *otp_bit_offset,
					       size_t *otp_bit_len)
{
	size_t i = 0U;

	if (!name)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0U; i < bsec_dev.cell_count; i++) {
		if (!bsec_dev.cells[i].name ||
		    strcmp(name, bsec_dev.cells[i].name))
			continue;

		if (otp_id)
			*otp_id = bsec_dev.cells[i].otp_id;

		if (otp_bit_offset)
			*otp_bit_offset = bsec_dev.cells[i].bit_offset;

		if (otp_bit_len)
			*otp_bit_len = bsec_dev.cells[i].bit_len;

		DMSG("nvmem %s = %zu: %"PRIu32" bit offset: %u, length: %zu",
		     name, i, bsec_dev.cells[i].otp_id,
		     bsec_dev.cells[i].bit_offset, bsec_dev.cells[i].bit_len);

		return TEE_SUCCESS;
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result stm32_bsec_find_otp_by_phandle(const uint32_t phandle,
					  uint32_t *otp_id,
					  uint8_t *otp_bit_offset,
					  size_t *otp_bit_len)
{
	size_t i = 0;

	if (!phandle)
		return TEE_ERROR_GENERIC;

	for (i = 0U; i < bsec_dev.cell_count; i++) {
		if (bsec_dev.cells[i].phandle != phandle)
			continue;

		if (otp_id)
			*otp_id = bsec_dev.cells[i].otp_id;

		if (otp_bit_offset)
			*otp_bit_offset = bsec_dev.cells[i].bit_offset;

		if (otp_bit_len)
			*otp_bit_len = bsec_dev.cells[i].bit_len;

		DMSG("nvmem %"PRIu32" = %zu: %"PRIu32" bit offset: %u, length: %zu",
		     phandle, i, bsec_dev.cells[i].otp_id,
		     bsec_dev.cells[i].bit_offset, bsec_dev.cells[i].bit_len);

		return TEE_SUCCESS;
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

static void save_dt_nvmem_layout(void *fdt, int bsec_node)
{
	int cell_max = 0;
	int cell_cnt = 0;
	int node = 0;
	unsigned int otp = 0U, otp_nb = 0U;

	fdt_for_each_subnode(node, fdt, bsec_node)
		cell_max++;
	if (!cell_max)
		return;

	bsec_dev.cells = calloc(cell_max, sizeof(struct nvmem_cell));
	if (!bsec_dev.cells)
		panic("Could not create nvmem layout");

	fdt_for_each_subnode(node, fdt, bsec_node) {
		paddr_t reg_offset = 0;
		size_t reg_length = 0;
		const char *name = NULL;
		const char *s = NULL;
		int len = 0;
		struct nvmem_cell *cell = &bsec_dev.cells[cell_cnt];
		uint32_t bits[2] = { };

		name = fdt_get_name(fdt, node, &len);
		if (!name || !len)
			continue;

		cell->phandle = fdt_get_phandle(fdt, node);

		reg_offset = _fdt_reg_base_address(fdt, node);
		reg_length = _fdt_reg_size(fdt, node);

		if (reg_offset == DT_INFO_INVALID_REG ||
		    reg_length == DT_INFO_INVALID_REG_SIZE) {
			IMSG("Malformed nvmem %s: ignored", name);
			continue;
		}

		cell->otp_id = reg_offset / sizeof(uint32_t);
		assert(cell->otp_id <= bsec_dev.max_id);
		cell->bit_offset = (reg_offset % sizeof(uint32_t)) * CHAR_BIT;
		otp_nb = reg_length / sizeof(uint32_t);
		cell->bit_len = otp_nb * sizeof(uint32_t) * CHAR_BIT;

		if (!_fdt_read_uint32_array(fdt, node, "bits", bits, 2)) {
			assert(bits[0] <= 7 && bits[1] >= 1);
			cell->bit_offset += bits[0];
			cell->bit_len = (size_t)bits[1];
		}

		s = strchr(name, '@');
		if (s)
			len = s - name;

		cell->name = strndup(name, len);
		if (!cell->name)
			panic();

		cell_cnt++;
		DMSG("nvmem[%d] = %s %"PRIu32"bit offset: %u, length: %zu",
		     cell_cnt, cell->name, cell->otp_id,
		     cell->bit_offset, cell->bit_len);

		/* check if shadowing is not allowed */
		if (fdt_getprop(fdt, node, "st,secure-otp", NULL)) {
			for (otp = cell->otp_id;
			     otp < cell->otp_id + otp_nb; otp++)
				bsec_dev.shadow->status[otp] |= STATUS_SECURE;
		}
		/* check if provisioning is allowed */
		else if (fdt_getprop(fdt, node,
				     "st,non-secure-otp-provisioning", NULL)) {
			for (otp = cell->otp_id;
			     otp < cell->otp_id + otp_nb; otp++)
				bsec_dev.shadow->status[otp] |=
					STATUS_PROVISIONING;
		}
	}

	if (cell_cnt != cell_max) {
		bsec_dev.cells = realloc(bsec_dev.cells,
					 cell_cnt * sizeof(struct nvmem_cell));
		if (!bsec_dev.cells)
			panic();
	}

	bsec_dev.cell_count = cell_cnt;
}

static void initialize_bsec_from_dt(void)
{
	void *fdt = NULL;
	int node = 0;
	struct dt_node_info bsec_info = { };

	fdt = get_embedded_dt();
	node = fdt_node_offset_by_compatible(fdt, 0, "st,stm32mp25-bsec");
	if (node < 0)
		panic();

	_fdt_fill_device_info(fdt, &bsec_info, node);

	if (bsec_info.reg != bsec_dev.base.pa ||
	    !(bsec_info.status & DT_STATUS_OK_SEC))
		panic();

	save_dt_nvmem_layout(fdt, node);
}

static TEE_Result
stm32_bsec_pm(enum pm_op op, unsigned int pm_hint,
	      const struct pm_callback_handle *pm_handle __unused)
{
	if (!PM_HINT_IS_STATE(pm_hint, CONTEXT))
		return TEE_SUCCESS;

	if (op == PM_OP_RESUME) {
		/* treat BSEC error */
		check_reset_error();

		/* re initialize the shadow */
		stm32_bsec_shadow_init(false);
	}

	return TEE_SUCCESS;
}

static TEE_Result initialize_bsec(void)
{
	struct stm32_bsec_static_cfg cfg = { };
	vaddr_t va = 0;

	plat_bsec_get_static_cfg(&cfg);

	va = core_mmu_get_va(cfg.shadow, MEM_AREA_RAM_SEC, SIZE_4K);
	if (!va)
		return TEE_ERROR_GENERIC;

	bsec_dev.base.pa = cfg.base;
	bsec_dev.shadow = (struct bsec_shadow *)va;
	bsec_dev.upper_base = cfg.upper_start;
	bsec_dev.max_id = cfg.max_id;

	initialize_bsec_from_dt();

	if ((bsec_get_version() != BSEC_IP_VERSION_1_0) ||
	    (bsec_get_id() != BSEC_IP_ID_3))
		panic("BSEC probe wrong IP version/ID\n");

	check_reset_error();

	/* initialize the shadow */
	stm32_bsec_shadow_init(true);

	if (IS_ENABLED(CFG_PM))
		register_pm_core_service_cb(stm32_bsec_pm, NULL, "stm32-bsec");

	return TEE_SUCCESS;
}

early_init(initialize_bsec);
