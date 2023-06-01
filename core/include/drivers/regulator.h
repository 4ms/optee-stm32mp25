/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020-2021, STMicroelectronics - All Rights Reserved
 */
#ifndef DRIVERS_REGULATOR_H
#define DRIVERS_REGULATOR_H

#include <sys/queue.h>
#include <tee_api_types.h>
#include <util.h>

const char *plat_get_lp_mode_name(int mode);
int plat_get_lp_mode_count(void);

/*
 * Consumer interface
 */

/* regulator-always-on : regulator should never be disabled */
#define REGUL_ALWAYS_ON		BIT(0)
/*
 * regulator-boot-on:
 * It's expected that this regulator was left on by the bootloader.
 * The core shouldn't prevent it from being turned off later.
 * The regulator is needed to exit from suspend so it is turned on during suspend entry.
 */
#define REGUL_BOOT_ON		BIT(1)

/*
 * ST proprietary flags: to be in a private struct
 * To move to driver private.
 */

/* regulator-over-current-protection: Enable over current protection. */
#define REGUL_OCP		BIT(2)
/* regulator-active-discharge: enable active discharge. */
#define REGUL_ACTIVE_DISCHARGE	BIT(3)
/* regulator-pull-down: Enable pull down resistor when the regulator is disabled. */
#define REGUL_PULL_DOWN		BIT(4)
/*
 * st,mask-reset: set mask reset for the regulator, meaning that the regulator
 * setting is maintained during pmic reset.
 */
#define REGUL_MASK_RESET	BIT(5)
/* st,regulator-sink-source: set the regulator in sink source mode */
#define REGUL_SINK_SOURCE	BIT(6)
/* st,regulator-bypass: set the regulator in bypass mode */
#define REGUL_ENABLE_BYPASS	BIT(7)

struct rdev *regulator_get_by_node_name(const char *node_name);
struct rdev *regulator_get_by_regulator_name(const char *reg_name);
struct rdev *regulator_get_by_supply_name(const void *fdt, int node,
					  const char *name);

TEE_Result regulator_enable(struct rdev *rdev);
TEE_Result regulator_disable(struct rdev *rdev);
bool regulator_is_enabled(const struct rdev *rdev);

TEE_Result regulator_set_voltage(struct rdev *rdev, uint16_t level_mv);
TEE_Result regulator_set_min_voltage(struct rdev *rdev);
TEE_Result regulator_get_voltage(const struct rdev *rdev, uint16_t *level_mv);

TEE_Result regulator_list_voltages(struct rdev *rdev, uint16_t **levels,
				   size_t *count);
void regulator_get_range(const struct rdev *rdev, uint16_t *min_mv,
			 uint16_t *max_mv);
TEE_Result regulator_set_flag(struct rdev *rdev, uint16_t flag);

/*
 * Driver Interface
 */

/* suspend() arguments */
#define LP_STATE_OFF		BIT(0)
#define LP_STATE_ON		BIT(1)
#define LP_STATE_UNCHANGED	BIT(2)
#define LP_STATE_SET_VOLT	BIT(3)

struct regul_desc {
	const char *node_name;
	const struct regul_ops *ops;
	const void *driver_data;
	const char *supply_name;
	const uint32_t ramp_delay_uv_per_us;
;	const uint32_t enable_ramp_delay_us;
};

struct regul_ops {
	TEE_Result (*set_state)(const struct regul_desc *desc, bool enabled);
	TEE_Result (*get_state)(const struct regul_desc *desc, bool *enabled);
	TEE_Result (*set_voltage)(const struct regul_desc *desc, uint16_t mv);
	TEE_Result (*get_voltage)(const struct regul_desc *desc, uint16_t *mv);
	TEE_Result (*list_voltages)(const struct regul_desc *desc,
				    uint16_t **levels, size_t *count);
	TEE_Result (*set_flag)(const struct regul_desc *desc, uint16_t flag);
	void (*lock)(const struct regul_desc *desc);
	void (*unlock)(const struct regul_desc *desc);
	TEE_Result (*suspend)(const struct regul_desc *desc, uint8_t state,
			      uint16_t mv);
};

TEE_Result regulator_register(const struct regul_desc *desc, int node);

/*
 * Internal regulator structure
 * The structure is internal to the core, and the content should not be used
 * by a consumer nor a driver.
 */
struct rdev {
	const struct regul_desc *desc;
	int32_t phandle;
	uint16_t min_mv;
	uint16_t max_mv;
	uint16_t cur_mv;
	uint16_t flags;
	uint32_t ramp_delay_uv_per_us;
	unsigned int enable_ramp_delay_us;
	const char *reg_name;
	uint8_t use_count;
	int32_t supply_phandle;
	struct rdev *supply_dev;
	uint8_t *lp_state;
	uint16_t *lp_mv;
	SLIST_ENTRY(rdev) link;
};

#ifdef CFG_REGULATOR_DRIVERS
void regulator_core_dump(void);
#else
static inline void regulator_core_dump(void)
{
}
#endif

#endif /* DRIVERS_REGULATOR_H */
