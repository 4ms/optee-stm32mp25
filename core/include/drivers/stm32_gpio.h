/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2017-2019, STMicroelectronics
 *
 * STM32 GPIO driver relies on platform util fiunctions to get base address
 * and clock ID of the GPIO banks. The drvier API allows to retrieve pin muxing
 * configuration for given nodes and load them at runtime. A pin control
 * instance provide an active and a standby configuration. Pin onwer is
 * responsible to load to expected configuration during PM state transitions
 * as STM32 GPIO driver does no register callbacks to the PM framework.
 */

#ifndef __STM32_GPIO_H
#define __STM32_GPIO_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>
#include <tee_api_types.h>

#define GPIO_MODE_INPUT		U(0x0)
#define GPIO_MODE_OUTPUT	U(0x1)
#define GPIO_MODE_ALTERNATE	U(0x2)
#define GPIO_MODE_ANALOG	U(0x3)

#define GPIO_OTYPE_PUSH_PULL	U(0x0)
#define GPIO_OTYPE_OPEN_DRAIN	U(0x1)

#define GPIO_OSPEED_LOW		U(0x0)
#define GPIO_OSPEED_MEDIUM	U(0x1)
#define GPIO_OSPEED_HIGH	U(0x2)
#define GPIO_OSPEED_VERY_HIGH	U(0x3)

#define GPIO_PUPD_NO_PULL	U(0x0)
#define GPIO_PUPD_PULL_UP	U(0x1)
#define GPIO_PUPD_PULL_DOWN	U(0x2)

#define GPIO_OD_LEVEL_LOW	U(0x0)
#define GPIO_OD_LEVEL_HIGH	U(0x1)

/*
 * GPIO configuration description structured as single 16bit word
 * for efficient save/restore when GPIO pin suspends or resumes.
 *
 * @mode:       One of GPIO_MODE_*
 * @otype:      One of GPIO_OTYPE_*
 * @ospeed:     One of GPIO_OSPEED_*
 * @pupd:       One of GPIO_PUPD_*
 * @od:         One of GPIO_OD_*
 * @af:         Alternate function numerical ID between 0 and 15
 */
struct gpio_cfg {
	uint16_t mode:		2;
	uint16_t otype:		1;
	uint16_t ospeed:	2;
	uint16_t pupd:		2;
	uint16_t od:		1;
	uint16_t af:		4;
};

/*
 * Descrption of a pin and its 2 states muxing
 *
 * @bank: GPIO bank identifier as assigned by the platform
 * @pin: Pin number in the GPIO bank
 * @active_cfg: Configuratioh in active state
 * @standby_cfg: Configuratioh in standby state
 * @link: Link to chain stm32_pinctrl structure in the list
 */
struct stm32_pinctrl {
	uint8_t bank;
	uint8_t pin;
	struct gpio_cfg active_cfg;
	struct gpio_cfg standby_cfg;

	STAILQ_ENTRY(stm32_pinctrl) link;
};

/*
 * Structure used to define list of stm32_pinctrl
 *
 * @stm32_pinctrl_list	Structure name
 * @stm32_pinctrl	Element of the structure
 */
STAILQ_HEAD(stm32_pinctrl_list, stm32_pinctrl);

/*
 * Apply series of pin muxing configuration
 *
 * @list: List of the pinctrl configuration to load
 */
void stm32_pinctrl_load_config(struct stm32_pinctrl_list *list);

/*
 * Apply series of pin muxing configuration, active state and standby state
 *
 * @pinctrl: array of pinctrl references
 * @count: Number of entries in @pinctrl
 */
void stm32_pinctrl_load_active_cfg(struct stm32_pinctrl_list *list);
void stm32_pinctrl_load_standby_cfg(struct stm32_pinctrl_list *list);

/*
 * Save pinctrl instances defined in DT node: identifiers and power states
 *
 * @fdt: device tree
 * @node: device node in the device tree
 *
 * Return a refernec eto  a pinctrl group (list)) upon success of NULL.
 */
struct stm32_pinctrl_list *stm32_pinctrl_fdt_get_pinctrl(const void *fdt,
							 int node);

/*
 * Get a pinctrl configuration reference from an indexed DT pinctrl property
 *
 * @fdt: device tree
 * @node: device node in the device tree
 * @index: Index of the pinctrl property
 * @plist: Output pinctrl list reference
 *
 * Return a TEE_Result compliant code
 */
TEE_Result stm32_pinctrl_dt_get_by_index(const void *fdt, int nodeoffset,
					 unsigned int index,
					 struct stm32_pinctrl_list **plist);

/*
 * Get a pinctrl configuration reference from a named DT pinctrl property
 *
 * @fdt: device tree
 * @node: device node in the device tree
 * @name: Name of the pinctrl
 * @plist: Output pinctrl list reference
 *
 * Return a TEE_Result compliant code
 */
TEE_Result stm32_pinctrl_dt_get_by_name(const void *fdt, int nodeoffset,
					const char *name,
					struct stm32_pinctrl_list **plist);

/*
 * Set target output GPIO pin to high or low level
 *
 * @bank: GPIO bank identifier as assigned by the platform
 * @pin: GPIO pin position in the GPIO bank
 * @high: 1 to set GPIO to high level, 0 to set to GPIO low level
 */
void stm32_gpio_set_output_level(unsigned int bank, unsigned int pin, int high);

/*
 * Set output GPIO pin referenced by @pinctrl to high or low level
 *
 * @pinctrl: Reference to pinctrl
 * @high: 1 to set GPIO to high level, 0 to set to GPIO low level
 */
static inline void stm32_pinctrl_set_gpio_level(struct stm32_pinctrl *pinctrl,
						int high)
{
	stm32_gpio_set_output_level(pinctrl->bank, pinctrl->pin, high);
}

/*
 * Get input GPIO pin current level, high or low
 *
 * @bank: GPIO bank identifier as assigned by the platform
 * @pin: GPIO pin position in the GPIO bank
 * Return 1 if GPIO level is high, 0 if it is low
 */
int stm32_gpio_get_input_level(unsigned int bank, unsigned int pin);

/*
 * Set target output GPIO pin to high or low level
 *
 * @pinctrl: Reference to pinctrl
 * Return 1 if GPIO level is high, 0 if it is low
 */
static inline int stm32_pinctrl_get_gpio_level(struct stm32_pinctrl *pinctrl)
{
	return stm32_gpio_get_input_level(pinctrl->bank, pinctrl->pin);
}

#ifdef CFG_STM32_GPIO
/*
 * Configure pin muxing access permission: can be secure or not
 *
 * @bank: GPIO bank identifier as assigned by the platform
 * @pin: Pin number in the GPIO bank
 * @secure: True if pin is secure, false otherwise
 */
void stm32_gpio_set_secure_cfg(unsigned int bank, unsigned int pin,
			       bool secure);

/*
 * Configure pin muxing access permission: can be secure or not
 *
 * @list: Pinctrl list reference
 * @secure: True if referenced pins are secure, false otherwise
 */
void stm32_pinctrl_set_secure_cfg(struct stm32_pinctrl_list *list, bool secure);
#else
static inline void stm32_gpio_set_secure_cfg(unsigned int bank __unused,
					     unsigned int pin __unused,
					     bool secure __unused)
{
	assert(0);
}
#endif
#endif /*__STM32_GPIO_H*/
