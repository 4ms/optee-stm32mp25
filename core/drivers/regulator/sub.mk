srcs-y += core.c
srcs-$(CFG_REGULATOR_FIXED) += regulator_fixed.c
srcs-$(CFG_STM32_REGULATOR_GPIO) += stm32_regulator_gpio.c
srcs-$(CFG_STM32_VREFBUF) += stm32_vrefbuf.c
