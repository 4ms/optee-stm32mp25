incdirs_ext-y += $(scpfw-path)/product/optee-stm32mp1/include

srcs-y += $(scpfw-path)/product/optee-stm32mp1/fw/config_mbx_smt.c
srcs-y += $(scpfw-path)/product/optee-stm32mp1/fw/config_scmi.c
srcs-y += $(scpfw-path)/product/optee-stm32mp1/fw/config_scmi_clocks.c
srcs-y += $(scpfw-path)/product/optee-stm32mp1/fw/config_scmi_reset_domains.c

ifeq ($(CFG_STM32MP13),y)
srcs-y += $(scpfw-path)/product/optee-stm32mp1/fw/config_scmi_optee_regu.c
$(eval $(call scpfw-embed-product-module,stm32_regu_consumer))
$(eval $(call scpfw-embed-product-module,psu_optee_regulator))
endif

scpfw-cmake-flags-y += -DCFG_STM32MP13=$(CFG_STM32MP13)
