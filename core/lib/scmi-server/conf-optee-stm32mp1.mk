$(call force,CFG_SCPFW_MOD_CLOCK,y)
$(call force,CFG_SCPFW_MOD_MSG_SMT,y)
$(call force,CFG_SCPFW_MOD_OPTEE_CLOCK,y)
$(call force,CFG_SCPFW_MOD_OPTEE_CONSOLE,y)
$(call force,CFG_SCPFW_MOD_OPTEE_MBX,y)
$(call force,CFG_SCPFW_MOD_OPTEE_RESET,y)
$(call force,CFG_SCPFW_MOD_RESET_DOMAIN,y)
$(call force,CFG_SCPFW_MOD_SCMI,y)
$(call force,CFG_SCPFW_MOD_SCMI_CLOCK,y)
$(call force,CFG_SCPFW_MOD_SCMI_RESET_DOMAIN,y)
$(call force,CFG_SCPFW_MOD_SCMI_VOLTAGE_DOMAIN,y)
$(call force,CFG_SCPFW_MOD_VOLTAGE_DOMAIN,y)

$(call force,CFG_SCPFW_MOD_STM32_PMIC_REGU,$(CFG_STPMIC1))
$(call force,CFG_SCPFW_MOD_STM32_PWR_REGU,y)

$(call force,CFG_SCPFW_NOTIFICATION,n)
$(call force,CFG_SCPFW_FAST_CHANNEL,n)
