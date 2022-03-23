flavor_dts_file-257F_DK = stm32mp257f-dk.dts
flavor_dts_file-257F_EV = stm32mp257f-ev.dts

flavorlist-MP25 = $(flavor_dts_file-257F_DK) \
		  $(flavor_dts_file-257F_EV)

ifneq ($(PLATFORM_FLAVOR),)
ifeq ($(flavor_dts_file-$(PLATFORM_FLAVOR)),)
$(error Invalid platform flavor $(PLATFORM_FLAVOR))
endif
CFG_EMBED_DTB_SOURCE_FILE ?= $(flavor_dts_file-$(PLATFORM_FLAVOR))
endif

ifneq ($(filter $(CFG_EMBED_DTB_SOURCE_FILE),$(flavorlist-MP25)),)
$(call force,CFG_STM32MP25,y)
endif

ifeq ($(filter $(CFG_STM32MP25),y),)
$(error STM32 Platform must be defined)
endif

$(call force,CFG_ARM64_core,y)
$(call force,CFG_WITH_LPAE,y)
# arm-v8 platforms
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
# Uncomment the line below to only support 64bit TA
supported-ta-targets ?= ta_arm64

$(call force,CFG_ARM_GIC_PM,y)
$(call force,CFG_GIC,y)
$(call force,CFG_INIT_CNTVOFF,y)
$(call force,CFG_PM,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_DT,y)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_DRIVERS_CLK,y)
$(call force,CFG_DRIVERS_CLK_DT,y)
$(call force,CFG_DRIVERS_CLK_EARLY_PROBE,y)
$(call force,CFG_STM32_FIREWALL,y)
$(call force,CFG_STM32MP_CLK_CORE,y)
$(call force,CFG_STM32MP25_CLK,y)
$(call force,CFG_STM32MP25_RSTCTRL,y)
$(call force,CFG_TEE_CORE_EMBED_INTERNAL_TESTS,n)

ifneq ($(filter $(CFG_EMBED_DTB_SOURCE_FILE),$(flavorlist-1G)),)
CFG_DRAM_SIZE    ?= 0x40000000
endif

CFG_DRAM_BASE ?= 0x80000000
CFG_TZDRAM_START ?= ($(CFG_DRAM_BASE) + 0x02000000)
CFG_TZDRAM_SIZE  ?= 0x02000000
CFG_DRAM_SIZE    ?= 0x80000000

CFG_CORE_HEAP_SIZE ?= 131072
CFG_CORE_RESERVED_SHM ?= n
CFG_DTB_MAX_SIZE ?= (256 * 1024)
CFG_MMAP_REGIONS ?= 30
CFG_NUM_THREADS ?= 5
CFG_TEE_CORE_NB_CORE ?= 2
CFG_STM32MP_OPP_COUNT ?= 3

CFG_STM32_BSEC3 ?= y
CFG_STM32_GPIO ?= y
CFG_STM32_IAC ?= y
CFG_STM32_RIF ?= y
CFG_STM32_RIFSC ?= y
CFG_STM32_RISAB ?= y
CFG_STM32_RISAF ?= y
CFG_STM32_RNG ?= y
CFG_STM32_SERC ?= y
CFG_STM32_SHARED_IO ?= y
CFG_STM32_UART ?= y

# Default enable some test facitilites
CFG_TEE_CORE_EMBED_INTERNAL_TESTS ?= y
CFG_WITH_STATS ?= y

# Default disable ASLR
CFG_CORE_ASLR ?= n

# UART instance used for early console (0 disables early console)
CFG_STM32_EARLY_CONSOLE_UART ?= 2

# Default disable external DT support
CFG_EXTERNAL_DT ?= n

# Enable if board is Rev.A
CFG_STM32MP25x_REVA ?= y

# Default enable HWRNG PTA support
CFG_HWRNG_PTA ?= y
ifeq ($(CFG_HWRNG_PTA),y)
$(call force,CFG_STM32_RNG,y,Mandated by CFG_HWRNG_PTA)
$(call force,CFG_WITH_SOFTWARE_PRNG,n,Mandated by CFG_HWRNG_PTA)
CFG_HWRNG_QUALITY ?= 1024
endif

# Default enable SCMI PTA support
CFG_SCMI_PTA ?= y
ifeq ($(CFG_SCMI_PTA),y)
$(call force,CFG_SCMI_MSG_DRIVERS,y,Mandated by CFG_SCMI_PTA)
endif

CFG_SCMI_MSG_DRIVERS ?= n
ifeq ($(CFG_SCMI_MSG_DRIVERS),y)
$(call force,CFG_SCMI_MSG_CLOCK,y)
$(call force,CFG_SCMI_MSG_RESET_DOMAIN,y)
$(call force,CFG_SCMI_MSG_SHM_MSG,y)
$(call force,CFG_SCMI_MSG_SMT,n)
endif

# Enable reset control
ifeq ($(CFG_STM32MP25_RSTCTRL),y)
$(call force,CFG_DRIVERS_RSTCTRL,y)
$(call force,CFG_STM32_RSTCTRL,y)
endif

# Enable Early TA NVMEM for provisioning management
CFG_TA_STM32MP_NVMEM ?= y
ifeq ($(CFG_TA_STM32MP_NVMEM),y)
$(call force,CFG_BSEC_PTA,y,Mandated by CFG_TA_STM32MP_NVMEM)
CFG_IN_TREE_EARLY_TAS += stm32mp_nvmem/1a8342cc-81a5-4512-99fe-9e2b3e37d626
endif
