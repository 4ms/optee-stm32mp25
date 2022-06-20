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

CFG_STM32_GPIO ?= y
CFG_STM32_RIF ?= y
CFG_STM32_RIFSC ?= y
CFG_STM32_RISAB ?= y
CFG_STM32_RISAF ?= y
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
