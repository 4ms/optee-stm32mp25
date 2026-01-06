export CROSS_COMPILE64=aarch64-none-linux-gnu-
export CROSS_COMPILE=aarch64-none-linux-gnu-
make PLATFORM=stm32mp2 CFG_EXT_DTS=../dt-stm32mp/stm32mp2/a35-td/optee CFG_EMBED_DTB_SOURCE_FILE=stm32mp257f-ev1-ca35tdcid-ostl.dts CFG_TEE_CORE_LOG_LEVEL=2 CFG_SCMI_SCPFW=n O=build all
