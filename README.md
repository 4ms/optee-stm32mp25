# OP-TEE Trusted OS
This git contains source code for the secure side implementation of OP-TEE
project.

All official OP-TEE documentation has moved to http://optee.readthedocs.io.

Open-source OP-TEE has identified security advisories here
https://github.com/OP-TEE/optee_os/security.
Please consider the status of these advisories before using the ST OP-TEE
project.

// OP-TEE core maintainers

# Compiling

## Prerequisites

- aarch64-none-elf toolchain v13.2. Other versions may work, but only this one was tested.
From: https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads

- python3

- python modules: cffi crytpography pyelftools pillow

E.g.:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install cffi crytpography pyelftools pillow
```

## Building

OP-TEE's docs say you need to use Linux and the aarch64-linux-gnu toolchain, but to compile just the 
optee-os, you can use the baremetal toolchain aarch64-none-elf (available on mac, linux, windows).

```bash
git clone https://github.com:4ms/optee-stm32mp25.git
cd optee-stm32mp25
git checkout mp2-baremetal

export CROSS_COMPILE=aarch64-linux-gnu-
export CROSS_COMPILE64=aarch64-linux-gnu-
make PLATFORM=stm32mp2 CFG_EMBED_DTB_SOURCE_FILE=stm32mp257f-ev1.dts CFG_TEE_CORE_LOG_LEVEL=2 CFG_SCMI_SCPFW=n O=build all
ls -l ../build-optee/core/tee-*_v2.bin
```

