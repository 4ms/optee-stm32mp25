# OP-TEE Trusted OS with more non-secure access granted

This is a fork of the 3.19.0-stm32mp branch from ST's fork.

All that has been modified besides this README is the device tree files
to provide more non-secure access to peripherals. See the git log for details.

## Building

You need to install the python prequisites:

```
python3 -m venv venv
source venv/bin/activate
pip3 install pyelftools pillow cryptography pycryptodomex
```

Do the `source venv/bin/activate` each time you start a work session

Make sure you have the right compilers on your PATH.
Later versions probably will work, but this happens to be what I tested with:
```
aarch64-none-elf-gcc -v
 gcc version 13.2.1 20231009 (Arm GNU Toolchain 13.2.rel1 (Build arm-13.7))

arm-none-eabi-gcc -v
 gcc version 12.3.1 20230626 (Arm GNU Toolchain 12.3.Rel1 (Build arm-12.35))
```


Build:
```
make \
    PLATFORM=stm32mp2 \
    PLATFORM_FLAVOR=257F_EV1 \
    ARCH=arm \
    ARM64_core=y \
    CFG_EMBED_DTB_SOURCE_FILE=stm32mp257f-ev1.dts \
    CROSS_COMPILE64=aarch64-none-elf- \
    CROSS_COMPILE=arm-none-eabi- \
    CFG_TEE_CORE_LOG_LEVEL=2
```


Original README:

# OP-TEE Trusted OS
This git contains source code for the secure side implementation of OP-TEE
project.

All official OP-TEE documentation has moved to http://optee.readthedocs.io.

Open-source OP-TEE has identified security advisories here
https://github.com/OP-TEE/optee_os/security.
Please consider the status of these advisories before using the ST OP-TEE
project.

// OP-TEE core maintainers
