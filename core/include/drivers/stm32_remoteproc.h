/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, STMicroelectronics - All Rights Reserved
 */

#ifndef __DRIVERS_STM32_REMOTEPROC_H
#define __DRIVERS_STM32_REMOTEPROC_H

#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

/*  supported firmwares */

#define STM32_M4_FW_ID          0
#define STM32_M33_FW_ID         1

/**
 * @brief stm32_rproc_get - get remote proc instance associated to a firmware ID
 *
 * @fw_id: Firmware ID
 *
 * Returns pointer to the remoteproc context or NULL if not found.
 */
void *stm32_rproc_get(uint32_t fw_id);

TEE_Result stm32_rproc_da_to_pa(uint32_t firmware_id, paddr_t da, size_t size,
				paddr_t *pa);
TEE_Result stm32_rproc_map(uint32_t firmware_id, paddr_t pa, size_t size,
			   void **va);
TEE_Result stm32_rproc_unmap(uint32_t firmware_id, paddr_t pa, size_t size);
TEE_Result stm32_rproc_mem_protect(uint32_t firmware_id, bool secure_access);

TEE_Result stm32_rproc_start(uint32_t firmware_id);
TEE_Result stm32_rproc_stop(uint32_t firmware_id);
TEE_Result stm32_rproc_set_boot_address(uint32_t firmware_id,
					paddr_t address, bool secure);

#endif /* __DRIVERS_STM32_REMOTEPROC_H */
