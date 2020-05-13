/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020, STMicroelectronics - All Rights Reserved
 */

#ifndef __REMOTEPROC_PTA_H
#define __REMOTEPROC_PTA_H

#include <util.h>

/*
 * Interface to the pseudo TA which provides platform implementation
 * of the remote processor management
 */

#define PTA_REMOTEPROC_UUID { 0x54af4a68, 0x19be, 0x40d7, \
		{ 0xbb, 0xe6, 0x89, 0x50, 0x35, 0x0a, 0x87, 0x44 } }

/* Firmware format */
#define PTA_REMOTEPROC_PROPRIETARY_FMT		BIT32(0)
#define PTA_REMOTEPROC_ELF_FMT			BIT32(1)

/* Firmware image protection */
/* The platorm supports copy of the input firmware image in secure memory */
#define PTA_REMOTEPROC_FW_SECURE_COPY		BIT32(0)
/* The platorm supports load of segment with hash protection */
#define PTA_REMOTEPROC_FW_WITH_HASH_TABLE	BIT32(1)
/* The platorm is able to change access to secure the firmware input image */
#define PTA_REMOTEPROC_FW_MEMORY_PROTECTION	BIT32(2)

/**
 * struct rproc_pta_key_info - public key information
 * @algo:	Algorithm, defined by public key algorithms TEE_ALG_*
 *		from TEE Internal API specification
 * @info_size:	Byte size of the @info
 * @info:	Append key information data
 */
struct rproc_pta_key_info {
	uint32_t algo;
	uint32_t info_size;
	char info[];
};

static inline size_t
	rproc_pta_get_keyinfo_size(struct rproc_pta_key_info *keyinf)
{
	size_t s = 0;

	if (!keyinf || ADD_OVERFLOW(sizeof(*keyinf), keyinf->info_size, &s))
		return 0;

	return s;
}

#define RPROC_PTA_GET_KEYINFO_SIZE(x)	rproc_pta_get_keyinfo_size((x))

/*
 * Platform capabilities.
 *
 * Get Platform firmware loader service capabilities.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 * [out] params[1].value.a:	Firmware format (PTA_REMOTEPROC_*_FMT)
 * [out] params[2].value.a:	Image protection method (PTA_REMOTEPROC_FW_*)
 */
#define PTA_REMOTEPROC_HW_CAPABILITIES		1

/*
 * Firmware loading.
 *
 * Optional service to implement only in case of proprietary format.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 * [in]  params[1].memref:	Loadable firmware image
 */
#define PTA_REMOTEPROC_FIRMWARE_LOAD		2

/*
 * Load a segment with a SHA256 hash.
 *
 * This command is used when the platform secure memory is too expensive to
 * save the whole firmware image in secure memory. Upon segment load, a
 * successful completion ensures the loaded image complies with the provided
 * hash.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 * [in]  params[1].memref:	Section data to load
 * [in]  params[2].value.a:	32bit LSB load device segment address
 * [in]  params[2].value.b:	32bit MSB load device segment address
 * [in]  params[3].memref:	Expected hash (SHA256) of the payload
 */
#define PTA_REMOTEPROC_LOAD_SEGMENT_SHA256	3

/*
 * Memory set.
 *
 * Fill a remote device memory with requested value. this is use for instance
 * to clear a memory on the remote firmware load.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 * [in]  params[1].value.a:	32bit LSB device memory address
 * [in]  params[1].value.b:	32bit MSB device memory address
 * [in]  params[2].value.a:	32bit LSB device memory size
 * [in]  params[2].value.b:	32bit MSB device memory size
 * [in]  params[3].value.a:	Byte value to be set
 */
#define PTA_REMOTEPROC_SET_MEMORY		4

/*
 * Firmware start.
 *
 * Start up a successfully remote processor firmware.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 */
#define PTA_REMOTEPROC_FIRMWARE_START		5

/*
 * Firmware stop.
 *
 * Stop of the remote processor firmware and release/clean resources.
 * After the command successful completion, remote processor firmware must be
 * reloaded prior being started again.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 */
#define PTA_REMOTEPROC_FIRMWARE_STOP		6

/*
 * Firmware device to physical address conversion.
 *
 * Return the physical address corresponding to an address got from the
 * firmware address layout.
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 * [in]  params[1].value.a:	32bit LSB Device memory address
 * [in]  params[1].value.b:	32bit MSB Device memory address
 * [in]  params[2].value.a:	32bit LSB Device memory size
 * [in]  params[2].value.b:	32bit MSB Device memory size
 * [out] params[3].value.a:	32bit LSB converted physical address
 * [out] params[3].value.b:	32bit MSB converted physical address
 */
#define PTA_REMOTEPROC_FIRMWARE_DA_TO_PA	7

/*
 * Verify the firmware digest against a signature
 *
 * Return TEE_SUCCESS if the signature is verified,  else an error
 *
 * [in]  params[0].value.a:	Unique 32bit firmware identifier
 * [in]  params[1].memref:	Key information (refer to @rproc_pta_key_info)
 * [in]  params[2].memref:	Digest of the firmware authenticated data
 * [in]  params[3].memref:	Signature of the firmware authenticated data
 */
#define PTA_REMOTEPROC_VERIFY_DIGEST	8

#endif /* __REMOTEPROC_PTA_H */
