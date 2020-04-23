 // SPDX-License-Identifier: BSD-2-Clause
 /*
  * Copyright (C) 2020-2021, STMicroelectronics - All Rights Reserved
  */

#include <elf_parser.h>
#include <remoteproc_pta.h>
#include <string.h>
#include <sys/queue.h>
#include <ta_remoteproc.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <types_ext.h>
#include <utee_defines.h>

/* Firmware state */
enum remoteproc_state {
	REMOTEPROC_OFF,
	REMOTEPROC_LOADED,
	REMOTEPROC_STARTED,
};

#define RPROC_HDR_MAGIC		0x3543A468 /*random value */
#define HEADER_VERSION		1

/* Supported signature algorithm */
enum remoteproc_sign_type {
	RPROC_RSASSA_PKCS1_v1_5_SHA256 = 1,
	RPROC_ECDSA_SHA256 = 2,
};

/*
 * struct remoteproc_segment - program header with hash structure
 * @phdr: program header
 * @hash: hash associated to the program segment.
 */
struct remoteproc_segment {
	Elf32_Phdr phdr;
	unsigned char hash[TEE_SHA256_HASH_SIZE];
};

/*
 * struct remoteproc_fw_hdr - firmware header
 * @magic:        Magic number, must be equal to RPROC_HDR_MAGIC
 * @version:      Version of the header (must be 1)
 * @hdr_length:   Total header byte length including chunks
 * @sign_length:  Signature chunk byte length
 * @sign_offset:  Signature chunk byte offset from header start
 * @sign_type:    Signature type
 * @phhdr_length: Program header with hashes byte size, possibly 0
 * @phhdr_offset: Program header with hashes byte offset, 0 if not used
 * @phhdr_type:   Program header with hash type or 0 if not used
 * @key_length:   Authentication key info byte length, possibly 0
 * @key_offset:   Authentication key info byte offset, 0 if not used
 * @img_length:   Firmware image chunk byte length
 * @img_offset:   Firmware image chunk byte offset
 * @img_type:     Firmware image type
 */
struct remoteproc_fw_hdr {
	uint32_t magic;
	uint32_t version;
	uint32_t hdr_length;
	uint32_t sign_length;
	uint32_t sign_offset;
	uint32_t sign_type;
	uint32_t phhdr_length;
	uint32_t phhdr_offset;
	uint32_t phhdr_type;
	uint32_t key_length;
	uint32_t key_offset;
	uint32_t img_length;
	uint32_t img_offset;
	uint32_t img_type;
};

/*
 * struct remoteproc_sig_algo - signature algorithm information
 * @sign_type: Header signature type
 * @id:        Signature algorigthm identifier TEE_ALG_*
 * @hash_len:  Signature hash length
 */
struct remoteproc_sig_algo {
	enum remoteproc_sign_type sign_type;
	uint32_t id;
	size_t hash_len;
};

/*
 * struct remoteproc_context - firmware context
 * @fw_id:       Unique Id of the firmware
 * @hdr:         Location of a secure copy of the firmware header
 * @fw_img:      Firmware image
 * @fw_img_size: Byte size of the firmware image
 * @rsc_pa:      Physical address of the firmware resource table
 * @rsc_size:    Byte size of the firmware resource table
 * @state:       Remote-processor state
 * @hw_fmt:      Image format capabilities of the remoteproc PTA
 * @hw_img_prot: Image protection capabilities of the remoteproc PTA
 * @link:        Linked list element
 */
struct remoteproc_context {
	uint32_t fw_id;
	struct remoteproc_fw_hdr *hdr;
	uint8_t *fw_img;
	size_t fw_img_size;
	paddr_t rsc_pa;
	uint32_t rsc_size;
	enum remoteproc_state state;
	uint32_t hw_fmt;
	uint32_t hw_img_prot;
	TAILQ_ENTRY(remoteproc_context) link;
};

TAILQ_HEAD(remoteproc_firmware_head, remoteproc_context);

static struct remoteproc_firmware_head firmware_head =
	TAILQ_HEAD_INITIALIZER(firmware_head);

static const struct remoteproc_sig_algo rproc_ta_sign_algo[] = {
	{
		.sign_type = RPROC_RSASSA_PKCS1_v1_5_SHA256,
		.id = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
		.hash_len = TEE_SHA256_HASH_SIZE,
	},
	{
		.sign_type = RPROC_ECDSA_SHA256,
		.id = TEE_ALG_ECDSA_P256,
		.hash_len = TEE_SHA256_HASH_SIZE,
	},
};

static size_t session_refcount;
static TEE_TASessionHandle pta_session;

static void remoteproc_header_dump(struct remoteproc_fw_hdr __maybe_unused *hdr)
{
	DMSG("magic :\t%#"PRIx32, hdr->magic);
	DMSG("version :\t%#"PRIx32, hdr->version);
	DMSG("hdr_length :\t%#"PRIx32, hdr->hdr_length);
	DMSG("sign_length :\t%#"PRIx32, hdr->sign_length);
	DMSG("sign_offset :\t%#"PRIx32, hdr->sign_offset);
	DMSG("sign_type :\t%#"PRIx32, hdr->sign_type);
	DMSG("phhdr_length :\t%#"PRIx32, hdr->phhdr_length);
	DMSG("phhdr_offset :\t%#"PRIx32, hdr->phhdr_offset);
	DMSG("phhdr_type :\t%#"PRIx32, hdr->phhdr_type);
	DMSG("key_length :\t%#"PRIx32, hdr->key_length);
	DMSG("key_offset :\t%#"PRIx32, hdr->key_offset);
	DMSG("img_length :\t%#"PRIx32, hdr->img_length);
	DMSG("img_offset :\t%#"PRIx32, hdr->img_offset);
	DMSG("img_type :\t%#"PRIx32, hdr->img_type);
}

static struct remoteproc_context *remoteproc_find_firmware(uint32_t fw_id)
{
	struct remoteproc_context *ctx = NULL;

	TAILQ_FOREACH(ctx, &firmware_head, link) {
		if (ctx->fw_id == fw_id)
			return ctx;
	}

	return NULL;
}

static struct remoteproc_context *remoteproc_add_firmware(uint32_t fw_id)
{
	struct remoteproc_context *ctx = NULL;

	ctx = TEE_Malloc(sizeof(*ctx), TEE_MALLOC_FILL_ZERO);
	if (!ctx)
		return NULL;

	ctx->fw_id = fw_id;

	TAILQ_INSERT_TAIL(&firmware_head, ctx, link);

	return ctx;
}

static const struct remoteproc_sig_algo *remoteproc_get_algo(uint32_t sign_type)
{
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(rproc_ta_sign_algo); i++)
		if (sign_type == rproc_ta_sign_algo[i].sign_type)
			return &rproc_ta_sign_algo[i];

	return NULL;
}

static TEE_Result remoteproc_pta_verify(struct remoteproc_context *ctx,
					const struct remoteproc_sig_algo  *algo,
					char *hash, uint32_t hash_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct remoteproc_fw_hdr *hdr = ctx->hdr;
	struct rproc_pta_key_info *keyinfo = NULL;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_MEMREF_INPUT);
	TEE_Param params[TEE_NUM_PARAMS] = { };

	keyinfo = TEE_Malloc(sizeof(*keyinfo) + hdr->key_length, 0);
	if (!keyinfo)
		return TEE_ERROR_OUT_OF_MEMORY;

	keyinfo->algo = algo->id;
	keyinfo->info_size = hdr->key_length;
	memcpy(keyinfo->info, (uint8_t *)hdr + hdr->key_offset,
	       hdr->key_length);

	params[0].value.a = ctx->fw_id;
	params[1].memref.buffer = keyinfo;
	params[1].memref.size = RPROC_PTA_GET_KEYINFO_SIZE(keyinfo);
	params[2].memref.buffer = hash;
	params[2].memref.size = hash_len;
	params[3].memref.buffer = (uint8_t *)hdr + hdr->sign_offset;
	params[3].memref.size = hdr->sign_length;

	res = TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
				  PTA_REMOTEPROC_VERIFY_DIGEST,
				  param_types, params, NULL);
	if (res != TEE_SUCCESS)
		EMSG("Failed to verify signature, res = %#"PRIx32, res);

	TEE_Free(keyinfo);

	return res;
}

static TEE_Result remoteproc_save_fw_header(struct remoteproc_context *ctx,
					    void *fw_orig,
					    uint32_t fw_orig_size)
{
	struct remoteproc_fw_hdr *hdr = fw_orig;

	remoteproc_header_dump(hdr);

	if (fw_orig_size <= sizeof(*hdr) || fw_orig_size <= hdr->hdr_length)
		return TEE_ERROR_CORRUPT_OBJECT;

	ctx->hdr = TEE_Malloc(hdr->hdr_length, TEE_MALLOC_FILL_ZERO);
	if (!ctx->hdr)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(ctx->hdr, fw_orig, hdr->hdr_length);

	return TEE_SUCCESS;
}

static TEE_Result remoteproc_verify_signature(struct remoteproc_context *ctx)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	struct remoteproc_fw_hdr *hdr = ctx->hdr;
	const struct remoteproc_sig_algo  *algo = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	char *hash = NULL;
	uint32_t hash_len = 0;

	algo = remoteproc_get_algo(hdr->sign_type);
	if (!algo) {
		EMSG("Unsupported signature type %d", hdr->sign_type);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Compute the header hash */
	hash_len = algo->hash_len;
	hash = TEE_Malloc(hash_len, 0);
	if (!hash)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		goto free_hash;

	res = TEE_DigestDoFinal(op, hdr, hdr->sign_offset, hash, &hash_len);
	if (res != TEE_SUCCESS)
		goto out;

	/*
	 * TODO:
	 * Provide alternative to verify the signature in the TA. This could
	 * be done for instance by getting the key object from secure storage.
	 */

	/* By default ask the pta to verify the signature. */
	res = remoteproc_pta_verify(ctx, algo, hash, hash_len);

out:
	TEE_FreeOperation(op);
free_hash:
	TEE_Free(hash);

	return res;
}

static TEE_Result remoteproc_verify_header(struct remoteproc_context *ctx)
{
	struct remoteproc_fw_hdr *hdr = ctx->hdr;
	uint32_t hdr_size = 0;
	uint32_t chunk_size = 0;
	uint32_t alignment = 0;

	if (hdr->magic != RPROC_HDR_MAGIC)
		return TEE_ERROR_CORRUPT_OBJECT;

	if (hdr->version != HEADER_VERSION)
		return TEE_ERROR_CORRUPT_OBJECT;

	/*
	 * The offsets are aligned to 64 bits format. The hdr_length takes into
	 * account these alignments while the length of each chunks are the
	 * effective length,excluding the alignment padding bytes.
	 */
	alignment = hdr->sign_length % sizeof(uint64_t) +
		    hdr->phhdr_length % sizeof(uint64_t) +
		    hdr->key_length % sizeof(uint64_t);

	if (ADD_OVERFLOW(sizeof(*hdr), hdr->sign_length, &hdr_size) ||
	    ADD_OVERFLOW(hdr_size, hdr->phhdr_length, &hdr_size) ||
	    ADD_OVERFLOW(hdr_size, hdr->key_length, &hdr_size) ||
	    ADD_OVERFLOW(hdr_size, alignment, &hdr_size) ||
	    hdr->hdr_length != hdr_size)
		return TEE_ERROR_CORRUPT_OBJECT;

	if (ADD_OVERFLOW(hdr->sign_offset, hdr->sign_length, &chunk_size) ||
	    chunk_size > hdr_size ||
	    ADD_OVERFLOW(hdr->key_offset, hdr->key_length, &chunk_size) ||
	    chunk_size > hdr_size ||
	    ADD_OVERFLOW(hdr->phhdr_offset, hdr->phhdr_length, &chunk_size) ||
	    chunk_size > hdr_size)
		return TEE_ERROR_CORRUPT_OBJECT;

	if (hdr->phhdr_length % sizeof(struct remoteproc_segment))
		return TEE_ERROR_CORRUPT_OBJECT;

	return remoteproc_verify_signature(ctx);
}

static TEE_Result get_rproc_pta_capabilities(struct remoteproc_context *ctx)
{
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_VALUE_OUTPUT,
					       TEE_PARAM_TYPE_VALUE_OUTPUT,
					       TEE_PARAM_TYPE_NONE);
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	params[0].value.a = ctx->fw_id;

	res = TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
				  PTA_REMOTEPROC_HW_CAPABILITIES,
				  param_types, params, NULL);
	if (res)
		return res;

	ctx->hw_fmt = params[1].value.a;
	ctx->hw_img_prot = params[2].value.a;

	return TEE_SUCCESS;
}

static TEE_Result remoteproc_verify_firmware(struct remoteproc_context *ctx,
					     uint8_t *fw_orig,
					     uint32_t fw_orig_size)
{
	struct remoteproc_fw_hdr *hdr = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = get_rproc_pta_capabilities(ctx);
	if (res)
		return res;

	/* Secure the firmware image depending on strategy */
	if (!(ctx->hw_img_prot & PTA_REMOTEPROC_FW_WITH_HASH_TABLE) ||
	    ctx->hw_fmt != PTA_REMOTEPROC_ELF_FMT) {
		/*
		 * Only hash table for ELF format support implemented
		 * in a first step.
		 */
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	res = remoteproc_save_fw_header(ctx, fw_orig, fw_orig_size);
	if (res)
		return res;

	res = remoteproc_verify_header(ctx);
	if (res)
		goto free_hdr;

	/* Store location of the loadable binary in non-secure memory */
	hdr = ctx->hdr;
	ctx->fw_img_size = hdr->img_length;
	ctx->fw_img = fw_orig + hdr->img_offset;

	DMSG("Firmware image addr: %p size: %zu", ctx->fw_img,
	     ctx->fw_img_size);

free_hdr:
	TEE_Free(ctx->hdr);

	return res;
}

static paddr_t remoteproc_da_to_pa(uint32_t da, uint32_t size, void *priv)
{
	struct remoteproc_context *ctx = priv;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_VALUE_OUTPUT);
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	params[0].value.a = ctx->fw_id;
	params[1].value.a = da;
	params[2].value.a = size;

	res = TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
				  PTA_REMOTEPROC_FIRMWARE_DA_TO_PA,
				  param_types, params, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to translate device address %#"PRIx32, da);
		return 0;
	}

	return (paddr_t)reg_pair_to_64(params[3].value.b, params[3].value.a);
}

static TEE_Result remoteproc_parse_rsc_table(struct remoteproc_context *ctx)
{
	uint32_t da = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = e32_parser_find_rsc_table(ctx->fw_img, ctx->fw_img_size,
					&da, &ctx->rsc_size);
	if (res == TEE_ERROR_NO_DATA) {
		/* Firmware without resource table */
		ctx->rsc_size = 0;
		ctx->rsc_pa = 0;
		return TEE_SUCCESS;
	}
	if (res)
		return res;

	if (da) {
		DMSG("Resource table device address %#"PRIx32" size %zu",
		     da, ctx->rsc_size);

		ctx->rsc_pa = remoteproc_da_to_pa(da, ctx->rsc_size, ctx);
		if (!ctx->rsc_pa)
			return TEE_ERROR_ACCESS_DENIED;
	}

	return TEE_SUCCESS;
}

static TEE_Result get_segment_hash(struct remoteproc_context *ctx, uint8_t *src,
				   uint32_t size, uint32_t da,
				   uint32_t mem_size, unsigned char **hash)
{
	struct remoteproc_fw_hdr *hdr = ctx->hdr;
	struct remoteproc_segment *peh = NULL;
	unsigned int i = 0;
	unsigned int nb_entry = hdr->phhdr_length / sizeof(*peh);

	peh = (void *)((uint8_t *)hdr + hdr->phhdr_offset);

	for (i = 0; i < nb_entry; peh++, i++) {
		if (peh->phdr.p_paddr != da)
			continue;

		/*
		 * Segment is read from a non secure memory. Crosscheck it using
		 * the hash table to verify that the segment has not been
		 * corrupted.
		 */
		if (peh->phdr.p_type != PT_LOAD)
			return TEE_ERROR_CORRUPT_OBJECT;

		if (peh->phdr.p_filesz != size || peh->phdr.p_memsz != mem_size)
			return TEE_ERROR_CORRUPT_OBJECT;

		if ((Elf32_Off)(src - ctx->fw_img) !=  peh->phdr.p_offset)
			return TEE_ERROR_CORRUPT_OBJECT;

		*hash = peh->hash;

		return TEE_SUCCESS;
	}

	return TEE_ERROR_NO_DATA;
}

static TEE_Result remoteproc_load_segment(uint8_t *src, uint32_t size,
					  uint32_t da, uint32_t mem_size,
					  void *priv)
{
	struct remoteproc_context *ctx = priv;
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_VALUE_INPUT,
					       TEE_PARAM_TYPE_MEMREF_INPUT);
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned char *hash = NULL;

	/*
	 * Invoke platform remoteproc PTA to load the segment in remote
	 * processor memory which is not mapped in the TA space.
	 */

	DMSG("Load segment %#"PRIx32" size %"PRIu32" (%"PRIu32")", da, size,
	     mem_size);

	res = get_segment_hash(ctx, src, size, da, mem_size, &hash);
	if (res)
		return res;

	params[0].value.a = ctx->fw_id;
	params[1].memref.buffer = src;
	params[1].memref.size = size;
	params[2].value.a = da;
	params[3].memref.buffer = hash;
	params[3].memref.size = TEE_SHA256_HASH_SIZE;

	if (size) {
		res = TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
					  PTA_REMOTEPROC_LOAD_SEGMENT_SHA256,
					  param_types, params, NULL);
		if (res != TEE_SUCCESS) {
			EMSG("Fails to load segment, res = 0x%x", res);
			return res;
		}
	}

	/* Fill the rest of the memory with 0 */
	if (size < mem_size) {
		param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					      TEE_PARAM_TYPE_VALUE_INPUT,
					      TEE_PARAM_TYPE_VALUE_INPUT,
					      TEE_PARAM_TYPE_VALUE_INPUT);
		params[1].value.a = da + size;
		params[2].value.a = mem_size - size;
		params[3].value.a = 0;

		res = TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
					  PTA_REMOTEPROC_SET_MEMORY,
					  param_types, params, NULL);
		if (res != TEE_SUCCESS)
			EMSG("Fails to clear segment, res = 0x%x", res);
	}

	return res;
}

static TEE_Result remoteproc_load_elf(struct remoteproc_context *ctx)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = e32_parse_ehdr(ctx->fw_img, ctx->fw_img_size);
	if (res) {
		EMSG("Failed to parse firmware, res = %#"PRIx32, res);
		return res;
	}

	return e32_parser_load_elf_image(ctx->fw_img, ctx->fw_img_size,
					 remoteproc_load_segment, ctx);
}

static TEE_Result remoteproc_load_fw(uint32_t pt,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct remoteproc_context *ctx = NULL;
	uint32_t fw_id = params[0].value.a;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	ctx = remoteproc_find_firmware(fw_id);
	if (!ctx)
		ctx = remoteproc_add_firmware(fw_id);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (ctx->state != REMOTEPROC_OFF)
		return TEE_ERROR_BAD_STATE;

	if (!params[1].memref.buffer || !params[1].memref.size)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("Got base addr: %p size %zu", params[1].memref.buffer,
	     params[1].memref.size);

	res = remoteproc_verify_firmware(ctx, params[1].memref.buffer,
					 params[1].memref.size);
	if (res) {
		EMSG("Can't Authenticate the firmware, res = %#"PRIx32, res);
		goto out;
	}

	res = remoteproc_load_elf(ctx);
	if (res)
		goto out;

	/* Take opportunity to get the resource table address */
	res = remoteproc_parse_rsc_table(ctx);
	if (res == TEE_SUCCESS)
		ctx->state = REMOTEPROC_LOADED;

out:
	/* Clear reference to firmware image from shared memory */
	ctx->fw_img = NULL;
	ctx->fw_img_size =  0;

	return res;
}

static TEE_Result remoteproc_start_fw(uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct remoteproc_context *ctx = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	ctx = remoteproc_find_firmware(params[0].value.a);
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (ctx->state) {
	case REMOTEPROC_OFF:
		res = TEE_ERROR_BAD_STATE;
		break;
	case REMOTEPROC_STARTED:
		res =  TEE_SUCCESS;
		break;
	case REMOTEPROC_LOADED:
		res = TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
					  PTA_REMOTEPROC_FIRMWARE_START,
					  pt, params, NULL);
		if (res == TEE_SUCCESS)
			ctx->state = REMOTEPROC_STARTED;
		break;
	default:
		res = TEE_ERROR_BAD_STATE;
	}

	return res;
}

static TEE_Result remoteproc_stop_fw(uint32_t pt,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct remoteproc_context *ctx = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	ctx = remoteproc_find_firmware(params[0].value.a);
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (ctx->state) {
	case REMOTEPROC_LOADED:
		res = TEE_ERROR_BAD_STATE;
		break;
	case REMOTEPROC_OFF:
		res = TEE_SUCCESS;
		break;
	case REMOTEPROC_STARTED:
		res = TEE_InvokeTACommand(pta_session, TEE_TIMEOUT_INFINITE,
					  PTA_REMOTEPROC_FIRMWARE_STOP,
					  pt, params, NULL);
		if (res == TEE_SUCCESS)
			ctx->state = REMOTEPROC_OFF;
		break;
	default:
		res = TEE_ERROR_BAD_STATE;
	}

	return res;
}

static TEE_Result remoteproc_get_rsc_table(uint32_t pt,
					   TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	struct remoteproc_context *ctx = NULL;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	ctx = remoteproc_find_firmware(params[0].value.a);
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	if (ctx->state == REMOTEPROC_OFF)
		return TEE_ERROR_BAD_STATE;

	reg_pair_from_64((uint64_t)ctx->rsc_pa,
			 &params[1].value.b, &params[1].value.a);
	reg_pair_from_64((uint64_t)ctx->rsc_size,
			 &params[2].value.b, &params[2].value.a);

	return TEE_SUCCESS;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt __unused,
				    TEE_Param params[TEE_NUM_PARAMS] __unused,
				    void **sess __unused)
{
	static const TEE_UUID uuid = PTA_REMOTEPROC_UUID;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!session_refcount) {
		res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
					&pta_session, NULL);
		if (res)
			return res;
	}

	session_refcount++;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess __unused)
{
	session_refcount--;

	if (!session_refcount)
		TEE_CloseTASession(pta_session);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess __unused, uint32_t cmd_id,
				      uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case TA_RPROC_FW_CMD_LOAD_FW:
		return remoteproc_load_fw(pt, params);
	case TA_RPROC_FW_CMD_START_FW:
		return remoteproc_start_fw(pt, params);
	case TA_RPROC_FW_CMD_STOP_FW:
		return remoteproc_stop_fw(pt, params);
	case TA_RPROC_FW_CMD_GET_RSC_TABLE:
		return remoteproc_get_rsc_table(pt, params);
	case TA_RPROC_FW_CMD_GET_COREDUMP:
		return TEE_ERROR_NOT_IMPLEMENTED;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
