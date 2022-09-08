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

/*
 *  signed file structure:
 *
 *                    ----+-------------+
 *                   /    |    Magic    |
 *                  /     +-------------+
 *                 /      +-------------+
 *                /       |   version   |
 *               /        +-------------+
 *              /         +-------------+
 * +-----------+          | sign size   |   size of the signature
 * |   Header  |          +-------------+   (in bytes, 64-bit aligned)
 * +-----------+          +-------------+
 *              \         | images size |   total size of the images to load
 *               \        +-------------+   (in bytes, 64-bit aligned)
 *                \       +-------------+
 *                 \      |  TLV size   |   Generic TLV size
 *                  \     +-------------+   (in bytes, 64-bit aligned)
 *                   \    +-------------+
 *                    \   | PLAT TLV sz |   Platform TLV size
 *                     \--+-------------+   (in bytes, 64-bit aligned)
 *
 *                        +-------------+   Signature of the header, the trailer
 *                        | Signature   |   and optionally the firmware image if
 *                        +-------------+   a hash table is not stored.
 *
 *                        +-------------+
 *                        |   Firmware  |
 *                        |    image    |
 *                        +-------------+
 *                  ------+-------------+
 *                 /      |+-----------+|
 *                /       ||   TLV     ||   Information used to authenticate the
 *  +-----------+/        ||           ||   firmware, stored in
 *  |  Trailer  |         |+-----------+|   Type-Length-Value format.
 *  +-----------+\        |+-----------+|
 *                \       || Platform  ||   Specific platform information,
 *                 \      ||   TLV     ||   stored in Type-Length-Value format.
 *                  \     |+-----------+|
 *                   -----+-------------+
 *
 *  TLV and platform TLV chunks:
 *
 *                        +-------------+
 *                        |    Magic    |
 *                        +-------------+
 *                        +-------------+
 *                        |    size     |  size of the TLV payload
 *                        +-------------+
 *                        +-------------+
 *                        |     TLV     |  TLV structures
 *                        |   payload   |
 *                        +-------------+
 */

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

enum remoteproc_img_type {
	REMOTEPROC_ELF_TYPE = 1,
	REMOTEPROC_INVALID_TYPE = 0xFF
};

/* remoteproc_tlv structure offsets */
#define RPROC_TLV_LENGTH_OF	U(0x02)
#define RPROC_TLV_VALUE_OF	U(0x04)

#define TLV_INFO_MAGIC		U(0x6907)
#define PLAT_TLV_INFO_MAGIC	U(0x6908)

/* TLV types */
#define RPROC_TLV_SIGNTYPE	U(0x01)
#define RPROC_TLV_HASHTYPE	U(0x02)
#define RPROC_TLV_NUM_IMG	U(0x03)
#define RPROC_TLV_IMGTYPE	U(0x04)
#define RPROC_TLV_IMGSIZE	U(0x05)
#define RPROC_TLV_HASHTABLE	U(0x10)
#define RPROC_TLV_PKEYINFO	U(0x11)

#define RPROC_TLV_SIGNTYPE_LGTH U(1)

#define LE16_TO_CPU(x) (((x)[1] << 8) | (x)[0])
#define LE32_TO_CPU(x) (((x)[3] << 24) | ((x)[2] << 16) | \
			((x)[1] << 8)  | (x)[0])

#define U64_ADD_TO_ALIGN(x) ((x) + sizeof(uint64_t) - ((x) % sizeof(uint64_t)))
#define U64_ALIGN_SZ(x) ((x) % (sizeof(uint64_t)) ? U64_ADD_TO_ALIGN(x) : (x))

/*
 * struct remoteproc_tlv - Type-Length-Value structure
 * @type: type of data
 * @length: size of the data.
 * @value: pointer to the data.
 */
struct remoteproc_tlv {
	uint16_t type;
	uint16_t length;
	uint8_t value[0];
};

/*
 * struct remoteproc_tlv_hr - type length data sutructure
 * @magic: magic value of the TLV chunk
 * @size: total size of the TLV values.
 */
struct remoteproc_tlv_hr {
	int32_t magic;
	int32_t size;
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
 * @sign_len:     Signature chunk byte length
 * @img_len:      Firmware image chunk byte length
 * @tlv_len:      Generic meta data chunk (TLV format)
 * @plat_tlv_len: Platform meta data chunk (TLV format)
 */
struct remoteproc_fw_hdr {
	uint32_t magic;
	uint32_t version;
	uint32_t sign_len;
	uint32_t img_len;
	uint32_t tlv_len;
	uint32_t plat_tlv_len;
};

#define FW_SIGN_OFFSET(fw_img, hdr)	((fw_img) + sizeof(*(hdr)))
#define FW_IMG_OFFSET(fw_img, hdr)	(FW_SIGN_OFFSET((fw_img), (hdr)) +    \
					 U64_ALIGN_SZ(hdr->sign_len))
#define FW_TLV_OFFSET(fw_img, hdr)	(FW_IMG_OFFSET((fw_img), (hdr)) +     \
					 U64_ALIGN_SZ(hdr->img_len))
#define FW_PTLV_OFFSET(fw_img, hdr)	(FW_TLV_OFFSET((fw_img), (hdr)) +     \
					 U64_ALIGN_SZ(hdr->tlv_len))

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
 * @hdr:         Location of a secure copy of the firmware header and signature
 * @tlr:         Location of a secure copy of the firmware trailer
 * @fw_img:      Firmware image
 * @fw_img_sz:   Byte size of the firmware image
 * @hash_table:  Location of a copy of the segment's hash table
 * @nb_segment:  number of segment to load
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
	uint8_t *tlr;
	uint8_t *fw_img;
	size_t fw_img_sz;
	struct remoteproc_segment *hash_table;
	uint32_t nb_segment;
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
	DMSG("sign_len :\t%#"PRIx32, hdr->sign_len);
	DMSG("img_len :\t%#"PRIx32, hdr->img_len);
	DMSG("tlv_len :\t%#"PRIx32, hdr->tlv_len);
	DMSG("plat_tlv_len :\t%#"PRIx32, hdr->plat_tlv_len);
}

static TEE_Result __maybe_unused
remoteproc_get_tlv(void *tlv_chunk, uint16_t type,
		   uint8_t **value, size_t *length)
{
	struct remoteproc_tlv_hr *tlv_hdr = tlv_chunk;
	uint8_t *p_tlv = (uint8_t *)tlv_chunk + sizeof(*tlv_hdr);
	uint8_t *p_end_tlv = p_tlv + tlv_hdr->size;
	uint16_t tlv_type = 0;
	uint16_t tlv_length = 0;

	*value = NULL;
	*length = 0;

	/* Parse the tlv area */
	while (p_tlv < p_end_tlv) {
		tlv_type = LE16_TO_CPU(p_tlv);
		tlv_length = LE16_TO_CPU(&p_tlv[RPROC_TLV_LENGTH_OF]);
		if (tlv_type == type) {
			/* The specified TLV has been found */
			DMSG("TLV type %#"PRIx16" found, size %#"PRIx16,
			     type, tlv_length);
			*value = &p_tlv[RPROC_TLV_VALUE_OF];
			*length = tlv_length;
			if (tlv_length)
				return TEE_SUCCESS;
			else
				return TEE_ERROR_NO_DATA;
		}
		p_tlv += U64_ALIGN_SZ(sizeof(struct remoteproc_tlv) +
				      tlv_length);
	}

	return TEE_ERROR_NO_DATA;
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
	size_t length = 0;
	uint8_t *tlv_keyinfo = NULL;
	uint8_t *sign = NULL;

	res = remoteproc_get_tlv(ctx->tlr, RPROC_TLV_PKEYINFO, &tlv_keyinfo,
				 &length);
	if (res != TEE_SUCCESS && res != TEE_ERROR_NO_DATA)
		return res;

	keyinfo = TEE_Malloc(sizeof(*keyinfo) + length, TEE_MALLOC_FILL_ZERO);
	if (!keyinfo)
		return TEE_ERROR_OUT_OF_MEMORY;

	keyinfo->algo = algo->id;
	keyinfo->info_size = length;
	memcpy(keyinfo->info, tlv_keyinfo, length);

	sign = (uint8_t *)hdr + sizeof(*hdr);

	params[0].value.a = ctx->fw_id;
	params[1].memref.buffer = keyinfo;
	params[1].memref.size = RPROC_PTA_GET_KEYINFO_SIZE(keyinfo);
	params[2].memref.buffer = hash;
	params[2].memref.size = hash_len;
	params[3].memref.buffer = sign;
	params[3].memref.size = hdr->sign_len;

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
	uint32_t length = sizeof(*hdr) + hdr->sign_len;

	remoteproc_header_dump(hdr);

	if (fw_orig_size <= length || !hdr->sign_len)
		return TEE_ERROR_CORRUPT_OBJECT;

	/* Copy the header and the signature chunk in secure memory */
	ctx->hdr = TEE_Malloc(length, TEE_MALLOC_FILL_ZERO);
	if (!ctx->hdr)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(ctx->hdr, fw_orig, length);

	return TEE_SUCCESS;
}

static TEE_Result remoteproc_save_fw_trailer(struct remoteproc_context *ctx,
					     uint8_t *fw_orig,
					     uint32_t fw_orig_size)
{
	struct remoteproc_fw_hdr *hdr = ctx->hdr;
	uint32_t tlr_size = 0;
	uint8_t *tlr_orig = NULL;

	tlr_size = U64_ALIGN_SZ(hdr->tlv_len) +
		   U64_ALIGN_SZ(hdr->plat_tlv_len);

	if (fw_orig_size <= tlr_size || !tlr_size)
		return TEE_ERROR_CORRUPT_OBJECT;

	tlr_orig = FW_TLV_OFFSET(fw_orig, hdr);

	ctx->tlr = TEE_Malloc(tlr_size, TEE_MALLOC_FILL_ZERO);
	if (!ctx->tlr)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(ctx->tlr, tlr_orig, tlr_size);

	return TEE_SUCCESS;
}

static TEE_Result remoteproc_verify_signature(struct remoteproc_context *ctx)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	struct remoteproc_fw_hdr *hdr = ctx->hdr;
	const struct remoteproc_sig_algo  *algo = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *tlv_sign_algo = NULL;
	size_t length = 0;
	char *hash = NULL;
	uint32_t hash_len = 0;

	/* Get the algo type from TLV data */
	res = remoteproc_get_tlv(ctx->tlr, RPROC_TLV_SIGNTYPE,
				 &tlv_sign_algo, &length);

	if (res != TEE_SUCCESS || length != RPROC_TLV_SIGNTYPE_LGTH)
		return TEE_ERROR_CORRUPT_OBJECT;

	algo = remoteproc_get_algo(*tlv_sign_algo);
	if (!algo) {
		EMSG("Unsupported signature type %d", *tlv_sign_algo);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Compute the header and trailer hashes */
	hash_len = algo->hash_len;
	hash = TEE_Malloc(hash_len, TEE_MALLOC_FILL_ZERO);
	if (!hash)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		goto free_hash;

	TEE_DigestUpdate(op, hdr, sizeof(*hdr));
	res = TEE_DigestDoFinal(op, ctx->tlr, U64_ALIGN_SZ(hdr->tlv_len) +
				U64_ALIGN_SZ(hdr->plat_tlv_len),
				hash, &hash_len);

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

static TEE_Result remoteproc_verify_header(struct remoteproc_context *ctx,
					   uint32_t fw_orig_size)
{
	struct remoteproc_fw_hdr *hdr = ctx->hdr;
	uint32_t size = 0;

	if (hdr->magic != RPROC_HDR_MAGIC)
		return TEE_ERROR_CORRUPT_OBJECT;

	if (hdr->version != HEADER_VERSION)
		return TEE_ERROR_CORRUPT_OBJECT;

	/*
	 * The offsets are aligned to 64 bits format. While the length of each
	 * chunks are the effective length, excluding the alignment padding
	 * bytes.
	 */
	if (ADD_OVERFLOW(sizeof(*hdr), U64_ALIGN_SZ(hdr->sign_len), &size) ||
	    ADD_OVERFLOW(size, U64_ALIGN_SZ(hdr->img_len), &size) ||
	    ADD_OVERFLOW(size, U64_ALIGN_SZ(hdr->tlv_len), &size) ||
	    ADD_OVERFLOW(size, U64_ALIGN_SZ(hdr->plat_tlv_len), &size) ||
	    fw_orig_size != size)
		return TEE_ERROR_CORRUPT_OBJECT;

	return TEE_SUCCESS;
}

static TEE_Result remoteproc_verify_trailer(struct remoteproc_context *ctx)
{
	struct remoteproc_fw_hdr *hdr = ctx->hdr;
	struct remoteproc_tlv_hr *tlv_hdr = NULL;
	uint32_t size = 0;

	/* The TLV chunk is at the beginning of the trailer */
	tlv_hdr = (struct remoteproc_tlv_hr *)(void *)ctx->tlr;

	if (tlv_hdr->magic != TLV_INFO_MAGIC)
		return TEE_ERROR_CORRUPT_OBJECT;

	if (hdr->tlv_len != (uint32_t)(tlv_hdr->size) + sizeof(*tlv_hdr))
		return TEE_ERROR_CORRUPT_OBJECT;

	/* An optional platform TLV chunk can follow the TLV chunk */
	if (!hdr->plat_tlv_len)
		return TEE_SUCCESS;

	tlv_hdr = (struct remoteproc_tlv_hr *)(void *)
		  (ctx->tlr + U64_ALIGN_SZ(hdr->tlv_len));

	if (tlv_hdr->magic != PLAT_TLV_INFO_MAGIC)
		return TEE_ERROR_CORRUPT_OBJECT;

	if (ADD_OVERFLOW(sizeof(*tlv_hdr), (uint32_t)tlv_hdr->size, &size) ||
	    hdr->plat_tlv_len  != size)
		return TEE_ERROR_CORRUPT_OBJECT;

	return TEE_SUCCESS;
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

	res = remoteproc_verify_header(ctx, fw_orig_size);
	if (res)
		goto free_hdr;

	res = remoteproc_save_fw_trailer(ctx, fw_orig, fw_orig_size);
	if (res)
		goto free_hdr;

	res = remoteproc_verify_trailer(ctx);
	if (res)
		goto free_tlr;

	res = remoteproc_verify_signature(ctx);
	if (res)
		goto free_tlr;

	/* Store location of the loadable binary in non-secure memory */
	hdr = ctx->hdr;
	ctx->fw_img_sz = hdr->img_len;
	ctx->fw_img = fw_orig + sizeof(*hdr) + hdr->sign_len;

	DMSG("Firmware image addr: %p size: %zu", ctx->fw_img,
	     ctx->fw_img_sz);

	/* TODO:  transmit to the PTA the platform tlv chunk */

	return res;

free_tlr:
	TEE_Free(ctx->tlr);
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

	/*
	 * The elf file contains remote processor device addresses, that refer
	 * to the remote processor memory space.
	 * A translation is needed to get the corresponding physical address.
	 */

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

	res = e32_parser_find_rsc_table(ctx->fw_img, ctx->fw_img_sz,
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
		DMSG("Resource table device address %#"PRIx32" size %x",
		     da, ctx->rsc_size);

		ctx->rsc_pa = remoteproc_da_to_pa(da, ctx->rsc_size, ctx);
		if (!ctx->rsc_pa)
			return TEE_ERROR_ACCESS_DENIED;
	}

	return TEE_SUCCESS;
}

static TEE_Result get_hash_table(struct remoteproc_context *ctx)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *tlv_hash = NULL;
	struct remoteproc_segment *hash_table = NULL;
	size_t length = 0;

	/* Get the segment's hash table from TLV data */
	res = remoteproc_get_tlv(ctx->tlr, RPROC_TLV_HASHTABLE,
				 &tlv_hash, &length);
	if (res || (length % sizeof(struct remoteproc_segment)))
		return res;

	/* We can not ensure that  tlv_hash is memory aligned so make a copy */
	hash_table = TEE_Malloc(length, TEE_MALLOC_FILL_ZERO);
	if (!hash_table)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(hash_table, tlv_hash, length);

	ctx->hash_table = hash_table;
	ctx->nb_segment = length / sizeof(struct remoteproc_segment);

	return TEE_SUCCESS;
}

static TEE_Result get_tlv_images_type(struct remoteproc_context *ctx,
				      uint8_t num_img, uint8_t idx,
				      uint8_t *img_type)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *tlv_value = NULL;
	size_t length = 0;

	/* Get the type of the image to load, from TLV data */
	res = remoteproc_get_tlv(ctx->tlr, RPROC_TLV_IMGTYPE,
				 &tlv_value, &length);
	if (res || length != (sizeof(*img_type) * num_img))
		return res;

	*img_type = tlv_value[idx];

	return TEE_SUCCESS;
}

static TEE_Result get_tlv_images_size(struct remoteproc_context *ctx,
				      uint8_t num_img, uint8_t idx,
				      uint32_t *img_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *tlv_value = NULL;
	size_t length = 0;

	/* Get the size of the image to load, from TLV data */
	res = remoteproc_get_tlv(ctx->tlr, RPROC_TLV_IMGSIZE,
				 &tlv_value, &length);
	if (res || length != (sizeof(*img_size) * num_img))
		return res;

	*img_size = LE32_TO_CPU(&tlv_value[sizeof(*img_size) * idx]);

	return TEE_SUCCESS;
}

static TEE_Result get_segment_hash(struct remoteproc_context *ctx, uint8_t *src,
				   uint32_t size, uint32_t da,
				   uint32_t mem_size, unsigned char **hash)
{
	struct remoteproc_segment *peh = NULL;
	unsigned int i = 0;
	unsigned int nb_entry = ctx->nb_segment;

	peh = (void *)(ctx->hash_table);

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

		if (src < ctx->fw_img ||
		    (src + peh->phdr.p_filesz) > (ctx->fw_img + ctx->fw_img_sz))
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
	uint8_t num_img = 0, i = 0;
	uint8_t img_type = REMOTEPROC_INVALID_TYPE;
	uint32_t img_size = 0;
	uint8_t *tlv = NULL;
	int32_t offset = 0;
	size_t length = 0;

	res = e32_parse_ehdr(ctx->fw_img, ctx->fw_img_sz);
	if (res) {
		EMSG("Failed to parse firmware, res = %#"PRIx32, res);
		return res;
	}

	res = get_hash_table(ctx);
	if (res)
		return res;

	/* Get the number of firmwares to load */

	res = remoteproc_get_tlv(ctx->tlr, RPROC_TLV_NUM_IMG,
				 &tlv, &length);
	if (res)
		goto out;
	if (length != sizeof(uint8_t)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	num_img = *tlv;

	for (i = 0; i < num_img; i++) {
		res = get_tlv_images_type(ctx, num_img, i, &img_type);
		if (res)
			goto out;
		if (img_type != REMOTEPROC_ELF_TYPE) {
			res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}

		res = get_tlv_images_size(ctx, num_img, i, &img_size);
		if (res)
			goto out;

		res = e32_parser_load_elf_image(ctx->fw_img + offset, img_size,
						remoteproc_load_segment, ctx);
		if (res)
			goto out;
		offset += img_size;
	}

out:
	/* TODO: clean-up the memories in case of fail */
	TEE_Free(ctx->hash_table);

	return res;
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

	DMSG("Got base addr: %p size %x", params[1].memref.buffer,
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
	ctx->fw_img_sz =  0;
	ctx->nb_segment =  0;

	/* Free allocated memories */
	TEE_Free(ctx->hdr);
	TEE_Free(ctx->tlr);

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

 /*
  * TA_OpenSessionEntryPoint: open a TA session associated to a firmware
  *  to manage.
  *
  *  [in]  params[0].value.a:	unique 32bit identifier of the firmware
  */
TEE_Result TA_OpenSessionEntryPoint(uint32_t pt,
				    TEE_Param params[TEE_NUM_PARAMS],
				    void **sess __unused)
{
	static const TEE_UUID uuid = PTA_REMOTEPROC_UUID;
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!session_refcount) {
		res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, pt, params,
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
