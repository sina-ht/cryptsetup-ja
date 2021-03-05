/*
 * LUKS - Linux Unified Key Setup v2
 *
 * Copyright (C) 2015-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2020 Milan Broz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _CRYPTSETUP_LUKS2_ONDISK_H
#define _CRYPTSETUP_LUKS2_ONDISK_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "libcryptsetup.h"

#define LUKS2_MAGIC_1ST "LUKS\xba\xbe"
#define LUKS2_MAGIC_2ND "SKUL\xba\xbe"
#define LUKS2_MAGIC_L 6
#define LUKS2_UUID_L 40
#define LUKS2_LABEL_L 48
#define LUKS2_SALT_L 64
#define LUKS2_CHECKSUM_ALG_L 32
#define LUKS2_CHECKSUM_L 64

#define LUKS2_KEYSLOTS_MAX       32
#define LUKS2_TOKENS_MAX         32
#define LUKS2_SEGMENT_MAX        32

#define LUKS2_BUILTIN_TOKEN_PREFIX "luks2-"
#define LUKS2_BUILTIN_TOKEN_PREFIX_LEN 6

#define LUKS2_TOKEN_KEYRING LUKS2_BUILTIN_TOKEN_PREFIX "keyring"

#define LUKS2_DIGEST_MAX 8

#define CRYPT_ANY_SEGMENT -1
#define CRYPT_DEFAULT_SEGMENT -2
#define CRYPT_ONE_SEGMENT -3

#define CRYPT_ANY_DIGEST -1

/* 20 MiBs */
#define LUKS2_DEFAULT_NONE_REENCRYPTION_LENGTH 0x1400000

/* 1 GiB */
#define LUKS2_REENCRYPT_MAX_HOTZONE_LENGTH 0x40000000

struct device;
struct luks2_reencrypt;
struct crypt_lock_handle;
struct crypt_dm_active_device;
struct luks_phdr; /* LUKS1 for conversion */

/*
 * LUKS2 header on-disk.
 *
 * Binary header is followed by JSON area.
 * JSON area is followed by keyslot area and data area,
 * these are described in JSON metadata.
 *
 * Note: uuid, csum_alg are intentionally on the same offset as LUKS1
 * (checksum alg replaces hash in LUKS1)
 *
 * String (char) should be zero terminated.
 * Padding should be wiped.
 * Checksum is calculated with csum zeroed (+ full JSON area).
 */
struct luks2_hdr_disk {
	char		magic[LUKS2_MAGIC_L];
	uint16_t	version;	/* Version 2 */
	uint64_t	hdr_size;	/* in bytes, including JSON area */
	uint64_t	seqid;		/* increased on every update */
	char		label[LUKS2_LABEL_L];
	char		checksum_alg[LUKS2_CHECKSUM_ALG_L];
	uint8_t		salt[LUKS2_SALT_L]; /* unique for every header/offset */
	char		uuid[LUKS2_UUID_L];
	char		subsystem[LUKS2_LABEL_L]; /* owner subsystem label */
	uint64_t	hdr_offset;	/* offset from device start in bytes */
	char		_padding[184];
	uint8_t		csum[LUKS2_CHECKSUM_L];
	char		_padding4096[7*512];
	/* JSON area starts here */
} __attribute__ ((packed));

/*
 * LUKS2 header in-memory.
 */
struct luks2_hdr {
	size_t		hdr_size;
	uint64_t	seqid;
	unsigned int	version;
	char		label[LUKS2_LABEL_L];
	char		subsystem[LUKS2_LABEL_L];
	char		checksum_alg[LUKS2_CHECKSUM_ALG_L];
	uint8_t		salt1[LUKS2_SALT_L];
	uint8_t		salt2[LUKS2_SALT_L];
	char		uuid[LUKS2_UUID_L];
	void		*jobj;
};

struct luks2_keyslot_params {
	enum { LUKS2_KEYSLOT_AF_LUKS1 = 0 } af_type;
	enum { LUKS2_KEYSLOT_AREA_RAW = 0 } area_type;

	union {
	struct {
		char hash[LUKS2_CHECKSUM_ALG_L]; // or include luks.h
		unsigned int stripes;
	} luks1;
	} af;

	union {
	struct {
		char encryption[65]; // or include utils_crypt.h
		size_t key_size;
	} raw;
	} area;
};

/*
 * Supportable header sizes (hdr_disk + JSON area)
 * Also used as offset for the 2nd header.
 */
#define LUKS2_HDR_16K_LEN 0x4000

#define LUKS2_HDR_BIN_LEN sizeof(struct luks2_hdr_disk)

//#define LUKS2_DEFAULT_HDR_SIZE 0x400000  /* 4 MiB */
#define LUKS2_DEFAULT_HDR_SIZE 0x1000000 /* 16 MiB */

#define LUKS2_MAX_KEYSLOTS_SIZE 0x8000000 /* 128 MiB */

#define LUKS2_HDR_OFFSET_MAX 0x400000 /* 4 MiB */

/* Offsets for secondary header (for scan if primary header is corrupted). */
#define LUKS2_HDR2_OFFSETS { 0x04000, 0x008000, 0x010000, 0x020000, \
                             0x40000, 0x080000, 0x100000, 0x200000, LUKS2_HDR_OFFSET_MAX }

int LUKS2_hdr_version_unlocked(struct crypt_device *cd,
	const char *backup_file);

int LUKS2_hdr_read(struct crypt_device *cd, struct luks2_hdr *hdr, int repair);
int LUKS2_hdr_write(struct crypt_device *cd, struct luks2_hdr *hdr);
int LUKS2_hdr_write_force(struct crypt_device *cd, struct luks2_hdr *hdr);
int LUKS2_hdr_dump(struct crypt_device *cd, struct luks2_hdr *hdr);

int LUKS2_hdr_uuid(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const char *uuid);

int LUKS2_hdr_labels(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const char *label,
	const char *subsystem,
	int commit);

void LUKS2_hdr_free(struct crypt_device *cd, struct luks2_hdr *hdr);

int LUKS2_hdr_backup(struct crypt_device *cd,
		     struct luks2_hdr *hdr,
		     const char *backup_file);
int LUKS2_hdr_restore(struct crypt_device *cd,
		      struct luks2_hdr *hdr,
		      const char *backup_file);

uint64_t LUKS2_hdr_and_areas_size(struct luks2_hdr *hdr);
uint64_t LUKS2_keyslots_size(struct luks2_hdr *hdr);
uint64_t LUKS2_metadata_size(struct luks2_hdr *hdr);

int LUKS2_keyslot_cipher_incompatible(struct crypt_device *cd, const char *cipher_spec);

/*
 * Generic LUKS2 keyslot
 */
int LUKS2_keyslot_open(struct crypt_device *cd,
	int keyslot,
	int segment,
	const char *password,
	size_t password_len,
	struct volume_key **vk);

int LUKS2_keyslot_open_all_segments(struct crypt_device *cd,
	int keyslot_old,
	int keyslot_new,
	const char *password,
	size_t password_len,
	struct volume_key **vks);

int LUKS2_keyslot_store(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *password,
	size_t password_len,
	const struct volume_key *vk,
	const struct luks2_keyslot_params *params);

int LUKS2_keyslot_wipe(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int wipe_area_only);

crypt_keyslot_priority LUKS2_keyslot_priority_get(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot);

int LUKS2_keyslot_priority_set(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	crypt_keyslot_priority priority,
	int commit);

/*
 * Generic LUKS2 token
 */
int LUKS2_token_json_get(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char **json);

int LUKS2_token_assign(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int token,
	int assign,
	int commit);

int LUKS2_token_is_assigned(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int token);

int LUKS2_token_create(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char *json,
	int commit);

crypt_token_info LUKS2_token_status(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char **type);

int LUKS2_token_open_and_activate(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char *name,
	const char *pin,
	uint32_t flags,
	void *usrptr);

int LUKS2_token_open_and_activate_any(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const char *name,
	const char *pin,
	uint32_t flags);

int LUKS2_token_keyring_get(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	struct crypt_token_params_luks2_keyring *keyring_params);

int LUKS2_token_keyring_json(char *buffer, size_t buffer_size,
	const struct crypt_token_params_luks2_keyring *keyring_params);

void crypt_token_unload_external_all(struct crypt_device *cd);

/*
 * Generic LUKS2 digest
 */
int LUKS2_digest_any_matching(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const struct volume_key *vk);

int LUKS2_digest_verify_by_segment(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int segment,
	const struct volume_key *vk);

int LUKS2_digest_verify(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const struct volume_key *vk,
	int keyslot);

int LUKS2_digest_assign(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int digest,
	int assign,
	int commit);

int LUKS2_digest_segment_assign(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int segment,
	int digest,
	int assign,
	int commit);

int LUKS2_digest_by_keyslot(struct luks2_hdr *hdr, int keyslot);

int LUKS2_digest_create(struct crypt_device *cd,
	const char *type,
	struct luks2_hdr *hdr,
	const struct volume_key *vk);

/*
 * LUKS2 generic
 */
int LUKS2_activate(struct crypt_device *cd,
	const char *name,
	struct volume_key *vk,
	uint32_t flags);

int LUKS2_activate_multi(struct crypt_device *cd,
	const char *name,
	struct volume_key *vks,
	uint64_t device_size,
	uint32_t flags);

int LUKS2_deactivate(struct crypt_device *cd,
	const char *name,
	struct luks2_hdr *hdr,
	struct crypt_dm_active_device *dmd,
	uint32_t flags);

int LUKS2_generate_hdr(
	struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const struct volume_key *vk,
	const char *cipherName,
	const char *cipherMode,
	const char *integrity,
	const char *uuid,
	unsigned int sector_size,
	uint64_t data_offset,
	uint64_t align_offset,
	uint64_t required_alignment,
	uint64_t metadata_size,
	uint64_t keyslots_size);

int LUKS2_check_metadata_area_size(uint64_t metadata_size);
int LUKS2_check_keyslots_area_size(uint64_t keyslots_size);

int LUKS2_wipe_header_areas(struct crypt_device *cd,
	struct luks2_hdr *hdr, bool detached_header);

uint64_t LUKS2_get_data_offset(struct luks2_hdr *hdr);
int LUKS2_get_data_size(struct luks2_hdr *hdr, uint64_t *size, bool *dynamic);
int LUKS2_get_sector_size(struct luks2_hdr *hdr);
const char *LUKS2_get_cipher(struct luks2_hdr *hdr, int segment);
const char *LUKS2_get_integrity(struct luks2_hdr *hdr, int segment);
int LUKS2_keyslot_params_default(struct crypt_device *cd, struct luks2_hdr *hdr,
	 struct luks2_keyslot_params *params);
int LUKS2_get_volume_key_size(struct luks2_hdr *hdr, int segment);
int LUKS2_get_keyslot_stored_key_size(struct luks2_hdr *hdr, int keyslot);
const char *LUKS2_get_keyslot_cipher(struct luks2_hdr *hdr, int keyslot, size_t *key_size);
int LUKS2_keyslot_find_empty(struct luks2_hdr *hdr);
int LUKS2_keyslot_active_count(struct luks2_hdr *hdr, int segment);
crypt_keyslot_info LUKS2_keyslot_info(struct luks2_hdr *hdr, int keyslot);
int LUKS2_keyslot_area(struct luks2_hdr *hdr,
	int keyslot,
	uint64_t *offset,
	uint64_t *length);
int LUKS2_keyslot_pbkdf(struct luks2_hdr *hdr, int keyslot, struct crypt_pbkdf_type *pbkdf);

/*
 * Permanent activation flags stored in header
 */
int LUKS2_config_get_flags(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t *flags);
int LUKS2_config_set_flags(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t flags);

/*
 * Requirements for device activation or header modification
 */
int LUKS2_config_get_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t *reqs);
int LUKS2_config_set_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t reqs, bool commit);

int LUKS2_unmet_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t reqs_mask, int quiet);

int LUKS2_key_description_by_segment(struct crypt_device *cd,
		struct luks2_hdr *hdr, struct volume_key *vk, int segment);
int LUKS2_volume_key_load_in_keyring_by_keyslot(struct crypt_device *cd,
		struct luks2_hdr *hdr, struct volume_key *vk, int keyslot);
int LUKS2_volume_key_load_in_keyring_by_digest(struct crypt_device *cd,
		struct luks2_hdr *hdr, struct volume_key *vk, int digest);

int LUKS2_luks1_to_luks2(struct crypt_device *cd,
			 struct luks_phdr *hdr1,
			 struct luks2_hdr *hdr2);
int LUKS2_luks2_to_luks1(struct crypt_device *cd,
			 struct luks2_hdr *hdr2,
			 struct luks_phdr *hdr1);

/*
 * LUKS2 reencryption
 */
int LUKS2_reencrypt_locked_recovery_by_passphrase(struct crypt_device *cd,
	int keyslot_old,
	int keyslot_new,
	const char *passphrase,
	size_t passphrase_size,
	uint32_t flags,
	struct volume_key **vks);

void LUKS2_reencrypt_free(struct crypt_device *cd,
	struct luks2_reencrypt *rh);

crypt_reencrypt_info LUKS2_reencrypt_status(struct luks2_hdr *hdr);

crypt_reencrypt_info LUKS2_reencrypt_get_params(struct luks2_hdr *hdr,
	struct crypt_params_reencrypt *params);

int LUKS2_reencrypt_lock(struct crypt_device *cd,
	struct crypt_lock_handle **reencrypt_lock);

int LUKS2_reencrypt_lock_by_dm_uuid(struct crypt_device *cd,
	const char *dm_uuid,
	struct crypt_lock_handle **reencrypt_lock);

void LUKS2_reencrypt_unlock(struct crypt_device *cd,
	struct crypt_lock_handle *reencrypt_lock);

int LUKS2_reencrypt_check_device_size(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	uint64_t check_size,
	uint64_t *dev_size,
	bool activation,
	bool dynamic);

#endif
