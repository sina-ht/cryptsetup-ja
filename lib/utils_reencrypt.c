/*
 * utils_reencrypt - online reencryption utilities
 *
 * Copyright (C) 2015-2019, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2019, Ondrej Kozina
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

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/fs.h>
#include <sys/ioctl.h>

#include "luks2_internal.h"
#include "utils_device_locking.h"

typedef enum { REENC_OK = 0, REENC_ERR, REENC_ROLLBACK, REENC_FATAL } reenc_status_t;

void LUKS2_reenc_context_free(struct crypt_device *cd, struct luks2_reenc_context *rh)
{
	if (!rh)
		return;

	if (rh->rp.type == REENC_PROTECTION_CHECKSUM) {
		if (rh->rp.p.csum.ch) {
			crypt_hash_destroy(rh->rp.p.csum.ch);
			rh->rp.p.csum.ch = NULL;
		}
		if (rh->rp.p.csum.checksums) {
			memset(rh->rp.p.csum.checksums, 0, rh->rp.p.csum.checksums_len);
			free(rh->rp.p.csum.checksums);
			rh->rp.p.csum.checksums = NULL;
		}
	}

	json_object_put(rh->jobj_segs_pre);
	rh->jobj_segs_pre = NULL;
	json_object_put(rh->jobj_segs_after);
	rh->jobj_segs_after = NULL;
	json_object_put(rh->jobj_segment_old);
	rh->jobj_segment_old = NULL;
	json_object_put(rh->jobj_segment_new);
	rh->jobj_segment_new = NULL;

	free(rh->reenc_buffer);
	rh->reenc_buffer = NULL;
	crypt_storage_wrapper_destroy(rh->cw1);
	rh->cw1 = NULL;
	crypt_storage_wrapper_destroy(rh->cw2);
	rh->cw2 = NULL;

	free(rh->device_name);
	free(rh->overlay_name);
	free(rh->hotzone_name);
	crypt_drop_keyring_key(cd, rh->vks);
	crypt_free_volume_key(rh->vks);
	crypt_unlock_internal(cd, rh->reenc_lock);
	free(rh);
}

static size_t _reenc_alignment(struct crypt_device *cd,
		struct luks2_hdr *hdr)
{
	int ss;
	/* FIXME: logical block size would make better sense */
	size_t alignment = device_block_size(cd, crypt_data_device(cd));

	log_dbg(cd, "data device sector size: %zu", alignment);

	ss = LUKS2_reencrypt_get_sector_size_old(hdr);
	log_dbg(cd, "Old sector size: %d", ss);
	if (ss > 0 && (size_t)ss > alignment)
		alignment = ss;
	ss = LUKS2_reencrypt_get_sector_size_new(hdr);
	log_dbg(cd, "New sector size: %d", ss);
	if (ss > 0 && (size_t)ss > alignment)
		alignment = (size_t)ss;

	return alignment;
}

/* returns void because it must not fail on valid LUKS2 header */
static void _load_backup_segments(struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh)
{
	int segment = LUKS2_get_segment_id_by_flag(hdr, "reencrypt-final");

	if (segment >= 0) {
		rh->jobj_segment_new = json_object_get(LUKS2_get_segment_jobj(hdr, segment));
		rh->digest_new = LUKS2_digest_by_segment(hdr, segment);
	} else {
		rh->jobj_segment_new = NULL;
		rh->digest_new = -ENOENT;
	}

	segment = LUKS2_get_segment_id_by_flag(hdr, "reencrypt-previous");
	if (segment >= 0) {
		rh->jobj_segment_old = json_object_get(LUKS2_get_segment_jobj(hdr, segment));
		rh->digest_old = LUKS2_digest_by_segment(hdr, segment);
	} else {
		rh->jobj_segment_old = NULL;
		rh->digest_old = -ENOENT;
	}

	segment = LUKS2_get_segment_id_by_flag(hdr, "reencrypt-moved-segment");
	if (segment >= 0)
		rh->jobj_segment_moved = json_object_get(LUKS2_get_segment_jobj(hdr, segment));
	else
		rh->jobj_segment_moved = NULL;
}

static int _reenc_load(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reenc_context *rh, uint64_t device_size, const struct crypt_params_reencrypt *params)
{
	int r;
	uint64_t dummy, area_length;

	rh->reenc_keyslot = LUKS2_find_keyslot(hdr, "reencrypt");
	if (rh->reenc_keyslot < 0)
		return -EINVAL;
	if (LUKS2_keyslot_area(hdr, rh->reenc_keyslot, &dummy, &area_length) < 0)
		return -EINVAL;

	if (!strcmp(LUKS2_reencrypt_mode(hdr), "reencrypt"))
		rh->type = REENCRYPT;
	else if (!strcmp(LUKS2_reencrypt_mode(hdr), "encrypt"))
		rh->type = ENCRYPT;
	else if (!strcmp(LUKS2_reencrypt_mode(hdr), "decrypt")) {
		rh->type = DECRYPT;
		rh->direction = BACKWARD;
	} else
		return -ENOTSUP;

	rh->alignment = _reenc_alignment(cd, hdr);

	if (!strcmp(params->resilience, "shift")) {
		log_dbg(cd, "Initializaing reencryption context with data_shift resilience.");
		rh->rp.type = REENC_PROTECTION_DATASHIFT;
		rh->data_shift = LUKS2_reencrypt_data_shift(hdr);
		rh->direction = rh->data_shift < 0 ? BACKWARD : FORWARD;
	} else if (!strcmp(params->resilience, "journal")) {
		log_dbg(cd, "Initializaing reencryption context with journal resilience.");
		rh->rp.type = REENC_PROTECTION_JOURNAL;
	} else if (!strcmp(params->resilience, "checksum")) {
		log_dbg(cd, "Initializaing reencryption context with checksum resilience.");
		rh->rp.type = REENC_PROTECTION_CHECKSUM;

		r = snprintf(rh->rp.p.csum.hash,
			sizeof(rh->rp.p.csum.hash), "%s", params->hash);
		if (r < 0 || (size_t)r >= sizeof(rh->rp.p.csum.hash)) {
			log_dbg(cd, "Invalid hash parameter");
			return -EINVAL;
		}
		r = crypt_hash_size(params->hash);
		if (r < 1) {
			log_dbg(cd, "Invalid hash size");
			return -EINVAL;
		}
		rh->rp.p.csum.hash_size = r;
		if (crypt_hash_init(&rh->rp.p.csum.ch, params->hash)) {
			log_dbg(cd, "Failed to init hash %s", params->hash);
			return -EINVAL;
		}

		rh->rp.p.csum.checksums_len = area_length;
		rh->rp.p.csum.checksums = aligned_malloc(&rh->rp.p.csum.checksums, rh->rp.p.csum.checksums_len,
				device_alignment(crypt_metadata_device(cd)));
		if (!rh->rp.p.csum.checksums)
			return -ENOMEM;
	} else if (!strcmp(params->resilience, "noop")) {
		log_dbg(cd, "Initializaing reencryption context with noop resilience.");
		rh->rp.type = REENC_PROTECTION_NOOP;
		rh->rp.p.noop.hz_size = params->hotzone_size;
	} else
		return -EINVAL;

	rh->length = LUKS2_get_reencrypt_length(hdr, rh, area_length);
	if (LUKS2_get_reencrypt_offset(hdr, rh->direction, device_size, &rh->length, &rh->offset)) {
		log_err(cd, "Failed to get reencryption offset.");
		return -EINVAL;
	}

	if (rh->offset > device_size)
		return -EINVAL;
	if (rh->length > device_size - rh->offset)
		rh->length = device_size - rh->offset;

	log_dbg(cd, "reencrypt-direction: %s", rh->direction == FORWARD ? "forward" : "backward");

	_load_backup_segments(hdr, rh);

	if (rh->direction == BACKWARD)
		rh->progress = device_size - rh->offset - rh->length;
	else
		rh->progress = rh->offset;

	log_dbg(cd, "reencrypt-previous digest id: %d", rh->digest_old);
	log_dbg(cd, "reencrypt-previous segment: %s", rh->jobj_segment_old ? json_object_to_json_string_ext(rh->jobj_segment_old, JSON_C_TO_STRING_PRETTY) : "<missing>");
	log_dbg(cd, "reencrypt-final digest id: %d", rh->digest_new);
	log_dbg(cd, "reencrypt-final segment: %s", rh->jobj_segment_new ? json_object_to_json_string_ext(rh->jobj_segment_new, JSON_C_TO_STRING_PRETTY) : "<missing>");

	log_dbg(cd, "reencrypt length: %" PRIu64, rh->length);
	log_dbg(cd, "reencrypt offset: %" PRIu64, rh->offset);
	log_dbg(cd, "reencrypt shift: %" PRIi64, rh->data_shift);
	log_dbg(cd, "reencrypt alignemnt: %zu", rh->alignment);
	log_dbg(cd, "reencrypt progress: %" PRIu64, rh->progress);

	rh->device_size = device_size;

	return rh->length < 512 ? -EINVAL : 0;
}

static size_t LUKS2_get_reencrypt_buffer_length(struct luks2_reenc_context *rh)
{
	if (rh->data_shift)
		return imaxabs(rh->data_shift);
	return rh->length;
}

static int _LUKS2_reenc_load(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	uint64_t device_size,
	struct luks2_reenc_context **rh,
	const struct crypt_params_reencrypt *params)
{
	int r;
	const struct crypt_params_reencrypt hdr_reenc_params = {
		.resilience = LUKS2_reencrypt_protection_type(hdr),
		.hash = LUKS2_reencrypt_protection_hash(hdr),
		.hotzone_size = LUKS2_DEFAULT_REENCRYPTION_LENGTH
	};
	struct luks2_reenc_context *tmp = calloc(1, sizeof (*tmp));

	if (!tmp)
		return -ENOMEM;

	if (!hdr_reenc_params.resilience) {
		r = -EINVAL;
		goto err;
	}

	/* skip context update if data shift is detected in header */
	if (!strcmp(hdr_reenc_params.resilience, "shift"))
		params = NULL;

	log_dbg(cd, "Initailizing reencryption context (%s).", params ? "update" : "load");

	if (!params)
		params = &hdr_reenc_params;

	r = _reenc_load(cd, hdr, tmp, device_size, params);
	if (r)
		goto err;

	tmp->reenc_buffer = aligned_malloc((void **)&tmp->reenc_buffer, LUKS2_get_reencrypt_buffer_length(tmp), device_alignment(crypt_data_device(cd))); 
	if (!tmp->reenc_buffer) {
		r = -ENOMEM;
		goto err;
	}

	*rh = tmp;

	return 0;
err:
	LUKS2_reenc_context_free(cd, tmp);

	return r;
}

static int _load_segments(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reenc_context *rh, uint64_t device_size)
{
	int r;

	log_dbg(cd, "Calculating segments.");

	r = LUKS2_reenc_create_segments(cd, hdr, rh, device_size);
	if (r) {
		log_err(cd, "Failed to create reencryption segments.");
		return r;
	}

	return r;
}

static int _load_segments_crashed(struct crypt_device *cd,
				struct luks2_hdr *hdr,
			        struct luks2_reenc_context *rh)
{
	int r;
	uint64_t data_offset = crypt_get_data_offset(cd) << SECTOR_SHIFT;

	if (!rh)
		return -EINVAL;

	rh->jobj_segs_pre = json_object_new_object();
	if (!rh->jobj_segs_pre)
		return -ENOMEM;

	json_object_object_foreach(LUKS2_get_segments_jobj(hdr), key, val) {
		if (LUKS2_segment_ignore(val))
			continue;
		json_object_object_add(rh->jobj_segs_pre, key, json_object_get(val));
	}

	r = LUKS2_reenc_create_segments_after(cd, hdr, rh, data_offset);
	if (r) {
		json_object_put(rh->jobj_segs_pre);
		rh->jobj_segs_pre = NULL;
	}

	return r;
}

static int LUKS2_reenc_load_crashed(struct crypt_device *cd,
	struct luks2_hdr *hdr, uint64_t device_size, struct luks2_reenc_context **rh)
{
	int r, reenc_seg;

	r = _LUKS2_reenc_load(cd, hdr, device_size, rh, NULL);
	if (!r)
		r = _load_segments_crashed(cd, hdr, *rh);

	if (!r) {
		reenc_seg = json_segments_segment_in_reencrypt(LUKS2_get_segments_jobj(hdr));
		if (reenc_seg < 0)
			r = -EINVAL;
		else
			(*rh)->length = LUKS2_segment_size(hdr, reenc_seg, 0);
	}

	if (!r && ((*rh)->rp.type == REENC_PROTECTION_CHECKSUM)) {
		/* we have to override calculated alignment with value stored in mda */
		(*rh)->alignment = LUKS2_reencrypt_protection_sector_size(hdr);
		if (!(*rh)->alignment) {
			log_dbg(cd, "Failed to get read resilience sector_size from metadata.");
			r = -EINVAL;
		}
	}
	if (r) {
		LUKS2_reenc_context_free(cd, *rh);
		*rh = NULL;
	}
	return r;
}

static int _init_storage_wrappers(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		struct volume_key *vks)
{
	int r;
	struct volume_key *vk;
	uint32_t wrapper_flags = DISABLE_KCAPI;

	vk = crypt_volume_key_by_id(vks, rh->digest_old);
	r = crypt_storage_wrapper_init(cd, &rh->cw1, crypt_data_device(cd),
			LUKS2_reencrypt_get_data_offset_old(hdr),
			crypt_get_iv_offset(cd),
			LUKS2_reencrypt_get_sector_size_old(hdr),
			LUKS2_reencrypt_segment_cipher_old(hdr),
			vk, wrapper_flags | OPEN_READONLY);
	if (r) {
		log_dbg(cd, "Failed to initialize storage wrapper for old cipher.");
		return r;
	}
	rh->wflags1 = wrapper_flags | OPEN_READONLY;
	log_dbg(cd, "Old cipher storage wrapper type: %d.", crypt_storage_wrapper_get_type(rh->cw1));

	if (rh->rp.type == REENC_PROTECTION_CHECKSUM) {
		wrapper_flags &= ~DISABLE_KCAPI;
		wrapper_flags |= DISABLE_DMCRYPT;
	}

	vk = crypt_volume_key_by_id(vks, rh->digest_new);
	r = crypt_storage_wrapper_init(cd, &rh->cw2, crypt_data_device(cd),
			LUKS2_reencrypt_get_data_offset_new(hdr),
			crypt_get_iv_offset(cd),
			LUKS2_reencrypt_get_sector_size_new(hdr),
			LUKS2_reencrypt_segment_cipher_new(hdr),
			vk, wrapper_flags);
	if (r) {
		log_dbg(cd, "Failed to initialize storage wrapper for new cipher.");
		return r;
	}
	rh->wflags2 = wrapper_flags;
	log_dbg(cd, "New cipher storage wrapper type: %d", crypt_storage_wrapper_get_type(rh->cw2));

	return 0;
}

static int LUKS2_reenc_context_set_name(struct luks2_reenc_context *rh, const char *name)
{
	if (!rh | !name)
		return -EINVAL;

	if (!(rh->device_name = strdup(name)))
		return -ENOMEM;
	if (asprintf(&rh->hotzone_name, "%s-hotzone", name) < 0) {
		rh->hotzone_name = NULL;
		return -ENOMEM;
	}
	if (asprintf(&rh->overlay_name, "%s-overlay", name) < 0) {
		rh->overlay_name = NULL;
		return -ENOMEM;
	}

	rh->online = true;
	return 0;
}

int LUKS2_reenc_recover(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	struct volume_key *vks)
{
	struct volume_key *vk_old, *vk_new;
	size_t count, s;
	ssize_t read, w;
	unsigned resilience;
	uint64_t area_offset, area_length, area_length_read, crash_iv_offset,
		 data_offset = crypt_get_data_offset(cd) << SECTOR_SHIFT;
	int r, new_sector_size, old_sector_size, rseg = json_segments_segment_in_reencrypt(rh->jobj_segs_pre), fd = -1;
	char *checksum_tmp = NULL, *data_buffer = NULL;
	struct crypt_storage_wrapper *cw1 = NULL, *cw2 = NULL;

	resilience = rh->rp.type;

	if (rseg < 0 || rh->length < 512)
		return -EINVAL;

	vk_new = crypt_volume_key_by_id(vks, rh->digest_new);
	if (!vk_new && rh->type != DECRYPT)
		return -EINVAL;
	vk_old = crypt_volume_key_by_id(vks, rh->digest_old);
	if (!vk_old && rh->type != ENCRYPT)
		return -EINVAL;
	old_sector_size = json_segment_get_sector_size(LUKS2_reencrypt_segment_old(hdr));
	new_sector_size = json_segment_get_sector_size(LUKS2_reencrypt_segment_new(hdr));
	crash_iv_offset = json_segment_get_iv_offset(json_segments_get_segment(rh->jobj_segs_pre, rseg));

	log_dbg(cd, "crash_offset: %" PRIu64 ", crash_length: %" PRIu64 ",  crash_iv_offset: %" PRIu64, data_offset + rh->offset, rh->length, crash_iv_offset);

	r = crypt_storage_wrapper_init(cd, &cw2, crypt_data_device(cd),
			data_offset + rh->offset, crash_iv_offset, new_sector_size,
			LUKS2_reencrypt_segment_cipher_new(hdr), vk_new, 0);
	if (r) {
		log_err(cd, "Failed to initialize new key storage wrapper.");
		return r;
	}

	if (LUKS2_keyslot_area(hdr, rh->reenc_keyslot, &area_offset, &area_length)) {
		r = -EINVAL;
		goto out;
	}

	data_buffer = aligned_malloc((void **)&data_buffer,
			rh->length, device_alignment(crypt_data_device(cd)));
	if (!data_buffer) {
		r = -ENOMEM;
		goto out;
	}

	switch (resilience) {
	case  REENC_PROTECTION_CHECKSUM:
		log_dbg(cd, "Checksums based recovery.");

		r = crypt_storage_wrapper_init(cd, &cw1, crypt_data_device(cd),
				data_offset + rh->offset, crash_iv_offset, old_sector_size,
				LUKS2_reencrypt_segment_cipher_old(hdr), vk_old, 0);
		if (r) {
			log_err(cd, "Failed to initialize old segment storage wrapper.");
			goto out;
		}

		count = rh->length / rh->alignment;
		area_length_read = (count + 1) * rh->rp.p.csum.hash_size;
		if (area_length_read > area_length) {
			log_dbg(cd, "Internal error in calculated area_length.");
			r = -EINVAL;
			goto out;
		}

		checksum_tmp = malloc(rh->rp.p.csum.hash_size);
		if (!checksum_tmp) {
			r = -ENOMEM;
			goto out;
		}

		/* TODO: lock for read */
		fd = device_open(cd, crypt_metadata_device(cd), O_RDONLY);
		if (fd < 0) {
			log_err(cd, "Failed to open mdata device.");
			goto out;
		}

		/* read old data checksums */
		read = read_lseek_blockwise(fd, device_block_size(cd, crypt_metadata_device(cd)),
					device_alignment(crypt_metadata_device(cd)), rh->rp.p.csum.checksums, area_length_read, area_offset);
		close(fd);
		if (read < 0 || (size_t)read != area_length_read) {
			log_err(cd, "Failed to read checksums.");
			r = -EINVAL;
			goto out;
		}

		read = crypt_storage_wrapper_read(cw2, 0, data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_err(cd, "Failed to read hotzone area.");
			r = -EINVAL;
			goto out;
		}

		for (s = 0; s < count; s++) {
			if (crypt_hash_write(rh->rp.p.csum.ch, data_buffer + (s * rh->alignment), rh->alignment)) {
				log_err(cd, "Failed to write hash.");
				r = EINVAL;
				goto out;
			}
			if (crypt_hash_final(rh->rp.p.csum.ch, checksum_tmp, rh->rp.p.csum.hash_size)) {
				log_err(cd, "Failed to finalize hash.");
				r = EINVAL;
				goto out;
			}
			if (!memcmp(checksum_tmp, (char *)rh->rp.p.csum.checksums + (s * rh->rp.p.csum.hash_size), rh->rp.p.csum.hash_size)) {
				log_dbg(cd, "Sector %zu (size %zu, offset %zu) needs recovery", s, rh->alignment, s * rh->alignment);
				if (crypt_storage_wrapper_decrypt(cw1, s * rh->alignment, data_buffer + (s * rh->alignment), rh->alignment)) {
					log_err(cd, "Failed to decrypt sector %zu.", s);
					r = -EINVAL;
					goto out;
				}
				w = crypt_storage_wrapper_encrypt_write(cw2, s * rh->alignment, data_buffer + (s * rh->alignment), rh->alignment);
				if (w < 0 || (size_t)w != rh->alignment) {
					log_err(cd, "Failed to recover sector %zu.", s);
					r = -EINVAL;
					goto out;
				}
			}
		}

		read = crypt_storage_wrapper_read(cw2, 0, data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_err(cd, "Failed to read hotzone area after recovery attempt.");
			r = -EINVAL;
			goto out;
		}

		if (crypt_hash_write(rh->rp.p.csum.ch, data_buffer, rh->length)) {
			log_err(cd, "Failed to write final hash.");
			r = EINVAL;
			goto out;
		}
		if (crypt_hash_final(rh->rp.p.csum.ch, checksum_tmp, rh->rp.p.csum.hash_size)) {
			log_err(cd, "Failed to finalize final hash.");
			r = EINVAL;
			goto out;
		}

		if (memcmp(checksum_tmp, (char *)rh->rp.p.csum.checksums + (s * rh->rp.p.csum.hash_size), rh->rp.p.csum.hash_size))
			/* TODO: so....what next? */
			log_err(cd, "Recovery failed. Checksum of new ciphertext doesn't match starting at %" PRIu64 ", length %" PRIu64 ".", data_offset + rh->offset, rh->length);
		else
			log_dbg(cd, "Checksums based recovery was successfull.");

		r = 0;
		break;
	case  REENC_PROTECTION_JOURNAL:
		log_dbg(cd, "Journal based recovery.");

		/* FIXME: validation candidate */
		if (rh->length > area_length) {
			r = -EINVAL;
			log_err(cd, "Invalid resilience parameters (internal error).");
			goto out;
		}

		/* TODO locking */
		r = crypt_storage_wrapper_init(cd, &cw1, crypt_metadata_device(cd),
				area_offset, crash_iv_offset, old_sector_size,
				LUKS2_reencrypt_segment_cipher_old(hdr), vk_old, 0);
		if (r) {
			log_err(cd, "Failed to initialize old key storage wrapper.");
			goto out;
		}
		read = crypt_storage_wrapper_read_decrypt(cw1, 0, data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_dbg(cd, "Failed to read journaled data.");
			r = -EIO;
			/* may content plaintext */
			crypt_memzero(data_buffer, rh->length);
			goto out;
		}
		read = crypt_storage_wrapper_encrypt_write(cw2, 0, data_buffer, rh->length);
		/* may content plaintext */
		crypt_memzero(data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_dbg(cd, "recovery write failed.");
			r = -EINVAL;
			goto out;
		}

		r = 0;
		break;
	case  REENC_PROTECTION_DATASHIFT:
		log_dbg(cd, "Data shift based recovery.");

		if (rseg == 0) {
			r = crypt_storage_wrapper_init(cd, &cw1, crypt_data_device(cd),
					json_segment_get_offset(rh->jobj_segment_moved, 0), 0, 0,
					LUKS2_reencrypt_segment_cipher_old(hdr), NULL, 0);
		} else
			r = crypt_storage_wrapper_init(cd, &cw1, crypt_data_device(cd),
					data_offset + rh->offset - imaxabs(rh->data_shift), 0, 0,
					LUKS2_reencrypt_segment_cipher_old(hdr), NULL, 0);
		if (r) {
			log_err(cd, "Failed to initialize old key storage wrapper.");
			goto out;
		}

		read = crypt_storage_wrapper_read_decrypt(cw1, 0, data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_dbg(cd, "Failed to read data.");
			r = -EIO;
			/* may content plaintext */
			crypt_memzero(data_buffer, rh->length);
			goto out;
		}

		read = crypt_storage_wrapper_encrypt_write(cw2, 0, data_buffer, rh->length);
		/* may content plaintext */
		crypt_memzero(data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_dbg(cd, "recovery write failed.");
			r = -EINVAL;
			goto out;
		}
		r = 0;
		break;
	default:
		r = -EINVAL;
	}
out:
	free(data_buffer);
	free(checksum_tmp);
	crypt_storage_wrapper_destroy(cw1);
	crypt_storage_wrapper_destroy(cw2);

	return r;
}

static int _add_moved_segment(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh)
{
	int s = LUKS2_segment_first_unused_id(hdr);

	if (!rh->jobj_segment_moved)
		return 0;

	if (s < 0)
		return s;

	if (json_object_object_add_by_uint(LUKS2_get_segments_jobj(hdr), s, json_object_get(rh->jobj_segment_moved))) {
		json_object_put(rh->jobj_segment_moved);
		return -EINVAL;
	}

	return 0;
}

static int _add_backup_segment(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		unsigned final)
{
	int digest, s = LUKS2_segment_first_unused_id(hdr);
	json_object *jobj;

	if (s < 0)
		return s;

	digest = final ? rh->digest_new : rh->digest_old;
	jobj = final ? rh->jobj_segment_new : rh->jobj_segment_old;

	if (json_object_object_add_by_uint(LUKS2_get_segments_jobj(hdr), s, json_object_get(jobj))) {
		json_object_put(jobj);
		return -EINVAL;
	}

	return LUKS2_digest_segment_assign(cd, hdr, s, digest, 1, 0);
}

static int _assign_segments_simple(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	unsigned pre,
	unsigned commit)
{
	int r, sg;

	if (pre && json_segments_count(rh->jobj_segs_pre) > 0) {
		log_dbg(cd, "Setting 'pre' segments.");

		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_pre, 0);
		if (!r)
			rh->jobj_segs_pre = NULL;
	} else if (!pre && json_segments_count(rh->jobj_segs_after) > 0) {
		log_dbg(cd, "Setting 'after' segments.");
		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_after, 0);
		if (!r)
			rh->jobj_segs_after = NULL;
	} else {
		log_dbg(cd, "No segments to set.");
		return -EINVAL;
	}

	if (r) {
		log_err(cd, "Failed to assign new enc segments.");
		return r;
	}

	r = _add_backup_segment(cd, hdr, rh, rh->type == ENCRYPT);
	if (r) {
		log_dbg(cd, "Failed to assign reencryption final backup segment.");
		return r;
	}

	r = _add_moved_segment(cd, hdr, rh);
	if (r) {
		log_dbg(cd, "Failed to assign reencryption moved backup segment.");
		return r;
	}

	for (sg = 0; sg < LUKS2_segments_count(hdr); sg++) {
		if (LUKS2_segment_is_type(hdr, sg, "crypt") &&
		    LUKS2_digest_segment_assign(cd, hdr, sg, rh->type == ENCRYPT ? rh->digest_new : rh->digest_old, 1, 0)) {
			log_err(cd, "Failed to assign digest %u to segment %u.", rh->digest_new, sg);
			return -EINVAL;
		}
	}

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

static int reenc_assign_segments(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reenc_context *rh, unsigned pre, unsigned commit)
{
	int r, rseg, scount;

	/* FIXME: validate in reencrypt context load */
	if (rh->digest_new < 0 && rh->type != DECRYPT)
		return -EINVAL;

	if (LUKS2_digest_segment_assign(cd, hdr, CRYPT_ANY_SEGMENT, CRYPT_ANY_DIGEST, 0, 0))
		return -EINVAL;

	if (rh->type == ENCRYPT || rh->type == DECRYPT)
		return _assign_segments_simple(cd, hdr, rh, pre, commit);

	if (pre && rh->jobj_segs_pre) {
		log_dbg(cd, "Setting 'pre' segments.");

		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_pre, 0);
		if (!r)
			rh->jobj_segs_pre = NULL;
	} else if (!pre && rh->jobj_segs_after) {
		log_dbg(cd, "Setting 'after' segments.");
		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_after, 0);
		if (!r)
			rh->jobj_segs_after = NULL;
	} else
		return -EINVAL;

	scount = LUKS2_segments_count(hdr);

	/* segment in reencryption has to hold reference on both digests */
	rseg = json_segments_segment_in_reencrypt(LUKS2_get_segments_jobj(hdr));
	if (rseg < 0 && pre)
		return -EINVAL;

	if (rseg >= 0) {
		LUKS2_digest_segment_assign(cd, hdr, rseg, rh->digest_new, 1, 0);
		LUKS2_digest_segment_assign(cd, hdr, rseg, rh->digest_old, 1, 0);
	}

	if (pre) {
		if (rseg > 0)
			LUKS2_digest_segment_assign(cd, hdr, 0, rh->digest_new, 1, 0);
		if (scount > rseg + 1)
			LUKS2_digest_segment_assign(cd, hdr, rseg + 1, rh->digest_old, 1, 0);
	} else {
		LUKS2_digest_segment_assign(cd, hdr, 0, rh->digest_new, 1, 0);
		if (scount > 1)
			LUKS2_digest_segment_assign(cd, hdr, 1, rh->digest_old, 1, 0);
	}

	if (r) {
		log_err(cd, "Failed to set segments.");
		return r;
	}

	r = _add_backup_segment(cd, hdr, rh, 0);
	if (r) {
		log_err(cd, "Failed to assign reencrypt previous backup segment.");
		return r;
	}
	r = _add_backup_segment(cd, hdr, rh, 1);
	if (r) {
		log_err(cd, "Failed to assign reencrypt final backup segment.");
		return r;
	}

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

int LUKS2_reenc_update_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh)
{
	return reenc_assign_segments(cd, hdr, rh, 0, 1);
}

/* FIXME: seems to be temporary and for encryption initialization only */
static int _encrypt_set_segments(struct crypt_device *cd, struct luks2_hdr *hdr, uint64_t dev_size, int64_t data_shift)
{
	int r;
	uint64_t first_segment_offset, first_segment_length,
		 second_segment_offset, second_segment_length,
		 data_offset = LUKS2_get_data_offset(hdr) << SECTOR_SHIFT;
	json_object *jobj_segment_first = NULL, *jobj_segment_second = NULL, *jobj_segments;

	if (dev_size < imaxabs(data_shift))
		return -EINVAL;

	if (data_shift > 0)
		return -ENOTSUP;

	if (data_shift < 0) {
		/* future data_device layout: [future LUKS2 header][+shift][second data segment][luks2size+shift][first data segment] */
		first_segment_offset = dev_size + data_offset + data_shift;
		first_segment_length = -data_shift;
		second_segment_offset = -data_shift;
		second_segment_length = dev_size + data_offset + 3 * data_shift;
	} else {
		/* future data_device layout with deatached header: [first data segment] */
		first_segment_offset = data_offset;
		first_segment_length = 0; /* dynamic */
	}

	jobj_segments = json_object_new_object();
	if (!jobj_segments)
		return -ENOMEM;

	r = -EINVAL;
	if (data_shift) {
		jobj_segment_first =  json_segment_create_linear(first_segment_offset, &first_segment_length, 0);
		jobj_segment_second = json_segment_create_linear(second_segment_offset, &second_segment_length, 0);
		if (!jobj_segment_second) {
			log_err(cd, "Failed generate 2nd segment.");
			goto err;
		}
	} else
		jobj_segment_first =  json_segment_create_linear(first_segment_offset, first_segment_length ? &first_segment_length : NULL, 0);

	if (!jobj_segment_first) {
		log_err(cd, "Failed generate 1st segment.");
		goto err;
	}

	json_object_object_add(jobj_segments, "0", jobj_segment_first);
	if (jobj_segment_second)
		json_object_object_add(jobj_segments, "1", jobj_segment_second);

	LUKS2_digest_segment_assign(cd, hdr, CRYPT_ANY_SEGMENT, CRYPT_ANY_DIGEST, 0, 0);

	r = LUKS2_segments_set(cd, hdr, jobj_segments, 0);
err:
	return r;
}

static int reenc_setup_segments(struct crypt_device *cd,
				struct luks2_hdr *hdr,
				struct device *hz_device,
				struct volume_key *vks,
				struct dm_target *result,
				uint64_t size)
{
	bool reenc_seg;
	struct volume_key *vk;
	uint64_t segment_size, segment_offset, segment_start = 0;
	int r;
	int s = 0;
	json_object *jobj, *jobj_segments = LUKS2_get_segments_jobj(hdr);

	while (result) {
		jobj = json_segments_get_segment(jobj_segments, s);
		if (!jobj) {
			log_dbg(cd, "Internal error. Segment %u is null.", s);
			r = -EINVAL;
			goto out;
		}

		reenc_seg = (s == json_segments_segment_in_reencrypt(jobj_segments));

		segment_offset = json_segment_get_offset(jobj, 1);
		segment_size = json_segment_get_size(jobj, 1);
		/* 'dynamic' length allowed in last segment only */
		if (!segment_size && !result->next)
			segment_size = (size >> SECTOR_SHIFT) - segment_start;
		if (!segment_size) {
			log_dbg(cd, "Internal error. Wrong segment size %u", s);
			r = -EINVAL;
			goto out;
		}

		if (!strcmp(json_segment_type(jobj), "crypt")) {
			vk = crypt_volume_key_by_id(vks, reenc_seg ? LUKS2_reencrypt_digest_new(hdr) : LUKS2_digest_by_segment(hdr, s));
			if (!vk) {
				log_err(cd, "Missing key for dm-crypt segment %d", s);
				r = -EINVAL;
				goto out;
			}

			if (reenc_seg)
				segment_offset -= crypt_get_data_offset(cd);

			r = dm_crypt_target_set(result, segment_start, segment_size,
						reenc_seg ? hz_device : crypt_data_device(cd),
						vk,
						json_segment_get_cipher(jobj),
						json_segment_get_iv_offset(jobj),
						segment_offset,
						"none",
						0,
						json_segment_get_sector_size(jobj));
			if (r) {
				log_err(cd, _("Failed to set dm-crypt segment."));
				goto out;
			}
		} else if (!strcmp(json_segment_type(jobj), "linear")) {
			r = dm_linear_target_set(result, segment_start, segment_size, reenc_seg ? hz_device : crypt_data_device(cd), segment_offset);
			if (r) {
				log_err(cd, _("Failed to set dm-linear segment."));
				goto out;
			}
		} else {
			r = -EINVAL;
			goto out;
		}

		segment_start += segment_size;
		s++;
		result = result->next;
	}

	return s;
out:
	return r;
}

/* GLOBAL FIXME: audit function names and parameters names */

/* FIXME:
 * 	1) audit log routines
 * 	2) can't we derive hotzone device name from crypt context? (unlocked name, device uuid, etc?)
 */
static int reenc_load_overlay_device(struct crypt_device *cd, struct luks2_hdr *hdr,
	const char *overlay, const char *hotzone, struct volume_key *vks, uint64_t size)
{
	char hz_path[PATH_MAX];
	int r;

	struct device *hz_dev = NULL;
	struct crypt_dm_active_device dmd = {
		.flags = CRYPT_ACTIVATE_KEYRING_KEY,
	};

	log_dbg(cd, "Loading new table for overlay device %s.", overlay);

	r = snprintf(hz_path, PATH_MAX, "%s/%s", dm_get_dir(), hotzone);
	if (r < 0 || r >= PATH_MAX) {
		r = -EINVAL;
		goto out;
	}

	r = device_alloc(cd, &hz_dev, hz_path);
	if (r) {
		log_err(cd, "Failed to alocate device %s.", hz_path);
		goto out;
	}

	r = dm_targets_allocate(&dmd.segment, LUKS2_segments_count(hdr));
	if (r) {
		log_err(cd, "Failed to allocate dm segments.");
		goto out;
	}

	r = reenc_setup_segments(cd, hdr, hz_dev, vks, &dmd.segment, size);
	if (r < 0) {
		log_err(cd, "Failed to create dm segments.");
		goto out;
	}

	r = dm_reload_device(cd, overlay, &dmd, 0, 0);
	if (!r) {
		log_dbg(cd, "Current %s device has following table in inactive slot:", overlay);
		dm_debug_table(&dmd);
	}

	/* what else on error here ? */
out:
	dm_targets_free(cd, &dmd);
	device_free(cd, hz_dev);

	return r;
}

/* FIXME:
 *	remove completely. the device should be read from header directly
 *
 * 	1) audit log functions
 * 	2) check flags
 */
static int reenc_replace_device(struct crypt_device *cd, const char *target, const char *source, uint32_t flags)
{
	int r, exists = 1;
	uint64_t size = 0;
	struct crypt_dm_active_device dmd_source;
	struct crypt_dm_active_device dmd_target = {};
	uint32_t dmflags = DM_SUSPEND_SKIP_LOCKFS | DM_SUSPEND_NOFLUSH;

	log_dbg(cd, "Replacing table in device %s with table from device %s.", target, source);

	/* check only whether target device exists */
	r = dm_status_device(cd, target);
	if (r < 0) {
		if (r == -ENODEV)
			exists = 0;
		else
			return r;
	}

	r = dm_query_device(cd, source, DM_ACTIVE_DEVICE | DM_ACTIVE_CRYPT_CIPHER |
			    DM_ACTIVE_CRYPT_KEYSIZE | DM_ACTIVE_CRYPT_KEY, &dmd_source);

	if (r < 0)
		return r;

	dmd_source.flags |= flags;

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_OK,
				crypt_get_data_offset(cd), &size, &dmd_source.flags);

	if (r)
		goto err;

	if (exists && size != dmd_source.size) {
		log_err(cd, "Source and target device sizes don't match. Source %" PRIu64 ", target: %" PRIu64 ".",
			dmd_source.size, size);
		r = -EINVAL;
		goto err;
	}

	if (exists) {
		r = dm_reload_device(cd, target, &dmd_source, 0, 0);
		if (!r) {
			log_dbg(cd, "Current %s device has following table in inactive slot:", target);
			dm_debug_table(&dmd_source);
		}
		if (!r) {
			log_dbg(cd, "Resuming device %s", target);
			r = dm_resume_device(cd, target, dmflags | act2dmflags(dmd_source.flags));
		}
	} else {
		r = dm_create_device(cd, target, CRYPT_LUKS2, &dmd_source);
		if (!r) {
			log_dbg(cd, "Created %s device with following table:", target);
			dm_debug_table(&dmd_source);
		}
	}
err:
	dm_targets_free(cd, &dmd_source);
	dm_targets_free(cd, &dmd_target);

	return r;
}

static int reenc_swap_backing_device(struct crypt_device *cd, const char *name,
			      const char *new_backend_name, uint32_t flags)
{
	int r;
	struct device *overlay_dev = NULL;
	char overlay_path[PATH_MAX] = { 0 };

	struct crypt_dm_active_device dmd = {
		.flags = flags,
	};

	log_dbg(cd, "Redirecting %s mapping to new backing device: %s.", name, new_backend_name);

	r = snprintf(overlay_path, PATH_MAX, "%s/%s", dm_get_dir(), new_backend_name);
	if (r < 0 || r >= PATH_MAX) {
		r = -EINVAL;
		goto out;
	}

	r = device_alloc(cd, &overlay_dev, overlay_path);
	if (r) {
		log_err(cd, "Failed to allocate device for new backing device.");
		goto out;
	}

	r = device_block_adjust(cd, overlay_dev, DEV_OK,
				0, &dmd.size, &dmd.flags);
	if (r)
		goto out;

	r = dm_linear_target_set(&dmd.segment, 0, dmd.size, overlay_dev, 0);
	if (r)
		goto out;

	r = dm_reload_device(cd, name, &dmd, 0, 0);
	if (!r) {
		log_dbg(cd, "Current %s device has following table in inactive slot:", name);
		dm_debug_table(&dmd);
	}
	if (!r) {
		log_dbg(cd, "Resuming device %s", name);
		r = dm_resume_device(cd, name, dmd.flags);
	}

out:
	dm_targets_free(cd, &dmd);
	device_free(cd, overlay_dev);

	return r;
}

static int reenc_activate_hotzone_device(struct crypt_device *cd, const char *name, uint32_t flags)
{
	int r;
	uint64_t new_offset = LUKS2_reencrypt_get_data_offset_new(crypt_get_hdr(cd, CRYPT_LUKS2)) >> SECTOR_SHIFT;

	struct crypt_dm_active_device dmd = {
		.flags = flags,
	};

	log_dbg(cd, "Activating hotzone device %s.", name);

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_OK,
				new_offset, &dmd.size, &dmd.flags);
	if (r)
		goto err;

	r = dm_linear_target_set(&dmd.segment, 0, dmd.size, crypt_data_device(cd), new_offset);
	if (r)
		goto err;

	r = dm_create_device(cd, name, "HOTZONE", &dmd);

	if (!r) {
		log_dbg(cd, "Created following %s device:", name);
		dm_debug_table(&dmd);
	}
err:
	dm_targets_free(cd, &dmd);

	return r;
}

/* pass reenc context instead? */
static int reenc_init_helper_devices(struct crypt_device *cd,
				     const char *name,
				     const char *hotzone,
				     const char *overlay)
{
	int r;

	/* Activate hotzone device 1:1 linear mapping to data_device */
	r = reenc_activate_hotzone_device(cd, hotzone, CRYPT_ACTIVATE_PRIVATE);
	if (r) {
		log_err(cd, "Failed to activate hotzone device %s.", hotzone);
		return r;
	}

	/*
	 * Activate overlay device with exactly same table as original 'name' mapping.
	 * Note that within this step the 'name' device may already include a table
	 * constructed from more than single dm-crypt segment. Therefore transfer
	 * mapping as is.
	 *
	 * If we're about to resume reencryption orig mapping has to be already validated for
	 * abrupt shutdown and rchunk_offset has to point on next chunk to reencrypt!
	 *
	 * TODO: in crypt_activate_by*
	 */
	r = reenc_replace_device(cd, overlay, name, CRYPT_ACTIVATE_PRIVATE);
	if (r) {
		log_err(cd, "Failed to activate overlay device %s with actual origin table.", overlay);
		goto err;
	}

	/* swap origin mapping to overlay device */
	r = reenc_swap_backing_device(cd, name, overlay, CRYPT_ACTIVATE_KEYRING_KEY);
	if (r) {
		log_err(cd, "Failed to load new maping for device %s.", name);
		goto err;
	}

	/*
	 * Now the 'name' (unlocked luks) device is mapped via dm-linear to an overlay dev.
	 * The overlay device has a original live table of 'name' device in-before the swap.
	 */

	return 0;
err:
	/* TODO: force error helper devices on error path */
	dm_remove_device(cd, overlay, 0);
	dm_remove_device(cd, hotzone, 0);

	return r;
}

/* TODO:
 * 	1) audit error path. any error in this routine is fatal and should be unlikely.
 * 	   usualy it would hint some collision with another userspace process touching
 * 	   dm devices directly.
 */
static int reenc_refresh_helper_devices(struct crypt_device *cd, const char *overlay, const char *hotzone)
{
	int r;

	/*
	 * we have to explicitely suspend the overlay device before suspending
	 * the hotzone one. Resuming overlay device (aka switching tables) only
	 * after suspending the hotzone may lead to deadlock.
	 *
	 * In other words: always suspend the stack from top to bottom!
	 */
	r = dm_suspend_device(cd, overlay, DM_SUSPEND_SKIP_LOCKFS | DM_SUSPEND_NOFLUSH);
	if (r) {
		log_err(cd, "Failed to suspend %s.", overlay);
		return r;
	}

	log_dbg(cd, "Suspended device %s",  overlay);

	/* suspend HZ device */
	r = dm_suspend_device(cd, hotzone, DM_SUSPEND_SKIP_LOCKFS | DM_SUSPEND_NOFLUSH);
	if (r) {
		log_err(cd, "Failed to suspend %s.", hotzone);
		return r;
	}

	log_dbg(cd, "Suspended device %s",  hotzone);

	/* resume overlay device: inactive table (with hotozne) -> live */
	r = dm_resume_device(cd, overlay, DM_RESUME_PRIVATE);
	if (r)
		log_err(cd, "Failed to resume device %s.", overlay);
	else
		log_dbg(cd, "Resume device %s.", overlay);

	return r;
}

static int reenc_refresh_overlay_devices(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const char *overlay,
		const char *hotzone,
		struct volume_key *vks,
		uint64_t device_size)
{
	int r = reenc_load_overlay_device(cd, hdr, overlay, hotzone, vks, device_size);
	if (r) {
		log_err(cd, "Failed to reload overlay device %s.", overlay);
		return REENC_ERR;
	}

	r = reenc_refresh_helper_devices(cd, overlay, hotzone);
	if (r) {
		log_err(cd, "Failed to refresh helper devices.");
		return REENC_ROLLBACK;
	}

	return REENC_OK;
}

static int move_data(struct crypt_device *cd, int devfd, int64_t data_shift)
{
	void *buffer;
	int r;
	ssize_t ret;
	uint64_t buffer_len, offset;
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	log_dbg(cd, "Going to move data from head of data device.");

	buffer_len = imaxabs(data_shift);
	if (!buffer_len)
		return -EINVAL;

	offset = json_segment_get_offset(LUKS2_get_segment_jobj(hdr, 0), 0);

	/* this is nonsense anyway */
	if (buffer_len != json_segment_get_size(LUKS2_get_segment_jobj(hdr, 0), 0)) {
		log_dbg(cd, "buffer_len %zu, segment size %zu", buffer_len, json_segment_get_size(LUKS2_get_segment_jobj(hdr, 0), 0));
		return -EINVAL;
	}

	buffer = aligned_malloc((void **)&buffer, buffer_len, device_alignment(crypt_data_device(cd)));
	if (!buffer)
		return -ENOMEM;

	ret = read_lseek_blockwise(devfd,
			device_block_size(cd, crypt_data_device(cd)),
			device_alignment(crypt_data_device(cd)),
			buffer, buffer_len, 0);
	if (ret < 0 || (uint64_t)ret != buffer_len) {
		r = -EIO;
		goto err;
	}

	log_dbg(cd, "Going to write %" PRIu64 " bytes at offset %" PRIu64, buffer_len, offset);
	ret = write_lseek_blockwise(devfd,
			device_block_size(cd, crypt_data_device(cd)),
			device_alignment(crypt_data_device(cd)),
			buffer, buffer_len, offset);
	if (ret < 0 || (uint64_t)ret != buffer_len) {
		r = -EIO;
		goto err;
	}

	r = 0;
err:
	memset(buffer, 0, buffer_len);
	free(buffer);
	return r;
}

int update_reencryption_flag(struct crypt_device *cd, int enable, bool commit)
{
	uint32_t reqs;
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	if (LUKS2_config_get_requirements(cd, hdr, &reqs))
		return -EINVAL;

	/* nothing to do */
	if (enable && (reqs & CRYPT_REQUIREMENT_ONLINE_REENCRYPT))
		return -EINVAL;

	/* nothing to do */
	if (!enable && !(reqs & CRYPT_REQUIREMENT_ONLINE_REENCRYPT))
		return -EINVAL;

	if (enable)
		reqs |= CRYPT_REQUIREMENT_ONLINE_REENCRYPT;
	else
		reqs &= ~CRYPT_REQUIREMENT_ONLINE_REENCRYPT;

	log_dbg(cd, "Going to %s reencryption requirement flag.", enable ? "store" : "wipe");

	return LUKS2_config_set_requirements(cd, hdr, reqs, commit);
}

static int _create_backup_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		int keyslot_new,
		const char *reenc_mode,
		const char *cipher,
		int64_t data_shift,
		uint64_t data_offset,
		const struct crypt_params_luks2 *params)
{
	int r, segment, digest_old = -1, digest_new = -1;
	json_object *jobj_segment_new = NULL, *jobj_segment_old = NULL, *jobj_segment_bcp = NULL;
	uint32_t sector_size = params ? params->sector_size : SECTOR_SIZE;
	uint64_t tmp;

	if (strcmp(reenc_mode, "decrypt")) {
		digest_new = LUKS2_digest_by_keyslot(hdr, keyslot_new);
		if (digest_new < 0)
			return -EINVAL;
	}

	if (strcmp(reenc_mode, "encrypt")) {
		digest_old = LUKS2_digest_by_segment(hdr, CRYPT_DEFAULT_SEGMENT);
		if (digest_old < 0)
			return -EINVAL;
	}

	segment = LUKS2_segment_first_unused_id(hdr);
	if (segment < 0)
		return -EINVAL;

	if (!strcmp(reenc_mode, "encrypt") && segment > 1) {
		json_object_copy(LUKS2_get_segment_jobj(hdr, 0), &jobj_segment_bcp);
		r = LUKS2_segment_set_flag(jobj_segment_bcp, "reencrypt-moved-segment");
		if (r)
			goto err;
		json_object_object_add_by_uint(LUKS2_get_segments_jobj(hdr), segment++, jobj_segment_bcp);
	}

	/* FIXME: Add detection for case (digest old == digest new && old segment == new segment) */
	if (digest_old >= 0)
		json_object_copy(LUKS2_get_segment_jobj(hdr, CRYPT_DEFAULT_SEGMENT), &jobj_segment_old);
	else if (!strcmp(reenc_mode, "encrypt")) {
		r = LUKS2_get_data_size(hdr, &tmp);
		if (r)
			goto err;
		jobj_segment_old = json_segment_create_linear(0, tmp ? &tmp : NULL, 0);
	}

	if (!jobj_segment_old) {
		r = -EINVAL;
		goto err;
	}

	r = LUKS2_segment_set_flag(jobj_segment_old, "reencrypt-previous");
	if (r)
		goto err;
	json_object_object_add_by_uint(LUKS2_get_segments_jobj(hdr), segment, jobj_segment_old);
	jobj_segment_old = NULL;
	if (digest_old >= 0)
		LUKS2_digest_segment_assign(cd, hdr, segment, digest_old, 1, 0);
	segment++;

	if (digest_new >= 0)
		jobj_segment_new = json_segment_create_crypt(
							data_offset * SECTOR_SIZE - (strcmp(reenc_mode, "encrypt") ? data_shift : 0),
							crypt_get_iv_offset(cd),
							NULL, cipher, sector_size, 0);
	else if (!strcmp(reenc_mode, "decrypt"))
		jobj_segment_new = json_segment_create_linear(data_offset * SECTOR_SIZE - data_shift, NULL, 0);

	if (!jobj_segment_new) {
		r = -EINVAL;
		goto err;
	}

	r = LUKS2_segment_set_flag(jobj_segment_new, "reencrypt-final");
	if (r)
		goto err;
	json_object_object_add_by_uint(LUKS2_get_segments_jobj(hdr), segment, jobj_segment_new);
	jobj_segment_new = NULL;
	if (digest_new >= 0)
		LUKS2_digest_segment_assign(cd, hdr, segment, digest_new, 1, 0);

	/* FIXME: also check occupied space by keyslot in shrunk area */
	if (data_shift && (crypt_metadata_device(cd) == crypt_data_device(cd))
	    && LUKS2_set_keyslots_size(cd, hdr, json_segment_get_offset(jobj_segment_new, 0))) {
		log_err(cd, "Failed to set new keyslots size.");
		r = -EINVAL;
		goto err;
	}

	return 0;
err:
	json_object_put(jobj_segment_new);
	json_object_put(jobj_segment_old);
	return r;
}

static int parse_reencryption_mode(const char *mode)
{
	return (!mode ||
		(strcmp(mode, "reencrypt") && strcmp(mode, "encrypt") && strcmp(mode, "decrypt")));
}

static int atomic_get_reencryption_flag(struct crypt_device *cd)
{
	int r;
	luks2_reencrypt_info ri;

	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r)
		return r;

	ri = LUKS2_reenc_status(crypt_get_hdr(cd, CRYPT_LUKS2));
	if (ri > REENCRYPT_NONE) {
		log_err(cd, _("Reencryption operation already in-progress or device is restricted by requirements."));
		return -EBUSY;
	}

	return 0;
}

/* only for reencryption or encryption initialization. Create reencrypt keyslot describing the operation */
/* it's basically special type of crypt_format */
int crypt_reencrypt_init(struct crypt_device *cd,
	int new_keyslot, /* to lookup digests only (since it's not covered by API atm) */
	const char *reencrypt_mode, /* "encrypt" or "reencrypt" */
	const char *cipher,
	const char *cipher_mode,
	int64_t data_shift,
	struct crypt_params_luks2 *params) /* NULL if not changed */
{
	char _cipher[128];
	struct luks2_hdr *hdr;
	int r, reencrypt_keyslot, devfd = -1;
	uint32_t sector_size = params ? params->sector_size : SECTOR_SIZE;
	uint64_t data_offset, dev_size = 0;

	if (onlyLUKS2(cd) || parse_reencryption_mode(reencrypt_mode))
		return -EINVAL;

	if (strcmp(reencrypt_mode, "decrypt") && (!(cipher && cipher_mode) || new_keyslot < 0))
		return -EINVAL;

	log_dbg(cd, "Initializing reencryption (mode: %s) in LUKS2 metadata.", reencrypt_mode);

	if (!cipher_mode || *cipher_mode == '\0')
		snprintf(_cipher, sizeof(_cipher), "%s", cipher);
	else
		snprintf(_cipher, sizeof(_cipher), "%s-%s", cipher, cipher_mode);

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	if (MISALIGNED(imaxabs(data_shift), sector_size >> SECTOR_SHIFT)) {
		log_err(cd, "Data shift is not aligned to requested encryption sector size (%" PRIu32 " bytes).", sector_size);
		return -EINVAL;
	}

	r = device_write_lock(cd, crypt_metadata_device(cd));
	if (r) {
		log_err(cd, _("Failed to acquire write lock on device %s."),
			device_path(crypt_metadata_device(cd)));
		return r;
	}

	r = atomic_get_reencryption_flag(cd);
	if (r) {
		device_write_unlock(cd, crypt_metadata_device(cd));
		return r;
	}

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_OK,
				crypt_get_data_offset(cd), &dev_size, NULL);
	if (r)
		goto err;

	if (MISALIGNED(dev_size, sector_size >> SECTOR_SHIFT)) {
		log_err(cd, "Data device is not aligned to requested encryption sector size (%" PRIu32 " bytes).", sector_size);
		r = -EINVAL;
		goto err;
	}

	data_shift <<= SECTOR_SHIFT;

	reencrypt_keyslot = LUKS2_keyslot_find_empty(hdr, NULL);
	if (reencrypt_keyslot < 0) {
		log_err(cd, "No room for another keyslot.");
		r = -EINVAL;
		goto err;
	}

	/*
	 * We must perform data move with exclusive open data device
	 * to exclude another cryptsetup process to colide with
	 * encryption initialization (or mount)
	 */
	if (data_shift && !strcmp(reencrypt_mode, "encrypt")) {
		if (imaxabs(data_shift) < LUKS2_get_data_offset(hdr)) {
			log_err(cd, "Data shift (%" PRIu64 " sectors) is less than LUKS2 header size (%" PRIu64 " sectors).", imaxabs(data_shift), LUKS2_get_data_offset(hdr));
			r = -EINVAL;
			goto err;
		}
		devfd = device_open_excl(cd, crypt_data_device(cd), O_RDWR);
		if (devfd < 0) {
			r = -EINVAL;
			log_err(cd, "Failed to open %s in exclusive mode (perhaps already mapped or mounted).",
				device_path(crypt_data_device(cd)));
			goto err;
		}
	}

	data_offset = crypt_get_data_offset(cd);
	if (!strcmp(reencrypt_mode, "encrypt")) {
		/* in-memory only */
		r = _encrypt_set_segments(cd, hdr, dev_size << SECTOR_SHIFT, data_shift);
		if (r)
			goto err;
	}

	r = LUKS2_keyslot_reencrypt_create(cd, hdr, reencrypt_keyslot,
					   reencrypt_mode, data_shift);
	if (r < 0)
		goto err;

	r = _create_backup_segments(cd, hdr, new_keyslot, reencrypt_mode, _cipher, data_shift, data_offset, params);
	if (r) {
		log_err(cd, _("Failed to create reencrypt backup segments."));
		goto err;
	}

	if (!strcmp(reencrypt_mode, "encrypt") && data_shift && move_data(cd, devfd, data_shift)) {
		r = -EIO;
		goto err;
	}

	/* This must be first and only metadata write in LUKS2 in crypt_reencrypt_init */
	r = update_reencryption_flag(cd, 1, true);
	if (r) {
		log_err(cd, "Failed to set online-reencryption requirement.");
		r = -EINVAL;
	} else
		r = reencrypt_keyslot;
err:
	device_write_unlock(cd, crypt_metadata_device(cd));
	if (devfd >= 0)
		close(devfd);

	if (r < 0)
		crypt_load(cd, CRYPT_LUKS2, NULL);

	return r;
}

static int reencrypt_hotzone_protect_init(struct crypt_device *cd,
	struct luks2_reenc_context *rh,
	const void *buffer, size_t buffer_len)
{
	size_t data_offset;
	int r;

	switch (rh->rp.type) {
	case REENC_PROTECTION_NOOP:
	case REENC_PROTECTION_JOURNAL:
	case REENC_PROTECTION_DATASHIFT:
		r = 0;
		break;
	case REENC_PROTECTION_CHECKSUM:
		log_dbg(cd, "Checksums hotzone resilience.");

		for (data_offset = 0, rh->rp.p.csum.last_checksum = rh->rp.p.csum.checksums; data_offset < buffer_len; data_offset += rh->alignment) {
			if (crypt_hash_write(rh->rp.p.csum.ch, (const char *)buffer + data_offset, rh->alignment)) {
				log_err(cd, "Failed to hash sector at offset %zu.", data_offset);
				return -EINVAL;
			}
			if (crypt_hash_final(rh->rp.p.csum.ch, rh->rp.p.csum.last_checksum, rh->rp.p.csum.hash_size)) {
				log_err(cd, "Failed to read sector hash.");
				return -EINVAL;
			}
			rh->rp.p.csum.last_checksum = (char *)rh->rp.p.csum.last_checksum + rh->rp.p.csum.hash_size;
		}
		r = 0;
		break;
	default:
		r = -EINVAL;
	}

	return r;
}

static int reencrypt_hotzone_protect_final(struct crypt_device *cd,
	struct luks2_hdr *hdr, struct luks2_reenc_context *rh,
	const void *buffer, size_t buffer_len)
{
	const void *pbuffer;
	size_t len;
	int r;

	if (rh->rp.type == REENC_PROTECTION_NOOP)
		return 0;

	if (rh->rp.type == REENC_PROTECTION_CHECKSUM) {
		log_dbg(cd, "Checksums hotzone resilience.");

		if (crypt_hash_write(rh->rp.p.csum.ch, buffer, buffer_len)) {
			log_err(cd, "Failed to hash new ciphertext.");
			return -EINVAL;
		}
		if (crypt_hash_final(rh->rp.p.csum.ch, rh->rp.p.csum.last_checksum, rh->rp.p.csum.hash_size)) {
			log_err(cd, "Failed to read sector hash.");
			return -EINVAL;
		}
		len = (char *)rh->rp.p.csum.last_checksum - (char *)rh->rp.p.csum.checksums + rh->rp.p.csum.hash_size;
		pbuffer = rh->rp.p.csum.checksums;
	} else if (rh->rp.type == REENC_PROTECTION_JOURNAL) {
		log_dbg(cd, "Journal hotzone resilience.");
		len = buffer_len;
		pbuffer = buffer;
	} else if (rh->rp.type == REENC_PROTECTION_DATASHIFT) {
		log_dbg(cd, "Data shift hotzone resilience.");
		return LUKS2_hdr_write(cd, hdr);
	} else
		return -EINVAL;

	log_dbg(cd, "Going to store %zu bytes in reencrypt keyslot.", len);

	r = LUKS2_keyslot_reencrypt_store(cd, hdr, rh->reenc_keyslot, pbuffer, len);

	return r > 0 ? 0 : r;
}

static int continue_reencryption(struct crypt_device *cd, struct luks2_reenc_context *rh, uint64_t device_size)
{
	log_dbg(cd, "rh->progress: %zu, device_size %zu", rh->progress, device_size);
	return device_size > rh->progress;
}

static int _update_reencrypt_context(struct crypt_device *cd,
	struct luks2_reenc_context *rh)
{
	if (rh->read < 0)
		return -EINVAL;

	if (rh->direction == BACKWARD) {
		if (rh->data_shift && rh->type == ENCRYPT /* && moved segment */) {
			if (rh->offset)
				rh->offset += rh->data_shift;
			if (rh->offset && (rh->offset < imaxabs(rh->data_shift))) {
				rh->length = rh->offset;
				rh->offset = imaxabs(rh->data_shift);
			}
			if (!rh->offset)
				rh->length = imaxabs(rh->data_shift);
		} else {
			if (rh->offset < rh->length)
				rh->length = rh->offset;
			rh->offset -= rh->length;
		}
	} else if (rh->direction == FORWARD) {
		rh->offset += (uint64_t)rh->read;
		/* it fails in-case of device_size < rh->offset later */
		if (rh->device_size - rh->offset < rh->length)
			rh->length = rh->device_size - rh->offset;
	} else
		return -EINVAL;

	if (rh->device_size < rh->offset) {
		log_err(cd, "Error: Calculated reencryption offset %" PRIu64 " is beyond device size %" PRIu64 ".", rh->offset, rh->device_size);
		return -EINVAL;
	}

	rh->progress += (uint64_t)rh->read;

	return 0;
}

int LUKS2_reenc_load(struct crypt_device *cd, struct luks2_hdr *hdr, uint64_t device_size,
		const char *passphrase, size_t passphrase_size, const struct crypt_params_reencrypt *params, struct luks2_reenc_context **rh, struct volume_key **vks)
{
	int keyslot, r;
	struct volume_key *vk;
	struct luks2_reenc_context *tmp = NULL;
	luks2_reencrypt_info ri = LUKS2_reenc_status(hdr);

	if (ri == REENCRYPT_CLEAN)
		r = _LUKS2_reenc_load(cd, hdr, device_size, &tmp, params);
	else if (ri == REENCRYPT_CRASH)
		r = LUKS2_reenc_load_crashed(cd, hdr, device_size, &tmp);
	else
		r = -EINVAL;
	if (r < 0 || !tmp) {
		log_err(cd, "Failed to load reenc context.");
		return r;
	}

	r = LUKS2_keyslot_open_all_segments(cd, CRYPT_ANY_SLOT, passphrase, passphrase_size, vks);
	if (r < 0)
		goto err;
	keyslot = r;

	r = -EINVAL;

	if (tmp->digest_new >= 0) {
		vk = crypt_volume_key_by_id(*vks, tmp->digest_new);
		if (!vk)
			goto err;
		r = LUKS2_volume_key_load_in_keyring_by_digest(cd, hdr, vk, crypt_volume_key_get_id(vk));
		if (r)
			goto err;
	}

	if (tmp->digest_old >= 0 && tmp->digest_old != tmp->digest_new) {
		vk = crypt_volume_key_by_id(*vks, tmp->digest_old);
		if (!vk)
			goto err;
		r = LUKS2_volume_key_load_in_keyring_by_digest(cd, hdr, vk, crypt_volume_key_get_id(vk));
		if (r)
			goto err;
	}

	*rh = tmp;

	return keyslot;
err:
	crypt_drop_keyring_key(cd, *vks);
	crypt_free_volume_key(*vks);
	*vks = NULL;
	LUKS2_reenc_context_free(cd, tmp);

	return r;
}

/* internal only */
int crypt_reencrypt_lock(struct crypt_device *cd, struct crypt_lock_handle **reencrypt_lock)
{
	int r;
	char *lock_resource;

	r = asprintf(&lock_resource, "LUKS2-reencryption-%s", crypt_get_uuid(cd));
	if (r < 0)
		return -ENOMEM;
	if (r < 20) {
		r = -EINVAL;
		goto out;
	}

	r = crypt_write_lock(cd, lock_resource, false, reencrypt_lock);
out:
	free(lock_resource);

	return r;
}

/* internal only */
void crypt_reencrypt_unlock(struct crypt_device *cd, struct crypt_lock_handle *reencrypt_lock)
{
	crypt_unlock_internal(cd, reencrypt_lock);
}

static int reencrypt_lock_and_verify(struct crypt_device *cd, struct luks2_hdr *hdr,
		struct crypt_lock_handle **reencrypt_lock)
{
	int r;
	luks2_reencrypt_info ri;
	struct crypt_lock_handle *h;

	ri = LUKS2_reenc_status(hdr);
	if (ri == REENCRYPT_INVALID) {
		log_err(cd, "Failed to read reencryption state.");
		return -EINVAL;
	}
	if (ri < REENCRYPT_CLEAN) {
		log_err(cd, "Device is not in reencryption.");
		return -EINVAL;
	}

	r = crypt_reencrypt_lock(cd, &h);
	if (r < 0) {
		if (r == -EBUSY)
			log_err(cd, "Reencryption process is already running.");
		else
			log_err(cd, "Failed to acquire reencryption lock.");
		return r;
	}

	/* With reencryption lock held, reload device context and verify metadata state */
	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r) {
		crypt_reencrypt_unlock(cd, h);
		return r;
	}

	ri = LUKS2_reenc_status(hdr);
	if (ri == REENCRYPT_CLEAN) {
		*reencrypt_lock = h;
		return 0;
	}

	crypt_reencrypt_unlock(cd, h);
	log_err(cd, "Device is not in clean reencryption state.");
	return -EINVAL;
}

static int _reencrypt_load(struct crypt_device *cd,
		const char *name,
		const char *passphrase,
		size_t passphrase_size,
		const struct crypt_params_reencrypt *params,
		uint32_t flags)
{
	int r;
	struct luks2_hdr *hdr;
	uint64_t device_size;
	struct crypt_lock_handle *reencrypt_lock;
	struct luks2_reenc_context *rh;
	struct volume_key *vks = NULL;

	log_dbg(cd, "Loading LUKS2 reencryption context.");

	rh = crypt_get_reenc_context(cd);
	if (rh) {
		LUKS2_reenc_context_free(cd, rh);
		crypt_set_reenc_context(cd, NULL);
		rh = NULL;
	}

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	r = reencrypt_lock_and_verify(cd, hdr, &reencrypt_lock);
	if (r)
		return r;

	/* From now on we hold reencryption lock */

	/* some configurations provides fixed device size */
	if ((r = LUKS2_get_data_size(hdr, &device_size)))
		goto err;

	device_size >>= SECTOR_SHIFT;

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_OK,
				crypt_get_data_offset(cd), &device_size, NULL);
	if (r)
		goto err;

	/* new device size reduced by new data_offset */
	device_size <<= SECTOR_SHIFT;

	r = LUKS2_reenc_load(cd, hdr, device_size, passphrase, passphrase_size, params, &rh, &vks);
	if (r < 0 || !rh) {
		log_err(cd, "Failed to load reenc context.");
		goto err;
	}

	if (name && (r = LUKS2_reenc_context_set_name(rh, name)))
		goto err;

	r = _init_storage_wrappers(cd, hdr, rh, vks);
	if (r)
		goto err;

	MOVE_REF(rh->vks, vks);
	MOVE_REF(rh->reenc_lock, reencrypt_lock);

	crypt_set_reenc_context(cd, rh);

	return 0;
err:
	crypt_reencrypt_unlock(cd, reencrypt_lock);
	crypt_drop_keyring_key(cd, vks);
	crypt_free_volume_key(vks);
	LUKS2_reenc_context_free(cd, rh);
	return r;
}

int crypt_reencrypt_load_by_keyring(struct crypt_device *cd,
		const char *name,
		const char *passphrase_description,
		const struct crypt_params_reencrypt *params,
		uint32_t flags)
{
	int r;
	char *passphrase;
	size_t passphrase_size;

	if (onlyLUKS2mask(cd, CRYPT_REQUIREMENT_ONLINE_REENCRYPT) || !passphrase_description)
		return -EINVAL;

	r = keyring_get_passphrase(passphrase_description, &passphrase, &passphrase_size);
	if (r < 0) {
		log_err(cd, _("Failed to read passphrase from keyring (error %d)."), r);
		return -EINVAL;
	}

	r = _reencrypt_load(cd, name, passphrase, passphrase_size, params, flags);

	crypt_memzero(passphrase, passphrase_size);
	free(passphrase);

	return r;
}

int crypt_reencrypt_load_by_passphrase(struct crypt_device *cd,
		const char *name,
		const char *passphrase,
		size_t passphrase_size,
		const struct crypt_params_reencrypt *params,
		uint32_t flags)
{
	if (onlyLUKS2mask(cd, CRYPT_REQUIREMENT_ONLINE_REENCRYPT) || !passphrase)
		return -EINVAL;

	return _reencrypt_load(cd, name, passphrase, passphrase_size, params, flags);
}

static reenc_status_t _reencrypt_step(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		uint64_t device_size,
		bool online)
{
	int r;

	/* update reencrypt keyslot protection parameters in memory only */
	r = reenc_keyslot_update(cd, rh);
	if (r < 0) {
		log_dbg(cd, "Keyslot update failed.");
		return REENC_ERR;
	}

	/* in memory only */
	r = _load_segments(cd, hdr, rh, device_size);
	if (r) {
		log_err(cd, "Failed to calculate new segments.");
		return REENC_ERR;
	}

	log_dbg(cd, "Actual luks2 header segments:\n%s", LUKS2_debug_dump_segments(hdr));

	r = reenc_assign_segments(cd, hdr, rh, 1, 0);
	if (r) {
		log_err(cd, "Failed to assign pre reenc segments.");
		return REENC_ERR;
	}

	log_dbg(cd, "Actual header segments post pre assign:\n%s", LUKS2_debug_dump_segments(hdr));

	if (online) {
		r = reenc_refresh_overlay_devices(cd, hdr, rh->overlay_name, rh->hotzone_name, rh->vks, rh->device_size);
		/* Teardown overlay devices with dm-error. None bio shall pass! */
		if (r != REENC_OK)
			return r;
	}

	log_dbg(cd, "Reencrypting chunk starting at offset: %zu, size :%zu.", rh->offset, rh->length);
	log_dbg(cd, "data_offset: %zu", crypt_get_data_offset(cd) << SECTOR_SHIFT);

	/* FIXME: moved segment only case */
	if (!rh->offset && rh->type == ENCRYPT && rh->data_shift) {
		crypt_storage_wrapper_destroy(rh->cw1);
		r = crypt_storage_wrapper_init(cd, &rh->cw1, crypt_data_device(cd),
				LUKS2_reencrypt_get_data_offset_moved(hdr),
				crypt_get_iv_offset(cd),
				LUKS2_reencrypt_get_sector_size_old(hdr),
				LUKS2_reencrypt_segment_cipher_old(hdr),
				crypt_volume_key_by_id(rh->vks, rh->digest_old),
				rh->wflags1);
		if (r) {
			log_err(cd, "Failed to reinitialize storage wrapper.");
			return REENC_ROLLBACK;
		}
		log_dbg(cd, "This will be encryption last step.");
	}

	rh->read = crypt_storage_wrapper_read(rh->cw1, rh->offset, rh->reenc_buffer, rh->length);
	if (rh->read < 0) {
		/* severity normal */
		log_err(cd, "Failed to read chunk starting at %zu.", rh->offset);
		return REENC_ROLLBACK;
	}

	r = reencrypt_hotzone_protect_init(cd, rh, rh->reenc_buffer, rh->read);
	if (r < 0) {
		/* severity normal */
		log_err(cd, "Failed initialize hotzone resilience, retval = %d", r);
		return REENC_ROLLBACK;
	}

	/* FIXME: wrap in single routine */
	if (rh->rp.type == REENC_PROTECTION_CHECKSUM) {
		/* severity normal */
		r = crypt_storage_wrapper_decrypt(rh->cw1, rh->offset, rh->reenc_buffer, rh->read);
		if (r) {
			log_err(cd, "Decryption failed.");
			return REENC_ROLLBACK;
		}
		if (crypt_storage_wrapper_encrypt(rh->cw2, rh->offset, rh->reenc_buffer, rh->read)) {
			log_err(cd, "Failed to encrypt chunk starting at sector %zu.", rh->offset);
			return REENC_ROLLBACK;
		}
	}

	/* metadata commit point */
	r = reencrypt_hotzone_protect_final(cd, hdr, rh, rh->reenc_buffer, rh->read);
	if (r < 0) {
		/* severity normal */
		log_err(cd, "Failed finalize hotzone resilience, retval = %d", r);
		/* Teardown overlay devices with dm-error. None bio shall pass! */
		return REENC_ROLLBACK;
	}
	if (rh->rp.type != REENC_PROTECTION_CHECKSUM) {
		r = crypt_storage_wrapper_decrypt(rh->cw1, rh->offset, rh->reenc_buffer, rh->read);
		if (r) {
			/* severity normal */
			log_err(cd, "Decryption failed.");
			return REENC_ROLLBACK;
		}
		if (rh->read != crypt_storage_wrapper_encrypt_write(rh->cw2, rh->offset, rh->reenc_buffer, rh->read)) {
			/* severity fatal */
			log_err(cd, "Failed to write chunk starting at sector %zu.", rh->offset);
			return REENC_FATAL;
		}
	} else {
		/* severity fatal */
		if (rh->read != crypt_storage_wrapper_write(rh->cw2, rh->offset, rh->reenc_buffer, rh->read)) {
			log_err(cd, "Failed to write chunk starting at sector %zu.", rh->offset);
			return REENC_FATAL;
		}
	}

	if (rh->rp.type != REENC_PROTECTION_NOOP)
		crypt_storage_wrapper_datasync(rh->cw2);

	/* metadata commit safe point */
	r = reenc_assign_segments(cd, hdr, rh, 0, rh->rp.type != REENC_PROTECTION_NOOP);
	if (r) {
		/* severity fatal */
		log_err(cd, "Failed to assign reenc segments.");
		return REENC_FATAL;
	}

	if (online) {
		/* severity normal */
		log_dbg(cd, "Resuming device %s", rh->hotzone_name);
		r = dm_resume_device(cd, rh->hotzone_name, DM_RESUME_PRIVATE);
		if (r) {
			log_err(cd, "Failed to resume device %s.", rh->hotzone_name);
			return REENC_ERR;
		}
	}

	return REENC_OK;
}

static int _reencrypt_teardown_ok(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reenc_context *rh)
{
	int i, r;
	bool finished = (!continue_reencryption(cd, rh, rh->device_size));

	if (rh->rp.type == REENC_PROTECTION_NOOP &&
	    LUKS2_hdr_write(cd, hdr)) {
		log_err(cd, "Failed to write LUKS2 metadata.");
		return -EINVAL;
	}

	if (rh->online) {
		r = LUKS2_reload(cd, rh->device_name, rh->vks, CRYPT_ACTIVATE_KEYRING_KEY | CRYPT_ACTIVATE_SHARED);
		if (r)
			log_err(cd, "Failed to reload %s device.", rh->device_name);
		if (!r) {
			r = dm_resume_device(cd, rh->device_name, 0);
			if (r)
				log_err(cd, "Failed to resume %s device.", rh->device_name);
		}
		dm_remove_device(cd, rh->overlay_name, 0);
		dm_remove_device(cd, rh->hotzone_name, 0);
	}

	if (finished) {
		if (LUKS2_reencrypt_get_data_offset_new(hdr) && LUKS2_set_keyslots_size(cd, hdr, LUKS2_reencrypt_get_data_offset_new(hdr)))
			log_err(cd, "Failed to set new keyslots_size after reencryption");
		if (rh->digest_old >= 0 && rh->digest_new != rh->digest_old)
			for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++)
				if (LUKS2_digest_by_keyslot(hdr, i) == rh->digest_old)
					crypt_keyslot_destroy(cd, i);
		crypt_keyslot_destroy(cd, rh->reenc_keyslot);
		if (reenc_erase_backup_segments(cd, hdr))
			log_err(cd, "Failed to erase backup segments");

		/* do we need atomic erase? */
		if (update_reencryption_flag(cd, 0, true))
			log_err(cd, "Failed to disable reencryption requirement flag.");
	}

	/* this frees reencryption lock */
	LUKS2_reenc_context_free(cd, rh);
	crypt_set_reenc_context(cd, NULL);

	return 0;
}

static int _reencrypt_free(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reenc_context *rh, reenc_status_t rs,
		    int (*progress)(uint64_t size, uint64_t offset, void *usrptr))
{
	switch (rs) {
	case REENC_OK:
		if (progress)
			progress(rh->device_size, rh->progress, NULL);
		return _reencrypt_teardown_ok(cd, hdr, rh);
	default:
		return -EIO;
	}
}

/* define return codes
 *
 *  < 0 error
 *  0 step finished ok
 *  1 interrupted cleanly (reenc context freed)
 */
int crypt_reencrypt_step(struct crypt_device *cd)
{
	int r;
	luks2_reencrypt_info ri;
	struct luks2_hdr *hdr;
	struct luks2_reenc_context *rh;
	reenc_status_t rs;

	if (onlyLUKS2mask(cd, CRYPT_REQUIREMENT_ONLINE_REENCRYPT))
		return -EINVAL;

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	ri = LUKS2_reenc_status(hdr);
	/* FIXME: why not ri != REENCRYPT_CLEAN */
	if (ri > REENCRYPT_CLEAN) {
		log_err(cd, "Can't resume reencryption. Unexpected reencryption status.");
		return -EINVAL;
	}

	rh = crypt_get_reenc_context(cd);
	if (!rh) {
		log_err(cd, "Missing reencrypt context.");
		return -EINVAL;
	}

	if (continue_reencryption(cd, rh, rh->device_size)) {
		rs = _reencrypt_step(cd, hdr, rh, rh->device_size, rh->online);
		if (rs != REENC_OK)
			return _reencrypt_free(cd, hdr, rh, rs, NULL);

		r = _update_reencrypt_context(cd, rh);
		if (r) {
			log_err(cd, "Failed to update reencryption context.");
			return _reencrypt_free(cd, hdr, rh, REENC_ERR, NULL);
		}
		return 0;
	} else
		return _reencrypt_free(cd, hdr, rh, REENC_OK, NULL);
}

int crypt_reencrypt(struct crypt_device *cd,
		    int (*progress)(uint64_t size, uint64_t offset, void *usrptr))
{
	int r;
	luks2_reencrypt_info ri;
	struct luks2_hdr *hdr;
	struct luks2_reenc_context *rh;
	reenc_status_t rs;
	bool quit = false;

	if (onlyLUKS2mask(cd, CRYPT_REQUIREMENT_ONLINE_REENCRYPT))
		return -EINVAL;

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	ri = LUKS2_reenc_status(hdr);
	if (ri > REENCRYPT_CLEAN) {
		log_err(cd, "Can't resume reencryption. Unexpected reencryption status.");
		return -EINVAL;
	}

	rh = crypt_get_reenc_context(cd);
	if (!rh || !rh->reenc_lock) {
		log_err(cd, "Missing or invalid reencrypt context.");
		return -EINVAL;
	}

	log_dbg(cd, "Resuming LUKS2 reencryption.");

	if (rh->online) {
		r = reenc_init_helper_devices(cd, rh->device_name, rh->hotzone_name, rh->overlay_name);
		if (r) {
			log_err(cd, "Failed to initalize reencryption device stack.");
			return -EINVAL;
		}
	}

	log_dbg(cd, "Progress %" PRIu64 ", device_size %" PRIu64, rh->progress, rh->device_size);
	if (progress && progress(rh->device_size, rh->progress, NULL))
		quit = true;

	rs = REENC_OK;

	while (!quit && continue_reencryption(cd, rh, rh->device_size)) {
		rs = _reencrypt_step(cd, hdr, rh, rh->device_size, rh->online);
		if (rs != REENC_OK)
			break;

		log_dbg(cd, "Progress %" PRIu64 ", device_size %" PRIu64, rh->progress, rh->device_size);
		if (progress && progress(rh->device_size, rh->progress, NULL))
			quit = true;

		r = _update_reencrypt_context(cd, rh);
		if (r) {
			log_err(cd, "Failed to update reencryption context.");
			rs = REENC_ERR;
			break;
		}

		log_dbg(cd, "Next reencryption offset will be %" PRIu64 " sectors.", rh->offset);
		log_dbg(cd, "Next reencryption chunk size will be %" PRIu64 " sectors).", rh->length);
	}

	return _reencrypt_free(cd, hdr, rh, rs, progress);
}

int reenc_erase_backup_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr)
{
	int segment = LUKS2_get_segment_id_by_flag(hdr, "reencrypt-previous");
	if (segment >= 0) {
		if (LUKS2_digest_segment_assign(cd, hdr, segment, CRYPT_ANY_DIGEST, 0, 0))
			return -EINVAL;
		json_object_object_del_by_uint(LUKS2_get_segments_jobj(hdr), segment);
	}
	segment = LUKS2_get_segment_id_by_flag(hdr, "reencrypt-final");
	if (segment >= 0) {
		if (LUKS2_digest_segment_assign(cd, hdr, segment, CRYPT_ANY_DIGEST, 0, 0))
			return -EINVAL;
		json_object_object_del_by_uint(LUKS2_get_segments_jobj(hdr), segment);
	}
	segment = LUKS2_get_segment_id_by_flag(hdr, "reencrypt-moved-segment");
	if (segment >= 0) {
		if (LUKS2_digest_segment_assign(cd, hdr, segment, CRYPT_ANY_DIGEST, 0, 0))
			return -EINVAL;
		json_object_object_del_by_uint(LUKS2_get_segments_jobj(hdr), segment);
	}

	return 0;
}
