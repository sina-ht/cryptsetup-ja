/*
 * utils_reencrypt - online reencryption utilities
 *
 * Copyright (C) 2015-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2018, Ondrej Kozina
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

#ifndef _UTILS_REENCRYPT_H
#define _UTILS_REENCRYPT_H

#include <unistd.h>

struct crypt_device;
struct luks2_hdr;
struct luks2_reenc_context;
struct crypt_lock_handle;
struct crypt_params_reencrypt;

int LUKS2_reenc_load(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	uint64_t device_size,
	const char *passphrase,
	size_t passphrase_size,
	const struct crypt_params_reencrypt *params,
	struct luks2_reenc_context **rh,
	struct volume_key **vks);
/*
int LUKS2_reenc_load_crashed(struct crypt_device *cd,
	struct luks2_hdr *hdr, uint64_t device_size);
*/

int LUKS2_reenc_update_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh);

int LUKS2_reenc_recover(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	struct volume_key *vks);

void LUKS2_reenc_context_free(struct crypt_device *cd, struct luks2_reenc_context *rh);

int reenc_erase_backup_segments(struct crypt_device *cd, struct luks2_hdr *hdr);

int crypt_reencrypt_lock(struct crypt_device *cd, struct crypt_lock_handle **reencrypt_lock);
void crypt_reencrypt_unlock(struct crypt_device *cd, struct crypt_lock_handle *reencrypt_lock);
#endif /* _UTILS_REENCRYPT_H */
