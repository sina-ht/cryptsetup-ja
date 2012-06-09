/*
 * dm-verity volume handling
 *
 * Copyright (C) 2012, Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
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

#ifndef _VERITY_H
#define _VERITY_H

#include <unistd.h>
#include "config.h"

#define VERITY_SIGNATURE	"verity\0\0"
#define VERITY_MAX_LEVELS	63
#define VERITY_MAX_SALT_SIZE	384

struct crypt_device;
struct crypt_params_verity;

int VERITY_read_sb(struct crypt_device *cd,
		   const char *device,
		   uint64_t sb_offset,
		   struct crypt_params_verity *params);

int VERITY_write_sb(struct crypt_device *cd,
		   const char *device,
		   uint64_t sb_offset,
		   struct crypt_params_verity *params);

int VERITY_activate(struct crypt_device *cd,
		     const char *name,
		     const char *hash_device,
		     const char *root_hash,
		     size_t root_hash_size,
		     struct crypt_params_verity *verity_hdr,
		     uint32_t activation_flags);

int VERITY_verify(struct crypt_device *cd,
		struct crypt_params_verity *verity_hdr,
		const char *data_device,
		const char *hash_device,
		const char *root_hash,
		size_t root_hash_size);

int VERITY_create(struct crypt_device *cd,
		  struct crypt_params_verity *verity_hdr,
		  const char *data_device,
		  const char *hash_device,
		  char *root_hash,
		  size_t root_hash_size);

uint64_t VERITY_hash_offset_block(struct crypt_params_verity *params);

#endif
