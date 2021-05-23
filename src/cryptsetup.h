/*
 * cryptsetup - setup cryptographic volumes for dm-crypt
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2021 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2021 Milan Broz
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

#ifndef CRYPTSETUP_H
#define CRYPTSETUP_H

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <limits.h>
#include <ctype.h>
#include <fcntl.h>
#include <popt.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "lib/nls.h"
#include "lib/bitops.h"
#include "lib/utils_crypt.h"
#include "lib/utils_loop.h"
#include "lib/utils_fips.h"
#include "lib/utils_io.h"
#include "lib/utils_blkid.h"
#include "lib/libcryptsetup_macros.h"

#include "libcryptsetup.h"

#define DEFAULT_CIPHER(type)	(DEFAULT_##type##_CIPHER "-" DEFAULT_##type##_MODE)

#define DEFAULT_WIPE_BLOCK	1048576 /* 1 MiB */
#define MAX_ACTIONS 16

/* Common tools */
void tool_log(int level, const char *msg, void *usrptr __attribute__((unused)));
void quiet_log(int level, const char *msg, void *usrptr);

int yesDialog(const char *msg, void *usrptr);
int noDialog(const char *msg, void *usrptr);
void show_status(int errcode);
const char *uuid_or_device(const char *spec);
__attribute__ ((noreturn)) \
void usage(poptContext popt_context, int exitcode, const char *error, const char *more);
void dbg_version_and_cmd(int argc, const char **argv);
int translate_errno(int r);

typedef enum { CREATED, UNLOCKED, REMOVED  } crypt_object_op;
void tools_keyslot_msg(int keyslot, crypt_object_op op);
void tools_token_msg(int token, crypt_object_op op);

extern volatile int quit;
void set_int_block(int block);
void set_int_handler(int block);
void check_signal(int *r);
int tools_signals_blocked(void);

int tools_get_key(const char *prompt,
		  char **key, size_t *key_size,
		  uint64_t keyfile_offset, size_t keyfile_size_max,
		  const char *key_file,
		  int timeout, int verify, int pwquality,
		  struct crypt_device *cd);
void tools_passphrase_msg(int r);
int tools_is_stdin(const char *key_file);
int tools_string_to_size(const char *s, uint64_t *size);

struct tools_progress_params {
	uint32_t frequency;
	struct timeval start_time;
	struct timeval end_time;
	uint64_t start_offset;
	bool batch_mode;
};

int tools_wipe_progress(uint64_t size, uint64_t offset, void *usrptr);
int tools_reencrypt_progress(uint64_t size, uint64_t offset, void *usrptr);

int tools_read_mk(const char *file, char **key, int keysize);
int tools_write_mk(const char *file, const char *key, int keysize);

int tools_read_json_file(const char *file, char **json, size_t *json_size, bool batch_mode);
int tools_write_json_file(const char *file, const char *json);

int tools_detect_signatures(const char *device, int ignore_luks, size_t *count, bool batch_mode);
int tools_wipe_all_signatures(const char *path);

int tools_lookup_crypt_device(struct crypt_device *cd, const char *type,
		const char *data_device_path, char *name, size_t name_length);


/* each utility is required to implement it */
void tools_cleanup(void);

/* Log */
#define log_dbg(x...) crypt_logf(NULL, CRYPT_LOG_DEBUG, x)
#define log_std(x...) crypt_logf(NULL, CRYPT_LOG_NORMAL, x)
#define log_verbose(x...) crypt_logf(NULL, CRYPT_LOG_VERBOSE, x)
#define log_err(x...) crypt_logf(NULL, CRYPT_LOG_ERROR, x)

typedef enum {
	CRYPT_ARG_BOOL = 0,
	CRYPT_ARG_STRING,
	CRYPT_ARG_INT32,
	CRYPT_ARG_UINT32,
	CRYPT_ARG_INT64,
	CRYPT_ARG_UINT64
} crypt_arg_type_info;

struct tools_arg {
	const char *name;
	bool set;
	crypt_arg_type_info type;
	union {
		char *str_value;
		uint64_t u64_value;
		uint32_t u32_value;
		int32_t i32_value;
		int64_t i64_value;
	} u;
	const char *actions_array[MAX_ACTIONS];
};

void tools_parse_arg_value(poptContext popt_context, crypt_arg_type_info type, struct tools_arg *arg, const char *popt_arg, int popt_val, bool(*needs_size_conv_fn)(unsigned arg_id));

void tools_args_free(struct tools_arg *args, size_t args_count);

void tools_check_args(const char *action, const struct tools_arg *args, size_t args_size, poptContext popt_context);

struct tools_log_params {
	bool verbose;
	bool debug;
};

#endif /* CRYPTSETUP_H */
