/*
 * Password quality check wrapper
 *
 * Copyright (C) 2012-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2020 Milan Broz
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

#include "cryptsetup.h"
#include <termios.h>

void tools_passphrase_msg(int r)
{
	if (r == -EPERM)
		log_err(_("No key available with this passphrase."));
	else if (r == -ENOENT)
		log_err(_("No usable keyslot is available."));
}

int tools_read_mk(const char *file, char **key, int keysize)
{
	int fd;

	if (!keysize || !key)
		return -EINVAL;

	*key = crypt_safe_alloc(keysize);
	if (!*key)
		return -ENOMEM;

	fd = open(file, O_RDONLY);
	if (fd == -1) {
		log_err(_("Cannot read keyfile %s."), file);
		goto fail;
	}

	if (read_buffer(fd, *key, keysize) != keysize) {
		log_err(_("Cannot read %d bytes from keyfile %s."), keysize, file);
		close(fd);
		goto fail;
	}
	close(fd);
	return 0;
fail:
	crypt_safe_free(*key);
	*key = NULL;
	return -EINVAL;
}

int tools_write_mk(const char *file, const char *key, int keysize)
{
	int fd, r = -EINVAL;

	fd = open(file, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR);
	if (fd < 0) {
		log_err(_("Cannot open keyfile %s for write."), file);
		return r;
	}

	if (write_buffer(fd, key, keysize) == keysize)
		r = 0;
	else
		log_err(_("Cannot write to keyfile %s."), file);

	close(fd);
	return r;
}

/*
 * Only tool that currently blocks signals explicitely is cryptsetup-reencrypt.
 * Leave the tools_get_key stub with signals handling here and remove it later
 * only if we find signals blocking obsolete.
 */
int tools_get_key(const char *prompt,
		  char **key, size_t *key_size,
		  uint64_t keyfile_offset, size_t keyfile_size_max,
		  const char *key_file,
		  int timeout, int verify, int pwquality,
		  struct crypt_device *cd)
{
	int r, block;

	block = tools_signals_blocked();
	if (block)
		set_int_block(0);

	r = crypt_cli_get_key(prompt, key, key_size, keyfile_offset,
		keyfile_size_max, key_file, timeout, verify, pwquality, cd, NULL);

	if (block && !quit)
		set_int_block(1);

	return r;
}
