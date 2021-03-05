/*
 * Integritysetup command line arguments list
 *
 * Copyright (C) 2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2020 Ondrej Kozina
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

/* long name, short name, popt type, help description, units, internal argument type, default value */

ARG(OPT_ALLOW_DISCARDS, '\0', POPT_ARG_NONE, N_("Allow discards (aka TRIM) requests for device"), NULL, CRYPT_ARG_BOOL, {}, OPT_ALLOW_DISCARDS_ACTIONS)

ARG(OPT_BATCH_MODE, 'q', POPT_ARG_NONE, N_("Do not ask for confirmation"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_BUFFER_SECTORS, '\0', POPT_ARG_STRING, N_("Buffers size"), N_("SECTORS"), CRYPT_ARG_UINT32, {}, {})

ARG(OPT_BITMAP_FLUSH_TIME, '\0', POPT_ARG_STRING, N_("Bitmap mode flush time"), N_("ms"), CRYPT_ARG_UINT32, {}, {})

ARG(OPT_BITMAP_SECTORS_PER_BIT, '\0', POPT_ARG_STRING, N_("Number of 512-byte sectors per bit (bitmap mode)."), "INT", CRYPT_ARG_UINT32, {}, {})

ARG(OPT_CANCEL_DEFERRED, '\0', POPT_ARG_NONE, N_("Cancel a previously set deferred device removal"), NULL, CRYPT_ARG_BOOL, {}, OPT_DEFERRED_ACTIONS)

ARG(OPT_DATA_DEVICE, '\0', POPT_ARG_STRING, N_("Path to data device (if separated)"), N_("path"), CRYPT_ARG_STRING, {}, {})

ARG(OPT_DEBUG, '\0', POPT_ARG_NONE, N_("Show debug messages"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_DEFERRED, '\0', POPT_ARG_NONE, N_("Device removal is deferred until the last user closes it"), NULL, CRYPT_ARG_BOOL, {}, OPT_DEFERRED_ACTIONS)

ARG(OPT_INTEGRITY, 'I', POPT_ARG_STRING, N_("Data integrity algorithm"), NULL, CRYPT_ARG_STRING, { .str_value = CONST_CAST(void *)DEFAULT_ALG_NAME }, {})

ARG(OPT_INTEGRITY_KEY_FILE, '\0', POPT_ARG_STRING, N_("Read the integrity key from a file"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_INTEGRITY_KEY_SIZE, '\0', POPT_ARG_STRING, N_("The size of the data integrity key"), N_("BITS"), CRYPT_ARG_UINT32, {}, {})

ARG(OPT_INTEGRITY_LEGACY_PADDING, '\0', POPT_ARG_NONE, N_("Use inefficient legacy padding (old kernels)"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_INTEGRITY_NO_JOURNAL, 'D', POPT_ARG_NONE, N_("Disable journal for integrity device"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_INTERLEAVE_SECTORS, '\0', POPT_ARG_STRING, N_("Interleave sectors"), N_("SECTORS"), CRYPT_ARG_UINT32, {}, OPT_INTERLEAVE_SECTORS_ACTIONS)

ARG(OPT_JOURNAL_COMMIT_TIME, '\0', POPT_ARG_STRING, N_("Journal commit time"), N_("ms"), CRYPT_ARG_UINT32, {}, {})

ARG(OPT_JOURNAL_INTEGRITY, '\0', POPT_ARG_STRING, N_("Journal integrity algorithm"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_JOURNAL_INTEGRITY_KEY_SIZE, '\0', POPT_ARG_STRING, N_("The size of the journal integrity key"), N_("BITS"), CRYPT_ARG_UINT32, {}, {})

ARG(OPT_JOURNAL_INTEGRITY_KEY_FILE, '\0', POPT_ARG_STRING, N_("Read the journal integrity key from a file"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_JOURNAL_CRYPT, '\0', POPT_ARG_STRING, N_("Journal encryption algorithm"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_JOURNAL_CRYPT_KEY_FILE, '\0', POPT_ARG_STRING, N_("Read the journal encryption key from a file"), NULL, CRYPT_ARG_STRING,{}, {})

ARG(OPT_JOURNAL_CRYPT_KEY_SIZE, '\0', POPT_ARG_STRING, N_("The size of the journal encryption key"), N_("BITS"), CRYPT_ARG_UINT32, {}, {})

ARG(OPT_JOURNAL_SIZE, 'j', POPT_ARG_STRING, N_("Journal size"), N_("bytes"), CRYPT_ARG_UINT64, {}, OPT_JOURNAL_SIZE_ACTIONS)

ARG(OPT_JOURNAL_WATERMARK, '\0', POPT_ARG_STRING, N_("Journal watermark"), N_("percent"), CRYPT_ARG_UINT32, {}, {})

ARG(OPT_NO_WIPE, '\0', POPT_ARG_NONE, N_("Do not wipe device after format"), NULL, CRYPT_ARG_BOOL, {}, OPT_NO_WIPE_ACTIONS)

ARG(OPT_PROGRESS_FREQUENCY, '\0', POPT_ARG_STRING, N_("Progress line update (in seconds)"), N_("secs"), CRYPT_ARG_UINT32, {}, {})

ARG(OPT_INTEGRITY_BITMAP_MODE, 'B', POPT_ARG_NONE, N_("Use bitmap to track changes and disable journal for integrity device"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_INTEGRITY_RECALCULATE, '\0', POPT_ARG_NONE, N_("Recalculate initial tags automatically."), NULL, CRYPT_ARG_BOOL, {}, OPT_INTEGRITY_RECALCULATE_ACTIONS)

ARG(OPT_INTEGRITY_RECOVERY_MODE, 'R', POPT_ARG_NONE, N_("Recovery mode (no journal, no tag checking)"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_SECTOR_SIZE, 's', POPT_ARG_STRING, N_("Sector size"), N_("bytes"), CRYPT_ARG_UINT32, { .u32_value = 512 }, OPT_SECTOR_SIZE_ACTIONS)

ARG(OPT_TAG_SIZE, 't', POPT_ARG_STRING, N_("Tag size (per-sector)"), N_("bytes"), CRYPT_ARG_UINT32, {}, OPT_TAG_SIZE_ACTIONS)

ARG(OPT_VERBOSE, 'v', POPT_ARG_NONE, N_("Shows more detailed error messages"), NULL, CRYPT_ARG_BOOL, {}, {})
