/*
 * Experimental reencryption utility for new reencryption code.
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

#include <stdlib.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <uuid/uuid.h>

#include "cryptsetup.h"
#include "lib/utils_keyring.h"

static const char *opt_active_name = NULL;
static const char *opt_resilience_mode = "checksum";
static const char *opt_resilience_hash = "sha256";
static const char *opt_cipher = NULL;
static const char *opt_hash = NULL;
static const char *opt_key_file = NULL;
static const char *opt_uuid = NULL;
static const char *opt_header_device = NULL;
static long opt_keyfile_size = 0;
static long opt_keyfile_offset = 0;
static int opt_iteration_time = 0;
static const char *opt_pbkdf = NULL;
static long opt_pbkdf_memory = DEFAULT_LUKS2_MEMORY_KB;
static long opt_pbkdf_parallel = DEFAULT_LUKS2_PARALLEL_THREADS;
static long opt_pbkdf_iterations = 0;
static int opt_version_mode = 0;
static int opt_random = 0;
static int opt_urandom = 0;
static int opt_tries = 3;
static int opt_key_slot = CRYPT_ANY_SLOT;
static int opt_key_size = 0;
static int opt_new = 0;
static int opt_resume = 0;
static int opt_init_only = 0;
static int opt_decrypt = 0;
static int opt_sector_size = 0;

static const char *opt_reduce_size_str = NULL;
static uint64_t opt_reduce_size = 0;
static const char *opt_extend_size_str = NULL;
static uint64_t opt_extend_size = 0;

/* do not set from command line, use helpers above */
static int64_t opt_data_shift;

/* TODO: This requires support in API so that we can set exact data_offset in LUKS2 header */
static const char *opt_offset_str = NULL;
static uint64_t opt_offset = 0;

static const char *opt_device_size_str = NULL;
static uint64_t opt_device_size = 0;


static const char **action_argv;

static int set_pbkdf_params(struct crypt_device *cd, const char *dev_type)
{
	struct crypt_pbkdf_type pbkdf = {};

	if (strcmp(dev_type, CRYPT_LUKS2))
		return -EINVAL;

	pbkdf.type = opt_pbkdf ?: DEFAULT_LUKS2_PBKDF;
	pbkdf.hash = opt_hash ?: DEFAULT_LUKS1_HASH;
	pbkdf.time_ms = opt_iteration_time ?: DEFAULT_LUKS2_ITER_TIME;
	if (strcmp(pbkdf.type, CRYPT_KDF_PBKDF2)) {
		pbkdf.max_memory_kb = opt_pbkdf_memory;
		pbkdf.parallel_threads = opt_pbkdf_parallel;
	}

	if (opt_pbkdf_iterations) {
		pbkdf.iterations = opt_pbkdf_iterations;
		pbkdf.flags |= CRYPT_PBKDF_NO_BENCHMARK;
	}

	return crypt_set_pbkdf_type(cd, &pbkdf);
}

static void auto_detect_active_name(struct crypt_device *cd, const char *data_device)
{
	static char dm_name[PATH_MAX];
	int r;

	r = tools_lookup_crypt_device(cd, crypt_get_type(cd), data_device, dm_name, sizeof(dm_name));
	if (r < 0) {
		if (r == -ENOTBLK)
			log_std("Device %s is not a block device.", data_device);
		else
			log_err("Auto detection failed. %s is missing?", data_device);
	}
	if (r > 0 && *dm_name != '\0') {
		log_std("Autodetected active crypt device %s for data device %s.", dm_name, data_device);
		opt_active_name = dm_name;
	}

	if (r >= 0)
		log_dbg("Device %s has %d active holders.", data_device, r);
}

static int action_reencrypt_next(const char *device)
{
	int r;
	uint32_t flags;
	char cipher [MAX_CIPHER_LEN], mode[MAX_CIPHER_LEN];
	int old_ks, new_ks;
	size_t passwordLen;
	char *password = NULL;
	struct crypt_device *cd = NULL;
	struct crypt_params_reencrypt reenc_params = {};
	struct crypt_params_luks2 luks2_params = {};

	r = crypt_parse_name_and_mode(opt_cipher ?: DEFAULT_CIPHER(LUKS1),
				      cipher, NULL, mode);
	if (r < 0) {
		log_err(_("No known cipher specification pattern detected.\n"));
		goto err;
	}

	if (crypt_init(&cd, opt_header_device ?: device) ||
	    crypt_load(cd, CRYPT_LUKS2, NULL))
		goto err;

	/* FIXME: move to single static routine */
	if (crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &flags)) {
		r = -EINVAL;
		goto err;
	}
	if (flags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT) {
		log_err("Reencryption already in-progress. Run rencryption with --resume.\n");
		r = -EBUSY;
		goto err;
	}
	if (flags & CRYPT_REQUIREMENT_OFFLINE_REENCRYPT) {
		log_err("Legacy offline reencryption already in-progress. Use cryptsetup-reencrypt.");
		r = -EINVAL;
		goto err;
	}

	luks2_params.sector_size = opt_sector_size ?: crypt_get_sector_size(cd);

	r = tools_get_key(_("Enter passphrase: "),
			  &password, &passwordLen, 0, 0, NULL, 0, 0, 0, cd);
	if (r < 0)
		goto err;

	old_ks = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, password, passwordLen, 0);
	if (old_ks < 0) {
		r = old_ks;
		log_dbg("failed");
		goto err;
	}

	r = set_pbkdf_params(cd, crypt_get_type(cd));
	if (r)
		goto err;

	/* FIXME: call this only if new volume key was requested */
	new_ks = crypt_keyslot_add_by_key(cd, CRYPT_ANY_SLOT, NULL,
			(opt_key_size ?: DEFAULT_LUKS1_KEYBITS) / 8,
			password, passwordLen, CRYPT_VOLUME_KEY_NO_SEGMENT);
	if (new_ks < 0) {
		r = new_ks;
		goto err;
	}

	r = crypt_reencrypt_init(cd, new_ks, "reencrypt", cipher, mode, opt_data_shift / SECTOR_SIZE, &luks2_params);
	if (r < 0 || opt_init_only)
		goto err;

	/* this simulates split between initialising a reencryption and actually running reencryption */
	crypt_free(cd);
	cd = NULL;

	if (opt_reduce_size) {
		reenc_params.resilience = "shift";
	} else {
		reenc_params.resilience = opt_resilience_mode;
		reenc_params.hash = opt_resilience_hash;
		reenc_params.hotzone_size = 25*1024*1024;
	}

	if (!opt_active_name)
		auto_detect_active_name(cd, device);

	if (crypt_init_data_device(&cd, opt_header_device ?: device, device) ||
	    crypt_load(cd, CRYPT_LUKS2, NULL) ||
	    crypt_reencrypt_load_by_passphrase(cd, opt_active_name, password, passwordLen, opt_reduce_size ? NULL : &reenc_params, 0))
		goto err;

	set_int_handler(0);
	r = crypt_reencrypt(cd, tools_reencrypt_progress);
err:
	crypt_safe_free(password);
	crypt_free(cd);

	return r;
}

static int action_reencrypt_resume(const char *device)
{
	char *password;
	size_t passwordLen;
	int keyslot, r;
	uint32_t flags;
	struct crypt_device *cd = NULL;
	struct crypt_params_reencrypt reenc_params = {};

	if (crypt_init(&cd, opt_header_device ?: device) ||
	    crypt_load(cd, CRYPT_LUKS2, NULL))
		goto err;

	if (crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &flags)) {
		r = -EINVAL;
		goto err;
	}

	if (!(flags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT)) {
		log_err("Device is not in-reencryption.\n");
		r = -EINVAL;
		goto err;
	}

	if (opt_header_device && crypt_set_data_device(cd, device)) {
		log_err("Failed to set data device.");
		r = -EINVAL;
		goto err;
	}

	r = tools_get_key(_("Enter passphrase: "),
			  &password, &passwordLen, 0, 0, NULL, 0, 0, 0, cd);
	if (r < 0)
		goto err;

	keyslot = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, password, passwordLen, 0);
	if (keyslot < 0) {
		log_dbg("failed to check keyslot(s)");
		goto err;
	}

	reenc_params.resilience = opt_resilience_mode;
	reenc_params.hash = opt_resilience_hash;

	r = crypt_reencrypt_load_by_passphrase(cd, opt_active_name, password, passwordLen, &reenc_params, 0);
	if (r < 0) {
		log_dbg("failed to initialise reencryption context.");
		goto err;
	}

	set_int_handler(0);

	r = crypt_reencrypt(cd, tools_reencrypt_progress);
err:
	crypt_free(cd);
	return r;
}

static int action_encrypt(const char *device)
{
	const char *head_ptr;
	char cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN], uuid_str[37], header_file[PATH_MAX];
	size_t passwordLen, keysize;
	uuid_t uuid;
	int keyslot, r, fd = -1;
	struct crypt_device *cd = NULL;
	char *password = NULL;
	struct stat st;
	struct crypt_params_reencrypt reenc_params = {};
	struct crypt_params_luks2 luks2_params = {
		.data_device = opt_header_device ? device : NULL,
		.sector_size = opt_sector_size ?: SECTOR_SIZE,
	};

	r = crypt_parse_name_and_mode(opt_cipher ?: DEFAULT_CIPHER(LUKS1),
				      cipher, NULL, cipher_mode);
	if (r < 0) {
		log_err(_("No known cipher specification pattern detected."));
		return r;
	}

	if (opt_uuid && uuid_parse(opt_uuid, uuid) == -1) {
		log_err(_("Wrong LUKS UUID format provided."));
		return -EINVAL;
	}
	if (!opt_uuid) {
		uuid_generate(uuid);
		uuid_unparse(uuid, uuid_str);
		opt_uuid = uuid_str;
	}

	keysize = (opt_key_size ?: DEFAULT_LUKS1_KEYBITS) / 8;

	if (opt_header_device)
		head_ptr = opt_header_device;
	else {
		snprintf(header_file, sizeof(header_file), "LUKS2-temp-%s.new", opt_uuid);
		head_ptr = header_file;
	}

	if (stat(head_ptr, &st) < 0 && errno == ENOENT) {
		log_dbg("Creating header file %s.", head_ptr);
		/* coverity[toctou] */
		fd = open(head_ptr, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
		if (fd == -1 || posix_fallocate(fd, 0, 4096))
			log_err(_("Cannot create header file %s."), head_ptr);
		else
			r = 0;
		if (fd != -1)
			close(fd);
		if (r < 0)
			return r;
	}

	if ((r = crypt_init(&cd, head_ptr)))
		goto err;
	r = set_pbkdf_params(cd, CRYPT_LUKS2);
	if (r)
		goto err;
	r = tools_get_key(_("Enter passphrase: "),
			  &password, &passwordLen, 0, 0, NULL, 0, 1, 0, cd);
	if (r < 0)
		goto err;

	if (crypt_set_data_offset(cd, imaxabs(opt_data_shift) / (2 * SECTOR_SIZE)))
		goto err;

	r = crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode,
			 opt_uuid, NULL, keysize, &luks2_params);
	if (r)
		goto err;

	r = crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT, NULL, keysize, password, passwordLen);
	if (r < 0)
		goto err;
	keyslot = r;

	if (!opt_header_device) {
		if (crypt_set_data_device(cd, device) < 0) {
			log_err("cant set data device.");
			r = -EINVAL;
			goto err;
		}
	}

	log_dbg("data_shift in cli: %" PRIi64, opt_data_shift / (2 * SECTOR_SIZE));
	r = crypt_reencrypt_init(cd, keyslot, "encrypt", cipher, cipher_mode, opt_data_shift / (2 * SECTOR_SIZE), NULL);
	if (r < 0) {
		log_err("reencrypt init failed.");
		crypt_keyslot_destroy(cd, keyslot);
		if (!opt_header_device)
			unlink(header_file);
		goto err;
	}

	if (!opt_header_device) {
		crypt_free(cd);

		if (crypt_init(&cd, device) ||
		    crypt_header_restore(cd, CRYPT_LUKS2, header_file)) {
			r = -EINVAL;
			log_err("Failed to place new header at device %s.", device);
			goto err;
		}
		unlink(header_file);
	}

	if (opt_data_shift)
		reenc_params.resilience = "shift";
	else {
		reenc_params.resilience = opt_resilience_mode;
		reenc_params.hash = opt_resilience_hash;
		reenc_params.hotzone_size = 30*1024*1024;
	}

	if (opt_init_only) {
		r = 0;
		goto err;
	}

	if (opt_active_name && ((r = crypt_activate_by_passphrase(cd, opt_active_name, keyslot, password, passwordLen, 0)) < 0)) {
		log_dbg("failed");
		goto err;
	}

	r = crypt_reencrypt_load_by_passphrase(cd, opt_active_name, password, passwordLen, opt_data_shift ? NULL : &reenc_params, 0);
	if (r) {
		log_err("Failed to load reencryption context.");
		goto err;
	}

	set_int_handler(0);

	r = crypt_reencrypt(cd, tools_reencrypt_progress);
err:
	if (fd >= 0)
		close(fd);
	crypt_safe_free(password);
	crypt_free(cd);
	return r;
}

static int action_decrypt(const char *device)
{
	size_t passwordLen;
	int r, fd = -1, devfd = -1;
	struct crypt_device *cd = NULL;
	char *password = NULL;
	struct crypt_params_reencrypt reenc_params = {};

	/*
	if (!opt_header_device) {
		log_err("Decrytpion w/o detached header is not supported.");
		return -EINVAL;
	}*/

	if (crypt_init(&cd, opt_header_device ?: device) ||
	    crypt_load(cd, CRYPT_LUKS2, NULL)) {
		log_err("Failed to init decryption.");
		r = -EINVAL;
		goto err;
	}

	if (opt_header_device && crypt_set_data_device(cd, device)) {
		log_err("Failed to set data device.");
		r = -EINVAL;
		goto err;
	}

	r = tools_get_key(_("Enter passphrase: "),
			  &password, &passwordLen, 0, 0, NULL, 0, 0, 0, cd);
	if (r < 0)
		goto err;
	r = crypt_activate_by_passphrase(cd, NULL, opt_key_slot, password, passwordLen, 0);
	if (r < 0) {
		log_dbg("wrong pass");
		goto err;
	}

	r = crypt_reencrypt_init(cd, CRYPT_ANY_SLOT, "decrypt", NULL, NULL, opt_data_shift / SECTOR_SIZE, NULL);
	if (r < 0) {
		log_err("reencrypt init failed.");
		goto err;
	}

	crypt_free(cd);
	if (crypt_init(&cd, opt_header_device?: device) ||
	    crypt_load(cd, CRYPT_LUKS2, NULL)) {
		log_err("Failed to load context for decryption.");
		goto err;
	}
	if (opt_header_device && crypt_set_data_device(cd, device)) {
		log_err("Failed to set data device.");
		goto err;
	}

	if (opt_data_shift) {
		/*
		crypt_free(cd);

		if (crypt_init(&cd, device) ||
		    crypt_header_restore(cd, CRYPT_LUKS2, header_file)) {
			r = -EINVAL;
			log_err("Failed to place new header at device %s.", device);
			goto err;
		}
		unlink(header_file);
		reenc_params.resilience = "data_shift";
		*/
	} else {
		reenc_params.resilience = opt_resilience_mode;
		reenc_params.hash = opt_resilience_hash;
		reenc_params.hotzone_size = 19*1024*1024;
	}

	if (opt_init_only) {
		r = 0;
		goto err;
	}

	r = crypt_reencrypt_load_by_passphrase(cd, opt_active_name, password, passwordLen, opt_data_shift ? NULL : &reenc_params, 0);
	if (r) {
		log_err("Failed to load reencryption context.");
		goto err;
	}

	set_int_handler(0);

	r = crypt_reencrypt(cd, tools_reencrypt_progress);
err:
	if (devfd >= 0)
		close(devfd);
	if (fd >= 0)
		close(fd);
	crypt_safe_free(password);
	crypt_free(cd);
	return r;
}

static void help(poptContext popt_context,
		 enum poptCallbackReason reason __attribute__((unused)),
		 struct poptOption *key,
		 const char *arg __attribute__((unused)),
		 void *data __attribute__((unused)))
{
	if (key->shortName == '?') {
		/* log_std("%s %s\n", PACKAGE_REENC, PACKAGE_VERSION); */
		poptPrintHelp(popt_context, stdout, 0);
		exit(EXIT_SUCCESS);
	} else
		usage(popt_context, EXIT_SUCCESS, NULL, NULL);
}

int main(int argc, const char **argv)
{
	static struct poptOption popt_help_options[] = {
		{ NULL,    '\0', POPT_ARG_CALLBACK, help, 0, NULL,                         NULL },
		{ "help",  '?',  POPT_ARG_NONE,     NULL, 0, N_("Show this help message"), NULL },
		{ "usage", '\0', POPT_ARG_NONE,     NULL, 0, N_("Display brief usage"),    NULL },
		POPT_TABLEEND
	};
	static struct poptOption popt_options[] = {
		{ NULL,                '\0', POPT_ARG_INCLUDE_TABLE, popt_help_options, 0, N_("Help options:"), NULL },
		{ "version",           '\0', POPT_ARG_NONE, &opt_version_mode,          0, N_("Print package version"), NULL },
		{ "verbose",           'v',  POPT_ARG_NONE, &opt_verbose,               0, N_("Shows more detailed error messages"), NULL },
		{ "debug",             '\0', POPT_ARG_NONE, &opt_debug,                 0, N_("Show debug messages"), NULL },
		{ "cipher",            'c',  POPT_ARG_STRING, &opt_cipher,              0, N_("The cipher used to encrypt the disk (see /proc/crypto)"), NULL },
		{ "key-size",          's',  POPT_ARG_INT, &opt_key_size,               0, N_("The size of the encryption key"), N_("BITS") },
		{ "hash",              'h',  POPT_ARG_STRING, &opt_hash,                0, N_("The hash used to create the encryption key from the passphrase"), NULL },
		{ "key-file",          'd',  POPT_ARG_STRING, &opt_key_file,            0, N_("Read the key from a file."), NULL },
		{ "iter-time",         'i',  POPT_ARG_INT, &opt_iteration_time,         0, N_("PBKDF2 iteration time for LUKS (in ms)"), N_("msecs") },
		{ "batch-mode",        'q',  POPT_ARG_NONE, &opt_batch_mode,            0, N_("Do not ask for confirmation"), NULL },
		{ "progress-frequency",'\0', POPT_ARG_INT, &opt_progress_frequency,     0, N_("Progress line update (in seconds)"), N_("secs") },
		{ "tries",             'T',  POPT_ARG_INT, &opt_tries,                  0, N_("How often the input of the passphrase can be retried"), NULL },
		{ "use-random",        '\0', POPT_ARG_NONE, &opt_random,                0, N_("Use /dev/random for generating volume key."), NULL },
		{ "use-urandom",       '\0', POPT_ARG_NONE, &opt_urandom,               0, N_("Use /dev/urandom for generating volume key."), NULL },
		{ "key-slot",          'S',  POPT_ARG_INT, &opt_key_slot,               0, N_("Use only this slot (others will be disabled)."), NULL },
		{ "keyfile-offset",   '\0',  POPT_ARG_LONG, &opt_keyfile_offset,        0, N_("Number of bytes to skip in keyfile"), N_("bytes") },
		{ "keyfile-size",      'l',  POPT_ARG_LONG, &opt_keyfile_size,          0, N_("Limits the read from keyfile"), N_("bytes") },
		{ "device-size",       '\0', POPT_ARG_STRING, &opt_device_size_str,     0, N_("Use only specified device size (ignore rest of device). DANGEROUS!"), N_("bytes") },
		{ "new",               'N',  POPT_ARG_NONE, &opt_new,                   0, N_("Create new header on not encrypted device."), NULL },
		{ "reduce-device-size",'\0', POPT_ARG_STRING, &opt_reduce_size_str,     0, N_("Reduce data device size (move data offset). DANGEROUS!"), N_("bytes") },
		{ "extend-device-size",'\0', POPT_ARG_STRING, &opt_extend_size_str,     0, N_("Extend data device size (move data offset). DANGEROUS!"), N_("bytes") },
		{ "offset",	       '\0', POPT_ARG_STRING, &opt_offset_str,		0, N_("Exact data offet where data to be encrypted starts. DANGEROUS!"), N_("bytes") },
		{ "pbkdf",             '\0', POPT_ARG_STRING, &opt_pbkdf,               0, N_("PBKDF algorithm (for LUKS2) (argon2i/argon2id/pbkdf2)."), NULL },
		{ "pbkdf-memory",      '\0', POPT_ARG_LONG, &opt_pbkdf_memory,          0, N_("PBKDF memory cost limit"), N_("kilobytes") },
		{ "pbkdf-parallel",    '\0', POPT_ARG_LONG, &opt_pbkdf_parallel,        0, N_("PBKDF parallel cost "), N_("threads") },
		{ "pbkdf-force-iterations",'\0',POPT_ARG_LONG, &opt_pbkdf_iterations,   0, N_("PBKDF iterations cost (forced, disables benchmark)"), NULL },
		{ "resilience",	       'R',  POPT_ARG_STRING, &opt_resilience_mode,     0, N_("Reencryption hotzone resilience type"), NULL },
		{ "resilience-hash",   '\0', POPT_ARG_STRING, &opt_resilience_hash,     0, N_("Reencryption hotzone checksums hash"), NULL },
		{ "resume",	       '\0', POPT_ARG_NONE, &opt_resume,		0, N_("Resume reencryption"), NULL },
		{ "active-name",       '\0', POPT_ARG_STRING, &opt_active_name,		0, N_("Name of device to be (re)encrypted"), NULL },
		{ "header",            '\0', POPT_ARG_STRING, &opt_header_device,       0, N_("Device or file with separated LUKS2 header"), NULL },
		{ "init-only",         '\0', POPT_ARG_NONE, &opt_init_only,		0, N_("Initialize reencryption metadata only."), NULL },
		{ "decrypt",	       '\0', POPT_ARG_NONE, &opt_decrypt,		0, N_("Decrypt device."), NULL },
		{ "sector-size",       '\0', POPT_ARG_INT, &opt_sector_size,            0, N_("Encryption sector size (default: 512 bytes)"), NULL },
		POPT_TABLEEND
	};
	poptContext popt_context;
	int r;

	crypt_set_log_callback(NULL, tool_log, NULL);

	set_int_block(1);

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	popt_context = poptGetContext(PACKAGE, argc, argv, popt_options, 0);
	poptSetOtherOptionHelp(popt_context,
	                       _("[OPTION...] <device>"));

	while((r = poptGetNextOpt(popt_context)) > 0) ;
	if (r < -1)
		usage(popt_context, EXIT_FAILURE, poptStrerror(r),
		      poptBadOption(popt_context, POPT_BADOPTION_NOALIAS));

	if (opt_version_mode) {
		log_std("%s %s\n", "reencrypt-next", "xxx");
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	}

	if (!opt_batch_mode)
		log_verbose(_("Reencryption will change: volume key%s%s%s%s.\n"),
			opt_hash   ? _(", set hash to ")  : "", opt_hash   ?: "",
			opt_cipher ? _(", set cipher to "): "", opt_cipher ?: "");

	action_argv = poptGetArgs(popt_context);
	if(!action_argv)
		usage(popt_context, EXIT_FAILURE, _("Argument required."),
		      poptGetInvocationName(popt_context));

	if (opt_random && opt_urandom)
		usage(popt_context, EXIT_FAILURE, _("Only one of --use-[u]random options is allowed."),
		      poptGetInvocationName(popt_context));

	if (opt_key_size < 0 || opt_iteration_time < 0 ||
	    opt_tries < 0 || opt_keyfile_offset < 0 || opt_key_size < 0 ||
	    opt_pbkdf_iterations < 0 || opt_pbkdf_memory < 0 ||
	    opt_pbkdf_parallel < 0) {
		usage(popt_context, EXIT_FAILURE,
		      _("Negative number for option not permitted."),
		      poptGetInvocationName(popt_context));
	}

	if (opt_pbkdf && crypt_parse_pbkdf(opt_pbkdf, &opt_pbkdf))
		usage(popt_context, EXIT_FAILURE,
		_("Password-based key derivation function (PBKDF) can be only pbkdf2 or argon2i/argon2id.\n"),
		poptGetInvocationName(popt_context));

	if (opt_pbkdf_iterations && opt_iteration_time)
		usage(popt_context, EXIT_FAILURE,
		_("PBKDF forced iterations cannot be combined with iteration time option.\n"),
		poptGetInvocationName(popt_context));

	if (opt_key_size % 8)
		usage(popt_context, EXIT_FAILURE,
		      _("Key size must be a multiple of 8 bits"),
		      poptGetInvocationName(popt_context));

	if (opt_key_slot != CRYPT_ANY_SLOT &&
	    (opt_key_slot < 0 || opt_key_slot >= crypt_keyslot_max(CRYPT_LUKS1)))
		usage(popt_context, EXIT_FAILURE, _("Key slot is invalid."),
		      poptGetInvocationName(popt_context));

	if (opt_random && opt_urandom)
		usage(popt_context, EXIT_FAILURE, _("Only one of --use-[u]random options is allowed."),
		      poptGetInvocationName(popt_context));

	if (opt_device_size_str &&
	    tools_string_to_size(NULL, opt_device_size_str, &opt_device_size))
		usage(popt_context, EXIT_FAILURE, _("Invalid device size specification."),
		      poptGetInvocationName(popt_context));

	if (opt_offset_str &&
	    tools_string_to_size(NULL, opt_offset_str, &opt_offset))
		usage(popt_context, EXIT_FAILURE, _("Invalid offset specification."),
		      poptGetInvocationName(popt_context));
	if (opt_offset % SECTOR_SIZE)
		usage(popt_context, EXIT_FAILURE, _("Offset must be multiple of 512 bytes sector."),
		      poptGetInvocationName(popt_context));

	if (opt_reduce_size_str &&
	    tools_string_to_size(NULL, opt_reduce_size_str, &opt_reduce_size))
		usage(popt_context, EXIT_FAILURE, _("Invalid device size specification."),
		      poptGetInvocationName(popt_context));
	if (opt_reduce_size > 1024 * 1024 * 1024)
		usage(popt_context, EXIT_FAILURE, _("Maximum device reduce size is 1 GiB."),
		      poptGetInvocationName(popt_context));
	if (opt_reduce_size % SECTOR_SIZE)
		usage(popt_context, EXIT_FAILURE, _("Reduce size must be multiple of 512 bytes sector."),
		      poptGetInvocationName(popt_context));

	opt_data_shift = -(int64_t)opt_reduce_size;
	if (opt_data_shift > 0)
		usage(popt_context, EXIT_FAILURE, _("Reduce size overflow."),
		      poptGetInvocationName(popt_context));

	if (opt_extend_size_str &&
	    tools_string_to_size(NULL, opt_extend_size_str, &opt_extend_size))
		usage(popt_context, EXIT_FAILURE, _("Invalid device size specification."),
		      poptGetInvocationName(popt_context));
	if (opt_extend_size > 1024 * 1024 * 1024)
		usage(popt_context, EXIT_FAILURE, _("Maximum device extend size is 1 GiB."),
		      poptGetInvocationName(popt_context));
	if (opt_extend_size % SECTOR_SIZE)
		usage(popt_context, EXIT_FAILURE, _("Extend size must be multiple of 512 bytes sector."),
		      poptGetInvocationName(popt_context));

	if (opt_extend_size < 0)
		usage(popt_context, EXIT_FAILURE, _("Extend size overflow."),
		      poptGetInvocationName(popt_context));
	if (opt_extend_size)
		opt_data_shift = opt_extend_size;

	if (opt_offset && (opt_reduce_size || opt_extend_size))
		usage(popt_context, EXIT_FAILURE, _("Parameters --offset and --reduce-device-size can not be used together."),
		      poptGetInvocationName(popt_context));

	if (opt_reduce_size && opt_extend_size)
		usage(popt_context, EXIT_FAILURE, _("Parameters --extend-device-size and --reduce-device-size can not be used together."),
		      poptGetInvocationName(popt_context));

	if (opt_sector_size &&
	    (opt_sector_size < SECTOR_SIZE || opt_sector_size > MAX_SECTOR_SIZE ||
	    (opt_sector_size & (opt_sector_size - 1))))
		usage(popt_context, EXIT_FAILURE,
		      _("Unsupported encryption sector size.\n"),
		      poptGetInvocationName(popt_context));

	if (opt_debug) {
		opt_verbose = 1;
		crypt_set_debug_level(-1);
		dbg_version_and_cmd(argc, argv);
	}

	if (opt_new)
		r = action_encrypt(action_argv[0]);
	else if (opt_decrypt)
		r = action_decrypt(action_argv[0]);
	else if (opt_resume)
		r = action_reencrypt_resume(action_argv[0]);
	else
		r = action_reencrypt_next(action_argv[0]);

	poptFreeContext(popt_context);

	return translate_errno(r);
}
