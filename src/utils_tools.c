/*
 * cryptsetup - setup cryptographic volumes for dm-crypt
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2020 Milan Broz
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
#include <math.h>
#include <signal.h>

/* interrupt handling */
volatile int quit = 0;
static int signals_blocked = 0;

static void int_handler(int sig __attribute__((__unused__)))
{
	quit++;
}

int tools_signals_blocked(void)
{
	return signals_blocked;
}

void set_int_block(int block)
{
	sigset_t signals_open;

	log_dbg("%slocking interruption on signal.", block ? "B" : "Unb");

	sigemptyset(&signals_open);
	sigaddset(&signals_open, SIGINT);
	sigaddset(&signals_open, SIGTERM);
	sigprocmask(block ? SIG_SETMASK : SIG_UNBLOCK, &signals_open, NULL);
	signals_blocked = block;
	quit = 0;
}

void set_int_handler(int block)
{
	struct sigaction sigaction_open;

	log_dbg("Installing SIGINT/SIGTERM handler.");
	memset(&sigaction_open, 0, sizeof(struct sigaction));
	sigaction_open.sa_handler = int_handler;
	sigaction(SIGINT, &sigaction_open, 0);
	sigaction(SIGTERM, &sigaction_open, 0);
	set_int_block(block);
}

void check_signal(int *r)
{
	if (quit && !*r)
		*r = -EINTR;
}

void tool_log(int level, const char *msg, void *usrptr)
{
	struct tools_log_params *params = (struct tools_log_params *)usrptr;

	switch (level) {

	case CRYPT_LOG_NORMAL:
		fprintf(stdout, "%s", msg);
		break;
	case CRYPT_LOG_VERBOSE:
		if (params && params->verbose)
			fprintf(stdout, "%s", msg);
		break;
	case CRYPT_LOG_ERROR:
		fprintf(stderr, "%s", msg);
		break;
	case CRYPT_LOG_DEBUG_JSON:
	case CRYPT_LOG_DEBUG:
		if (params && params->debug)
			fprintf(stdout, "# %s", msg);
		break;
	}
}

void quiet_log(int level, const char *msg, void *usrptr)
{
	struct tools_log_params *params = (struct tools_log_params *)usrptr;

	if ((!params || !params->verbose) && (level == CRYPT_LOG_ERROR || level == CRYPT_LOG_NORMAL))
		return;
	tool_log(level, msg, usrptr);
}

static int _dialog(const char *msg, void *usrptr, int default_answer)
{
	const char *fail_msg = (const char *)usrptr;
	char *answer = NULL;
	size_t size = 0;
	int r = default_answer, block;

	block = tools_signals_blocked();
	if (block)
		set_int_block(0);

	if (isatty(STDIN_FILENO)) {
		log_std("\nWARNING!\n========\n");
		log_std("%s\n\nAre you sure? (Type 'yes' in capital letters): ", msg);
		fflush(stdout);
		if(getline(&answer, &size, stdin) == -1) {
			r = 0;
			/* Aborted by signal */
			if (!quit)
				log_err(_("Error reading response from terminal."));
			else
				log_dbg("Query interrupted on signal.");
		} else {
			r = !strcmp(answer, "YES\n");
			if (!r && fail_msg)
				log_err("%s", fail_msg);
		}
	}

	if (block && !quit)
		set_int_block(1);

	free(answer);
	return r;
}

int yesDialog(const char *msg, void *usrptr)
{
	return _dialog(msg, usrptr, 1);
}

int noDialog(const char *msg, void *usrptr)
{
	return _dialog(msg, usrptr, 0);
}

void show_status(int errcode)
{
	char *crypt_error;

	if (!errcode) {
		log_verbose(_("Command successful."));
		return;
	}

	if (errcode < 0)
		errcode = translate_errno(errcode);

	if (errcode == 1)
		crypt_error = _("wrong or missing parameters");
	else if (errcode == 2)
		crypt_error = _("no permission or bad passphrase");
	else if (errcode == 3)
		crypt_error = _("out of memory");
	else if (errcode == 4)
		crypt_error = _("wrong device or file specified");
	else if (errcode == 5)
		crypt_error = _("device already exists or device is busy");
	else
		crypt_error = _("unknown error");

	log_verbose(_("Command failed with code %i (%s)."), -errcode, crypt_error);
}

const char *uuid_or_device(const char *spec)
{
	static char device[PATH_MAX];
	char s, *ptr;
	int i = 0, uuid_len = 5;

	/* Check if it is correct UUID=<LUKS_UUID> format */
	if (spec && !strncmp(spec, "UUID=", uuid_len)) {
		strcpy(device, "/dev/disk/by-uuid/");
		ptr = &device[strlen(device)];
		i = uuid_len;
		while ((s = spec[i++]) && i < (PATH_MAX - 13)) {
			if (!isxdigit(s) && s != '-')
				return spec; /* Bail it out */
			if (isalpha(s))
				s = tolower(s);
			*ptr++ = s;
		}
		*ptr = '\0';
		return device;
	}

	return spec;
}

__attribute__ ((noreturn)) void usage(poptContext popt_context,
					     int exitcode, const char *error,
					     const char *more)
{
	poptPrintUsage(popt_context, stderr, 0);
	if (error)
		log_err("%s: %s", more, error);
	tools_cleanup();
	poptFreeContext(popt_context);
	exit(exitcode);
}

void dbg_version_and_cmd(int argc, const char **argv)
{
	int i;

	log_std("# %s %s processing \"", PACKAGE_NAME, PACKAGE_VERSION);
	for (i = 0; i < argc; i++) {
		if (i)
			log_std(" ");
		log_std("%s", argv[i]);
	}
	log_std("\"\n");
}

/* Translate exit code to simple codes */
int translate_errno(int r)
{
	switch (r) {
	case 0: 	r = EXIT_SUCCESS; break;
	case -EEXIST:
	case -EBUSY:	r = 5; break;
	case -ENOTBLK:
	case -ENODEV:	r = 4; break;
	case -ENOMEM:	r = 3; break;
	case -EPERM:	r = 2; break;
	case -EINVAL:
	case -ENOENT:
	case -ENOSYS:
	default:	r = EXIT_FAILURE;
	}
	return r;
}

void tools_keyslot_msg(int keyslot, crypt_object_op op)
{
	if (keyslot < 0)
		return;

	if (op == CREATED)
		log_verbose(_("Key slot %i created."), keyslot);
	else if (op == UNLOCKED)
		log_verbose(_("Key slot %i unlocked."), keyslot);
	else if (op == REMOVED)
		log_verbose(_("Key slot %i removed."), keyslot);
}

void tools_token_msg(int token, crypt_object_op op)
{
	if (token < 0)
		return;

	if (op == CREATED)
		log_verbose(_("Token %i created."), token);
	else if (op == REMOVED)
		log_verbose(_("Token %i removed."), token);
}

/*
 * Device size string parsing, suffixes:
 * s|S - 512 bytes sectors
 * k  |K  |m  |M  |g  |G  |t  |T   - 1024 base
 * kiB|KiB|miB|MiB|giB|GiB|tiB|TiB - 1024 base
 * kb |KB |mM |MB |gB |GB |tB |TB  - 1000 base
 */
int tools_string_to_size(struct crypt_device *cd, const char *s, uint64_t *size)
{
	char *endp = NULL;
	size_t len;
	uint64_t mult_base, mult, tmp;

	*size = strtoull(s, &endp, 10);
	if (!isdigit(s[0]) ||
	    (errno == ERANGE && *size == ULLONG_MAX) ||
	    (errno != 0 && *size == 0))
		return -EINVAL;

	if (!endp || !*endp)
		return 0;

	len = strlen(endp);
	/* Allow "B" and "iB" suffixes */
	if (len > 3 ||
	   (len == 3 && (endp[1] != 'i' || endp[2] != 'B')) ||
	   (len == 2 && endp[1] != 'B'))
		return -EINVAL;

	if (len == 1 || len == 3)
		mult_base = 1024;
	else
		mult_base = 1000;

	mult = 1;
	switch (endp[0]) {
	case 's':
	case 'S': mult = 512;
		break;
	case 't':
	case 'T': mult *= mult_base;
		 /* Fall through */
	case 'g':
	case 'G': mult *= mult_base;
		 /* Fall through */
	case 'm':
	case 'M': mult *= mult_base;
		 /* Fall through */
	case 'k':
	case 'K': mult *= mult_base;
		break;
	default:
		return -EINVAL;
	}

	tmp = *size * mult;
	if (*size && (tmp / *size) != mult) {
		log_dbg("Device size overflow.");
		return -EINVAL;
	}

	*size = tmp;
	return 0;
}

/* Time progress helper */

/* The difference in seconds between two times in "timeval" format. */
static double time_diff(struct timeval *start, struct timeval *end)
{
	return (end->tv_sec - start->tv_sec)
		+ (end->tv_usec - start->tv_usec) / 1E6;
}

static void tools_clear_line(void)
{
	/* vt100 code clear line */
	log_std("\33[2K\r");
}

static void tools_time_progress(uint64_t device_size, uint64_t bytes, struct tools_progress_params *parms)
{
	struct timeval now_time;
	unsigned long long mbytes, eta;
	double tdiff, uib, frequency;
	int final = (bytes == device_size);
	const char *eol, *ustr = "";

	gettimeofday(&now_time, NULL);
	if (parms->start_time.tv_sec == 0 && parms->start_time.tv_usec == 0) {
		parms->start_time = now_time;
		parms->end_time = now_time;
		parms->start_offset = bytes;
		return;
	}

	if (parms->frequency) {
		frequency = (double)parms->frequency;
		eol = "\n";
	} else {
		frequency = 0.5;
		eol = "";
	}

	if (!final && time_diff(&parms->end_time, &now_time) < frequency)
		return;

	parms->end_time = now_time;

	tdiff = time_diff(&parms->start_time, &parms->end_time);
	if (!tdiff)
		return;

	mbytes = bytes  / 1024 / 1024;
	uib = (double)(bytes - parms->start_offset) / tdiff;

	/* FIXME: calculate this from last minute only. */
	eta = (unsigned long long)(device_size / uib - tdiff);

	if (uib > 1073741824.0f) {
		uib /= 1073741824.0f;
		ustr = "Gi";
	} else if (uib > 1048576.0f) {
		uib /= 1048576.0f;
		ustr = "Mi";
	} else if (uib > 1024.0f) {
		uib /= 1024.0f;
		ustr = "Ki";
	}

	if (!parms->frequency)
		tools_clear_line();
	if (final)
		log_std("Finished, time %02llu:%02llu.%03llu, "
			"%4llu MiB written, speed %5.1f %sB/s\n",
			(unsigned long long)tdiff / 60,
			(unsigned long long)tdiff % 60,
			(unsigned long long)((tdiff - floor(tdiff)) * 1000.0),
			mbytes, uib, ustr);
	else
		log_std("Progress: %5.1f%%, ETA %02llu:%02llu, "
			"%4llu MiB written, speed %5.1f %sB/s%s",
			(double)bytes / device_size * 100,
			eta / 60, eta % 60, mbytes, uib, ustr, eol);
	fflush(stdout);
}

int tools_wipe_progress(uint64_t size, uint64_t offset, void *usrptr)
{
	int r = 0;
	struct tools_progress_params *parms = (struct tools_progress_params *)usrptr;

	if (parms && !parms->batch_mode)
		tools_time_progress(size, offset, parms);

	check_signal(&r);
	if (r) {
		if (!parms || !parms->frequency)
			tools_clear_line();
		log_err(_("\nWipe interrupted."));
	}

	return r;
}

int tools_is_cipher_null(const char *cipher)
{
	if (!cipher)
		return 0;

	return !strcmp(cipher, "cipher_null") ? 1 : 0;
}

/*
 * Keyfile - is standard input treated as a binary file (no EOL handling).
 */
int tools_is_stdin(const char *key_file)
{
	if (!key_file)
		return 1;

	return strcmp(key_file, "-") ? 0 : 1;
}

int tools_reencrypt_progress(uint64_t size, uint64_t offset, void *usrptr)
{
	int r = 0;
	struct tools_progress_params *parms = (struct tools_progress_params *)usrptr;

	if (parms && !parms->batch_mode)
		tools_time_progress(size, offset, parms);

	check_signal(&r);
	if (r) {
		if (!parms || !parms->frequency)
			tools_clear_line();
		log_err(_("\nReencryption interrupted."));
	}

	return r;
}
