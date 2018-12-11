/*
 * ParaStation
 *
 * Copyright (C) 2009 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <wordexp.h>
#include <errno.h>
#include "pscom_debug.h"
#include "pscom_priv.h"

static char __pscom_debug_linefmt[100] = "";
FILE * __pscom_debug_stream = NULL;
FILE *pscom_debug_file = NULL; // Final output.
char pscom_debug_filename[FILENAME_MAX] = "";

static
char *_pscom_debug_linefmt(void)
{
	if (!__pscom_debug_linefmt[0]) {
		// initialize linefmt.
		char hostname[32];
		if (gethostname(hostname, sizeof(hostname)) < 0 || !hostname[0]) {
			hostname[0] = 0;
		}

		snprintf(__pscom_debug_linefmt, sizeof(__pscom_debug_linefmt),
			 "<PSP:%s:%d:%%s>\n", hostname, getpid());
	}

	return __pscom_debug_linefmt;
}


void pscom_debug_set_prefix(const char *prefix)
{
	char s[100];
	char *t;

	// Output to file? Dont change the prefix.
	if (__pscom_debug_linefmt[0] == '%') return;

	// replace all format characters of prefix
	strncpy(s, prefix, sizeof(s));
	for (t = s; *t; t++) if (*t == '%' || *t == '\\') *t = '/';

	// Use new prefix
	snprintf(__pscom_debug_linefmt, sizeof(__pscom_debug_linefmt),
		 "<PSP:%s:%%s>\n", s);
}


static
FILE *_pscom_debug_file()
{
	if (pscom_debug_file) return pscom_debug_file;
	if (!pscom_debug_filename[0]) return stderr;

	pscom_debug_file = fopen(pscom_debug_filename, "a");
	if (pscom_debug_file) {
		strcpy(__pscom_debug_linefmt, "%s\n");
	} else {
		// Error. Use stderr;
		pscom_debug_file = stderr;
		pscom_dprintf("Opening file %s failed : %s\n", pscom_debug_filename, strerror(errno));
		__pscom_debug_linefmt[0] = '\0';
	}

	return pscom_debug_file;
}


int pscom_dwrite(const char *_msg, size_t len)
{
	int ret = 0;
	char *saveptr = NULL;
	char *line;
	char *msg = strndup(_msg, len);
	FILE *out = _pscom_debug_file();

	for (line = strtok_r(msg, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
		// foreach line do:
		int rc = fprintf(out, _pscom_debug_linefmt(), line);
		if (rc < 0) { ret = rc; break; /* error */ }
		ret += rc;
	}
	fflush(out);
	free(msg);

	return ret;
}


int pscom_dprintf(const char *fmt, ...)
{
	va_list arg;
	char msg[1000];
	int ret = 0;

	va_start(arg, fmt);

	ret = vsnprintf(msg, sizeof(msg), fmt, arg);

	va_end(arg);

	if (ret < 0) return ret; // error

	return pscom_dwrite(msg, strlen(msg));
}


ssize_t pscom_cookie_write(void *cookie, const char *buf, size_t len)
{
	return pscom_dwrite(buf, len);
}


static
cookie_io_functions_t pscom_debug_io = {
	.read = NULL,
	.write = pscom_cookie_write,
	.seek = NULL,
	.close = NULL,
};


FILE *pscom_debug_stream(void)
{
	if (!__pscom_debug_stream) {
		__pscom_debug_stream = fopencookie(NULL, "w", pscom_debug_io);
		setvbuf(__pscom_debug_stream, NULL, _IOLBF, BUFSIZ);
	}

	return __pscom_debug_stream;
}


static
char *__wordexp_error(int error)
{
	switch (error) {
	case WRDE_NOSPACE: return "Ran out of memory.";
	case WRDE_BADCHAR: return "A metachar appears in the wrong place.";
	case WRDE_BADVAL: return "Undefined var reference with WRDE_UNDEF.";
	case WRDE_CMDSUB: return "Command substitution with WRDE_NOCMD.";
	case WRDE_SYNTAX: return "Shell syntax error.";
	}
	return "failed";
}


void pscom_debug_set_filename(const char *filename, int expand)
{
	if (pscom_debug_file &&
	    pscom_debug_file != stderr) {
		fclose(pscom_debug_file);
		pscom_debug_file = 0;
	}

	pscom_debug_filename[0] = '\0';

	if (filename) {
		if (expand) {
			wordexp_t p;
			int rc;

			rc = wordexp(filename, &p,
				     WRDE_NOCMD // Don’t do command substitution.
				);

			if (!rc) {
				if (p.we_wordc == 1) {
					// No error and only one result
					strncpy(pscom_debug_filename, p.we_wordv[0], sizeof(pscom_debug_filename));
				} else {
					DPRINT(D_FATAL, "wordexp(" ENV_DEBUG_OUT "=\"%s\", WRDE_NOCMD) : %d words",
					       filename, (int)p.we_wordc);
				}
				wordfree(&p);
			} else {
				DPRINT(D_FATAL, "wordexp(" ENV_DEBUG_OUT "=\"%s\", WRDE_NOCMD) : %s",
				       filename, __wordexp_error(rc));
			}
		}

		if (!pscom_debug_filename[0]) {
			// no expansion or expansion failed
			strncpy(pscom_debug_filename, filename, sizeof(pscom_debug_filename));
		}
	}
}
