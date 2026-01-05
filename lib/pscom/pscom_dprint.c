/*
 * ParaStation
 *
 * Copyright (C) 2009-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <bits/types/cookie_io_functions_t.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h> /* IWYU pragma: keep */
#include <time.h>
#include <unistd.h>
#include <wordexp.h>

#include "pscom_debug.h"
#include "pscom_env.h"
#include "pscom_priv.h"
#include "pscom_util.h"

#define PSCOM_BACKTRACE 1
#ifdef PSCOM_BACKTRACE
#include <execinfo.h>
#endif

static char __pscom_debug_linefmt[100]  = "";
FILE *__pscom_debug_stream              = NULL;
FILE *pscom_debug_file                  = NULL; // Final output.
char pscom_debug_filename[FILENAME_MAX] = "";
struct timeval pscom_debug_time_start;
enum {
    TIME_NONE,
    TIME_US,
    TIME_WALL,
    TIME_DATE,
    TIME_DELTA
} pscom_debug_time_mode = TIME_NONE;


static char *pscom_dtimestr(void)
{
    static char timestr[30];
    struct timeval time;
    timestr[0] = '\0'; // Default

    switch (pscom_debug_time_mode) {
    case TIME_NONE: break;
    case TIME_WALL:
        // Seconds.microseconds
        pscom_gettimeofday(&time);
        snprintf(timestr, sizeof(timestr), "%04lu.%06lu:", time.tv_sec,
                 time.tv_usec);
        break;
    case TIME_DATE:
        // YYYY-MM-DD_hh:mm:ss.uuuuuu
        pscom_gettimeofday(&time);
        char fmt[20];
        strftime(fmt, sizeof(fmt), "%Y-%m-%d_%H:%M:%S", localtime(&time.tv_sec));
        snprintf(timestr, sizeof(timestr), "%s.%06lu:", fmt, time.tv_usec);
        break;
    case TIME_DELTA:
    case TIME_US:
        // Seconds.microseconds since start or last call.
        pscom_gettimeofday(&time);
        if (time.tv_usec < pscom_debug_time_start.tv_usec) {
            time.tv_usec += 1000000;
            time.tv_sec -= 1;
        }
        time.tv_usec -= pscom_debug_time_start.tv_usec;
        time.tv_sec -= pscom_debug_time_start.tv_sec;

        snprintf(timestr, sizeof(timestr), "%04lu.%06lu:", time.tv_sec,
                 time.tv_usec);
        if (pscom_debug_time_mode == TIME_DELTA) {
            pscom_gettimeofday(&pscom_debug_time_start);
        }
        break;
    }
    return timestr;
}


char *_pscom_debug_linefmt_disabled(void)
{
    return "%s%s\n";
}


char *_pscom_debug_linefmt(void)
{
    if (!__pscom_debug_linefmt[0]) {
        // initialize linefmt.
        char hostname[32];
        if (gethostname(hostname, sizeof(hostname)) < 0 || !hostname[0]) {
            hostname[0] = 0;
        }

        snprintf(__pscom_debug_linefmt, sizeof(__pscom_debug_linefmt),
                 "<PSP:%%s%s:%d:%%s>\n", hostname, getpid());
    }

    return __pscom_debug_linefmt;
}


char *_pscom_debug_linefmt_custom(const char *prefix, const char *postfix)
{
    static char line_fmt[100] = "";
    snprintf(line_fmt, sizeof(line_fmt), "%s%%s%%s%s\n", prefix ? prefix : "",
             postfix ? postfix : "");

    return line_fmt;
}


void pscom_dtime_init(void)
{
    const char *mode = pscom.env.debug_timing;

    if (!mode || !mode[0] || (0 == strcmp(mode, "0"))) {
        // unset, "" or "0"
        pscom_debug_time_mode = TIME_NONE;
    } else if ((0 == strcmp(mode, "wall"))) {
        pscom_debug_time_mode = TIME_WALL;
    } else if ((0 == strcmp(mode, "date"))) {
        pscom_debug_time_mode = TIME_DATE;
    } else if ((0 == strcmp(mode, "delta"))) {
        pscom_debug_time_mode = TIME_DELTA;
    } else if ((0 == strcmp(mode, "1")) || (0 == strcmp(mode, "us"))) {
        pscom_debug_time_mode = TIME_US;
    } else {
        DPRINT(D_WARN, "Unknown PSP_DEBUG_TIMING. Expecting '0', '1', 'us', "
                       "'date', 'wall' or 'delta'.");
        pscom_debug_time_mode = TIME_US;
    }

    switch (pscom_debug_time_mode) {
    case TIME_DELTA:
    case TIME_US:
        pscom_gettimeofday(&pscom_debug_time_start);
        if (D_INFO <= pscom.env.debug) {
            char start[20];
            strftime(start, sizeof(start), "%Y-%m-%d %H:%M:%S",
                     localtime(&pscom_debug_time_start.tv_sec));
            DPRINT(D_INFO, "start %s.%06lu", start,
                   pscom_debug_time_start.tv_usec);
        }
        break;
    default: break;
    }
}


void pscom_debug_set_prefix(const char *prefix)
{
    char s[sizeof(__pscom_debug_linefmt) - 12];
    char *t;

    // Output to file? Dont change the prefix.
    if (__pscom_debug_linefmt[0] == '%') { return; }

    // replace all format characters of prefix
    pscom_strncpy0(s, prefix, sizeof(s));
    for (t = s; *t; t++) {
        if (*t == '%' || *t == '\\') { *t = '/'; }
    }

    // Use new prefix
    snprintf(__pscom_debug_linefmt, sizeof(__pscom_debug_linefmt),
             "<PSP:%%s%s:%%s>\n", s);
}


static FILE *_pscom_debug_file(void)
{
    if (pscom_debug_file) { return pscom_debug_file; }
    if (!pscom_debug_filename[0]) { return stderr; }

    pscom_debug_file = fopen(pscom_debug_filename, "a");
    if (pscom_debug_file) {
        strcpy(__pscom_debug_linefmt, "%s%s\n");
    } else {
        // Error. Use stderr;
        pscom_debug_file = stderr;
        pscom_dprintf("Opening file %s failed : %s\n", pscom_debug_filename,
                      strerror(errno));
        __pscom_debug_linefmt[0] = '\0';
    }

    return pscom_debug_file;
}


int pscom_dwrite(FILE *out, const char *_msg, size_t len, char *line_fmt)
{
    int ret       = 0;
    char *saveptr = NULL;
    char *line;
    char *msg = strndup(_msg, len);

    for (line = strtok_r(msg, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        // foreach line do:
        int rc = fprintf(out, line_fmt, pscom_dtimestr(), line);
        if (rc < 0) {
            ret = rc;
            break; /* error */
        }
        ret += rc;
    }
    fflush(out);
    free(msg);

    return ret;
}


PSCOM_API_EXPORT
int pscom_dprintf(const char *fmt, ...)
{
    va_list arg;
    char msg[1000];
    int ret = 0;

    va_start(arg, fmt);

    ret = vsnprintf(msg, sizeof(msg), fmt, arg);

    va_end(arg);

    if (ret < 0) {
        return ret; // error
    }

    return pscom_dwrite(_pscom_debug_file(), msg, strlen(msg),
                        _pscom_debug_linefmt());
}


static ssize_t pscom_cookie_write(void *cookie, const char *buf, size_t len)
{
    return pscom_dwrite(_pscom_debug_file(), buf, len, _pscom_debug_linefmt());
}


static cookie_io_functions_t pscom_debug_io = {
    .read  = NULL,
    .write = pscom_cookie_write,
    .seek  = NULL,
    .close = NULL,
};


PSCOM_PLUGIN_API_EXPORT
FILE *pscom_debug_stream(void)
{
    if (!__pscom_debug_stream) {
        __pscom_debug_stream = fopencookie(NULL, "w", pscom_debug_io);
        setvbuf(__pscom_debug_stream, NULL, _IOLBF, BUFSIZ);
    }

    return __pscom_debug_stream;
}


static char *__wordexp_error(int error)
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
    if (pscom_debug_file && pscom_debug_file != stderr) {
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
                    pscom_strncpy0(pscom_debug_filename, p.we_wordv[0],
                                   sizeof(pscom_debug_filename));
                } else {
                    DPRINT(D_FATAL,
                           "wordexp(PSP_DEBUG_OUT=\"%s\", WRDE_NOCMD) : %d "
                           "words",
                           filename, (int)p.we_wordc);
                }
                wordfree(&p);
            } else {
                DPRINT(D_FATAL,
                       "wordexp(PSP_DEBUG_OUT=\"%s\", WRDE_NOCMD) : %s",
                       filename, __wordexp_error(rc));
            }
        }

        if (!pscom_debug_filename[0]) {
            // no expansion or expansion failed
            pscom_strncpy0(pscom_debug_filename, filename,
                           sizeof(pscom_debug_filename));
        }
    }
}


#ifdef PSCOM_BACKTRACE
void pscom_backtrace_dump(int sig)
{
    void *array[20];
    int size;
    char **strings;
    int i;

    size    = backtrace(array, 20);
    strings = backtrace_symbols(array, size);

    DPRINT(D_FATAL, "Backtrace%s:",
           sig == SIGSEGV ? " after SIGSEGV (Invalid memory reference)" : "");

    for (i = 0; i < size; i++) { DPRINT(D_FATAL, "#%2u: %s", i, strings[i]); }
    /* backtrace_symbols_fd (array, size, 1); */
    free(strings);
    if (sig == SIGSEGV) { _exit(1); }
}


static int pscom_sigsegv_enabled = 0;
static sighandler_t pscom_sigsegv_old_handler;

void pscom_backtrace_onsigsegv_enable(void)
{
    if (!pscom_sigsegv_enabled++) {
        pscom_sigsegv_old_handler = signal(SIGSEGV, pscom_backtrace_dump);
    }
}


void pscom_backtrace_onsigsegv_disable(void)
{
    if (!--pscom_sigsegv_enabled) {
        sighandler_t old = signal(SIGSEGV, pscom_sigsegv_old_handler);
        if (old != pscom_backtrace_dump) {
            DPRINT(D_WARN,
                   "pscom_backtrace_onsigsegv_disable() expected "
                   "pscom_backtrace_dump(%p) but got %p",
                   pscom_backtrace_dump, old);
            // reregister old handler
            signal(SIGSEGV, old);
        }
    }
}
#else
void pscom_backtrace_dump(void)
{
}

void pscom_backtrace_onsigsegv_enable(void)
{
}


void pscom_backtrace_onsigsegv_disable(void)
{
}
#endif
