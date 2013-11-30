/*
 * bsock_syslog - syslog() wrapper for error messages
 *
 * Copyright (c) 2011, Glue Logic LLC. All rights reserved. code()gluelogic.com
 *
 *  This file is part of bsock.
 *
 *  bsock is free software: you can redistribute it and/or modify it under
 *  the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  bsock is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with bsock.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <bsock_syslog.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

static int bsock_syslog_level = BSOCK_SYSLOG_PERROR;
static int bsock_syslog_logfd = STDERR_FILENO;
static const char *bsock_syslog_ident;
static size_t bsock_syslog_identlen = 0;

__attribute_cold__
__attribute_noinline__
void
bsock_syslog_setlevel (const int level)
{
    bsock_syslog_level = level;
}

__attribute_cold__
__attribute_noinline__
void
bsock_syslog_setlogfd (const int fd)
{
    bsock_syslog_logfd = fd;
}

__attribute_cold__
__attribute_noinline__
void
bsock_syslog_openlog (const char * const ident,
                      const int option, const int facility)
{
    if (bsock_syslog_level != BSOCK_SYSLOG_PERROR_NOSYSLOG)
        openlog(ident, option, facility);
    bsock_syslog_ident = ident; /*store passed string; see 'man openlog'*/
    bsock_syslog_identlen = (NULL != ident) ? strlen(ident) : 0;
}

__attribute_cold__
__attribute_noinline__
__attribute_format__((printf,3,4))
void
bsock_syslog (const int errnum, const int priority,
              const char * const restrict fmt, ...)
{
    va_list ap;
    size_t len;
    char str[1024] = "";
    char buf[256] = ": ";
    if (0 == errnum || 0 != strerror_r(errnum, buf+2, sizeof(buf)-2))
        buf[0] = '\0';

    va_start(ap, fmt);
    len = (size_t)vsnprintf(str, sizeof(str), fmt, ap); /*str can be truncated*/
    va_end(ap);

    if (bsock_syslog_level != BSOCK_SYSLOG_PERROR_NOSYSLOG)
        syslog(priority, "%s%s", str, buf);

    /*(stderr closed when daemon; skip stderr)*/
    if (bsock_syslog_level != BSOCK_SYSLOG_DAEMON) {
        struct iovec iov[5] = { { (void *)(uintptr_t)bsock_syslog_ident,
                                  bsock_syslog_identlen },
                                { (void *)(uintptr_t)": ",
                                  bsock_syslog_identlen ? 2 : 0 },
                                { str, len < sizeof(str) ? len : sizeof(str) },
                                { buf, strlen(buf) },
                                { (void *)(uintptr_t)"\n", 1 } };
        if (writev(bsock_syslog_logfd, iov, sizeof(iov)/sizeof(struct iovec))){}
    }

    errno = errnum;
}
