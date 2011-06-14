/*
 * bsock_syslog - syslog() wrapper for error messages
 *
 * Copyright (c) 2011, Glue Logic LLC. All rights reserved. code()gluelogic.com
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Glue Logic LLC nor the names of its contributors
 *     may be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

void  __attribute__((cold))
bsock_syslog_setlevel (const int level)
{
    bsock_syslog_level = level;
}

void  __attribute__((cold))
bsock_syslog_setlogfd (const int fd)
{
    bsock_syslog_logfd = fd;
}

void  __attribute__((cold))
bsock_syslog_openlog (const char * const ident,
                      const int option, const int facility)
{
    if (bsock_syslog_level != BSOCK_SYSLOG_PERROR_NOSYSLOG)
        openlog(ident, option, facility);
    bsock_syslog_ident = ident; /*store passed string; see 'man openlog'*/
    bsock_syslog_identlen = (NULL != ident) ? strlen(ident) : 0;
}

void  __attribute__((cold))  __attribute__((format(printf,3,4))) 
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
        struct iovec iov[4] = { { (void *)(uintptr_t)bsock_syslog_ident,
                                  bsock_syslog_identlen },
                                { str, len < sizeof(str) ? len : sizeof(str) },
                                { buf, strlen(buf) },
                                { "\n", 1 } };
        writev(bsock_syslog_logfd, iov, sizeof(iov)/sizeof(struct iovec));
    }

    errno = errnum;
}
