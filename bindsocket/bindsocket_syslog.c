/*
 * bindsocket_syslog - syslog() wrapper for error messages
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

#include <bindsocket_syslog.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#ifndef BINDSOCKET_SYSLOG_IDENT
#define BINDSOCKET_SYSLOG_IDENT "bindsocket"
#endif

#ifndef BINDSOCKET_SYSLOG_FACILITY
#define BINDSOCKET_SYSLOG_FACILITY LOG_DAEMON
#endif

static int bindsocket_syslog_level = BINDSOCKET_SYSLOG_PERROR;

void
bindsocket_syslog_setlevel (const int level)
{
    bindsocket_syslog_level = level;
}

void
bindsocket_syslog_openlog (void)
{
    openlog(BINDSOCKET_SYSLOG_IDENT, LOG_NOWAIT, BINDSOCKET_SYSLOG_FACILITY);
}

void  __attribute__((cold))  __attribute__((format(printf,2,3))) 
bindsocket_syslog (const int errnum, const char * const restrict fmt, ...)
{
    va_list ap;
    char str[1024] = "";
    char buf[256] = ": ";
    if (0 == errnum || 0 != strerror_r(errnum, buf+2, sizeof(buf)-2))
        buf[0] = '\0';

    va_start(ap, fmt);
    (void)vsnprintf(str, sizeof(str), fmt, ap);/* str is truncated, as needed */
    va_end(ap);

    syslog(LOG_ERR, "%s%s", str, buf); /* syslog() always */

    /*(stderr closed when daemon; skip stderr)*/
    if (BINDSOCKET_SYSLOG_DAEMON != bindsocket_syslog_level)
        fprintf(stderr, BINDSOCKET_SYSLOG_IDENT": %s%s\n", str, buf);
}
