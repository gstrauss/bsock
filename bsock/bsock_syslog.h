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

#ifndef INCLUDED_BSOCK_SYSLOG_H
#define INCLUDED_BSOCK_SYSLOG_H

#include "plasma/plasma_attr.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
  BSOCK_SYSLOG_DAEMON = 0,
  BSOCK_SYSLOG_PERROR = 1,
  BSOCK_SYSLOG_PERROR_NOSYSLOG = 2
};

__attribute_cold__
__attribute_noinline__
void
bsock_syslog_setlevel (const int level);

__attribute_cold__
__attribute_noinline__
void
bsock_syslog_setlogfd (const int fd);

__attribute_cold__
__attribute_noinline__
void
bsock_syslog_openlog (const char * const ident,
                      const int option, const int facility);

__attribute_cold__
__attribute_noinline__
__attribute_format__((printf,3,4))
void
bsock_syslog (const int errnum, const int priority,
              const char * const restrict fmt, ...);

#ifdef __cplusplus
}
#endif

#endif
