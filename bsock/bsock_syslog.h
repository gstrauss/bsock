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
