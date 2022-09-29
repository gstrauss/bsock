/*
 * bsock_daemon - daemon initialization and signal setup
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

#ifndef INCLUDED_BSOCK_DAEMON_H
#define INCLUDED_BSOCK_DAEMON_H

#include "plasma/plasma_attr.h"
#include "plasma/plasma_stdtypes.h"

#ifdef __cplusplus
extern "C" {
#endif

EXPORT bool
bsock_daemon_setuid_stdinit (void);

EXPORT bool
bsock_daemon_init (const int supervised, const bool check);

__attribute_nonnull__()
EXPORT int
bsock_daemon_init_socket (const char * const restrict sockpath, /*(persistent)*/
                          const uid_t uid, const gid_t gid,
                          const mode_t mode);

EXPORT size_t
bsock_daemon_msg_control_max (void);

#ifdef __cplusplus
}
#endif

#endif
