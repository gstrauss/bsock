/*
 * bsock_resvaddr - maintain persistent reserved address
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

#ifndef INCLUDED_BSOCK_RESVADDR_H
#define INCLUDED_BSOCK_RESVADDR_H

#include "plasma/plasma_attr.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef _AIX
#include "bsock_addrinfo.h"  /* struct addrinfo */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* use ai->ai_flags for bsock flags since otherwise unused by bsock */
#define BSOCK_FLAGS_REBIND AI_PASSIVE  /* close() and re-bind() resv addr */

__attribute_nonnull__()
int
bsock_resvaddr_fd (const struct addrinfo * const restrict ai);

void
bsock_resvaddr_config (void);

#ifdef __cplusplus
}
#endif

#endif
