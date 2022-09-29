/*
 * bsock_bindresvport - bind socket to random low port (privileged IP port)
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

#ifndef INCLUDED_BSOCK_BINDRESVPORT_H
#define INCLUDED_BSOCK_BINDRESVPORT_H

#include "plasma/plasma_attr.h"

#include <sys/types.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

__attribute_nonnull__()
int
bsock_bindresvport_sa (const int sockfd, struct sockaddr *sa);

#ifdef __cplusplus
}
#endif

#endif
