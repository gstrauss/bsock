/*
 * bsock_addrinfo - struct addrinfo string manipulation
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

#ifndef INCLUDED_BSOCK_ADDRINFO_H
#define INCLUDED_BSOCK_ADDRINFO_H

#include "plasma/plasma_attr.h"
#include "plasma/plasma_stdtypes.h"

#include <sys/socket.h>
#include <netdb.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_AIX) && !defined(_ALL_SOURCE)
/* #define _ALL_SOURCE required for definition of struct addrinfo on AIX (!) */
/* !!Differs!! from Single Unix Specification SUSv6 (from 2004!)
 * http://pubs.opengroup.org/onlinepubs/009695399/basedefs/netdb.h.html */
struct addrinfo
{                         /* AIX struct addrinfo DIFFERS FROM POSIX STANDARD! */
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    size_t ai_addrlen;         /* socklen_t in standard */
    char *ai_canonname;        /* order swapped with ai_addr in standard */
    struct sockaddr *ai_addr;  /* order swapped with ai_cannonname in standard*/
    struct addrinfo *ai_next;
};
#define AI_PASSIVE 0x02        /* specific to AIX */
#endif

struct bsock_addrinfo_strs {
    const char *family;
    const char *socktype;
    const char *protocol;
    const char *service;
    const char *addr;
};

/* ai->ai_addr must be provided containing usable storage of len ai->ai_addrlen
 * (recommended: #include <sys/socket.h> and use struct sockaddr_storage) */
__attribute_nonnull__
EXPORT bool
bsock_addrinfo_from_strs(struct addrinfo * const restrict ai,
                         const struct bsock_addrinfo_strs *
                           const restrict aistr);

__attribute_nonnull__
EXPORT bool
bsock_addrinfo_to_strs(const struct addrinfo * const restrict ai,
                       struct bsock_addrinfo_strs * const aistr,
                       char * const restrict buf, const size_t bufsz);

__attribute_nonnull__
EXPORT bool
bsock_addrinfo_split_str(struct bsock_addrinfo_strs * const aistr,
                         char * const restrict str);

__attribute_nonnull_x__((2,3))
EXPORT bool
bsock_addrinfo_recv_ex (const int fd,
                        struct addrinfo * const restrict ai,
                        int * const restrict rfd,
                        char * const restrict ctrlbuf,
                        const size_t ctrlbuf_sz);

#define bsock_addrinfo_recv(fd, ai, rfd) \
        bsock_addrinfo_recv_ex((fd),(ai),(rfd),0,0)

__attribute_nonnull__
EXPORT bool
bsock_addrinfo_send (const int fd,
                     const struct addrinfo * const restrict ai, const int sfd);

#ifdef __cplusplus
}
#endif

#endif
