/*
 * bsock_addrinfo - struct addrinfo string manipulation
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

#ifndef INCLUDED_BSOCK_ADDRINFO_H
#define INCLUDED_BSOCK_ADDRINFO_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdbool.h>

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

/* ai->ai_addr must be provided containing usage storage of len ai->ai_addrlen
 * (recommend: int addr[28]; ai->ai_addr=addr; ai->ai_addrlen=sizeof(addr); )*/
bool  __attribute__((nonnull))
bsock_addrinfo_from_strs(struct addrinfo * const restrict ai,
                         const struct bsock_addrinfo_strs *
                           const restrict aistr);

bool  __attribute__((nonnull))
bsock_addrinfo_to_strs(const struct addrinfo * const restrict ai,
                       struct bsock_addrinfo_strs * const aistr,
                       char * const restrict buf, const size_t bufsz);

bool  __attribute__((nonnull))
bsock_addrinfo_split_str(struct bsock_addrinfo_strs * const aistr,
                         char * const restrict str);

bool  __attribute__((nonnull (2,3)))
bsock_addrinfo_recv_ex (const int fd,
                        struct addrinfo * const restrict ai,
                        int * const restrict rfd,
                        char * const restrict ctrlbuf,
                        const size_t ctrlbuf_sz);

#define bsock_addrinfo_recv(fd, ai, rfd) \
        bsock_addrinfo_recv_ex((fd),(ai),(rfd),0,0)

bool  __attribute__((nonnull))
bsock_addrinfo_send (const int fd,
                     const struct addrinfo * const restrict ai, const int sfd);

#ifdef __cplusplus
}
#endif

#endif
