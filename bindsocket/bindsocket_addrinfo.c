/*
 * bindsocket_addrinfo - struct addrinfo string manipulation
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

#include <bindsocket_addrinfo.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>

int
bindsocket_addrinfo_family_from_str (const char * const family)
{
    /* list of protocol families below is not complete */
    if (        0 == strcmp(family, "AF_INET")
             || 0 == strcmp(family, "PF_INET"))
        return AF_INET;
    else if (   0 == strcmp(family, "AF_INET6")
             || 0 == strcmp(family, "PF_INET6"))
        return AF_INET6;
    else if (   0 == strcmp(family, "AF_LOCAL")
             || 0 == strcmp(family, "AF_UNIX")
             || 0 == strcmp(family, "AF_FILE")
             || 0 == strcmp(family, "PF_LOCAL")
             || 0 == strcmp(family, "PF_UNIX")
             || 0 == strcmp(family, "PF_FILE"))
        return AF_UNIX;
    else
        return -1;
}

int
bindsocket_addrinfo_socktype_from_str (const char * const restrict socktype)
{
    if (     0 == strcmp(socktype, "SOCK_STREAM"))
        return SOCK_STREAM;
    else if (0 == strcmp(socktype, "SOCK_DGRAM"))
        return SOCK_DGRAM;
    else if (0 == strcmp(socktype, "SOCK_RAW"))
        return SOCK_RAW;
    else if (0 == strcmp(socktype, "SOCK_RDM"))
        return SOCK_RDM;
    else if (0 == strcmp(socktype, "SOCK_SEQPACKET"))
        return SOCK_SEQPACKET;
    else if (0 == strcmp(socktype, "SOCK_DCCP"))
        return SOCK_DCCP;
    else if (0 == strcmp(socktype, "SOCK_PACKET"))
        return SOCK_PACKET;
    else
        return -1;
}

int
bindsocket_addrinfo_protocol_from_str (const char * const restrict protocol)
{
    struct protoent * const restrict pe = getprotobyname(protocol);
    return (pe != NULL ? pe->p_proto : -1);
}

bool
bindsocket_addrinfo_from_strings(struct addrinfo * const restrict ai,
                                 const char * const restrict family,
                                 const char * const restrict socktype,
                                 const char * const restrict protocol,
                                 const char * const restrict service,
                                 const char * const restrict addr)
{
    struct addrinfo hints = {
      .ai_flags     = AI_V4MAPPED | AI_ADDRCONFIG,
      .ai_addrlen   = 0,
      .ai_addr      = NULL,
      .ai_canonname = NULL,
      .ai_next      = NULL
    };
    hints.ai_family   = bindsocket_addrinfo_family_from_str(family);
    hints.ai_socktype = bindsocket_addrinfo_socktype_from_str(socktype);
    hints.ai_protocol = bindsocket_addrinfo_protocol_from_str(protocol);
    if (   -1 == hints.ai_family
        || -1 == hints.ai_socktype
        || -1 == hints.ai_protocol)
        return false;  /* invalid strings */

    if (hints.ai_family == AF_INET || hints.ai_family == AF_INET6) {
        struct addrinfo *gai;
        if (0 == getaddrinfo(addr, service, &hints, &gai)) {
            /* gai->ai_next *not* used; not using gai.ai_flags = AI_ALL */
            if (ai->ai_addrlen >= gai->ai_addrlen) {
                ai->ai_flags     = 0;
                ai->ai_family    = gai->ai_family;
                ai->ai_socktype  = gai->ai_socktype;
                ai->ai_protocol  = gai->ai_protocol;
                ai->ai_addrlen   = gai->ai_addrlen;
                ai->ai_canonname = NULL;
                ai->ai_next      = NULL;
                memcpy(ai->ai_addr, gai->ai_addr, gai->ai_addrlen);
                freeaddrinfo(gai);
                return true;
            }
            else { /* not enough space in addr buffer; should not happen */
                return true;
                freeaddrinfo(gai);
                return false;
            }
        }
        /* gai_strerror(r) (r = getaddrinfo(...)) */
        return false;
    }
    else if (hints.ai_family == AF_UNIX) {
        const size_t len = strlen(addr);
        if (len < sizeof(((struct sockaddr_un *)0)->sun_path)
            && sizeof(struct sockaddr_un) <= ai->ai_addrlen) {
            ai->ai_flags    = 0;
            ai->ai_family   = hints.ai_family;
            ai->ai_socktype = hints.ai_socktype;
            ai->ai_protocol = hints.ai_protocol;
            ai->ai_addrlen  = sizeof(struct sockaddr_un);
            ai->ai_canonname= NULL;
            ai->ai_next     = NULL;
            ((struct sockaddr_un *)ai->ai_addr)->sun_family = AF_UNIX;
            memcpy(((struct sockaddr_un *)ai->ai_addr)->sun_path, addr, len+1);
            return true;
        }
        return false; /* not enough space in addr buffer */
    }
    /* (else addr family not supported here (parsing code not written)) */
    return false;
}

