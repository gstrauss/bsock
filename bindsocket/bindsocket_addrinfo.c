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
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>

/* Note: routines here are simple sequences of short lists of string comparisons
 * A more performant approach might be table-driven sorted tables and bsearch().
 * Similarly, simple string parsing routines like strtok() are used, even though
 * less string traversals could be achieved through additional coding */

static int
bindsocket_addrinfo_family_from_str (const char * const restrict family)
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
    else if (   0 == strcmp(family, "AF_UNSPEC")
             || 0 == strcmp(family, "PF_UNSPEC"))
        return AF_UNSPEC;
    else {
        errno = EAFNOSUPPORT;
        return -1;
    }
}

static const char *
bindsocket_addrinfo_family_to_str (const int family)
{
    /* list of protocol families below is not complete */
    switch (family) {
      case AF_UNSPEC:  return "AF_UNSPEC";
      case AF_UNIX:    return "AF_UNIX";
      case AF_INET:    return "AF_INET";
      case AF_INET6:   return "AF_INET6";
      default:         errno = EAFNOSUPPORT;
                       return NULL;
    }
}

static int
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
    else {
        errno = ESOCKTNOSUPPORT;
        return -1;
    }
}

static const char *
bindsocket_addrinfo_socktype_to_str (const int socktype)
{
    switch (socktype) {
      case SOCK_STREAM:    return "SOCK_STREAM";
      case SOCK_DGRAM:     return "SOCK_DGRAM";
      case SOCK_RAW:       return "SOCK_RAW";
      case SOCK_RDM:       return "SOCK_RDM";
      case SOCK_SEQPACKET: return "SOCK_SEQPACKET";
      case SOCK_DCCP:      return "SOCK_DCCP";
      case SOCK_PACKET:    return "SOCK_PACKET";
      default:             errno = ESOCKTNOSUPPORT;
                           return NULL;
    }
}

static int
bindsocket_addrinfo_protocol_from_str (const char * const restrict protocol)
{
    struct protoent * const restrict pe = getprotobyname(protocol);
    return (pe != NULL ? pe->p_proto : (errno = EPROTONOSUPPORT, -1));
}

static const char *
bindsocket_addrinfo_protocol_to_str (const int proto)
{
    struct protoent * const restrict pe = getprotobynumber(proto);
    return (pe != NULL ? pe->p_name : (errno = EPROTONOSUPPORT, NULL));
}

bool
bindsocket_addrinfo_from_strs(struct addrinfo * const restrict ai,
                              const struct bindsocket_addrinfo_strs *
                                const restrict aistr)
{
    struct addrinfo hints = {
      .ai_flags     = AI_V4MAPPED | AI_ADDRCONFIG,
      .ai_addrlen   = 0,
      .ai_addr      = NULL,
      .ai_canonname = NULL,
      .ai_next      = NULL
    };
    hints.ai_family   = bindsocket_addrinfo_family_from_str(aistr->family);
    hints.ai_socktype = bindsocket_addrinfo_socktype_from_str(aistr->socktype);
    hints.ai_protocol = bindsocket_addrinfo_protocol_from_str(aistr->protocol);
    if (-1==hints.ai_family || -1==hints.ai_socktype || -1==hints.ai_protocol)
        return false;  /* invalid strings */

    if (hints.ai_family == AF_INET || hints.ai_family == AF_INET6) {
        struct addrinfo *gai;
        int r;
        if (0 == (r = getaddrinfo(aistr->addr, aistr->service, &hints, &gai))) {
            /* gai->ai_next *not* used; not using gai->ai_flags = AI_ALL */
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
            else {
                freeaddrinfo(gai);
                errno = ENOSPC;
                return false;
            }
        }
        if (EAI_SYSTEM != r) errno = EINVAL;  /* better: gai_strerror(r) */
        return false;
    }
    else if (hints.ai_family == AF_UNIX) {
        const size_t len = strlen(aistr->addr);
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
            memcpy(((struct sockaddr_un *)ai->ai_addr)->sun_path,
                   aistr->addr, len+1);
            return true;
        }
        errno = ENOSPC;
        return false;
    }
    else { /* (addr family not supported here (parsing code not written)) */
        errno = EAFNOSUPPORT;
        return false;
    }
}

bool
bindsocket_addrinfo_to_strs(const struct addrinfo * const restrict ai,
                            struct bindsocket_addrinfo_strs * const aistr,
                            char * const restrict buf, const size_t bufsz)
{
    /* (Note: buf should be at least 56 bytes for IPv6 tcp + port + address)
     * (Recommended bufsz is >= 68 for 15 char protocol, and 80 for safety)
     * (Recommended bufsz is 128 if code changed to copy AF_UNIX sun_path) */
    size_t protolen;
    aistr->family   = bindsocket_addrinfo_family_to_str(ai->ai_family);
    aistr->socktype = bindsocket_addrinfo_socktype_to_str(ai->ai_socktype);
    aistr->protocol = bindsocket_addrinfo_protocol_to_str(ai->ai_protocol);
    if (NULL==aistr->family || NULL==aistr->socktype || NULL==aistr->protocol)
        return false;
    protolen = strlen(aistr->protocol) + 1; /* +1 for '\0' */
    if (protolen <= bufsz) { /*copy str into buf for more predictable lifetime*/
        memcpy(buf+bufsz-protolen, aistr->protocol, protolen);
        aistr->protocol = buf+bufsz-protolen;
    }
    else {
        errno = ENOSPC;
        return false;
    }

    if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
        if (INET6_ADDRSTRLEN + 6 + protolen > bufsz) {
            errno = ENOSPC;
            return false;
        }
        aistr->service = aistr->protocol - 6; /* 6 for short port num str */
        aistr->addr = buf;
        if (0 == getnameinfo(ai->ai_addr, ai->ai_addrlen,
                             buf, bufsz-protolen-6, /*max addr sz*/
                             buf+bufsz-protolen-6, 6,
                             NI_NUMERICHOST|NI_NUMERICSERV))
            return true;
    }
    else if (ai->ai_family == AF_UNIX) {
        aistr->service = "0";
        aistr->addr    = ((struct sockaddr_un *)ai->ai_addr)->sun_path;
        return true;
    }
    else  /* (addr family not supported here (parsing code not written)) */
        errno = EAFNOSUPPORT;

    return false;
}

bool
bindsocket_addrinfo_split_str(struct bindsocket_addrinfo_strs * const aistr,
                              char * const restrict str)
{
    return (   NULL != (aistr->family   = strtok(str,  " "))
            && NULL != (aistr->socktype = strtok(NULL, " "))
            && NULL != (aistr->protocol = strtok(NULL, " "))
            && NULL != (aistr->service  = strtok(NULL, " "))
            && NULL != (aistr->addr     = strtok(NULL, " "))
            && NULL == (                  strtok(NULL, " "))
           ) || (errno = EINVAL, false);
}
