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
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

/* Note: routines here are simple sequences of short lists of string comparisons
 * A more performant approach might be table-driven sorted tables and bsearch().
 * Similarly, simple string parsing routines like strtok() are used, even though
 * less string traversals could be achieved through additional coding */

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
    else if (   0 == strcmp(family, "AF_UNSPEC")
             || 0 == strcmp(family, "PF_UNSPEC"))
        return AF_UNSPEC;
    else {
        errno = EAFNOSUPPORT;
        return -1;
    }
}

const char *
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
    else {
        errno = ESOCKTNOSUPPORT;
        return -1;
    }
}

const char *
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

int
bindsocket_addrinfo_protocol_from_str (const char * const restrict protocol)
{
    struct protoent * const restrict pe = getprotobyname(protocol);
    return (pe != NULL ? pe->p_proto : (errno = EPROTONOSUPPORT, -1));
}

const char *
bindsocket_addrinfo_protocol_to_str (const int proto)
{
    struct protoent * const restrict pe = getprotobynumber(proto);
    return (pe != NULL ? pe->p_name : (errno = EPROTONOSUPPORT, NULL));
}

bool
bindsocket_addrinfo_from_strs(struct addrinfo * const restrict ai,
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
        int r;
        if (0 == (r = getaddrinfo(addr, service, &hints, &gai))) {
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
        errno = ENOSPC;
        return false;
    }
    else { /* (addr family not supported here (parsing code not written)) */
        errno = EAFNOSUPPORT;
        return false;
    }
}

bool
bindsocket_addrinfo_to_strs(struct addrinfo * const restrict ai,
                            char * const restrict buf, const size_t bufsz,
                            char ** const family,
                            char ** const socktype,
                            char ** const protocol,
                            char ** const service,
                            char ** const addr)
{
    size_t sz = 0;
    const char * const restrict ai_family =
      bindsocket_addrinfo_family_to_str(ai->ai_family);
    const char * const restrict ai_socktype =
      bindsocket_addrinfo_socktype_to_str(ai->ai_socktype);
    const char * const restrict ai_protocol =
      bindsocket_addrinfo_protocol_to_str(ai->ai_protocol);
    if (NULL == family || NULL == socktype || NULL == protocol)
        return false;

    /* getservbyport() could be called on port for service name of port
     * However, number string of port is printed since addresses and ports are
     * sometimes used for purposes other than standard service of that port
     * and the numeric string is more readable for the purposes of bindsocket */

    /* Walking through strings would be more efficient, but snprintf
     * and line split is simpler.  (Revisit if bottleneck (not likely)) */

    if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
        char addrstr[INET6_ADDRSTRLEN];
        /* (sin_port is at same offset in struct sockaddr_in, sockaddr_in6) */
        const uint16_t port =
          ntohs(((struct sockaddr_in *)ai->ai_addr)->sin_port);
        if (NULL == inet_ntop(ai->ai_family, ai->ai_addr,
                              addrstr, sizeof(addrstr)))
            return false;
        sz = snprintf(buf, bufsz, "%s %s %s %hu %s",
                      ai_family, ai_socktype, ai_protocol, port, addrstr);
    }
    else if (ai->ai_family == AF_UNIX) {
        sz = snprintf(buf, bufsz, "%s %s %s 0 %s",
                      ai_family, ai_socktype, ai_protocol,
                      ((struct sockaddr_un *)ai->ai_addr)->sun_path);
    }
    else { /* (addr family not supported here (parsing code not written)) */
        errno = EAFNOSUPPORT;
        return false;
    }

    if (sz >= bufsz) {
        errno = ENOSPC;
        return false;
    }

    return bindsocket_addrinfo_split_str(buf, family, socktype,
                                         protocol, service, addr);
}

bool
bindsocket_addrinfo_split_str(char * const restrict buf,
                              char ** const family,
                              char ** const socktype,
                              char ** const protocol,
                              char ** const service,
                              char ** const addr)
{
    return (   NULL != (*family   = strtok(buf,  " "))
            && NULL != (*socktype = strtok(NULL, " "))
            && NULL != (*protocol = strtok(NULL, " "))
            && NULL != (*service  = strtok(NULL, " "))
            && NULL != (*addr     = strtok(NULL, " "))
            && NULL == (            strtok(NULL, " "))) || (errno=EINVAL,false);
}
