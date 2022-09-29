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

/*
 * getprotobyname_r() and getprotobynumber_r() are not standardized
 */

#ifdef __linux__
/*(#define _BSD_SOURCE for getprotobyname_r(), getprotobynumber_r())*/
#include <sys/types.h>
struct protoent;
extern int getprotobyname_r (__const char *__restrict __name,
                             struct protoent *__restrict __result_buf,
                             char *__restrict __buf, size_t __buflen,
                             struct protoent **__restrict __result);

extern int getprotobynumber_r (int __proto,
                               struct protoent *__restrict __result_buf,
                               char *__restrict __buf, size_t __buflen,
                               struct protoent **__restrict __result);
#endif

#ifdef __sun
/*(#define __EXTENSIONS__ before includes
 * for INET6_ADDRSTRLEN, getprotobyname_r(), getprotobynumber_r()) */
struct protoent;
struct protoent *getprotobyname_r(const char *, struct protoent *, char *, int);
struct protoent *getprotobynumber_r(int, struct protoent *, char *, int);
#define getprotobyname_r(protocol, pe, buf, bufsz, peres) \
  ((*(peres)=getprotobyname_r((protocol),(pe),(buf),(bufsz)))!=NULL ? 0 : errno)
#define getprotobynumber_r(proto, pe, buf, bufsz, peres) \
  ((*(peres)=getprotobynumber_r((proto),(pe),(buf),(bufsz)))!=NULL ? 0 : errno)
#endif

#ifdef _AIX
/*(#define _ALL_SOURCE before includes
 * for struct protoent_data, getprotobyname_r(), getprotobynumber_r())
 * and struct addrinfo */
#define _ALL_SOURCE  /* import IBM ugliness */
#if 0
#include <stdio.h>
#define _MAXALIASES 35
#define _MAXLINELEN 1024
struct protoent_data {     /* should be considered opaque */
    FILE *proto_fp;
    int _proto_stayopen;
    char line[_MAXLINELEN];
    char *proto_aliases[_MAXALIASES];
    int  currentlen;
    char *current;
    void *_proto_reserv1;  /* reserved for future use */
    void *_proto_reserv2;  /* reserved for future use */
};
extern int getprotobyname_r(const char *name, struct protoent *protoptr,
        struct protoent_data *proto_data);
extern int getprotobynumber_r(int proto, struct protoent *protoptr,
        struct protoent_data *proto_data);
#endif /* #if 0 */
#endif

#if defined(__hpux) \
 ||(defined(__APPLE__) && defined(__MACH__)) \
 || defined(__CYGWIN__)
/* OSX: getprotobyname(), getprotobynumber() use thread-local storage */
/* HP-UX: getprotobyname(), getprotobynumber() thread-safe on HP-UX? not sure */
#undef HAVE_GETPROTOBYNAME_R
#undef HAVE_GETPROTOBYNUMBER_R
#else
#define HAVE_GETPROTOBYNAME_R
#define HAVE_GETPROTOBYNUMBER_R
#endif



#include <bsock_addrinfo.h>

#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>

#include <bsock_unix.h>

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#ifdef __hpux
#ifndef ESOCKTNOSUPPORT /* otherwise would require -D_HPUX_SOURCE */
#define ESOCKTNOSUPPORT 222
#endif
#endif

#if defined(__APPLE__) && defined(__MACH__)
#ifndef ESOCKTNOSUPPORT /* otherwise would require -D_DARWIN_C_SOURCE */
#define ESOCKTNOSUPPORT 44
#endif
#endif

#define memcmp_constr(str,constr) memcmp((str),(constr),sizeof(constr))

/* Note: routines here are simple sequences of short lists of string comparisons
 * A more performant approach might be table-driven sorted tables and bsearch().
 * Similarly, simple string parsing routines like strtok() are used, even though
 * less string traversals could be achieved through additional coding */

__attribute_nonnull__()
static int
bsock_addrinfo_family_from_str (const char * const restrict family)
{
    /* list of protocol families below is not complete */
    if (        0 == memcmp_constr(family, "AF_INET")
             || 0 == memcmp_constr(family, "PF_INET"))
        return AF_INET;
    else if (   0 == memcmp_constr(family, "AF_INET6")
             || 0 == memcmp_constr(family, "PF_INET6"))
        return AF_INET6;
    else if (   0 == memcmp_constr(family, "AF_LOCAL")
             || 0 == memcmp_constr(family, "AF_UNIX")
             || 0 == memcmp_constr(family, "AF_FILE")
             || 0 == memcmp_constr(family, "PF_LOCAL")
             || 0 == memcmp_constr(family, "PF_UNIX")
             || 0 == memcmp_constr(family, "PF_FILE"))
        return AF_UNIX;
    else if (   0 == memcmp_constr(family, "AF_UNSPEC")
             || 0 == memcmp_constr(family, "PF_UNSPEC"))
        return AF_UNSPEC;
    else {
        errno = EAFNOSUPPORT;
        return -1;
    }
}

static const char *
bsock_addrinfo_family_to_str (const int family)
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

__attribute_nonnull__()
static int
bsock_addrinfo_socktype_from_str (const char * const restrict socktype)
{
    if (     0 == memcmp_constr(socktype, "SOCK_STREAM"))
        return SOCK_STREAM;
    else if (0 == memcmp_constr(socktype, "SOCK_DGRAM"))
        return SOCK_DGRAM;
    else if (0 == memcmp_constr(socktype, "SOCK_RAW"))
        return SOCK_RAW;
  #ifdef SOCK_RDM
    else if (0 == memcmp_constr(socktype, "SOCK_RDM"))
        return SOCK_RDM;
  #endif
    else if (0 == memcmp_constr(socktype, "SOCK_SEQPACKET"))
        return SOCK_SEQPACKET;
  #ifdef SOCK_DCCP
    else if (0 == memcmp_constr(socktype, "SOCK_DCCP"))
        return SOCK_DCCP;
  #endif
  #ifdef SOCK_PACKET
    else if (0 == memcmp_constr(socktype, "SOCK_PACKET"))
        return SOCK_PACKET;
  #endif
    else {
        errno = ESOCKTNOSUPPORT;
        return -1;
    }
}

static const char *
bsock_addrinfo_socktype_to_str (const int socktype)
{
    switch (socktype) {
      case SOCK_STREAM:    return "SOCK_STREAM";
      case SOCK_DGRAM:     return "SOCK_DGRAM";
      case SOCK_RAW:       return "SOCK_RAW";
    #ifdef SOCK_RDM
      case SOCK_RDM:       return "SOCK_RDM";
    #endif
      case SOCK_SEQPACKET: return "SOCK_SEQPACKET";
    #ifdef SOCK_DCCP
      case SOCK_DCCP:      return "SOCK_DCCP";
    #endif
    #ifdef SOCK_PACKET
      case SOCK_PACKET:    return "SOCK_PACKET";
    #endif
      default:             errno = ESOCKTNOSUPPORT;
                           return NULL;
    }
}

__attribute_nonnull__()
static int
bsock_addrinfo_protocol_from_str (const char * const restrict protocol)
{
  #ifdef _AIX
    struct protoent pe;
    struct protoent_data pedata;
  #endif

    if (!isdigit(((const unsigned char *)protocol)[0])) {
      #ifdef HAVE_GETPROTOBYNAME_R
      #ifndef _AIX
        struct protoent pe;
        struct protoent *peres;
        char buf[1024];
        if (0 == getprotobyname_r(protocol, &pe, buf, sizeof(buf), &peres))
            return pe.p_proto;
      #else  /* _AIX */
        if (0 == getprotobyname_r(protocol, &pe, &pedata))
            return pe.p_proto;
      #endif /* _AIX */
      #else
        struct protoent * const restrict pe = getprotobyname(protocol);
        if (NULL != pe)
            return pe->p_proto;
      #endif
        /* (treating all errors as EPROTONOSUPPORT, including ERANGE) */
    }
    else {
        /* check strtol() succeeded, entire string converted
         * to number and (0 <= lproto && lproto <= INT_MAX)
         * (thread-safe since only checking validity of proto num) */
        char *e;
        long lproto;
      #ifndef _AIX
        if ((errno = 0, lproto = strtol(protocol, &e, 10), 0 == errno)
            && '\0' == *e && 0 == (lproto >> 31)
            && NULL != getprotobynumber((int)lproto)) /*(check validity only)*/
            return (int)lproto;
      #else  /* _AIX */
        if ((errno = 0, lproto = strtol(protocol, &e, 10), 0 == errno)
            && '\0' == *e && 0 == (lproto >> 31)
            && 0 == getprotobynumber_r((int)lproto, &pe, &pedata))
            return (int)lproto;
      #endif /* _AIX */
    }

    errno = EPROTONOSUPPORT;
    return -1;
}

#ifdef HAVE_GETPROTOBYNUMBER_R
__attribute_nonnull__()
static char *
bsock_addrinfo_protocol_to_str (const int proto,
                                char * const buf, const size_t bufsz)
{
  #ifndef _AIX
    struct protoent pe;
    struct protoent *peres;
    int rc;                /*(recommended bufsz is at least 1024 bytes)*/
    return (0 == (rc = getprotobynumber_r(proto, &pe, buf, bufsz, &peres)))
      ? pe.p_name
      : (errno = (rc == ERANGE ? ENOSPC : EPROTONOSUPPORT), (char *)NULL);
         /* (treating all other errors as EPROTONOSUPPORT) */
  #else  /* _AIX */
    struct protoent pe;
    struct protoent_data pedata;
    size_t len;
    return (0 == getprotobynumber_r(proto, &pe, &pedata))
      ? (len = strlen(pe.p_name)) < bufsz
          ? memcpy(buf, pe.p_name, len+1)
          : (errno = ENOSPC, (char *)NULL)
      : (errno = EPROTONOSUPPORT, (char *)NULL);
         /* (treating all other errors as EPROTONOSUPPORT) */
  #endif /* _AIX */
}
#else /* e.g. __hpux || (__APPLE__ && __MACH__) */
/* Note: caller must copy result
 * On OSX, getprotobynumber() uses thread-local storage for thread-safety */
static char *
bsock_addrinfo_protocol_to_str (const int proto)
{
    struct protoent * const restrict pe = getprotobynumber(proto);
    return (NULL != pe) ? pe->p_name : NULL;
}
#define bsock_addrinfo_protocol_to_str(proto,buf,bufsz) \
        bsock_addrinfo_protocol_to_str(proto)
#endif

__attribute_nonnull__()
bool
bsock_addrinfo_from_strs(struct addrinfo * const restrict ai,
                         const struct bsock_addrinfo_strs *
                           const restrict aistr)
{
    struct addrinfo hints = {
      .ai_flags     = AI_V4MAPPED | AI_ADDRCONFIG,
      .ai_addrlen   = 0,
      .ai_addr      = NULL,
      .ai_canonname = NULL,
      .ai_next      = NULL
    };
    hints.ai_family   = bsock_addrinfo_family_from_str(aistr->family);
    hints.ai_socktype = bsock_addrinfo_socktype_from_str(aistr->socktype);
    hints.ai_protocol = bsock_addrinfo_protocol_from_str(aistr->protocol);
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
            && (socklen_t)sizeof(struct sockaddr_un) <= ai->ai_addrlen) {
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

__attribute_nonnull__()
bool
bsock_addrinfo_to_strs(const struct addrinfo * const restrict ai,
                       struct bsock_addrinfo_strs * const aistr,
                       char * const restrict buf, const size_t bufsz)
{
    /* (Note: buf should be at least 56 bytes for IPv6 tcp + port + address)
     * (Recommended bufsz is >= 68 for 15 char protocol, and 80 for safety)
     * (Recommended bufsz is 128 if code changed to copy AF_UNIX sun_path) */
    size_t protolen;
    aistr->family   = bsock_addrinfo_family_to_str(ai->ai_family);
    aistr->socktype = bsock_addrinfo_socktype_to_str(ai->ai_socktype);
    aistr->protocol = bsock_addrinfo_protocol_to_str(ai->ai_protocol,buf,bufsz);
    if (NULL==aistr->family || NULL==aistr->socktype || NULL==aistr->protocol)
        return false;
    protolen = strlen(aistr->protocol) + 1; /* +1 for '\0' */
    memmove(buf+bufsz-protolen, aistr->protocol, protolen);/*(move to buf end)*/
    aistr->protocol = buf+bufsz-protolen;

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

__attribute_nonnull__()
bool
bsock_addrinfo_split_str(struct bsock_addrinfo_strs * const aistr,
                         char * const restrict str)
{
    return (   NULL != (aistr->family   = strtok(str,  " "  ))
            && NULL != (aistr->socktype = strtok(NULL, " "  ))
            && NULL != (aistr->protocol = strtok(NULL, " "  ))
            && NULL != (aistr->service  = strtok(NULL, " "  ))
            && NULL != (aistr->addr     = strtok(NULL, " \n"))
            && NULL == (                  strtok(NULL, " \n"))
           ) || (errno = EINVAL, false);
}

__attribute_nonnull__((2,3))
bool
bsock_addrinfo_recv_ex (const int fd,
                        struct addrinfo * const restrict ai,
                        int * const restrict rfd,
                        char * const restrict ctrlbuf,
                        const size_t ctrlbuf_sz)
{
    /* receive addrinfo request */
    /* caller provides buffer in ai->ai_addr and specifies sz in ai->ai_addrlen
     * (recommended: #include <sys/socket.h> and use struct sockaddr_storage) */
    /* N.B. data received from client is untrustworthy; validate well */
    /* N.B. partial write from client results in error;
     *      client will have to open new connection to retry */
    uint64_t protover = 0; /* bsock v0 and space for flags */
    struct iovec iov[] = {
      { .iov_base = &protover,   .iov_len = sizeof(protover) },
      { .iov_base = ai,          .iov_len = sizeof(struct addrinfo) },
      { .iov_base = ai->ai_addr, .iov_len = ai->ai_addrlen }
    };
    unsigned int nrfds = 1;
    ssize_t r = (ctrlbuf != NULL)
      ? bsock_unix_recv_fds_ex(fd, rfd, &nrfds, iov,
                               sizeof(iov)/sizeof(struct iovec),
                               ctrlbuf, ctrlbuf_sz)
      : bsock_unix_recv_fds(fd, rfd, &nrfds, iov,
                            sizeof(iov)/sizeof(struct iovec));
    if (r <= 0)
        return false;  /* error or client disconnect */
    if (r < (ssize_t)sizeof(protover))
        return false;  /* truncated msg */

    if (0 == protover) {  /* bsock protocol version */
        if (r >= (ssize_t)(sizeof(protover)+sizeof(struct addrinfo))
            && ai->ai_addrlen > 0
            && r == (ssize_t)
                    (sizeof(protover)+sizeof(struct addrinfo)+ai->ai_addrlen)) {
            ai->ai_addr      = iov[2].iov_base; /* assign pointer values */
            ai->ai_canonname = NULL;
            ai->ai_next      = NULL;
            /*ai->ai_flags = 0;*//* ai_flags are used for bsock flags */
            return true;
        }
        return false;  /* truncated msg or invalid ai->ai_addrlen */
    }
    else if ('F' == ((char *)&protover)[1] && '_' == ((char *)&protover)[2]) {
        /* protover taken as char string beginning "AF_" or "PF_" */
        /* collapse iovec array into string, parse into tokens, fill addrinfo */
        struct bsock_addrinfo_strs aistr;
        char line[256];
        if (r >= (ssize_t)sizeof(line)) return false; /* should not happen */
        /*(sizeof(protover)+sizeof(struct addrinfo) == 40; fits in line[256])*/
        memcpy(line, &protover, sizeof(protover));
        memcpy(line + sizeof(protover), ai, sizeof(struct addrinfo));
        line[r] = '\0';
        if ((r -= (ssize_t)(sizeof(protover) + sizeof(struct addrinfo))) > 0)
            memcpy(line + sizeof(protover) + sizeof(struct addrinfo),
                   iov[2].iov_base, (size_t)r);

        /* restore ai->ai_addrlen ai->ai_addr buffer sizes passed into routine*/
        ai->ai_addrlen = iov[2].iov_len;
        ai->ai_addr    = (struct sockaddr *)iov[2].iov_base;

        return bsock_addrinfo_split_str(&aistr, line)
          ? bsock_addrinfo_from_strs(ai, &aistr)
          : false;  /* invalid client request; truncated msg */
    }

    return false;   /* invalid client request; undecipherable format */
}

#if 0 /* see #define bsock_addrinfo_recv(fd, ai, rfd) in bsock_addrinfo.h */
__attribute_nonnull__()
bool
bsock_addrinfo_recv (const int fd,
                     struct addrinfo * const restrict ai,
                     int * const restrict rfd)
{
    return bsock_addrinfo_recv_ex(fd, ai, rfd, NULL, 0);
}
#endif

__attribute_nonnull__()
bool
bsock_addrinfo_send (const int fd,
                     const struct addrinfo * const restrict ai, const int sfd)
{
    /* msg sent atomically, or else not transmitted: error w/ errno==EMSGSIZE */
    /* Note: struct addrinfo contains pointers.  These are not valid on other
     * side of socket, but do expose client pointer addresses to server.
     * Could avoid by copying struct addrinfo, setting pointers zero in copy */
    uint64_t protover = 0; /* bsock v0 and space for flags */
    struct iovec iov[] = {
      { .iov_base = &protover,             .iov_len = sizeof(protover) },
      { .iov_base = (void *)(uintptr_t)ai, .iov_len = sizeof(struct addrinfo) },
      { .iov_base = ai->ai_addr,           .iov_len = ai->ai_addrlen }
    };
    ssize_t w = bsock_unix_send_fds(fd, &sfd, (sfd >= 0), iov,
                                    sizeof(iov)/sizeof(struct iovec));
    return w == (ssize_t)
                (sizeof(protover) + sizeof(struct addrinfo) + ai->ai_addrlen);
    /* (caller might choose not to report errno==EPIPE or errno==ECONNRESET) */
}

#if 0 /* sample client code sending an addrinfo string (structured precisely) */
    const char * const msg = "AF_INET SOCK_STREAM tcp 80 0.0.0.0";
    const size_t msglen = strlen(msg);
    if (msglen == send(sfd, msg, msglen, MSG_NOSIGNAL|MSG_DONTWAIT))
        return true;
    perror("send");
    return false;
#endif
