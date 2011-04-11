/*
 * bindsocket - bind() sockets to restricted ports for lower-privilege daemons
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

#define _XOPEN_SOURCE 600

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <poll.h>
#include <pwd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

extern char **environ; /* avoid #define _GNU_SOURCE for visibility of environ */

#ifndef POLLRDHUP
#define POLLRDHUP 0
#endif

#ifndef BINDSOCKET_GROUP
#define BINDSOCKET_GROUP "daemon"
#endif

/* N.B. directory (and tree above it) must be writable only by root */
/* Unit test drivers not run as root should override this location at compile */
#ifndef BINDSOCKET_SOCKET_DIR
#define BINDSOCKET_SOCKET_DIR "/var/run/bindsocket"
#endif
#define BINDSOCKET_SOCKET BINDSOCKET_SOCKET_DIR "/socket"
/* <<<FUTURE: /etc/bindsocket ? */
#define BINDSOCKET_CONFIG BINDSOCKET_SOCKET_DIR "/config"

#ifndef BINDSOCKET_SYSLOG_IDENT
#define BINDSOCKET_SYSLOG_IDENT "bindsocket"
#endif
#ifndef BINDSOCKET_SYSLOG_FACILITY
#define BINDSOCKET_SYSLOG_FACILITY LOG_DAEMON
#endif

static int syslog_perror_level = 0;

static void
bindsocket_openlog (void)
{
    openlog(BINDSOCKET_SYSLOG_IDENT, LOG_NOWAIT, BINDSOCKET_SYSLOG_FACILITY);
}

static void __attribute__((noinline)) __attribute__((cold))
syslog_perror (const char * const restrict str, const int errnum)
{
    /* (not written to use vsyslog(); lazy
     *  and not currently needed for error messages in this program) */

    /* syslog() always */
    if (0 != errno)
        syslog(LOG_ERR, "%s: %s", str, strerror(errnum));
    else
        syslog(LOG_ERR, "%s", str);

    if (0 == syslog_perror_level) { /*(stderr closed when daemon; skip perror)*/
        if (0 != errnum) {
            errno = errnum;
            perror(str);
        }
        else
            fprintf(stderr, "%s\n", str);
    }
}

static int
str_to_ai_family (const char * const family)
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

static int
str_to_ai_socktype (const char * const restrict socktype)
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

static int
str_to_ai_protocol (const char * const restrict protocol)
{
    struct protoent * const restrict pe = getprotobyname(protocol);
    return (pe != NULL ? pe->p_proto : -1);
}

static bool
strs_to_addrinfo (struct addrinfo * const restrict ai,
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
    if (   -1 == (hints.ai_family   = str_to_ai_family(family))
        || -1 == (hints.ai_socktype = str_to_ai_socktype(socktype))
        || -1 == (hints.ai_protocol = str_to_ai_protocol(protocol)))
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

/* retry_close() - make effort to avoid leaking open file descriptors */
static int
retry_close (const int fd)
{
    int r;
    if (fd < 0) return 0;
    do {r = close(fd);} while (r != 0 && errno == EINTR);
    if (0 != r) syslog_perror("close", errno);
    return r;
}

static ssize_t
retry_poll_fd (const int fd, const short events, const int timeout)
{
    struct pollfd pfd = { .fd = fd, .events = events, .revents = 0 };
    int n;
    do { n = poll(&pfd, 1, timeout); } while (-1 == n && errno == EINTR);
    if (-1 == n) syslog_perror("poll", errno);
    return n;
}

static ssize_t
unix_domain_recvmsg (const int fd,
                     struct iovec * const restrict iov,
                     const size_t iovlen)
{
    /* (nonblocking recvmsg(); caller might poll() before call to here)*/
    ssize_t r;
    /* RFC 3542 min ancillary data is 10240; recommends getsockopt SO_SNDBUF */
    char ctrlbuf[108]; /* BSD mbuf is 108 */
    struct msghdr msg = {
      .msg_name       = NULL,
      .msg_namelen    = 0,
      .msg_iov        = iov,
      .msg_iovlen     = iovlen,
      .msg_control    = ctrlbuf,
      .msg_controllen = sizeof(ctrlbuf),
      .msg_flags      = 0
    };
    struct cmsghdr *cmsg;
    do { r = recvmsg(fd, &msg, MSG_DONTWAIT); } while (-1==r && errno==EINTR);
    if (r < 1) { /* EOF (r=0) or error (r=-1) */
        if (-1 == r) syslog_perror("recvmsg", errno);
        return r;
    }

    /*(MSG_TRUNC should not happen on stream-based (SOCK_STREAM) socket)*/
    /*(MSG_CTRUNC is unexpected in bindsocket and is notable error/attack)*/
    /* N.B. since bindsocket_client_session() handled in short-lived child
     * fork()ed from parent daemon and will exit soon, simply syslog.
     * Alternatively, daemon could closelog(), close fds > STDERR_FILENO,
     * and then repeat call to openlog() */
    if (msg.msg_flags & MSG_CTRUNC)
        syslog(LOG_CRIT, "recvmsg msg_flags MSG_CTRUNC");

    /* recvmsg() can receive multiple fds even if MSG_PEEK
     * recvmsg() can receive multiple fds even if MSG_CTRUNC (ctrlbuf too small)
     * recvmsg() can receive int array of fds and/or multiple cmsgs with fds
     * (defensive client must handle multiple fds received unexpectedly)
     * (defensive client might setsockopt SO_PASSCRED, check SCM_CREDENTIALS) */

    for (cmsg=CMSG_FIRSTHDR(&msg); NULL != cmsg; cmsg=CMSG_NXTHDR(&msg,cmsg)) {
        if (cmsg->cmsg_type == SCM_RIGHTS && cmsg->cmsg_level == SOL_SOCKET) {
            int * const fds = (int *)CMSG_DATA(cmsg);
            int n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            /* close excess fds received; unexpected by bindsocket */
            while (n-- > 0)
                retry_close(fds[n]);
        }
    }

    return r;
}

static ssize_t
unix_domain_sendmsg (const int fd,
                     struct iovec * const restrict iov,
                     const size_t iovlen)
{
    /* (nonblocking sendmsg(); caller might poll() before call to here)*/
    /* (caller should handle EAGAIN and EWOULDBLOCK) */
    ssize_t w;
    struct msghdr msg = {
      .msg_name       = NULL,
      .msg_namelen    = 0,
      .msg_iov        = iov,
      .msg_iovlen     = iovlen,
      .msg_control    = NULL,
      .msg_controllen = 0,
      .msg_flags      = 0
    };
    do { w = sendmsg(fd, &msg, MSG_DONTWAIT|MSG_NOSIGNAL);
    } while (-1 == w && errno == EINTR);
    if (-1 == w && errno != EPIPE && errno != ECONNRESET)
        syslog_perror("sendmsg", errno);
    return w;
}

static int
unix_domain_recv_fd (const int fd)
{
    /* receive and return file descriptor sent over unix domain socket */
    /* 'man cmsg' provides example code */
    ssize_t r;
    char iovbuf[4]; /* match data size of iovbuf in unix_domain_send_fd() */
    struct iovec iov = { .iov_base = iovbuf, .iov_len = sizeof(iovbuf) };
    /* RFC 3542 min ancillary data is 10240; recommends getsockopt SO_SNDBUF */
    char ctrlbuf[108]; /* BSD mbuf is 108 */
    struct msghdr msg = {
      .msg_name       = NULL,
      .msg_namelen    = 0,
      .msg_iov        = &iov,
      .msg_iovlen     = 1,
      .msg_control    = ctrlbuf,
      .msg_controllen = sizeof(ctrlbuf),
      .msg_flags      = 0
    };
    struct cmsghdr *cmsg;
    int rfd = -1;
    if (1 != retry_poll_fd(fd, POLLIN|POLLRDHUP, -1)) return -1;
    do { r = recvmsg(fd, &msg, MSG_DONTWAIT); } while (-1==r && errno==EINTR);
    if (r < 1) { /* EOF (r=0) or error (r=-1) */
        if (-1 == r) syslog_perror("recvmsg", errno);
        return -1;
    }

    /*(MSG_TRUNC should not happen on stream-based (SOCK_STREAM) socket)*/
    /*(MSG_CTRUNC is unexpected from bindsocket daemon; notable error/attack)*/
    if (msg.msg_flags & MSG_CTRUNC)
        syslog(LOG_CRIT, "recvmsg msg_flags MSG_CTRUNC");

    /* recvmsg() can receive multiple fds even if MSG_CTRUNC (ctrlbuf too small)
     * recvmsg() can receive int array of fds and/or multiple cmsgs with fds
     * (defensive client must handle multiple fds received unexpectedly)
     * (defensive client might setsockopt SO_PASSCRED, check SCM_CREDENTIALS) */

    for (cmsg=CMSG_FIRSTHDR(&msg); NULL != cmsg; cmsg=CMSG_NXTHDR(&msg,cmsg)) {
        if (cmsg->cmsg_type == SCM_RIGHTS && cmsg->cmsg_level == SOL_SOCKET) {
            int * const fds = (int *)CMSG_DATA(cmsg);
            int n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            if (-1 == rfd)
                rfd = fds[0];  /* received fd; success */
            /* close excess fds received; unexpected by bindsocket */
            while (n-- > 0) {
                if (fds[n] != rfd)
                    retry_close(fds[n]);
            }
        }
    }
    return rfd;
}

static bool
unix_domain_send_fd (const int cfd, const int fd)
{
    /* pass any non-zero-length data so client can distinguish msg from EOF */
    /* 'man cmsg' provides sample code */
    /*(caller might first poll() POLLOUT since nonblocking sendmsg() employed)*/
    ssize_t w;
    char iovbuf[4] = {0,0,0,0};
    struct iovec iov = { .iov_base = iovbuf, .iov_len = sizeof(iovbuf) };
    char ctrlbuf[CMSG_SPACE(sizeof(int))]; /* fd int-sized; 4 bytes of data */
    struct msghdr msg = {
      .msg_name       = NULL,
      .msg_namelen    = 0,
      .msg_iov        = &iov,
      .msg_iovlen     = 1,
      .msg_control    = ctrlbuf,
      .msg_controllen = sizeof(ctrlbuf),
      .msg_flags      = 0
    };
    struct cmsghdr *cmsg   = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level       = SOL_SOCKET;
    cmsg->cmsg_type        = SCM_RIGHTS;
    cmsg->cmsg_len         = msg.msg_controllen = CMSG_LEN(sizeof(int));/*data*/
    *(int *)CMSG_DATA(cmsg)= fd;
    do { w = sendmsg(cfd, &msg, MSG_DONTWAIT|MSG_NOSIGNAL);
    } while (-1 == w && errno == EINTR);
    if (-1 == w && errno != EPIPE && errno != ECONNRESET)
        syslog_perror("sendmsg", errno);
    return (-1 != w);
}

static int
unix_domain_socket_connect (const char * const restrict sockpath)
{
    /* connect to unix domain socket */
    /* (not bothering to retry socket() and connect(); lazy) */
    /* (retry_close to avoid fd resource leak) */
    /* (blocking connect(); not doing O_NONBLOCK socket and poll() for write */
    struct sockaddr_un saddr;
    const size_t len = strlen(sockpath);
    int fd;
    if (len >= sizeof(saddr.sun_path))
        return -1;
    saddr.sun_family = AF_UNIX;
    memcpy(saddr.sun_path, sockpath, len+1);
    if (  -1 != (fd = socket(AF_UNIX, SOCK_STREAM, 0))
        && 0 == connect(fd, (struct sockaddr *)&saddr, sizeof(saddr)))
        return fd;

    syslog_perror("socket,connect", errno);
    retry_close(fd);
    return -1;
}

static int
unix_domain_socket_bind_listen (const char * const restrict sockpath)
{
    /* bind and listen to unix domain socket */
    /* (not bothering to retry bind() and listen(); lazy) */
    /* (retry_close to avoid fd resource leak) */
    /* N.B. caller must create dir for sockpath with restricted permissions &
     *      caller must set umask so socket created with desired permissions*/
    struct sockaddr_un saddr;
    const size_t len = strlen(sockpath);
    int fd, flags;
    if (len >= sizeof(saddr.sun_path))
        return -1;
    saddr.sun_family = AF_UNIX;
    memcpy(saddr.sun_path, sockpath, len+1);
    if (  -1 != (fd = socket(AF_UNIX, SOCK_STREAM, 0))
        && 0 == bind(fd, (struct sockaddr *)&saddr, sizeof(saddr))
        && 0 == listen(fd, 4))      /* (arbitrary listen backlog of 4) */
        return fd;

    /* socket exists: test connect, or remove socket and retry to listen */
    if (  fd >= 0 && errno == EADDRINUSE
        &&-1 != (flags = fcntl(fd, F_GETFL, 0))
        && 0 == fcntl(fd, F_SETFL, flags|O_NONBLOCK)
        && 0 != connect(fd, (struct sockaddr *)&saddr, sizeof(saddr))
        && errno == ECONNREFUSED    /* nobody listening */
        && 0 == unlink(sockpath)
        && 0 == retry_close(fd)
        &&-1 != (fd = socket(AF_UNIX, SOCK_STREAM, 0))
        && 0 == bind(fd, (struct sockaddr *)&saddr, sizeof(saddr))
        && 0 == listen(fd, 4))      /* (arbitrary listen backlog of 4) */
        return fd;

    syslog_perror("socket,bind,listen", errno);
    retry_close(fd);
    return -1;
}

static bool
bindsocket_recv_addrinfo (const int fd, const int msec,
                          struct addrinfo * const restrict ai)
{
    /* receive addrinfo request */
    /* caller provides buffer in ai->ai_addr and specifies sz in ai->ai_addrlen
     * To support IPv4, IPv6, AF_UNIX domain sockets (2 byte short + 108 chars)
     * and align buffer: int addr[27]; ai.ai_addr = (struct sockaddr *)addr */
    /* N.B. data received from client is untrustworthy; validate well */
    /* N.B. partial write from client results in error;
     *      client will have to open new connection to retry */
    uint64_t protover = 0; /* bindsocket v0 and space for flags */
    struct iovec iov[] = {
      { .iov_base = &protover,   .iov_len = sizeof(protover) },
      { .iov_base = ai,          .iov_len = sizeof(struct addrinfo) },
      { .iov_base = ai->ai_addr, .iov_len = ai->ai_addrlen }
    };
    if (1 != retry_poll_fd(fd, POLLIN|POLLRDHUP, msec)) return false;
    ssize_t r = unix_domain_recvmsg(fd, iov, sizeof(iov)/sizeof(struct iovec));
    if (r <= 0)
        return false;  /* error or client disconnect */
    if (r < sizeof(protover))
        return false;  /* truncated msg */

    if (0 == protover) {  /* bindsocket protocol version */
        if (r >= sizeof(protover)+sizeof(struct addrinfo) && ai->ai_addrlen > 0
            && r == sizeof(protover)+sizeof(struct addrinfo)+ai->ai_addrlen) {
            ai->ai_addr      = iov[2].iov_base; /* assign pointer values */
            ai->ai_canonname = NULL;
            ai->ai_next      = NULL;
            return true;
        }
        return false;  /* truncated msg or invalid ai->ai_addrlen */
    }
    else if (0 == memcmp(((char *)&protover)+1, "F_", 2)) {
        /* protover taken as char string beginning "AF_" or "PF_" */
        /* collapse iovec array into string, parse into tokens, fill addrinfo */
        char *family, *socktype, *protocol, *service, *addr;
        char line[256];
        if (r >= sizeof(line)) return false; /* should not happen */
        /*(sizeof(protover)+sizeof(struct addrinfo) == 40; fits in line[256])*/
        memcpy(line, &protover, sizeof(protover));
        memcpy(line + sizeof(protover), ai, sizeof(struct addrinfo));
        line[r] = '\0';
        if ((r -= (sizeof(protover) + sizeof(struct addrinfo))) > 0)
            memcpy(line + sizeof(protover) + sizeof(struct addrinfo),
                   iov[2].iov_base, r);

        /* restore ai->ai_addrlen ai->ai_addr buffer sizes passed into routine*/
        ai->ai_addrlen = iov[2].iov_len;
        ai->ai_addr    = (struct sockaddr *)iov[2].iov_base;

        if (   NULL != (family   = strtok(line, " "))
            && NULL != (socktype = strtok(NULL, " "))
            && NULL != (protocol = strtok(NULL, " "))
            && NULL != (service  = strtok(NULL, " "))
            && NULL != (addr     = strtok(NULL, " "))
            && NULL == (           strtok(NULL, " ")))
            return strs_to_addrinfo(ai,family,socktype,protocol,service,addr);

        return false;  /* invalid client request; truncated msg */
    }

    return false;
}

static bool
bindsocket_send_addrinfo (const int fd, const int msec,
                          struct addrinfo * const restrict ai)
{
    /* msg sent atomically, or else not transmitted: error w/ errno==EMSGSIZE */
    /* Note: struct addrinfo contains pointers.  These are not valid on other
     * side of socket, but do expose client pointer addresses to server.
     * Could avoid by copying struct addrinfo, setting pointers zero in copy */
    uint64_t protover = 0; /* bindsocket v0 and space for flags */
    struct iovec iov[] = {
      { .iov_base = &protover,   .iov_len = sizeof(protover) },
      { .iov_base = ai,          .iov_len = sizeof(struct addrinfo) },
      { .iov_base = ai->ai_addr, .iov_len = ai->ai_addrlen }
    };
    if (1 != retry_poll_fd(fd, POLLOUT, msec)) return false;
    ssize_t w = unix_domain_sendmsg(fd, iov, sizeof(iov)/sizeof(struct iovec));
    return w == (sizeof(protover) + sizeof(struct addrinfo) + ai->ai_addrlen);
}

#ifdef __linux__
/* obtain peer credentials
 * (requires Linux getsockopt SO_PEERCRED or BSD-style getpeereid() support) */
static int
getpeereid(const int s,uid_t * const restrict euid,gid_t * const restrict egid)
{
    struct ucred { pid_t pid; uid_t uid; gid_t gid; }; /*or define _GNU_SOURCE*/
    struct ucred ucred;
    socklen_t slen = sizeof(struct ucred);
    if (0 != getsockopt(s, SOL_SOCKET, SO_PEERCRED, &ucred, &slen))
        return -1;
    *euid = ucred.uid;
    *egid = ucred.gid;
    return 0;
}
#endif

#ifdef __sun__
/* obtain peer credentials using getpeerucred() (Solaris 10) */
#include <ucred.h>
static int
getpeereid(const int s,uid_t * const restrict euid,gid_t * const restrict egid)
{
    struct ucred_t *ucred;
    if (0 != getpeerucred(s, &ucred))
        return -1;
    *euid = ucred_geteuid(ucred);
    *egid = ucred_getegid(ucred);
    ucred_free(ucred);
    return (*euid != -1 && *egid != -1) ? 0 : -1;
}
#endif

static bool
bindsocket_is_authorized_addrinfo (const struct addrinfo * const restrict ai,
                                 const uid_t uid, const gid_t gid)
{
    /* Note: no process optimization implemented
     *       (numerous options for caching, improving performance if needed) */
    /* <<<FUTURE: better error messages for config file errors */

    char *username, *family, *socktype, *protocol, *service, *addr;
    FILE *cfg;
    struct passwd *pw;
    struct addrinfo *gai;
    struct addrinfo hints = {
      .ai_flags     = AI_V4MAPPED | AI_ADDRCONFIG,
      /* ai_family, ai_socktype, ai_protocol are filled in from config file */
      .ai_addrlen   = 0,
      .ai_addr      = NULL,
      .ai_canonname = NULL,
      .ai_next      = NULL
    };
    int r;
    const uid_t euid = geteuid();
    struct stat st;
    char line[256];
    bool rc = false;

    if (uid == 0 || gid == 0)  /* permit root or wheel */
        return true;

    if (NULL == (cfg = fopen(BINDSOCKET_CONFIG, "r"))) {
        syslog_perror(BINDSOCKET_CONFIG, errno);
        return false;
    }
    if (0 != fstat(fileno(cfg), &st)
        || st.st_uid != euid || (st.st_mode & (S_IWGRP|S_IWOTH))) {
        syslog_perror("ownership/permissions incorrect on "BINDSOCKET_CONFIG,0);
        return false;
    }

    while (!feof(cfg) && !ferror(cfg)) {
        if (NULL == fgets(line, sizeof(line), cfg))
            continue;  /* EOF or error reading file */
        if (*line == '#' || *line == '\n')
            continue;  /* comment or blank line */
        if (   NULL == (username = strtok(line, " "))
            || NULL == (family   = strtok(NULL, " "))
            || NULL == (socktype = strtok(NULL, " "))
            || NULL == (protocol = strtok(NULL, " "))
            || NULL == (service  = strtok(NULL, " "))
            || NULL == (addr     = strtok(NULL, " "))
            || NULL != (           strtok(NULL, " "))) {
            syslog_perror("bindsocket config file error", 0);
            continue;
        }
        if ( NULL == (pw = getpwnam(username))
            || -1 == (hints.ai_family   = str_to_ai_family(family))
            || -1 == (hints.ai_socktype = str_to_ai_socktype(socktype))
            || -1 == (hints.ai_protocol = str_to_ai_protocol(protocol))) {
            syslog_perror("bindsocket config file error", 0);
            continue;
        }

        if (   pw->pw_uid != uid                 /* not unspecified by client */
            || (hints.ai_family  != ai->ai_family && AF_UNSPEC != ai->ai_family)
            || hints.ai_socktype != ai->ai_socktype
            || (hints.ai_protocol != ai->ai_protocol && 0 != ai->ai_protocol))
            continue;  /* not a match */

        if (hints.ai_family == AF_INET || hints.ai_family == AF_INET6) {
            if (0 == (r = getaddrinfo(addr, service, &hints, &gai))) {
                /* gai->ai_next *not* checked; not using hints.ai_flags = AI_ALL
                 * config file should have specific addrs that each match one */
                if (   gai->ai_addrlen == ai->ai_addrlen
                    || 0 == memcmp(gai->ai_addr, ai->ai_addr, ai->ai_addrlen)) {
                    freeaddrinfo(gai);
                    rc = true;
                    break;  /* match; success */
                } /* else not a match */
                freeaddrinfo(gai);
            }
            else
                syslog_perror("getaddrinfo", 0); /* gai_strerror(r) */
        }
        else if (hints.ai_family == AF_UNIX) {
            if (0 == strncmp(((struct sockaddr_un *)ai->ai_addr)->sun_path,
                             addr, ai->ai_addrlen)) {
                rc = true;
                break;  /* match; success */
            } /* else not a match */
        }
        /* (else not supported by bindsocket, or config file error) */
    }

    if (!rc) {
        syslog_perror("permission denied", 0);
    }
    fclose(cfg);  /* not required; bindsocket_client_session() exits soon */
    return rc;
}

static int
bindsocket_client_session (const int cfd,
                           const int argc, char * const * const restrict argv)
{
    /* <<<FUTURE: might add additional logging of request and success/failure */
    int fd;
    int rc = EXIT_FAILURE;
    uid_t euid;
    gid_t egid;
    int flag = 1;
    int addr[27];/* buffer for IPv4, IPv6, or AF_UNIX w/ up to 108 char path */
    struct addrinfo ai = {  /* init only fields used to pass buf and bufsize */
      .ai_addrlen = sizeof(addr),
      .ai_addr    = (struct sockaddr *)addr
    };

    if (0 != getpeereid(cfd, &euid, &egid))
        return EXIT_FAILURE;

    /* syslog all connections to (or instantiations of) bindsocket daemon
     * <<<FUTURE: might write custom wrapper to platform-specific getpeereid()
     * and combine with syslog() call to log pid and other info, if available */
    syslog(LOG_INFO, "connect: uid:%d gid:%d", euid, egid);

    /* set alarm (uncaught here) to enforce time limit on blocking syscalls */
    alarm(2);

    /* receive addrinfo from client */
    if (!(5 != argc
          ? bindsocket_recv_addrinfo(cfd, -1, &ai) /*(-1 for infinite poll)*/
          : strs_to_addrinfo(&ai,argv[0],argv[1],argv[2],argv[3],argv[4]))) {
        alarm(0); /* not strictly needed since callers exit upon return */
        syslog_perror("invalid client request", 0);
        return EXIT_FAILURE;
    }

    /* check client credentials to authorize client request,
     * bind socket, send socket fd to client (no poll since send only one msg)*/
    if (bindsocket_is_authorized_addrinfo(&ai, euid, egid)) {
        if (   0 <= (fd = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol))
            && 0 == setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&flag,sizeof(flag))
            && 0 == bind(fd, (struct sockaddr *)ai.ai_addr, ai.ai_addrlen))
            rc = unix_domain_send_fd(cfd, fd) ? EXIT_SUCCESS : EXIT_FAILURE;
        else
            syslog_perror("socket,setsockopt,bind", errno);

        retry_close(fd);/* not strictly needed since callers exit upon return */
    }

    alarm(0); /* not strictly needed since callers exit upon return */
    return rc;
}

static bool
setuid_stdinit (void)
{
    /* Note: not retrying upon interruption; any fail to init means exit fail */

    /* Clear the environment */
    static char *empty_env[] = { NULL };
    environ = empty_env;

    /* Unblock all signals (regardless of what was inherited from parent) */
    sigset_t sigset_empty;
    if (0 != sigemptyset(&sigset_empty)
        || sigprocmask(0 != SIG_SETMASK, &sigset_empty, (sigset_t *) NULL)) {
        syslog_perror("sigprocmask", errno);
        return false;
    }

    return true;
}

static volatile int bindsocket_children = 0;

/* bindsocket high and low watermarks for in-flight forked children.
 * If hiwat is exceeded, then wait num children falls to lowat before continuing
 * to accept new connections.  bindsocket expects to be very fast and seldom
 * called, so detection of any outstanding behavior should be escalated. */
#define BINDSOCKET_CHILD_HIWAT 16
#define BINDSOCKET_CHILD_LOWAT  8

static void  __attribute__((noinline)) __attribute__((cold))
bindsocket_wait_children (void)
{
    /* syslog() once every 10 secs while excess pending children condition */
    static time_t prior = 0;
    const time_t t = time(NULL);
    if (prior+10 < t) {
        prior = t;
        syslog(LOG_CRIT, "pending children (%d) > hi watermark (%d)",
               bindsocket_children, BINDSOCKET_CHILD_HIWAT);
    }

    /* bindsocket_children is 'volatile' */
    while (bindsocket_children > BINDSOCKET_CHILD_LOWAT)
        poll(NULL, 0, 100);
}

static void
daemon_sa_chld (int signum)
{
    pid_t pid;
    int remaining = bindsocket_children; /* bindsocket_children is 'volatile' */
    do { pid = waitpid(-1, NULL, WNOHANG);
    } while (pid > 0 ? --remaining > 0 : (-1 == pid && errno == EINTR));
    bindsocket_children = (-1 == pid && errno == ECHILD) ? 0 : remaining;
}

static void
daemon_sa_handler (int signum)
{
    exit(EXIT_SUCCESS);  /* executes atexit() handlers */
}

static bool
daemon_signal_init (void)
{
    /* configure signal handlers for bindsocket desired behaviors
     *   SIGALRM: default handler
     *   SIGCLD:  ignore
     *   SIGHUP:  clean up and exit (for now)
     *   SIGINT:  clean up and exit
     *   SIGTERM: clean up and exit
     */
    struct sigaction act;
    (void) sigemptyset(&act.sa_mask);

    act.sa_handler = SIG_DFL;
    act.sa_flags = 0;  /* omit SA_RESTART */
    if (sigaction(SIGALRM, &act, (struct sigaction *) NULL) != 0) {
        syslog_perror("sigaction", errno);
        return false;
    }

    act.sa_handler = daemon_sa_chld;
    act.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &act, (struct sigaction *) NULL) != 0) {
        syslog_perror("sigaction", errno);
        return false;
    }

    act.sa_handler = daemon_sa_handler;
    act.sa_flags = SA_RESTART;
    if (sigaction(SIGHUP, &act, (struct sigaction *) NULL) != 0) {
        syslog_perror("sigaction", errno);
        return false;
    }

    act.sa_handler = daemon_sa_handler;
    act.sa_flags = 0;  /* omit SA_RESTART */
    if (   sigaction(SIGINT,  &act, (struct sigaction *) NULL) != 0
        || sigaction(SIGTERM, &act, (struct sigaction *) NULL) != 0) {
        syslog_perror("sigaction", errno);
        return false;
    }

    return true;
}

static bool
daemon_init (const int supervised)
{
    /* Note: not retrying upon interruption; any fail to init means exit fail */

    /* Change current working dir to / for sane cwd and to limit mounts in use*/
    if (0 != chdir("/")) {
        syslog_perror("chdir /", errno);
        return false;
    }

    /* Detach from parent (process to be inherited by init) unless supervised */
    if (supervised) {
        if (setsid() == (pid_t)-1) {
            syslog_perror("setsid", errno);
            return false;
        }
    }
    else {
        pid_t pid;

        /* Ensure that SIGCHLD is not ignored (might be inherited from caller)*/
        struct sigaction act;
        (void) sigemptyset(&act.sa_mask);
        act.sa_handler = SIG_DFL;
        act.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &act, (struct sigaction *) NULL) != 0) {
            syslog_perror("sigaction", errno);
            return false;
        }

        if ((pid = fork()) != 0) {   /* parent */
            int status = EXIT_FAILURE;
            if (pid > 0 && waitpid(pid, &status, 0) != pid)
                status = EXIT_FAILURE;
            _exit(status);
        }                            /* child */
        else if ((pid = setsid()) == (pid_t)-1 || (pid = fork()) != 0) {
            if ((pid_t)-1 == pid) syslog_perror("setsid,fork", errno);
            _exit((pid_t)-1 == pid);
        }                            /* grandchild falls through */
    }

    /* Close unneeded file descriptors */
    /* (not closing all fds > STDERR_FILENO; lazy and we check root is caller)
     * (if closing all fds, must then closelog(); bindsocket_openlog()) */
    if (0 != retry_close(STDIN_FILENO))  return false;
    if (0 != retry_close(STDOUT_FILENO)) return false;
    if (!supervised) {
        if (0 != retry_close(STDERR_FILENO)) return false;
        syslog_perror_level = 1;
    }
    else {
        /* STDERR_FILENO must be open so it is not reused for sockets */
        struct stat st;
        if (0 != fstat(STDERR_FILENO, &st)) {
            syslog_perror("stat STDERR_FILENO", errno);
            return false;
        }
    }

    /* Configure signal handlers for bindsocket desired behaviors */
    if (!daemon_signal_init())
        return false;

    return true;
}

static int bindsocket_daemon_pid = -1;

static void
bindsocket_daemon_atexit (void)
{
    if (getpid() == bindsocket_daemon_pid)
        unlink(BINDSOCKET_SOCKET);
}

static int
bindsocket_daemon_init_socket (void)
{
    struct passwd *pw;
    struct stat st;
    int sfd;
    const uid_t euid = geteuid();
    mode_t mask;

    /* sanity check ownership and permissions on dir that will contain socket */
    /* (note: not checking entire tree above BINDSOCKET_SOCKET_DIR; TOC-TOU) */
    if (0 != stat(BINDSOCKET_SOCKET_DIR, &st)) {
        syslog_perror(BINDSOCKET_SOCKET_DIR, errno);
        return -1;
    }
    if (st.st_uid != euid || (st.st_mode & (S_IWGRP|S_IWOTH))) {
        syslog_perror("ownership/permissions incorrect on "
                      BINDSOCKET_SOCKET_DIR, 0);
        return -1;
    }

    mask = umask(0177); /* create socket with very restricted permissions */
    sfd = unix_domain_socket_bind_listen(BINDSOCKET_SOCKET);
    umask(mask);        /* restore prior umask */
    if (-1 == sfd)
        return -1;

    bindsocket_daemon_pid = getpid();
    atexit(bindsocket_daemon_atexit);

    if (NULL != (pw = getpwnam(BINDSOCKET_GROUP))
        && 0 == chown(BINDSOCKET_SOCKET, euid, pw->pw_gid)
        && 0 == chmod(BINDSOCKET_SOCKET, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP))
        return sfd;

    syslog_perror("getpwnam,chown,chmod", errno);
    return -1;
}

int
bindsocket_daemon_main (int argc, char *argv[])
{
    int sfd, cfd, daemon = false, supervised = false;

    /* setuid safety measures must be performed before anything else */
    if (!setuid_stdinit())
        return EXIT_FAILURE;

    /* openlog() for syslog() */
    bindsocket_openlog();

    /* parse arguments */
    optind = 1;
    while ((sfd = getopt(argc, argv, "dhF")) != -1) {
        switch (sfd) {
          case 'd': daemon = true; break;
          case 'F': supervised = true; break;
          default:  syslog(LOG_ERR, "bad arguments sent by uid %d", getuid());
                    fprintf(stderr, "\nerror: invalid arguments\n");/*fallthru*/
          case 'h': fprintf(stdout, "\n"
                            "  bindsocket -h\n"
                            "  bindsocket -d [-F]\n"
                            "  bindsocket <addr_family> <socktype> <protocol> "
                                        "<service_or_port> <addr>\n\n");
                    return (sfd == 'h' ? EXIT_SUCCESS : EXIT_FAILURE);
        }
    }

    /*
     * one-shot mode; handle single request and exit
     */

    if (!daemon) {
        struct stat st;
        if (0 != fstat(STDIN_FILENO, &st)) {
            syslog_perror("fstat stdin", errno);
            return EXIT_FAILURE;
        }
        if (S_ISSOCK(st.st_mode))
            return bindsocket_client_session(STDIN_FILENO,
                                             argc-optind, argv+optind);
        syslog_perror("invalid socket on bindsocket stdin", 0);
        return EXIT_FAILURE; /* STDIN_FILENO must be socket for one-shot mode */
    }

    /*
     * daemon mode
     */

    if (getuid() != geteuid()) {
        /* do not permit setuid privileges to initiate daemon mode */
        syslog_perror(BINDSOCKET_SYSLOG_IDENT
                      " daemon can not be started via setuid", 0);
        return EXIT_FAILURE;
    }

    if (!daemon_init(supervised))
        return EXIT_FAILURE;

    sfd = bindsocket_daemon_init_socket();
    if (-1 == sfd)
        return EXIT_FAILURE;

    /* daemon event loop
     * parent: accept and fork
     * child: close listen sfd, check credentials, bind socket, send sock fd
     * (Note: by virtue of daemon_init() which detaches from calling process,
     *  bindsocket has no child processes at this point.  (If supervised, then
     *  bindsocket started as root and bindsocket should not have any children))
     * (Note: technically, bindsocket_children increment should be made atomic)
     */
    bindsocket_children = 0;
    do {
        if (bindsocket_children > BINDSOCKET_CHILD_HIWAT)
            bindsocket_wait_children();
        if (-1 != (cfd = accept(sfd, NULL, NULL))) {
            ++bindsocket_children;
            if (0 == fork()) {
                retry_close(sfd);
                _exit(bindsocket_client_session(cfd, 0, NULL));
            }
            retry_close(cfd);
        }
        else if (errno != EINTR && errno != ECONNABORTED)
            break;
    } while (1);
    syslog_perror("accept", errno);
    return EXIT_FAILURE;
}




/* define _BSD_SOURCE prior to #include <grp.h> for prototype of setgroups() */
int setgroups(size_t size, const gid_t *list);

int
main (int argc, char *argv[])
{
    int sv[2];

    /* simple test: default is socketpair.  extra argc != 6 means daemon mode */

    if (1 == argc || 6 == argc) {
        if (0 != socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
            perror("socketpair");
            return EXIT_FAILURE;
        }
    }

    if (0 == fork()) {

        /* TESTING */

        if (0 == geteuid())
            setgroups(0, NULL);

        setgid(500);
        setuid(500);

        int sfd;
        if (1 == argc || 6 == argc) {
            retry_close(sv[0]);
            sfd = sv[1];
        }
        else {
            poll(NULL, 0, 100); /* give daemon a chance to start up */
            sfd = unix_domain_socket_connect(BINDSOCKET_SOCKET);
        }
        if (-1 == sfd)
            return EXIT_FAILURE;

        if (6 != argc) {
          #if 1
            struct sockaddr_in iaddr;
            struct addrinfo ai = {
              .ai_flags    = 0,
              .ai_family   = AF_INET,
              .ai_socktype = SOCK_STREAM,
              .ai_protocol = 6, /* TCP */
              .ai_addrlen  = sizeof(iaddr),
              .ai_addr     = (struct sockaddr *)&iaddr,
              .ai_canonname= NULL,
              .ai_next     = NULL
            };
            memset(&iaddr,'\0',sizeof(iaddr));/*init for deterministic compare*/
            /* config file test: gs AF_INET SOCK_STREAM tcp 8080 0.0.0.0 */
            iaddr.sin_family = AF_INET;
            iaddr.sin_port   = htons(8080);
            iaddr.sin_addr.s_addr = htonl(INADDR_ANY);
            if (!bindsocket_send_addrinfo(sfd, -1, &ai))
                return EXIT_FAILURE;
          #else
            const char * const msg = "AF_INET SOCK_STREAM tcp 8080 0.0.0.0";
            const size_t msglen = strlen(msg);
            if (msglen != send(sfd, msg, msglen, MSG_NOSIGNAL|MSG_DONTWAIT)) {
                syslog_perror("send", errno);
                return EXIT_FAILURE;
            }
          #endif
        }

        int fd = unix_domain_recv_fd(sfd);
        retry_close(sfd);
        fprintf(stderr, "received fd: %d\n", fd);
        /* document: caller should check sanity: fd >= 0 */
        /* document: caller should set F_CLOEXEC if desired, and then listen()*/

        return EXIT_SUCCESS;
    }
    else {
        if (1 == argc || 6 == argc) {
            dup2(sv[0], STDIN_FILENO);
            if (sv[0] != STDIN_FILENO) close(sv[0]);
            if (sv[1] != STDIN_FILENO) close(sv[1]);
            bindsocket_daemon_main(argc, argv);
        }
        else {
            char *args[] = { BINDSOCKET_SYSLOG_IDENT, "-d", "-F" };
            if (fork() != 0) _exit(0); /* testing 'supervise'd mode */
            bindsocket_daemon_main(3, args);
        }

        return EXIT_SUCCESS;
    }
}
