/*
 * bindsocket_unixdomain - unix domain socket sendmsg and recvmsg wrappers
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

/* Note: module contains both client and server code for bindsocket protocol
 * (code could be split into separate .c files, but keep together for brevity)*/

#include <bindsocket_unixdomain.h>
#include <bindsocket_addrinfo.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <netdb.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#ifndef POLLRDHUP
#define POLLRDHUP 0
#endif

/* nointr_close() - make effort to avoid leaking open file descriptors */
static int
nointr_close (const int fd)
{ int r; do { r = close(fd); } while (r != 0 && errno == EINTR); return r; }

static int
retry_poll_fd (const int fd, const short events, const int timeout)
{
    struct pollfd pfd = { .fd = fd, .events = events, .revents = 0 };
    int n; /*EINTR results in retrying poll with same timeout again and again*/
    do { n = poll(&pfd, 1, timeout); } while (-1 == n && errno == EINTR);
    return n;
}

/* sample client code */
int
bindsocket_unixdomain_socket_connect (const char * const restrict sockpath)
{
    /* connect to unix domain socket */
    /* (not bothering to retry socket() and connect(); lazy) */
    /* (nointr_close to avoid fd resource leak) */
    /* (blocking connect(); not doing O_NONBLOCK socket and poll() for write */
    struct sockaddr_un saddr;
    const size_t len = strlen(sockpath);
    int fd;
    if (len >= sizeof(saddr.sun_path)) {
        errno = EINVAL;
        return -1;
    }
    saddr.sun_family = AF_UNIX;
    memcpy(saddr.sun_path, sockpath, len+1);
    if (  -1 != (fd = socket(AF_UNIX, SOCK_STREAM, 0))
        && 0 == connect(fd, (struct sockaddr *)&saddr, sizeof(saddr)))
        return fd;

    if (-1 != fd) {
        int errnum = errno;
        nointr_close(fd);
        errno = errnum;
    }
    return -1;
}

int
bindsocket_unixdomain_socket_bind_listen (const char * const restrict sockpath)
{
    /* bind and listen to unix domain socket */
    /* (not bothering to retry bind() and listen(); lazy) */
    /* (nointr_close to avoid fd resource leak) */
    /* N.B. caller must create dir for sockpath with restricted permissions &
     *      caller must set umask so socket created with desired permissions*/
    struct sockaddr_un saddr;
    const size_t len = strlen(sockpath);
    int fd, flags;
    if (len >= sizeof(saddr.sun_path)) {
        errno = EINVAL;
        return -1;
    }
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
        && 0 == nointr_close(fd)
        &&-1 != (fd = socket(AF_UNIX, SOCK_STREAM, 0))
        && 0 == bind(fd, (struct sockaddr *)&saddr, sizeof(saddr))
        && 0 == listen(fd, 4))      /* (arbitrary listen backlog of 4) */
        return fd;

    if (-1 != fd) {
        int errnum = errno;
        nointr_close(fd);
        errno = errnum;
    }
    return -1;
}

ssize_t
bindsocket_unixdomain_recvmsg (const int fd,
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
    if (r < 1)  /* EOF (r=0) or error (r=-1) */
        return r;

    /*(MSG_TRUNC should not happen on stream-based (SOCK_STREAM) socket)*/
    /*(MSG_CTRUNC is unexpected in bindsocket and is notable error/attack)*/
    /* N.B. since bindsocket_client_session() handled in short-lived child
     * fork()ed from parent daemon and will exit soon, simply syslog.
     * Alternatively, daemon could closelog(), close fds > STDERR_FILENO,
     * and then repeat call to openlog() */
    if (msg.msg_flags & MSG_CTRUNC)
        syslog(LOG_ERR, "recvmsg msg_flags MSG_CTRUNC unexpected");

    errno = 0; /* returning -1 with errno == 0 means no fd received */

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
                nointr_close(fds[n]);
        }
    }

    return r;
}

/* sample client code */
ssize_t
bindsocket_unixdomain_sendmsg (const int fd,
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
    return w;
    /* (caller might choose not to report errno==EPIPE or errno==ECONNRESET) */
}

/* sample client code corresponding to bindsocket_unixdomain_send_fd() */
int
bindsocket_unixdomain_recv_fd (const int fd)
{
    /* receive and return file descriptor sent over unix domain socket */
    /* 'man cmsg' provides example code */
    ssize_t r;
    char iovbuf[4];/*match iovbuf data size in bindsocket_unixdomain_send_fd()*/
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
    do { r = recvmsg(fd, &msg, MSG_DONTWAIT); } while (-1==r && errno==EINTR);
    if (r < 1) {  /* EOF (r=0) or error (r=-1) */
        if (0 == r && 0 == errno) errno = EPIPE;
        return -1;
    }

    /*(MSG_TRUNC should not happen on stream-based (SOCK_STREAM) socket)*/
    /*(MSG_CTRUNC is unexpected from bindsocket daemon; notable error/attack)*/
    if (msg.msg_flags & MSG_CTRUNC)
        syslog(LOG_ERR, "recvmsg msg_flags MSG_CTRUNC unexpected");

    errno = 0; /* returning -1 with errno == 0 means no fd received */

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
                    nointr_close(fds[n]);
            }
        }
    }
    return rfd;
}

bool
bindsocket_unixdomain_send_fd (const int cfd, const int fd)
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
    /* avoid gcc warning: dereferencing type-punned pointer ... */
    /*  *(int *)CMSG_DATA(cmsg) = fd; */
    int * const fds = (int *)CMSG_DATA(cmsg); fds[0] = fd;
    cmsg->cmsg_level       = SOL_SOCKET;
    cmsg->cmsg_type        = SCM_RIGHTS;
    cmsg->cmsg_len         = msg.msg_controllen = CMSG_LEN(sizeof(int));/*data*/
    do { w = sendmsg(cfd, &msg, MSG_DONTWAIT|MSG_NOSIGNAL);
    } while (-1 == w && errno == EINTR);
    return (-1 != w);
    /* (caller might choose not to report errno==EPIPE or errno==ECONNRESET) */
}

bool
bindsocket_unixdomain_recv_addrinfo (const int fd, const int msec,
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
    errno = 0;
    if (1 != retry_poll_fd(fd, POLLIN|POLLRDHUP, msec)) return false;
    ssize_t r =
      bindsocket_unixdomain_recvmsg(fd, iov, sizeof(iov)/sizeof(struct iovec));
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

        if (bindsocket_addrinfo_split_str(line, &family, &socktype, &protocol,
                                          &service, &addr))
            return bindsocket_addrinfo_from_strs(ai, family, socktype,
                                                 protocol, service, addr);

        return false;  /* invalid client request; truncated msg */
    }

    return false;
}

/* sample client code corresponding to bindsocket_unixdomain_recv_addrinfo() */
bool
bindsocket_unixdomain_send_addrinfo (const int fd, const int msec,
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
    errno = 0;
    if (1 != retry_poll_fd(fd, POLLOUT, msec)) return false;
    ssize_t w =
      bindsocket_unixdomain_sendmsg(fd, iov, sizeof(iov)/sizeof(struct iovec));
    return w == (sizeof(protover) + sizeof(struct addrinfo) + ai->ai_addrlen);
    /* (caller might choose not to report errno==EPIPE or errno==ECONNRESET) */
}
/* sample client code corresponding to bindsocket_unixdomain_recv_addrinfo() */
#if 0 /* sample client code sending an addrinfo string (structured precisely) */
    const char * const msg = "AF_INET SOCK_STREAM tcp 80 0.0.0.0";
    const size_t msglen = strlen(msg);
    if (msglen == send(sfd, msg, msglen, MSG_NOSIGNAL|MSG_DONTWAIT))
        return true;
    perror("send");
    return false;
#endif

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

int
bindsocket_unixdomain_getpeereid (const int s, uid_t * const restrict euid,
                                  gid_t * const restrict egid)
{
    return getpeereid(s, euid, egid);
}
