/*
 * bsock_unix - unix domain socket sendmsg and recvmsg wrappers
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

/* (module contains both client and server code)
 * (code could be split into separate .c files, but keep together for brevity)*/

#include <bsock_unix.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#ifdef __linux__
#ifndef SO_PEERCRED
#if __has_include(<asm-generic/socket.h>) /* or define _DEFAULT_SOURCE */
#include <asm-generic/socket.h> /* SO_PEERCRED */
#endif
#endif
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

#if defined(__APPLE__) && defined(__MACH__)  /*(or define _DARWIN_C_SOURCE)*/
#ifndef CMSG_SPACE
#define	CMSG_SPACE(l)		(__DARWIN_ALIGN32(sizeof(struct cmsghdr)) + __DARWIN_ALIGN32(l))
#endif
#ifndef CMSG_LEN
#define	CMSG_LEN(l)		(__DARWIN_ALIGN32(sizeof(struct cmsghdr)) + (l))
#endif
#endif

/* nointr_close() - make effort to avoid leaking open file descriptors */
static int
nointr_close (const int fd)
{ int r; retry_eintr_do_while(r = close(fd), r != 0); return r; }

__attribute_nonnull__()
int
bsock_unix_socket_connect (const char * const restrict sockpath)
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
        const int errnum = errno;
        nointr_close(fd);
        errno = errnum;
    }
    return -1;
}

__attribute_nonnull__()
int
bsock_unix_socket_bind_listen (const char * const restrict sockpath,
                               int * const restrict bound)
{
    /* bind and listen to unix domain socket */
    /* (not bothering to retry bind() and listen() if EINTR; lazy) */
    /* (nointr_close to avoid fd resource leak) */
    /* (no setsockopt SO_REUSEADDR; AF_UNIX sockets have no TIME_WAIT state)
     * ('man netstat' on Linux; XXX: ?AF_UNIX TIME_WAIT on other OS? prob not)*/
    /* N.B. caller must create dir for sockpath with restricted permissions and
     *      caller must set umask so socket created with desired permissions */
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
        && 0 == (*bound = bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)))
        && 0 == listen(fd, SOMAXCONN))
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
        && 0 == (*bound = bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)))
        && 0 == listen(fd, SOMAXCONN))
        return fd;

    if (-1 != fd) {
        const int errnum = errno;
        nointr_close(fd);
        errno = errnum;
    }
    return -1;
}

__attribute_nonnull__((1))
static void
bsock_unix_recv_ancillary (struct msghdr * const restrict msg,
                           int * const restrict rfds,
                           unsigned int * const restrict nrfdsp)
{
    struct cmsghdr *cmsg;
    unsigned int nrfd = 0;
    const unsigned int nrfds = nrfdsp != NULL ? *nrfdsp : 0;

    /* recvmsg() can receive multiple fds even if MSG_CTRUNC (ctrlbuf too small)
     * recvmsg() can receive int array of fds and/or multiple cmsgs with fds
     * (defensive client must handle multiple fds received unexpectedly)
     * (defensive client might setsockopt SO_PASSCRED, check SCM_CREDENTIALS) */

    for (cmsg = CMSG_FIRSTHDR(msg); NULL != cmsg; cmsg = CMSG_NXTHDR(msg,cmsg)){
        if (cmsg->cmsg_type == SCM_RIGHTS && cmsg->cmsg_level == SOL_SOCKET) {
            const int * const restrict fds = (int *)CMSG_DATA(cmsg);
            const unsigned int nfds = (cmsg->cmsg_len-CMSG_LEN(0))/sizeof(int);
            unsigned int nfd = nrfds - nrfd;
            if (0 !=nfd) {
                if (nfd > nfds)
                    nfd = nfds;
                memcpy(rfds+nrfd, fds, nfd*sizeof(int));
                nrfd += nfd;
            }
            while (nfd < nfds)
                nointr_close(fds[nfd++]);  /* close excess fds received */
        }
    }

    if (nrfdsp != NULL)
        *nrfdsp = nrfd;
}

__attribute_noinline__
__attribute_nonnull__((4))
static ssize_t
bsock_unix_recv_fds_msghdr (const int fd,
                            int * const restrict rfds,
                            unsigned int * const restrict nrfds,
                            struct msghdr * const restrict msg)
{
    /* receive and return file descriptor(s) sent over unix domain socket */
    /* 'man cmsg' provides example code */
    ssize_t r;
    retry_eintr_do_while(r = recvmsg(fd, msg, MSG_DONTWAIT), -1 == r);
    if (r < 1) {  /* EOF (r=0) or error (r=-1) */
        if (0 == r && 0 == errno) errno = EPIPE;
        return -1;
    }

    /*(MSG_TRUNC should not happen on stream-based (SOCK_STREAM) socket)*/
    /*(MSG_CTRUNC should not happen if ctrlbuf >= socket max ancillary data)*/
    /*(syslog() here; no dependency on bsock_syslog.h)*/
    if (msg->msg_flags & MSG_CTRUNC)
        syslog(LOG_CRIT, "recvmsg(%d) msg_flags MSG_CTRUNC unexpected", fd);

    bsock_unix_recv_ancillary(msg, rfds, nrfds);

    return r;
}

__attribute_nonnull__((4))
ssize_t
bsock_unix_recv_fds (const int fd,
                     int * const restrict rfds,
                     unsigned int * const restrict nrfds,
                     struct iovec * const restrict iov,
                     const size_t iovlen)
{
    /* receive and return file descriptor(s) sent over unix domain socket */
    /* 'man cmsg' provides example code */
    char ctrlbuf[BSOCK_ANCILLARY_DATA_MAX];
    struct msghdr msg = {
      .msg_name       = NULL,
      .msg_namelen    = 0,
      .msg_iov        = iov,
      .msg_iovlen     = iovlen,
      .msg_control    = ctrlbuf,
      .msg_controllen = sizeof(ctrlbuf),
      .msg_flags      = 0
    };
    return bsock_unix_recv_fds_msghdr(fd, rfds, nrfds, &msg);
}

__attribute_nonnull__((4,6))
ssize_t
bsock_unix_recv_fds_ex (const int fd,
                        int * const restrict rfds,
                        unsigned int * const restrict nrfds,
                        struct iovec * const restrict iov,
                        const size_t iovlen,
                        char * const restrict ctrlbuf,
                        const size_t ctrlbuf_sz)
{
    /* receive and return file descriptor(s) sent over unix domain socket */
    /* 'man cmsg' provides example code */
    struct msghdr msg = {
      .msg_name       = NULL,
      .msg_namelen    = 0,
      .msg_iov        = iov,
      .msg_iovlen     = iovlen,
      .msg_control    = ctrlbuf,
      .msg_controllen = ctrlbuf_sz,
      .msg_flags      = 0
    };
    return bsock_unix_recv_fds_msghdr(fd, rfds, nrfds, &msg);
}

__attribute_nonnull__((4))
ssize_t
bsock_unix_send_fds (const int fd,
                     const int * const restrict sfds,
                     unsigned int nsfds,
                     struct iovec * const restrict iov,
                     const size_t iovlen)
{
    /* send iov msg and (optional) file descriptor(s) over unix domain socket */
    /* pass any non-zero-length data so client can distinguish msg from EOF
     * (caller must provide iov array with iov[0].iov_len != 0 to pass fds) */
    /* 'man cmsg' provides sample code */
    /*(caller might first poll() POLLOUT since nonblocking sendmsg() employed)*/
    /*(caller should handle EAGAIN and EWOULDBLOCK) */
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

    char ctrlbuf[CMSG_SPACE((nsfds*=sizeof(int))+4)]; /*(+4 ensures not 0-len)*/
    if (0 != nsfds) {  /*(fill control msg (cmsg) if fds to send)*/
        struct cmsghdr * restrict cmsg;
        msg.msg_control    = ctrlbuf;
        msg.msg_controllen = sizeof(ctrlbuf);
        cmsg = CMSG_FIRSTHDR(&msg);
        memcpy(CMSG_DATA(cmsg), sfds, nsfds);
        cmsg->cmsg_level   = SOL_SOCKET;
        cmsg->cmsg_type    = SCM_RIGHTS;
        cmsg->cmsg_len     = msg.msg_controllen = CMSG_LEN(nsfds); /*data*/
    }

    retry_eintr_do_while(w=sendmsg(fd,&msg,MSG_DONTWAIT|MSG_NOSIGNAL), -1 == w);
    return w;
    /* (caller might choose not to report errno==EPIPE or errno==ECONNRESET) */
}

#ifdef __linux__
/* obtain peer credentials
 * (requires Linux getsockopt SO_PEERCRED or BSD-style getpeereid() support) */
__attribute_nonnull__()
static inline int
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
__attribute_nonnull__()
static inline int
getpeereid(const int s,uid_t * const restrict euid,gid_t * const restrict egid)
{
    ucred_t *ucred;
    if (0 != getpeerucred(s, &ucred))
        return -1;
    *euid = ucred_geteuid(ucred);
    *egid = ucred_getegid(ucred);
    ucred_free(ucred);
    return (*euid != -1 && *egid != -1) ? 0 : -1;
}
#endif

#ifdef _AIX
int getpeereid (int, uid_t * __restrict__, gid_t * __restrict__);
#endif

#if defined(__APPLE__) && defined(__MACH__)  /*(or define _DARWIN_C_SOURCE)*/
int getpeereid (int, uid_t * __restrict__, gid_t * __restrict__);
#endif

#ifndef __hpux
__attribute_nonnull__()
int
bsock_unix_getpeereid (const int s,
                       uid_t * const restrict euid,
                       gid_t * const restrict egid)
{
    return getpeereid(s, euid, egid);
}
#else  /* unsupported on HP-UX */
__attribute_nonnull__()
int
bsock_unix_getpeereid (const int s  __attribute_unused__,
                       uid_t * const restrict euid  __attribute_unused__,
                       gid_t * const restrict egid  __attribute_unused__)
{
    return -1;  /* unsupported on HP-UX */
}
#endif


#if 0 /* sample code */
__attribute_nonnull__()
ssize_t
bsock_unix_recvmsg (const int fd,
                    struct iovec * const restrict iov,
                    const size_t iovlen)
{
    /* (nonblocking recvmsg(); caller might poll() before call to here)*/
    return bsock_unix_recv_fds(fd, NULL, NULL, iov, iovlen);
}

__attribute_nonnull__()
ssize_t
bsock_unix_sendmsg (const int fd,
                    struct iovec * const restrict iov,
                    const size_t iovlen)
{
    /* (nonblocking sendmsg(); caller might poll() before call to here)*/
    return bsock_unix_send_fds(fd, NULL, 0, iov, iovlen);
}
#endif
