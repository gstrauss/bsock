/*
 * bindsocket_bind.c - interfaces to bind to reserved ports
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

#include <bindsocket_bind.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <unistd.h>

extern char **environ;

#include <bindsocket_unixdomain.h>

#ifndef BINDSOCKET_POLL_TIMEOUT
#define BINDSOCKET_POLL_TIMEOUT 5000  /*(poll timeout in millisecs)*/
#endif

#ifndef BINDSOCKET_EXE
#error "BINDSOCKET_EXE must be defined"
#endif
#ifndef BINDSOCKET_SOCKET_DIR
#error "BINDSOCKET_SOCKET_DIR must be defined"
#endif
#define BINDSOCKET_SOCKET BINDSOCKET_SOCKET_DIR "/socket"

/* nointr_close() - make effort to avoid leaking open file descriptors */
static int
nointr_close (const int fd)
{ int r; do { r = close(fd); } while (r != 0 && errno == EINTR); return r; }

static int
bindsocket_bind_send_addr_and_recv (const int fd,
                                    const struct addrinfo * const restrict ai,
                                    const int sfd)
{
    /* bindsocket_unixdomain_poll_recv_fd()
     *   fills errnum to indicate remote success/failure
     * (no poll before sending addrinfo since this is first write to socket)
     * (dup2 rfd to fd if rfd != -1; indicates persistent reserved addr,port) */
    int rfd = -1;
    int errnum = 0;
    struct iovec iov = { .iov_base = &errnum, .iov_len = sizeof(errnum) };
    if (bindsocket_unixdomain_send_addrinfo(sfd, ai, fd)
        && -1 != bindsocket_unixdomain_poll_recv_fd(sfd, &rfd, &iov, 1,
                                                    BINDSOCKET_POLL_TIMEOUT)) {
        if (-1 != rfd) {
            /* assert(rfd != fd); should not happen from ..._poll_recv_fd() */
            if (0 == errnum) {
                do { errnum = dup2(rfd,fd);
                } while (errnum == -1 && (errno == EINTR || errno == EBUSY));
                errnum = (errnum == fd) ? 0 : errno;
            }
            nointr_close(rfd);
        }
    }
    else
        errnum = errno;

    return errnum;
}

static bool
bindsocket_bind_viafork (const int fd,
                         const struct addrinfo * const restrict ai)
{
    /* (ai->ai_next is ignored) */
    int sv[2];
    int errnum;
    pid_t pid;
    struct stat st;

    if (0 != stat(BINDSOCKET_EXE, &st))
        return false;
    if (!(st.st_mode & S_ISUID))
        return (errno = EPERM, false);

    if (0 != socketpair(AF_UNIX, SOCK_STREAM, 0, sv))
        return false;

    pid = fork();         /*(bindsocket_bind_resvaddr() retries on EAGAIN)*/
    if (0 == pid) {       /* child; no retry if child signalled, errno==EINTR */
        static char *args[] = { BINDSOCKET_EXE, NULL };
        if (   dup2(sv[0], STDIN_FILENO) != STDIN_FILENO
            || (sv[0] != STDIN_FILENO && 0 != close(sv[0]))
            || (sv[1] != STDIN_FILENO && 0 != close(sv[1])))
            _exit(errno);
        fcntl(STDIN_FILENO, F_SETFD, 0);/* unset all fdflags, incl FD_CLOEXEC */
        execve(args[0], args, environ);
        _exit(errno); /*(not reached unless execve() failed)*/
    }
    else if (-1 != pid) { /* parent */
        nointr_close(sv[0]);
        errnum = bindsocket_bind_send_addr_and_recv(fd, ai, sv[1]);
        while (pid != waitpid(pid,NULL,0) && errno == EINTR) ;
        /* reap child process but ignore exit status; program might be ignoring
         * SIGCHLD or might have custom SIGCHLD handler, either of which would
         * prevent waitpid() above from reliably obtaining child status */
    }
    else {                /* fork() error */
        errnum = errno;
        nointr_close(sv[0]);
    }

    nointr_close(sv[1]);
    errno = errnum;
    return (0 == errnum);
}

static bool
bindsocket_bind_viasock (const int fd,
                         const struct addrinfo * const restrict ai)
{
    int errnum;
    int sfd;

    do {
        sfd = bindsocket_unixdomain_socket_connect(BINDSOCKET_SOCKET);
        if (-1 == sfd)
            return false;
        errnum = bindsocket_bind_send_addr_and_recv(fd, ai, sfd);
        nointr_close(sfd);
    } while (errnum == EAGAIN && 0 == poll(NULL, 0, 1));
    errno = errnum;
    return (0 == errnum);
}

int
bindsocket_bind_resvaddr (const int fd,
                          const struct addrinfo * const restrict ai)
{
    /* (bindresvaddr name similar to bindresvport(), but similarities end there)
     * (return value 0 for success, -1 upon error; match return value of bind())
     * (ai->ai_next is ignored) */

    if (bindsocket_bind_viasock(fd, ai) || bindsocket_bind_viafork(fd, ai))
        return 0;

    switch (errno) {
      default: errno = EACCES; /*FALLTHRU*/
      case EACCES: case EADDRINUSE: case EBADF: case EINVAL: case ENOTSOCK:
               return -1;
    }
}

static int (*bind_rtld_next)(int, const struct sockaddr *, socklen_t);
static int
bind_rtld_findnext (int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    bind_rtld_next = (int(*)(int,const struct sockaddr *,socklen_t))(uintptr_t)
      dlsym((void *)-1L, "bind"); /* RTLD_NEXT=(void *)-1L is glibc extension */
    return (NULL != bind_rtld_next)
      ? bind_rtld_next(sockfd, addr, addrlen)
      : (bind_rtld_next = bind_rtld_findnext, errno = ENOSYS, -1);
}
static int (*bind_rtld_next)(int, const struct sockaddr *, socklen_t) =
  bind_rtld_findnext;

int
bindsocket_bind_intercept (int sockfd, const struct sockaddr *addr,
                           socklen_t addrlen)
{
    struct addrinfo ai = {
      .ai_flags    = 0,
      .ai_family   = addr->sa_family,
      .ai_socktype = 0,
      .ai_protocol = 0,
      .ai_addrlen  = addrlen,
      .ai_addr     = (struct sockaddr *)(uintptr_t)addr,
      .ai_canonname= NULL,
      .ai_next     = NULL
    };
    socklen_t optlen;

    /* bindsocket supports only AF_INET, AF_INET6, AF_UNIX;
     * simply bind if address family is otherwise */
    if (ai.ai_family == AF_INET || ai.ai_family == AF_INET6) {
        /* simply bind if port < IPPORT_RESERVED; no root privileges needed */
        const short int port = (ai.ai_family == AF_INET)
          ? ntohs(((struct sockaddr_in  *)ai.ai_addr)->sin_port)
          : ntohs(((struct sockaddr_in6 *)ai.ai_addr)->sin6_port);
        if (port >= IPPORT_RESERVED)
            return bind_rtld_next(sockfd, ai.ai_addr, ai.ai_addrlen);
      #if 0 /* getnameinfo() is overkill for simple port check */
        char host[INET6_ADDRSTRLEN];
        char port[6];
        switch (getnameinfo(ai.ai_addr, ai.ai_addrlen, host, sizeof(host),
                            port, sizeof(port), NI_NUMERICHOST|NI_NUMERICSERV)){
          case 0: if (atoi(port) < IPPORT_RESERVED) break;
                  else return bind_rtld_next(sockfd, ai.ai_addr, ai.ai_addrlen);
          case default:    errno = EINVAL; return -1;
          case EAI_MEMORY: errno = ENOMEM; return -1;
          case EAI_SYSTEM:                 return -1;
        }
      #endif
    }
    else if (ai.ai_family != AF_UNIX)
        return bind_rtld_next(sockfd, ai.ai_addr, ai.ai_addrlen);

    if (0 == geteuid())
        return bind_rtld_next(sockfd, ai.ai_addr, ai.ai_addrlen);

    optlen = sizeof(ai.ai_socktype);
    if (-1 == getsockopt(sockfd,SOL_SOCKET,SO_TYPE,&ai.ai_socktype,&optlen))
        return -1;
  #ifdef SO_PROTOCOL
    optlen = sizeof(ai.ai_protocol);
    if (-1 == getsockopt(sockfd,SOL_SOCKET,SO_PROTOCOL,&ai.ai_socktype,&optlen))
        return -1;
  #else
    /* else pass ai_protocol == 0, which will typically work as expected (tcp)
     * since bindsocket calls getaddrinfo() and uses first entry returned */
  #endif

    return bindsocket_bind_resvaddr(sockfd, &ai);
}
