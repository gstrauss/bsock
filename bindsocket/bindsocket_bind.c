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
     * (close rfd unconditionally since expecting rfd == -1 and there
     *  is no provision made to return rfd to caller in current usage) */
    int rfd = -1;
    int errnum = 0;
    struct iovec iov = { .iov_base = &errnum, .iov_len = sizeof(errnum) };
    if (bindsocket_unixdomain_send_addrinfo(sfd, ai, fd)
        && -1 != bindsocket_unixdomain_poll_recv_fd(sfd, &rfd, &iov, 1,
                                                    BINDSOCKET_POLL_TIMEOUT)) {
        if (-1 != rfd) nointr_close(rfd);
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

    pid = fork();/*(not retrying fork on EAGAIN; ?add counter, limited retry?)*/
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
    const int sfd = bindsocket_unixdomain_socket_connect(BINDSOCKET_SOCKET);
    if (-1 == sfd)
        return false;

    errnum = bindsocket_bind_send_addr_and_recv(fd, ai, sfd);
    nointr_close(sfd);
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
    return (bindsocket_bind_viasock(fd, ai) || bindsocket_bind_viafork(fd, ai))
      ? 0
      : -1;
}
