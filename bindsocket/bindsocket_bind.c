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
#include <unistd.h>

extern char **environ;

#include <bindsocket_unixdomain.h>

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
bindsocket_bind_viafork (const int fd,
                         const struct addrinfo * const restrict ai)
{
    /* (ai->ai_next is ignored) */
    pid_t pid;
    const int ms = 5000; /*(poll timeout in millisecs)*/
    int sv[2];
    int errnum = 0;
    struct iovec iov = { .iov_base = &errnum, .iov_len = sizeof(errnum) };
    struct stat st;
    char *args[] = { BINDSOCKET_EXE, NULL };

    if (0 != stat(BINDSOCKET_EXE, &st))
        return -1;
    if (!(st.st_mode & S_ISUID))
        return (errno = EPERM, -1);

    if (0 != socketpair(AF_UNIX, SOCK_STREAM, 0, sv))
        return -1;

    pid = fork();/*(not retrying fork on EAGAIN; ?add counter, limited retry?)*/
    if (0 == pid) {       /* child; no retry if child signalled, errno==EINTR */
        if (dup2(sv[0], STDIN_FILENO) != STDIN_FILENO)
            _exit(errno);
        if (sv[0] != STDIN_FILENO) close(sv[0]);
        if (sv[1] != STDIN_FILENO) close(sv[1]);
        fcntl(STDIN_FILENO, F_SETFD, 0);/* unset all fdflags, incl FD_CLOEXEC */
        execve(args[0], args, environ);
        _exit(errno); /*(not reached unless execve() failed)*/
    }
    else if (-1 != pid) { /* parent */
        nointr_close(sv[0]);  /* see comments in bindsocket_bind_resvaddr() */
        if (!bindsocket_unixdomain_send_addrinfo(sv[1], ai, fd)
            || (-1==bindsocket_unixdomain_poll_recv_fd(sv[1],&sv[0],&iov,1,ms)))
            errnum = errno;
        while (pid != waitpid(pid, NULL, 0) && errno==EINTR) ;/*ignore exit rc*/
    }
    else                  /* fork() error */
        errnum = errno;

    if (-1 != sv[0]) nointr_close(sv[0]);
    if (-1 != sv[1]) nointr_close(sv[1]);
    errno = errnum;
    return (0 == errnum) ? 0 : -1;
}

int
bindsocket_bind_resvaddr (const int fd,
                          const struct addrinfo * const restrict ai)
{
    /* (bindresvaddr name is similar to bindresvport(),
     *  but similarities end there)
     * (ai->ai_next is ignored) */

    int rfd = -1;
    int errnum = 0;
    struct iovec iov = { .iov_base = &errnum, .iov_len = sizeof(errnum) };
    const int ms = 5000; /*(poll timeout in millisecs)*/
    const int sfd = bindsocket_unixdomain_socket_connect(BINDSOCKET_SOCKET);
    if (-1 == sfd)
        return bindsocket_bind_viafork(fd, ai);

    /* bindsocket_unixdomain_poll_recv_fd()
     *   fills errnum to indicate remote success/failure
     *   (else manually set errnum (upon failure to retrieve remote status))
     * (no poll before sending addrinfo since this is first write to socket) */
    if (!bindsocket_unixdomain_send_addrinfo(sfd, ai, fd)
        || (-1 == bindsocket_unixdomain_poll_recv_fd(sfd, &rfd, &iov, 1, ms)))
        errnum = errno;

    nointr_close(sfd);
    if (-1 != rfd)
        nointr_close(rfd);

    errno = errnum;

    return (0 == errnum) ? 0 : -1;
}
