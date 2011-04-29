/*
 * bindsocket.t.c - sample client code to obtain sockets from bindsocket daemon
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bindsocket_unixdomain.h>

#ifndef BINDSOCKET_SOCKET_DIR
#error "BINDSOCKET_SOCKET_DIR must be defined"
#endif
#define BINDSOCKET_SOCKET BINDSOCKET_SOCKET_DIR "/socket"

extern char **environ;

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
        if (1 == argc || 6 == argc) {
            dup2(sv[0], STDIN_FILENO);
            if (sv[0] != STDIN_FILENO) close(sv[0]);
            if (sv[1] != STDIN_FILENO) close(sv[1]);
            argv[0] = "./bindsocket";
            execve(argv[0], argv, environ);
        }
        else {
            /* supervise'd (-F) to stay in foreground and show stderr */
            char *args[] = { "./bindsocket", "-d", "-F" };
            execve(args[0], args, environ);
        }

        return EXIT_FAILURE; /* notreached; execve() failed */
    }

    /* TESTING */

    if (0 == geteuid())
        setgroups(0, NULL);

    setgid(500);
    setuid(500);

    int sfd;
    int nfd = -1;
    if (1 == argc || 6 == argc) {
        while (0 != close(sv[0]) && errno == EINTR) ;/*similar to nointr_close*/
        sfd = sv[1];
    }
    else {
        poll(NULL, 0, 100); /* give daemon a chance to start up */
        sfd = bindsocket_unixdomain_socket_connect(BINDSOCKET_SOCKET);
        if (-1 == sfd) {
            perror("bindsocket_unixdomain_socket_connect "BINDSOCKET_SOCKET);
            return EXIT_FAILURE;
        }
    }

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
       #if 1  /* test sending socket created by client */
        nfd = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol);
       #endif
        if (!bindsocket_unixdomain_send_addrinfo(sfd, &ai, nfd)) {
            perror("bindsocket_unixdomain_send_addrinfo");
            return EXIT_FAILURE;
        }
      #else
        const char * const msg = "AF_INET SOCK_STREAM tcp 8080 0.0.0.0";
        const size_t msglen = strlen(msg);
        if (msglen != send(sfd, msg, msglen, MSG_NOSIGNAL|MSG_DONTWAIT)) {
            perror("send");
            return EXIT_FAILURE;
        }
      #endif
    }

    int fd = -1;
    int errnum = EXIT_FAILURE;
    struct iovec iov = { .iov_base = &errnum, .iov_len = sizeof(errnum) };
    if (-1 == bindsocket_unixdomain_poll_recv_fd(sfd, &fd, &iov, 1, -1)
        || (errno = errnum) != 0)
        perror("bindsocket_unixdomain_recv_fd");
    while (0 != close(sfd) && errno == EINTR) ; /* similar to nointr_close() */
    fprintf(stderr, "sent fd: %d; received fd: %d\n", nfd, fd);
    /* document: caller should check sanity: fd >= 0 */
    /* document: caller should set F_CLOEXEC if desired, and then listen()*/

    return errnum;
}
