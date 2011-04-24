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

#ifndef INCLUDED_BINDSOCKET_UNIXDOMAIN_H
#define INCLUDED_BINDSOCKET_UNIXDOMAIN_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* sample client code */
int
bindsocket_unixdomain_socket_connect (const char * const restrict sockpath);

int
bindsocket_unixdomain_socket_bind_listen (const char * const restrict sockpath);

ssize_t
bindsocket_unixdomain_recv_fd (const int fd, int * const restrict rfd,
                               struct iovec * const restrict iov,
                               const size_t iovlen);

ssize_t
bindsocket_unixdomain_send_fd (const int fd, const int sfd,
                               struct iovec * const restrict iov,
                               const size_t iovlen);

bool
bindsocket_unixdomain_recv_addrinfo (const int fd, const int msec,
                                     struct addrinfo * const restrict ai,
                                     int * const restrict rfd);

/* sample client code corresponding to bindsocket_unixdomain_recv_addrinfo() */
bool
bindsocket_unixdomain_send_addrinfo (const int fd, const int msec,
                                     struct addrinfo * const restrict ai,
                                     const int sfd);

int
bindsocket_unixdomain_getpeereid (const int s, uid_t * const restrict euid,
                                  gid_t * const restrict egid);

#if 0   /* sample code */
ssize_t
bindsocket_unixdomain_recvmsg (const int fd,
                               struct iovec * const restrict iov,
                               const size_t iovlen);

ssize_t
bindsocket_unixdomain_sendmsg (const int fd,
                               struct iovec * const restrict iov,
                               const size_t iovlen);
#endif  /* sample code */

#ifdef __cplusplus
}
#endif

#endif
