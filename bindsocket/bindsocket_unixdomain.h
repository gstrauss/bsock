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
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* bindsocket stack allocation for recvmsg() ancillary data
 * On Linux, maximum length of ancillary data and user control data is set in
 * /proc/sys/net/core/optmem_max (man 3 cmsg, man 7 socket); customarily 10240.
 * RFC 3542: Advanced Sockets Application Program Interface (API) for IPv6
 * RFC 3542 min ancillary data is 10240; recommends getsockopt SO_SNDBUF
 * (traditional BSD mbuf is 108, which is way too small for RFC 3542 spec)
 * The reason this setting is important is because (at least on Linux) a client
 * can send as many file descriptors as fit in msg_control buf.  Even if
 * recvmsg() reports MSG_CTRUNC, the file descriptors that the client sent are
 * still received (up to sysconf(_SC_OPEN_MAX)), resulting in leakage of file
 * descriptors unless process takes extra measures to close fds it does not know
 * about.  Such an undertaking is difficult to do correctly since process might
 * not know which fds have been opened by lower-level libraries, e.g. to syslog,
 * nscd, /etc/protocols, /etc/services, etc.  Setting this buffer size to the
 * maximum allowed means that MSG_CTRUNC should not be possible.  (Take care
 * if increasing size since buffer is allocated on stack (as of this writing))
 */
#ifndef BINDSOCKET_ANCILLARY_DATA_MAX
#define BINDSOCKET_ANCILLARY_DATA_MAX 10240
#endif

int
bindsocket_unixdomain_socket_connect (const char * const restrict sockpath);

int
bindsocket_unixdomain_socket_bind_listen (const char * const restrict sockpath);

ssize_t
bindsocket_unixdomain_recv_fds (const int fd, int * const restrict rfds,
                                unsigned int * const restrict nrfds,
                                struct iovec * const restrict iov,
                                const size_t iovlen);

ssize_t
bindsocket_unixdomain_send_fds (const int fd,
                                const int * const restrict sfds,
                                unsigned int * const restrict nsfds,
                                struct iovec * const restrict iov,
                                const size_t iovlen);

int
bindsocket_unixdomain_getpeereid (const int s, uid_t * const restrict euid,
                                  gid_t * const restrict egid);

#ifdef __cplusplus
}
#endif

#endif
