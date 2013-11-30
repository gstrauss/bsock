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

#ifndef INCLUDED_BSOCK_UNIX_H
#define INCLUDED_BSOCK_UNIX_H

#include "plasma/plasma_attr.h"

#include <sys/types.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* bsock stack allocation for recvmsg() ancillary data
 * On Linux, maximum length of ancillary data and user control data is set in
 * /proc/sys/net/core/optmem_max (man 3 cmsg, man 7 socket); customarily 10240.
 * RFC 3542: Advanced Sockets Application Program Interface (API) for IPv6
 * RFC 3542 min ancillary data is 10240; recommends getsockopt SO_SNDBUF
 * (traditional BSD mbuf is 108, which is way too small for RFC 3542 spec)
 *
 * The reason this setting is important is because a client can send many file
 * descriptors.  On Linux, even if recvmsg() reports MSG_CTRUNC, the file
 * descriptors that the client sent are still received by the server process
 * (up to sysconf(_SC_OPEN_MAX)), resulting in leakage of file descriptors
 * unless process takes extra measures to close fds it does not know about.
 * Such an undertaking is difficult to do correctly since process might not
 * know which fds have been opened by lower-level libraries, e.g. to syslog,
 * nscd, /etc/protocols, /etc/services, etc.  Setting this buffer size to the
 * maximum allowed means that MSG_CTRUNC should not be possible.  (Take care
 * if increasing size since buffer is allocated on stack (as of this writing.)
 * On Linux, client can send the same descriptor many times and it will be
 * dup'd and received many times by server.  On Linux, there appears to be a
 * maximum of 255 file descriptors that can be sent with sendmsg() over unix
 * domain sockets, whether in one or many separate ancillary control buffers.
 * On Linux, these ancillary control buffers appear to be independent of
 * SO_RCVBUF and SO_SNDBUF sizes of either client or server; limiting size of
 * SO_RCVBUF and SO_SNDBUF has no effect on size of ancillary control buffers.
 * In any case, allocating /proc/sys/net/core/optmem_max for ancillary control
 * buffers prevents the possibility of MSG_CTRUNC on Linux.
 */
#ifndef BSOCK_ANCILLARY_DATA_MAX
#define BSOCK_ANCILLARY_DATA_MAX 10240
#endif

__attribute_nonnull__
int
bsock_unix_socket_connect (const char * const restrict sockpath);

__attribute_nonnull__
int
bsock_unix_socket_bind_listen (const char * const restrict sockpath,
                               int * const restrict bound);

__attribute_nonnull_x__((4))
ssize_t
bsock_unix_recv_fds (const int fd,
                     int * const restrict rfds,
                     unsigned int * const restrict nrfds,
                     struct iovec * const restrict iov,
                     const size_t iovlen);

__attribute_nonnull_x__((4,6))
ssize_t
bsock_unix_recv_fds_ex (const int fd,
                        int * const restrict rfds,
                        unsigned int * const restrict nrfds,
                        struct iovec * const restrict iov,
                        const size_t iovlen,
                        char * const restrict ctrlbuf,
                        const size_t ctrlbuf_sz);

__attribute_nonnull_x__((4))
ssize_t
bsock_unix_send_fds (const int fd,
                     const int * const restrict sfds,
                     unsigned int nsfds,
                     struct iovec * const restrict iov,
                     const size_t iovlen);

__attribute_nonnull__
int
bsock_unix_getpeereid (const int s,
                       uid_t * const restrict euid,
                       gid_t * const restrict egid);

#ifdef __cplusplus
}
#endif

#endif
