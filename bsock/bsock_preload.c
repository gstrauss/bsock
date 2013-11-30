/*
 * bsock_preload - interpose bind() to call bsock_bind_intercept()
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

#include <plasma/plasma_attr.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <unistd.h>

#include <bsock_bind.h>

int bindresvport  (const int, struct sockaddr_in * restrict);
int bindresvport6 (const int, struct sockaddr_in6 * restrict);

static int (*bind_rtld_next)(int, const struct sockaddr *, socklen_t);
__attribute_nonnull__
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

__attribute_noinline__
__attribute_nonnull__
static int
bsock_preload_bind (const int sockfd, const struct sockaddr *addr,
                    const socklen_t addrlen)
{
    struct addrinfo ai = {
      .ai_flags    = 0,
      .ai_family   = addr->sa_family,
      .ai_socktype = 0,
      .ai_protocol = IPPROTO_TCP,  /*(default if no SO_PROTOCOL sockopt)*/
      .ai_addrlen  = addrlen,
      .ai_addr     = (struct sockaddr *)(uintptr_t)addr,
      .ai_canonname= NULL,
      .ai_next     = NULL
    };
    socklen_t optlen;

    /* bsock supports only AF_INET, AF_INET6, AF_UNIX;
     * simply bind if address family is otherwise */
    if (ai.ai_family == AF_INET || ai.ai_family == AF_INET6) {
        /* simply bind if port >= IPPORT_RESERVED; no root privileges needed */
        const int port = (ai.ai_family == AF_INET)
          ? ntohs(((struct sockaddr_in  *)ai.ai_addr)->sin_port)
          : ntohs(((struct sockaddr_in6 *)ai.ai_addr)->sin6_port);
        if (port >= IPPORT_RESERVED
            && 0 == bind_rtld_next(sockfd, ai.ai_addr, ai.ai_addrlen))
            return 0;
            /*(fall through if bind() fails in case persistent reserved addr)*/
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

    if (0 == geteuid() && 0 == bind_rtld_next(sockfd,ai.ai_addr,ai.ai_addrlen))
        return 0;
        /*(fall through if bind() fails in case persistent reserved addr)*/

    optlen = sizeof(ai.ai_socktype);
    if (-1 == getsockopt(sockfd,SOL_SOCKET,SO_TYPE,&ai.ai_socktype,&optlen))
        return -1;
  #ifdef SO_PROTOCOL
    optlen = sizeof(ai.ai_protocol);
    if (-1 == getsockopt(sockfd,SOL_SOCKET,SO_PROTOCOL,&ai.ai_protocol,&optlen))
        return -1;
  #endif /* else pass ai_protocol == IPPROTO_TCP, the most likely value */

    return bsock_bind_addrinfo(sockfd, &ai);
}

int
bind (const int sockfd, const struct sockaddr * const restrict addr,
      const socklen_t addrlen)
{
    return bsock_preload_bind(sockfd, addr, addrlen);
}

int
bindresvport (const int sockfd, struct sockaddr_in * const restrict sin)
{
    return bsock_preload_bind(sockfd, (const struct sockaddr *)sin,
                              sizeof(struct sockaddr_in));
}

int
bindresvport6 (const int sockfd, struct sockaddr_in6 * const restrict sin6)
{
    return bsock_preload_bind(sockfd, (const struct sockaddr *)sin6,
                              sizeof(struct sockaddr_in6));
}
