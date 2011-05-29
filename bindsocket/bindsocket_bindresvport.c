/*
 * bindsocket_bindresvport - bind socket to random low port (privileged IP port)
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

/* bindsocket_bindresvport_sa() originally intended to be portable routine
 * implemented to man page spec without dependency on openssl, though the
 * code is now nearly identical to openssh/openbsd-compat/bindresvport.c
 * The main difference is that bindsocket_bindresvport.c DOES NOT use a
 * crytographically secure mechanism for generating random start port, and
 * is therfore more susceptible to random spoofing attacks than is openbsd
 * bindresvport_sa().  bindsocket_bindresvport_sa() is also tailored for
 * use by bindsocket application, requiring pthread mutex around device open.
 *
 * opessh/openbsd-compat/bindresvport.c contains the following license:
 */

/* ---------- */
/* This file has be substantially modified from the original OpenBSD source */

/*      $OpenBSD: bindresvport.c,v 1.17 2005/12/21 01:40:22 millert Exp $       */

/*
 * Copyright 1996, Jason Downs.  All rights reserved.
 * Copyright 1998, Theo de Raadt.  All rights reserved.
 * Copyright 2000, Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libc/rpc/bindresvport.c */
/* ---------- */

#include <bindsocket_bindresvport.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef IPPORT_RESERVEDSTART
#define IPPORT_RESERVEDSTART 600
#endif

#ifndef BINDSOCKET_BINDRESVPORT_SKIP
#define BINDSOCKET_BINDRESVPORT_SKIP \
  623,631,636,664,749,750,783,873,992,993,994,995
/*
 * (collected from https://bugzilla.redhat.com/show_bug.cgi?id=103401)
 *
 * 623     (DMTF/ASF RMCP)
 * 631     (IPP == CUPS)
 * 636     (LDAPS)
 * 664     (DMTF/ASF RSP)
 * 749     (Kerberos V kadmin)
 * 750     (Kerberos V kdc)
 * 783     (spamd in spamassassin)
 * 873     (rsyncd)
 * 992-995 (SSL-enabled telnet, IMAP, IRC, and POP3)
 *
 * Alert Standard Format (ASF)
 * (NICs might discard packets for non-ASF usage of these ports.)
 * http://en.wikipedia.org/wiki/Alert_Standard_Format
 */
#endif

#ifdef BINDSOCKET_BINDRESVPORT_SKIP  /* comma-separated list of ports to skip */
static int
bindsocket_bindresvport_skip (const unsigned int port)
{
    /*(FUTURE: use bsearch() if list is long)*/
    static const unsigned int skiplist[] = { BINDSOCKET_BINDRESVPORT_SKIP };
    size_t i;
    for (i = 0; i < sizeof(skiplist)/sizeof(int) && skiplist[i] != port; ++i) ;
    return (i != sizeof(skiplist)/sizeof(int)); /* port is on skiplist */
}
#else
#define bindsocket_bindresvport_skip(port) 0
#endif

static void bindsocket_bindresvport_cleanup_mutex (void * const restrict mutex)
{
    pthread_mutex_unlock((pthread_mutex_t *)mutex);
}

static int
bindsocket_bindresvport_random_port (void)
{
    /* Choosing pseudo-random starting port to which to attempt to bind().
     * /dev/urandom provides decent randomness (unless entropy runs out).
     * XOR lower 4 nibbles with the upper 4 nibbles in reverse order
     * since lowest bits provided by /dev/urandom are less random.
     * (Note: read() not protected with mutex since reading random bytes!)
     * (arc4random() would be even better defense against random spoofing)
     * (getpid() and time() are poorer, more predictable choices) */
    static pthread_mutex_t devurandom_mutex = PTHREAD_MUTEX_INITIALIZER;
    static volatile int ufd = -1;
    int fd = ufd;
    int r = -1;
    if (-1 == fd || read(fd, &r, sizeof(int)) != sizeof(int)) {
        int cancel_type;
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &cancel_type);
        pthread_cleanup_push(bindsocket_bindresvport_cleanup_mutex,
                             &devurandom_mutex);
        r = -1;
        if (0 == pthread_mutex_trylock(&devurandom_mutex)) {
            fd = ufd; /* re-check volatile ufd after obtaining mutex */
            if (-1 == fd || read(fd, &r, sizeof(int)) != sizeof(int)) {
                /* race condition around close and reopen (between threads);
                 * another thread might read from original ufd, which could
                 * be opened by another thread to another file.  However,
                 * reopen should be rare, if ever, after initial open.
                 * Full safety would employ mutex around all read() in fn.*/
                ufd = -1;
                if (-1 != fd)
                    while (0 != close(fd) && errno == EINTR) ;
                fd = ufd = open("/dev/urandom", O_RDONLY|O_NONBLOCK);
                if (-1 == fd || read(fd, &r, sizeof(int)) != sizeof(int))
                    r = -1;
            }
            pthread_mutex_unlock(&devurandom_mutex);
        } /* (use less random getpid() ^ time() if obtaining mutex fails) */
        pthread_cleanup_pop(0);
        pthread_setcanceltype(cancel_type, NULL);
    }
    if (-1 != r)
        r ^= (((r>>4)&0xF000)|((r>>12)&0xF00)|((r>>20)&0xF0)|((r>>28)&0xF));
    else
        r = (int)(getpid() ^ time(NULL));
    return(IPPORT_RESERVEDSTART + (r % (IPPORT_RESERVED-IPPORT_RESERVEDSTART)));
}

int
bindsocket_bindresvport_sa (const int sockfd, struct sockaddr *sa)
{
    /* (code below honors sin_addr or sin6_addr, if specified) */
    /* (code below honors sin_port or sin6_port as pstart if in valid range) */
    in_port_t port;
    in_port_t pstart;
    in_port_t *portptr;
    socklen_t addrlen;
    struct sockaddr_in6 saddr; /*(sized for AF_INET or AF_INET6 sockaddr)*/
    if (NULL == sa) {
        socklen_t optlen = sizeof(sa->sa_family);
        memset(&saddr, '\0', sizeof(saddr));
        sa = (struct sockaddr *)&saddr;
        if (0 != getsockopt(sockfd,SOL_SOCKET,SO_TYPE,&sa->sa_family,&optlen))
            return -1;
    }

    if (AF_INET == sa->sa_family) {
        portptr = &((struct sockaddr_in *)sa)->sin_port;
        addrlen = sizeof(struct sockaddr_in);
    }
    else if (AF_INET6 == sa->sa_family) {
        portptr = &((struct sockaddr_in6 *)sa)->sin6_port;
        addrlen = sizeof(struct sockaddr_in6);
    }
    else {
        errno = EAFNOSUPPORT;
        return -1;
    }

    pstart = ntohs(*portptr);  /* 0 == pstart trips port range check below */
    if (pstart < IPPORT_RESERVEDSTART || pstart >= IPPORT_RESERVED)
        pstart = (in_port_t) bindsocket_bindresvport_random_port();

    port = pstart;
    do {
        if (!bindsocket_bindresvport_skip(port)) {
            *portptr = htons(port);
            if (0 == bind(sockfd, sa, addrlen))
                return 0;
            else if (errno != EADDRINUSE)
                return -1;
        }
        if (++port == IPPORT_RESERVED)
            port = IPPORT_RESERVEDSTART;
    } while (port != pstart);
    return -1;
}
