/*
 * bsock_authz - addrinfo authorization
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

/* ? clang-2.9-10.fc16.i686 and compiling bsock_authz.c with -D_FORTIFY_SOURCE=2
 *   results in spinning read() taking 100% CPU ?  TODO: file bug report */
#ifdef __clang__
#undef _FORTIFY_SOURCE
#endif

#include <bsock_authz.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <bsock_addrinfo.h>
#include <bsock_syslog.h>

#ifndef BSOCK_CONFIG
#error "BSOCK_CONFIG must be defined"
#endif

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif
#if (defined(__GNUC__) && __GNUC_PREREQ(4,3)) || __has_attribute(cold)
#ifndef __attribute_cold__
#define __attribute_cold__  __attribute__((cold))
#endif
#endif
#ifndef __attribute_cold__
#define __attribute_cold__
#endif

/* nointr_close() - make effort to avoid leaking open file descriptors */
static int
nointr_close (const int fd)
{ int r; do { r = close(fd); } while (r != 0 && errno == EINTR); return r; }

static void  __attribute__((nonnull))
bsock_cleanup_close (void * const arg)
{
    const int fd = *(int *)arg;
    if (-1 != fd)
        nointr_close(fd);
}

struct bsock_authz_hash_st {
    uid_t mask;
    struct addrinfo **table;
    struct addrinfo *ai;
    int *addr;
};

static struct bsock_authz_hash_st * restrict bsock_authz_hash;

static bool  __attribute__((nonnull))
bsock_authz_valid (const struct addrinfo * const restrict ai,
                   const uid_t uid, const gid_t gid)
{
    /* Note: client must specify address family; AF_UNSPEC not supported */
    const struct addrinfo * restrict h;
    if (uid == 0 || gid == 0)  /* permit root or wheel */
        return true;
    h = bsock_authz_hash->table[(uid & bsock_authz_hash->mask)];
    for (; h != NULL; h = h->ai_next) {
        if (   h->ai_flags    == (int)uid
            && h->ai_family   == ai->ai_family
            && h->ai_socktype == ai->ai_socktype
            && h->ai_protocol == ai->ai_protocol
            && h->ai_addrlen  == ai->ai_addrlen
            && 0 == memcmp(h->ai_addr, ai->ai_addr, h->ai_addrlen)  )
            return true;
    }
    return ((errno = EACCES), false);
}

int  __attribute__((nonnull))
bsock_authz_validate (struct addrinfo * const restrict ai,
                      const uid_t uid, const gid_t gid)
{
    /* check client credentials to authorize client request */
    if (bsock_authz_valid(ai, uid, gid))
        return true;

    /* Open Group Base Specifications Issue 6 for <netinet/in.h>
     * http://pubs.opengroup.org/onlinepubs/009604599/basedefs/netinet/in.h.html
     * The sockaddr_in6 structure shall be set to zero by an application
     * prior to using it, since implementations are free to have additional,
     * implementation-defined fields in sockaddr_in6.
     *
     * Since a similar statement is not made for struct sockaddr_in, and since
     * struct sockaddr_in might have addition padding structures, copy relevant
     * members to a zero'd out struct sockaddr_in for comparison when AF_INET
     * (e.g. struct sockaddr_in has 8 bytes in sin_zero member on Linux).
     * For other socktype (not AF_INET, AF_INET6) assume zero'd like AF_INET6 */
    if (ai->ai_family == AF_INET) {  /* copy paranoia might be excess */
        struct sockaddr * const restrict sockaddr_orig = ai->ai_addr;
        struct sockaddr_in sin;
        memset(&sin, '\0', sizeof(struct sockaddr_in));
        sin.sin_family     = AF_INET;
        sin.sin_port       =((struct sockaddr_in *)ai->ai_addr)->sin_port;
        sin.sin_addr.s_addr=((struct sockaddr_in*)ai->ai_addr)->sin_addr.s_addr;
        ai->ai_addr        = (struct sockaddr *)&sin;
        const bool rc      = bsock_authz_valid(ai, uid, gid);
        ai->ai_addr        = sockaddr_orig; /* restore (struct sockaddr *) */
        if (rc)
            return true;
    }

    return false;
}

static int  __attribute_cold__
bsock_authz_config_parse (struct bsock_authz_hash_st* const restrict authz_hash,
                          char * const restrict buf)
{
    char *b, *e, *name;
    struct addrinfo * restrict ai = authz_hash->ai;
    int * restrict addr = authz_hash->addr;
    struct addrinfo **hh;
    struct bsock_addrinfo_strs aistr;
    int line = 1;
    struct passwd pw;
    struct passwd *pwres = NULL;
    char pwbuf[2048];

    /* efficiency: keep database open (advantageous for nss_mcdb module) */
    /* (not bothering to close database if error or pthread_cancel() called)*/
    setpwent();

    /* (note: expects final line in buf to end in '\n' (or else skips it)) */
    /* (assumes sizeof(uid_t) <= sizeof(int); if not true, then must
     *  change code to store uid in (uintptr_t)h->ai_canonname in hash) */
    /* (XXX: should check this assumption in bsock.t.c tests) */
    /*assert(sizeof(uid_t) <= sizeof(int));*//*(ai->ai_flags is int-sized)*/

    for (b = buf; NULL != (e = strchr(b, '\n')); b = e+1, ++line) {
        if (*b == '\n' || *b == '#')  /* skip blank lines,  '#' comments */
            continue;
        *e = '\0';

        b = strchr((name = b), ' ');
        if (NULL != b && (*b = '\0',
                          0 == getpwnam_r(name,&pw,pwbuf,sizeof(pwbuf),&pwres)
                          && NULL != pwres)) {
            do { ++b; } while (*b == ' ');
        }
        else {
            bsock_syslog(EINVAL, LOG_ERR, "invalid line (%d) in config (%s)",
                         line, BSOCK_CONFIG);
            return EINVAL;
        }

        /*(sufficient space should have previously been allocated)*/
        ai->ai_addr    = (struct sockaddr *)addr;
        ai->ai_addrlen = sizeof(struct sockaddr_storage);

        if (bsock_addrinfo_split_str(&aistr, b)
            && bsock_addrinfo_from_strs(ai, &aistr)) {
            addr += ((ai->ai_addrlen + 7) & (size_t)~0x7); /* 8-byte align */
            ai->ai_flags = (int)pw.pw_uid;
            hh = &authz_hash->table[(pw.pw_uid & authz_hash->mask)];
            ai->ai_next = *hh;
            *hh = ai++;/*sufficient struct addrinfo should have been allocated*/
        }
        else {
            bsock_syslog(EINVAL, LOG_ERR, "invalid line (%d) in config (%s)",
                         line, BSOCK_CONFIG);
            return errno;
        }
    }

    endpwent();

    return 0;
}

/* XXX: future
 * bsock_resvaddr_config() and bsock_authz_config() should share parsing code */

void  __attribute_cold__
bsock_authz_config (void)
{
    char * volatile restrict buf = NULL; /*volatile for pthread_cleanup_push()*/
    struct bsock_authz_hash_st * volatile restrict authz_hash = NULL;
    int fd = -1;
    int n = 0;
    int table_sz = 8;

    pthread_cleanup_push(bsock_cleanup_close, &fd);
    do {
        struct stat st;
        if (-1 == (fd = open(BSOCK_CONFIG, O_RDONLY, 0))) {
            bsock_syslog(errno, LOG_ERR, BSOCK_CONFIG);
            break;
        }
        if (0 != fstat(fd, &st)
            || st.st_uid != geteuid() || (st.st_mode & (S_IWGRP|S_IWOTH))) {
            bsock_syslog(EPERM, LOG_ERR,
                         "ownership/permissions incorrect on %s", BSOCK_CONFIG);
            break;
        }

        pthread_cleanup_push(free, buf);

        if (NULL != (buf = malloc((size_t)st.st_size+2))) {
            char * restrict b = buf;
            ssize_t r = 0;
            ssize_t len = st.st_size;
            b[len] = b[len+1] = '\0';
            do {
                r = read(fd, b, len);
            } while (-1 != r ? (b+=r, len-=r) : (errno == EINTR));
            if (0 == len) {
                /* count lines for later struct addrinfo memory allocation
                 * (not exact; might be few more than needed; but that's okay)*/
                b = buf;
                if (b[st.st_size-1] != '\n')
                    b[st.st_size] = '\n';/* ensure final line ends in newline */
                while (NULL != (b = strchr(b+1, '\n')))
                    ++n;       /*(does not count first line, if blank)*/
                if (n & 1)
                    ++n;/*(make n even for mem alignment considerations below)*/
                if (n <= 1048576) { /* arbitrary limit: 1 million lines (!) */
                    while (table_sz < n)
                        table_sz <<= 1;
                }
                else {
                    bsock_syslog(EINVAL,LOG_ERR,"too many lines in config (%s)",
                                 BSOCK_CONFIG);
                    free(buf);
                    buf = NULL;
                }
            }
            else {
                bsock_syslog(errno, LOG_ERR, "read config (%s)", BSOCK_CONFIG);
                free(buf);
                buf = NULL;
            }
        }
        else
            bsock_syslog(errno, LOG_ERR, "malloc");

        pthread_cleanup_pop(0);

    } while (0);
    pthread_cleanup_pop(1);  /* close(fd)  */

    /* allocate space, wasting some memory but ensuring enough
     * size for ai_addr by using struct sockaddr_storage */
    authz_hash = malloc(  sizeof(struct bsock_authz_hash_st)
                        + sizeof(struct addrinfo *) * table_sz
                        + sizeof(struct addrinfo) * n
                        + sizeof(struct sockaddr_storage) * n);
    if (NULL == authz_hash) {
        bsock_syslog(errno, LOG_ERR, "malloc");
        free(buf);
        buf = NULL;
    }
    else {
        authz_hash->table = (struct addrinfo **)(authz_hash+1);
        authz_hash->ai    = (struct addrinfo *)(authz_hash->table+table_sz);
        authz_hash->addr  = (int *)(authz_hash->ai+n);
        memset(authz_hash->table, '\0', sizeof(struct addrinfo *) * table_sz);
        memset(authz_hash->addr,  '\0', sizeof(struct sockaddr_storage) * n);
        pthread_cleanup_push(free, (void *)(uintptr_t)buf);
        pthread_cleanup_push(free, (void *)(uintptr_t)authz_hash);

        n = bsock_authz_config_parse(authz_hash, buf);

        pthread_cleanup_pop(0);  /* free(authz_hash) (only if cancelled) */
        pthread_cleanup_pop(1);  /* free(buf); finished parsing buf */
        if (0 != n) {
            free(authz_hash);
            authz_hash = NULL;
        }
    }

    if (NULL == bsock_authz_hash) {
        bsock_authz_hash = authz_hash;
        if (NULL == authz_hash)
            exit(1);  /* unable to continue if no prior, good bsock config */
    }
    else if (NULL != authz_hash) {
        const struct bsock_authz_hash_st * restrict p = bsock_authz_hash;
        bsock_authz_hash = authz_hash; /* (might do atomic swap in future) */
        /* pause 1 sec for simple and coarse (not perfect) mechanism to give
         * other threads accessing hash time to finish, else might crash.
         * (could instead grab mutex around all bsock_authz_hash accesses) */
        pthread_cleanup_push(free, (void *)(uintptr_t)p);
        poll(NULL, 0, 1000);
        pthread_cleanup_pop(1);
    }
}
