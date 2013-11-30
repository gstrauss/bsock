/*
 * bsock_authz - addrinfo authorization
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

/* clang-2.9-10.fc16.i686 and compiling bsock_authz.c with -D_FORTIFY_SOURCE=2
 * results in spinning read() taking 100% CPU.  Fixed in clang 3.0.
 *   http://llvm.org/bugs/show_bug.cgi?id=10160
 *   http://llvm.org/bugs/show_bug.cgi?id=9614 */
#if defined(__clang_major__) && __clang_major__ < 3
#undef _FORTIFY_SOURCE
#endif

#include <bsock_authz.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <plasma/plasma_stdtypes.h>

#include <bsock_addrinfo.h>
#include <bsock_syslog.h>

#ifndef BSOCK_CONFIG
#error "BSOCK_CONFIG must be defined"
#endif

/* nointr_close() - make effort to avoid leaking open file descriptors */
static int
nointr_close (const int fd)
{ int r; retry_eintr_do_while(r = close(fd), r != 0); return r; }

struct bsock_authz_hash_st {
    uid_t mask;
    struct addrinfo **table;
    struct addrinfo *ai;
    int *addr;
};

static struct bsock_authz_hash_st * restrict bsock_authz_hash;

__attribute_nonnull__
static bool
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

__attribute_nonnull__
int
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

__attribute_cold__
__attribute_noinline__
static int
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

__attribute_cold__
__attribute_noinline__
void
bsock_authz_config (void)
{
    char * restrict buf = NULL;
    struct bsock_authz_hash_st * restrict authz_hash = NULL;
    int fd = -1;
    int n = 0;
    int table_sz = 8;

    do {
        struct stat st;
        if (-1 == (fd = open(BSOCK_CONFIG, O_RDONLY|O_NONBLOCK, 0))) {
            bsock_syslog(errno, LOG_ERR, BSOCK_CONFIG);
            break;
        }
        if (0 != fstat(fd, &st)
            || st.st_uid != geteuid() || (st.st_mode & (S_IWGRP|S_IWOTH))) {
            bsock_syslog(EPERM, LOG_ERR,
                         "ownership/permissions incorrect on %s", BSOCK_CONFIG);
            break;
        }

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
    } while (0);
    if (-1 != fd)
        nointr_close(fd);

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
        if (NULL == buf || 0 != bsock_authz_config_parse(authz_hash, buf)) {
            free(authz_hash);
            authz_hash = NULL;
        }
        free(buf);
    }

    if (NULL == bsock_authz_hash) {
        bsock_authz_hash = authz_hash;
        if (NULL == authz_hash)
            exit(1);  /* unable to continue if no prior, good bsock config */
    }
    else if (NULL != authz_hash) {
        struct bsock_authz_hash_st * const restrict p = bsock_authz_hash;
        bsock_authz_hash = authz_hash; /* (might do atomic swap in future) */
        /* pause 1 sec for simple and coarse (not perfect) mechanism to give
         * other threads accessing hash time to finish, else might crash.
         * (could instead grab mutex around all bsock_authz_hash accesses) */
        while (poll(NULL, 0, 1000) != 0)
            ;
        free(p);
    }
}
