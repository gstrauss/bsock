/*
 * bsock_resvaddr - maintain persistent reserved address
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

#include <bsock_resvaddr.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
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

#ifndef BSOCK_RESVADDR_CONFIG
#define BSOCK_RESVADDR_CONFIG BSOCK_CONFIG".resvaddr"
#endif

#if defined(__GNUC__) && __GNUC_PREREQ(4,3)
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

struct bsock_resvaddr {
    struct bsock_resvaddr *next;
    struct addrinfo *ai;
    int fd;
};

struct bsock_resvaddr_alloc {
    struct bsock_resvaddr **table;
    size_t table_sz;   /* power of 2 assumed by hash access routines */
    size_t elt_count;  /* elements in table */
    struct bsock_resvaddr *elt;
    struct addrinfo *ai;
    char *buf;
    size_t buf_sz;
    struct bsock_resvaddr_alloc *prev;
};

static struct bsock_resvaddr *empty_resvaddr;
static struct bsock_resvaddr_alloc empty_alloc =
  { .table = &empty_resvaddr, .table_sz = 1 };
static struct bsock_resvaddr_alloc *bsock_resvaddr_alloc =
  &empty_alloc;

static size_t
bsock_resvaddr_count (void)
{
    return (NULL != bsock_resvaddr_alloc) ? bsock_resvaddr_alloc->elt_count : 0;
}

static uint32_t  __attribute__((nonnull))
bsock_resvaddr_hash (const struct addrinfo * const restrict ai)
{
    const unsigned char * const restrict addr = (unsigned char *)ai->ai_addr;
    const size_t addrlen = ai->ai_addrlen;
    size_t i = SIZE_MAX;/* (size_t)-1; will wrap around to 0 with first ++i */
    uint32_t h = 5381;  /* djb cdb hash function: http://cr.yp.to/cdb/cdb.txt */
    while (++i < addrlen)
        h = (h + (h << 5)) ^ addr[i];
    return h;
}

static int
  __attribute__((noinline))  __attribute_cold__  __attribute__((nonnull))
bsock_resvaddr_rebind (const struct addrinfo * restrict ai,
                       int * const restrict tfd);

int  __attribute__((nonnull))
bsock_resvaddr_fd (const struct addrinfo * const restrict ai)
{
    const uint32_t h = bsock_resvaddr_hash(ai);
    struct bsock_resvaddr_alloc * const ar = bsock_resvaddr_alloc;
    struct bsock_resvaddr * restrict t = ar->table[h & (ar->table_sz-1)];
    const struct addrinfo * restrict tai;
    for (; NULL != t; t = t->next) {
        tai = t->ai;
        if (   ai->ai_addrlen == tai->ai_addrlen
            && 0 == memcmp(ai->ai_addr, tai->ai_addr, ai->ai_addrlen)
            && ai->ai_family   == tai->ai_family
            && ai->ai_socktype == tai->ai_socktype
            && ai->ai_protocol == tai->ai_protocol)
            return !(ai->ai_flags & BSOCK_FLAGS_REBIND)
              ? t->fd
              : bsock_resvaddr_rebind(ai, &t->fd);
    }
    return -1;
}

static void  __attribute__((nonnull))  __attribute_cold__
bsock_resvaddr_cleanup_close (void * const arg)
{
    const int * const restrict fd = (int *)arg;
    if (-1 != fd[0])
        nointr_close(fd[0]);
    if (-1 != fd[1])
        nointr_close(fd[1]);
}

static int
  __attribute__((noinline))  __attribute_cold__  __attribute__((nonnull))
bsock_resvaddr_rebind (const struct addrinfo * restrict ai,
                       int * const restrict tfd)
{
    /* (race condition with re-reading config (mitigated by reconfig sleep)) */
    /* (requires pthread PTHREAD_CANCEL_DEFERRED type for proper operation) */
    int fd[] = { -1, -1 }, flag = 1;
    pthread_cleanup_push(bsock_resvaddr_cleanup_close, &fd);
    if (-1 != (fd[0] = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol))
        && (!(AF_INET == ai->ai_family || AF_INET6 == ai->ai_family)
            || 0==setsockopt(fd[0],SOL_SOCKET,SO_REUSEADDR,&flag,sizeof(flag)))
        /*(race condition with another thread requesting same address)*/
        && (fd[1] = *tfd, *tfd = -1, 0 == nointr_close(fd[1]))
        && (fd[1] = -1, 0 == bind(fd[0], ai->ai_addr, ai->ai_addrlen))) {
        *tfd = fd[0]; fd[0] = -1;
    }
    else {
        bsock_syslog(errno, LOG_ERR, "socket,setsockopt,bind");
        bsock_resvaddr_cleanup_close(&fd);
    }
    pthread_cleanup_pop(0);
    return *tfd;
}

struct bsock_resvaddr_cleanup {
    FILE *fp;
    struct bsock_resvaddr_alloc *ar;
};

static void  __attribute__((nonnull))
bsock_resvaddr_cleanup (void * const arg)
{
    struct bsock_resvaddr_cleanup * const cleanup =
      (struct bsock_resvaddr_cleanup *)arg;
    struct bsock_resvaddr_alloc *ar = cleanup->ar;
    size_t i;
    int fd;
    if (NULL != cleanup->fp)
        fclose(cleanup->fp);
    if (NULL == ar)
        return;
    if (ar == bsock_resvaddr_alloc) {
        /* successful reconfig; cleanup ar->prev */
        ar = ar->prev;
        if (&empty_alloc == ar)
            return;
        /* any thread still servicing request for addr that is no longer 
         * reserved might return invalid descriptor or race with new fd in
         * another thread reusing just-close()d fd.  In other words, admin
         * should avoid unreserving addr that is actively requested */
        for (i = 0; i < ar->elt_count; ++i) {
            if (-1 == bsock_resvaddr_fd(ar->elt[i].ai)) {
                if (-1 != (fd = ar->elt[i].fd)) {
                    nointr_close(fd);
                    ar->elt[i].fd = -1;
                }
            }
        }
        /* any thread still reading old table (unlikely) might crash program.
         * (could wrap access to table in mutex, but table changes rarely) */
        free(ar);
        cleanup->ar->prev = NULL;
    }
    else {
        /* aborted reconfig; cleanup ar */
        for (i = 0; i < ar->elt_count; ++i) {
            if (-1 != (fd = ar->elt[i].fd))
                nointr_close(fd);
        }
        free(ar);
    }
}

void
bsock_resvaddr_config (void)
{
    FILE *cfg;
    int addr[28];/* buffer for IPv4, IPv6, or AF_UNIX w/ up to 108 char path */
    struct addrinfo ai = {  /* init only fields used to pass buf and bufsize */
      .ai_addrlen = sizeof(addr),
      .ai_addr    = (struct sockaddr *)addr
    };
    struct bsock_addrinfo_strs aistr;
    struct bsock_resvaddr_alloc *ar = NULL;
    struct bsock_resvaddr *t;
    struct bsock_resvaddr **tp;
    struct bsock_resvaddr_cleanup cleanup = { .ar = NULL };
    struct stat st;
    unsigned int lineno = 0;
    unsigned int addr_count = 0;
    unsigned int table_sz = 32;
    int flag = 1;
    size_t addr_sz = 0;
    char line[256];   /* username + AF_UNIX, AF_INET, AF_INET6 bsock str */
    bool rc = true;
    bool addr_added = false;

    /* (requires pthread PTHREAD_CANCEL_DEFERRED type for proper operation) */
    pthread_cleanup_push(bsock_resvaddr_cleanup, &cleanup);

    do {

        if (NULL == (cleanup.fp = fopen(BSOCK_RESVADDR_CONFIG, "r"))) {
            if (errno != ENOENT) /*(not error: resvaddr config does not exist)*/
                bsock_syslog(errno, LOG_ERR, BSOCK_RESVADDR_CONFIG);
            break;
        }
        cfg = cleanup.fp;

        if (0 != fstat(fileno(cfg), &st)
            || st.st_uid != geteuid() || (st.st_mode & (S_IWGRP|S_IWOTH))) {
            bsock_syslog(EPERM,LOG_ERR,"ownership/permissions incorrect on %s",
                         BSOCK_RESVADDR_CONFIG);
            break;
        }

        while (NULL != fgets(line, sizeof(line), cfg)) {
            ++lineno;
            if ('#' == line[0] || '\n' == line[0])
                continue;  /* skip # comments, blank lines */
            if (   !bsock_addrinfo_split_str(&aistr, line)
                || !bsock_addrinfo_from_strs(&ai, &aistr)   ) {
                bsock_syslog(EINVAL, LOG_ERR, "error parsing line %u in %s",
                             lineno, BSOCK_RESVADDR_CONFIG);
                rc = false;
            }
            if (!rc)
                continue; /* parse to end of file to report all syntax errors */
            ++addr_count;
            addr_sz += (ai.ai_addrlen + 3) & (size_t)~0x3;/* align to 4 bytes */
            if (-1 == bsock_resvaddr_fd(&ai))
                addr_added = true;
        }
        if (!rc)
            break;  /* parse error occurred */
        if (ferror(cfg) || !feof(cfg)) {
            bsock_syslog(errno, LOG_ERR, "file read error in %s",
                              BSOCK_RESVADDR_CONFIG);
            break;  /* parse error occurred */
        }
        if (!addr_added && bsock_resvaddr_count() == addr_count)
            break;  /* no change in reserved addr list */
        if (0 != fseek(cfg, 0L, SEEK_SET)) {
            bsock_syslog(errno, LOG_ERR, "fseek");
            break;  /* rewind to beginning of file failed; unlikely */
        }
        clearerr(cfg);

        /* sanity-check number of addr, calculate power 2 size of hash table */
        if (sysconf(_SC_OPEN_MAX) < (long)addr_count) {
            bsock_syslog(EINVAL, LOG_ERR,
                         "too many entries (> _SC_OPEN_MAX) in %s",
                         BSOCK_RESVADDR_CONFIG);
            break;
        }
        while (table_sz < addr_count)
            table_sz <<= 1;

        /* allocate space for new table structures; take care for alignments */
        ar = malloc(  sizeof(struct bsock_resvaddr_alloc)
                    + sizeof(struct bsock_resvaddr *) * table_sz
                    + sizeof(struct bsock_resvaddr) * addr_count
                    + sizeof(struct addrinfo) * addr_count + addr_sz);
        if (NULL == ar) {
            bsock_syslog(errno, LOG_ERR, "malloc");
            break;
        }
        ar->table    = (struct bsock_resvaddr **)(ar+1);
        ar->table_sz = table_sz;
        ar->elt_count= addr_count;
        ar->elt      = (struct bsock_resvaddr *)(ar->table+table_sz);
        ar->ai       = (struct addrinfo *)(ar->elt+addr_count);
        ar->buf      = (char *)(ar->ai+addr_count);
        ar->buf_sz   = addr_sz;
        ar->prev     = bsock_resvaddr_alloc;
        /* initialize all elt->fd to -1 for use by cleanup routines */
        memset(ar->elt, -1, sizeof(struct bsock_resvaddr) * addr_count);

        /* populate reserved addr table */
        lineno = 0; /* reuse to count addr instead of lines */
        while (NULL != fgets(line, sizeof(line), cfg)) {
            if ('#' == line[0] || '\n' == line[0])
                continue;  /* skip # comments, blank lines */
            if (   !bsock_addrinfo_split_str(&aistr, line)
                || !bsock_addrinfo_from_strs(&ai, &aistr)
                || lineno >= ar->elt_count || ai.ai_addrlen > ar->buf_sz   ) {
                bsock_syslog(EINVAL, LOG_ERR,
                             "error parsing config (modified?) in %s",
                             BSOCK_RESVADDR_CONFIG);
                rc = false;
                break; /* should not happen; checked above */
            }

            /* allocate table element */
            t     = ar->elt + lineno;
            t->ai = ar->ai  + lineno;

            /* retrieve previously reserved addr or bind to reserve new addr */
            if (-1 == (t->fd = bsock_resvaddr_fd(&ai))) {
                t->fd = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol);
                if (-1 != t->fd
                    && (!(AF_INET == ai.ai_family || AF_INET6 == ai.ai_family)
                        || 0 == setsockopt(t->fd, SOL_SOCKET, SO_REUSEADDR,
                                           &flag, sizeof(flag))) /* flag == 1 */
                    && 0 == bind(t->fd, ai.ai_addr, ai.ai_addrlen))
                    flag = 1;
                else {
                    flag = errno;
                    bsock_syslog(flag, LOG_ERR, "socket,setsockopt,bind");
                    bsock_syslog(flag, LOG_ERR, "skipping addr: %s %s %s %s %s",
                                 aistr.family,aistr.socktype,
                                 aistr.protocol,aistr.service,aistr.addr);
                    if (-1 != t->fd) {
                        nointr_close(t->fd);
                        t->fd = -1;
                    }
                    flag = 1;
                    continue;
                }
            }

            /* copy addrinfo */
            t->ai->ai_family   = ai.ai_family;
            t->ai->ai_socktype = ai.ai_socktype;
            t->ai->ai_protocol = ai.ai_protocol;
            t->ai->ai_addrlen  = ai.ai_addrlen;
            t->ai->ai_addr     = (struct sockaddr *)ar->buf;
            memcpy(t->ai->ai_addr, ai.ai_addr, ai.ai_addrlen);
            ar->buf    += (ai.ai_addrlen + 3) & (size_t)~0x3;  /* align to 4 */
            ar->buf_sz -= (ai.ai_addrlen + 3) & (size_t)~0x3;  /* align to 4 */

            /* insert into table */
            tp = &ar->table[bsock_resvaddr_hash(t->ai) & (ar->table_sz-1)];
            t->next = *tp;
            *tp = t;
            ++lineno;
        }
        if (!rc || ferror(cfg) || !feof(cfg)) {
            bsock_syslog(errno, LOG_ERR, "file read error in %s",
                         BSOCK_RESVADDR_CONFIG);
            break;  /* parse error occurred */
        }

        /* activate new table */
        ar->elt_count = lineno;  /* actual num elements in table */
        bsock_resvaddr_alloc = ar;

        poll(NULL, 0, 1000); /* yield in case other threads reading old table */

    } while (0);

    pthread_cleanup_pop(1);  /* bsock_resvaddr_cleanup(&ar) */
}
