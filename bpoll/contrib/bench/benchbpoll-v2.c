/*
 * benchbpoll-v2.c - custom implementation of microbenchmarks employing bpoll
 *
 * benchbpoll-v2.c is a custom implementation of the basic microbenchmarking
 * steps taken in bench.c provided with libevent and, subsequently libev.
 *
 *
 * Copyright (c) 2012, Glue Logic LLC. All rights reserved. code()gluelogic.com
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
 *
 *
 * Sat 03/31/2012 - code () gluelogic.com
 *     bench.c implementation using bpoll
 *     Add support for preprocessor flags to control use of sockets,pipes,splice
 *
 */

#ifdef USE_SPLICE
#ifndef USE_PIPES
#define USE_PIPES
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <sys/uio.h>
static char vmdata[8192];
static struct iovec iov = { .iov_base = vmdata, .iov_len = 1 };
static int devnull;
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
extern char *optarg;

#include <bpoll/bpoll.h>

static int count, writes, fired, errors;

static void
read_cb(bpollset_t * const restrict bpset  __attribute__((unused)),
        bpollelt_t * const restrict bpelt,
        const int data  __attribute__((unused)))
{
    ssize_t rc;
  #ifndef USE_SPLICE
    unsigned char buf[4];
    do {
        rc = read(bpelt->fd, &buf, sizeof(buf));/*(usually expect only 1 byte)*/
    } while (rc == -1 && errno == EINTR);
  #else
    rc = splice(bpelt->fd, NULL, devnull, NULL, 4,
                SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
  #endif

    if (rc != -1)
        count += (int)rc;
    else
        ++errors;

    if (writes) {
      #ifndef USE_SPLICE
        do {
            rc = write((int)(intptr_t)bpelt->udata, "e", 1);
        } while (rc == -1 && errno == EINTR);
      #else
        rc = vmsplice((int)(intptr_t)bpelt->udata, &iov, 1, SPLICE_F_NONBLOCK);
      #endif
        if (rc == 1) {
            --writes;
            ++fired;
        }
        else
            ++errors;
    }
}

static bpoll_fn_cb_event_t fn_cb_event;
/* fn_cb_event=read_cb to use bpollset event callback instead of results list */

static void  __attribute__((noinline))
parse_args(const int argc, char ** const restrict argv,
           int * const restrict num_fdpairs,
           int * const restrict num_active,
           int * const restrict num_writes)
{
    struct rlimit rl;
    char c;

    /* set defaults */
    *num_fdpairs = 100;
    *num_active  = 1;
    *num_writes  = 0;

    while ((c = getopt(argc, argv, "n:a:w:")) != -1) {
        switch (c) {
          case 'n':
            *num_fdpairs = atoi(optarg); if (*num_fdpairs > 0) continue; break;
          case 'a':
            *num_active  = atoi(optarg); if (*num_active  > 0) continue; break;
          case 'w':
            *num_writes  = atoi(optarg); if (*num_writes >= 0) continue; break;
          default:
            fprintf(stderr, "Invalid argument \"%c\"\n", c); exit(1);
        }
        fprintf(stderr, "Invalid argument -%c \"%s\"\n", c, optarg);
        exit(1);
    }

    if (*num_active > *num_fdpairs)
        *num_active = *num_fdpairs;
    if (*num_writes > *num_fdpairs)
        *num_writes = *num_fdpairs;

    rl.rlim_cur = rl.rlim_max = *num_fdpairs * 2 + 50;
    if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
        perror("setrlimit");
}

#ifdef BENCH_TIMING  /* reporting */

static struct timeval ts, te;

/* convenience macro for to find difference between two struct timevals */
#ifndef timersub
#define timersub(tvp, uvp, vvp)                              \
    do {                                                     \
        (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;       \
        (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;    \
        if ((vvp)->tv_usec < 0) {                            \
            (vvp)->tv_sec--;                                 \
            (vvp)->tv_usec += 1000000;                       \
        }                                                    \
    } while (0)
#endif

#define BENCHMARK_START(ts) \
    gettimeofday(&ts, NULL)

#define BENCHMARK_END(ts, te, label)                                        \
    gettimeofday(&te, NULL);                                                \
    timersub(&te, &ts, &ts);                                                \
    fprintf(stdout, "%8ld %s\n", ts.tv_sec * 1000000L + ts.tv_usec, label); \
    BENCHMARK_START(ts)

#else

#define BENCHMARK_START(ts)
#define BENCHMARK_END(ts, te, label)

#endif

int
main (const int argc, char ** const argv)
{
    int i, j, num_fdpairs, num_active, num_writes;

    /* parse arguments and check runtime environment */
    parse_args(argc, argv, &num_fdpairs, &num_active, &num_writes);

    /* allocate bpollset and fdpairs array data structures */
    struct bpollelt_t *bpelt;
    struct bpollelt_t **results;
    struct bpollset_t * const restrict bpset =
      bpoll_create(NULL, fn_cb_event, NULL, NULL, NULL);
    int * const restrict fdpairs = (int *)
      malloc(num_fdpairs * 2 * sizeof(int));
    if (bpset == NULL || fdpairs == NULL)
        return perror("malloc"), 1;              /* exit(1) if error */

    /* initialize bpollset */
    /* (On Pentium-M 2 GHz laptop on this very specific test benchmark,
     *  and testing power-2 queue sizes from 32 - 1024:
     *  queue size 512 is fastest with benchmark -n 40000 -a 400   (  1% busy)
     *  queue size 512 is fastest with benchmark -n 10000 -a 1000  ( 10% busy)
     *  queue size  64 marginally faster with    -n 10000 -a 10000 (100% busy)
     *  (benchmark probably does not reflect real-world performance; YMMV))
     * (libev uses queue size of 64) */
    if (bpoll_init(bpset, BPOLL_M_NOT_SET, num_fdpairs, 512, 0) != 0)
        return perror("bpoll_init"), 1;          /* exit(1) if error */
    bpoll_timespec_from_msec(bpset, 0);

    /* open file descriptor pairs for read/write */
    for (i = 0; i < num_fdpairs; ++i) {
      #ifdef USE_PIPES
        if (pipe(fdpairs+(i<<1)) == -1)
            return perror("pipe"), 1;            /* exit(1) if error */
      #else
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fdpairs+(i<<1)) == -1)
            return perror("socketpair"), 1;      /* exit(1) if error */
      #endif
        /* (should follow with fcntl O_NONBLOCK both fds in real-world usage) */
    }

  #ifdef USE_SPLICE
    if ((devnull = open("/dev/null", O_WRONLY|O_NONBLOCK, 0)) == -1)
        return perror("open /dev/null"), 1;
  #endif

    /* add to bpollset the read side of file descriptor pairs */
    BENCHMARK_START(ts);
    for (i = 0; i < num_fdpairs; ++i) {
        bpelt = bpoll_elt_init(bpset, NULL, fdpairs[i<<1],
                            #ifdef USE_PIPES
                               BPOLL_FD_PIPE,
                            #else
                               BPOLL_FD_SOCKET,
                            #endif
                               BPOLL_FL_ZERO);
        if (bpelt == NULL)
            return perror("bpoll_elt_init"), 1;  /* exit(1) if error */
        /* pre-cache another descriptor (prior to i in list) for extra writes
         * (wrap around to end if at beginning of list) */
        bpelt->udata = (void *)(uintptr_t)
          fdpairs[ (i != 0 ? i-1 : num_fdpairs-1) * 2 + 1 ];

        if (bpoll_elt_add(bpset, bpelt, BPOLLIN) != 0)
            return perror("bpoll_elt_add"), 1;   /* exit(1) if error */
    }
    BENCHMARK_END(ts, te, "bpoll_elt_add");

  #ifdef BENCH_TIMING
    /* Nothing written yet; should always return 0 (nothing ready)
     * Time this to measure overhead of poll mechanism with nothing ready */
    i = bpoll_poll(bpset, bpoll_timespec(bpset));
    if (i != 0)
        fprintf(stderr, "bpoll_poll: expected 0, not %d\n", i);
    BENCHMARK_END(ts, te, "bpoll_poll (nothing ready yet)");
    i = bpoll_poll(bpset, bpoll_timespec(bpset));
    if (i != 0)
        fprintf(stderr, "bpoll_poll: expected 0, not %d\n", i);
    BENCHMARK_END(ts, te, "bpoll_poll (nothing ready yet)");
    fputc('\n', stdout);
  #endif

    const int space = (num_fdpairs / num_active) * 2;

    ssize_t w;  /* w to silence compilier warning for unused result */
    for (int k = 0; k < 200; ++k) {
        /* send data to num_active file descriptors to make ready for read() */
        for (i = 0; i < num_active; ++i)
          #ifndef USE_SPLICE
            w = write(fdpairs[i * space + 1], "e", 1);
          #else
            w = vmsplice(fdpairs[i * space + 1], &iov, 1, SPLICE_F_NONBLOCK);
          #endif
        fired = num_active;
        count = 0 & w; /* & w to silence compiler warning for set but unused */
        writes = num_writes;

      #ifndef BENCH_TIMING

        do {
            bpoll_poll(bpset, bpoll_timespec(bpset));
            if (!fn_cb_event) {
                results = bpoll_get_results(bpset);
                for (i = 0, j = bpoll_get_nfound(bpset); i < j; ++i)
                    read_cb(bpset, results[i], -1);
            }
        } while (count != fired);

      #else  /* BENCH_TIMING - reporting */ 

        BENCHMARK_START(ts);
        bpoll_flush_pending(bpset);
        BENCHMARK_END(ts, te, "bpoll_flush_pending");
        do {
            bpoll_kernel(bpset, bpoll_timespec(bpset));
            BENCHMARK_END(ts, te, "bpoll_kernel");
            bpoll_process(bpset);
            BENCHMARK_END(ts, te, "bpoll_process");
            /*(if fn_cb_event, above includes time taken by callback routines)*/
            if (!fn_cb_event) {
                results = bpoll_get_results(bpset);
                for (i = 0, j = bpoll_get_nfound(bpset); i < j; ++i)
                    read_cb(bpset, results[i], -1);
                BENCHMARK_END(ts, te, "event processing");
            }
        } while (count != fired);
        fputc('\n', stdout);

      #endif /* BENCH_TIMING - reporting */ 
    }

  #ifdef BENCH_TIMING
    /* remove all file descriptors from bpollset (unnecessary unless timing)
     * (BPOLL_FL_CLOSE not set; allow remove, re-add for timing, if desired)*/
    BENCHMARK_START(ts);
    for (i = 0; i < num_fdpairs; ++i) {
        if (bpoll_elt_remove_by_fd(bpset, fdpairs[i<<1]) != 0)
            perror("bpoll_elt_remove");
    }
    BENCHMARK_END(ts, te, "bpoll_elt_remove (loop)");
    bpoll_flush_pending(bpset);
    BENCHMARK_END(ts, te, "bpoll_flush_pending");
  #endif

    bpoll_destroy(bpset);
    BENCHMARK_END(ts, te, "bpoll_destroy");

    free(fdpairs);

    if (0 != errors)
        fprintf(stderr, "errors: %8d\n", errors);

    return (0 != errors);
}

/* NOTE: overhead of epoll_ctl() syscall per file descriptor makes is
 * expensive for lots of adds and removes with little work in between,
 * e.g. adding and removing after only one read or write to descriptor. */
/* TODO: consider writing larger num chars to better simulate real traffic */
