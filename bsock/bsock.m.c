/*
 * bsock - bind() sockets to restricted ports for lower-privilege daemons
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

#include <plasma/plasma_attr.h>
#include <plasma/plasma_stdtypes.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <netdb.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <bsock_addrinfo.h>
#include <bsock_authz.h>
#include <bsock_bindresvport.h>
#include <bsock_daemon.h>
#include <bsock_resvaddr.h>
#include <bsock_syslog.h>
#include <bsock_unix.h>

#include <bpoll/bpoll.h>

#ifndef BSOCK_SYSLOG_IDENT
#define BSOCK_SYSLOG_IDENT "bsock"
#endif

#ifndef BSOCK_SYSLOG_FACILITY
#define BSOCK_SYSLOG_FACILITY LOG_DAEMON
#endif

#ifndef BSOCK_GROUP
#error "BSOCK_GROUP must be defined"
#endif

/* N.B. directory (and tree above it) must be writable only by root */
/* Unit test drivers not run as root should override this location at compile */
#ifndef BSOCK_SOCKET_DIR
#error "BSOCK_SOCKET_DIR must be defined"
#endif
#define BSOCK_SOCKET BSOCK_SOCKET_DIR "/socket"

#ifndef BSOCK_SOCKET_MODE
#define BSOCK_SOCKET_MODE S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP
#endif


#ifdef SO_ACCEPTFILTER  /* OpenBSD, FreeBSD, NetBSD */
#define BSOCK_UNIX_ACCEPTFILTER
#endif

/* Note: Linux does not support TCP_DEFER_ACCEPT on AF_UNIX sockets;
 * setsockopt TCP_DEFER_ACCEPT on AF_UNIX socket returns EOPNOTSUPP:
 * "Operation not supported" */
#if 0  /* disabled */
#ifdef __linux__
#include <netinet/in.h>   /* IPPROTO_TCP */
#include <netinet/tcp.h>  /* TCP_DEFER_ACCEPT */
#ifdef TCP_DEFER_ACCEPT
#define BSOCK_UNIX_ACCEPTFILTER
#endif
#endif
#endif

/* main() assumes MSG_DONTWAIT support if BSOCK_UNIX_ACCEPTFILTER and
 * this assumption is true for Linux and *BSD, but check here for others
 * (or fcntl c->fd F_SETFL O_NONBLOCK before speculative bsock_addrinfo_recv) */
#ifndef MSG_DONTWAIT
#undef BSOCK_UNIX_ACCEPTFILTER
#endif


/* MSG_DONTWAIT is defined to MSG_DONTWAIT on Linux;
 * preprocessor does not see the actual enum value;
 * unexpected result with #if !defined(MSG_DONTWAIT) || (MSG_DONTWAIT-0 == 0) */
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif


#if !(defined(_POSIX_TIMERS) && _POSIX_TIMERS >= 200112L) \
 && !defined(__CYGWIN__)
/* Mac OSX does not implement POSIX Advanced Realtime extensions (POSIX.1-2001),
 * even though this comment is being written in 2015, 14 years later (!)
 * Since this file is application-level code, provide kludge replacements for
 * timer_create(), timer_settime(), and timer_delete() using setitimer()
 * (with lower time resolution), though marked deprecated in POSIX.1-2008.
 * These kludges are very specific to the use herein; not generic. */
#include <sys/time.h>
struct itimerspec {
  struct timespec it_interval;
  struct timespec it_value;
};
/*(avoid compiler warnings/errors for unused variables; set timerid to 0)*/
typedef int timer_t;
#define timer_create(clockid, sevp, timerid) (*(timerid) = 0)
#define timer_delete(timerid) do { } while (timerid)
/*(tv_nsec not used by bsock.m.c, so cast to itimerval for ease)*/
/*(XXX: _Static_assert sizeof(struct itimerspec) == sizeof(struct itimerval) )*/
#define timer_settime(a,b,it,ot) \
  setitimer(ITIMER_REAL, ((struct itimerval *)(it)), ((struct itimerval *)(ot)))
#endif

/* nointr_close() - make effort to avoid leaking open file descriptors */
static int
nointr_close (const int fd)
{ int r; retry_eintr_do_while(r = close(fd), r != 0); return r; }

static volatile sig_atomic_t signalled_hup = true;

static void
bsock_sa_handler_sighup (const int signo  __attribute_unused__)
{
    signalled_hup = true; /*set flag to run reconfigure steps when convenient*/
}

__attribute_cold__
__attribute_noinline__
static void
bsock_sigaction_sighup (void)
{
    /* efficiency: keep databases open (advantageous for nss_mcdb module) */
    /* perform database open in event thread (thread-specific in nss_mcdb)*/
    setprotoent(1);
    setservent(1);

    /* refresh table of persistent reserved addresses */
    bsock_resvaddr_config();
    /* refresh table of authorized username/address/port */
    bsock_authz_config();

    endprotoent();
    endservent();
}

static time_t epochsec;

static void
bsock_sa_handler_sigalrm (const int signo  __attribute_unused__)
{
    ++epochsec;
    /* Note: bsock is not concerned with precision less than +/- 1 sec,
     * or else this signal handler could use clock_gettime() to calculate
     * drift and timer_gettime() and timer_settime() to adjust.
     * (clock_gettime(), timer_gettime(), timer_settime() are async-signal-safe)
     * Would need to modify sigaction() to pass SA_SIGINFO to obtain timer_t,
     * and to modify the parameters taken by this routine to receive siginfo_t.
     * In addition, timerfd would be preferred over signal handler to avoid
     * race condition of signal received right before bpoll_poll(), resulting
     * in extra interval passing before bpoll_poll() interrupted by SIGALRM.
     * On the other hand, if we were to be more lax about precision in cleaning
     * up idle connections, use sigevent SIGEV_THREAD instead of signal handler
     * and have bpoll_poll() return e.g. once a min instead of once a sec */
}

/* simple fixed-size statically allocated hash table
 * using statically allocated elements (to enforce max connections)
 * (not expecting many simultaneous requests; one connection per uid limit)*/
#define BSOCK_CONNECTION_TABLE_SZ 32  /* must be power of two */
#define BSOCK_CONNECTION_MAX 128
struct bsock_uid_table_st {
    struct bsock_uid_table_st *next;
    uid_t uid;
};
static struct bsock_uid_table_st bsock_uid_elts[BSOCK_CONNECTION_MAX];
static struct bsock_uid_table_st * bsock_uid_table[BSOCK_CONNECTION_TABLE_SZ];
static struct bsock_uid_table_st * bsock_uid_head;

static void
bsock_uid_table_init (void)
{
    bsock_uid_head = bsock_uid_elts;
    for (unsigned int i = 0; i < BSOCK_CONNECTION_MAX-1; ++i)
        bsock_uid_elts[i].next = &bsock_uid_elts[i+1];
    bsock_uid_elts[BSOCK_CONNECTION_MAX-1].next = NULL;
}

static bool
bsock_uid_table_add (const uid_t uid)
{
    struct bsock_uid_table_st ** const next =
      &bsock_uid_table[(uid & (BSOCK_CONNECTION_TABLE_SZ-1))];
    /* check if uid already in table */
    struct bsock_uid_table_st *t = *next;
    while (NULL != t && t->uid != uid)
        t = t->next;
    /* get element from bsock_uid_head if uid not already in table */
    if (NULL == t && NULL != (t = bsock_uid_head)) {
        bsock_uid_head = t->next;
        t->uid  = uid;
        t->next = *next;
        *next   = t;
        return true;
    }
    return false;
}

static void
bsock_uid_table_remove (const uid_t uid)
{
    struct bsock_uid_table_st **prev =
      &bsock_uid_table[(uid & (BSOCK_CONNECTION_TABLE_SZ-1))];
    struct bsock_uid_table_st *t = *prev;
    while (NULL != t && t->uid != uid)
        t = *(prev = &t->next);
    if (NULL != t) {
        *prev = t->next;
        t->next = bsock_uid_head;
        bsock_uid_head = t;
    }
}

static size_t bsock_ctrlbuf_sz;
static char *bsock_ctrlbuf;

/* preallocate bsock_ctrlbuf */
static bool
bsock_ctrlbuf_alloc (void)
{
    /* 16MB arbitrary sanity check limit borders on absurd; expecting 10-40KB */
    bsock_ctrlbuf_sz = bsock_daemon_msg_control_max();
    if (bsock_ctrlbuf_sz <= 16777216)
        bsock_ctrlbuf = malloc(bsock_ctrlbuf_sz);
    if (bsock_ctrlbuf != NULL)
        return true;
    else {
        bsock_syslog(errno, LOG_ERR, "max ancillary data very "
          "large (?); error in malloc(%zu)", bsock_ctrlbuf_sz);
        return false;
    }
}

struct bsock_client_st {
  int fd;
  int uid_table;
  uid_t uid;
  gid_t gid;
  struct bsock_client_st *tprev;
  struct bsock_client_st *tnext;
  time_t tstamp;
};

__attribute_nonnull__()
static int
bsock_client_handler (struct bsock_client_st * const restrict c,
                      struct addrinfo * const restrict ai,
                      int fd)
{
    int nfd = -1;
    int rc = EXIT_FAILURE;
    int flag;
    struct iovec iov = { .iov_base = &flag, .iov_len = sizeof(flag) };

    do {  /*(required steps follow block in order to send response to client)*/

        if (0 == ai->ai_addrlen) { /* overloaded to indicate error if value 0 */
            break;
        }

        /* check client credentials to authorize client request */
        if (!bsock_authz_validate(ai, c->uid, c->gid))
            break;

        /* check if addr, port already reserved and bound in bsock cache
         * (Note: fd is intentionally not set to nfd to avoid cleanup close) */
        if (-1 != (nfd = bsock_resvaddr_fd(ai))) {
            if (c->fd != fd)
                rc = EXIT_SUCCESS;
            else  /* (incompatible (unsupportable) with authbind (c->fd==fd)) */
                errno = EACCES;
            break;
        }

        /* create socket (if not provided by client) */
        if (-1 == fd) {
            fd = nfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (-1 == nfd) {
                bsock_syslog(errno, LOG_ERR, "socket");
                break;
            }
        }

        if (AF_INET == ai->ai_family || AF_INET6 == ai->ai_family) {
            if (0 == (AF_INET == ai->ai_family
                      ? ((struct sockaddr_in *)ai->ai_addr)->sin_port
                      : ((struct sockaddr_in6 *)ai->ai_addr)->sin6_port)) {
                /* bind to reserved port (special-case port == 0) */
                if (0 == bsock_bindresvport_sa(fd, ai->ai_addr))
                    rc = EXIT_SUCCESS;
                else
                    bsock_syslog(errno, LOG_ERR, "bindresvport_sa");
                break;  /* break out of while(0) on either success or failure */
            }
            else {
                /* set SO_REUSEADDR socket option */
                flag = 1;
                if (0 != setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                                    &flag, sizeof(flag))) {
                    bsock_syslog(errno, LOG_ERR, "setsockopt");
                    break;
                }
            }
        }

        /* bind to address */
        if (0 == bind(fd, ai->ai_addr, ai->ai_addrlen))
            rc = EXIT_SUCCESS;
        else
            bsock_syslog(errno, LOG_ERR, "bind");

    } while (0);

    if (rc == EXIT_SUCCESS)
        flag = 0;       /*(iov.iov_base = &flag)*/
    else if (0 == (flag = errno))
        flag = EACCES;  /*(iov.iov_base = &flag)*/

    /* send 4-byte value in data to indicate success or errno value
     * (send socket fd to client if new socket, no poll since only one send) */
    if (c->fd != fd) {
        /* poll()d before recv above, so can defer O_NONBLOCK to here */
        if (!MSG_DONTWAIT)
            (void)fcntl(c->fd, F_SETFL, fcntl(c->fd, F_GETFL, 0) | O_NONBLOCK);
        rc = (bsock_unix_send_fds(c->fd, &nfd, (-1 != nfd), &iov, 1)
              == (ssize_t)iov.iov_len)
          ? EXIT_SUCCESS
          : EXIT_FAILURE;
        if (rc == EXIT_FAILURE && errno != EPIPE && errno != ECONNRESET)
            bsock_syslog(errno, LOG_ERR, "sendmsg");
        if (-1 != fd)
            nointr_close(fd);
    }
    else
        rc = flag;  /* authbind: set exit value */

    return rc;
}

__attribute_nonnull__()
static int
bsock_client_event (struct bsock_client_st * const restrict c,
                    struct addrinfo * const restrict ai)
{
    /* receive addrinfo from client and handle request */
    /* using preallocated buffer avoids MSG_CTRUNC but dictates single thread */
    int fd = -1;
    if (!bsock_addrinfo_recv_ex(c->fd,ai,&fd,bsock_ctrlbuf,bsock_ctrlbuf_sz)) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return EAGAIN;       /* socket not ready; must poll for dataready */
        else {
            ai->ai_addrlen = 0;  /* overloaded flag to send error in response */
            bsock_syslog(errno, LOG_ERR,
                         "(uid:%u) recv addrinfo error or invalid addrinfo",
                         (uint32_t)c->uid);
        }
    }
    bsock_client_handler(c, ai, fd);     /* ignore rc; client request handled */
    /* caller must close(c->fd) as appropriate
     * (defer to caller so that bpollset can manage close(c->fd)) */
    return 0;
}

__attribute_cold__
__attribute_noinline__
static void
bsock_client_send_errno (const int fd, int errnum)
{
    /* one-shot response; send buffer should be empty and should not block */
    struct iovec iov = { .iov_base = &errnum, .iov_len = sizeof(int) };
    (void)bsock_unix_send_fds(fd,NULL,0,&iov,1); /* no err chk; send & forget */
}

static void
bsock_bpollelt_cb_close (bpollset_t * const restrict bpollset
                           __attribute_unused__,
                         bpollelt_t * const restrict bpollelt)
{
    struct bsock_client_st * const c=(struct bsock_client_st *) bpollelt->udata;
    if (c->uid_table)
        bsock_uid_table_remove(c->uid);
    if (c->tprev != NULL) { /* remove from linked list ordered by req time */
        c->tprev->tnext = c->tnext;
        c->tnext->tprev = c->tprev;
    }
    nointr_close(c->fd);
}

/* (similar to uint32_to_ascii_base10_loop() in
 *   https://github.com/gstrauss/mcdb/blob/master/uint32.c ) */
__attribute_nonnull__()
static int
uint32_to_str(uint32_t u, char * const buf)
{
    char * restrict out = buf;
    int n = 0;
    char tmp[10];
    do { tmp[n++] = '0' + (u % 10); } while ((u /= 10));
    do { *out++ = tmp[--n]; } while (n);
    return (int)(out - buf);
}

__attribute_noinline__
__attribute_nonnull__()
static void
bsock_infostr (char * restrict infobuf,
               const int fd, const uid_t uid, const gid_t gid)
{
    /* snprintf() can be expensive so special-case LOG_INFO.
     * (snprintf() took 1.5 usec with fmtstr below -- as much as a system call!)
     * snprintf(info, sizeof(info), "fd(%d) uid:%u gid:%u",
     *          fd, (uint32_t)uid, (uint32_t)gid);
     * We assume buffer large enough to hold fmtstr plus (3) 10-digit uint32_t,
     * i.e. our callers pass 64-byte buffer, and fd should not be negative. */
    infobuf[0] = 'f';
    infobuf[1] = 'd';
    infobuf[2] = '(';
    infobuf += 3;
    infobuf += uint32_to_str((uint32_t)fd, infobuf);
    infobuf[0] = ')';
    infobuf[1] = ' ';
    infobuf[2] = 'u';
    infobuf[3] = 'i';
    infobuf[4] = 'd';
    infobuf[5] = ':';
    infobuf += 6;
    infobuf += uint32_to_str((uint32_t)uid, infobuf);
    infobuf[0] = ' ';
    infobuf[1] = 'g';
    infobuf[2] = 'i';
    infobuf[3] = 'd';
    infobuf[4] = ':';
    infobuf += 5;
    infobuf += uint32_to_str((uint32_t)gid, infobuf);
    infobuf[0] = '\0';
}

__attribute_nonnull__()
static bool
bsock_bpollset_add (struct bsock_client_st * const restrict m,
                    struct bsock_client_st * const restrict sentinel,
                    bpollset_t * const restrict bpollset)
{
    /* add client fd to bpollset
     * allocate connection table entry; permit one request at a time per uid
     * and limit the number of outstanding requests (if requests block) */
    if (!bpoll_get_is_full(bpollset) && bsock_uid_table_add(m->uid)) {
        bpollelt_t * const restrict bpollelt =
          bpoll_elt_init(bpollset,NULL,m->fd,BPOLL_FD_SOCKET,BPOLL_FL_CLOSE);
        if (NULL != bpollelt
            && 0 == bpoll_elt_add(bpollset, bpollelt, BPOLLIN)) {
            /* attach client connection info to bpollelt user data.
             * add to doubly-linked list ordered by request time */
            m->uid_table    = 1;
            m->tstamp       = sentinel->tstamp;
            m->tnext        = sentinel;
            m->tprev        = sentinel->tprev;
            m->tprev->tnext = sentinel->tprev = (struct bsock_client_st *)
              memcpy(bpollelt->udata, m, sizeof(struct bsock_client_st));
            m->fd = -1; /*flag to not close m->fd; still waiting to process it*/
            return true;
        }
        else {
            if (NULL == bpollelt)
                bsock_syslog(errno, LOG_ERR, "bpoll_elt_init");
            else {
                bsock_syslog(errno, LOG_WARNING, "bpoll_elt_add");
                bpoll_elt_destroy(bpollset, bpollelt);
            }
            bsock_uid_table_remove(m->uid);
            /*(send EAGAIN instead of ENOMEM or ENOSPC or others)*/
        }
    }
    /* else sendmsg with EAGAIN; permit only one request at a time per uid */
    return false;
}

__attribute_nonnull__()
static int
bsock_accept_loop (const int sfd,
                   struct bsock_client_st * const restrict sentinel,
                   bpollset_t * const restrict bpollset)
{
    struct bsock_client_st m = { .fd = -1 };
    struct sockaddr_storage addr;
    struct addrinfo ai = {  /* init only fields used to pass buf and bufsize */
      .ai_addrlen = sizeof(addr),
      .ai_addr    = (struct sockaddr *)&addr
    };
    int accept_max = 64; /* set limit to avoid starvation of bpollset fds */
    int rv = EAGAIN;
    int logbuf_idx = 0; /* logbuf[] MUST be sized to hold accept_max entries! */
    char logbuf[8192];  /* accept_max * (63 bytes (max) + '\0') per log entry */

    /* accept loop
     * accept, get client credentials, insert into table, handle ready events */
    do {
        /* accept new connection, get client credentials,
         * buffer LOG_INFO entries (64-byte fixed record size for simplicity)
         * handle client request (if data ready) or else add to bpollset
         * (speculative recv: see if data ready; skip unnecessary poll) */
        if (-1 != (m.fd = accept(sfd, NULL, NULL))) {
            if (0 == bsock_unix_getpeereid(m.fd, &m.uid, &m.gid)) {
                bsock_infostr(logbuf+logbuf_idx, m.fd, m.uid, m.gid);
                logbuf_idx += 64;
                /*(set O_NONBLOCK if non-blocking recvmsg() is unsupported)*/
                if (!MSG_DONTWAIT)
                    fcntl(m.fd, F_SETFL, fcntl(m.fd, F_GETFL, 0) | O_NONBLOCK);
                ai.ai_addrlen = sizeof(addr);         /* reset value each use */
                if (0 != bsock_client_event(&m, &ai)  /*handle or bpollset add*/
                    && !bsock_bpollset_add(&m,sentinel,bpollset))
                    /* XXX: ? bsock_syslog() if bpoll_get_is_full(bpollset) ?
                     *      (if so, rate limit warnings to avoid spew) */
                    bsock_client_send_errno(m.fd, EAGAIN);
            }       /*see bsock_bind_viasock()*/
            else
                bsock_syslog(errno, LOG_ERR, "getpeereid");

            if (-1 != m.fd)  /* close client fd (unless added to bpollset) */
                nointr_close(m.fd);
        }
        else {
            switch (errno) {
              case EMFILE:/* return EAGAIN to close completed requests, retry */
             #if EAGAIN != EWOULDBLOCK
              case EWOULDBLOCK:
             #endif
              case EAGAIN:break; /* rv == EAGAIN; */
              case ECONNABORTED:
              case EINTR: continue;
              case EBADF:
              case EINVAL:/* listen sfd closed by another thread */
                          rv = EXIT_SUCCESS; break;
              default:    /* temporary process/system resource issue */
                          /*(see also man accept() "Error Handling" on Linux)*/
                          bsock_syslog(errno, LOG_ERR, "accept");
                          (void)poll(NULL, 0, 10); /* pause 10ms and continue */
                          continue;
            }
            break;
        }

    } while (--accept_max);

    /* flush buffered LOG_INFO entries
     * (log info can be extremely useful, but it is not free;
     *  there can be measurable cost to info/metrics collection) */
    for (int idx = 0; idx < logbuf_idx; idx+=64)
        bsock_syslog(0, LOG_INFO, "%s", logbuf+idx);

    return rv;
}

static int
bsock_event_loop (const int sfd)
{
    bpollelt_t * bpollelt;
    bpollelt_t ** results;
    bpollset_t * const restrict bpollset =
      bpoll_create(NULL, NULL, bsock_bpollelt_cb_close, NULL, NULL);
    struct bsock_client_st *c;
    struct sockaddr_storage addr;
    struct addrinfo ai = {  /* init only fields used to pass buf and bufsize */
      .ai_addrlen = sizeof(addr),
      .ai_addr    = (struct sockaddr *)&addr
    };
    struct bsock_client_st sentinel;
    int i, accepting = 0, nfound;
    timer_t timerid;
    struct itimerspec it = { {1,0}, {0,0} }; /* init it_interval to 1 sec */
    sentinel.tprev = sentinel.tnext = &sentinel;
    sentinel.tstamp = 0;

    /* create/init bpollset and add sfd
     * typical expected bsock use is low concurrency;
     * use BPOLL_M_POLL instead of BPOLL_M_NOT_SET
     * No cleanup of bpollset is done on error since program exits soon after */
    if (NULL == bpollset
        || 0 != bpoll_init(bpollset, BPOLL_M_POLL,
                           BSOCK_CONNECTION_MAX, BSOCK_CONNECTION_MAX,
                           sizeof(struct bsock_client_st))) {
        bsock_syslog(errno, LOG_ERR, "bpoll_create, bpoll_init");
        return EXIT_FAILURE;
    }
    (void)fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL, 0) | O_NONBLOCK);
    bpollelt = bpoll_elt_init(bpollset,NULL,sfd,BPOLL_FD_SOCKET,BPOLL_FL_CLOSE);
    if (NULL == bpollelt
        || 0 != bpoll_elt_add(bpollset, bpollelt, BPOLLIN)) {
        bsock_syslog(errno, LOG_ERR,
                     "bpoll_elt_init, bpoll_elt_add");
        return EXIT_FAILURE;
    }

    if (!bsock_ctrlbuf_alloc())
        return EXIT_FAILURE;

    /* create interval timer (disarmed), set bpoll_poll() timer 60 secs
     * so that bpoll_poll() periodically returns and checks for sighup */
    if (timer_create(CLOCK_REALTIME, NULL, &timerid) == 0)
        bpoll_timespec_from_sec_nsec(bpollset, 60, 0);
    else {
        bsock_syslog(errno, LOG_ERR, "timer_create");
        return EXIT_FAILURE;
    }

    /* daemon event loop; handle ready events before accept()ing new requests */
    do {

        /* check if interval timer needs to be enabled/disabled
         * (timer SIGALRM will interrupt bpoll_poll(), when timer is set)
         * (interval timer is more efficient than calling time() after
         *  returning from each and every bpoll_poll() */
        if (sentinel.tnext != &sentinel) {  /* client connections exist */
            if (it.it_value.tv_sec == 0) {
                it.it_value.tv_sec  = 1;    /* arm timer; tv_sec|tv_nsec != 0 */
                timer_settime(timerid, 0, &it, NULL);
            }
        }
        else {                              /* listen sock only */
            if (it.it_value.tv_sec != 0) {
                it.it_value.tv_sec  = 0;    /* disarm timer; tv_sec=tv_nsec=0 */
                timer_settime(timerid, 0, &it, NULL);
            }
        }

        nfound = bpoll_poll(bpollset, bpoll_timespec(bpollset));

        if (-1 == nfound && errno != EINTR) {  /* should not happen */
            bsock_syslog(errno, LOG_ERR, "bpoll_poll");
            /* use nanosleep() to avoid sleep() and SIGALRM interaction */
            nanosleep(&it.it_interval, NULL);/* reuse 'it' timespec for 1 sec */
        } /* fall through to do processing */

        /* efficiency: keep databases open (advantageous for nss_mcdb module) */
        /* perform database open in event thread (thread-specific in nss_mcdb)*/
        if (signalled_hup) {
            signalled_hup = false;
            bsock_sigaction_sighup();
        }

        results = bpoll_get_results(bpollset);
        for (i = 0; i < nfound; ++i) {
            bpollelt = results[i];
            c = (struct bsock_client_st *) bpollelt->udata;
            if (bpollelt->fd == sfd) { accepting = 1; continue; }
            ai.ai_addrlen = sizeof(addr);             /* reset value each use */
            if ((bpollelt->events & BPOLLERR)
                || 0 != bsock_client_event(c, &ai)) {
                /* EAGAIN; should not happen after returned ready in bpollset */
                bsock_syslog(EAGAIN, LOG_WARNING,
                             "(uid:%u) recvmsg(%d) not ready",
                             (uint32_t)c->uid, c->fd);
                bsock_client_send_errno(c->fd,EAGAIN);/*see bsock_bind_viasock*/
            }
            /* Aside: bsock requests handled as one packet in, one packet out.
             * Were bpollelt to stay in bpollset, would need to clear revents
             * i.e. bpoll_elt_clear_revents(bpollelt);
             *      after handling revents */
            /* bpollset defers fd close (and cleanup events on close), so update
             * uid tables and timer linked list above instead of waiting for
             * bsock_bpollelt_cb_close() callback.  Waiting for cleanup might
             * delay servicing next client request, or might trigger alarm below
             * causing socket to be handled a second time, which is incorrect.*/
            c->uid_table = 0;
            bsock_uid_table_remove(c->uid);
            /* remove from linked list ordered by req time */
            c->tprev->tnext = c->tnext;
            c->tnext->tprev = c->tprev;
            c->tprev = c->tnext = NULL;
            bpoll_elt_remove(bpollset, bpollelt); /*(BPOLL_FL_CLOSE fd)*/
        }

        /* coarse precision to +/- 1 sec good enough for our use, so make
         * connection timeout at least 2 secs so at least 1 sec has to pass */
        sentinel.tstamp =
          (it.it_value.tv_sec != 0) ? epochsec : (epochsec = time(NULL));
        c = sentinel.tnext;  /* loop exits immediately if tnext == &sentinal */
        while (sentinel.tstamp - c->tstamp >= 2) {/* 2 sec timeout (+/- 1 sec)*/
            bsock_syslog(ETIME, LOG_WARNING, "(uid:%u) recvmsg(%d) timed out",
                         (uint32_t)c->uid, c->fd);
            bsock_client_send_errno(c->fd, ETIME);   /*see bsock_bind_addrinfo*/
            bpoll_elt_remove_by_fd(bpollset,c->fd);  /*(BPOLL_FL_CLOSE fd)*/
            c = c->tnext;
        }

        /* loop for more ready events before accepting new, if nfound hit max
         * (on the other hand, waiting too long to accept new connections might
         *  result in full kernel TCP SYN queue, and packets getting dropped) */
    } while (   !accepting
             || nfound == BSOCK_CONNECTION_MAX /*(? is this test useful ?)*/
             || (accepting = 0,
                 bsock_accept_loop(sfd,&sentinel,bpollset) == EAGAIN)   );

    timer_delete(timerid);
    bpoll_destroy(bpollset);
    return EXIT_SUCCESS;
}

static int
retry_poll_fd (const int fd, const short events, const int timeout)
{
    struct pollfd pfd = { .fd = fd, .events = events, .revents = 0 };
    int n; /*EINTR results in retrying poll with same timeout again and again*/
    retry_eintr_do_while(n = poll(&pfd, 1, timeout), -1 == n);
    if (0 == n) errno = ETIME; /* specific for bsock; not generic */
    return n;
}

/* one-shot mode; handle single request and exit */
__attribute_cold__
__attribute_noinline__
__attribute_nonnull__()
static int
bsock_client_once (const int argc, char ** const restrict argv)
{
    struct bsock_client_st m;
    struct bsock_addrinfo_strs aistr;
    struct stat st;
    struct sockaddr_storage addr;
    struct addrinfo ai = { /*init only fields used to pass buf and bufsize*/
      .ai_addrlen = sizeof(addr),
      .ai_addr    = (struct sockaddr *)&addr
    };
    int fd = -1, rc;
    char info[64];
    if (0 != fstat(STDIN_FILENO, &st)) {
        bsock_syslog(errno, LOG_ERR, "(uid:%u) fstat stdin",(uint32_t)getuid());
        return EXIT_FAILURE;
    }
    if (!S_ISSOCK(st.st_mode)) {
        bsock_syslog(ENOTSOCK, LOG_ERR,
                     "(uid:%u) invalid socket on bsock stdin",
                     (uint32_t)getuid());
        return EXIT_FAILURE; /* STDIN_FILENO must be socket for one-shot */
    }
    switch (argc) {
      case 0: break;
      case 1: if (bsock_addrinfo_split_str(&aistr, argv[0]))
                  break;
              bsock_syslog(errno, LOG_ERR,
                           "(uid:%u) invalid address info arguments",
                           (uint32_t)getuid());
              return EXIT_FAILURE;
      case 5: aistr.family   = argv[0];
              aistr.socktype = argv[1];
              aistr.protocol = argv[2];
              aistr.service  = argv[3];
              aistr.addr     = argv[4];
              break;
      default: bsock_syslog(EINVAL, LOG_ERR,
                            "(uid:%u) invalid number of arguments",
                            (uint32_t)getuid());
               return EXIT_FAILURE;
    }

    m.fd  = STDIN_FILENO;
    m.uid = (uid_t)-1;
    m.gid = (gid_t)-1;

    /* get client credentials (non-daemon mode) */
    if (0 != argc) {
        /* authbind: client provided as stdin the socket to which to bind()
         *(http://www.chiark.greenend.org.uk/ucgi/~ijackson/cvsweb/authbind)
         * bsock has args and stdin is not a connected socket.
         * bsock is running setuid; use real uid, gid as credentials */
        /*(On AIX, ai.ai_addrlen is size_t, so cast to socklen_t for 64-bit
         * compilation.  Only valid here since addrlen result is ignored) */
        if (0 != getpeername(m.fd, ai.ai_addr, (socklen_t *)&ai.ai_addrlen)) {
            if (errno == ENOTCONN) {
                fd = m.fd;
                m.uid = getuid();
                m.gid = getgid();
            }
            else {
                bsock_syslog(errno, LOG_ERR, "(uid:%u) getpeername",
                             (uint32_t)getuid());
                return EXIT_FAILURE;
            }
        }
        ai.ai_addrlen = sizeof(addr); /*reset addr size after getpeername()*/
    }
    if ((uid_t)-1 == m.uid) {
        if (0 != bsock_unix_getpeereid(m.fd, &m.uid, &m.gid)) {
            bsock_syslog(errno, LOG_ERR, "getpeereid");
            return EXIT_FAILURE;
        }
    }
    bsock_infostr(info, m.fd, m.uid, m.gid);

    /* receive addrinfo from client */
    if (!(0 == argc
          ? 1 == retry_poll_fd(m.fd, POLLIN, 2000)
            && bsock_addrinfo_recv(m.fd, &ai, &fd)    /* args from socket  */
          : bsock_addrinfo_from_strs(&ai, &aistr))) { /* command line args */
        ai.ai_addrlen = 0;    /* overloaded flag to send error in response */
        bsock_syslog(errno, LOG_ERR,
                     "(uid:%u) recv addrinfo error or invalid addrinfo",
                     (uint32_t)m.uid);
    }

    rc = bsock_client_handler(&m, &ai, fd);
    bsock_syslog(0, LOG_INFO, "%s", info); /*deferred to not delay response*/
    /*(not bothering to close() m.fd or fd since program is exiting)*/
    return rc;
}

__attribute_nonnull__()
int
main (int argc, char *argv[])
{
    int sfd, opt, daemon = false, supervised = false;
    struct group *gr;

    /* setuid safety measures must be performed before anything else */
    if (!bsock_daemon_setuid_stdinit())
        return EXIT_FAILURE;

    /* openlog() for syslog() */
    bsock_syslog_openlog(BSOCK_SYSLOG_IDENT, LOG_NDELAY, BSOCK_SYSLOG_FACILITY);

    /* parse arguments */
    while ((opt = getopt(argc, argv, "dhF")) != -1
           || (daemon && optind != argc)) { /* no additional args for daemon */
        switch (opt) {
          case 'd': daemon = true; break;
          case 'F': supervised = true; break;
          default:  if (0 != getuid()) /*(syslog here; not bsock_syslog)*/
                        syslog(LOG_ERR,"bad arguments sent by uid %d",getuid());
                    fprintf(stderr, "\nerror: invalid arguments\n");/*fallthru*/
          case 'h': fprintf((opt == 'h' ? stdout : stderr), "\n"
                            "  bsock -h\n"
                            "  bsock -d [-F]\n"
                            "  bsock <addr_family> <socktype> <protocol> "
                                        "<service_or_port> <addr>\n\n");
                    return (opt == 'h' ? EXIT_SUCCESS : EXIT_FAILURE);
        }
    }

    /*
     * one-shot mode; handle single request and exit
     */

    if (!daemon)
        return bsock_client_once(argc-optind, argv+optind);

    /*
     * daemon mode
     */

    if (getuid() != geteuid()) {
        /* do not permit setuid privileges to initiate daemon mode */
        bsock_syslog(EACCES, LOG_ERR, "daemon can not be started via setuid");
        return EXIT_FAILURE;
    }

    if (NULL == (gr = getgrnam(BSOCK_GROUP))) { /*ok; no other threads yet*/
        bsock_syslog(errno, LOG_ERR, "getgrnam");
        return EXIT_FAILURE;
    }

    if (!bsock_daemon_init(supervised, false))  /*(and skip optmem_max check)*/
        return EXIT_FAILURE;

    sfd = bsock_daemon_init_socket(BSOCK_SOCKET, geteuid(), gr->gr_gid,
                                   BSOCK_SOCKET_MODE);
    if (-1 == sfd)
        return EXIT_FAILURE;

  #ifdef BSOCK_UNIX_ACCEPTFILTER
    {
      #if defined(SO_ACCEPTFILTER)
        /* setsockopt SO_ACCEPTFILTER must be after listen() */
        /* http://www.freebsd.org/cgi/man.cgi?query=setsockopt */
        /* http://www.freebsd.org/cgi/man.cgi?query=accept_filter */
        /* http://www.freebsd.org/cgi/man.cgi?query=accf_data */
        struct accept_filter_arg af = { .af_name = "dataready", .af_arg  = "" };
        if (0 != setsockopt(sfd, SOL_SOCKET, SO_ACCEPTFILTER, &af, sizeof(af)))
            bsock_syslog(errno, LOG_WARNING, "setsockopt SO_ACCEPTFILTER");
      #elif defined(TCP_DEFER_ACCEPT) && 0  /* disabled */
        /* Note: Linux does not support TCP_DEFER_ACCEPT on AF_UNIX sockets;
         * setsockopt TCP_DEFER_ACCEPT on AF_UNIX socket returns EOPNOTSUPP:
         * "Operation not supported" */
        int timeout = 2;  /* 2 secs; kernel converts to num TCP retransmits */
        if (0 != setsockopt(sfd, SOL_TCP, TCP_DEFER_ACCEPT,
                            &timeout, sizeof(timeout)))
            bsock_syslog(errno, LOG_WARNING, "setsockopt TCP_DEFER_ACCEPT");
      #endif
    }
  #endif

    bsock_uid_table_init();  /* used to permit one concurrent request per uid */

    {
        struct sigaction act = { .sa_handler = bsock_sa_handler_sighup,
                                 .sa_flags   = SA_RESTART };
        sigemptyset(&act.sa_mask);
        if (0 != sigaction(SIGHUP, &act, NULL))
            bsock_syslog(errno, LOG_ERR, "sigaction");
        act.sa_handler = bsock_sa_handler_sigalrm;
        if (0 != sigaction(SIGALRM, &act, NULL))
            bsock_syslog(errno, LOG_ERR, "sigaction");
    }

    bsock_sigaction_sighup();  /* trigger initial config setup */
    return bsock_event_loop(sfd);
}
