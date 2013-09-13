/*
 * bsock - bind() sockets to restricted ports for lower-privilege daemons
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <netdb.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <bsock_addrinfo.h>
#include <bsock_authz.h>
#include <bsock_bindresvport.h>
#include <bsock_daemon.h>
#include <bsock_resvaddr.h>
#include <bsock_syslog.h>
#include <bsock_unix.h>

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

/* bsock_client_thread assumes MSG_DONTWAIT support if BSOCK_UNIX_ACCEPTFILTER
 * and this assumption is true for Linux and *BSD, but check here for others
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


/* nointr_close() - make effort to avoid leaking open file descriptors */
static int
nointr_close (const int fd)
{ int r; do { r = close(fd); } while (r != 0 && errno == EINTR); return r; }

static int  __attribute__((noinline))
retry_poll_fd (const int fd, const short events, const int timeout)
{
    struct pollfd pfd = { .fd = fd, .events = events, .revents = 0 };
    int n; /*EINTR results in retrying poll with same timeout again and again*/
    do { n = poll(&pfd, 1, timeout); } while (-1 == n && errno == EINTR);
    if (0 == n) errno = ETIME; /* specific for bsock; not generic */
    return n;
}

static void  __attribute__((nonnull))
bsock_cleanup_close (void * const arg)
{
    const int fd = *(int *)arg;
    if (-1 != fd)
        nointr_close(fd);
}

struct bsock_client_st {
  struct bsock_client_st *next;
  int fd;
  uid_t uid;
  gid_t gid;
};

/* simple fixed-size statically allocated hash table
 * using statically allocated elements (enforces max threads)
 * accessed read/write while holding mutex
 * (not expecting many simultaneous requests; limiting one thread max per uid)*/
#define BSOCK_THREAD_TABLE_SZ 32  /* must be power of two */
#define BSOCK_THREAD_MAX 128
static pthread_mutex_t bsock_thread_table_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct bsock_client_st bsock_thread_elts[BSOCK_THREAD_MAX];
static struct bsock_client_st * bsock_thread_head = bsock_thread_elts;
static struct bsock_client_st * bsock_thread_table[BSOCK_THREAD_TABLE_SZ];

static void
bsock_thread_table_init (void)
{
    for (unsigned int i = 0; i < BSOCK_THREAD_MAX-1; ++i)
        bsock_thread_elts[i].next = &bsock_thread_elts[i+1];
    bsock_thread_elts[BSOCK_THREAD_MAX-1].next = NULL;
}

static struct bsock_client_st *  __attribute__((nonnull))
bsock_thread_table_query (const struct bsock_client_st * const c)
{
    const uid_t uid = c->uid;
    struct bsock_client_st *t = 
      bsock_thread_table[(uid & (BSOCK_THREAD_TABLE_SZ-1))];
    while (NULL != t && t->uid != uid)
        t = t->next;
    return t;
}

static struct bsock_client_st *  __attribute__((nonnull))
bsock_thread_table_add (struct bsock_client_st * const c)
{
    /* (not checking for multiple-add of same uid (do not do that)) */
    struct bsock_client_st ** const next =
      &bsock_thread_table[(c->uid & (BSOCK_THREAD_TABLE_SZ-1))];
    struct bsock_client_st * const t = bsock_thread_head;
    if (NULL == t)
        return NULL;
    bsock_thread_head = t->next;
    memcpy(t, c, sizeof(struct bsock_client_st));
    t->next = *next;
    return (*next = t);
}

static void  __attribute__((nonnull))
bsock_thread_table_remove (struct bsock_client_st * const c)
{
    /* (removes only first uid found if multiple (should not happen)) */
    const uid_t uid = c->uid;
    struct bsock_client_st **prev =
      &bsock_thread_table[(uid & (BSOCK_THREAD_TABLE_SZ-1))];
    struct bsock_client_st *t = *prev;
    /* mark to prevent bsock_cleanup_client taking extra mutex to repeat this */
    c->next = (struct bsock_client_st *)~(uintptr_t)0;
    while (NULL != t && t->uid != uid)
        t = *(prev = &t->next);
    if (NULL != t) {
        *prev = t->next;
        t->next = bsock_thread_head;
        bsock_thread_head = t;
    }
}

static int  __attribute__((nonnull))
bsock_client_handler (struct bsock_client_st * const restrict c,
                      struct addrinfo * const restrict ai,
                      int * const restrict fd)
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
         * (Note: *fd is intentionally not set to nfd to avoid cleanup close) */
        if (-1 != (nfd = bsock_resvaddr_fd(ai))) {
            if (c->fd != *fd)
                rc = EXIT_SUCCESS;
            else /* (incompatible (unsupportable) with authbind (c->fd==*fd)) */
                errno = EACCES;
            break;
        }

        /* create socket (if not provided by client) */
        if (-1 == *fd) {
            *fd = nfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
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
                if (0 == bsock_bindresvport_sa(*fd, ai->ai_addr))
                    rc = EXIT_SUCCESS;
                else
                    bsock_syslog(errno, LOG_ERR, "bindresvport_sa");
                break;  /* break out of while(0) on either success or failure */
            }
            else {
                /* set SO_REUSEADDR socket option */
                flag = 1;
                if (0 != setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR,
                                    &flag, sizeof(flag))) {
                    bsock_syslog(errno, LOG_ERR, "setsockopt");
                    break;
                }
            }
        }

        /* bind to address */
        if (0 == bind(*fd, ai->ai_addr, ai->ai_addrlen))
            rc = EXIT_SUCCESS;
        else
            bsock_syslog(errno, LOG_ERR, "bind");

    } while (0);

    if (rc == EXIT_SUCCESS)
        flag = 0;       /*(iov.iov_base = &flag)*/
    else if (0 == (flag = errno))
        flag = EACCES;  /*(iov.iov_base = &flag)*/

    /* send 4-byte value in data to indicate success or errno value
     * (send socket *fd to client if new socket, no poll since only one send) */
    if (c->fd != *fd) {
        /* poll()d before recv above, so can defer O_NONBLOCK to here */
        if (!MSG_DONTWAIT)
            (void)fcntl(c->fd, F_SETFL, fcntl(c->fd, F_GETFL, 0) | O_NONBLOCK);
        rc = (bsock_unix_send_fds(c->fd, &nfd, (-1 != nfd), &iov, 1)
              == (ssize_t)iov.iov_len)
          ? EXIT_SUCCESS
          : EXIT_FAILURE;
        if (rc == EXIT_FAILURE && errno != EPIPE && errno != ECONNRESET)
            bsock_syslog(errno, LOG_ERR, "sendmsg");
    }
    else {
        rc = flag;  /* authbind: set exit value */
        *fd = -1;   /* no-op bsock_cleanup_close(fd) since *fd == c->fd */
    }

    return rc;
}

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

static void  __attribute__((noinline))
bsock_infostr (char * restrict infobuf,
               const int fd, const uid_t uid, const gid_t gid)
{
    /* snprintf() can be expensive so special-case LOG_INFO.
     * (snprintf() took 1.5 usec with fmtstr below -- as much as a system call!)
     * snprintf(info, sizeof(info), "fd(%d) uid:%u gid:%u",
     *          fd, (uint32_t)uid, (uint32_t)gid);
     * We assume buffer large enough to hold fmtstr plus (3) 10-digit uint32_t,
     * i.e. our callers pass 64-byte buffer, and fd must not be negative. */
    infobuf[0] = 'f';
    infobuf[1] = 'd';
    infobuf[2] = '(';
    infobuf += 3 + uint32_to_str((uint32_t)fd, infobuf+3);
    infobuf[0] = ')';
    infobuf[1] = ' ';
    infobuf[2] = 'u';
    infobuf[3] = 'i';
    infobuf[4] = 'd';
    infobuf[5] = ':';
    infobuf += 6 + uint32_to_str((uint32_t)uid, infobuf+6);
    infobuf[0] = ' ';
    infobuf[1] = 'g';
    infobuf[2] = 'i';
    infobuf[3] = 'd';
    infobuf[4] = ':';
    infobuf += 5 + uint32_to_str((uint32_t)gid, infobuf+5);
    infobuf[0] = '\0';
}

static void  __attribute__((nonnull))
bsock_cleanup_client (void * const arg)
{
    struct bsock_client_st * const c = (struct bsock_client_st *)arg;
    if (-1 != c->fd)
        nointr_close(c->fd);
    if (c->next != (struct bsock_client_st *)~(uintptr_t)0) {
        pthread_mutex_lock(&bsock_thread_table_mutex);
        bsock_thread_table_remove(c);
        pthread_mutex_unlock(&bsock_thread_table_mutex);
    }
}

static void *  __attribute__((nonnull))
bsock_client_thread (void * const arg)
{
    struct bsock_client_st c; /* copy so that not referencing hash entry */
    struct sockaddr_storage addr;
    struct addrinfo ai = {  /* init only fields used to pass buf and bufsize */
      .ai_addrlen = sizeof(addr),
      .ai_addr    = (struct sockaddr *)&addr
    };
    int fd = -1;
    char info[64];
    memcpy(&c, arg, sizeof(struct bsock_client_st));
    bsock_infostr(info, c.fd, c.uid, c.gid);
    /* receive addrinfo from client
     * (NOTE: receiving addrinfo is ONLY place in bsock that can block on
     *  client input (at this time).  Set timeout for 2000ms (2 sec)) */
    if (!(/* speculative recv if OS can defer accept() until data ready*/
          #ifdef BSOCK_UNIX_ACCEPTFILTER
          bsock_addrinfo_recv(c.fd, &ai, &fd)
          || ((errno == EAGAIN || errno == EWOULDBLOCK)
              && 1 == retry_poll_fd(c.fd, POLLIN, 2000)
              && bsock_addrinfo_recv(c.fd, &ai, &fd))
          #else
                 1 == retry_poll_fd(c.fd, POLLIN, 2000)
              && bsock_addrinfo_recv(c.fd, &ai, &fd)
          #endif
         ) ) {
        ai.ai_addrlen = 0;   /* overloaded flag to send error in response */
        bsock_syslog(errno, LOG_ERR,
                     "(uid:%u) recv addrinfo error or invalid addrinfo",
                     (uint32_t)c.uid);
    }
    /* (remove from thread table prior to send due to observed process and 
     *  thread execution order where a sequence of bind requests from same
     *  uid would get deferred since this thread did not remove uid from thread
     *  table before client was able to make another request, and the listening
     *  thread able to handle it (and defer due to existing request in process))
     * (bsock_client_handler() should not perform any activities that block) */
    pthread_mutex_lock(&bsock_thread_table_mutex);
    bsock_thread_table_remove(&c);
    pthread_mutex_unlock(&bsock_thread_table_mutex);
    bsock_client_handler(&c, &ai, &fd);  /* ignore rc; client request handled */
    bsock_cleanup_close(&fd);
    bsock_cleanup_client(&c);
    /* syslog all connections to bsock daemon
     * Note: This syslog results in bsock taking 1.3x longer (wall clock)
     * to service each request on my uniprocessor system, so do syslog after
     * servicing request for benefit of multiple requests on multiprocessors.
     * (However, if thread cancelled before here, then logging doesn't happen)*/
    bsock_syslog(0, LOG_INFO, "%s", info); /* deferred to not delay response */
    return NULL;  /* end of thread; identical to pthread_exit() */
}

static void  __attribute_cold__
bsock_sigaction_sighup (void)
{
    /* efficiency: keep databases open (advantageous for nss_mcdb module) */
    /* perform database open in event thread (thread-specific in nss_mcdb)*/
    /* (not bothering to close these databases if pthread_cancel() called)*/
    setprotoent(1);
    setservent(1);

    /* refresh table of persistent reserved addresses */
    bsock_resvaddr_config();
    /* refresh table of authorized username/address/port */
    bsock_authz_config();

    endprotoent();
    endservent();
}

static void  __attribute__((nonnull))
bsock_sigaction (sigset_t * const restrict sigs, const int signo)
{
    switch (signo) {
      case SIGHUP:
        bsock_sigaction_sighup();
        break;
      case SIGINT: case SIGQUIT: case SIGTERM:
        (void)pthread_sigmask(SIG_UNBLOCK, sigs, NULL);
        raise(signo); /*not expected to return, but reset mask if it does*/
        (void)pthread_sigmask(SIG_BLOCK, sigs, NULL);
        break;
      default:
        bsock_syslog(0, LOG_ERR, "caught unexpected signal: %d", signo);
        break;
    }
}

static void  __attribute__((nonnull))  __attribute__((noreturn))
bsock_sigwait (void * const arg)
{
    sigset_t * const sigs = (sigset_t *)arg;
    int signo = SIGHUP;
    for (;;) {
        bsock_sigaction(sigs, signo);
        (void) sigwait(sigs, &signo);
    }
}

static void
bsock_thread_signals (void)
{
    static sigset_t sigs;/*('static' since must persist after routine returns)*/
    pthread_t thread;
    int errnum;
    (void) sigemptyset(&sigs);
    (void) sigaddset(&sigs, SIGHUP);
    (void) sigaddset(&sigs, SIGINT);
    (void) sigaddset(&sigs, SIGQUIT);
    (void) sigaddset(&sigs, SIGTERM);
    /* block signals (signal mask inherited by threads subsequently created) */
    if (0 != (errnum = pthread_sigmask(SIG_BLOCK, &sigs, NULL))) {
        bsock_syslog(errnum, LOG_ERR, "pthread_sigmask");
        return;
    }
    if (0 != (errnum = pthread_create(&thread, NULL,
                                      (void *(*)(void *))&bsock_sigwait,&sigs)))
        bsock_syslog(errnum, LOG_ERR, "pthread_create");
}

static void  __attribute__((noinline))  __attribute_cold__
bsock_client_send_errno (const int fd, int errnum)
{
    /* one-shot response; send buffer should be empty and should not block */
    struct iovec iov = { .iov_base = &errnum, .iov_len = sizeof(int) };
    bsock_unix_send_fds(fd, NULL, 0, &iov, 1);  /* no err chk; send & forget */
}

static int
bsock_thread_event_loop (const int sfd, pthread_attr_t * const restrict attr)
{
    /* daemon event loop
     * accept, get client credentials, insert into table, spawn handler thread
     *
     * (As written, code is extensible to use timer thread which expires long
     *  running threads using pthread_cancel().  Not implemented in bsock since
     *  bsock only blocks on reading addrinfo from client, and handler thread
     *  poll()s for limited time before aborting.)  (It should be possible to
     *  implement as single-thread using poll() for POLLIN on all accept()ed
     *  connections, and then handling in-line once data ready.
     *  Alternatively via SIGIO.)
     */
    struct bsock_client_st m;
    struct bsock_client_st *c;
    pthread_t thread_id;

    do {

        /* accept new connection */
        if (-1 == (m.fd = accept(sfd, NULL, NULL))) {
            switch (errno) {
              case ECONNABORTED:
              case EINTR: continue;
              case EINVAL:/* listen sfd closed by another thread */
                          pthread_attr_destroy(attr);
                          return EXIT_SUCCESS;
              default:    /* temporary process/system resource issue */
                          bsock_syslog(errno, LOG_ERR, "accept");
                          (void)poll(NULL, 0, 10); /* pause 10ms and continue */
                          continue;
            }
        }

        /* get client credentials */
        if (0 != bsock_unix_getpeereid(m.fd, &m.uid, &m.gid)) {
            bsock_syslog(errno, LOG_ERR, "getpeereid");
            nointr_close(m.fd);
            continue;
        }

        /* allocate thread table entry; permit one request at a time per uid */
        c = NULL;
        pthread_mutex_lock(&bsock_thread_table_mutex);
        if (bsock_thread_table_query(&m) == NULL) {
            while ((c = bsock_thread_table_add(&m)) == NULL) {
                /* (yield then retry if max threads already in progress) */
                pthread_mutex_unlock(&bsock_thread_table_mutex);
                sched_yield();
                pthread_mutex_lock(&bsock_thread_table_mutex);
            }
        }
        pthread_mutex_unlock(&bsock_thread_table_mutex);
        if (NULL == c) {
            /* sendmsg with EAGAIN; permit only one request at a time per uid */
            bsock_client_send_errno(m.fd, EAGAIN);  /*see bsock_bind_viasock()*/
            nointr_close(m.fd);
            continue;
        }

        /* create handler thread */
        if (0 != pthread_create(&thread_id, attr, bsock_client_thread, c)) {
            bsock_thread_table_remove(c);
            nointr_close(m.fd);
            continue;
        }

    } while (1);
}

/* one-shot mode; handle single request and exit */
static int
  __attribute__((nonnull))  __attribute__((noinline))  __attribute_cold__
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
        if (0 != getpeername(m.fd, ai.ai_addr, &ai.ai_addrlen)) {
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

    rc = bsock_client_handler(&m, &ai, &fd);
    bsock_syslog(0, LOG_INFO, "%s", info); /*deferred to not delay response*/
    /*(not bothering to close() m.fd or fd since program is exiting)*/
    return rc;
}

int  __attribute__((nonnull))
main (int argc, char *argv[])
{
    int sfd, opt, daemon = false, supervised = false;
    struct group *gr;
    pthread_attr_t attr;

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

    if (!bsock_daemon_init(supervised, true))
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

    if (   0 != pthread_attr_init(&attr)
        || 0 != pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)
        || 0 != pthread_attr_setstacksize(&attr, 32768)) {/*(should be plenty)*/
        bsock_syslog(errno, LOG_ERR, "pthread_attr_*");
        return EXIT_FAILURE;
    }
    bsock_thread_table_init(); /*used to permit one concurrent request per uid*/

    bsock_thread_signals();    /*blocks signals for all but one thread*/

    return bsock_thread_event_loop(sfd, &attr);
}
