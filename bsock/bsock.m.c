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
#include <sys/un.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
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

#ifndef BSOCK_CONFIG
#error "BSOCK_CONFIG must be defined"
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
  pthread_t thread;
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

static struct bsock_client_st *  __attribute__((nonnull))
bsock_thread_table_remove (struct bsock_client_st * const c)
{
    /* (removes only first uid found if multiple (should not happen)) */
    const uid_t uid = c->uid;
    struct bsock_client_st **prev =
      &bsock_thread_table[(uid & (BSOCK_THREAD_TABLE_SZ-1))];
    struct bsock_client_st *t = *prev;
    while (NULL != t && t->uid != uid)
        t = *(prev = &t->next);
    if (NULL != t) {
        *prev = t->next;
        t->next = bsock_thread_head;
        bsock_thread_head = t;
    }
    return t;
}

static const char * restrict bsock_authz_lines;

static char *
bsock_authz_config_read (const int fd, const size_t sz)
{
    char * restrict buf = NULL;
    pthread_cleanup_push(free, buf);
    if (NULL != (buf = malloc(sz+2))) {
        buf[0] = '\n';
        buf[sz+1] = '\0';
        if (read(fd, buf+1, sz) != (ssize_t)sz) {
            free(buf);
            buf = NULL;
        }
    }
    else
        bsock_syslog(errno, LOG_ERR, "malloc");
    pthread_cleanup_pop(0);
    return buf;
}

static void
bsock_authz_config (void)
{
    char * restrict buf = NULL;
    struct stat st;
    int fd = -1;

    pthread_cleanup_push(bsock_cleanup_close, &fd);

    do {

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

        buf = bsock_authz_config_read(fd, (size_t)st.st_size);

    } while (0);

    pthread_cleanup_pop(1);  /* close(fd)  */

    if (NULL == buf)
        return;

    if (NULL == bsock_authz_lines)
        bsock_authz_lines = buf;
    else {
        const char * const restrict p = bsock_authz_lines;
        bsock_authz_lines = buf; /* (might do atomic swap in future) */
        /* pause 1 sec for simple and coarse (not perfect) mechanism to give
         * other threads running strstr() time to finish, else might crash.
         * (could grab mutex around all bsock_authz_lines access, if desired) */
        pthread_cleanup_push(free, (void *)(uintptr_t)p);
        poll(NULL, 0, 1000);
        free((void *)(uintptr_t)p);
        pthread_cleanup_pop(0);
    }
}

static bool  __attribute__((nonnull))
bsock_is_authorized_addrinfo (const struct addrinfo * const restrict ai,
                              const uid_t uid, const gid_t gid)
{
    /* Note: client must specify address family; AF_UNSPEC not supported
     * Note: minimal process optimization implemented (room for improvement)
     *       (numerous options for caching, improving performance if needed)
     *       (e.g. bsearch(), or (better) use a cdb) */

    char *p;
    struct bsock_addrinfo_strs aistr;
    char cmpstr[256]; /* username + AF_UNIX, AF_INET, AF_INET6 bsock str */
    char bufstr[80];  /* buffer for use by bsock_addrinfo_to_strs() */
    struct passwd pw;
    struct passwd *pwres;
    char pwbuf[2048];

    if (uid == 0 || gid == 0)  /* permit root or wheel */
        return true;
    if (0 != getpwuid_r(uid, &pw, pwbuf, sizeof(pwbuf), &pwres))
        return false;

    if (ai->ai_family != ai->ai_addr->sa_family) {
        bsock_syslog(EINVAL, LOG_ERR, "addrinfo inconsistent");
        return false;
    }

    /* convert username and addrinfo to string for comparison with config file
     * (validate and canonicalize user input)
     * (user input converted to addrinfo and back to str to canonicalize str) */
    if (!bsock_addrinfo_to_strs(ai, &aistr, bufstr, sizeof(bufstr))) {
        bsock_syslog(ENOSPC, LOG_ERR, "addrinfo string expansion is too long");
        return false;
    }
  #if 0
    cmplen = snprintf(cmpstr, sizeof(cmpstr), "\n%s %s %s %s %s %s\n",
                      pw.pw_name, aistr.family, aistr.socktype, aistr.protocol,
                      aistr.service, aistr.addr);
    if (cmplen >= sizeof(cmpstr)) {
            bsock_syslog(ENOSPC, LOG_ERR,
                         "addrinfo string expansion is too long");
            return false;
    }
  #else
    cmpstr[0] = '\n';
    if (    NULL == (p = memccpy(cmpstr+1, pw.pw_name, '\0', sizeof(cmpstr)-1))
        || (*(p-1) = ' ',NULL==(p = memccpy(p, aistr.family,  '\0',
                                            sizeof(cmpstr)-(size_t)(p-cmpstr))))
        || (*(p-1) = ' ',NULL==(p = memccpy(p, aistr.socktype,'\0',
                                            sizeof(cmpstr)-(size_t)(p-cmpstr))))
        || (*(p-1) = ' ',NULL==(p = memccpy(p, aistr.protocol,'\0',
                                            sizeof(cmpstr)-(size_t)(p-cmpstr))))
        || (*(p-1) = ' ',NULL==(p = memccpy(p, aistr.service, '\0',
                                            sizeof(cmpstr)-(size_t)(p-cmpstr))))
        || (*(p-1) = ' ',NULL==(p = memccpy(p, aistr.addr,    '\0',
                                            sizeof(cmpstr)-(size_t)(p-cmpstr))))
        || sizeof(cmpstr) == p-cmpstr   ) {
        bsock_syslog(ENOSPC, LOG_ERR, "addrinfo string expansion is too long");
        return false;
    }
    *(p-1) = '\n';
    *p = '\0';
    /*cmplen = (size_t)(p - cmpstr);*/
  #endif

    return (NULL != strstr(bsock_authz_lines, cmpstr)
      ? true
      : ((errno=EACCES), false));
}

static int  __attribute__((nonnull (1)))
bsock_client_session (struct bsock_client_st * const restrict c,
                      struct bsock_addrinfo_strs * const restrict aistr)
{
    int fd = -1, nfd = -1;
    int rc = EXIT_FAILURE;
    int flag;
    int addr[28];/* buffer for IPv4, IPv6, or AF_UNIX w/ up to 108 char path */
    struct addrinfo ai = {  /* init only fields used to pass buf and bufsize */
      .ai_addrlen = sizeof(addr),
      .ai_addr    = (struct sockaddr *)addr
    };
    struct iovec iov = { .iov_base = &flag, .iov_len = sizeof(flag) };
    uid_t uid;

    /* get client credentials (if non-daemon mode) */
    if ((uid_t)-1 == c->uid) {
        if (NULL != aistr && 0 != getpeername(c->fd,ai.ai_addr,&ai.ai_addrlen)){
            /* authbind: client provided as stdin the socket to which to bind()
             *(http://www.chiark.greenend.org.uk/ucgi/~ijackson/cvsweb/authbind)
             * bsock has args and stdin is not a connected socket.
             * bsock is running setuid; use real uid, gid as credentials */
            if (errno == ENOTCONN) {
                fd = c->fd; /*(Note: setting fd=c->fd is reason why code here)*/
                c->uid = getuid();
                c->gid = getgid();
            }
            else {
                bsock_syslog(errno, LOG_ERR, "getpeername");
                return EXIT_FAILURE;
            }
        }
        ai.ai_addrlen = sizeof(addr); /* reset addr size after getpeername() */
        if ((uid_t)-1 == c->uid) {
            if (0 != bsock_unix_getpeereid(c->fd, &c->uid, &c->gid)){
                bsock_syslog(errno, LOG_ERR, "getpeereid");
                return EXIT_FAILURE;
            }
        }
    }

    pthread_cleanup_push(bsock_cleanup_close, &fd);

    do {  /*(required steps follow this block; this might be made subroutine)*/

        /* receive addrinfo from client
         * (NOTE: receiving addrinfo is ONLY place in bsock that can block on
         *  client input (at this time).  Set timeout for 2000ms (2 sec)) */
        if (!(NULL == aistr
              ? 1 == retry_poll_fd(c->fd, POLLIN, 2000)
                && bsock_addrinfo_recv(c->fd, &ai, &fd)
              : bsock_addrinfo_from_strs(&ai, aistr))) {
            bsock_syslog(errno, LOG_ERR,
                              "recv addrinfo error or invalid addrinfo");
            break;
        }

        /* check client credentials to authorize client request */
        if (!bsock_is_authorized_addrinfo(&ai, c->uid, c->gid))
            break;

        /* check if addr, port already reserved and bound in bsock cache
         * (Note: fd is intentionally not set to nfd to avoid cleanup close) */
        if (-1 != (nfd = bsock_resvaddr_fd(&ai))) {
            if (c->fd != fd)
                rc = EXIT_SUCCESS;
            else /* (incompatible (unsupportable) with authbind (c->fd==fd)) */
                errno = EACCES;
            break;
        }

        /* create socket (if not provided by client) */
        if (-1 == fd) {
            fd = nfd = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol);
            if (-1 == fd) {
                bsock_syslog(errno, LOG_ERR, "socket");
                break;
            }
        }

        if (AF_INET == ai.ai_family || AF_INET6 == ai.ai_family) {
            if (0 == (AF_INET == ai.ai_family
                      ? ((struct sockaddr_in *)ai.ai_addr)->sin_port
                      : ((struct sockaddr_in6 *)ai.ai_addr)->sin6_port)) {
                /* bind to reserved port (special-case port == 0) */
                if (0 == bsock_bindresvport_sa(fd, ai.ai_addr))
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
        if (0 == bind(fd, ai.ai_addr, ai.ai_addrlen))
            rc = EXIT_SUCCESS;
        else
            bsock_syslog(errno, LOG_ERR, "bind");

    } while (0);

    if (rc == EXIT_SUCCESS)
        flag = 0;       /*(iov.iov_base = &flag)*/
    else if (0 == (flag = errno))
        flag = EACCES;  /*(iov.iov_base = &flag)*/

    /* (remove from thread table prior to send due to observed process and 
     *  thread execution order where a sequence of bind requests from same
     *  uid would get deferred since this thread did not remove uid from thread
     *  table before client was able to make another request, and the listening
     *  thread able to handle it (and defer due to existing request in process))
     * (skip pthread_cleanup_push(),_pop() on mutex since in cleanup and
     *  bsock_thread_table_remove() provides no cancellation point) */
    pthread_mutex_lock(&bsock_thread_table_mutex);
    bsock_thread_table_remove(c);
    pthread_mutex_unlock(&bsock_thread_table_mutex);
    uid = c->uid;
    c->uid = (uid_t)-1;

    /* send 4-byte value in data to indicate success or errno value
     * (send socket fd to client if new socket, no poll since only one send) */
    if (c->fd != fd) {
        rc = (bsock_unix_send_fds(c->fd, &nfd, (-1 != nfd), &iov, 1)
              == (ssize_t)iov.iov_len)
          ? EXIT_SUCCESS
          : EXIT_FAILURE;
        if (rc == EXIT_FAILURE && errno != EPIPE && errno != ECONNRESET)
            bsock_syslog(errno, LOG_ERR, "sendmsg");
    }
    else {
        rc = flag;  /* authbind: set exit value */
        fd = -1;    /* no-op bsock_cleanup_close(&fd) since fd == c->fd */
    }

    pthread_cleanup_pop(1);  /* bsock_cleanup_close(&fd)  */

    /* syslog all connections to (or instantiations of) bsock daemon
     * Note: This syslog results in bsock taking 1.5x longer (wall clock)
     * to service each request on my uniprocessor system, so do syslog after
     * servicing request for benefit of multiple requests on multiprocessors.
     * (However, if thread cancelled before this point, syslog does not happen)
     * <<<FUTURE: might write custom wrapper to platform-specific getpeereid
     * and combine with syslog() to log pid and other info, if available.
     * <<<FUTURE: might add additional logging of request and success/failure */
    bsock_syslog(0, LOG_INFO, "connect: uid:%d gid:%d", uid, c->gid);

    return rc;
}

static void  __attribute__((nonnull))
bsock_cleanup_client (void * const arg)
{
    struct bsock_client_st * const c = (struct bsock_client_st *)arg;
    if (-1 != c->fd)
        nointr_close(c->fd);
    /* (skip pthread_cleanup_push(),_pop() on mutex since in cleanup and
     *  bsock_thread_table_remove() provides no cancellation point) */
    if ((uid_t)-1 != c->uid) {
        pthread_mutex_lock(&bsock_thread_table_mutex);
        bsock_thread_table_remove(c);
        pthread_mutex_unlock(&bsock_thread_table_mutex);
    }
}

static void *  __attribute__((nonnull))
bsock_client_thread (void * const arg)
{
    struct bsock_client_st c; /* copy so that not referencing hash entry */
    memcpy(&c, arg, sizeof(struct bsock_client_st));
    pthread_cleanup_push(bsock_cleanup_client, &c);
    bsock_client_session(&c, NULL);  /* ignore rc */
    pthread_cleanup_pop(1);  /* bsock_cleanup_client(&c) */
    return NULL;  /* end of thread; identical to pthread_exit() */
}

static void *  __attribute__((nonnull))  __attribute__((noreturn))
bsock_sigwait (void * const arg)
{
    sigset_t * const sigs = (sigset_t *)arg;
    int signum = SIGHUP;
    for (;;) {
        switch (signum) {
          case SIGHUP:
            /* efficiency: keep databases open */
            endprotoent();
            setprotoent(1);
            endservent();
            setservent(1);
            /* (no locks needed; executed while signals blocked) */
            /* refresh table of persistent reserved addresses */
            bsock_resvaddr_config();
            /* refresh table of authorized username/address/port */
            bsock_authz_config();
            break;
          case SIGINT: case SIGQUIT: case SIGTERM:
            (void)pthread_sigmask(SIG_UNBLOCK, sigs, NULL);
            raise(signum); /*not expected to return, but reset mask if it does*/
            (void)pthread_sigmask(SIG_BLOCK, sigs, NULL);
            break;
          default:
            bsock_syslog(0,LOG_ERR,"caught unexpected signal: %d",signum);
            break;
        }
        (void) sigwait(sigs, &signum);
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
    if (0 != (errnum = pthread_create(&thread, NULL, &bsock_sigwait, &sigs)))
        bsock_syslog(errnum, LOG_ERR, "pthread_create");
}

int  __attribute__((nonnull))
main (int argc, char *argv[])
{
    int sfd, daemon = false, supervised = false, errnum = EAGAIN;
    struct bsock_client_st m;
    struct bsock_client_st *c;
    pthread_attr_t attr;
    struct iovec iov = { .iov_base = &errnum, .iov_len = sizeof(int) };
    struct group *gr;

    /* setuid safety measures must be performed before anything else */
    if (!bsock_daemon_setuid_stdinit())
        return EXIT_FAILURE;

    /* openlog() for syslog() */
    bsock_syslog_openlog(BSOCK_SYSLOG_IDENT, LOG_NDELAY, BSOCK_SYSLOG_FACILITY);

    /* parse arguments */
    while ((sfd = getopt(argc, argv, "dhF")) != -1
           || (daemon && optind != argc)) { /* no additional args for daemon */
        switch (sfd) {
          case 'd': daemon = true; break;
          case 'F': supervised = true; break;
          default:  if (0 != getuid()) /*(syslog here; not bsock_syslog)*/
                        syslog(LOG_ERR,"bad arguments sent by uid %d",getuid());
                    fprintf(stderr, "\nerror: invalid arguments\n");/*fallthru*/
          case 'h': fprintf((sfd == 'h' ? stdout : stderr), "\n"
                            "  bsock -h\n"
                            "  bsock -d [-F]\n"
                            "  bsock <addr_family> <socktype> <protocol> "
                                        "<service_or_port> <addr>\n\n");
                    return (sfd == 'h' ? EXIT_SUCCESS : EXIT_FAILURE);
        }
    }

    /*
     * one-shot mode; handle single request and exit
     */

    if (!daemon) {
        struct bsock_addrinfo_strs aistr;
        struct bsock_addrinfo_strs *aistrptr = &aistr;
        struct stat st;
        if (0 != fstat(STDIN_FILENO, &st)) {
            bsock_syslog(errno, LOG_ERR, "fstat stdin");
            return EXIT_FAILURE;
        }
        if (!S_ISSOCK(st.st_mode)) {
            bsock_syslog(ENOTSOCK, LOG_ERR, "invalid socket on bsock stdin");
            return EXIT_FAILURE; /* STDIN_FILENO must be socket for one-shot */
        }
        argv += optind;
        switch ((argc -= optind)) {
          case 0: aistrptr = NULL;
                  break;
          case 1: if (bsock_addrinfo_split_str(&aistr, argv[0]))
                      break;
                  bsock_syslog(errno,LOG_ERR,"invalid address info arguments");
                  return EXIT_FAILURE;
          case 5: aistr.family   = argv[0];
                  aistr.socktype = argv[1];
                  aistr.protocol = argv[2];
                  aistr.service  = argv[3];
                  aistr.addr     = argv[4];
                  break;
          default: bsock_syslog(EINVAL, LOG_ERR, "invalid number of arguments");
                   return EXIT_FAILURE;
        }

        m.fd  = STDIN_FILENO;
        m.uid = (uid_t)-1;
        m.gid = (gid_t)-1;
        return bsock_client_session(&m, aistrptr);
    }

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

    if (!bsock_daemon_init(supervised))
        return EXIT_FAILURE;

    sfd = bsock_daemon_init_socket(BSOCK_SOCKET, geteuid(), gr->gr_gid,
                                   BSOCK_SOCKET_MODE);
    if (-1 == sfd)
        return EXIT_FAILURE;

    if (   0 != pthread_attr_init(&attr)
        || 0 != pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)
        || 0 != pthread_attr_setstacksize(&attr, 32768)) {/*(should be plenty)*/
        bsock_syslog(errno, LOG_ERR, "pthread_attr_*");
        return EXIT_FAILURE;
    }
    bsock_thread_table_init();

    bsock_thread_signals();  /* blocks signals for all but one thread */

    /* daemon event loop
     * accept, get client credentials, insert into table, spawn handler thread
     *
     * (As written, code is extensible to use timer thread which expires long
     *  running threads using pthread_cancel().  Not implemented in bsock since
     *  bsock only blocks on reading addrinfo from client, and handler handler
     *  thread poll()s for limited time before aborting.)  (It should be
     *  possible to implement as single-thread using poll() for POLLIN on all
     *  accept()ed connections, and then handling in-line once data ready.
     *  Alternatively via SIGIO.)
     */
    do {

        /* accept new connection */
        if (-1 == (m.fd = accept(sfd, NULL, NULL))) {
            switch (errno) {
              case ECONNABORTED:
              case EINTR: continue;
              case EINVAL:/* listen sfd closed by another thread */
                          pthread_attr_destroy(&attr);
                          return EXIT_SUCCESS;
              default:    /* temporary process/system resource issue */
                          bsock_syslog(errno, LOG_ERR, "accept");
                          poll(NULL, 0, 10); /* pause 10ms and continue */
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
            bsock_unix_send_fds(m.fd, NULL, 0, &iov, 1);
            nointr_close(m.fd);
            continue;
        }

        /* create handler thread */
        if (0 != pthread_create(&c->thread, &attr, bsock_client_thread, c)) {
            bsock_thread_table_remove(c);
            nointr_close(m.fd);
            continue;
        }

    } while (1);
}
