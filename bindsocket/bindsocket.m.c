/*
 * bindsocket - bind() sockets to restricted ports for lower-privilege daemons
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
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

extern char **environ; /* avoid #define _GNU_SOURCE for visibility of environ */

#include <bindsocket_addrinfo.h>
#include <bindsocket_bindresvport.h>
#include <bindsocket_resvaddr.h>
#include <bindsocket_syslog.h>
#include <bindsocket_unixdomain.h>

#ifndef BINDSOCKET_GROUP
#error "BINDSOCKET_GROUP must be defined"
#endif

#ifndef BINDSOCKET_CONFIG
#error "BINDSOCKET_CONFIG must be defined"
#endif

/* N.B. directory (and tree above it) must be writable only by root */
/* Unit test drivers not run as root should override this location at compile */
#ifndef BINDSOCKET_SOCKET_DIR
#error "BINDSOCKET_SOCKET_DIR must be defined"
#endif
#define BINDSOCKET_SOCKET BINDSOCKET_SOCKET_DIR "/socket"

/* retry_close() - make effort to avoid leaking open file descriptors
 *                 call perror() if error */
static int
retry_close (const int fd)
{
    int r;
    if (fd < 0) return 0;
    do {r = close(fd);} while (r != 0 && errno == EINTR);
    if (0 != r) bindsocket_syslog(errno, "close");
    return r;
}

static void
bindsocket_cleanup_close (void * const arg)
{
    const int fd = *(int *)arg;
    if (-1 != fd)
        retry_close(fd);
}

static void
bindsocket_cleanup_fclose (void * const arg)
{
    FILE * const fp = (FILE *)arg;
    if (NULL != fp)
        fclose(fp);
}

struct bindsocket_client_st {
  struct bindsocket_client_st *next;
  pthread_t thread;
  int fd;
  uid_t uid;
  gid_t gid;
};

/* simple fixed-size statically allocated hash table
 * using statically allocated elements (enforces max threads)
 * accessed read/write while holding mutex
 * (not expecting many simultaneous requests; limiting one thread max per uid)*/
#define BINDSOCKET_THREAD_TABLE_SZ 32  /* must be power of two */
#define BINDSOCKET_THREAD_MAX 128
static pthread_mutex_t
       bindsocket_thread_table_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct bindsocket_client_st 
       bindsocket_thread_elts[BINDSOCKET_THREAD_MAX];
static struct bindsocket_client_st *
       bindsocket_thread_head = bindsocket_thread_elts;
static struct bindsocket_client_st *
       bindsocket_thread_table[BINDSOCKET_THREAD_TABLE_SZ]; /*static init to 0*/

static void
bindsocket_thread_table_init (void)
{
    for (unsigned int i = 0; i < BINDSOCKET_THREAD_MAX-1; ++i)
        bindsocket_thread_elts[i].next = &bindsocket_thread_elts[i+1];
    bindsocket_thread_elts[BINDSOCKET_THREAD_MAX-1].next = NULL;
}

static struct bindsocket_client_st *
bindsocket_thread_table_query (const struct bindsocket_client_st * const c)
{
    const uid_t uid = c->uid;
    struct bindsocket_client_st *t = 
      bindsocket_thread_table[(uid & (BINDSOCKET_THREAD_TABLE_SZ-1))];
    while (NULL != t && t->uid != uid)
        t = t->next;
    return t;
}

static struct bindsocket_client_st *
bindsocket_thread_table_add (struct bindsocket_client_st * const c)
{
    /* (not checking for multiple-add of same uid (do not do that)) */
    struct bindsocket_client_st ** const next =
      &bindsocket_thread_table[(c->uid & (BINDSOCKET_THREAD_TABLE_SZ-1))];
    struct bindsocket_client_st * const t = bindsocket_thread_head;
    if (NULL == t)
        return NULL;
    bindsocket_thread_head = t->next;
    memcpy(t, c, sizeof(struct bindsocket_client_st));
    t->next = *next;
    return (*next = t);
}

static struct bindsocket_client_st *
bindsocket_thread_table_remove (struct bindsocket_client_st * const c)
{
    /* (removes only first uid found if multiple (should not happen)) */
    const uid_t uid = c->uid;
    struct bindsocket_client_st **prev =
      &bindsocket_thread_table[(uid & (BINDSOCKET_THREAD_TABLE_SZ-1))];
    struct bindsocket_client_st *t = *prev;
    while (NULL != t && t->uid != uid)
        t = *(prev = &t->next);
    if (NULL != t) {
        *prev = t->next;
        t->next = bindsocket_thread_head;
        bindsocket_thread_head = t;
    }
    return t;
}

static bool
bindsocket_is_authorized_addrinfo (const struct addrinfo * const restrict ai,
                                   const uid_t uid, const gid_t gid)
{
    /* Note: client must specify address family; AF_UNSPEC not supported
     * Note: minimal process optimization implemented (room for improvement)
     *       (numerous options for caching, improving performance if needed)
     *       (e.g. reading and caching config file by uid in parent daemon
     *        and re-reading configuration file upon receiving HUP signal,
     *        or, better, storing strings in mcdb, and re-open mcdb upon HUP) */

    char *p;
    struct bindsocket_addrinfo_strs aistr;
    FILE *cfg;
    size_t cmplen;
    struct stat st;
    char line[256];   /* username + AF_UNIX, AF_INET, AF_INET6 bindsocket str */
    char cmpstr[256]; /* username + AF_UNIX, AF_INET, AF_INET6 bindsocket str */
    char bufstr[80];  /* buffer for use by bindsocket_addrinfo_to_strs() */
    bool rc = false;
    struct passwd pw;
    struct passwd *pwres;
    char pwbuf[2048];

    if (uid == 0 || gid == 0)  /* permit root or wheel */
        return true;
    if (0 != getpwuid_r(uid, &pw, pwbuf, sizeof(pwbuf), &pwres))
        return false;

    if (ai->ai_family != ai->ai_addr->sa_family) {
        bindsocket_syslog((errno = EINVAL), "addrinfo inconsistent");
        return false;
    }

    /* convert username and addrinfo to string for comparison with config file
     * (validate and canonicalize user input)
     * (user input converted to addrinfo and back to str to canonicalize str) */
    if (!bindsocket_addrinfo_to_strs(ai, &aistr, bufstr, sizeof(bufstr))) {
        bindsocket_syslog((errno = ENOSPC),
                          "addrinfo string expansion is too long");
        return false;
    }
  #if 0
    cmplen = snprintf(cmpstr, sizeof(cmpstr), "%s %s %s %s %s %s\n",
                      pw.pw_name, aistr.family, aistr.socktype, aistr.protocol,
                      aistr.service, aistr.addr);
    if (cmplen >= sizeof(cmpstr)) {
            bindsocket_syslog((errno = ENOSPC),
                              "addrinfo string expansion is too long");
            return false;
    }
  #else
    if (    NULL==(p=memccpy(cmpstr,pw.pw_name,'\0',sizeof(cmpstr)))
        || (*(p-1) = ' ',
            NULL==(p=memccpy(p,aistr.family,  '\0',sizeof(cmpstr)-(p-cmpstr))))
        || (*(p-1) = ' ',
            NULL==(p=memccpy(p,aistr.socktype,'\0',sizeof(cmpstr)-(p-cmpstr))))
        || (*(p-1) = ' ',
            NULL==(p=memccpy(p,aistr.protocol,'\0',sizeof(cmpstr)-(p-cmpstr))))
        || (*(p-1) = ' ',
            NULL==(p=memccpy(p,aistr.service, '\0',sizeof(cmpstr)-(p-cmpstr))))
        || (*(p-1) = ' ',
            NULL==(p=memccpy(p,aistr.addr,    '\0',sizeof(cmpstr)-(p-cmpstr))))
        || sizeof(cmpstr) == p-cmpstr   ) {
        bindsocket_syslog((errno = ENOSPC),
                          "addrinfo string expansion is too long");
        return false;
    }
    *(p-1) = '\n';
    *p = '\0';
    cmplen = p - cmpstr;
  #endif

    if (NULL == (cfg = fopen(BINDSOCKET_CONFIG, "r"))) {
        bindsocket_syslog(errno, BINDSOCKET_CONFIG);
        return false;
    }

    /* (requires pthread PTHREAD_CANCEL_DEFERRED type for proper operation) */
    pthread_cleanup_push(bindsocket_cleanup_fclose, cfg);

    if (0 == fstat(fileno(cfg), &st)
        && st.st_uid == geteuid() && !(st.st_mode & (S_IWGRP|S_IWOTH))) {
        /* compare username and addrinfo string; skip # comments, blank lines */
        while (!rc && NULL != fgets(line, sizeof(line), cfg))
            rc = (0 == memcmp(line, cmpstr, cmplen));
        if (!rc)
            bindsocket_syslog((errno = EACCES), "permission denied");
    }
    else
        bindsocket_syslog((errno = EPERM),
                          "ownership/permissions incorrect on %s",
                          BINDSOCKET_CONFIG);

    pthread_cleanup_pop(1);  /* fclose(cfg)  */
    return rc;
}

static int
bindsocket_client_session (struct bindsocket_client_st * const restrict c,
                           struct bindsocket_addrinfo_strs *
                             const restrict aistr)
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

    /* get client credentials (if non-daemon mode) */
    if (-1 == c->uid) {
        if (NULL != aistr && 0 != getpeername(c->fd,ai.ai_addr,&ai.ai_addrlen)){
            /* authbind: client provided as stdin the socket to which to bind()
             *(http://www.chiark.greenend.org.uk/ucgi/~ijackson/cvsweb/authbind)
             * bindsocket has args and stdin is not a connected socket.
             * bindsocket is running setuid; use real uid, gid as credentials */
            if (errno == ENOTCONN) {
                fd = c->fd; /*(Note: setting fd=c->fd is reason why code here)*/
                c->uid = getuid();
                c->gid = getgid();
            }
            else {
                bindsocket_syslog(errno, "getpeername");
                return EXIT_FAILURE;
            }
        }
        ai.ai_addrlen = sizeof(addr); /* reset addr size after getpeername() */
        if (-1 == c->uid) {
            if (0 != bindsocket_unixdomain_getpeereid(c->fd, &c->uid, &c->gid)){
                bindsocket_syslog(errno, "getpeereid");
                return EXIT_FAILURE;
            }
        }
    }

    /* syslog all connections to (or instantiations of) bindsocket daemon
     * <<<FUTURE: might write custom wrapper to platform-specific getpeereid
     * and combine with syslog() to log pid and other info, if available */
    syslog(LOG_INFO, "connect: uid:%d gid:%d", c->uid, c->gid);

    pthread_cleanup_push(bindsocket_cleanup_close, &fd);

    do {  /*(required steps follow this block; this might be made subroutine)*/

        /* receive addrinfo from client
         * (NOTE: receiving addrinfo is ONLY place in bindsocket that can block
         *  on client input (at this time).  Set timeout for 2000ms (2 sec)) */
        if (!(NULL == aistr
              ? bindsocket_unixdomain_poll_recv_addrinfo(c->fd, &ai, &fd, 2000)
              : bindsocket_addrinfo_from_strs(&ai, aistr))) {
            bindsocket_syslog(errno, "recv addrinfo error or invalid addrinfo");
            break;
        }

        /* check client credentials to authorize client request */
        if (!bindsocket_is_authorized_addrinfo(&ai, c->uid, c->gid))
            break;

        /* check if addr, port already reserved and bound in bindsocket cache
         * (Note: fd is intentionally not set to nfd to avoid cleanup close) */
        if (-1 != (nfd = bindsocket_resvaddr_fd(&ai))) {
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
                bindsocket_syslog(errno, "socket");
                break;
            }
        }

        if (AF_INET == ai.ai_family || AF_INET6 == ai.ai_family) {
            if (0 == (AF_INET == ai.ai_family
                      ? ((struct sockaddr_in *)ai.ai_addr)->sin_port
                      : ((struct sockaddr_in6 *)ai.ai_addr)->sin6_port)) {
                /* bind to reserved port (special-case port == 0) */
                if (0 == bindsocket_bindresvport_sa(fd, ai.ai_addr))
                    rc = EXIT_SUCCESS;
                else
                    bindsocket_syslog(errno, "bindresvport_sa");
                break;  /* break out of while(0) on either success or failure */
            }
            else {
                /* set SO_REUSEADDR socket option */
                flag = 1;
                if (0 != setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                                    &flag, sizeof(flag))) {
                    bindsocket_syslog(errno, "setsockopt");
                    break;
                }
            }
        }

        /* bind to address */
        if (0 == bind(fd, ai.ai_addr, ai.ai_addrlen))
            rc = EXIT_SUCCESS;
        else
            bindsocket_syslog(errno, "bind");

    } while (0);

    /* send 4-byte value in data to indicate success or errno value
     * (send socket fd to client if new socket, no poll since only one send) */
    flag = (rc == EXIT_SUCCESS) ? 0 : errno;  /*(iov.iov_base = &flag)*/
    if (c->fd != fd) {
        rc = (bindsocket_unixdomain_send_fd(c->fd, nfd, &iov, 1) == iov.iov_len)
          ? EXIT_SUCCESS
          : EXIT_FAILURE;
        if (rc == EXIT_FAILURE && errno != EPIPE && errno != ECONNRESET)
            bindsocket_syslog(errno, "sendmsg");
    }
    else {
        rc = flag;  /* authbind: set exit value */
        fd = -1;    /* no-op bindsocket_cleanup_close(&fd) since fd == c->fd */
    }

    pthread_cleanup_pop(1);  /* bindsocket_cleanup_close(&fd)  */

    /* <<<FUTURE: might add additional logging of request and success/failure */
    return rc;
}

static void
bindsocket_cleanup_client (void * const arg)
{
    struct bindsocket_client_st * const c = (struct bindsocket_client_st *)arg;
    retry_close(c->fd);
    /* (skip pthread_cleanup_push(),_pop() on mutex since in cleanup and
     *  bindsocket_thread_table_remove() provides no cancellation point) */
    pthread_mutex_lock(&bindsocket_thread_table_mutex);
    bindsocket_thread_table_remove(c);
    pthread_mutex_unlock(&bindsocket_thread_table_mutex);
}

static void *
bindsocket_client_thread (void * const arg)
{
    struct bindsocket_client_st * const c = (struct bindsocket_client_st *) arg;
    pthread_cleanup_push(bindsocket_cleanup_client, c);
    bindsocket_client_session(c, NULL);  /* ignore rc */
    pthread_cleanup_pop(1);  /* bindsocket_cleanup_client(c) */
    return NULL;  /* end of thread; identical to pthread_exit() */
}

static bool
setuid_stdinit (void)
{
    /* Note: not retrying upon interruption; any fail to init means exit fail */

    /* Clear the environment */
    static char *empty_env[] = { NULL };
    environ = empty_env;

    /* Unblock all signals (regardless of what was inherited from parent) */
    sigset_t sigset_empty;
    if (0 != sigemptyset(&sigset_empty)
        || sigprocmask(0 != SIG_SETMASK, &sigset_empty, (sigset_t *) NULL)) {
        bindsocket_syslog(errno, "sigprocmask");
        return false;
    }

    return true;
}

static void
daemon_sa_handler (int signum)
{
    exit(EXIT_SUCCESS);  /* executes atexit() handlers */
}

static bool
daemon_signal_init (void)
{
    /* configure signal handlers for bindsocket desired behaviors
     *   SIGALRM: default handler
     *   SIGPIPE: ignore
     *   SIGCLD:  ignore
     *   SIGHUP:  clean up and exit (for now)
     *   SIGINT:  clean up and exit
     *   SIGQUIT: clean up and exit
     *   SIGTERM: clean up and exit
     */
    struct sigaction act;
    (void) sigemptyset(&act.sa_mask);

    act.sa_handler = SIG_DFL;
    act.sa_flags = 0;  /* omit SA_RESTART */
    if (sigaction(SIGALRM, &act, (struct sigaction *) NULL) != 0) {
        bindsocket_syslog(errno, "sigaction");
        return false;
    }

    act.sa_handler = SIG_IGN;
    act.sa_flags = 0;  /* omit SA_RESTART */
    if (sigaction(SIGPIPE, &act, (struct sigaction *) NULL) != 0) {
        bindsocket_syslog(errno, "sigaction");
        return false;
    }

    act.sa_handler = SIG_IGN;
    act.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &act, (struct sigaction *) NULL) != 0) {
        bindsocket_syslog(errno, "sigaction");
        return false;
    }

    act.sa_handler = daemon_sa_handler;
    act.sa_flags = SA_RESTART;
    if (sigaction(SIGHUP, &act, (struct sigaction *) NULL) != 0) {
        bindsocket_syslog(errno, "sigaction");
        return false;
    }

    act.sa_handler = daemon_sa_handler;
    act.sa_flags = 0;  /* omit SA_RESTART */
    if (   sigaction(SIGINT,  &act, (struct sigaction *) NULL) != 0
        || sigaction(SIGQUIT, &act, (struct sigaction *) NULL) != 0
        || sigaction(SIGTERM, &act, (struct sigaction *) NULL) != 0) {
        bindsocket_syslog(errno, "sigaction");
        return false;
    }

    return true;
}

static bool
daemon_init (const int supervised)
{
    /* Note: not retrying upon interruption; any fail to init means exit fail */

    /* Change current working dir to / for sane cwd and to limit mounts in use*/
    if (0 != chdir("/")) {
        bindsocket_syslog(errno, "chdir /");
        return false;
    }

    /* Detach from parent (process to be inherited by init) unless supervised */
    if (supervised) {
        if (setsid() == (pid_t)-1) {
            bindsocket_syslog(errno, "setsid");
            return false;
        }
    }
    else {
        pid_t pid;

        /* Ensure that SIGCHLD is not ignored (might be inherited from caller)*/
        struct sigaction act;
        (void) sigemptyset(&act.sa_mask);
        act.sa_handler = SIG_DFL;
        act.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &act, (struct sigaction *) NULL) != 0) {
            bindsocket_syslog(errno, "sigaction");
            return false;
        }

        if ((pid = fork()) != 0) {   /* parent */
            int status = EXIT_FAILURE;
            if (pid > 0 && waitpid(pid, &status, 0) != pid)
                status = EXIT_FAILURE;
            _exit(status);
        }                            /* child */
        else if ((pid = setsid()) == (pid_t)-1 || (pid = fork()) != 0) {
            if ((pid_t)-1 == pid) bindsocket_syslog(errno, "setsid,fork");
            _exit((pid_t)-1 == pid);
        }                            /* grandchild falls through */
    }

    /* Close unneeded file descriptors */
    /* (not closing all fds > STDERR_FILENO; lazy and we check root is caller)
     * (if closing all fds, must then closelog(); bindsocket_syslog_openlog())*/
    if (0 != retry_close(STDIN_FILENO))  return false;
    if (0 != retry_close(STDOUT_FILENO)) return false;
    if (!supervised) {
        if (0 != retry_close(STDERR_FILENO)) return false;
        bindsocket_syslog_setlevel(BINDSOCKET_SYSLOG_DAEMON);
    }
    else {
        /* STDERR_FILENO must be open so it is not reused for sockets */
        struct stat st;
        if (0 != fstat(STDERR_FILENO, &st)) {
            bindsocket_syslog(errno, "stat STDERR_FILENO");
            return false;
        }
    }

    /* Configure signal handlers for bindsocket desired behaviors */
    if (!daemon_signal_init())
        return false;

    /* Sanity check system socket option max memory for ancillary data
     * (see bindsocket_unixdomain.h for more details) */
  #ifdef __linux__
    {
        ssize_t r;
        long optmem_max;
        const int fd = open("/proc/sys/net/core/optmem_max", O_RDONLY, 0);
        char buf[32];
        if (-1 != fd) {
            if ((r = read(fd, buf, sizeof(buf)-1)) >= 0) {
                buf[r] = '\0';
                errno = 0;
                optmem_max = strtol(buf, NULL, 10);
                if (0 == errno && optmem_max > BINDSOCKET_ANCILLARY_DATA_MAX)
                    bindsocket_syslog(errno, "max ancillary data very large "
                      "(%ld > %d); consider recompiling bindsocket with larger "
                      "BINDSOCKET_ANCILLARY_DATA_MAX", optmem_max,
                      BINDSOCKET_ANCILLARY_DATA_MAX);
            }
            retry_close(fd);
        }
    }
  #endif

    return true;
}

static int bindsocket_daemon_pid = -1;

static void
bindsocket_daemon_atexit (void)
{
    if (getpid() == bindsocket_daemon_pid)
        unlink(BINDSOCKET_SOCKET);
}

static int
bindsocket_daemon_init_socket (void)
{
    struct group *gr;
    struct stat st;
    int sfd;
    const uid_t euid = geteuid();
    mode_t mask;

    /* sanity check ownership and permissions on dir that will contain socket */
    /* (note: not checking entire tree above BINDSOCKET_SOCKET_DIR; TOC-TOU) */
    if (0 != stat(BINDSOCKET_SOCKET_DIR, &st)) {
        bindsocket_syslog(errno, BINDSOCKET_SOCKET_DIR);
        return -1;
    }
    if (st.st_uid != euid || (st.st_mode & (S_IWGRP|S_IWOTH))) {
        bindsocket_syslog((errno = EPERM),
                          "ownership/permissions incorrect on %s",
                          BINDSOCKET_SOCKET_DIR);
        return -1;
    }

    mask = umask(0177); /* create socket with very restricted permissions */
    sfd = bindsocket_unixdomain_socket_bind_listen(BINDSOCKET_SOCKET);
    umask(mask);        /* restore prior umask */
    if (-1 == sfd) {
        bindsocket_syslog(errno, "socket,bind,listen");
        return -1;
    }

    bindsocket_daemon_pid = getpid();
    atexit(bindsocket_daemon_atexit);

    if (NULL != (gr = getgrnam(BINDSOCKET_GROUP)) /* ok; no other threads yet */
        && 0 == chown(BINDSOCKET_SOCKET, euid, gr->gr_gid)
        && 0 == chmod(BINDSOCKET_SOCKET, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP))
        return sfd;

    bindsocket_syslog(errno, "getgrnam,chown,chmod");
    return -1;
}

static void *
bindsocket_sigwait (void * const arg)
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
            /* refresh table of persistent reserved addresses
             * (no locks needed; executed while signals blocked) */
            bindsocket_resvaddr_config();
            break;
          case SIGINT: case SIGQUIT: case SIGTERM:
            daemon_sa_handler(signum);
            break;
          default:
            bindsocket_syslog(0, "caught unexpected signal: %d", signum);
            break;
        }
        (void) sigwait(sigs, &signum);
    }
    return NULL;
}

static void
bindsocket_thread_signals (void)
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
        bindsocket_syslog((errno = errnum), "pthread_sigmask");
        return;
    }
    if (0 != (errnum = pthread_create(&thread,NULL,&bindsocket_sigwait,&sigs)))
        bindsocket_syslog((errno = errnum), "pthread_create");
}

int
main (int argc, char *argv[])
{
    int sfd, daemon = false, supervised = false, errnum = EAGAIN;
    struct bindsocket_client_st m;
    struct bindsocket_client_st *c;
    pthread_attr_t attr;
    struct iovec iov = { .iov_base = &errnum, .iov_len = sizeof(int) };

    /* setuid safety measures must be performed before anything else */
    if (!setuid_stdinit())
        return EXIT_FAILURE;

    /* openlog() for syslog() */
    bindsocket_syslog_openlog();

    /* parse arguments */
    optind = 1;
    while ((sfd = getopt(argc, argv, "dhF")) != -1) {
        switch (sfd) {
          case 'd': daemon = true; break;
          case 'F': supervised = true; break;
          default:  syslog(LOG_ERR, "bad arguments sent by uid %d", getuid());
                    fprintf(stderr, "\nerror: invalid arguments\n");/*fallthru*/
          case 'h': fprintf(stdout, "\n"
                            "  bindsocket -h\n"
                            "  bindsocket -d [-F]\n"
                            "  bindsocket <addr_family> <socktype> <protocol> "
                                        "<service_or_port> <addr>\n\n");
                    return (sfd == 'h' ? EXIT_SUCCESS : EXIT_FAILURE);
        }
    }
    argc -= optind;
    argv += optind;

    /*
     * one-shot mode; handle single request and exit
     */

    if (!daemon) {
        struct bindsocket_addrinfo_strs aistr;
        struct bindsocket_addrinfo_strs *aistrptr = &aistr;
        struct stat st;
        if (0 != fstat(STDIN_FILENO, &st)) {
            bindsocket_syslog(errno, "fstat stdin");
            return EXIT_FAILURE;
        }
        if (!S_ISSOCK(st.st_mode)) {
            bindsocket_syslog((errno = ENOTSOCK),
                              "invalid socket on bindsocket stdin");
            return EXIT_FAILURE; /* STDIN_FILENO must be socket for one-shot */
        }
        switch (argc) {
          case 0: aistrptr = NULL;
                  break;
          case 1: if (bindsocket_addrinfo_split_str(&aistr, argv[0]))
                      break;
                  bindsocket_syslog(errno, "invalid address info arguments");
                  return EXIT_FAILURE;
          case 5: aistr.family   = argv[0];
                  aistr.socktype = argv[1];
                  aistr.protocol = argv[2];
                  aistr.service  = argv[3];
                  aistr.addr     = argv[4];
                  break;
          default: bindsocket_syslog((errno = EINVAL),
                                     "invalid number of arguments");
                   return EXIT_FAILURE;
        }

        m.fd  = STDIN_FILENO;
        m.uid = -1;
        m.gid = -1;
        return bindsocket_client_session(&m, aistrptr);
    }

    /*
     * daemon mode
     */

    if (getuid() != geteuid()) {
        /* do not permit setuid privileges to initiate daemon mode */
        bindsocket_syslog((errno = EACCES),
                          "daemon can not be started via setuid");
        return EXIT_FAILURE;
    }

    if (!daemon_init(supervised))
        return EXIT_FAILURE;

    sfd = bindsocket_daemon_init_socket();
    if (-1 == sfd)
        return EXIT_FAILURE;

    if (   0 != pthread_attr_init(&attr)
        || 0 != pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)
        || 0 != pthread_attr_setstacksize(&attr, 32768)) {/*(should be plenty)*/
        bindsocket_syslog(errno, "pthread_attr_*");
        return EXIT_FAILURE;
    }
    bindsocket_thread_table_init();

    bindsocket_thread_signals();  /* blocks signals for all but one thread */

    /* daemon event loop
     * accept, get client credentials, insert into table, spawn handler thread
     *
     * (As written, code is extensible to use timer thread which expires long
     *  running threads using pthread_cancel().  Not implemented in bindsocket
     *  since bindsocket only blocks on reading addrinfo from client, and
     *  handler thread poll()s for limited time before aborting.)  (It should
     *  be possible to implement as single-thread using poll() for POLLIN on
     *  all accept()ed connections, and then handling in-line once data ready.
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
                          bindsocket_syslog(errno, "accept");
                          poll(NULL, 0, 10); /* pause 10ms and continue */
                          continue;
            }
        }

        /* get client credentials */
        if (0 != bindsocket_unixdomain_getpeereid(m.fd, &m.uid, &m.gid)) {
            bindsocket_syslog(errno, "getpeereid");
            retry_close(m.fd);
            continue;
        }

        /* allocate thread table entry; permit one request at a time per uid */
        c = NULL;
        pthread_mutex_lock(&bindsocket_thread_table_mutex);
        if (bindsocket_thread_table_query(&m) == NULL) {
            while ((c = bindsocket_thread_table_add(&m)) == NULL) {
                /* (pause 1ms and retry if max threads already in progress) */
                pthread_mutex_unlock(&bindsocket_thread_table_mutex);
                poll(NULL, 0, 1);
                pthread_mutex_lock(&bindsocket_thread_table_mutex);
            }
        }
        pthread_mutex_unlock(&bindsocket_thread_table_mutex);
        if (NULL == c) {
            /* sendmsg with EAGAIN; permit only one request at a time per uid */
            bindsocket_unixdomain_sendmsg(m.fd, &iov, 1);
            retry_close(m.fd);
            continue;
        }

        /* create handler thread */
        if (0 != pthread_create(&c->thread,&attr,bindsocket_client_thread,c)) {
            bindsocket_thread_table_remove(c);
            retry_close(m.fd);
            continue;
        }

    } while (1);
}
