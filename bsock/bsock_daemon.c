/*
 * bsock_daemon - daemon initialization and signal setup
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

#include <bsock_daemon.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

extern char **environ; /* avoid #define _GNU_SOURCE for visibility of environ */

#include <plasma/plasma_stdtypes.h>

#include <bsock_syslog.h>
#include <bsock_unix.h>

/* nointr_close() - make effort to avoid leaking open file descriptors */
static int
nointr_close (const int fd)
{ int r; retry_eintr_do_while(r = close(fd), r != 0); return r; }

bool
bsock_daemon_setuid_stdinit (void)
{
    /* Note: not retrying upon interruption; any fail to init means exit fail */

    /* Clear the environment
     * (set LANG=C for performance)
     * (set PATH since some systems add current dir to implicit PATH if empty)*/
    static char default_path[] = "PATH=/usr/bin:/bin";
    static char default_lang[] = "LANG=C";
    static char *basic_env[] = { default_path, default_lang, NULL };
    environ = basic_env;

    /* Unblock all signals (regardless of what was inherited from parent) */
    sigset_t sigset_empty;
    if (0 != sigemptyset(&sigset_empty)
        || 0 != sigprocmask(SIG_SETMASK, &sigset_empty, (sigset_t *) NULL)) {
        bsock_syslog(errno, LOG_ERR, "sigprocmask");
        return false;
    }

    return true;
}

static void
bsock_daemon_sa_ignore (int signum  __attribute_unused__)
{   /*(handler gets reset to SIG_DFL by execve(); SIG_IGN would be inherited)*/
    /* ignore signal */
}

__attribute_noreturn__
static void
bsock_daemon_sa_handler (int signum  __attribute_unused__)
{
    exit(EXIT_SUCCESS);  /* executes atexit() handlers */
}

static bool
bsock_daemon_signal_init (void)
{
    /* configure signal handlers for bsock desired behaviors
     *   SIGALRM: default handler
     *   SIGCLD:  default handler
     *   SIGPIPE: ignore
     *   SIGHUP:  clean up and exit (for now)
     *   SIGINT:  clean up and exit
     *   SIGQUIT: clean up and exit
     *   SIGTERM: clean up and exit
     */
    struct sigaction act;
    (void) sigemptyset(&act.sa_mask);

    /* Unblock all signals (regardless of what was inherited from parent)
     * (repeated from bsock_daemon_setuid_stdinit() in case that not run)*/
    if (0 != sigprocmask(SIG_SETMASK, &act.sa_mask, (sigset_t *) NULL)) {
        bsock_syslog(errno, LOG_ERR, "sigprocmask");
        return false;
    }

    act.sa_handler = SIG_DFL;
    act.sa_flags = 0;  /* omit SA_RESTART */
    if (sigaction(SIGALRM, &act, (struct sigaction *) NULL) != 0) {
        bsock_syslog(errno, LOG_ERR, "sigaction");
        return false;
    }

    act.sa_handler = SIG_DFL;
    act.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &act, (struct sigaction *) NULL) != 0) {
        bsock_syslog(errno, LOG_ERR, "sigaction");
        return false;
    }

    /*(handler gets reset to SIG_DFL by execve(); SIG_IGN would be inherited)*/
    act.sa_handler = bsock_daemon_sa_ignore;
    act.sa_flags = 0;  /* omit SA_RESTART */
    if (sigaction(SIGPIPE, &act, (struct sigaction *) NULL) != 0) {
        bsock_syslog(errno, LOG_ERR, "sigaction");
        return false;
    }

    act.sa_handler = bsock_daemon_sa_handler;
    act.sa_flags = SA_RESTART;
    if (sigaction(SIGHUP, &act, (struct sigaction *) NULL) != 0) {
        bsock_syslog(errno, LOG_ERR, "sigaction");
        return false;
    }

    act.sa_handler = bsock_daemon_sa_handler;
    act.sa_flags = 0;  /* omit SA_RESTART */
    if (   sigaction(SIGINT,  &act, (struct sigaction *) NULL) != 0
        || sigaction(SIGQUIT, &act, (struct sigaction *) NULL) != 0
        || sigaction(SIGTERM, &act, (struct sigaction *) NULL) != 0) {
        bsock_syslog(errno, LOG_ERR, "sigaction");
        return false;
    }

    return true;
}

bool
bsock_daemon_init (const int supervised, const bool check)
{
    /* Note: not retrying upon interruption; any fail to init means exit fail */

    /* Change current working dir to / for sane cwd and to limit mounts in use*/
    if (0 != chdir("/")) {
        bsock_syslog(errno, LOG_ERR, "chdir /");
        return false;
    }

    /* Configure signal handlers for bsock desired behaviors */
    if (!bsock_daemon_signal_init())
        return false;

    /* Detach from parent (process to be inherited by init) unless supervised */
    if (supervised) {
        if (getpgrp() != getpid() && setsid() == (pid_t)-1) {
            bsock_syslog(errno, LOG_ERR, "setsid");
            return false;
        }
    }
    else {
        pid_t pid;
        if ((pid = fork()) != 0) {   /* parent */
            int status = EXIT_FAILURE;
            if (pid > 0 && waitpid(pid, &status, 0) != pid)
                status = EXIT_FAILURE;
            _exit(status);
        }                            /* child */
        else if ((pid = setsid()) == (pid_t)-1 || (pid = fork()) != 0) {
            if ((pid_t)-1==pid) bsock_syslog(errno, LOG_ERR, "setsid,fork");
            _exit((pid_t)-1 == pid);
        }                            /* grandchild falls through */
    }

    /* Close unneeded file descriptors */
    /* (not closing all fds > STDERR_FILENO; lazy and we check root is caller)
     * (if closing all fds, must then closelog(), bsock_syslog_openlog())*/
    if (0 != nointr_close(STDIN_FILENO))  return false;
    if (0 != nointr_close(STDOUT_FILENO)) return false;
    if (!supervised) {
        if (0 != nointr_close(STDERR_FILENO)) return false;
        bsock_syslog_setlevel(BSOCK_SYSLOG_DAEMON);
    }
    else {
        /* STDERR_FILENO must be open so it is not reused for sockets */
        struct stat st;
        if (0 != fstat(STDERR_FILENO, &st)) {
            bsock_syslog(errno, LOG_ERR, "stat STDERR_FILENO");
            return false;
        }
    }

    /* Sanity check system socket option max memory for ancillary data
     * (see bsock_unix.h for more details) */
    if (check) {
        const size_t optmem_max = bsock_daemon_msg_control_max();
        if (optmem_max > BSOCK_ANCILLARY_DATA_MAX)
            bsock_syslog(errno, LOG_ERR, "max ancillary data very large "
                         "(%zu > %d); consider recompiling bsock with larger "
                         "BSOCK_ANCILLARY_DATA_MAX", optmem_max,
                         BSOCK_ANCILLARY_DATA_MAX);
    }

    return true;
}

static int bsock_daemon_pid = -1;
static int bsock_daemon_socket_bound = -1;
static const char *bsock_daemon_socket_path;

static void
bsock_daemon_atexit (void)
{
    if (0 == bsock_daemon_socket_bound && getpid() == bsock_daemon_pid)
        (void)unlink(bsock_daemon_socket_path);
}

__attribute_nonnull__
int
bsock_daemon_init_socket (const char * const restrict sockpath,
                          const uid_t uid, const gid_t gid, const mode_t mode)
{
    /* N.B.: this routine supports a single (one) socket per program */
    int sfd;
    mode_t mask;
    /* sanity check ownership and permissions on dir that will contain socket */
    /* (other ownership and permissions can be safe; this enforces one option)*/
    /* (note: not checking entire tree above socket dir; TOC-TOU) */
    char * const slash = strrchr(sockpath,'/');
    if (NULL != slash && '/' == *sockpath) {
        struct stat st;
        char dir[slash-sockpath+2];
        memcpy(dir, sockpath, (size_t)(slash-sockpath+1));
        dir[slash != sockpath ? slash-sockpath : 1] = '\0';
        if (0 != stat(dir, &st)) {
            bsock_syslog(errno, LOG_ERR, "%s", dir);
            return -1;
        }
        if (st.st_uid != uid || (st.st_mode & (S_IWGRP|S_IWOTH))) {
            bsock_syslog(EPERM, LOG_ERR,
                         "ownership/permissions incorrect on %s", dir);
            return -1;
        }
    }
    else {
        bsock_syslog(EINVAL, LOG_ERR, "socket path must be absolute path");
        return -1;
    }

    /* N.B.: sockpath must persist after main();
     * sockpath must not be allocated on stack
     * (would be better to malloc() and copy sockpath) */
    bsock_daemon_socket_path = sockpath;
    bsock_daemon_pid = getpid();
    atexit(bsock_daemon_atexit);

    mask = umask(0177); /* create socket with very restricted permissions */
    sfd = bsock_unix_socket_bind_listen(sockpath, &bsock_daemon_socket_bound);
    umask(mask);        /* restore prior umask */
    if (-1 == sfd) {
        bsock_syslog(errno, LOG_ERR, "socket,bind,listen");
        return -1;
    }
    (void)fcntl(sfd, F_SETFD, fcntl(sfd, F_GETFD, 0) | FD_CLOEXEC);

    if (0 == chown(sockpath, uid, gid) && 0 == chmod(sockpath, mode))
        return sfd;

    bsock_syslog(errno, LOG_ERR, "chown,chmod");
    (void)unlink(bsock_daemon_socket_path);
    bsock_daemon_socket_bound = -1;
    nointr_close(sfd);
    return -1;
}

size_t
bsock_daemon_msg_control_max (void)
{
  #ifdef __linux__
    /* obtain system max size for ancillary data
     * (see bsock_unix.h for more details) */
    long optmem_max = BSOCK_ANCILLARY_DATA_MAX;
    ssize_t r;
    const int fd = open("/proc/sys/net/core/optmem_max",O_RDONLY|O_NONBLOCK,0);
    char buf[32];
    if (-1 != fd) {
        if ((r = read(fd, buf, sizeof(buf)-1)) >= 0) {
            buf[r] = '\0';
            errno = 0;
            optmem_max = strtol(buf, NULL, 10);
            if (0 != errno || BSOCK_ANCILLARY_DATA_MAX > optmem_max)
                optmem_max = BSOCK_ANCILLARY_DATA_MAX;
        }
        nointr_close(fd);
    }
    return (size_t)optmem_max;
  #else
    return (size_t)BSOCK_ANCILLARY_DATA_MAX;  /* patches for other OS welcome */
  #endif
}
