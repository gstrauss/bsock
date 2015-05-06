/*
 * proxyexec - proxy command execution without setuid
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

/* Notes:
 * - proxyexec requires that daemon be given command to run with client args.
 *   Command that daemon runs should validate and optionally replace client
 *   argv[0], which is argv[1] provided to command run by daemon.
 * - proxyexec does not perform any server-side concurrency control
 *   Target command should manage concurrency, as required.
 *   Alternatively, login session limits by user might be employed.
 */

#include <plasma/plasma_attr.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <wordexp.h>

#include <bsock/bsock_daemon.h>
#include <bsock/bsock_syslog.h>
#include <bsock/bsock_unix.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

#ifndef PATH_MAX
#ifdef MAXPATHLEN
#define PATH_MAX MAXPATHLEN
#else
#define PATH_MAX 1024
#endif
#endif

#ifndef PROXYEXEC_SOCKET_DIR    /* must end in '/' */
#define PROXYEXEC_SOCKET_DIR "/usr/local/var/run/proxyexec/"
#endif

#ifndef __GLIBC_PREREQ
#  if defined __GLIBC__ && defined __GLIBC_MINOR__
#    define __GLIBC_PREREQ(maj, min) \
        ((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))
#  else
#    define __GLIBC_PREREQ(maj, min) 0
#  endif
#endif

/* rawmemchr and dup3 are non-portable GNU glibc extension
 * copy prototyes instead of #define _GNU_SOURCE before all headers
 * to limit exposed definitions to standards-compliant definitions */
#if __GLIBC_PREREQ(2,1)
extern void *rawmemchr (__const void *__s, int __c)
     __THROW __attribute_pure__ __nonnull ((1));
#define RAWMEMCHR(s,c,z) rawmemchr(s,c)
#else
#define RAWMEMCHR(s,c,z) memchr(s,c,z)
#endif
#if __GLIBC_PREREQ(2,9)
/*(need _XOPEN_SOURCE=700 define O_CLOEXEC, but vfork() removed from SUSv7)
 *(since dup3() is glibc extension, also copy the glibc O_CLOEXEC definition)*/
#ifndef O_CLOEXEC 
#define O_CLOEXEC 02000000
#endif
int dup3(int oldfd, int newfd, int flags);
#endif
#if defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 700 && !defined(__USE_MISC)
extern pid_t vfork (void); /*(vfork() removed from POSIX.1-2008 (SUSv7))*/
#endif

/* module contains both client and server code
 * (code could be split into separate .c files, but keep together for brevity)*/

/* nointr_close() - make effort to avoid leaking open file descriptors */
static int
nointr_close (const int fd)
{ int r; retry_eintr_do_while(r = close(fd), r != 0); return r; }

__attribute_noinline__
static int
retry_poll_fd (const int fd, const short events, const int timeout)
{
    struct pollfd pfd = { .fd = fd, .events = events, .revents = 0 };
    int n; /*EINTR results in retrying poll with same timeout again and again*/
    retry_eintr_do_while(n = poll(&pfd, 1, timeout), -1 == n);
    if (0 == n) errno = ETIME; /* specific for bsock; not generic */
    return n;
}

struct proxyexec_env_st {
  const size_t sz;
  const char * restrict s;
};

/* env vars permitted to tranfer
 * SSH_CONNECTION and CGI/1.1 REMOTE_{ADDR,PORT},SERVER_{ADDR,PORT} for logging
 * (very incomplete list of CGI/1.1 variables) */
static struct proxyexec_env_st proxyexec_envs[] =
  {
    { sizeof("REMOTE_ADDR")-1,    "REMOTE_ADDR" },
    { sizeof("REMOTE_PORT")-1,    "REMOTE_PORT" },
    { sizeof("SERVER_ADDR")-1,    "SERVER_ADDR" },
    { sizeof("SERVER_PORT")-1,    "SERVER_PORT" },
    { sizeof("SSH_CONNECTION")-1, "SSH_CONNECTION" }
  };

/*
 * daemon (server)
 */

struct proxyexec_context {
  int fd;
  uid_t uid;
  gid_t gid;
  int argc;
  char **argv;
  const char *path;
};

__attribute_pure__
__attribute_nonnull__
static int
proxyexec_env_cmp (const void *x, const void *y)
{
    const struct proxyexec_env_st * const restrict a =
      (const struct proxyexec_env_st *)x;
    const struct proxyexec_env_st * const restrict b =
      (const struct proxyexec_env_st *)y;
    return a->sz < b->sz ? -1 : a->sz > b->sz ? 1 : memcmp(a->s, b->s, a->sz);
}

__attribute_pure__
__attribute_nonnull__
static inline bool
proxyexec_env_allowed (const char * const restrict s, const size_t sz)
{
    const struct proxyexec_env_st e = { .s = s, .sz = sz };
    return bsearch(&e, proxyexec_envs,
                   sizeof(proxyexec_envs)/sizeof(struct proxyexec_env_st),
                   sizeof(struct proxyexec_env_st), proxyexec_env_cmp) != NULL;
}

__attribute_nonnull__
static bool
proxyexec_argv_env_parse (char *b, char * const e,
                          char ** const restrict argv, const uint32_t argc)
{
    /* Note: use of putenv() requires data passed by caller be persistent
     * (i.e. data should be located on heap and not on stack) */
    /* b is beginning of data; e is (data + datasz);
     * argv must be sized 1 greater than argc (for terminating NULL) */
    argv[argc] = NULL;
    if (b == e)
        return (0 == argc);

    if ('\0' != *(e-1))  /* error unless buffer ends in '\0' (or is empty) */
        return (errno = EINVAL, false);
    /* (could now use non-portable GNU rawmemchr() to search for '\0' below) */

    /* parse received data into argc, argv (always set argv[argc] = NULL) */
    uint32_t argn;
    for (argn = 0; argn < argc && (argv[argn] = b) != e; ++argn)
        b = 1 + (char *)RAWMEMCHR(b, '\0', e-b);
    if (argn != argc)
        return (errno = EINVAL, false);

    /* parse remaining strings into environment, if any
     * (silently skip vars whose values look like bash functions;
     *  do not propagate exported bash functions across security boundary) */
    errno = EINVAL;
    char *eq = b;
    while (b != e && (eq = (char *)memchr(b, '=', (size_t)(e - b))) != NULL
           && proxyexec_env_allowed(b, (size_t)(eq - b))
           && ((eq[1] != '(' || e-eq-1 < 4 || 0 != memcmp(eq+1, "() {", 4))
               ? 0 == putenv(b) : true))
        b = 1uL + (char *)RAWMEMCHR(eq+1, '\0', e-eq-1);
    return (b == e);
}

static size_t proxyexec_ctrlbuf_sz;
static char *proxyexec_ctrlbuf;

/* preallocate proxyexec_ctrlbuf; implicit copy-on-write in child processes */
static bool
proxyexec_ctrlbuf_alloc (void)
{
    proxyexec_ctrlbuf_sz = bsock_daemon_msg_control_max();
    proxyexec_ctrlbuf = malloc(proxyexec_ctrlbuf_sz);
    if (proxyexec_ctrlbuf != NULL)
        return true;
    else {
        bsock_syslog(errno, LOG_ERR, "max ancillary data very "
          "large (?); error in malloc(%zu)", proxyexec_ctrlbuf_sz);
        return false;
    }
}

__attribute_nonnull__
static ssize_t
proxyexec_stdfds_recv_dup2 (int fd, struct iovec * const restrict iov,
                            const size_t iovlen)
{
    /* caller must ensure fd > STDERR_FILENO, or else fd gets closed below */
    /* use of proxyexec_ctrlbuf not thread-safe; proxyexec is not threaded */
    int rfds[3];
    unsigned int n = 3;
    int i, x;
    const ssize_t r = bsock_unix_recv_fds_ex(fd, rfds, &n, iov, iovlen,
                                             proxyexec_ctrlbuf,
                                             proxyexec_ctrlbuf_sz);
    if (-1 == r || 3 != n)
        return -1;  /* fatal error; called should exit; might leak fds */
    /* (STDIN_FILENO == 0, STDOUT_FILENO == 1, STDERR_FILENO == 2) */
    for (i = 0; i < 3; ++i) {
        if (i != rfds[i]) {
            do { x = dup2(rfds[i], i);
            } while (-1 == x && (errno == EINTR || errno == EBUSY));
            if (x != i || 0 != nointr_close(rfds[i]))
                return -1;  /* fatal error; caller should exit; leak fds */
        }
    }
    return r;
}

__attribute_nonnull__
static int
proxyexec_fork_exec (char ** const restrict argv)
{
    /* set SIGCHLD handler to default (not ignored, as is done in parent) */
    struct sigaction act;
    (void) sigemptyset(&act.sa_mask);
    act.sa_handler = SIG_DFL;
    act.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &act, (struct sigaction *) NULL) != 0) {
        bsock_syslog(errno, LOG_ERR, "sigaction");
        return EXIT_FAILURE;
    }

    int status = EXIT_FAILURE;
    const pid_t pid = vfork();
    if (0 == pid) {
        execv(argv[0], argv);
        _exit(errno);  /* exec() failed */
    }
    else if (-1 != pid) {
        /* close transferred descriptors so that target program can detect EOF*/
        nointr_close(STDIN_FILENO);
        nointr_close(STDOUT_FILENO);
        nointr_close(STDERR_FILENO);
        retry_eintr_while(-1 == waitpid(pid, &status, 0));
    }

    return status;
}

__attribute_noinline__
__attribute_nonnull__
static int
proxyexec_child_session (struct proxyexec_context * const restrict cxt)
{
    /* Note: leaks memory upon failure, but free() skipped since program exits*/
        /*if (iov[1].iov_base != buf) free(iov[1].iov_base);*/
        /*if (argv != args) free(argv);*/

    char ** restrict argv;
    ssize_t r;
    uint32_t hdr[2];  /* total size (not including hdr), and num argc */
    struct iovec iov[2];
    char *args[1024];/*(large enough to avoid need to malloc() in most cases)*/
    char buf[8192];  /*(large enough to avoid need to malloc() in most cases)*/

    iov[0].iov_base = (void *)hdr;
    iov[0].iov_len  = sizeof(hdr);
    iov[1].iov_base = buf;
    iov[1].iov_len  = sizeof(buf);

    /* receive argv and stdfds
     * (require at least 8 bytes (sizeof(hdr)) sent with initial msg) */
    r = -1;
    if (    1!=retry_poll_fd(cxt->fd, POLLIN, 1000) /* block up to one second */
        || (r = proxyexec_stdfds_recv_dup2(cxt->fd, iov,
                                           sizeof(iov)/sizeof(struct iovec)))
             < (ssize_t)sizeof(hdr)) {
        bsock_syslog((-1 == r ? errno : EINVAL), LOG_ERR, "recv argv,fds");
        return EXIT_FAILURE;
    }
    r -= (ssize_t)sizeof(hdr); /* 8 bytes */
    /* recv remaining data (if any) */
    if (hdr[0] > (uint32_t)r) {
        const size_t more = hdr[0] - (uint32_t)r;
        if (hdr[0] > sizeof(buf)) {
            if (hdr[0] > 2097152u) {/*2 MB; chosen (arbitrarily) to have limit*/
                bsock_syslog(E2BIG, LOG_ERR, "recv argv,fds");
                return EXIT_FAILURE;
            }
            iov[1].iov_base = malloc(hdr[0]);
            if (NULL == iov[1].iov_base) {
                bsock_syslog(errno, LOG_ERR, "malloc");
                return EXIT_FAILURE;
            }
            memcpy(iov[1].iov_base, buf, (size_t)r);
        }

        /* set alarm (uncaught here); enforce time limit on blocking syscall */
        fcntl(cxt->fd, F_SETFL, (fcntl(cxt->fd, F_GETFL, 0) & ~O_NONBLOCK));
        alarm(2);  /* arbitrarily chosen limit */
        r = recv(cxt->fd, ((char *)iov[1].iov_base)+r, more, MSG_WAITALL);
        alarm(0);
      #if MSG_DONTWAIT == 0
        fcntl(cxt->fd, F_SETFL, (fcntl(cxt->fd, F_GETFL, 0) | O_NONBLOCK));
      #endif

        if (more != (size_t)r) {
            bsock_syslog((-1 == r ? errno : EINVAL), LOG_ERR, "recv argv");
            return EXIT_FAILURE;
        }
    }

    /* validate num args; size up argv, leaving space for final NULL */
    if (hdr[1] < sizeof(args)/sizeof(char *) - (size_t)cxt->argc)
        argv = args;
    else {
        if (hdr[1] > 65536u) { /*64K args; chosen (arbitrarily) to have limit*/
            bsock_syslog(E2BIG, LOG_ERR, "recv argv,fds");
            return EXIT_FAILURE;
        }
        argv = malloc(((size_t)cxt->argc+hdr[1]+1)*sizeof(char *));
        if (NULL == argv) {
            bsock_syslog(errno, LOG_ERR, "malloc");
            return EXIT_FAILURE;
        }
    }

    /* Note: must not return() from this routine once we putenv() using data
     * potentially from stack (e.g. in buf), or else might cause program crash*/

    memcpy(argv,cxt->argv,(size_t)cxt->argc*sizeof(char *)); /*target cmd+args*/
    if (!proxyexec_argv_env_parse((char *)iov[1].iov_base,         /*data*/
                                  ((char *)iov[1].iov_base)+hdr[0],/*data+sz*/
                                  argv + cxt->argc, hdr[1])) {     /*argv,argc*/
        bsock_syslog(errno, LOG_ERR, "parse argv,env");
        _exit(EXIT_FAILURE);
    }

    /* add PROXYEXEC_* to environment (buffers are large enough)
     * (sizeof(uid_t,gid_t) <= sizeof(uint32_t) checked in main()
     * Note: typically a very bad (tm) idea to putenv() stack variables, but
     * this routine does not return after this point (see similar note above) */
    char proxyexec_uid[28] = "PROXYEXEC_UID="; /* 14 char label */
    char proxyexec_gid[28] = "PROXYEXEC_GID="; /* 14 char label */
    snprintf(proxyexec_uid+14,sizeof(proxyexec_uid)-14,"%u",(uint32_t)cxt->uid);
    snprintf(proxyexec_gid+14,sizeof(proxyexec_uid)-14,"%u",(uint32_t)cxt->gid);
    if (0 != putenv(proxyexec_uid) || 0 != putenv(proxyexec_gid)) {
        bsock_syslog(errno, LOG_ERR, "putenv");
        _exit(EXIT_FAILURE);
    }
    if (0 != chdir(cxt->path)) {
        bsock_syslog(errno, LOG_ERR, "chdir");
        _exit(EXIT_FAILURE);
    }

    const int status = proxyexec_fork_exec(argv);
    _exit( send(cxt->fd, &status, sizeof(status), MSG_DONTWAIT|MSG_NOSIGNAL)
           == sizeof(status) ? EXIT_SUCCESS : EXIT_FAILURE );

  #if defined(_AIX) || defined(__hpux)
    return EXIT_FAILURE; /*@NOTREACHED@*/
  #endif
}

/*
 * client
 */

__attribute_nonnull__
static ssize_t
proxyexec_stdfds_send (const int fd,
                       struct iovec * const restrict iov, const size_t iovlen)
{
    static const int sfds[] = { STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO };
    return bsock_unix_send_fds(fd, sfds, sizeof(sfds)/sizeof(int), iov, iovlen);
}

__attribute_nonnull__
static size_t
proxyexec_env_serialize (char * const restrict buf, const size_t sz)
{
    /*(future: consider different algorithm if proxyexec_envs[] has many elts)*/
    char *v;
    size_t slen, vlen, total = 0;
    uint32_t u;
    for (u=0; u < sizeof(proxyexec_envs)/sizeof(struct proxyexec_env_st); ++u) {
        if (NULL == (v = getenv(proxyexec_envs[u].s)))
            continue;
        slen = proxyexec_envs[u].sz;
        vlen = strlen(v) + 1;  /* +1 to include terminating NIL */
        if (slen + vlen + 1 > sz - total)
            return SIZE_MAX;
        memcpy(buf+total, proxyexec_envs[u].s, slen);
        buf[total+slen] = '=';
        memcpy(buf+total+slen+1, v, vlen);
        total += slen + vlen + 1;
    }
    return total;
}

__attribute_nonnull__
static bool
proxyexec_argv_env_send (const int fd, wordexp_t * const restrict cmd,
                         char * const restrict envbuf, size_t envbufsz)
{
    /* ARG_MAX (sysconf(_SC_ARG_MAX)) limits max size of argv and environ
     * (therefore, integer overflow of uint32_t should not be possible below) */
    /* iov[0] contains header: 4-byte total len and 4-byte argc */
    size_t sz;
    char ** const restrict argv = cmd->we_wordv;
    const uint32_t argc = (uint32_t)cmd->we_wordc;
    uint32_t u;
    uint32_t max = (argc <= IOV_MAX-2 ? argc : IOV_MAX-1);
    uint32_t hdr[2] = { 0, (uint32_t)argc };/* assert(argc <= UINT_MAX) */
    struct iovec iov[IOV_MAX];
    struct iovec * const iovp = iov+1;
    bool rc;
    /* store argv in struct iovec array (or first IOV_MAX-1 elements if many)*/
    iov[0].iov_base = (void *)hdr;
    iov[0].iov_len  = sizeof(hdr);
    for (sz = 0, u = 0; u < max; ++u)
        sz += iovp[u].iov_len = strlen((iovp[u].iov_base = argv[u])) + 1;
    if (argc <= IOV_MAX-2) {
        /* store buf of environ strings at end of struct iovec array */
        iovp[argc].iov_base = envbuf;
        sz += iovp[argc].iov_len = envbufsz;
        hdr[0] = (uint32_t)sz; /* store 4-byte total len */
        /* send data; sz is not always an exact match, for some reason */
        rc = (sz <= (size_t)proxyexec_stdfds_send(fd, iov, argc+2));
    }
    else { /* handle case of argc > IOV_MAX-2 */
        size_t totalsz = sz;
        char *p;
        struct iovec iovx[2];
        /* calculate size of remaining argv elements */
        for (; u < argc; ++u)
            totalsz += strlen(argv[u]) + 1;
        hdr[0] = (uint32_t)(totalsz + envbufsz); /* store 4-byte total len */
        iovx[0].iov_base = p = malloc((iovx[0].iov_len = totalsz -= sz));
        /* store buf of environ strings at end of struct iovec array */
        iovx[1].iov_base = envbuf;
        iovx[1].iov_len  = envbufsz;
        totalsz += envbufsz; /* totalsz now represents size of data in iovx */
        if (NULL == p)
            return false;
        /* flatten remaining argv into buffer
         * (totalsz arg to memccpy is oversized, but we know that
         *  strings fit into buffer, and p will not be NULL) */
        for (u = IOV_MAX-1; u < argc; ++u)
            p = memccpy(p, argv[u], '\0', totalsz);
        /* send data; sz is not always an exact match, for some reason */
        rc = (        sz <= (size_t)proxyexec_stdfds_send(fd, iov, IOV_MAX)
              && totalsz == (size_t)bsock_unix_send_fds(fd, NULL, 0, iovx, 2));
        free(iovx[0].iov_base);
    }
    /* close transferred descriptors so that target program can detect EOF */
    nointr_close(STDIN_FILENO);
    nointr_close(STDOUT_FILENO);
    nointr_close(STDERR_FILENO);
    return rc;
}

__attribute_nonnull__
static int
proxyexec_client (const int argc, char ** const restrict argv)
{
    /* Syntax check and perform shell expansion if SSH[2]?_ORIGINAL_COMMAND.
     * (SSH2_ORIGINAL_COMMAND is for commerical ssh2, not OpenSSH)
     * Security: wordexp() might be used to probe system for certain info
     * (specifically, wordexp() tilde expansion and wildcard expansion)
     * If this is a security concern, consider using sshd_config ChrootDirectory
     * (or replacing wordexp() with code that performs only word splitting) */
    wordexp_t cmd = { .we_wordc = (size_t)argc, .we_wordv = argv };
    const char *command_string = NULL;
    int fd = -1, status = EXIT_FAILURE;

    /* Note: argc,argv are remaining values after main() removes proxyexec -c */
    if (1 == argc) {
        /* argc should be one and argv[0] contain single string of command,args
         * if /usr/sbin/proxyexec is user shell (e.g. in /etc/passwd or LDAP) */
        command_string = argv[0];
    }
    else if (   NULL != (command_string = getenv("SSH_ORIGINAL_COMMAND"))
             || NULL != (command_string = getenv("SSH2_ORIGINAL_COMMAND"))) {
        /* argc should be zero if proxyexec executed from authorized_keys via
         * command="/usr/sbin/proxyexec -c" and SSH[2]?_ORIGINAL_COMMAND set */
        if (0 != argc) {
            fputs("Invalid argument\n", stderr);
            return EXIT_FAILURE;
        }
    }

    if (NULL != command_string && 0 != wordexp(command_string,&cmd,WRDE_NOCMD)){
        cmd.we_wordc = 0;
        command_string = NULL;
    }

    do {
        size_t sz, envsz;
        char *bn;
        char envbuf[8192];  /*(buffer for env vars; arbitrarily sized)*/

        if (cmd.we_wordc == 0 || *cmd.we_wordv[0] == '\0') {
            fputs("Invalid argument\n", stderr);
            break;
        }

        /* serialize environment to send */
        envsz = proxyexec_env_serialize(envbuf, sizeof(envbuf));
        if (envsz == SIZE_MAX)
            break;

        /* construct path, connect to "/var/run/proxyexec/<basename>/socket" */
        bn = strrchr(cmd.we_wordv[0], '/');
        bn = (NULL != bn) ? bn+1 : cmd.we_wordv[0];
        sz = strlen(bn);  /* disallow "." and "..", and check length */
        if (!(bn[0]=='.' && (bn[1]=='\0' || (bn[1]=='.' && bn[2]=='\0')))
            && sizeof(PROXYEXEC_SOCKET_DIR)+sz+6+sizeof("socket") <= PATH_MAX) {
            /*(add sz for name len, add 6 more for "default"; sz >= 1)*/
            char sock[sizeof(PROXYEXEC_SOCKET_DIR)+sz+6+sizeof("socket")];
            memcpy(sock,PROXYEXEC_SOCKET_DIR,sizeof(PROXYEXEC_SOCKET_DIR)-1);
            memcpy(sock+sizeof(PROXYEXEC_SOCKET_DIR)-1, bn, sz);
            memcpy(sock+sizeof(PROXYEXEC_SOCKET_DIR)-1+sz,
                   "/socket", sizeof("/socket"));
            fd = bsock_unix_socket_connect(sock);
            if (-1 == fd) {
                memcpy(sock+sizeof(PROXYEXEC_SOCKET_DIR)-1,
                       "default/socket", sizeof("default/socket"));
                fd = bsock_unix_socket_connect(sock);
                if (-1 == fd)
                    break;
            }
          #if MSG_DONTWAIT == 0
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
          #endif
        }
        else {
            fputs("Invalid argument\n", stderr);
            break;
        }

      #if MSG_NOSIGNAL==0 /*(ignore SIGPIPE on platforms without MSG_NOSIGNAL)*/
        {   /*(SIGPIPE already ignored in daemon via bsock_daemon_init())*/
            struct sigaction act;
            (void) sigemptyset(&act.sa_mask);
            act.sa_handler = SIG_IGN;
            act.sa_flags = 0;  /* omit SA_RESTART */
            if (sigaction(SIGPIPE, &act, (struct sigaction *) NULL) != 0)
                break;
        }
      #endif

        /* send argv,env,fds over socket and wait for exit status */
        if (   proxyexec_argv_env_send(fd, &cmd, envbuf, envsz)
            && 0 == fcntl(fd, F_SETFL, (fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK))
            && recv(fd, &status, sizeof(status), MSG_WAITALL)==sizeof(status)) {
            if (WIFEXITED(status)) {
                status = WEXITSTATUS(status); /* set exit status from daemon */
                break;
            }
            else if (WIFSIGNALED(status)) {
              #if MSG_NOSIGNAL==0
                if (WTERMSIG(status) == SIGPIPE) {
                    struct sigaction act;
                    (void) sigemptyset(&act.sa_mask);
                    act.sa_handler = SIG_DFL;
                    act.sa_flags = 0;  /* omit SA_RESTART */
                    sigaction(SIGPIPE, &act, (struct sigaction *) NULL);
                }
              #endif
                raise(WTERMSIG(status)); /* raise signal received from daemon */
            }
        }
        status = EXIT_FAILURE;
    } while (0);

    if (-1 != fd)
        nointr_close(fd);

    if (NULL != command_string)
        wordfree(&cmd);

    return status;
}


__attribute_nonnull__
int
main (int argc, char *argv[])
{
    int sfd, cfd, dup2fd, log_info = 1, daemon = false, supervised = false;
    struct proxyexec_context cxt;
    char *sockpath = NULL;
    char path[PATH_MAX];

    /* login shell: -proxyexec ...  (not permitted) */
    if (argv[0][0] == '-') {
        fputs("Invalid invocation; not an interactive shell\n", stderr);
        return EXIT_FAILURE;
    }

    /* client mode: proxyexec -c [cmd] [args]* */
    if (argc >= 2 && argv[1][0]=='-' && argv[1][1]=='c' && argv[1][2]=='\0') {
        if (argc > 2 && argv[2][0] == '-') {
            if (argv[2][1] == '-' && argv[2][2] == '\0') { --argc; ++argv; }
            else { sfd = '?'; /* invalid arg */ goto process_optind; }
        }
        argc -= 2;
        argv += 2;
        return proxyexec_client(argc, argv);/*(possible: argc 0, argv[0] NULL)*/
    }

    /*
     * daemon mode
     */

    /* parse arguments (and require daemon mode be specified explicitly) */
    char * const pc = getenv("POSIXLY_CORRECT");
    static char posixly_correct[] = "POSIXLY_CORRECT=1";
    if (0 != putenv(posixly_correct)) {
        perror("putenv");
        return EXIT_FAILURE;
    }
    while ((sfd = getopt(argc,argv,"dhqs:F")) != -1
           || !daemon || NULL == sockpath || optind == argc) {
      process_optind: /* goto label */
        switch (sfd) {
          case 'd': daemon = true; break;
          case 'F': supervised = true; break;
          case 'q': log_info = 0; break;   /* quiet; skip logging connect info*/
          case 's': sockpath = optarg; break;/*"/var/run/proxyexec/.../socket"*/
          default:  fprintf(stderr, "\nerror: invalid arguments\n");/*fallthru*/
          case 'h': fprintf((sfd == 'h' ? stdout : stderr), "\n"
            "  proxyexec -h                                       help\n"
            "  proxyexec -d [-F] [-q] -s <sock> <cmd> [args]*     daemon mode\n"
            "  proxyexec -c [cmd] [args]*                         client mode\n"
            "\n");
                    return (sfd == 'h' ? EXIT_SUCCESS : EXIT_FAILURE);
        }
    }
    /* remaining arguments define target program argv[0] + positional args that
     * precede arguments received over unix domain socket from client argv */
    cxt.argc = argc - optind;
    cxt.argv = argv + optind;
    if (pc == NULL || *pc == '\0')
        unsetenv("POSIXLY_CORRECT");

    /* save current working directory; bsock_daemon_init() chdir()s to "/" */
    cxt.path = getcwd(path, sizeof(path));
    if (NULL == cxt.path) {
        perror("getcwd");
        return EXIT_FAILURE;
    }

    /* proxyexec redirects stderr to client before exec of target.
     * dup stderr to higher fd to ensure errors go to daemon stderr,
     * (and not back to client) (do this before bsock_daemon_init())
     * (similarly, openlog before fd close()s in bsock_daemon_init()) */
    if ((sfd = dup(STDERR_FILENO)) <= STDERR_FILENO)
        return EXIT_FAILURE;
    if (!supervised)
        nointr_close(sfd);
    else {
        fcntl(sfd, F_SETFD, fcntl(sfd, F_GETFD, 0) | FD_CLOEXEC);
        bsock_syslog_setlogfd(sfd);
        bsock_syslog_setlevel(BSOCK_SYSLOG_PERROR_NOSYSLOG);
    }
    bsock_syslog_openlog("proxyexec", LOG_NOWAIT|LOG_ODELAY, LOG_DAEMON);

    if (!bsock_daemon_init(supervised, false)) /*(false:skip ctrlbuf sz check)*/
        return EXIT_FAILURE;

    /* ensure file descriptors are open to {STDIN,STDOUT,STDERR}_FILENO
     * so that sfd is higher (avoid extra work in client session)
     * bsock_daemon_init() close()s STDIN_FILENO, STDOUT_FILENO, and,
     * if !supervised, also STDERR_FILENO */
    do {
        cfd = open("/dev/null", O_RDWR, 0);  /* not retrying on EINTR; lazy */
        if (-1 == cfd)
            return EXIT_FAILURE;
    } while (cfd < STDERR_FILENO);
    if (cfd > STDERR_FILENO)
        nointr_close(cfd);

    /* proxyexec unix domain socket init; sets FD_CLOEXEC */
    sfd = bsock_daemon_init_socket(sockpath, geteuid(), getegid(), 0666);
    if (-1 == sfd || sfd <= STDERR_FILENO)
        return EXIT_FAILURE;

    /* close std fds to avoid extra work in client session */
    nointr_close(STDIN_FILENO);
    nointr_close(STDOUT_FILENO);
    nointr_close(STDERR_FILENO);

    /* determine to which fd to dup2 cfd in client session
     * (expecting original stderr or openlog on fd 4, and sfd on fd 5) */
    dup2fd = 6;
    struct stat st;
    while (0 == fstat(dup2fd, &st))  /* find next fd to return EBADF */
        ++dup2fd;

    /* set SIGCHLD handler to ignore (master process does not need to reap) */
    struct sigaction act;
    (void) sigemptyset(&act.sa_mask);
    act.sa_handler = SIG_IGN;
    act.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &act, (struct sigaction *) NULL) != 0) {
        bsock_syslog(errno, LOG_ERR, "sigaction");
        return EXIT_FAILURE;
    }

    /* preallocate proxyexec_ctrlbuf; implicit copy-on-write in child procs */
    if (!proxyexec_ctrlbuf_alloc())
        return EXIT_FAILURE;

    /* sort proxyexec_envs[] list of allowed environment variables */
    qsort(proxyexec_envs,sizeof(proxyexec_envs)/sizeof(struct proxyexec_env_st),
          sizeof(struct proxyexec_env_st), proxyexec_env_cmp);
    /* sanity check sizes of types */
    if (sizeof(uid_t) > sizeof(uint32_t) || sizeof(gid_t) > sizeof(uint32_t)) {
        bsock_syslog(E2BIG, LOG_ERR, "uid_t/gid_t larger than uint32_t");
        return EXIT_FAILURE;
    }

    /* daemon event loop: accept() and fork() child to handle each connection */
    do {

        /* accept new connection */
        if (-1 == (cfd = accept(sfd, NULL, NULL))) {
            switch (errno) {
              case ECONNABORTED:
              case EINTR: continue;
              case EINVAL:free(proxyexec_ctrlbuf);
                          return EXIT_FAILURE;
              default: /* temporary process/system resource issue */
                          bsock_syslog(errno, LOG_ERR, "accept");
                          poll(NULL, 0, 10); /* pause 10ms and continue */
                          continue;
            }
        }

        /* get client credentials */
        if (0 != bsock_unix_getpeereid(cfd, &cxt.uid, &cxt.gid)) {
            bsock_syslog(errno, LOG_ERR, "getpeereid");
            nointr_close(cfd);
            continue;
        }

        /* log all connections to (or instantiations of) daemon */
        if (log_info)
            bsock_syslog(0, LOG_INFO, "connect: uid:%u gid:%u %s",
                         (uint32_t)cxt.uid, (uint32_t)cxt.gid, sockpath);

        if (0 == fork()) {
            /*assert(cfd <= STDERR_FILENO);*//* expecting cfd == 0 */
          #if __GLIBC_PREREQ(2,9)
            cxt.fd = dup3(cfd, dup2fd, O_CLOEXEC);
          #else
            cxt.fd = dup2(cfd, dup2fd);
          #endif
            if (-1 == cxt.fd) {
                bsock_syslog(errno, LOG_ERR, "dup2/3");
                _exit( errno );
            }
          #if !__GLIBC_PREREQ(2,9)
            fcntl(cxt.fd, F_SETFD, fcntl(cxt.fd, F_GETFD, 0) | FD_CLOEXEC);
          #endif
            if (!MSG_DONTWAIT)
                fcntl(cxt.fd, F_SETFL, fcntl(cxt.fd, F_GETFL, 0) | O_NONBLOCK);
            nointr_close(cfd);
            _exit( proxyexec_child_session(&cxt) );
        }
        nointr_close(cfd);

    } while (1);
}
