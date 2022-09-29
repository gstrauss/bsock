/*
 * bpoll - bookkeeping event poller
 *
 * bpoll provides a thin and portable abstraction interface using historical
 * poll semantics to detect ready events on socket, pipe, and other descriptors.
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

#ifndef INCLUDED_BPOLL_H
#define INCLUDED_BPOLL_H

#include "plasma/plasma_attr.h"
#include "plasma/plasma_stdtypes.h"

/**
 * @file bpoll.h
 * @brief bookkeeping event poller
 */

/*(enable mechanisms coarsely by platform; should replace this with autoconf)*/
#define HAVE_SYS_SELECT_H 1
#if !defined(NETWARE) && !defined(_AIX)
#define HAVE_POLL_H 1
#endif
#ifdef __linux__
/* Linux kernel 2.5.44+ has epoll_wait() */
#define HAVE_SYS_EPOLL_H 1
/* Linux kernel 2.6.16+ and glibc 2.4 has ppoll() */
#define HAS_PPOLL 1
/* Linux kernel 2.6.19+ and glibc 2.6 has epoll_pwait() */
#define HAS_EPOLL_PWAIT 1
#endif
#ifdef __sun
#define HAVE_SYS_DEVPOLL_H 1
#ifdef __SunOS_5_10  /* Solaris 10 has <port.h> for event ports */
#define HAVE_PORT_H 1
#endif
#ifdef __GNUC__      /* XXX: assuming Solaris 10 or better */
#define HAVE_PORT_H 1
#endif
#endif
#ifdef __hpux
#define HAVE_SYS_DEVPOLL_H 1
#endif
#ifdef _AIX
#define HAVE_SYS_POLL_H 1
#ifdef _AIX61  /* AIX 6.1+ has <sys/pollset.h> for pollsets */
#define HAVE_SYS_POLLSET_H 1
#endif
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) \
 || (defined(__APPLE__) && defined(__MACH__))  /* MacOS X */
#define HAVE_SYS_EVENT_H 1
#endif

#if defined(HAVE_SYS_SELECT_H) || defined(_AIX)
# ifndef _WIN32
#  include <sys/select.h>  /* POSIX.1-2001 */
# else /* FD_SETSIZE > 64 on Windows is reported to not scale well */
#  define FD_SETSIZE 64
#  include <Winsock2.h>
# endif
#endif

#if (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE-0 >= 200112L) \
 || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE-0 >= 600)
#define HAS_PSELECT 1
#else
#define HAS_PSELECT 0
#endif

/* ('man ppoll' on Linux for routine with sigset_t arg for signal safety) */
/* http://www.opengroup.org/onlinepubs/000095399/functions/select.html */
/* (ppoll() is linux-specific poll() imp of pselect() requires kernel 2.6.16+
 *  and defining _GNU_SOURCE prior to #include <poll.h>.  This is done in
 *  bpoll.c to avoid forcing exposure of #define _GNU_SOURCE in this header)*/
#ifndef HAS_PPOLL
#define HAS_PPOLL 0
#endif
#ifdef HAVE_POLL_H
# define HAS_POLL 1
# include <poll.h>
#endif
#ifdef HAVE_SYS_POLL_H
# define HAS_POLL 1
# include <sys/poll.h>
#endif
#if !defined(HAVE_POLL_H) && !defined(HAVE_SYS_POLL_H) \
  && defined(HAS_POLL) && HAS_POLL
# include <poll.h>
#endif
#ifndef HAS_POLL
# define HAS_POLL   0
# ifndef POLLIN
#  define POLLIN     0x001
#  define POLLPRI    0x002
#  define POLLOUT    0x004
#  define POLLERR    0x008
#  define POLLHUP    0x010
#  define POLLNVAL   0x020
# endif
struct pollfd {
    int fd;         /**< file descriptor */
    short events;   /**< requested events */
    short revents;  /**< returned events */
};
#endif

#ifdef HAVE_SYS_DEVPOLL_H
# define HAS_DEVPOLL 1
# include <sys/devpoll.h>
#else
# define HAS_DEVPOLL 0
#endif

#ifdef HAVE_SYS_EPOLL_H
# define HAS_EPOLL 1
# include <sys/epoll.h>
# ifndef HAS_EPOLL_PWAIT
# define HAS_EPOLL_PWAIT 0
# endif
#else
# define HAS_EPOLL 0
# define HAS_EPOLL_PWAIT 0
#endif

#ifdef HAVE_SYS_EVENT_H
# define HAS_KQUEUE 1
# include <sys/event.h>
#else
# define HAS_KQUEUE 0
#endif

#ifdef HAVE_PORT_H
# define HAS_EVPORT 1
# include <port.h>
#else
# define HAS_EVPORT 0
#endif

#ifdef HAVE_SYS_POLLSET_H
# define HAS_POLLSET 1
/* #include <sys/poll.h> *//*(should have been done above)*/
# include <sys/pollset.h>
# include <fcntl.h>
#else
# define HAS_POLLSET 0
#endif

#include <time.h>  /* struct timespec */

#ifdef _REENTRANT
#ifndef _THREAD_SAFE
#define _THREAD_SAFE
#endif
#endif

#ifdef _THREAD_SAFE
#include <pthread.h>       /* pthread_mutex_t */
#endif


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @defgroup bpoll Poll Routines
 * @{
 */

/**
 * Use poll() constants provided by the system.
 * In the cases of /dev/poll and epoll, these also match the system constants
 *
 * @defgroup bpoll_opt Poll Options
 * @{
 */
#define BPOLLIN    POLLIN    /**< able to read without blocking */
#define BPOLLPRI   POLLPRI   /**< pending priority data */
#define BPOLLOUT   POLLOUT   /**< able to write without blocking */
#define BPOLLERR   POLLERR   /**< pending error */
#define BPOLLHUP   POLLHUP   /**< hangup occurred */
#define BPOLLNVAL  POLLNVAL  /**< invalid polling request (invalid fd) */

/* For semi-completeness, though not meaningful to all bpoll mechanisms
 * (might change default value to 0 on platforms which do not support a flag) */
#ifdef POLLRDNORM
#define BPOLLRDNORM POLLRDNORM
#else
#define BPOLLRDNORM 0x0040
#endif
#ifdef POLLRDBAND
#define BPOLLRDBAND POLLRDBAND
#else
#define BPOLLRDBAND 0x0080
#endif
#ifdef POLLWRNORM
#define BPOLLWRNORM POLLWRNORM  /* (equivalent to POLLOUT on Solaris) */
#else
#define BPOLLWRNORM 0x0100      /* Linux value */
#endif
#ifdef POLLWRBAND
#define BPOLLWRBAND POLLWRBAND
#else
#define BPOLLWRBAND 0x0200      /* (0x0100 on Solaris) */
#endif
#ifdef POLLMSG
#define BPOLLMSG    POLLMSG
#else
#define BPOLLMSG    0x0400
#endif
#ifdef POLLREMOVE               /* /dev/poll */
#define BPOLLREMOVE POLLREMOVE
#else
# ifdef __sun
#  define BPOLLREMOVE 0x0800
# else
#  define BPOLLREMOVE 0x1000    /* Linux 2.6.17+ with _GNU_SOURCE defined */
# endif
#endif
#ifdef POLLRDHUP
#  define BPOLLRDHUP  POLLRDHUP /* Linux epoll (must be requested in events) */
#else
#  define BPOLLRDHUP  0x2000
#endif
#ifdef POLLNORM
#define BPOLLNORM   POLLNORM
#else
#define BPOLLNORM   BPOLLRDNORM
#endif
#ifdef EPOLLONESHOT
#define BPOLLDISPATCH EPOLLONESHOT
#else
#define BPOLLDISPATCH 0x40000000/* Linux epoll */
#endif
#ifdef EPOLLET
#define BPOLLET     EPOLLET     /* (edge-triggered; minimal support by bpoll) */
#else
#define BPOLLET     0x80000000  /* Linux epoll */
#endif
/* http://lkml.org/lkml/2003/7/12/116 explains rationale for POLLRDHUP
 *   (detect read shutdown event when using edge-triggered epoll)
 *   (POLLRDHUP must be requested in pollfd.events) */
/** @} */

/* convenient combinations */
#define BPOLLRDANY (BPOLLIN | BPOLLRDNORM | BPOLLRDBAND | BPOLLPRI)
#define BPOLLWRANY (BPOLLOUT| BPOLLWRNORM | BPOLLWRBAND)


/**
 * @defgroup bpoll polling mechanisms
 * @{
 */
enum {
    BPOLL_M_NOT_SET = 0,
    BPOLL_M_POLL    = 1,
    BPOLL_M_DEVPOLL = 2,
    BPOLL_M_EPOLL   = 4,
    BPOLL_M_KQUEUE  = 8,
    BPOLL_M_EVPORT  = 16,
    BPOLL_M_POLLSET = 32
};
/** @} */

/**
 * @defgroup bpoll element file descriptor type
 * @{
 */
typedef enum {
    BPOLL_FD_NOT_SET = 0,   /**< descriptor type is not set */
    BPOLL_FD_SOCKET,        /**< descriptor is socket */
    BPOLL_FD_PIPE,          /**< descriptor is pipe */
    BPOLL_FD_FILE,          /**< descriptor is file */
    BPOLL_FD_EVENT,         /**< descriptor is eventfd */
    BPOLL_FD_SIGNAL,        /**< descriptor is signalfd */
    BPOLL_FD_TIMER,         /**< descriptor is timerfd */
    BPOLL_FD_INOTIFY        /**< descriptor is inotify fd */
} bpoll_fdtype_e;
/** @} */

#define BPOLL_FD_SIGMASK 0x80000000  /* flag for bpoll_poll_single() */

/**
 * @defgroup bpoll element bit flags
 * @{
 */
typedef enum {
    /* flags */
    BPOLL_FL_ZERO       = 0, /**< zero (flag name for clarity) */
    BPOLL_FL_CLOSE      = 1, /**< close fd upon removal from bpollset */
    /* flpriv (flags internal, private) */
    BPOLL_FL_MEM_BLOCK  = 1, /**< element allocated from bpollset mem chunk */
    BPOLL_FL_CTL_ADD    = 2, /**< element pending add */
    BPOLL_FL_CTL_DEL    = 4, /**< element pending delete */
    BPOLL_FL_DISPATCHED = 8, /**< element returned by kernel (BPOLLDISPATCH) */
    BPOLL_FL_DISP_KQRD  = 16,/**< element returned by kernel (BPOLLDISPATCH) */
    BPOLL_FL_DISP_KQWR  = 32 /**< element returned by kernel (BPOLLDISPATCH) */
} bpoll_flags_e;
/** @} */

/** @see struct bpollelt_t */
typedef struct bpollelt_t bpollelt_t;

/**
 * bpoll element
 * @remark initialize by calling bpoll_elt_init()
 */
struct bpollelt_t {
    int fd;                     /**< file descriptor or OS identifier */
    int events;                 /**< requested events (read-only for caller) */
    int revents;                /**< returned events (not always used by lib) */
    unsigned int idx;           /**< index in bpollset substructures (private)*/
    unsigned int fdtype :  8;   /**< descriptor type */
    unsigned int flags  :  8;   /**< flags */
    unsigned int flpriv : 16;   /**< flags (private; internal) */
    void *udata;                /**< user data; allows app to add context */
};

/** @see struct bpollset_t */
typedef struct bpollset_t bpollset_t;

/** bpoll set function pointers for callbacks and for memory management */
/* bpoll_fn_cb_close_t should call close() and do application bookkeeping;
 * bpoll_fn_cb_close_t should not modify bpollset or call bpoll routines */
typedef void (*bpoll_fn_cb_event_t)(bpollset_t *, bpollelt_t *, int data);
typedef void (*bpoll_fn_cb_close_t)(bpollset_t *, bpollelt_t *);
typedef void * (*bpoll_fn_mem_alloc_t)(void *, size_t);
typedef void (*bpoll_fn_mem_free_t)(void *, void *);

/** bpoll element memory block */
#if !defined(__GNUC__) || __GNUC__-0 >= 3
struct bpoll_mem_block {
    bpollelt_t b;
    char data[];  /* C99 VLA */
};
#else
struct bpoll_mem_block {
    bpollelt_t b;
    char data[0];
};
#endif
typedef struct bpoll_mem_block bpoll_mem_block_t;

/** bpoll set of bpoll elements, bpoll poll mechanism, and state */
struct bpollset_t {
    unsigned int mech;
    unsigned int idx;
    unsigned int clr;
    unsigned int limit;
    int nfound;
    unsigned int queue_sz;
    unsigned int results_sz;
    unsigned int bpollelts_sz;
    bpollelt_t **bpollelts;
    bpollelt_t **results;
    bpollelt_t **rmlist;
    int rmsz;
    int rmidx;
    struct pollfd *pollfds;
    struct pollfd *pfd_ready;
  #if HAS_KQUEUE
    struct kevent *kevents;
    struct kevent *keready;
    int kereceipts;
  #endif
  #if HAS_EVPORT
    struct port_event *evport_events;
  #endif
  #if HAS_EPOLL
    struct epoll_event *epoll_events;
    struct epoll_event *epoll_ready;
  #endif
  #if HAS_POLLSET
    struct poll_ctl *pollset_events;
  #endif
    sigset_t *sigmaskp;

  #if !HAS_POLLSET  /* kqueue, evport, devpoll, epoll */
    int fd;
  #else             /* pollset (AIX) */
    pollset_t fd;
  #endif
    int timeout;
    struct timespec ts; /*significant only for HAS_KQUEUE HAS_EVPORT HAS_PPOLL*/

    bpoll_fn_cb_event_t fn_cb_event;
    bpoll_fn_cb_close_t fn_cb_close;
    bpoll_fn_mem_alloc_t fn_mem_alloc;
    bpoll_fn_mem_free_t fn_mem_free;

    void *vdata;
    size_t mem_chunk_sz;
    struct bpoll_mem_block *mem_chunk_head;
    struct bpoll_mem_block *mem_chunk_tail;
    struct bpoll_mem_block *mem_block_head;
    unsigned int mem_block_sz;
    int mem_block_freed;

  #if !HAS_POLL || (HAS_PSELECT && !HAS_PPOLL)
    fd_set readset;
    fd_set writeset;
    fd_set exceptset;
    int maxfd;
  #ifdef NETWARE
    unsigned int fdtype;
  #endif
  #endif /* !HAS_POLL */

  #ifdef _THREAD_SAFE
    /* spaced for separate cache line from frequently hit members, if possible*/
    void *bpollelts_used[16];
    pthread_mutex_t mutex;
    volatile int nelts;
  #else  /* !_THREAD_SAFE */
    int nelts;
  #endif /* !_THREAD_SAFE */
};




/*(e.g. for use before accept() of new fds intended to be added to bpollset)*/
#define bpoll_get_is_full(bpollset) \
  ((int)(bpollset)->limit == (bpollset)->nelts)

#define bpoll_get_nelts_avail(bpollset) \
  ((int)(bpollset)->limit - (bpollset)->nelts)

__attribute_const__
__attribute_warn_unused_result__
EXPORT extern unsigned int
bpoll_mechanisms (void);

/* optional interface for consumer to flush pending events, e.g. fd removal,
 * prior to bpoll_poll() or bpoll_kernel() (which calls this if no error)*/
__attribute_noinline__
__attribute_nonnull__()
EXPORT extern int  __attribute_regparm__((1))
bpoll_flush_pending (bpollset_t * const restrict bpollset);

/* (returns 0 on success, else the value of errno) */
__attribute_nonnull__()
EXPORT extern int  __attribute_regparm__((1))
bpoll_enable_thrsafe_add(bpollset_t * const restrict bpollset);

/* (separate routine from bpoll_init() so that a cleanup can be registered
 *  (i.e. bpoll_destroy()) before opening /dev/poll, kqueue, epoll, etc.)
 */
__attribute_warn_unused_result__
EXPORT extern bpollset_t *
bpoll_create (void * const vdata,
              bpoll_fn_cb_event_t  const fn_cb_event,
              bpoll_fn_cb_close_t  const fn_cb_close,
              bpoll_fn_mem_alloc_t const fn_mem_alloc,
              bpoll_fn_mem_free_t  const fn_mem_free);

/* (returns 0 on success, else the value of errno) */
__attribute_nonnull__()
__attribute_warn_unused_result__
EXPORT extern int  __attribute_regparm__((1))
bpoll_init (bpollset_t * const restrict bpollset,
            unsigned int flags, unsigned int limit, 
            const unsigned int queue_sz, const unsigned int block_sz);

EXPORT extern void  __attribute_regparm__((1))
bpoll_destroy (bpollset_t * const restrict bpollset);

/* (caller should not modify bpollelt, but macros using this need non-const) */
__attribute_pure__
__attribute_nonnull__()
__attribute_warn_unused_result__
EXPORT extern bpollelt_t *  __attribute_regparm__((2))
bpoll_elt_get (bpollset_t * const restrict bpollset, const int fd);

#define bpoll_elt_get_fd(bpollelt)            ((bpollelt)->fd)
#define bpoll_elt_get_events(bpollelt)        ((bpollelt)->events)
#define bpoll_elt_get_revents(bpollelt)       ((bpollelt)->revents)
#define bpoll_elt_get_flags(bpollelt)         ((bpollelt)->flags)
#define bpoll_elt_get_udata(bpollelt)         ((bpollelt)->udata)
#define bpoll_elt_set_udata(bpollelt, vdata)  ((bpollelt)->udata = (vdata))
#define bpoll_elt_clear_revents(bpollelt)     ((bpollelt)->revents = 0)

#define bpoll_get_nelts(bpollset)             ((bpollset)->nelts)
#define bpoll_get_nfound(bpollset)            ((bpollset)->nfound)
#define bpoll_get_results(bpollset)           ((bpollset)->results)
#define bpoll_get_vdata(bpollset)             ((bpollset)->vdata)
#define bpoll_set_vdata(bpollset, udata)      ((bpollset)->vdata = (udata))

/* for use only to re-init fd before bpollelt added to bpollset,
 * i.e. when struct sockaddr_storage is part of bpollelt->udata
 *      for accept(), which must occur prior to bpoll_elt_add() */
#define bpoll_elt_reinit_fd(bpollelt, fdinit) (bpollelt)->fd = (fdinit)

#if HAS_PSELECT || HAS_PPOLL || HAS_EPOLL_PWAIT
/* atomic signal mask manipulation; default is NULL: no sigmask manipulation) */
/* (used only with pselect() and Linux-specific ppoll() and epoll_pwait()) */
__attribute_nonnull__()
EXPORT extern sigset_t *  __attribute_regparm__((1))
bpoll_sigmask_get (bpollset_t * const restrict bpollset, const int vivify);

__attribute_cold__
__attribute_noinline__
__attribute_nonnull__((1))
EXPORT extern int
bpoll_sigmask_set (bpollset_t * const restrict bpollset,
                   sigset_t * const restrict sigs);
#else
#define bpoll_sigmask_get(bpollset,vivify)    NULL
#define bpoll_sigmask_set(bpollset,maskp)     0
#endif


__attribute_nonnull__((1))
EXPORT extern bpollelt_t *  __attribute_regparm__((2))
bpoll_elt_init (bpollset_t * const restrict bpollset, 
                bpollelt_t * restrict bpollelt,
                const int fd,
                const bpoll_fdtype_e fdtype,
                const bpoll_flags_e flags);

__attribute_nonnull__()
EXPORT extern int  __attribute_regparm__((3))
bpoll_elt_rearm_immed (bpollset_t * const restrict bpollset,
                       bpollelt_t ** const restrict bpollelt,
                       int * const restrict nelts,
                       const int events);

__attribute_nonnull__()
EXPORT extern int  __attribute_regparm__((3))
bpoll_elt_add_immed (bpollset_t * const restrict bpollset,
                     bpollelt_t ** const restrict bpollelt,
                     int * const restrict nelts,
                     const int events);

__attribute_nonnull__()
EXPORT extern int  __attribute_regparm__((3))
bpoll_elt_add (bpollset_t * const restrict bpollset,
               bpollelt_t * const restrict bpollelt,
               const int events);

/* (it is caller's responsibility to make sure bpollelt is part of bpollset)
 * caller should not set bpollelt->events except through this API, although
 * caller may read bpollelt->events for use in & or | current set of flags
 * using macro bpoll_elt_get_events() and bpoll_elt_get_revents()
 */
__attribute_nonnull__((1))
EXPORT extern int  __attribute_regparm__((3))
bpoll_elt_modify (bpollset_t * const restrict bpollset,
                  bpollelt_t * const restrict bpollelt,
                  const int events);

#define bpoll_elt_modify_by_fd( bpollset, fd, events ) \
        bpoll_elt_modify((bpollset), bpoll_elt_get((bpollset),(fd)), (events))

__attribute_nonnull__((1))
EXPORT extern int  __attribute_regparm__((2))
bpoll_elt_remove (bpollset_t * const restrict bpollset,
                  bpollelt_t * const restrict bpollelt);

#define bpoll_elt_remove_by_fd( bpollset, fd ) \
        bpoll_elt_remove((bpollset), bpoll_elt_get((bpollset),(fd)))

__attribute_nonnull__()
EXPORT int  __attribute_regparm__((2))
bpoll_elt_destroy (bpollset_t * const restrict bpollset,
                   bpollelt_t * const restrict bpollelt);


#define bpoll_timespec_from_sec_nsec(bpollset, sec, nsec)              \
  ((bpollset)->timeout    = 0, /* filled in by bpoll_timespec_set() */ \
   (bpollset)->ts.tv_sec  = (time_t)(sec),                             \
   (bpollset)->ts.tv_nsec = (nsec),                                    \
   bpoll_timespec_set((bpollset), &(bpollset)->ts))

#define bpoll_timespec_from_msec(bpollset, msec)                               \
  ((bpollset)->timeout    = (msec),                                            \
   (bpollset)->ts.tv_sec  = (time_t)((msec) / 1000),  /*millisecs to secs*/    \
   (bpollset)->ts.tv_nsec = ((msec) % 1000) * 1000000,/*millisecs to nanosecs*/\
   bpoll_timespec_set((bpollset), &(bpollset)->ts))

#define bpoll_timespec(bpollset)        (&(bpollset)->ts)
#define bpoll_timespec_get(bpollset)    (&(bpollset)->ts)
#define bpoll_get_timespec(bpollset)    (&(bpollset)->ts)
#define bpoll_get_timeout_ms(bpollset)  (bpollset)->timeout
#define bpoll_set_timespec(bpollset,ts) bpoll_timespec_set((bpollset), (ts))

__attribute_noinline__
__attribute_nonnull__((1))
EXPORT struct timespec *  __attribute_regparm__((2))
bpoll_timespec_set (bpollset_t * const bpollset,
                    const struct timespec * const timespec);


/* poll kernel for ready events
 * This routine has return values similar to poll()
 * -1 on error, 0 on timeout, else number of descriptors with pending events
 * caller must handle EINTR, because timespec NULL can only be interrupted by a
 * signal, and so we do not want to automatically restart the call if EINTR is
 * received.  Upon receipt of other errors, caller should call bpoll_destroy().
 */
__attribute_noinline__
__attribute_nonnull__((1))
EXPORT extern int  __attribute_regparm__((2))
bpoll_kernel (bpollset_t * const restrict bpollset,
              const struct timespec * const timespec);

/* process each bpollelt with pending event(s) (e.g. run callback routine)
 * (intended to be called following bpoll_kernel())
 * Return value is same as bpoll_kernel()
 */
__attribute_noinline__
__attribute_nonnull__()
EXPORT extern int  __attribute_regparm__((1))
bpoll_process (bpollset_t * const restrict bpollset);

/* (convenience routine)
 * poll kernel and process events
 * Wraps bpoll_kernel() and bpoll_process() routines
 * Return value from bpoll_kernel() is passed through.
 *
 * Caller must handle EINTR, because timespec NULL can only be interrupted by a
 * signal, and so we do not want to automatically restart the call if EINTR is
 * received.
 *
 * If bpollset->fn_cb_event is NULL, then the effect will be to fill the
 * bpollelts' revents with pending events.  This may be useful for bpollsets
 * with few bpollelts where caller has assigned meaning to specific bpollelts
 * and finds it convenient to walk all bpollelts between calls to this routine.
 * In this case, it is caller responsibility to clear bpollelt->revents of all
 * bpollelts where bpollelt->revents != 0 between calls to this routine.  On
 * subsequent call to bpoll_poll(), bpollelt->revents *may* have flags or'd if
 * there are new events, and *may or may not* be zeroed if there are no new
 * events on that bpollelt.  Not clearing bpollelt->revents will not affect
 * these routines, but may confuse or block the caller that checks and reacts
 * to the bpollelt->revents flags.
 *
 * Callback routine should expect to handle read and write separately, since
 * for the kqueue mechanism, the callback will be called twice (once for read
 * and once for write) if both read and write are ready.  (The callback routine
 * should not assume that read or write is not set if bpollelt->revents sets
 * one but not the other.)  (If the callback routine pointer is NULL, then the
 * flags are OR'd (|) together, so both BPOLLIN and BPOLLOUT will be set upon
 * return from this routine bpoll_poll(), but this is not true if the callback
 * routine pointer is non-NULL.)
 *
 * Callback routine can choose to ignore the info provided by 'data' param.
 * It should ignore it if the value is -1.
 * For 'data' values >= 0, they have meaning depending on kqueue filter:
 *   revents & BPOLLIN   -> data is length of buffered data pending to be read
 *                          (0 indicates EOF)
 *   revents & BPOLLOUT  -> data is length of buffer space available for writing
 *   revents & BPOLLHUP  -> no more data can be written; peer no longer reading
 *                          (there might still be data available to read)
 *   revents & BPOLLNVAL -> data is system errno
 * The value of 'data' should be >= 0 for sockets and pipes.
 * Note that the value in 'data' might be negative: a negative offset might be
 * returned by EVFILT_READ on a VNODE, including value of -1, but this library
 * is intended for use on sockets and pipes, not on VNODES.  Likewise, NOTE_EOF
 * is not set for VNODES.  In other words, if bpollelt->fdtype == BPOLL_FD_FILE,
 * then be careful with the value of 'data'.
 *
 * When the kqueue mechanism is being used, this library expects to operate
 * only on EVFILT_READ and EVFILT_WRITE kqueue filters so if filter is not
 * one, then we expect the other.  Violate this assumption at your own risk.
 */
__attribute_nonnull__((1))
EXPORT extern int  __attribute_regparm__((2))
bpoll_poll (bpollset_t * const restrict bpollset,
            const struct timespec * const timespec);

/* poll single descriptor (standalone, portable, convenience routine)
 * (overload sec == (time_t)-1 to mean infinite (no) timeout)
 * (overload fdtype to use empty sigmask if (fdtype & BPOLL_FD_SIGMASK))
 * (overload return value: 0 timeout, -1 interrupt/error, other: revents)
 */
EXPORT extern int
bpoll_poll_single (const int fd, const int events, const int fdtype,
                   const time_t sec, const long nsec);


#ifdef __cplusplus
}
#endif

#endif  /* ! BPOLL_H */
