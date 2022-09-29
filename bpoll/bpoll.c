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

#ifndef INCLUDED_BPOLL_C
#define INCLUDED_BPOLL_C

#ifdef __linux__  /* define _GNU_SOURCE prior to #include <poll.h> for ppoll */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include "bpoll.h"

#include <plasma/plasma_feature.h>
#include <plasma/plasma_attr.h>

/* attempt to avoid explosing plasma_* symbols when bpoll.o included in .so */
#ifdef __GNUC__
#pragma GCC visibility push(hidden)
#endif
#include <plasma/plasma_atomic.h>
#ifdef __GNUC__
#pragma GCC visibility pop
#endif

/*#include <assert.h>*/
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef PLASMA_FEATURE_POSIX
#include <unistd.h>        /* close() */
#endif

#ifndef  ENOTSOCK
# define ENOTSOCK EBADF
#endif

#ifdef _THREAD_SAFE
#include <pthread.h>       /* pthread_mutex_t, pthread_mutex_*() */
#else
#define pthread_mutex_lock(mutexp) 0
#define pthread_mutex_unlock(mutexp) (void)0
#define pthread_mutex_init(mutexp,attr) 0
#define pthread_mutex_destroy(mutexp) 0
#endif

#ifdef __cplusplus
#ifndef SIZE_MAX
#define SIZE_MAX ((size_t)-1)
#endif
#endif


/*
 * bpoll static (internal) support functions
 *
 * Code for bpoll mechanisms is contained within this single file (bpoll.c)
 * for encapsulation and compiler inlining and optimization.  The code could be
 * organized into separate files, but at this time it has been chosen not to do
 * so.
 */


/* bpoll block allocator and bpollelt membership of bpollset
 *
 * pool of bpollelt and memory for (optional) data structure used by caller
 * (and associated with bpollelt)  (memory locality and caller convenience)
 *
 * internal note: bpollelt->idx = ~1u is used to flag block as free
 * internal note: blocks are allocated in chunks of BPOLL_MEM_BLOCKS_PER_CHUNK
 *   Pointer to next chunk is stored at end of chunk, and is not included in
 *   bpollset->mem_chunk_sz.  Chunk size is actually:
 *     (mem_chunk_sz + sizeof(bpoll_mem_block_t **))
 */

/* BPOLL_MEM_ALIGNMENT is the minimum alignment used
 * (must be a power of two)
 * (effectively 4-bytes on 32-bit ILP32 and 8-bytes on 64-bit LP64)
 * Note: (long double) might need larger alignment on some systems */
#ifndef BPOLL_MEM_ALIGNMENT
union align {
    long int l;
    double d;
    void *v;
    void (*f)(void);
};
#define BPOLL_MEM_ALIGNMENT sizeof(union align)
#endif
#define BPOLL_MEM_ALIGN(size) \
  (((size) + (BPOLL_MEM_ALIGNMENT - 1)) & ~(size_t)(BPOLL_MEM_ALIGNMENT - 1))
#define BPOLL_MEM_ALIGN_MAX (SIZE_MAX - (BPOLL_MEM_ALIGNMENT - 1))

/* blocks per chunk (choice of 256 is arbitrary) */
#ifndef BPOLL_MEM_BLOCKS_PER_CHUNK
#define BPOLL_MEM_BLOCKS_PER_CHUNK 256
#endif
/* reorder free blocks once in a while (choice of 512 is arbitrary) */
#ifndef BPOLL_MEM_BLOCK_REORDER
#define BPOLL_MEM_BLOCK_REORDER 512
#endif


__attribute_cold__
__attribute_malloc__
__attribute_noinline__
__attribute_nonnull__()
static bpoll_mem_block_t *  __attribute_regparm__((1))
bpoll_mem_chunk_alloc (bpollset_t * const restrict bpollset);
static bpoll_mem_block_t *  __attribute_regparm__((1))
bpoll_mem_chunk_alloc (bpollset_t * const restrict bpollset)
{
    bpoll_mem_block_t *block, *chunk_end;
    const unsigned int block_sz = bpollset->mem_block_sz;
    /*assert(block_sz >= sizeof(bpollelt_t));*/

    /* global lock within program since allocations should be relatively rare,
     * e.g. 1000 times through this routine would allocate 256,000 bpollelts,
     * which is greater than some system-wide limits on num file descriptors.
     * (see BPOLL_MEM_BLOCKS_PER_CHUNK, currently set to 256)
     * In practice, bpollset limits will likely be many fewer */
  #ifdef _THREAD_SAFE
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    if (__builtin_expect( (pthread_mutex_lock(&mutex) != 0), 0))
        return NULL;
  #endif

    /* check if another thread allocated chunk while we waited for mutex lock */
    while (bpollset->mem_block_head == NULL) {/*'while', not 'if', for 'break'*/
        block = (bpoll_mem_block_t *)
                bpollset->fn_mem_alloc(bpollset->vdata,
                                       bpollset->mem_chunk_sz
                                       + sizeof(bpoll_mem_block_t **));
        if (block == NULL)
            break;
        if (bpollset->mem_chunk_tail != NULL)
            *(bpoll_mem_block_t **)((char *)bpollset->mem_chunk_tail
                                    + bpollset->mem_chunk_sz) = block;
        else
            bpollset->mem_chunk_head = block;
        bpollset->mem_chunk_tail = block;
        bpollset->mem_block_head = block;
        chunk_end = (bpoll_mem_block_t *)
          ((char *)block + bpollset->mem_chunk_sz);
        while (block < chunk_end) {
            __builtin_prefetch(block+4, 1, 2); /* XXX: measure perf and tune */
            block->b.idx = ~1u;
            block->b.udata = (void *)((char *)block + block_sz);
            block = (bpoll_mem_block_t *)block->b.udata;
        }
        block = (bpoll_mem_block_t *)(void *)((char *)block - block_sz);
        block->b.udata = NULL;
        *(bpoll_mem_block_t **)chunk_end = NULL;
    }

  #ifdef _THREAD_SAFE
    pthread_mutex_unlock(&mutex);
  #endif
    return bpollset->mem_block_head;
}


__attribute_cold__
__attribute_noinline__
__attribute_nonnull__()
static void  __attribute_regparm__((1))
bpoll_mem_block_reorder (bpollset_t * const restrict bpollset);
static void  __attribute_regparm__((1))
bpoll_mem_block_reorder (bpollset_t * const restrict bpollset)
{
    /*(not thread-safe; mem_block_freed logic skipped when enable_thrsafe_add)*/
    bpoll_mem_block_t *p, *n;
    bpoll_mem_block_t *chunk_head = bpollset->mem_chunk_head;
    const unsigned int block_sz = bpollset->mem_block_sz;
    /*assert(bpollset->mem_block_freed != 0);*/
    bpollset->mem_block_freed = 0;

    /* find first free block in linear search through chunks */
    do {
        bpoll_mem_block_t * const chunk_end = (bpoll_mem_block_t *)
          ((char *)chunk_head + bpollset->mem_chunk_sz);
        p = chunk_head;
        while (p < chunk_end && p->b.idx != ~1u)
            p = (bpoll_mem_block_t *)(void *)((char *)p + block_sz);
        if (p != chunk_end)
            break;
        chunk_head = *(bpoll_mem_block_t **)chunk_end; /* next chunk */
    } while (chunk_head != NULL);

    /* (should not happen if called only when bpollset->mem_block_freed != 0) */
    if (chunk_head == NULL)
        return;

    bpollset->mem_block_head = p;

    /* link free blocks by chasing pointers in linear search through chunks */
    n = (bpoll_mem_block_t *)(void *)((char *)p + block_sz);
    do {
        bpoll_mem_block_t * const chunk_end = (bpoll_mem_block_t *)
          ((char *)chunk_head + bpollset->mem_chunk_sz);
        while (n < chunk_end) {
            if (n->b.idx == ~1u) {
                p->b.udata = (void *)n;
                p = n;
            }
            n = (bpoll_mem_block_t *)(void *)((char *)n + block_sz);
        }
        chunk_head = n = *(bpoll_mem_block_t **)chunk_end; /* next chunk */
    } while (chunk_head != NULL);

    p->b.udata = NULL;
}


__attribute_nonnull__()
static void  __attribute_regparm__((1))
bpoll_maint_mem_block (bpollset_t * const restrict bpollset);
static void  __attribute_regparm__((1))
bpoll_maint_mem_block (bpollset_t * const restrict bpollset)
{
    /* reorder free blocks once in a while
     * XXX: test how frequently this triggers and if it has locality benefit */
    if (__builtin_expect(
           (bpollset->mem_block_freed >= BPOLL_MEM_BLOCK_REORDER), 0))
        bpoll_mem_block_reorder(bpollset);
}


__attribute_nonnull__()
static bpollelt_t *  __attribute_regparm__((1))
bpoll_elt_alloc (bpollset_t * const restrict bpollset);
static bpollelt_t *  __attribute_regparm__((1))
bpoll_elt_alloc (bpollset_t * const restrict bpollset)
{
    bpoll_mem_block_t ** const mem_block_head = &bpollset->mem_block_head;
    bpoll_mem_block_t *b, *next;
    do {
        if (   __builtin_expect((NULL==(b=*mem_block_head)), 0)
            && __builtin_expect((NULL==(b=bpoll_mem_chunk_alloc(bpollset))),0))
            return NULL;
        if (bpollset->clr || bpollset->mech == BPOLL_M_POLL) {
            *mem_block_head = (bpoll_mem_block_t *)b->b.udata;
            if (bpollset->mem_block_freed != 0)
                --bpollset->mem_block_freed;
            break;
        }
        else {
            b = (bpoll_mem_block_t *)
              *(volatile bpoll_mem_block_t **)mem_block_head;
            if (b != NULL) {
                next = (bpoll_mem_block_t *)b->b.udata;
                if (plasma_atomic_CAS_ptr_vcast(mem_block_head, b, next))
                    break;
                else
                    b = NULL; /*(for unlikely while() loop condition)*/
            }
        }
    } while (__builtin_expect( (b == NULL), 0));
    b->b.idx = ~0u;  /*(i.e. not ~1u)*/
    b->b.udata = b->data;
    b->b.flpriv = BPOLL_FL_MEM_BLOCK;
    return &b->b;
}


__attribute_nonnull__()
static void  __attribute_regparm__((2))
bpoll_elt_free (bpollset_t * const restrict bpollset,
                bpollelt_t * const restrict bpollelt);
static void  __attribute_regparm__((2))
bpoll_elt_free (bpollset_t * const restrict bpollset,
                bpollelt_t * const restrict bpollelt)
{
    /* check bpollelt allocated from bpollset and not already on free list
     * (idx == ~1u indicates double free; caller should try not to trigger this)
     * (safety here since some bpoll error paths might conceivably hit twice)*/
    if (__builtin_expect( (bpollelt->flpriv & BPOLL_FL_MEM_BLOCK), 1)
        && __builtin_expect( (bpollelt->idx != ~1u), 1)) {
        bpollelt->idx = ~1u;
        if (bpollset->clr || bpollset->mech == BPOLL_M_POLL) {
            bpollelt->udata = (void *)bpollset->mem_block_head;
            bpollset->mem_block_head = (bpoll_mem_block_t *)bpollelt;
            ++bpollset->mem_block_freed;
        }
        else {
            do {
                bpollelt->udata = (void *)
                 *(volatile bpoll_mem_block_t **)&bpollset->mem_block_head;
                if (plasma_atomic_CAS_ptr_vcast(&bpollset->mem_block_head,
                                                (bpoll_mem_block_t *)
                                                 bpollelt->udata,
                                                (bpoll_mem_block_t *)
                                                 bpollelt))
                    break;
                else
                    bpollelt->udata = NULL; /*(for unlikely while() loop cond)*/
            } while (__builtin_expect( (bpollelt->udata == NULL), 0));
        }
    }
    else
        bpollelt->flags = bpollelt->flpriv = BPOLL_FL_ZERO;
}


__attribute_nonnull__()
static void  __attribute_regparm__((2))
bpoll_elt_close (bpollset_t * const bpollset, bpollelt_t * const bpollelt);
static void  __attribute_regparm__((2))
bpoll_elt_close (bpollset_t * const bpollset, bpollelt_t * const bpollelt)
{
    if ((bpollelt->flags & BPOLL_FL_CLOSE) && bpollelt->fd != -1) {
        if (bpollset->fn_cb_close != NULL)
            bpollset->fn_cb_close(bpollset, bpollelt);
        else {
          #ifdef _WIN32
            if (bpollelt->fdtype == BPOLL_FD_SOCKET) {
                while (__builtin_expect( (closesocket(bpollelt->fd) == -1), 0)
                       && errno == EINTR) ;
            }
            else
          #endif/*_WIN32*/
            {
                while (__builtin_expect( (close(bpollelt->fd) == -1), 0)
                       && errno == EINTR) ;
            }
        }
        bpollelt->fd = -1; /*(in case bpoll_elt_close() called again)*/
    }
}


/* The threshold size after which bpollset->bpollelts array is indexed
 * by fd number instead of linear scan through an unorganized array.
 * (This saves memory when the number of fds to poll is small,
 *  since the actual fd identifier (number) might be fairly large)
 * (alternatively, implement hash lookup for larger fdsets)
 * (This must be a power of 2 for bpoll_eltlist_resize())
 *    assert((BPOLL_FD_THRESH & (BPOLL_FD_THRESH-1)) == 0);
 * (Arbitrarily set to 8)
 */
#define BPOLL_FD_THRESH 8u


/* separate from bpoll_elt_fetch() for better inlining of bpoll_elt_fetch() */
__attribute_noinline__
__attribute_nonnull__()
__attribute_pure__
__attribute_warn_unused_result__
static bpollelt_t *  __attribute_regparm__((2))
bpoll_elt_fetch_small (const bpollset_t * const restrict bpollset,const int fd);
static bpollelt_t *  __attribute_regparm__((2))
bpoll_elt_fetch_small (const bpollset_t * const restrict bpollset,const int fd)
{
    bpollelt_t ** const restrict bpollelts = bpollset->bpollelts;
    int i = 0;
    const int nelts = bpollset->nelts;
    while (i < nelts && fd != bpollelts[i]->fd)
        ++i;
    return (i < nelts) ? bpollelts[i] : NULL;
}


__attribute_nonnull__()
__attribute_pure__
__attribute_warn_unused_result__
static bpollelt_t *  __attribute_regparm__((2))
bpoll_elt_fetch (const bpollset_t * const restrict bpollset, const int fd);
static bpollelt_t *  __attribute_regparm__((2))
bpoll_elt_fetch (const bpollset_t * const restrict bpollset, const int fd)
{
    return (bpollset->bpollelts_sz > BPOLL_FD_THRESH)
      ? (fd>=0 && (unsigned int)fd < bpollset->bpollelts_sz)
          ? bpollset->bpollelts[fd]
          : NULL
      : bpoll_elt_fetch_small(bpollset, fd);
}


__attribute_cold__
__attribute_noinline__
__attribute_nonnull__()
__attribute_warn_unused_result__
static int  __attribute_regparm__((2))
bpoll_results_resize (bpollset_t * const restrict bpollset,const size_t nfound);
static int  __attribute_regparm__((2))
bpoll_results_resize (bpollset_t * const restrict bpollset,const size_t nfound)
{
    size_t sz = (size_t)bpollset->results_sz;
    bpollelt_t **results;
    /*assert(sz < nfound);*/
    do { sz <<= 1; } while (sz < nfound);
    results = (bpollelt_t **)
      bpollset->fn_mem_alloc(bpollset->vdata, sz * sizeof(bpollelt_t *));
    if (__builtin_expect( (bpollset->results == NULL), 0))
        return -1;  /* errno == ENOMEM */
    if (bpollset->fn_mem_free != NULL)
        bpollset->fn_mem_free(bpollset->vdata, bpollset->results);
    bpollset->results = results;
    bpollset->results_sz = (unsigned int)sz;
    return 0;
}


__attribute_noinline__
__attribute_nonnull__()
__attribute_warn_unused_result__
static int  __attribute_regparm__((1))
bpoll_rmlist_resize (bpollset_t * const restrict bpollset);
static int  __attribute_regparm__((1))
bpoll_rmlist_resize (bpollset_t * const restrict bpollset)
{
    size_t rmsz = (size_t)(bpollset->rmsz) << 1u;
    bpollelt_t **rmlist;

    if (__builtin_expect( (rmsz == 0), 0)) {
        rmsz = (bpollset->limit <= BPOLL_FD_THRESH)
          ? BPOLL_FD_THRESH
          : BPOLL_FD_THRESH << 1;
    }
    else if (__builtin_expect( (rmsz > UINT_MAX/sizeof(bpollelt_t *)), 0))
        return ENOMEM;
    rmlist = (bpollelt_t **)
      bpollset->fn_mem_alloc(bpollset->vdata, rmsz * sizeof(bpollelt_t *));
    if (__builtin_expect( (rmlist == NULL), 0))
        return ENOMEM;

    if (bpollset->rmlist != NULL) {
        memcpy(rmlist, bpollset->rmlist,
               (size_t)(bpollset->rmsz) * sizeof(bpollelt_t *));
        if (bpollset->fn_mem_free != NULL)
            bpollset->fn_mem_free(bpollset->vdata, bpollset->rmlist);
    }
    bpollset->rmlist = rmlist;
    bpollset->rmsz   = (int)rmsz;
    return 0;
}


__attribute_noinline__
__attribute_nonnull__()
__attribute_warn_unused_result__
static int  __attribute_regparm__((2))
bpoll_eltlist_resize (bpollset_t * const restrict bpollset, const int fd);
static int  __attribute_regparm__((2))
bpoll_eltlist_resize (bpollset_t * const restrict bpollset, const int fd)
{
    unsigned int nalloc = bpollset->bpollelts_sz;
    bpollelt_t **bpollelts, **bpollelts_prev;

    if (fd < (int)nalloc)
        return 0;  /*(resized by different process while waiting for mutex)*/
    if (__builtin_expect(((unsigned int) fd > UINT_MAX/sizeof(bpollelt_t *)),0))
        return ENOMEM;
    do {
        nalloc <<= 1;
    } while (nalloc <= (unsigned int) fd);
    if (__builtin_expect( (nalloc > UINT_MAX/sizeof(bpollelt_t *)), 0))
        return ENOMEM;
    bpollelts = (bpollelt_t **)
      bpollset->fn_mem_alloc(bpollset->vdata,
                             (size_t)(nalloc * sizeof(bpollelt_t *)));
    if (__builtin_expect( (bpollelts == NULL), 0))
        return ENOMEM;

    bpollelts_prev = bpollset->bpollelts;
    memcpy(bpollelts, bpollelts_prev,
           bpollset->bpollelts_sz * sizeof(bpollelt_t *));
    memset(bpollelts+bpollset->bpollelts_sz, 0,
           (nalloc - bpollset->bpollelts_sz)*sizeof(bpollelt_t *));
    bpollset->bpollelts    = bpollelts;
    bpollset->bpollelts_sz = nalloc;
    if (bpollset->fn_mem_free != NULL) {
        /* free() prev bpollelts list immediately if threaded add not enabled */
        if (bpollset->clr != 0u || bpollset->mech == BPOLL_M_POLL)
            bpollset->fn_mem_free(bpollset->vdata, bpollelts_prev);
      #ifdef _THREAD_SAFE
        else {
             /* Note: not free()ing immediately since bpoll_elt_fetch()
              * bpoll_fd_fetch() might (unlikely) have been suspended
              * while holding pointer to this list */
            /* find free slot in used list
             * (used list pads structure for cache line separation)
             * If no free slot, bpollset->limit >= 524288 (512K) descriptors?
             * (should not happen) so just free first element in list.
             * (bpoll_elt_fetch() in another thread should not still
             *  be suspended holding pointer to 15 eltlist allocations
             *  prior (power 2 allocated), but stranger things have happened) */
            unsigned int i = 0;
            while (i < sizeof(bpollset->bpollelts_used)/sizeof(bpollelt_t*)
                   && bpollset->bpollelts_used[i] != NULL)
                ++i;
            if (i == sizeof(bpollset->bpollelts_used)/sizeof(bpollelt_t*)) {
                bpollset->fn_mem_free(bpollset->vdata,
                                      bpollset->bpollelts_used[0]);
                memmove(bpollset->bpollelts_used, bpollset->bpollelts_used+1,
                        sizeof(bpollset->bpollelts_used)-sizeof(bpollelt_t *));
                --i;
            }
            bpollset->bpollelts_used[i] = bpollelts_prev;
        }
      #endif
    }
    return 0;
}


__attribute_nonnull__()
__attribute_warn_unused_result__
static int  __attribute_regparm__((2))
bpoll_fd_add (bpollset_t * const restrict bpollset,
              bpollelt_t * const restrict bpollelt);
static int  __attribute_regparm__((2))
bpoll_fd_add (bpollset_t * const restrict bpollset,
              bpollelt_t * const restrict bpollelt)
{
    const int fd = bpollelt->fd;

    if (__builtin_expect( (fd < 0), 0))
        return (errno = EINVAL);
    if (__builtin_expect( (bpoll_elt_fetch(bpollset, fd) != NULL), 0))
        return (errno = EEXIST);
    if (__builtin_expect( ((unsigned int)bpollset->nelts >= bpollset->limit),0))
        return (errno = ENOSPC);

    if (bpollset->bpollelts_sz > BPOLL_FD_THRESH) {
        if (__builtin_expect( ((unsigned int)fd < bpollset->bpollelts_sz), 1)
            || bpoll_eltlist_resize(bpollset, fd) == 0) {
            bpollset->bpollelts[fd] = bpollelt;
            ++bpollset->nelts;
            return 0;
        }
        else
            return (errno = ENOMEM);
    }
    else {
        int i = 0;
        const int nelts = bpollset->nelts;
        bpollelt_t ** const restrict bpollelts = bpollset->bpollelts;
        while (i < nelts && fd != bpollelts[i]->fd)
            ++i;
        if (i < (int)BPOLL_FD_THRESH) {
            bpollelts[i] = bpollelt; /* replaces existing bpollelt, if any */
            if (i == nelts)
                ++bpollset->nelts;
            return 0;
        }
        else
            return (errno = ENOSPC);
    }
}


__attribute_nonnull__()
__attribute_warn_unused_result__
static int  __attribute_regparm__((2))
bpoll_fd_add_thrsafe (bpollset_t * const restrict bpollset,
                      bpollelt_t * const restrict bpollelt);
static int  __attribute_regparm__((2))
bpoll_fd_add_thrsafe (bpollset_t * const restrict bpollset,
                      bpollelt_t * const restrict bpollelt)
{
    const int thrsafe = !bpollset->clr; /*overloaded flag; 0 for thread-safety*/
    int rc = !thrsafe ? 0 : pthread_mutex_lock(&bpollset->mutex);
    if (__builtin_expect( (rc == 0), 1)) {
        rc = bpoll_fd_add(bpollset, bpollelt);
        if (thrsafe)
            pthread_mutex_unlock(&bpollset->mutex);
    }
    return rc;
}


__attribute_nonnull__()
__attribute_warn_unused_result__
static int  __attribute_regparm__((3))
bpoll_fd_add_eltlist (bpollset_t * const restrict bpollset,
                      bpollelt_t ** const restrict bpollelt,
                      int * const restrict nelts);
static int  __attribute_regparm__((3))
bpoll_fd_add_eltlist (bpollset_t * const restrict bpollset,
                      bpollelt_t ** const restrict bpollelt,
                      int * const restrict nelts)
{
    /* sanity checks (done in bulk here instead of bpoll_fd_add()) */
    int n = *nelts, maxfd = 0, rc;
    *nelts = 0;
    if (__builtin_expect( (n <= 0), 0))
        return (errno = EINVAL);
    if (__builtin_expect( (bpollset->bpollelts_sz <= BPOLL_FD_THRESH), 0))
        return (errno = EINVAL);
    for (int i = 0, fd; i < n; ++i) {
        fd = bpollelt[i]->fd;
        if (maxfd < fd)
            maxfd = fd;  /* maxfd */
        if (__builtin_expect( (fd < 0), 0))
            return (errno = EINVAL);
        /* error for caller to resubmits fd;
         * sanity check only; still chance of TOC-TOU race; should not happen */
        if (__builtin_expect( (bpoll_elt_fetch(bpollset, fd) != NULL), 0))
            return (errno = EEXIST);
    }
    rc = pthread_mutex_lock(&bpollset->mutex);
    if (__builtin_expect( (rc != 0), 0))
        return rc;
    do {
        if (__builtin_expect(
             ((unsigned)(bpollset->nelts+n) > bpollset->limit), 0)) {
            n = (int)(bpollset->limit - (unsigned int)bpollset->nelts);
            if (__builtin_expect( (n == 0), 0)) {
                rc = (errno = ENOSPC);
                break;
            }
        }
        if (__builtin_expect( ((unsigned int)maxfd >= bpollset->bpollelts_sz),0)
            && bpoll_eltlist_resize(bpollset, maxfd) != 0) {
            rc = (errno = ENOMEM);
            break;
        }
        *nelts = n;
        bpollset->nelts += n;
        bpollelt_t ** const restrict bpollelts = bpollset->bpollelts;
        for (int i = 0; i < n; ++i)
            bpollelts[bpollelt[i]->fd] = bpollelt[i];
    } while (0);
    pthread_mutex_unlock(&bpollset->mutex);
    return rc;
}


__attribute_nonnull__()
static void  __attribute_regparm__((2))
bpoll_fd_remove (bpollset_t * const restrict bpollset, const int fd);
static void  __attribute_regparm__((2))
bpoll_fd_remove (bpollset_t * const restrict bpollset, const int fd)
{
    bpollelt_t ** const restrict bpollelts = bpollset->bpollelts;
    /*assert(fd >= 0);*//* should not happen; corrupted bpollelt if it does */
    /* Note: caller must take mutex around this routine if thread-safety needed
     * (currently bpoll_fd_remove() called only by bpoll_fd_remove_eltlist())
     * (and why fd is passed for convenience instead of bpollelt, which would
     *  match the calling params of bpoll_fd_add())*/

    if (bpollset->bpollelts_sz > BPOLL_FD_THRESH) {
        if ((unsigned int)fd < bpollset->bpollelts_sz && bpollelts[fd] != NULL){
            bpollelts[fd] = NULL;
            --bpollset->nelts;
        }
    }
    else {
        int i = 0;
        const int nelts = bpollset->nelts;
        while (i < nelts && fd != bpollelts[i]->fd)
            ++i;
        if (i != nelts) {
            bpollelts[i] = bpollelts[nelts-1]; /*(no problem if i == nelts-1)*/
            --bpollset->nelts;
        }
    }
}


__attribute_noinline__
__attribute_nonnull__()
static void  __attribute_regparm__((3))
bpoll_fd_remove_eltlist (bpollset_t * const restrict bpollset,
                         bpollelt_t * const restrict * const restrict bpollelt,
                         const int nelts);
static void  __attribute_regparm__((3))
bpoll_fd_remove_eltlist (bpollset_t * const restrict bpollset,
                         bpollelt_t * const restrict * const restrict bpollelt,
                         const int nelts)
{
    /* bpollset->clr should be ~0
     * if bpollset->nelts <= BPOLL_FD_THRESH && bpollset->mech != BPOLL_M_POLL
     * or if BPOLL_M_POLL and running maintenance routine
     * (in other words, always for BPOLL_M_POLL, except bpoll_elt_abort())*/
    /* bpollset->clr overloaded flag; 0 for thread-safety
     * (thread-safe code here reduces access to volatile bpollset->nelts) */

    if (!bpollset->clr) {
      #ifdef _THREAD_SAFE
        pthread_mutex_lock(&bpollset->mutex);
      #endif
        {   /*(proceed even if mutex lock fails; fail should not happen)*/
            bpollelt_t ** const restrict bpollelts = bpollset->bpollelts;
            const int bpollelts_sz = (int)bpollset->bpollelts_sz;
            int fd, removed = 0;
            for (int i = 0; i < nelts; ++i) {
                fd = bpollelt[i]->fd;
                if (fd < bpollelts_sz && bpollelts[fd] != NULL) {
                    bpollelts[fd] = NULL;
                    ++removed;
                }
            }
            bpollset->nelts -= removed;
        }
      #ifdef _THREAD_SAFE
        pthread_mutex_unlock(&bpollset->mutex);
      #endif
    }
    else {
        for (int idx = 0; idx < nelts; ++idx)
            bpoll_fd_remove(bpollset, bpollelt[idx]->fd);
    }
}


__attribute_cold__
__attribute_noinline__
__attribute_nonnull__((1))
static void  __attribute_regparm__((2))
bpoll_elt_abort (bpollset_t * const restrict bpollset,
                 bpollelt_t * const restrict bpollelt);
static void  __attribute_regparm__((2))
bpoll_elt_abort (bpollset_t * const restrict bpollset,
                 bpollelt_t * const restrict bpollelt)
{
    /* Note: depending on from where this is called, caller may leak bpollelt,
     * but that would be same as fd close() which automatically removed fd from
     * some of the poll mechanisms, never again returning ready. */
    /* Might be NULL if bpollelt previously removed from bpollset. */
    if (bpollelt != NULL) {
        /* remove from bpollset before any other (potential) action
         * to prevent loops if caller tries to re-remove invalid fd. */
        bpollelt->revents = BPOLLNVAL;
        bpoll_fd_remove_eltlist(bpollset, &bpollelt, 1);
        bpoll_elt_close(bpollset, bpollelt);
        bpoll_elt_free(bpollset, bpollelt);
    }
}


__attribute_malloc__
static void *
bpoll_mem_alloc_default (void * const restrict vdata  __attribute_unused__,
                         const size_t len)
{
    return malloc(len);
}


static void
bpoll_mem_free_default (void * const restrict vdata  __attribute_unused__,
                        void * const restrict mem)
{
    free(mem);
}


__attribute_noinline__
__attribute_nonnull__()
static void  __attribute_regparm__((1))
bpoll_cleanup (bpollset_t * const restrict bpollset);
static void  __attribute_regparm__((1))
bpoll_cleanup (bpollset_t * const restrict bpollset)
{
    int rc = 0;

    /* walk *all* bpollset->bpollelts looking for BPOLL_FL_CLOSE and close() */
    if (bpollset->bpollelts != NULL) {
        bpollelt_t ** const restrict bpollelts = bpollset->bpollelts;
        const int nelts = bpollset->bpollelts_sz > BPOLL_FD_THRESH
          ? (int)bpollset->bpollelts_sz
          : bpollset->nelts;
        for (int idx = 0; idx < nelts; ++idx) {
            if (bpollelts[idx] != NULL)
                bpoll_elt_close(bpollset, bpollelts[idx]);
        }
    }

    /* free() allocated memory and close mechanism-specific fd, if applicable */
    if (bpollset->fn_mem_free != NULL) {
        bpoll_mem_block_t *chunk_head;
        bpoll_mem_block_t *chunk_next;
        /* (not worth separating out to separate routine for each mechanism) */
        switch (bpollset->mech) {
         #if HAS_KQUEUE
          case BPOLL_M_KQUEUE:
            if (bpollset->kevents != NULL) {
                bpollset->fn_mem_free(bpollset->vdata, bpollset->kevents);
                bpollset->kevents = NULL;
            }
            break;
         #endif
         #if HAS_EVPORT
          case BPOLL_M_EVPORT:
            if (bpollset->evport_events != NULL) {
                bpollset->fn_mem_free(bpollset->vdata, bpollset->evport_events);
                bpollset->evport_events = NULL;
            }
            break;
         #endif
         #if HAS_EPOLL
          case BPOLL_M_EPOLL:
            if (bpollset->epoll_events != NULL) {
                bpollset->fn_mem_free(bpollset->vdata, bpollset->epoll_events);
                bpollset->epoll_events = NULL;
            }
            break;
         #endif
         #if HAS_POLLSET
          case BPOLL_M_POLLSET:
            if (bpollset->pollset_events != NULL) {
                bpollset->fn_mem_free(bpollset->vdata,bpollset->pollset_events);
                bpollset->pollset_events = NULL;
                bpollset->pollfds = NULL;
            }
            if (bpollset->fd != -1) {
                do {
                    rc = pollset_destroy(bpollset->fd);
                } while (rc == 0 ? (bpollset->fd = -1, 0) : errno == EINTR);
            }
            break;
         #endif
         #if HAS_DEVPOLL
          case BPOLL_M_DEVPOLL:
         #endif
          case BPOLL_M_POLL:
            if (bpollset->pollfds != NULL) {
                bpollset->fn_mem_free(bpollset->vdata, bpollset->pollfds);
                bpollset->pollfds = NULL;
            }
            break;
          case BPOLL_M_NOT_SET:
          default:
            break;
        }
        chunk_next = bpollset->mem_chunk_head;
        while (NULL != (chunk_head = chunk_next)) {
            chunk_next = *(bpoll_mem_block_t **)
              ((char *)chunk_head + bpollset->mem_chunk_sz);
            bpollset->fn_mem_free(bpollset->vdata, chunk_head);
        }
        if (bpollset->rmlist != NULL) {
            bpollset->fn_mem_free(bpollset->vdata, bpollset->rmlist);
            bpollset->rmlist = NULL;
        }
        if (bpollset->results != NULL) {
            bpollset->fn_mem_free(bpollset->vdata, bpollset->results);
            bpollset->results = NULL;
            bpollset->results_sz = 0;
        }
        if (bpollset->bpollelts != NULL) {
            bpollset->fn_mem_free(bpollset->vdata, bpollset->bpollelts);
            bpollset->bpollelts = NULL;
        }
      #if HAS_PSELECT || HAS_PPOLL || HAS_EPOLL_PWAIT
        if (bpollset->sigmaskp != NULL)
            bpoll_sigmask_set(bpollset, NULL);
      #endif
      #ifdef _THREAD_SAFE
        for (unsigned int i = 0;
             i < sizeof(bpollset->bpollelts_used)/sizeof(bpollelt_t*); ++i)
            bpollset->fn_mem_free(bpollset->vdata, bpollset->bpollelts_used[i]);
      #endif
    }

    if (bpollset->fd != -1) {
        do {
            rc = close(bpollset->fd);
        } while (rc == 0 ? (bpollset->fd = -1, 0) : errno == EINTR);
    }

  #ifdef _THREAD_SAFE
    /* destroy mutex; ignore error; mutex might not have been initialized yet */
    pthread_mutex_destroy(&bpollset->mutex);
  #endif

    bpollset->mech = BPOLL_M_NOT_SET;
}


/*
 * poller mechanism-specific routines implementing the following interfaces
 *
 * bpoll_init_*()         - initialize bpollset for given poller mechanism
 * bpoll_destroy_*()      - (does not exist; inlined in bpoll_cleanup() above)
 * bpoll_commit_*events() - submit pending changes to kernel
 * bpoll_kernel_*()       - query kernel for pending events
 * bpoll_process_*()      - process results from bpoll_kernel_*() (callbacks)
 * bpoll_prepidx_*()      - ready next slot to append to list of pending changes
 * bpoll_elt_add_immed_*()- add element to bpollset (immed submit to kernel)
 * bpoll_elt_add_*()      - add element to bpollset (queue for submit to kernel)
 * bpoll_elt_modify_*()   - modify element in bpollset
 * bpoll_elt_remove_*()   - remove element from bpollset
 * bpoll_maint_*()        - perform deferred bpollset maintenance
 *
 * (The poll(), select() poller mechanism is mechanism with most lines of code
 *  due to simpleton data structures that need processing for cross-referencing.
 *  It is about ~ 400 lines, whereas mechanisms each average ~ 250 +/- 25 lines)
 */


/* batch processing size for bpoll_elt_add_immed_*() */
#define BPOLL_IMMED_SZ 32

#define BPOLL_EVENTS_FILT(events)    (events & ~(BPOLLET|BPOLLDISPATCH))


__attribute_nonnull__()
static int
bpoll_init_pollfds (bpollset_t * const restrict bpollset);
static int
bpoll_init_pollfds (bpollset_t * const restrict bpollset)
{
    /* For BPOLL_M_POLL, double the size of pollfds array to allow for
     * modifications to be cached at the same time that results are processed.*/
    const unsigned int limit = bpollset->limit;
    const unsigned int n = limit << 1; /*half for changes, half for result set*/
    bpollset->pollfds = NULL;
    bpollset->mech = BPOLL_M_POLL;
    #if HAS_PPOLL
      bpollset->sigmaskp = NULL;
    #elif HAS_POLL
      /* FD_SETSIZE defaults to 32767 on AIX; not likely to be a problem */
      #if _AIX
      #ifdef FD_SETSIZE
        if (limit > FD_SETSIZE)
            return (errno = EINVAL);
      #endif
      #endif
    #else /* !HAS_POLL */
      #ifdef FD_SETSIZE
        if (limit > FD_SETSIZE)
            return (errno = EINVAL);
      #endif
      #ifdef NETWARE
        bpollset->fdtype = BPOLL_FD_NOT_SET;
      #endif
        bpollset->maxfd = -1;
        FD_ZERO(&bpollset->readset);
        FD_ZERO(&bpollset->writeset);
        FD_ZERO(&bpollset->exceptset);
    #endif /* !HAS_POLL */
    if (limit > INT_MAX || n > UINT_MAX/sizeof(struct pollfd))
        return (errno = EINVAL);
    bpollset->pollfds = (struct pollfd *)
      bpollset->fn_mem_alloc(bpollset->vdata, n*sizeof(struct pollfd));
    if (bpollset->pollfds == NULL)
        return errno;
    bpollset->clr = ~0u;
    bpollset->pfd_ready = bpollset->pollfds;
    bpollset->queue_sz  = n;  /* repurpose queue_sz for pollfds_sz */
    return 0;
}


/* bpoll maintenance - close() fds pending on rmlist
 *                     remove bpollelt from bpollset
 *
 * (Note: this should follow commit of any other pending changes to kernel;
 *  pending lists might conceivably reference bpollelt elements of rmlist)
 * (evport and epoll commit to kernel in separate step prior to polling kernel)
 */
__attribute_nonnull__()
static void
bpoll_maint_default (bpollset_t * const restrict bpollset);
static void
bpoll_maint_default (bpollset_t * const restrict bpollset)
{
    bpollelt_t ** const restrict rmlist = bpollset->rmlist;
    const int rmidx = bpollset->rmidx;
    bpoll_fd_remove_eltlist(bpollset, rmlist, rmidx); /* min critical section */
    for (int idx = 0; idx < rmidx; ++idx) {
        bpoll_elt_close(bpollset, rmlist[idx]);
        bpoll_elt_free(bpollset, rmlist[idx]);
    }
    bpollset->rmidx = 0;
}


__attribute_noinline__
__attribute_nonnull__()
static int
bpoll_commit_poll_events (bpollset_t * const restrict bpollset);
static int
bpoll_commit_poll_events (bpollset_t * const restrict bpollset)
{
    int i;
    int fd;
    int idx                                 = (int)bpollset->clr;
    const int nelts                         = bpollset->nelts - bpollset->rmidx;
    struct pollfd  * const restrict pollfds = bpollset->pollfds;
    bpollelt_t ** const restrict bpollelts  = bpollset->bpollelts;
    /*assert(bpollset->clr != ~0u);*/

    if (bpollset->bpollelts_sz > BPOLL_FD_THRESH) {
        /* swap in valid fd elements from end of list to compress list */
        for (i = nelts + bpollset->rmidx; idx < i; ++idx) {
            if ((fd = pollfds[idx].fd) == -1) {
                do { --i; } while ((fd = pollfds[i].fd) == -1 && idx < i);
                if (idx == i) break;  /* fd == -1; invalid */
                pollfds[idx].fd     = fd;
                pollfds[idx].events = pollfds[i].events;
                bpollelts[fd]->idx  = (unsigned int)idx;
            }
        }
    }
    else {
        /* simple walk and shift in small list (nelts < BPOLL_FD_THRESH) */
        for (i = idx+1; idx < nelts; ++i) {
            if ((fd = pollfds[i].fd) != -1) {
                pollfds[idx].fd     = fd;
                pollfds[idx].events = pollfds[i].events;
                (bpoll_elt_fetch(bpollset, fd))->idx = (unsigned int)idx++;
            }
        }
    }
    bpollset->clr = ~0u;
    bpollset->idx = (unsigned int)nelts;
    return 0;
}


#if !HAS_POLL || (HAS_PSELECT && !HAS_PPOLL)
__attribute_nonnull__()
static void
bpoll_kernel_pollfds_select (bpollset_t * const restrict bpollset);
static void
bpoll_kernel_pollfds_select (bpollset_t * const restrict bpollset)
{
    int fd;
    int idx;         /* see bpoll_commit_poll_events() */
    const int nelts = bpollset->nelts - bpollset->rmidx;
    struct pollfd * const restrict pollfds = bpollset->pollfds;
    fd_set readset, writeset, exceptset;

    /*bpollset->nfound = -1;*//* reset if chance of return before probe kernel*/

    /* cull removed fds from struct pollfd *pollfds[] array */
    if (bpollset->clr != ~0u)
        bpoll_commit_poll_events(bpollset);

    /* recalculate max fd if necessary */
    if ((fd = bpollset->maxfd) == -1) {
        for (fd = 0, idx = 0; idx < nelts; ++idx) {
            if (fd < pollfds[idx].fd)
                fd = pollfds[idx].fd;
        }
        bpollset->maxfd = fd;
    }

    memcpy(&readset,   &bpollset->readset,   sizeof(fd_set));
    memcpy(&writeset,  &bpollset->writeset,  sizeof(fd_set));
    memcpy(&exceptset, &bpollset->exceptset, sizeof(fd_set));

  #if HAS_PSELECT  /* pselect() is POSIX.1-2001 */
    bpollset->nfound = pselect(fd+1, &readset, &writeset, &exceptset,
                               bpollset->timeout >=0 ? &bpollset->ts : NULL,
                               bpollset->sigmaskp);
  #else /* !HAS_PSELECT */
    /* note: struct timeval might be modified by select() */
    struct timeval tv;
    if (bpollset->timeout > 0) {
        tv.tv_sec  = bpollset->ts.tv_sec;
        tv.tv_usec = (bpollset->ts.tv_nsec+999) / 1000; /* nsecs to usecs */
    }
    else {
        tv.tv_sec  = 0;
        tv.tv_usec = 0;
    }

   #ifdef NETWARE
    /* NetWare only has select() on sockets and pipe_select() on pipes
     * http://developer.novell.com/ndk/doc/libc/index.html \
     *   ?page=/ndk/doc/libc/libc_enu/data/sdk86.html#sdk86
     * http://developer.novell.com/ndk/doc/libc/index.html \
     *   ?page=/ndk/doc/libc/libc_enu/data/aktgeo5.html */
    if (bpollset->fdtype == BPOLL_FD_PIPE)
        bpollset->nfound = pipe_select(fd+1, &readset, &writeset, &exceptset,
                                       bpollset->timeout >= 0 ? &tv : NULL);
    else
   #endif
        bpollset->nfound = select(fd+1, &readset, &writeset, &exceptset,
                                  bpollset->timeout >= 0 ? &tv : NULL);
  #endif /* !HAS_PSELECT */

    if (bpollset->nfound > 0) {
        int revents;
        int active = 0;
        int nfd_active = 0;
        const int nfound = bpollset->nfound;
        for (idx = 0; idx < nelts; ++idx) {
            fd = pollfds[idx].fd;
            revents = 0;
            if (FD_ISSET(fd, &readset))   { ++active; revents |= BPOLLIN;  }
            if (FD_ISSET(fd, &writeset))  { ++active; revents |= BPOLLOUT; }
            if (FD_ISSET(fd, &exceptset)) { ++active;
                bpollelt_t * const restrict bpollelt =
                  bpoll_elt_fetch(bpollset, fd);
                revents |= (bpollelt->fdtype == BPOLL_FD_SOCKET
                            && (bpollelt->events & BPOLLIN))
                  ? BPOLLPRI|BPOLLIN
                  : BPOLLERR;
            }
            if (revents != 0) {
                pollfds[idx].revents = revents;
                ++nfd_active;
                if (active == nfound)
                    break;
            }
            /* (notes on meanings of 'exception set')
             * fd to socket: out-of-band data received
             * fd to pipe: empty and not open for write / not open for read
             * fd to regular file, tty, directory, character-special file or
             *   block-special file: never has exceptional condition pending */
        }
        bpollset->nfound = nfd_active;
    }
}
#endif


#if HAS_POLL
__attribute_nonnull__()
static void
bpoll_kernel_pollfds_poll (bpollset_t * const restrict bpollset);
static void
bpoll_kernel_pollfds_poll (bpollset_t * const restrict bpollset)
{
    /*bpollset->nfound = -1;*//* reset if chance of return before probe kernel*/

    /* On Solaris >= 7, docs recommend keeping array as static
     * as possible, and leaving pollfds with fd set to -1.
     * http://developers.sun.com/solaris/articles/polling_efficient.html
     * (Array will still be adjusted and dead pollfds removed if we run
     *  out of space when trying to add new fds in bpoll_elt_add()) */
  #if !defined(__sun) || !defined(__SunOS_5_7)
    /* cull removed fds from struct pollfd *pollfds[] array */
    const nfds_t nelts = (nfds_t)(bpollset->nelts - bpollset->rmidx);
    if (bpollset->clr != ~0u)
        bpoll_commit_poll_events(bpollset);
  #else
    const nfds_t nelts = (nfds_t)bpollset->nelts;
  #endif

  #if HAS_PPOLL
    /* Linux provides ppoll() that takes sigmask similar to SUSv3 pselect()
     * http://www.opengroup.org/onlinepubs/000095399/functions/select.html*/
    bpollset->nfound = ppoll(bpollset->pollfds, nelts,
                             bpollset->timeout >= 0 ? &bpollset->ts : NULL,
                             bpollset->sigmaskp);
  #else
    bpollset->nfound = poll(bpollset->pollfds, nelts, bpollset->timeout);

    /* AIX poll() return value is combo of num fds and msg queues ready */
    /* http://publib.boulder.ibm.com/infocenter/systems/index.jsp? [...]
         topic=/com.ibm.aix.basetechref/doc/basetrf1/poll.htm
     * msg queues are not supported in bpoll since we do not track them
     * and do not keep them at the end of pollfds.  If we did, we would
     * need to pass to poll() second argument (nelts) as (nmsgs<<16|nfds)
    #ifdef _AIX
    bpollset->nfound = poll(bpollset->pollfds, nelts, bpollset->timeout);
    bpollset->nfound = NFDS(bpollset->nfound) + NMSGS(bpollset->nfound);
    #endif
     */
  #endif
}
#endif


__attribute_nonnull__()
static int
bpoll_kernel_pollfds (bpollset_t * const restrict bpollset);
static int
bpoll_kernel_pollfds (bpollset_t * const restrict bpollset)
{
  #if HAS_POLL
   #if HAS_PSELECT && !HAS_PPOLL
    if (bpollset->sigmaskp)
        bpoll_kernel_pollfds_select(bpollset);
    else
   #endif
        bpoll_kernel_pollfds_poll(bpollset);
  #else
    bpoll_kernel_pollfds_select(bpollset);
  #endif

    /* perform deferred bpollset maint after committing changes to kernel
     * (events committed to kernel above, so can ignore return value here) */
    if (bpollset->rmidx != 0) {
        bpoll_maint_default(bpollset);
        bpoll_maint_mem_block(bpollset);
    }

    return bpollset->nfound;
}


/* declare proto for bpoll_elt_modify_pollfds() for bpoll_process_pollfds() */
__attribute_nonnull__()
static int
bpoll_elt_modify_pollfds (bpollset_t * const restrict bpollset,
                          bpollelt_t * const restrict bpollelt,
                          const int events);


__attribute_nonnull__()
static int
bpoll_process_pollfds (bpollset_t * const restrict bpollset);
static int
bpoll_process_pollfds (bpollset_t * const restrict bpollset)
{
    bpollelt_t * restrict bpollelt;
    const struct pollfd * const restrict pfd_ready = bpollset->pfd_ready;
    bpollelt_t ** const restrict results = bpollset->results;
    bpoll_fn_cb_event_t const fn_cb_event = bpollset->fn_cb_event;
    int nremain = bpollset->nfound;
    int events;
    /*assert(nfound > 0);*/
    /*if (results != NULL) assert(nremain <= bpollset->results_sz);*/

    for (int i = 0, j = 0; nremain != 0; ++i) {
        if (pfd_ready[i].revents == 0)
            continue;
        --nremain;
        if ((bpollelt = bpoll_elt_fetch(bpollset, pfd_ready[i].fd)) != NULL) {
            bpollelt->revents = (int) pfd_ready[i].revents;
            if (__builtin_expect( (bpollelt->events & BPOLLDISPATCH), 0)) {
                events = bpollelt->events;
                bpoll_elt_modify_pollfds(bpollset, bpollelt, 0);
                bpollelt->flpriv |= BPOLL_FL_DISPATCHED;
                bpollelt->events = events;/*restore events value set by caller*/
            }
            if (results != NULL)
                results[j++] = bpollelt;
            else {
                fn_cb_event(bpollset, bpollelt, -1);
                bpollelt->revents = 0;
            }
        }
    }
    return bpollset->nfound;
}


#if 0 /* BPOLL_M_POLL: no support for immediate add while another thread polls*/
__attribute_nonnull__()
static int  __attribute_regparm__((3))
bpoll_elt_add_immed_pollfds (bpollset_t * const restrict bpollset,
                             bpollelt_t ** const restrict bpollelt,
                             int * const restrict nelts,
                             const int events, const int flpriv);
#endif


#define bpoll_prepidx_pollfds(bpollset)                                       \
    __builtin_prefetch(bpollset->pollfds+bpollset->idx, 1, 1);                \
    if (__builtin_expect( (bpollset->idx == bpollset->queue_sz), 0))          \
        bpoll_commit_poll_events(bpollset)


__attribute_nonnull__()
static int  __attribute_regparm__((3))
bpoll_elt_add_pollfds (bpollset_t * const restrict bpollset,
                       bpollelt_t * const restrict bpollelt,
                       const int events);
static int  __attribute_regparm__((3))
bpoll_elt_add_pollfds (bpollset_t * const restrict bpollset,
                       bpollelt_t * const restrict bpollelt,
                       const int events)
{
    int rc;
    const int fd = bpollelt->fd;

 #if !HAS_POLL
  #ifdef _WIN32
    if (__builtin_expect( (bpollelt->fdtype != BPOLL_FD_SOCKET), 0))
        return (errno = EINVAL);
  #elif defined(FD_SETSIZE)
    if (fd >= FD_SETSIZE)
        return (errno = EBADF);
  #endif /* FD_SETSIZE */
  #ifdef NETWARE
    /* NetWare only has select() on sockets and pipe_select() on pipes*/
    rc = bpollelt->fdtype != BPOLL_FD_SOCKET
      && bpollelt->fdtype != BPOLL_FD_PIPE;
    if (__builtin_expect( (rc == 1), 0))
        return (errno = EBADF);
    if (bpollset->fdtype != bpollelt->fdtype) {
        if (bpollset->fdtype == BPOLL_FD_NOT_SET)
            bpollset->fdtype = bpollelt->fdtype;
        else
            return (errno = EBADF);
    }
  /* endif NETWARE */
  #elif defined(APR_FILES_AS_SOCKETS) && !APR_FILES_AS_SOCKETS
    if (bpollelt->fdtype != BPOLL_FD_SOCKET)
        return (errno = ENOTSOCK);
  #endif /* !APR_FILES_AS_SOCKETS */
 #endif /* !HAS_POLL */

    bpoll_prepidx_pollfds(bpollset); /* macro */
    rc = bpoll_fd_add(bpollset, bpollelt);
    if (__builtin_expect((rc != 0), 0))
        return rc;
    bpollset->pollfds[(bpollelt->idx = bpollset->idx++)].fd = fd;
    bpollelt->revents = 0;
    /*(bpoll_elt_modify() always succeeds for BPOLL_M_POLL)*/
    bpollelt->events = !events;  /* must be set by bpoll_elt_modify() */
    (void) bpoll_elt_modify(bpollset, bpollelt, events);
 #if !HAS_POLL
    if (bpollset->maxfd < fd && (bpollset->maxfd != -1 || bpollset->nelts == 0))
        bpollset->maxfd = fd;
 #endif /* !HAS_POLL */
    return 0;
}


__attribute_nonnull__()
static int
bpoll_elt_modify_pollfds (bpollset_t * const restrict bpollset,
                          bpollelt_t * const restrict bpollelt,
                          const int events);
static int
bpoll_elt_modify_pollfds (bpollset_t * const restrict bpollset,
                          bpollelt_t * const restrict bpollelt,
                          const int events)
{
  #if !HAS_POLL
    const int fd = bpollelt->fd;

    if (events & BPOLLIN)
        FD_SET(fd, &bpollset->readset);
    else
        FD_CLR(fd, &bpollset->readset);

    if (events & BPOLLOUT)
        FD_SET(fd, &bpollset->writeset);
    else
        FD_CLR(fd, &bpollset->writeset);

    if (events & (BPOLLPRI|BPOLLERR|BPOLLHUP|BPOLLNVAL))
        FD_SET(fd, &bpollset->exceptset);
    else
        FD_CLR(fd, &bpollset->exceptset);
  #endif /* !HAS_POLL */

    bpollset->pollfds[bpollelt->idx].events = (short)events;
    bpollelt->events = events;
    bpollelt->flpriv &= ~BPOLL_FL_DISPATCHED;
    return 0;
}


__attribute_nonnull__()
static int
bpoll_elt_remove_pollfds (bpollset_t * const restrict bpollset,
                          bpollelt_t * const restrict bpollelt);
static int
bpoll_elt_remove_pollfds (bpollset_t * const restrict bpollset,
                          bpollelt_t * const restrict bpollelt)
{
    /* no failure mode for BPOLL_M_POLL (else must update bpoll_elt_add())*/
    const unsigned int idx = bpollelt->idx;
  #if !HAS_POLL
    const int fd = bpollelt->fd;
    if (bpollset->mech == BPOLL_M_POLL) {
        FD_CLR(fd, &bpollset->readset);
        FD_CLR(fd, &bpollset->writeset);
        FD_CLR(fd, &bpollset->exceptset);
        if (bpollset->maxfd == fd)
            bpollset->maxfd = -1;
    }
  #endif /* !HAS_POLL */

    if (idx != ~0u) {
        bpollset->pollfds[idx].fd = -1;
        bpollset->pollfds[idx].revents = 0;
        if (bpollset->clr > idx)
            bpollset->clr = idx;
    }

  #ifdef NETWARE
    /*(bpollset->nelts decremented to 0 by when pending changes are committed)*/
    if (bpollset->nelts == 1)
        bpollset->fdtype = BPOLL_FD_NOT_SET;
  #endif

    bpollelt->events = 0;  /* nop; for consistency between bpoll mechanisms */
    return 0;
}


#if HAS_KQUEUE


/* EV_ONESHOT deletes filter when returning event, requiring EV_ADD to rearm.
 * EV_DISPATCH disables filter for returned event and has been available in
 * kqueue since about 2009.  If not available, emulate with EV_ONESHOT|EV_ADD.
 * (EV_ADD is harmless, though possibly slightly more costly, if supplied when
 *  it is not needed, but omitting EV_ADD may result in EV_ERROR with ENOENT
 *  when attempting to modify a filter that does not exist in kqueue.) */
#ifndef EV_DISPATCH
#define EV_DISPATCH (EV_ONESHOT | EV_ADD)
#endif


__attribute_nonnull__()
static int
bpoll_init_kqueue (bpollset_t * const restrict bpollset);
static int
bpoll_init_kqueue (bpollset_t * const restrict bpollset)
{
    /* For BPOLL_M_KQUEUE, quadruple the size of kevents array to allow for
     * modifications to be cached at the same time that results are processed.
     * (half for changes, half for result set, then *=2)
     * (might have both read and write kevents for each fd, so *= 2) */
    const unsigned int n = bpollset->queue_sz << 2;
    bpollset->kevents = NULL;
    bpollset->mech = BPOLL_M_KQUEUE;
    if (bpollset->queue_sz > (INT_MAX>>1) || n > UINT_MAX/sizeof(struct kevent))
        return (errno = EINVAL);
    if (bpollset->queue_sz < 2)  /*slots to queue read and write filters*/
        return (errno = EINVAL);
    if (n >= USHRT_MAX) /*kqueue bpollelt->idx used as two unsigned short ints*/
        return (errno = EINVAL);  /*(!USHRT_MAX used as flag for filter added)*/
    while ((bpollset->fd = kqueue()) < 0) {
        if (errno != EINTR)
            return errno;
    }
    fcntl(bpollset->fd, F_SETFD, FD_CLOEXEC);
    bpollset->kevents = (struct kevent *)
      bpollset->fn_mem_alloc(bpollset->vdata, n * sizeof(struct kevent));
    if (bpollset->kevents == NULL)
        return errno;
    bpollset->keready = bpollset->kevents+(n>>1);
    bpollset->kereceipts = 0;
    return 0;
}


/* forward declaration */
__attribute_noinline__
__attribute_nonnull__()
static int
bpoll_recover_kevents_dispatch (bpollset_t * const restrict bpollset);


__attribute_noinline__
__attribute_nonnull__()
__attribute_warn_unused_result__
static int
bpoll_recover_kevent_readd (struct kevent * const restrict kev, const int fd);
static int
bpoll_recover_kevent_readd (struct kevent * const restrict kev, const int fd)
{
    int rv;
    const struct timespec ts = { 0, 0 };
    kev->flags &= ~(EV_EOF|EV_ERROR|EV_RECEIPT);
    kev->flags |= EV_ADD;
    kev->fflags = 0;
    kev->data   = 0;
    do {
        rv = kevent(fd, kev, 1, kev, 0, &ts);
    } while (__builtin_expect( (rv == -1), 0) && errno == EINTR);
    return rv != -1 ? 0 : -1;
}


__attribute_noinline__
__attribute_nonnull__()
static void
bpoll_recover_kevent_abort (bpollset_t * const restrict bpollset,
                            struct kevent * const restrict keready,
                            const int n);
static void
bpoll_recover_kevent_abort (bpollset_t * const restrict bpollset,
                            struct kevent * const restrict keready,
                            const int n)
{
    bpollelt_t * const restrict bpollelt = keready[0].udata;
    int i = (keready[0].filter==EVFILT_READ || keready[0].filter==EVFILT_WRITE)
      ? 1
      : n;
    if (bpollelt == NULL)
        return;
    while (i < n && keready[i].udata != bpollelt)
        ++i;
    if (i == n)
        /* (see comments in bpoll_elt_abort()) */
        bpoll_elt_abort(bpollset, bpollelt);
    else if ((keready[i].flags & EV_ERROR) && (keready[i].flags & EV_RECEIPT)) {
        /* Note: assuming error for which we do not wish to try to recover */
        /* Note: assumes no more than two receipts for same bpollelt possible */
        keready[i].udata = NULL; /* marked handled; see above 'return' if NULL*/
        bpoll_elt_abort(bpollset, bpollelt);
    }
    else
        /* muddle along; there is valid event on other filter for same fd */
        bpollelt->events &=
          ~(keready[0].filter == EVFILT_WRITE ? BPOLLOUT : BPOLLIN);
}


__attribute_nonnull__()
static int
bpoll_recover_kevents_receipts (bpollset_t * const restrict bpollset,
                                struct kevent * const restrict keready,
                                const int n);
static int
bpoll_recover_kevents_receipts (bpollset_t * const restrict bpollset,
                                struct kevent * const restrict keready,
                                const int n)
{
    /* scan kqueue receipts; receipts are returned prior to pending events */
    int i;
    for (i = 0; i < n && (keready[i].flags & EV_RECEIPT); ++i) {
        /*assert((keready[i].flags & EV_ERROR) == EV_ERROR);*//* in receipts */
        if (__builtin_expect( (keready[i].data == 0), 1))
            continue;
        else if (keready[i].data == ENOENT) {/*keready[i].data is system errno*/
            if (keready[i].flags & EV_DELETE)
                continue;  /* ignore ENOENT for EV_DELETE */
            else if (!(keready[i].flags & EV_ADD)) {
                /* should not happen; bookkeeping mismatch; retry with EV_ADD */
                if (bpoll_recover_kevent_readd(keready+i,bpollset->fd) == 0)
                    continue;
            }
        }
        /* abort bpollelt unless other ops on same bpollelt pending in keready[]
         * (keready[i].data == EBADF or unexpected filter error) */
        bpoll_recover_kevent_abort(bpollset, keready+i, n-i);
    }
    return i;
}


__attribute_noinline__
__attribute_nonnull__()
__attribute_warn_unused_result__
static int
bpoll_commit_kevents_impl (bpollset_t * const restrict bpollset,
                           struct kevent * const restrict kevents,
                           struct kevent * const restrict keready,
                           const int n);
static int
bpoll_commit_kevents_impl (bpollset_t * const restrict bpollset,
                           struct kevent * const restrict kevents,
                           struct kevent * const restrict keready,
                           const int n)
{
    int rv;
    const struct timespec ts = { 0, 0 };
    /*assert(n != 0);*/

    /* limit keready to num events submitted; expect exactly that num receipts*/
    /*(caller must ensure keready is at least as large as n)*/
    do {
        rv = kevent(bpollset->fd, kevents, n, keready, n, &ts);
    } while (__builtin_expect( (rv == -1), 0) && errno == EINTR);
    if (__builtin_expect( (rv != n), 0)) {
        if (rv != -1 && errno == 0) /* should not happen */
            errno = EINVAL;
        return -1;
    }
    bpoll_recover_kevents_receipts(bpollset, keready, n);
    return 0;
}


__attribute_nonnull__()
__attribute_warn_unused_result__
static int
bpoll_commit_kevents (bpollset_t * const restrict bpollset);
static int
bpoll_commit_kevents (bpollset_t * const restrict bpollset)
{
    /* (bpollset->kevents should be sized large enough that this code is not
     *  run frequently, unless caller explictly invokes bpoll_flush_pending(),
     *  or if there are more pending events to submit than desired number
     *  of events to be returned.  keready is stored on the stack (about 5K
     *  for 128 entries) so as not to overwrite bpollset->keready in the case
     *  where bpoll_process() is running callbacks on bpollset->keready.) */
    int n, sum;
    struct kevent keready[BPOLL_IMMED_SZ<<2]; /*see bpoll_elt_add_immed_kqueue*/

    /*assert(bpollset->idx != 0);*/

    for (sum = 0; (n = (int)bpollset->idx - sum) != 0; sum += n) {
        if (n > (BPOLL_IMMED_SZ<<2))
            n =  BPOLL_IMMED_SZ<<2;
        if (bpoll_commit_kevents_impl(bpollset, bpollset->kevents+sum,
                                      keready, n) != 0)
            return -1;
    } 
    return (bpollset->idx = 0);
}


__attribute_nonnull__()
static int
bpoll_kernel_kqueue (bpollset_t * const restrict bpollset);
static int
bpoll_kernel_kqueue (bpollset_t * const restrict bpollset)
{
    /* write pending changes to kqueue
     * (consistently handle submit errors similar to other bpoll mechanisms)
     * (defer commit to kevent() below if num changes < queue_sz; commit
     *  if >= queue_sz (in case all result in EV_ERROR) to make progress) */
    bpollset->nfound = -1; /* reset if chance of return before probe kernel */
    if (bpollset->idx >= bpollset->queue_sz
        && bpoll_commit_kevents(bpollset) != 0)
        return -1;

    /* Write pending changes to kqueue at same time as check for new events.
     * (besides EINTR, possible errors include EINVAL, ENOENT, or ESRCH if
     *  submitted change event is invalid or contains errors and there are
     *  too many descriptors ready and not enough space to add another
     *  kevent to result set with EV_ERROR flag set for the submitted
     *  changed event.  However, bpollset->keready is sized such that these
     *  should not be an issue.
     *  ASSUMPTION: once kevent() is called, this code assumes that all
     *  changes are committed (or errors placed in the result set) whether
     *  or not kevent() is interrupted by a signal.  (If this is invalid
     *  assumption, call bpoll_commit_kevents() (above) so that events are
     *  submitted and errors are caught prior to calling kevent() (below).) */
    bpollset->nfound = kevent(bpollset->fd, bpollset->kevents, bpollset->idx,
                              bpollset->keready, (int)bpollset->queue_sz,
                              bpollset->timeout >= 0 ? &bpollset->ts : NULL);
    bpollset->kereceipts = 0;
    if (bpollset->nfound > 0 && bpollset->idx != 0)
        bpollset->nfound -= bpollset->kereceipts =
          bpoll_recover_kevents_receipts(bpollset, bpollset->keready,
                                         bpollset->nfound);
    bpollset->idx = 0;

    /* perform deferred bpollset maint after committing changes to kernel
     * (events committed to kernel above, so can ignore return value here) */
    if (bpollset->rmidx != 0) {
        bpoll_maint_default(bpollset);
        bpoll_maint_mem_block(bpollset);
    }

    return bpollset->nfound;
}


__attribute_nonnull__()
static int
bpoll_process_kqueue (bpollset_t * const restrict bpollset);
static int
bpoll_process_kqueue (bpollset_t * const restrict bpollset)
{
    bpollelt_t * restrict bpollelt;
    struct kevent * const restrict keready = bpollset->keready;
    bpollelt_t ** const restrict results = bpollset->results;
    bpoll_fn_cb_event_t const fn_cb_event = bpollset->fn_cb_event;
    int i, j, revents, dispatched = 0;
    const int nfound = bpollset->kereceipts + bpollset->nfound;
    /*assert(nfound > 0);*/
    /*if (results != NULL) assert(bpollset->nfound <= bpollset->results_sz);*/

    for (i = bpollset->kereceipts, j = 0; i < nfound; ++i) {
        bpollelt = (bpollelt_t *)keready[i].udata;
        revents =
            (keready[i].filter != EVFILT_WRITE
             ? (!(keready[i].flags & EV_EOF) ? BPOLLIN  : BPOLLIN|BPOLLRDHUP)
             : (!(keready[i].flags & EV_EOF) ? BPOLLOUT : BPOLLOUT|BPOLLHUP))
          | ((keready[i].flags & EV_ERROR) ? BPOLLERR : 0);
            /*(system errno is in keready[i].data when EV_ERROR is set)*/
        /*(not differentiating which filter returned, if more than one)*/
        if (bpollelt->events & BPOLLDISPATCH)
            bpollelt->flpriv |= (dispatched = BPOLL_FL_DISPATCHED)
                             |  (keready[i].filter != EVFILT_WRITE
                                 ? BPOLL_FL_DISP_KQRD
                                 : BPOLL_FL_DISP_KQWR);
        if (results != NULL) {
            /* (might have multiple filters; add to results list only once) */
            if (bpollelt->revents == 0)
                results[j++] = bpollelt;
            /* (no callback, so aggregate bpollelt->revents with |= ) */
            bpollelt->revents |= revents;
        }
        else {
            bpollelt->revents = revents;
            fn_cb_event(bpollset, bpollelt, keready[i].data);
            bpollelt->revents = 0;
        }
    }
    if (results != NULL) {
        bpollset->nfound = j;/*(events might have been combined into bpollelt)*/
        /*(extra pass to disable additional filters for dispatched fds
         * due to bpoll data structure limitation where bpollelt focuses on fd
         * (with multiple filters) whereas kqueue treats filters separately)
         *(implemented as a separate pass through the results for simplicity
         * and to keep this code out of the loop for other usage scenarios)*/
        if (dispatched != 0 && bpollset->clr == 0u) /*(thread-safe flag)*/
            return bpoll_recover_kevents_dispatch(bpollset);
    }
    return bpollset->nfound;
}


/* implement EV_SET() macro allowing for arbitrary expression to struct kevent*/
/* XXX: depending on platform, might cast udata = (intptr_t)(f) or (void *)(f)*/
#define KEV_SET(kep_expr,a,b,c,d,e,f) do { \
    register struct kevent * const restrict kep = (kep_expr); \
    kep->ident  = (uintptr_t)(a); \
    kep->filter = (b); \
    kep->flags  = (c); \
    kep->fflags = (d); \
    kep->data   = (e); \
    kep->udata  = (f); \
  } while (0)


__attribute_nonnull__()
static int  __attribute_regparm__((3))
bpoll_elt_add_immed_kqueue (bpollset_t * const restrict bpollset,
                            bpollelt_t ** const restrict bpollelt,
                            int * const restrict nelts,
                            const int events, const int flpriv);
static int  __attribute_regparm__((3))
bpoll_elt_add_immed_kqueue (bpollset_t * const restrict bpollset,
                            bpollelt_t ** const restrict bpollelt,
                            int * const restrict nelts,
                            const int events, const int flpriv)
{
    /* kevents[64] is sized such that up to 32 bpollelt added to kqueue at once
     * (using about 2.5K stack usage for each of kevents[64] and keready[64]) */
    /* (idxflag overloaded to indicate if read or write filters submitted) */
    int i = 0, idx, rc;
    const int n = *nelts;
    const int flags = ((events & BPOLLET)         ? EV_CLEAR    : 0)
                    | ((events & BPOLLDISPATCH)   ? EV_DISPATCH : 0)
                    | EV_RECEIPT;
    const unsigned int idxflag = ((events & BPOLLOUT) ? 0 : (USHRT_MAX<<16))
                               | ((events & BPOLLIN)  ? 0 :  USHRT_MAX);
    struct kevent kevents[BPOLL_IMMED_SZ<<1];
    struct kevent keready[BPOLL_IMMED_SZ<<1];
    /* kqueue does not provide a convenient way to discover urgent data
     * (a.k.a. out-of-band priority data) on socket, a la poll() POLLPRI
     * (If you know of a way to detect OOB with kqueue, please tell me!) */
    if (__builtin_expect((events & (BPOLLPRI|BPOLLRDBAND|BPOLLWRBAND)), 0)) {
        *nelts = 0;
        return (errno = EINVAL);
    }
    while (i != n) {
        if (flpriv == BPOLL_FL_CTL_ADD) {
            for (idx=0; i < n && idx < (BPOLL_IMMED_SZ<<1); ++i) {
                bpollelt[i]->events = events;
                bpollelt[i]->revents = 0;
                bpollelt[i]->idx = idxflag;
                if (events & BPOLLIN) {
                    KEV_SET(&kevents[idx], bpollelt[i]->fd, EVFILT_READ,
                            flags | EV_ADD | EV_ENABLE, 0, 0, bpollelt[i]);
                    ++idx;
                }
                if (events & BPOLLOUT) {
                    KEV_SET(&kevents[idx], bpollelt[i]->fd, EVFILT_WRITE,
                            flags | EV_ADD | EV_ENABLE, 0, 0, bpollelt[i]);
                    ++idx;
                }
            }
        }
        else {
            for (idx=0; i < n && idx < (BPOLL_IMMED_SZ<<1); ++i) {
                if (((events & BPOLLIN) ^ (bpollelt[i]->events & BPOLLIN))
                    || (bpollelt[i]->flpriv & BPOLL_FL_DISP_KQRD)) {
                    bpollelt[i]->idx &= 0xFFFF0000u;  /* not USHRT_MAX */
                    KEV_SET(&kevents[idx], bpollelt[i]->fd, EVFILT_READ,
                            flags
                            | ((events & BPOLLIN) ? EV_ENABLE : EV_DISABLE)
                            | ((bpollelt[i]->idx & 0xFFFF) != USHRT_MAX
                               ? 0 : EV_ADD),
                            0, 0, bpollelt[i]);
                    ++idx;
                }
                if (((events & BPOLLOUT) ^ (bpollelt[i]->events & BPOLLOUT))
                    || (bpollelt[i]->flpriv & BPOLL_FL_DISP_KQWR)) {
                    bpollelt[i]->idx &= 0x0000FFFFu;  /* not USHRT_MAX */
                    KEV_SET(&kevents[idx], bpollelt[i]->fd, EVFILT_WRITE,
                            flags
                            | ((events & BPOLLOUT) ? EV_ENABLE : EV_DISABLE)
                            | ((bpollelt[i]->idx >> 16) != USHRT_MAX
                               ? 0 : EV_ADD),
                            0, 0, bpollelt[i]);
                    ++idx;
                }
                bpollelt[i]->events = events; /*assign after value check above*/
                bpollelt[i]->flpriv &=
                  ~(BPOLL_FL_DISPATCHED|BPOLL_FL_DISP_KQRD|BPOLL_FL_DISP_KQWR);
            }
        }
        rc = bpoll_commit_kevents_impl(bpollset, kevents, keready, idx);
        if (__builtin_expect((rc == 0), 1))
            *nelts = i;
        else {  /* unexpected error */
            if (__builtin_expect( (flpriv != BPOLL_FL_CTL_ADD), 0)) {
                /* events already overwritten; set dispatched flags to
                 * allow for resubmit if caller attempts to recover */
                /* (BPOLL_FL_DISPATCHED restored later) */
                for (idx = *nelts; idx < i; ++idx)
                    ((bpollelt_t *)(kevents[idx].udata))->flpriv |=
                      (kevents[idx].filter != EVFILT_WRITE
                       ? BPOLL_FL_DISP_KQRD
                       : BPOLL_FL_DISP_KQWR);
            }
            return rc;
        }
    }
    return 0;
}


/*(code expects at least two slots available for read and write filters)*/
#define bpoll_prepidx_kqueue(bpollset)                                        \
    __builtin_prefetch(bpollset->kevents+bpollset->idx, 1, 1),                \
      (__builtin_expect( (bpollset->idx > (bpollset->queue_sz<<1)-2), 0)      \
       && __builtin_expect( (bpoll_commit_kevents(bpollset) != 0), 0))


__attribute_nonnull__()
static int  __attribute_regparm__((3))
bpoll_elt_add_kqueue (bpollset_t * const restrict bpollset,
                      bpollelt_t * const restrict bpollelt,
                      const int events);
static int  __attribute_regparm__((3))
bpoll_elt_add_kqueue (bpollset_t * const restrict bpollset,
                      bpollelt_t * const restrict bpollelt,
                      const int events)
{
    unsigned int idx;
    const int flags = ((events & BPOLLET)       ? EV_CLEAR    : 0)
                    | ((events & BPOLLDISPATCH) ? EV_DISPATCH : 0)
                    | EV_ADD | EV_RECEIPT | EV_ENABLE;
    int rc;
    /* kqueue does not provide a convenient way to discover urgent data
     * (a.k.a. out-of-band priority data) on socket, a la poll() POLLPRI
     * (If you know of a way to detect OOB with kqueue, please tell me!) */
    if (__builtin_expect((events & (BPOLLPRI|BPOLLRDBAND|BPOLLWRBAND)), 0))
        return (errno = EINVAL);

    if (bpoll_prepidx_kqueue(bpollset)) /* macro */
        return errno;
    rc = bpoll_fd_add_thrsafe(bpollset, bpollelt);
    if (__builtin_expect((rc != 0), 0))
        return rc;
    idx = bpollset->idx++;
    if ((events & BPOLLIN) && (events & BPOLLOUT))
        ++bpollset->idx; /* (bpoll_prepidx_kqueue() checks +2 avail, incr +1) */
    bpollelt->events = events;
    bpollelt->revents = 0;
    if (events & BPOLLIN) {
        KEV_SET(&bpollset->kevents[idx], bpollelt->fd, EVFILT_READ,
                flags, 0, 0, bpollelt);
        bpollelt->idx = (USHRT_MAX<<16) | idx++;
    }
    if (events & BPOLLOUT) {
        KEV_SET(&bpollset->kevents[idx], bpollelt->fd, EVFILT_WRITE,
                flags, 0, 0, bpollelt);
        bpollelt->idx = (idx<<16) | (bpollelt->idx & USHRT_MAX);
    }
    return 0;
}


__attribute_nonnull__()
static int  __attribute_regparm__((3))
bpoll_elt_modify_kqueue (bpollset_t * const restrict bpollset,
                         bpollelt_t * const restrict bpollelt,
                         const int events);
static int  __attribute_regparm__((3))
bpoll_elt_modify_kqueue (bpollset_t * const restrict bpollset,
                         bpollelt_t * const restrict bpollelt,
                         const int events)
{
    /* should not get here if nothing to do;
     * events changed, or BPOLL_FL_DISPATCHED */
    struct kevent * const restrict kevents = bpollset->kevents;
    unsigned int rdidx = bpollelt->idx & 0xFFFF;
    unsigned int wridx = bpollelt->idx >> 16;
    unsigned int idx = USHRT_MAX;
    const unsigned int fd = (unsigned int)bpollelt->fd;
    int flags = ((events & BPOLLET)       ? EV_CLEAR    : 0)
              | ((events & BPOLLDISPATCH) ? EV_DISPATCH : 0)
              | EV_RECEIPT;
    int rdflags = 0, wrflags = 0; /* zero indicates no need for filter change */
    if (((events & BPOLLIN) ^ (bpollelt->events & BPOLLIN))
        || (bpollelt->flpriv & BPOLL_FL_DISP_KQRD)) {
        rdflags = flags | ((events & BPOLLIN) ? EV_ENABLE : EV_DISABLE)
                        | (rdidx != USHRT_MAX ? 0         : EV_ADD);
        if (rdidx >= bpollset->idx || fd != kevents[rdidx].ident) {
            if (bpoll_prepidx_kqueue(bpollset))   /* macro */
                return errno;
            idx = rdidx = bpollset->idx++;
        }
        else if (kevents[rdidx].flags & EV_ADD)
            rdflags |= EV_ADD;
    }
    if (((events & BPOLLOUT) ^ (bpollelt->events & BPOLLOUT))
        || (bpollelt->flpriv & BPOLL_FL_DISP_KQWR)) {
        wrflags = flags | ((events & BPOLLOUT) ? EV_ENABLE : EV_DISABLE)
                        | (wridx != USHRT_MAX  ? 0         : EV_ADD);
        if (wridx >= bpollset->idx || fd != kevents[wridx].ident) {
            if (idx != USHRT_MAX)   /*(bpoll_prepidx_kqueue() checks +2 avail */
                wridx = ++bpollset->idx;
            else {
                if (bpoll_prepidx_kqueue(bpollset)) /* macro */
                    return errno;
                wridx = bpollset->idx++;
            }
        }
        else if (kevents[wridx].flags & EV_ADD)
            wrflags |= EV_ADD;
    }
    if (rdflags != 0)
        KEV_SET(&kevents[rdidx], fd, EVFILT_READ,  rdflags, 0, 0, bpollelt);
    if (wrflags != 0)
        KEV_SET(&kevents[wridx], fd, EVFILT_WRITE, wrflags, 0, 0, bpollelt);
    bpollelt->idx = (wridx<<16) | rdidx;
    bpollelt->events = events;
    /* unset dispatched flags;
     * caller must remove interest from events if temporarily not interested */
    bpollelt->flpriv &=
      ~(BPOLL_FL_DISPATCHED|BPOLL_FL_DISP_KQRD|BPOLL_FL_DISP_KQWR);
    return 0;
}


__attribute_nonnull__()
static int  __attribute_regparm__((2))
bpoll_elt_remove_kqueue (bpollset_t * const restrict bpollset,
                         bpollelt_t * const restrict bpollelt);
static int  __attribute_regparm__((2))
bpoll_elt_remove_kqueue (bpollset_t * const restrict bpollset,
                         bpollelt_t * const restrict bpollelt)
{
    struct kevent * const restrict kevents = bpollset->kevents;
    unsigned int rdidx = bpollelt->idx & 0xFFFF;
    unsigned int wridx = bpollelt->idx >> 16;
    unsigned int idx = ~0u;
    const unsigned int fd = (unsigned int)bpollelt->fd;
    /* (If EV_ERROR is returned by a kevent, skip removal attempt;
     *  it will be removed from kqueue automatically when its fd is closed
     *  (or else is invalid and would just generate another error)) */
    if (bpollelt->revents & BPOLLERR) {
        bpollelt->events = 0;/* nop; for consistency between bpoll mechanisms */
        return 0;
    }
    /* (If queued but never added to kernel, EV_ERROR ENOENT ignored by bpoll)*/
    if (rdidx != USHRT_MAX) { /* read filter added to kernel */
        if (rdidx >= bpollset->idx || fd != kevents[rdidx].ident) {
            if (bpoll_prepidx_kqueue(bpollset)) /* macro */
                return errno;
            idx = rdidx = bpollset->idx++;
            kevents[rdidx].flags = 0; /* not EV_ADD */
        }
        if (!(kevents[rdidx].flags & EV_ADD))
            KEV_SET(&kevents[rdidx], fd, EVFILT_READ,
                    EV_DELETE|EV_DISABLE|EV_RECEIPT, 0, 0, bpollelt);
    }
    if (wridx != USHRT_MAX) { /* write filter added to kernel */
        if (wridx >= bpollset->idx || fd != kevents[wridx].ident) {
            if (idx != ~0u)         /*(bpoll_prepidx_kqueue() checks +2 avail */
                wridx = ++bpollset->idx;
            else {
                if (bpoll_prepidx_kqueue(bpollset))  /* macro */
                    return errno;
                wridx = bpollset->idx++;
            }
            kevents[wridx].flags = 0; /* not EV_ADD */
        }
        if (!(kevents[wridx].flags & EV_ADD))
            KEV_SET(&kevents[wridx], fd, EVFILT_WRITE,
                    EV_DELETE|EV_DISABLE|EV_RECEIPT, 0, 0, bpollelt);
    }
    bpollelt->idx = (wridx<<16) | rdidx;
    bpollelt->events = 0;  /* nop; for consistency between bpoll mechanisms */
    return 0;
}


__attribute_noinline__
static int
bpoll_recover_kevents_dispatch (bpollset_t * const restrict bpollset)
{
    /* disable complementary read or write filter for bpollelt with interest in
     * both read and write, but only one dispatched in current set of results.
     * There is a fair amount of logic in bpoll_elt_modify_kqueue() that should
     * not be duplicated.  It might one day be abstracted from that routine for
     * use by both routines, but for now, bpoll_recover_kevents_dispatch()
     * calls bpoll_elt_modify_kqueue() and jerry rigs the bpollelt values.
     * (should not fail submitting events since there should be at least enough
     *  space in queue to submit one filter for each result (less one), unless
     *  caller submitted new filters between bpoll_kernel() and bpoll_process(),
     *  or unless every single result needs a second filter disabled, since
     *  bpoll_prepidx_kqueue() always checks for two available slot indexes)
     * (To avoid the possibility of needing two kernel commits, could modify
     *  bpoll_kernel_kqueue() to pass kevent() a slightly reduced queue_sz-1)
     * Caller should not modify events between bpoll_poll(), bpoll_process() */
    bpollelt_t *bpollelt;
    bpollelt_t ** const restrict results = bpollset->results;
    int i, events, rc;
    const int n = bpollset->nfound;
    for (i = 0; i < n; ++i) {
        bpollelt = results[i];
        events = bpollelt->events;
        if ((events & (BPOLLIN|BPOLLOUT)) != (BPOLLIN|BPOLLOUT)
            || (bpollelt->flpriv
                 & (BPOLL_FL_DISPATCHED|BPOLL_FL_DISP_KQRD|BPOLL_FL_DISP_KQWR))
                == (BPOLL_FL_DISPATCHED|BPOLL_FL_DISP_KQRD|BPOLL_FL_DISP_KQWR))
            continue;
        /* modify flpriv and events so that complement filter gets disabled */
        bpollelt->flpriv &=
          ~(BPOLL_FL_DISPATCHED|BPOLL_FL_DISP_KQRD|BPOLL_FL_DISP_KQWR);
        rc = bpoll_elt_modify_kqueue(bpollset, bpollelt,
                                     (events & ~((events & BPOLLIN)
                                                 ? BPOLLOUT
                                                 : BPOLLIN)));
        /* restore flpriv and events, and reflect disabled complement filter */
        bpollelt->events  = events;
        bpollelt->flpriv |=
          BPOLL_FL_DISPATCHED|BPOLL_FL_DISP_KQRD|BPOLL_FL_DISP_KQWR;
        if (__builtin_expect( (rc != 0), 0))
            return rc;
    }
    return 0;
}


#endif /* HAS_KQUEUE */


#if HAS_EVPORT


__attribute_nonnull__()
static int
bpoll_init_evport (bpollset_t * const restrict bpollset);
static int
bpoll_init_evport (bpollset_t * const restrict bpollset)
{
    const unsigned int limit = bpollset->queue_sz;
    bpollset->evport_events = NULL;
    bpollset->mech = BPOLL_M_EVPORT;
    /* max allowable num events or association of objects per port is min
     * value of process.max-port-events resource control when port_create()
     * called. (see setrctrl(2) and rctladm(1M) for resource control info)*/
    if (limit > UINT_MAX/sizeof(struct port_event))
        return (errno = EINVAL);
    while ((bpollset->fd = port_create()) < 0) {
        if (errno != EINTR)
            return errno;
    }
    fcntl(bpollset->fd, F_SETFD, FD_CLOEXEC);
    bpollset->evport_events = (struct port_event *)
      bpollset->fn_mem_alloc(bpollset->vdata,limit*sizeof(struct port_event));
    if (bpollset->evport_events == NULL)
        return errno;
    return 0;
}


__attribute_noinline__
__attribute_nonnull__()
static void
bpoll_maint_evport (bpollset_t * const restrict bpollset);
static void
bpoll_maint_evport (bpollset_t * const restrict bpollset)
{
    bpollelt_t *bpollelt;
    bpollelt_t ** const restrict rmlist = bpollset->rmlist;
    const int rmidx = bpollset->rmidx;
    const int fd = bpollset->fd;
    int rv;
    for (int idx = 0; idx < rmidx; ++idx) {
        bpollelt = rmlist[idx];
        /*(skip dissociate for add then delete (not currently associated))*/
        if ((bpollelt->flpriv
             & (BPOLL_FL_CTL_ADD | BPOLL_FL_CTL_DEL | BPOLL_FL_DISPATCHED))
              == BPOLL_FL_CTL_DEL && BPOLL_EVENTS_FILT(bpollelt->events) != 0) {
            do {
                rv = port_dissociate(fd,PORT_SOURCE_FD,(uintptr_t)bpollelt->fd);
            } while (__builtin_expect( (rv != 0), 0) && errno == EINTR);
            bpollelt->events = 0;
        }
        /* errors other than EINTR should not happen, and likely
         * indicate some sort of bad fd, so just continue */
    }
    bpoll_maint_default(bpollset);
}


__attribute_noinline__
__attribute_nonnull__()
__attribute_warn_unused_result__
static int
bpoll_commit_evport_impl (bpollset_t * const restrict bpollset,
                          struct port_event * const restrict portev,
                          const int n);
static int
bpoll_commit_evport_impl (bpollset_t * const restrict bpollset,
                          struct port_event * const restrict portev,
                          const int n)
{
    bpollelt_t * restrict bpollelt;
    int i, rv = 0;
    const int portfd = bpollset->fd;
    for (i = 0; i < n; ++i) {
        /* (portev[i].portev_user contains a (bpollelt_t *) ) */
        bpollelt = portev[i].portev_user;
        bpollelt->idx = ~0u;
        /* skip reassociate if no event interest */
        if (bpollelt->flpriv & BPOLL_FL_CTL_DEL)
            continue;
        if (BPOLL_EVENTS_FILT(bpollelt->events) != 0) {
            bpollelt->flpriv &= ~BPOLL_FL_CTL_ADD;
            do {/*(filter out bpollelt->events flags not meaningful to evport)*/
                rv = port_associate(portfd, PORT_SOURCE_FD,
                                    (uintptr_t)bpollelt->fd,
                                    BPOLL_EVENTS_FILT(bpollelt->events),
                                    bpollelt);
            } while (__builtin_expect( (rv == -1), 0) && errno == EINTR);
        }
        else if (!(bpollelt->flpriv & BPOLL_FL_CTL_ADD)) {
            do {/*dissociate if associated and modified for no event interest*/
                rv = port_dissociate(portfd, PORT_SOURCE_FD,
                                     (uintptr_t)bpollelt->fd);
            } while (__builtin_expect( (rv == -1), 0) && errno == EINTR);
        }
        if (__builtin_expect( (rv != 0), 0)) {
            if (errno == EBADFD)
                /* attempted to associate fd that has been closed.
                 * Silently set POLLNVAL, remove from bpollset, and continue
                 * (see further comments in bpoll_elt_abort()) */
                bpoll_elt_abort(bpollset, bpollelt);
            else
                return rv;  /* unexpected or unrecoverable error */
        }
    }
    return 0;
}


__attribute_nonnull__()
__attribute_warn_unused_result__
static int
bpoll_commit_evport_events (bpollset_t * const restrict bpollset);
static int
bpoll_commit_evport_events (bpollset_t * const restrict bpollset)
{
    const int rc = bpoll_commit_evport_impl(bpollset, bpollset->evport_events,
                                            (int)bpollset->idx);
    if (__builtin_expect( (rc == 0), 1)) {
        bpollset->idx = 0;
        if (bpollset->rmidx != 0)
            bpoll_maint_evport(bpollset);
    }
    return rc;
}


__attribute_nonnull__()
static int
bpoll_kernel_evport (bpollset_t * const restrict bpollset);
static int
bpoll_kernel_evport (bpollset_t * const restrict bpollset)
{
    struct port_event * const restrict portev = bpollset->evport_events;

    /* reassociate with event port all pending associations,
     * including those of previously reaped events (unless BPOLLDISPATCH) */
    bpollset->nfound = -1; /* reset if chance of return before probe kernel */
    if ((bpollset->idx != 0 || bpollset->rmidx != 0)
        && bpoll_commit_evport_events(bpollset) != 0)
        return -1;

    /* port_getn() might return events even with EINTR or ETIME.  See thread:
     *   http://mail.opensolaris.org/
     *     pipermail/networking-discuss/2009-August/011979.html
     * which also suggests EINTR might return garbage in nevents,
     * so take precautions to see if > 0 but invalid events.
     * Not perfect, but attempt to not lose events.
     * If events are valid, assume nevents is valid.
     *
     * Also, 32-bit port_getn() on Solaris 10 x86 might return large
     * negative value instead of 0 when returning immediately.
     * https://issues.apache.org/bugzilla/show_bug.cgi?id=48029
     * Check port_getn() != -1 for success instead of checking port_getn()==0 */

    portev[0].portev_source = USHRT_MAX; /* invalid value used as flag */
    bpollset->idx = 1; /* set minimum num events for which to wait */
    if (port_getn(bpollset->fd, portev, bpollset->queue_sz, &bpollset->idx,
                  bpollset->timeout >= 0 ? &bpollset->ts : NULL) == 0
        || errno == ETIME
        || (errno == EINTR && portev[0].portev_source != USHRT_MAX)) {
        /* map bpollelt->idx into evports_events for later reassociate */
        /* (portev[i].portev_user contains a (bpollelt_t *) ) */
        /* (since already walking events, copy revents into bpollelt,
         *  which does some work bpoll_process_evport() would otherwise do) */
        const int nfound = (int)bpollset->idx;
        int reassoc = -1;  /* index of last portev[] element to reassociate */
        bpollelt_t * restrict bpollelt;
        for (int i = 0; i < nfound; ++i) {
            bpollelt = portev[i].portev_user;
            bpollelt->revents = portev[i].portev_events;
            if (!(bpollelt->events & BPOLLDISPATCH)) { /*cross-ref for reassoc*/
                bpollelt->idx = (unsigned int)(reassoc = i);
                bpollelt->flpriv |= BPOLL_FL_CTL_ADD;
            }
            else {                                  /*one-shot*/
                bpollelt->idx = bpollset->queue_sz; /*invalid index*/
                bpollelt->flpriv |= BPOLL_FL_CTL_ADD | BPOLL_FL_DISPATCHED;
            }
        }
        bpollset->nfound = nfound;

        /* default behavior in bpoll is not one-shot, in contrast to default
         * behavior of evport.  bpoll emulates persistence by later
         * re-adding to evport fds for which events have been returned,
         * unless BPOLLDISPATCH */
        if (reassoc+1 == nfound) { /* none one-shot; bpoll reassociate all */
            /* bpoll default */
        }
        else if (reassoc == -1) {  /* all one-shot; skip bpoll reassociate */
            bpollset->idx = 0;
        }
        else {                     /* mix of one-shot and not; reorder list */
            bpollelt_t *btmp;
            bpollelt = portev[reassoc].portev_user;
            for (int i = 0; i < reassoc; ++i) {
                btmp = portev[i].portev_user;
                if (btmp->events & BPOLLDISPATCH) {
                    portev[reassoc].portev_user = btmp;
                    portev[i].portev_user = bpollelt;
                    bpollelt->idx = (unsigned int)i; /*cross-reference reassoc*/
                    while (i < --reassoc) { /* search backwards for next swap */
                        bpollelt = portev[reassoc].portev_user;
                        if (!(bpollelt->events & BPOLLDISPATCH))
                            break;
                    }
                }
            }
            bpollset->idx = (unsigned int)(reassoc+1);
        }
    }
    else
        bpollset->nfound = -1;

    /* perform deferred bpollset maint after committing changes to kernel */
    bpoll_maint_mem_block(bpollset);

    return bpollset->nfound;
}


__attribute_nonnull__()
static int
bpoll_process_evport (bpollset_t * const restrict bpollset);
static int
bpoll_process_evport (bpollset_t * const restrict bpollset)
{
    struct port_event * const restrict portev = bpollset->evport_events;
    bpollelt_t ** const restrict results = bpollset->results;
    const int nfound = bpollset->nfound;
    /*assert(nfound > 0);*/
    /*if (results != NULL) assert(nfound <= bpollset->results_sz);*/

    /* (portev_events copied to bpollelt->revents in bpoll_kernel_evport()) */
    if (results != NULL) {
        for (int i = 0; i < nfound; ++i)
            results[i] = portev[i].portev_user;
    }
    else {
        bpollelt_t * restrict bpollelt;
        bpoll_fn_cb_event_t const fn_cb_event = bpollset->fn_cb_event;
        for (int i = 0; i < nfound; ++i) {
            bpollelt = portev[i].portev_user;
            fn_cb_event(bpollset, bpollelt, -1);
            bpollelt->revents = 0;
        }
    }
    return nfound;
}


__attribute_nonnull__()
static int
bpoll_elt_add_immed_evport (bpollset_t * const restrict bpollset,
                            bpollelt_t ** const restrict bpollelt,
                            int * const restrict nelts,
                            const int events, const int flpriv);
static int
bpoll_elt_add_immed_evport (bpollset_t * const restrict bpollset,
                            bpollelt_t ** const restrict bpollelt,
                            int * const restrict nelts,
                            const int events, const int flpriv)
{
    int i = 0, idx, rc;
    const int n = *nelts;
    struct port_event portev[BPOLL_IMMED_SZ];
    while (i != n) {
        for (idx=0; i < n && idx < BPOLL_IMMED_SZ; ++idx, ++i) {
            portev[idx].portev_user = bpollelt[i];
            bpollelt[i]->events = events;
            if (flpriv == BPOLL_FL_CTL_ADD)
                bpollelt[i]->revents = 0;
            else
                bpollelt[i]->flpriv &= ~BPOLL_FL_DISPATCHED;
            bpollelt[i]->flpriv |= BPOLL_FL_CTL_ADD; /* always add for evport */
        }
        rc = bpoll_commit_evport_impl(bpollset, portev, idx);
        if (__builtin_expect((rc != 0), 0)) {
            *nelts = (i -= idx);
            return rc;
        }
    }
    return 0;
}


#define bpoll_prepidx_evport(bpollset)                                        \
    __builtin_prefetch(bpollset->evport_events+bpollset->idx, 1, 1),          \
      (__builtin_expect( (bpollset->idx == bpollset->queue_sz), 0)            \
       && __builtin_expect( (bpoll_commit_evport_events(bpollset) != 0), 0))


__attribute_nonnull__()
static int
bpoll_elt_add_evport (bpollset_t * const restrict bpollset,
                      bpollelt_t * const restrict bpollelt,
                      const int events);
static int
bpoll_elt_add_evport (bpollset_t * const restrict bpollset,
                      bpollelt_t * const restrict bpollelt,
                      const int events)
{
    int rc;
    if (bpoll_prepidx_evport(bpollset))  /* macro */
        return errno;
    bpollelt->flpriv |= BPOLL_FL_CTL_ADD;
    rc = bpoll_fd_add_thrsafe(bpollset, bpollelt);
    if (__builtin_expect( (rc != 0), 0)
     || __builtin_expect( (0 == BPOLL_EVENTS_FILT(events)), 0)) {
        bpollelt->events = bpollelt->revents = 0;
        return rc;
    }
    bpollset->evport_events[(bpollelt->idx = bpollset->idx++)].portev_user =
      bpollelt;
    bpollelt->events = events;
    bpollelt->revents = 0;
    return 0;
}


__attribute_nonnull__()
static int
bpoll_elt_modify_evport (bpollset_t * const restrict bpollset,
                         bpollelt_t * const restrict bpollelt,
                         const int events);
static int
bpoll_elt_modify_evport (bpollset_t * const restrict bpollset,
                         bpollelt_t * const restrict bpollelt,
                         const int events)
{
    unsigned int idx = bpollelt->idx;
    if (idx >= bpollset->idx
        || bpollset->evport_events[idx].portev_user == NULL
        || ((bpollelt_t *)bpollset->evport_events[idx].portev_user)->fd
             != bpollelt->fd) {
        if (bpoll_prepidx_evport(bpollset))  /* macro */
            return errno;
        bpollelt->idx = idx = bpollset->idx++;
    }
    /* (for simplicity, add to pending list even if events == 0;
     *  reassociate is skipped if events == 0)*/
    /* (always update portev_user in case bpollelt is a copy (don't do that!))*/
    bpollset->evport_events[idx].portev_user = bpollelt;
    bpollelt->events = events;
    bpollelt->flpriv &= ~BPOLL_FL_DISPATCHED;
    return 0;
}


__attribute_nonnull__()
static int
bpoll_elt_remove_evport (bpollset_t * const restrict bpollset
                           __attribute_unused__,
                         bpollelt_t * const restrict bpollelt
                           __attribute_unused__);
static int
bpoll_elt_remove_evport (bpollset_t * const restrict bpollset
                           __attribute_unused__,
                         bpollelt_t * const restrict bpollelt
                           __attribute_unused__)
{
    /*bpollelt->events = 0;*//* do not modify events; see bpoll_maint_evport()*/
    return 0;
}


#endif /* HAS_EVPORT */


#if HAS_DEVPOLL

#include <stropts.h>


__attribute_nonnull__()
static int
bpoll_init_devpoll (bpollset_t * const restrict bpollset);
static int
bpoll_init_devpoll (bpollset_t * const restrict bpollset)
{
    /* For BPOLL_M_DEVPOLL, double the size of pollfds array to allow for
     * modifications to be cached at the same time that results are processed.*/
    /* might check rlimit for all poll mechanisms, but this is required for
     * /dev/poll because ioctl DP_POLL will fail if size of array passed
     * is larger than max fds allowed (check was added in Solaris 10) */
    const unsigned int limit = bpollset->queue_sz;
    const unsigned int n = limit << 1; /*half for changes, half for result set*/
    bpollset->pollfds = NULL;
    bpollset->mech = BPOLL_M_DEVPOLL;
    if (limit > INT_MAX || n > UINT_MAX/sizeof(struct pollfd))
        return (errno = EINVAL);
    while ((bpollset->fd = open("/dev/poll", O_RDWR|O_NONBLOCK)) < 0) {
        if (errno != EINTR)
            return errno;
    }
    fcntl(bpollset->fd, F_SETFD, FD_CLOEXEC);
    bpollset->pollfds = (struct pollfd *)
      bpollset->fn_mem_alloc(bpollset->vdata, n*sizeof(struct pollfd));
    if (bpollset->pollfds == NULL)
        return errno;
    bpollset->pfd_ready = bpollset->pollfds+limit;
    return 0;
}


__attribute_nonnull__()
__attribute_warn_unused_result__
static int
bpoll_commit_devpoll_impl (bpollset_t * const restrict bpollset,
                           struct pollfd * const restrict pollfds,
                           const int n);
static int
bpoll_commit_devpoll_impl (bpollset_t * const restrict bpollset,
                           struct pollfd * const restrict pollfds,
                           const int n)
{
    const ssize_t size = n * sizeof(struct pollfd);
    ssize_t rv;
    /*assert(size != 0);*/
    /* internet search alludes to bug in Solaris with /dev/poll
     * and so libevent uses pwrite() instead of write() */
    do {
        if ((rv = pwrite(bpollset->fd, pollfds, size, 0)) == size)
            return 0;
        /* (re-send entire set of changes if interrupted) */
    } while (__builtin_expect( (rv != -1), 0)
          || __builtin_expect( (errno == EINTR), 0));

    return -1;
}


__attribute_noinline__
__attribute_nonnull__()
__attribute_warn_unused_result__
static int
bpoll_commit_devpoll_events (bpollset_t * const restrict bpollset);
static int
bpoll_commit_devpoll_events (bpollset_t * const restrict bpollset)
{
    /*assert(bpollset->idx != 0);*/
    const int rc = bpoll_commit_devpoll_impl(bpollset, bpollset->pollfds,
                                             (int)bpollset->idx);
    return (__builtin_expect( (rc == 0), 1)) ? (int)(bpollset->idx = 0) : rc;
}


__attribute_nonnull__()
static int
bpoll_kernel_devpoll (bpollset_t * const restrict bpollset);
static int
bpoll_kernel_devpoll (bpollset_t * const restrict bpollset)
{
    struct dvpoll dp = {
      .dp_fds = bpollset->pfd_ready,
      .dp_nfds = (int)bpollset->queue_sz,
      .dp_timeout = bpollset->timeout
    };

    /* The Solaris 9 man page (last revised 15 May 2001) notes that Sun's
     * /dev/poll driver does not yet support polling (timeout of 0).
     * Therefore, you may wish to always set timeout of at least 1 ms.  See:
     * http://docs.sun.com/db/doc/817-0685/6mgfgvagm?a=view#poll-7d-indx-2
     * The above page is no longer available, and the latest man page for
     * poll(7d) does support polling timeout 0.
     *   http://download.oracle.com/docs/cd/E23823_01/html/816-5177/poll-7d.html
     */
  #if defined(__sun) && !defined(__SunOS_5_10)
    if (dp.dp_timeout == 0)
        dp.dp_timeout = 1;
  #endif

    /* write pending changes to /dev/poll */
    bpollset->nfound = -1; /* reset if chance of return before probe kernel */
    if (bpollset->idx > 0 && bpoll_commit_devpoll_events(bpollset) != 0)
        return -1;

    bpollset->nfound = ioctl(bpollset->fd, DP_POLL, &dp);

    /* perform deferred bpollset maint after committing changes to kernel
     * (events committed to kernel above, so can ignore return value here) */
    if (bpollset->rmidx != 0) {
        bpoll_maint_default(bpollset);
        bpoll_maint_mem_block(bpollset);
    }

    return bpollset->nfound;
}


/* [see further below for bpoll_process_devpollset()] */


__attribute_nonnull__()
static int
bpoll_elt_add_immed_devpoll (bpollset_t * const restrict bpollset,
                             bpollelt_t ** const restrict bpollelt,
                             int * const restrict nelts,
                             const int events, const int flpriv);
static int
bpoll_elt_add_immed_devpoll (bpollset_t * const restrict bpollset,
                             bpollelt_t ** const restrict bpollelt,
                             int * const restrict nelts,
                             const int events, const int flpriv)
{
    int i = 0, idx, rc;
    const int n = *nelts;
    struct pollfd pollfds[BPOLL_IMMED_SZ];
    while (i != n) {
        for (idx=0; i < n && idx < BPOLL_IMMED_SZ; ++idx, ++i) {
            pollfds[idx].fd = bpollelt[i]->fd;
            pollfds[idx].events = (short)(bpollelt[i]->events = events);
            if (flpriv == BPOLL_FL_CTL_ADD)
                bpollelt[i]->revents = 0;
            else
                bpollelt[i]->flpriv &= ~BPOLL_FL_DISPATCHED;
        }
        rc = bpoll_commit_devpoll_impl(bpollset, pollfds, idx);
        if (__builtin_expect((rc != 0), 0)) {
            *nelts = (i -= idx);
            return rc;
        }
    }
    return 0;
}


#define bpoll_prepidx_devpoll(bpollset)                                       \
    __builtin_prefetch(bpollset->pollfds+bpollset->idx, 1, 1),                \
      (__builtin_expect( (bpollset->idx == bpollset->queue_sz), 0)            \
       && __builtin_expect( (bpoll_commit_devpoll_events(bpollset) != 0), 0))


__attribute_nonnull__()
static int
bpoll_elt_add_devpoll (bpollset_t * const restrict bpollset,
                       bpollelt_t * const restrict bpollelt,
                       const int events);
static int
bpoll_elt_add_devpoll (bpollset_t * const restrict bpollset,
                       bpollelt_t * const restrict bpollelt,
                       const int events)
{
    unsigned int idx;
    int rc;
    if (bpoll_prepidx_devpoll(bpollset))  /* macro */
        return errno;
    rc = bpoll_fd_add_thrsafe(bpollset, bpollelt);
    if (__builtin_expect( (rc != 0), 0)
     || __builtin_expect( (0 == BPOLL_EVENTS_FILT(events)), 0)) {
        bpollelt->events = bpollelt->revents = 0;
        return rc;
    }
    idx = bpollset->idx++;
    bpollset->pollfds[idx].fd = bpollelt->fd;
    bpollset->pollfds[idx].events = (short)events;
    bpollelt->events = events;
    bpollelt->revents = 0;
    return 0;
}


__attribute_nonnull__()
static int
bpoll_elt_modify_devpoll (bpollset_t * const restrict bpollset,
                          bpollelt_t * const restrict bpollelt,
                          const int events);
static int
bpoll_elt_modify_devpoll (bpollset_t * const restrict bpollset,
                          bpollelt_t * const restrict bpollelt,
                          const int events)
{
    /* remove fd from devpoll prior to modifying events in which interested
     * (necessary for top performance, but does not jive with documentation)
     * Solaris poll(7d) man page states
     *   http://docs.sun.com/app/docs/doc/816-5177/poll-7d?a=view
     *   Writing an array of pollfd struct to the /dev/poll driver has the
     *   effect of adding these file descriptors to the monitored poll file
     *   descriptor set represented by the fd. [ ... ]
     *   If a pollfd array contains multiple pollfd entries with the same
     *   fd field, the "events" field in each pollfd entry is OR'ed.
     * IRIX poll man page states
     *   http://techpubs.sgi.com/library/tpl/cgi-bin/getdoc.cgi?
     *     coll=0650&db=man&fname=/usr/share/catman/a_man/cat7/poll.z
     *   A user can unregister pollfds from the device's poll set by adding
     *   the POLLREMOVE flag to the events field of a pollfd and writing it
     *   to the device.  Users wishing to remove flags from the events field
     *   of a registered pollfd should write two pollfds to the device; the
     *   first should remove the pollfd with the POLLREMOVE flag and the
     *   second should re-add the pollfd with the new set of desired flags.
     * Performance measurements posted to newsgroup indicate the latter.
     *   http://unix.derkeiler.com/
     *     Newsgroups/comp.unix.solaris/2007-09/msg00107.html
     *   http://dbaspot.com/solaris/
     *     247036-dev-poll-dp_poll-ioctl-insanely-slow.html
     * future: roast Sun and get fix or at least have them update doc with
     *   section about modifying interest in events on a given fd.
     *   Make sure Sun handles case where fd is closed and re-opened
     *   between calls to write() to devpoll fd, and multiple pollfds
     *   for old and new inode attached to that fd are written to
     *   devpoll fd in one shot.  (Seems like current behavior handles)
     * XXX: does HP-UX devpoll suffer same shortcomings as Solaris devpoll?
     */
    unsigned int idx;
    if (BPOLL_EVENTS_FILT(bpollelt->events) != 0) {
        if (bpoll_prepidx_devpoll(bpollset))  /* macro */
            return errno;
        idx = bpollset->idx++;
        bpollset->pollfds[idx].fd = bpollelt->fd;
        bpollset->pollfds[idx].events = POLLREMOVE;
        bpollelt->events = 0;
    } /* (end section for remove fd from devpoll) */
    if (BPOLL_EVENTS_FILT(events) != 0) {
        if (bpoll_prepidx_devpoll(bpollset))  /* macro */
            return errno;
        idx = bpollset->idx++;
        bpollset->pollfds[idx].fd = bpollelt->fd;
        bpollset->pollfds[idx].events = (short)events;
        bpollelt->events = events;
        bpollelt->flpriv &= ~BPOLL_FL_DISPATCHED;
    }
    return 0;
}


__attribute_nonnull__()
static int
bpoll_elt_remove_devpoll (bpollset_t * const restrict bpollset,
                          bpollelt_t * const restrict bpollelt);
static int
bpoll_elt_remove_devpoll (bpollset_t * const restrict bpollset,
                          bpollelt_t * const restrict bpollelt)
{
    /* remove file descriptors from monitored poll set even if
     * BPOLL_FL_CLOSE is set, or else POLLNVAL revents may be returned */
    if (BPOLL_EVENTS_FILT(bpollelt->events) != 0
        && !(bpollelt->flpriv & BPOLL_FL_DISPATCHED)) {
        unsigned int idx;
        if (bpoll_prepidx_devpoll(bpollset))  /* macro */
            return errno;
        idx = bpollset->idx++;
        bpollset->pollfds[idx].fd = bpollelt->fd;
        bpollset->pollfds[idx].events = POLLREMOVE;
        bpollelt->events = 0;
    }
    return 0;
}


#endif /* HAS_DEVPOLL */


#if HAS_POLLSET


__attribute_nonnull__()
static int
bpoll_init_pollset (bpollset_t * const restrict bpollset);
static int
bpoll_init_pollset (bpollset_t * const restrict bpollset)
{
    unsigned int limit = bpollset->queue_sz;
    bpollset->pollset_events = NULL;
    bpollset->mech = BPOLL_M_POLLSET;
    if (limit > INT_MAX)
        return (errno = EINVAL);
    while ((bpollset->fd = pollset_create((int)bpollset->limit)) < 0) {
        if (errno != EINTR)
            return errno;
    }
    /*(not doubling poll_ctl for delete + add might result in an extra call
     * to pollset_ctl(); not a big deal)*/
    if ((bpollset->pollset_events = (struct poll_ctl *)
         bpollset->fn_mem_alloc(bpollset->vdata,
                                 limit*sizeof(struct poll_ctl)
                                +limit*sizeof(struct pollfd))) == NULL)
        return errno;
    bpollset->pollfds = bpollset->pfd_ready =
      (struct pollfd *)(bpollset->pollset_events+limit);
    return 0;
}


__attribute_noinline__
__attribute_nonnull__()
__attribute_warn_unused_result__
static int
bpoll_commit_pollset_impl (bpollset_t * const restrict bpollset,
                           struct poll_ctl * const restrict pollset_events,
                           const int n);
static int
bpoll_commit_pollset_impl (bpollset_t * const restrict bpollset,
                           struct poll_ctl * const restrict pollset_events,
                           const int n)
{
    int rv;
    int done = 0;
    /*assert(n != 0);*/
    /*(bpollset->fd is actually pollset_t; not fd)*/
    while ((rv = pollset_ctl(bpollset->fd, pollset_events+done, n-done)) != 0) {
        if (rv == -1 && errno == EINTR)
            continue;
        /* (should not happen unless changes occur outside bpoll purview) */
        if (rv == -1)
            rv = 0;
        if (pollset_events[rv].cmd == PS_ADD)
            pollset_events[rv].cmd = PS_MOD;            /*modify, resubmit*/
        else if (pollset_events[rv].cmd == PS_DELETE) { /*skip, resubmit rest*/
            bpoll_elt_abort(bpollset,
                            bpoll_elt_fetch(bpollset, pollset_events[rv].fd));
            /* (see further comments in bpoll_elt_abort()) */
            if (n - done == ++rv) /* special-case if skipping last element */
                return 0;
        }
        else /* PS_MOD */
            return -1;
        done += rv;
    }
    return 0;
}


__attribute_nonnull__()
__attribute_warn_unused_result__
static int
bpoll_commit_pollset_events (bpollset_t * const restrict bpollset);
static int
bpoll_commit_pollset_events (bpollset_t * const restrict bpollset)
{
    /*assert(bpollset->idx != 0);*/
    const int rc = bpoll_commit_pollset_impl(bpollset, bpollset->pollset_events,
                                             (int)bpollset->idx);
    return (__builtin_expect( (rc == 0), 1)) ? (int)(bpollset->idx = 0) : rc;
}


__attribute_nonnull__()
static int
bpoll_kernel_pollset (bpollset_t * const restrict bpollset);
static int
bpoll_kernel_pollset (bpollset_t * const restrict bpollset)
{
    /* write pending changes */
    bpollset->nfound = -1; /* reset if chance of return before probe kernel */
    if (bpollset->idx != 0 && bpoll_commit_pollset_events(bpollset) != 0)
        return -1;

    bpollset->nfound = pollset_poll(bpollset->fd, bpollset->pfd_ready,
                                    (int)bpollset->queue_sz, bpollset->timeout);

    /* perform deferred bpollset maint after committing changes to kernel
     * (events committed to kernel above, so can ignore return value here) */
    if (bpollset->rmidx != 0) {
        bpoll_maint_default(bpollset);
        bpoll_maint_mem_block(bpollset);
    }

    return bpollset->nfound;
}


/* [see further below for bpoll_process_devpollset()] */


__attribute_nonnull__()
static int
bpoll_elt_add_immed_pollset (bpollset_t * const restrict bpollset,
                             bpollelt_t ** const restrict bpollelt,
                             int * const restrict nelts,
                             const int events, const int flpriv);
static int
bpoll_elt_add_immed_pollset (bpollset_t * const restrict bpollset,
                             bpollelt_t ** const restrict bpollelt,
                             int * const restrict nelts,
                             const int events, const int flpriv)
{
    int i = 0, idx, rc;
    const int n = *nelts;
    const short int cmd = (flpriv == BPOLL_FL_CTL_ADD ? PS_ADD : PS_MOD);
    struct poll_ctl pollset_events[BPOLL_IMMED_SZ];
    while (i != n) {
        for (idx=0; i < n && idx < BPOLL_IMMED_SZ; ++idx, ++i) {
            pollset_events[idx].cmd = cmd;
            pollset_events[idx].events = (short)(bpollelt[i]->events = events);
            pollset_events[idx].fd = bpollelt[i]->fd;
            if (flpriv == BPOLL_FL_CTL_ADD)
                bpollelt[i]->revents = 0;
            else
                bpollelt[i]->flpriv &= ~BPOLL_FL_DISPATCHED;
        }
        rc = bpoll_commit_pollset_impl(bpollset, pollset_events, idx);
        if (__builtin_expect((rc != 0), 0)) {
            *nelts = (i -= idx);
            return rc;
        }
    }
    return 0;
}


#define bpoll_prepidx_pollset(bpollset)                                       \
    __builtin_prefetch(bpollset->pollset_events+bpollset->idx, 1, 1),         \
      (__builtin_expect( (bpollset->idx == bpollset->queue_sz), 0)            \
       && __builtin_expect( (bpoll_commit_pollset_events(bpollset) != 0), 0))


__attribute_nonnull__()
static int
bpoll_elt_add_pollset (bpollset_t * const restrict bpollset,
                       bpollelt_t * const restrict bpollelt,
                       const int events);
static int
bpoll_elt_add_pollset (bpollset_t * const restrict bpollset,
                       bpollelt_t * const restrict bpollelt,
                       const int events)
{
    unsigned int idx;
    int rc;
    if (bpoll_prepidx_pollset(bpollset))  /* macro */
        return errno;
    rc = bpoll_fd_add_thrsafe(bpollset, bpollelt);
    if (__builtin_expect( (rc != 0), 0)
     || __builtin_expect( (0 == BPOLL_EVENTS_FILT(events)), 0)) {
        bpollelt->events = bpollelt->revents = 0;
        return rc;
    }
    idx = bpollset->idx++;
    bpollset->pollset_events[idx].cmd = PS_ADD;
    bpollset->pollset_events[idx].fd = bpollelt->fd;
    bpollset->pollset_events[idx].events = (short)events;
    bpollelt->events = events;
    bpollelt->revents = 0;
    return 0;
}


__attribute_nonnull__()
static int
bpoll_elt_modify_pollset (bpollset_t * const restrict bpollset,
                          bpollelt_t * const restrict bpollelt,
                          const int events);
static int
bpoll_elt_modify_pollset (bpollset_t * const restrict bpollset,
                          bpollelt_t * const restrict bpollelt,
                          const int events)
{
    unsigned int idx;
    if ((BPOLL_EVENTS_FILT(bpollelt->events) & ~BPOLL_EVENTS_FILT(events))
        && !(bpollelt->flpriv & BPOLL_FL_DISPATCHED)) {
        /*removing flags requires delete,add*/
        if (bpoll_prepidx_pollset(bpollset))  /* macro */
            return errno;
        idx = bpollset->idx++;
        bpollset->pollset_events[idx].cmd = PS_DELETE;
        bpollset->pollset_events[idx].fd = bpollelt->fd;
        bpollelt->events = 0;
    }
    if (BPOLL_EVENTS_FILT(events) != 0) {
        if (bpoll_prepidx_pollset(bpollset))  /* macro */
            return errno;
        idx = bpollset->idx++;
        bpollset->pollset_events[idx].cmd =
          (BPOLL_EVENTS_FILT(bpollelt->events) != 0
          && !(bpollelt->flpriv & BPOLL_FL_DISPATCHED) ? PS_MOD : PS_ADD);
        bpollset->pollset_events[idx].fd = bpollelt->fd;
        bpollset->pollset_events[idx].events = (short)events;
        bpollelt->events = events;
        bpollelt->flpriv &= ~BPOLL_FL_DISPATCHED;
    }
    return 0;
}


__attribute_nonnull__()
static int
bpoll_elt_remove_pollset (bpollset_t * const restrict bpollset,
                          bpollelt_t * const restrict bpollelt);
static int
bpoll_elt_remove_pollset (bpollset_t * const restrict bpollset,
                          bpollelt_t * const restrict bpollelt)
{
    /* remove file descriptors from monitored poll set even if
     * BPOLL_FL_CLOSE is set, or else POLLNVAL revents may be returned */
    if (BPOLL_EVENTS_FILT(bpollelt->events) != 0
        && !(bpollelt->flpriv & BPOLL_FL_DISPATCHED)) {
        unsigned int idx;
        if (bpoll_prepidx_pollset(bpollset))  /* macro */
            return errno;
        idx = bpollset->idx++;
        bpollset->pollset_events[idx].cmd = PS_DELETE;
        bpollset->pollset_events[idx].fd = bpollelt->fd;
        bpollelt->events = 0;
    }
    return 0;
}


#endif /* HAS_POLLSET */


/* shared by devpoll (Solaris) and pollset (AIX) */
#if HAS_DEVPOLL || HAS_POLLSET
__attribute_nonnull__()
static int
bpoll_process_devpollset (bpollset_t * const restrict bpollset);
static int
bpoll_process_devpollset (bpollset_t * const restrict bpollset)
{
    bpollelt_t * restrict bpollelt;
    const struct pollfd * const restrict pfd_ready = bpollset->pfd_ready;
    bpollelt_t ** const restrict results = bpollset->results;
    bpoll_fn_cb_event_t const fn_cb_event = bpollset->fn_cb_event;
    const int nfound = bpollset->nfound;
    int events;
    /*assert(nfound > 0);*/

    /* check bpoll_elt_fetch() does not return NULL.  While unlikely, it may
     * be possible that kernel returns fd somehow no longer associated with
     * a bpollelt in the bpollset */
    for (int i = 0; i < nfound; ++i) {
        if ((bpollelt = bpoll_elt_fetch(bpollset, pfd_ready[i].fd)) != NULL) {
            bpollelt->revents = (int) pfd_ready[i].revents;
            if (__builtin_expect( (bpollelt->events & BPOLLDISPATCH), 0)) {
                events = bpollelt->events;
                /*(unlikely that queueing removal would fail, but if it did then
                 * events might be returned again by subsequent bpoll_poll)*/
              #if HAS_DEVPOLL
                if (bpoll_elt_remove_devpoll(bpollset, bpollelt) == 0)
                    bpollelt->flpriv |= BPOLL_FL_DISPATCHED;
              #endif
              #if HAS_POLLSET
                if (bpoll_elt_remove_pollset(bpollset, bpollelt) == 0)
                    bpollelt->flpriv |= BPOLL_FL_DISPATCHED;
              #endif
                bpollelt->events = events;/*restore events value set by caller*/
            }
            if (results != NULL)
                results[i] = bpollelt;
            else {
                fn_cb_event(bpollset, bpollelt, -1);
                bpollelt->revents = 0;
            }
        }
    }
    return nfound;
}
#endif /* HAS_DEVPOLL || HAS_POLLSET */


#if HAS_EPOLL


__attribute_nonnull__()
static int
bpoll_init_epoll (bpollset_t * const restrict bpollset);
static int
bpoll_init_epoll (bpollset_t * const restrict bpollset)
{
    /* For BPOLL_M_EPOLL, double the size of epoll_event array to allow for
     * modifications to be cached at the same time that results are processed.*/
    const unsigned int limit = bpollset->queue_sz;
    const unsigned int n = limit << 1; /*half for changes, half for result set*/
    bpollset->epoll_events = NULL;
    bpollset->mech = BPOLL_M_EPOLL;
    #if HAS_EPOLL_PWAIT
      bpollset->sigmaskp = NULL;
    #endif
    if (limit > INT_MAX || n > UINT_MAX/sizeof(struct epoll_event))
        return (errno = EINVAL);
    #ifndef EPOLL_CLOEXEC  /*(limit ignored in more recent epoll_create())*/
      while ((bpollset->fd = epoll_create((size_t)bpollset->limit)) < 0)
    #else
      while ((bpollset->fd = epoll_create1(EPOLL_CLOEXEC)) < 0)
    #endif
        {
            if (errno != EINTR)
                return errno;
        }
    #ifndef EPOLL_CLOEXEC
      fcntl(bpollset->fd, F_SETFD, FD_CLOEXEC);
    #endif
    bpollset->epoll_events = (struct epoll_event *)
      bpollset->fn_mem_alloc(bpollset->vdata, n*sizeof(struct epoll_event));
    if (bpollset->epoll_events == NULL)
        return errno;
    /* valgrind reports (in 32-bit)
     * "Syscall param epoll_ctl(event) points to uninitialised byte(s)"
     * in bpoll_commit_epoll_events() though the struct epoll_event is
     * initialized.  Might memset(bpollset->epoll_events, 0, limit) to quiet.
     * The uninitialized bytes are part of union epoll_data .u64, since
     * we store .ptr (4-bytes in 32-bit) and union is 8-bytes (for .u64). */
    bpollset->epoll_ready = bpollset->epoll_events+limit;
    return 0;
}


/*(avoid library overhead; epoll_ctl operates on single fd; called frequently)*/
#include <sys/syscall.h>
#ifdef __NR_epoll_ctl
#define epoll_ctl(epfd, op, fd, event) \
  (syscall(__NR_epoll_ctl, (epfd), (op), (fd), (event)))
#endif


__attribute_noinline__
__attribute_nonnull__()
static void
bpoll_maint_epoll (bpollset_t * const restrict bpollset);
static void
bpoll_maint_epoll (bpollset_t * const restrict bpollset)
{
    bpollelt_t ** const restrict rmlist = bpollset->rmlist;
    const int rmidx = bpollset->rmidx;
    const int fd = bpollset->fd;
    int rv;
    for (int idx = 0; idx < rmidx; ++idx) {
        /*(skip EPOLL_CTL_DEL if add then delete before initial EPOLL_CTL_ADD)*/
        if ((rmlist[idx]->flpriv
             & (BPOLL_FL_CTL_ADD | BPOLL_FL_CTL_DEL | BPOLL_FL_DISPATCHED))
            == BPOLL_FL_CTL_DEL) {
            do { /*(Linux kernel 2.6.9+ required with NULL epoll_event arg)*/
                rv = epoll_ctl(fd, EPOLL_CTL_DEL, rmlist[idx]->fd, NULL);
            } while (__builtin_expect( (rv != 0), 0) && errno == EINTR);
        }
        /* errors other than EINTR should not happen, and likely indicate
         * some sort of bad fd (EBADF, ENOENT, EPERM), so just continue */
    }
    bpoll_maint_default(bpollset);
}


__attribute_noinline__
__attribute_nonnull__()
__attribute_warn_unused_result__
static int
bpoll_commit_epoll_impl (bpollset_t * const restrict bpollset,
                         struct epoll_event * const restrict epoll_events,
                         const int n);
static int
bpoll_commit_epoll_impl (bpollset_t * const restrict bpollset,
                         struct epoll_event * const restrict epoll_events,
                         const int n)
{
    bpollelt_t *bpollelt;
    int op, rv;
    const int epollfd = bpollset->fd;

    for (int i = 0; i < n; ++i) {
        bpollelt = (bpollelt_t *)epoll_events[i].data.ptr;
        bpollelt->idx = ~0u;
        if (bpollelt->flpriv & BPOLL_FL_CTL_DEL)
            continue;
        op = (bpollelt->flpriv & BPOLL_FL_CTL_ADD)
          ? EPOLL_CTL_ADD
          : EPOLL_CTL_MOD;
        bpollelt->flpriv &= ~BPOLL_FL_CTL_ADD;
        do {
            rv = epoll_ctl(epollfd, op, bpollelt->fd, &epoll_events[i]);
        } while (__builtin_expect( (rv == -1), 0) && errno == EINTR);
        if (__builtin_expect( (rv != 0), 0)) {
            if (errno == EBADF || errno == ENOENT)
                /* e.g. caller close()d file descriptors unbeknownst to bpoll */
                bpoll_elt_abort(bpollset, bpollelt);
            else if (errno == EEXIST && op == EPOLL_CTL_ADD)
                /* workaround Linux kernel bug with dup*() and
                 * underlying kernel file description man epoll(7) */
                --i;  /* loop around and retry as EPOLL_CTL_MOD */
            else
                return rv;  /* unexpected or **unrecoverable** error */
        }
    }
    return 0;
}


__attribute_nonnull__()
__attribute_warn_unused_result__
static int  __attribute_regparm__((1))
bpoll_commit_epoll_events (bpollset_t * const restrict bpollset);
static int  __attribute_regparm__((1))
bpoll_commit_epoll_events (bpollset_t * const restrict bpollset)
{
    const int rc = bpoll_commit_epoll_impl(bpollset, bpollset->epoll_events,
                                           (int)bpollset->idx);
    if (__builtin_expect( (rc == 0), 1)) {
        bpollset->idx = 0;
        if (bpollset->rmidx != 0)
            bpoll_maint_epoll(bpollset);
    }
    return rc;
}


__attribute_nonnull__()
static int
bpoll_kernel_epoll (bpollset_t * const restrict bpollset);
static int
bpoll_kernel_epoll (bpollset_t * const restrict bpollset)
{
    /* write pending changes */
    bpollset->nfound = -1; /* reset if chance of return before probe kernel */
    if ((bpollset->idx != 0 || bpollset->rmidx != 0)
        && bpoll_commit_epoll_events(bpollset) != 0)
        return -1;

    /* epoll_pwait() added in kernel 2.6.19;
       use epoll_wait() without sigmask arg if epoll_pwait() not available*/
  #if HAS_EPOLL_PWAIT
    bpollset->nfound = epoll_pwait(bpollset->fd, bpollset->epoll_ready,
                                   (int)bpollset->queue_sz, bpollset->timeout,
                                   bpollset->sigmaskp);
  #else
    bpollset->nfound = epoll_wait(bpollset->fd, bpollset->epoll_ready,
                                  (int)bpollset->queue_sz, bpollset->timeout);
  #endif

    /* perform deferred bpollset maint after committing changes to kernel */
    bpoll_maint_mem_block(bpollset);

    return bpollset->nfound;
}


__attribute_nonnull__()
static int
bpoll_process_epoll (bpollset_t * const restrict bpollset);
static int
bpoll_process_epoll (bpollset_t * const restrict bpollset)
{
    struct epoll_event * const restrict epoll_ready = bpollset->epoll_ready;
    bpollelt_t * restrict bpollelt;
    bpollelt_t ** const restrict results = bpollset->results;
    const int nfound = bpollset->nfound;
    /*assert(nfound > 0);*/
    /*if (results != NULL) assert(nfound <= bpollset->results_sz);*/

    if (results != NULL) {
        for (int i = 0; i < nfound; ++i) {
            results[i] = bpollelt = (bpollelt_t *)epoll_ready[i].data.ptr;
            bpollelt->revents = (int) epoll_ready[i].events;
            if (bpollelt->events & BPOLLDISPATCH)
                bpollelt->flpriv |= BPOLL_FL_DISPATCHED;
        }
    }
    else {
        bpoll_fn_cb_event_t const fn_cb_event = bpollset->fn_cb_event;
        for (int i = 0; i < nfound; ++i) {
            bpollelt = (bpollelt_t *)epoll_ready[i].data.ptr;
            bpollelt->revents = (int) epoll_ready[i].events;
            if (bpollelt->events & BPOLLDISPATCH)
                bpollelt->flpriv |= BPOLL_FL_DISPATCHED;
            fn_cb_event(bpollset, bpollelt, -1);
            bpollelt->revents = 0;
        }
    }
    return nfound;
}


__attribute_nonnull__()
static int
bpoll_elt_add_immed_epoll (bpollset_t * const restrict bpollset,
                           bpollelt_t ** const restrict bpollelt,
                           int * const restrict nelts,
                           const int events, const int flpriv);
static int
bpoll_elt_add_immed_epoll (bpollset_t * const restrict bpollset,
                           bpollelt_t ** const restrict bpollelt,
                           int * const restrict nelts,
                           const int events, const int flpriv)
{
    int i = 0, idx, rc;
    const int n = *nelts;
    struct epoll_event epoll_events[BPOLL_IMMED_SZ];
    while (i != n) {
        for (idx=0; i < n && idx < BPOLL_IMMED_SZ; ++idx, ++i) {
            epoll_events[idx].data.ptr = bpollelt[i];
            epoll_events[idx].events   = (__uint32_t) events;
            bpollelt[i]->events = events;
            if (flpriv == BPOLL_FL_CTL_ADD) {
                bpollelt[i]->revents = 0;
                bpollelt[i]->flpriv |= BPOLL_FL_CTL_ADD;
            }
            else
                bpollelt[i]->flpriv &= ~BPOLL_FL_DISPATCHED;
        }
        rc = bpoll_commit_epoll_impl(bpollset, epoll_events, idx);
        if (__builtin_expect((rc != 0), 0)) {
            *nelts = (i -= idx);
            return rc;
        }
    }
    return 0;
}


#define bpoll_prepidx_epoll(bpollset)                                         \
    __builtin_prefetch(bpollset->epoll_events+bpollset->idx, 1, 1),           \
      (__builtin_expect( (bpollset->idx == bpollset->queue_sz), 0)            \
       && __builtin_expect( (bpoll_commit_epoll_events(bpollset) != 0), 0))   \


__attribute_nonnull__()
static int  __attribute_regparm__((3))
bpoll_elt_add_epoll (bpollset_t * const restrict bpollset,
                     bpollelt_t * const restrict bpollelt,
                     const int events);
static int  __attribute_regparm__((3))
bpoll_elt_add_epoll (bpollset_t * const restrict bpollset,
                     bpollelt_t * const restrict bpollelt,
                     const int events)
{
    unsigned int idx;
    int rc;
  #if 0 /* epoll now supports sockets,pipes,eventfd,signalfd,inotify,timerfd */
    rc = bpollelt->fdtype != BPOLL_FD_SOCKET
      && bpollelt->fdtype != BPOLL_FD_PIPE;
    if (__builtin_expect( (rc == 1), 0))
        return (errno = ENOTSUP);
  #endif
    if (bpoll_prepidx_epoll(bpollset)) /* macro */
        return errno;
    rc = bpoll_fd_add_thrsafe(bpollset, bpollelt);
    if (__builtin_expect((rc != 0), 0)) {
        return rc;
    }
    idx = bpollset->idx++;
    bpollset->epoll_events[idx].data.ptr = bpollelt;
    bpollset->epoll_events[idx].events   = (__uint32_t) events;
    bpollelt->events = events;
    bpollelt->revents = 0;
    bpollelt->idx = idx;
    bpollelt->flpriv |= BPOLL_FL_CTL_ADD;
    return 0;
}


__attribute_nonnull__()
static int  __attribute_regparm__((3))
bpoll_elt_modify_epoll (bpollset_t * const restrict bpollset,
                        bpollelt_t * const restrict bpollelt,
                        const int events);
static int  __attribute_regparm__((3))
bpoll_elt_modify_epoll (bpollset_t * const restrict bpollset,
                        bpollelt_t * const restrict bpollelt,
                        const int events)
{
    unsigned int idx = bpollelt->idx;
    if (idx >= bpollset->idx) {  /* ~0u if no pending change */
        if (bpoll_prepidx_epoll(bpollset)) /* macro */
            return errno;
        idx = bpollset->idx++;
    }
    bpollset->epoll_events[idx].data.ptr= bpollelt;
    bpollset->epoll_events[idx].events  = (__uint32_t) events;
    bpollelt->events = events;
    bpollelt->flpriv &= ~BPOLL_FL_DISPATCHED;
    bpollelt->idx = idx;
    return 0;
}


__attribute_nonnull__()
static int  __attribute_regparm__((2))
bpoll_elt_remove_epoll (bpollset_t * const restrict bpollset
                          __attribute_unused__,
                        bpollelt_t * const restrict bpollelt
                          __attribute_unused__);
static int  __attribute_regparm__((2))
bpoll_elt_remove_epoll (bpollset_t * const restrict bpollset
                          __attribute_unused__,
                        bpollelt_t * const restrict bpollelt
                          __attribute_unused__)
{
    bpollelt->events = 0;  /* nop; for consistency between bpoll mechanisms */
    return 0;
}


#endif /* HAS_EPOLL */


__attribute_noinline__
__attribute_nonnull__()
static int  __attribute_regparm__((3))
bpoll_elt_rearm_immed_impl (bpollset_t * const restrict bpollset,
                            bpollelt_t ** const restrict bpollelt,
                            int * const restrict nelts,
                            const int events, const int flpriv);
static int  __attribute_regparm__((3))
bpoll_elt_rearm_immed_impl (bpollset_t * const restrict bpollset,
                            bpollelt_t ** const restrict bpollelt,
                            int * const restrict nelts,
                            const int events, const int flpriv)
{
    int rc;
    const int n = *nelts;

   #if HAS_KQUEUE
    if (bpollset->mech == BPOLL_M_KQUEUE)
        rc = bpoll_elt_add_immed_kqueue(bpollset, bpollelt, nelts,
                                        events, flpriv);
    else
   #endif
   #if HAS_EVPORT
    if (bpollset->mech == BPOLL_M_EVPORT)
        rc = bpoll_elt_add_immed_evport(bpollset, bpollelt, nelts,
                                        events, flpriv);
    else
   #endif
   #if HAS_POLLSET
    if (bpollset->mech == BPOLL_M_POLLSET)
        rc = bpoll_elt_add_immed_pollset(bpollset, bpollelt, nelts,
                                         events, flpriv);
    else
   #endif
   #if HAS_DEVPOLL
    if (bpollset->mech == BPOLL_M_DEVPOLL)
        rc = bpoll_elt_add_immed_devpoll(bpollset, bpollelt, nelts,
                                         events, flpriv);
    else
   #endif
   #if HAS_EPOLL
    if (bpollset->mech == BPOLL_M_EPOLL)
        rc = bpoll_elt_add_immed_epoll(bpollset, bpollelt, nelts,
                                       events, flpriv);
    else
   #endif
        /* BPOLL_M_POLL does not support immed add while another thread polls */
        rc = (errno = EINVAL);

  #if !HAS_KQUEUE && !HAS_EVPORT && !HAS_POLLSET && !HAS_DEVPOLL && !HAS_EPOLL
    /* (quell compiler warnings for unused params and unused routines) */
    (void)bpollset; (void)bpollelt; (void)events; (void)flpriv;
    (void)&bpoll_fd_add_thrsafe; (void)&bpoll_elt_abort;
  #endif

    /* some elements might have been added even if return value != 0 */
    return __builtin_expect( (n == *nelts), 1)
      ? rc
      : rc != 0 ? rc : ((errno = ENOSPC), -1);
}


/*
 * bpoll public interfaces
 */


unsigned int
bpoll_mechanisms (void)
{
    return BPOLL_M_POLL
       #if HAS_DEVPOLL
         | BPOLL_M_DEVPOLL
       #endif
       #if HAS_EPOLL
         | BPOLL_M_EPOLL
       #endif
       #if HAS_KQUEUE
         | BPOLL_M_KQUEUE
       #endif
       #if HAS_EVPORT
         | BPOLL_M_EVPORT
       #endif
       #if HAS_POLLSET
         | BPOLL_M_POLLSET
       #endif
         ;
}


int  __attribute_regparm__((1))
bpoll_flush_pending (bpollset_t * const restrict bpollset)
{
    if (bpollset->idx != 0 || bpollset->rmidx != 0) {
        switch (bpollset->mech) {
         #if HAS_KQUEUE
          case BPOLL_M_KQUEUE:
            if (0 == bpoll_commit_kevents(bpollset)) break;
            return errno;
         #endif
         #if HAS_EVPORT
          case BPOLL_M_EVPORT:
            if (0 == bpoll_commit_evport_events(bpollset)) break;
            return errno;
         #endif
         #if HAS_POLLSET
          case BPOLL_M_POLLSET:
            if (0 == bpoll_commit_pollset_events(bpollset)) break;
            return errno;
         #endif
         #if HAS_DEVPOLL
          case BPOLL_M_DEVPOLL:
            if (0 == bpoll_commit_devpoll_events(bpollset)) break;
            return errno;
         #endif
         #if HAS_EPOLL
          case BPOLL_M_EPOLL:
            if (0 == bpoll_commit_epoll_events(bpollset)) break;
            return errno;
         #endif
          case BPOLL_M_POLL:
            break;
          default:
            return (errno = EINVAL);
        }
    }

    /* close() fds pending on rmlist and remove bpollelt from bpollset
     * (Note: this should follow commit of any other pending changes to kernel;
     *  pending lists might conceivably reference bpollelt elements of rmlist)*/
    if (bpollset->rmidx != 0) {
      #if HAS_EVPORT
        if (bpollset->mech == BPOLL_M_EVPORT)
            bpoll_maint_evport(bpollset);
        else
      #endif
      #if HAS_EPOLL
        if (bpollset->mech == BPOLL_M_EPOLL)
            bpoll_maint_epoll(bpollset);
        else
      #endif
            bpoll_maint_default(bpollset);
    }

    bpoll_maint_mem_block(bpollset);

    return 0;
}


int  __attribute_regparm__((1))
bpoll_enable_thrsafe_add(bpollset_t * const restrict bpollset)
{
  #ifdef _THREAD_SAFE
    return (bpollset->mech != BPOLL_M_POLL
            && bpollset->bpollelts_sz > BPOLL_FD_THRESH)
      ? (int)(bpollset->clr = 0u)
      : (errno = EINVAL);
  #else    /* avoid variable unused warning for bpollset */
    return (errno = EINVAL) | (bpollset->mech == BPOLL_M_NOT_SET);
  #endif
}


#if HAS_PSELECT || HAS_PPOLL || HAS_EPOLL_PWAIT
sigset_t *  __attribute_regparm__((1))
bpoll_sigmask_get (bpollset_t * const restrict bpollset, const int vivify)
{
    if (bpollset->sigmaskp == NULL && vivify)
        bpollset->sigmaskp = bpollset->fn_mem_alloc(bpollset->vdata,
                                                    sizeof(sigset_t));
    return bpollset->sigmaskp;
}


int
bpoll_sigmask_set (bpollset_t * const restrict bpollset,
                   sigset_t * const restrict sigs)
{
    if (sigs == bpollset->sigmaskp)
        return 0;
    else if (sigs != NULL) {
        sigset_t * const restrict sigmaskp = bpoll_sigmask_get(bpollset, 1);
        if (sigmaskp == NULL)
            return -1;
        memcpy(bpollset->sigmaskp, sigs, sizeof(sigset_t));
        return 0;
    }
    else {/*(sigs == NULL)*/
        if (bpollset->sigmaskp != NULL) {
            if (bpollset->fn_mem_free != NULL)
                bpollset->fn_mem_free(bpollset->vdata, bpollset->sigmaskp);
            bpollset->sigmaskp = NULL;
        }
        return 0;
    }
}
#endif /* HAS_PSELECT || HAS_PPOLL || HAS_EPOLL_PWAIT */


/* (separate routine from bpoll_init() so that a cleanup can be registered
 *  (i.e. bpoll_destroy()) before opening /dev/poll, kqueue, epoll, etc.)
 */
bpollset_t *
bpoll_create (void * const vdata,
              bpoll_fn_cb_event_t  const fn_cb_event,
              bpoll_fn_cb_close_t  const fn_cb_close,
              bpoll_fn_mem_alloc_t const fn_mem_alloc,
              bpoll_fn_mem_free_t  const fn_mem_free)
{
    register bpollset_t * const restrict bpollset =
      fn_mem_alloc == NULL
        ? (bpollset_t *) bpoll_mem_alloc_default(vdata, sizeof(bpollset_t))
        : (bpollset_t *) fn_mem_alloc(vdata, sizeof(bpollset_t));
    if (__builtin_expect( (bpollset == NULL), 0))
        return NULL;

    bpollset->mech             = BPOLL_M_NOT_SET;
    bpollset->vdata            = vdata;
    bpollset->fd               = -1;
    bpollset->bpollelts        = NULL;
    bpollset->results          = NULL;
    bpollset->rmidx            = 0;
    bpollset->rmsz             = 0;
    bpollset->rmlist           = NULL;
    bpollset->timeout          = -1;
    bpollset->ts.tv_sec        = 0;
    bpollset->ts.tv_nsec       = 0;
    bpollset->fn_cb_event      = fn_cb_event;
    bpollset->fn_cb_close      = fn_cb_close;
    if (fn_mem_alloc == NULL) {
        bpollset->fn_mem_alloc = bpoll_mem_alloc_default;
        bpollset->fn_mem_free  = bpoll_mem_free_default;
    }
    else {  /* (permit fn_mem_free to be NULL) */
        bpollset->fn_mem_alloc = fn_mem_alloc;
        bpollset->fn_mem_free  = fn_mem_free;
    }
    bpollset->mem_chunk_sz     = (size_t)~0u;
    bpollset->mem_chunk_head   = NULL;
    bpollset->mem_chunk_tail   = NULL;
    bpollset->mem_block_head   = NULL;
    bpollset->mem_block_sz     = ~0u;
    bpollset->mem_block_freed  = 0;
  #ifdef _THREAD_SAFE
    memset(bpollset->bpollelts_used, 0, sizeof(bpollset->bpollelts_used));
  #endif
    return bpollset;
}


/* (returns 0 on success, else the value of errno) */
int  __attribute_regparm__((1))
bpoll_init (bpollset_t * const restrict bpollset,
            unsigned int flags, unsigned int limit,
            const unsigned int queue_sz, const unsigned int block_sz)
{
    unsigned int n;
    int rc;

    if (bpollset->mech != BPOLL_M_NOT_SET) {
        /* destroy in bpoll_init() to be able to return error, if any
         * (destruction repeated in bpoll_cleanup()) */
        rc = pthread_mutex_destroy(&bpollset->mutex);
        if (rc != 0)
            return (errno = rc);
        bpoll_cleanup(bpollset);
    }

    /* initialize bpollelt_t block allocator parameters
     * If caller requires alignment greater than alignment of bpollelt_t, then
     * caller should add padding to block_sz requested and should subsequently
     * add the necessary padding, as needed, when assigning from block->data. */
    if (block_sz > UINT_MAX - sizeof(bpollelt_t))
        return (errno = EINVAL);
  #if !defined(_LP64) && !defined(__LP64__)
    if ((size_t)block_sz
           > BPOLL_MEM_ALIGN_MAX/BPOLL_MEM_BLOCKS_PER_CHUNK-sizeof(bpollelt_t))
        return (errno = EINVAL);
  #endif
    bpollset->mem_block_sz =
      (unsigned int)BPOLL_MEM_ALIGN(sizeof(bpollelt_t) + (size_t)block_sz);
    bpollset->mem_chunk_sz = (limit <= BPOLL_FD_THRESH)
      ? BPOLL_FD_THRESH
      : BPOLL_MEM_BLOCKS_PER_CHUNK;
    bpollset->mem_chunk_sz *= bpollset->mem_block_sz;

    /* basic validation of descriptor limit requested */
    if (__builtin_expect( (limit == 0), 0))
        return (errno = EINVAL);
    if (limit > BPOLL_FD_THRESH) {
        /* do not incur overhead of getrlimit check if limit <= BPOLL_FD_THRESH;
         * (still possible rlimits set this low and will error when exceeded) */
        struct rlimit rlim;
        do {
            rc = getrlimit(RLIMIT_NOFILE, &rlim);
        } while (__builtin_expect( (rc == -1), 0) && errno == EINTR);
        if (__builtin_expect( (rc != 0), 0))
            return errno;
        if (__builtin_expect( (limit >= rlim.rlim_max), 0)) {
            if (limit == (unsigned int)-1) {
                limit = rlim.rlim_max-1;
                if (__builtin_expect( (rlim.rlim_max == 0), 0)
                 || __builtin_expect( (limit == 0), 0))
                    return (errno = EINVAL);
            }
            else if (limit == rlim.rlim_max)
                limit = rlim.rlim_max-1;
            else
                return (errno = EINVAL);
        }
        if (limit >= rlim.rlim_cur) { /* need +1 fd for most bpoll mechanisms */
            if (limit > rlim.rlim_max - 8 && rlim.rlim_max >= 16)
                limit = rlim.rlim_max - 8;
            rlim.rlim_cur = limit + 8;/* attempt to add a touch of headroom */
            if (rlim.rlim_cur > rlim.rlim_max)
                rlim.rlim_cur = rlim.rlim_max;
            do {
                rc = setrlimit(RLIMIT_NOFILE, &rlim);
            } while (__builtin_expect( (rc == -1), 0) && errno == EINTR);
            if (__builtin_expect( (rc != 0), 0))
                return errno;
        }
    }

    /* simplistic "choose poll mechanism for me"; if limit <= 16 use poll(),
     * (threshold (16) chosen via a brief and coarse benchmark; review further)
     * else prefer more advanced poll-type mechanism, if available.
     * (order of 'if' statements in code below determines mechanism choice) */
    if (flags == BPOLL_M_NOT_SET)
        flags = limit <= 16 ? (unsigned int)BPOLL_M_POLL : ~0u;

    bpollset->idx          = 0;
    bpollset->clr          =~0u;
    bpollset->limit        = limit;
    bpollset->nfound       = 0;
    bpollset->nelts        = 0;
    bpollset->bpollelts_sz = 0;
    bpollset->results_sz   = 0;
    bpollset->queue_sz = queue_sz != 0 && queue_sz <= limit ? queue_sz : limit;

    /* (certain poll mechanisms take an (int) arg for max entries to return,
     *  effectively reducing 'limit' to < INT_MAX.  In practice, poll mechanism
     *  limits are actually much less.) */

  #if HAS_KQUEUE
    if (flags & BPOLL_M_KQUEUE)  rc = bpoll_init_kqueue(bpollset);  else
  #endif
  #if HAS_POLLSET
    if (flags & BPOLL_M_POLLSET) rc = bpoll_init_pollset(bpollset); else
  #endif
  #if HAS_DEVPOLL
    if (flags & BPOLL_M_DEVPOLL) rc = bpoll_init_devpoll(bpollset); else
  #endif
  #if HAS_EVPORT
    if (flags & BPOLL_M_EVPORT)  rc = bpoll_init_evport(bpollset);  else
  #endif
  #if HAS_EPOLL
    if (flags & BPOLL_M_EPOLL)   rc = bpoll_init_epoll(bpollset);   else
  #endif
    if (flags & BPOLL_M_POLL)    rc = bpoll_init_pollfds(bpollset); else
    /* else */ return (errno = EINVAL);

    if (rc != 0) {
        bpoll_cleanup(bpollset);
        return (errno = rc);
    }

    bpollset->bpollelts_sz = /* (BPOLL_FD_THRESH expected to be power of 2) */
      (bpollset->limit<=BPOLL_FD_THRESH) ? BPOLL_FD_THRESH : BPOLL_FD_THRESH<<1;
    n = bpollset->bpollelts_sz * sizeof(bpollelt_t *);
    bpollset->bpollelts = (bpollelt_t **)
      bpollset->fn_mem_alloc(bpollset->vdata, n);
    if (__builtin_expect( (bpollset->bpollelts == NULL), 0)) {
        rc = errno;
        bpoll_cleanup(bpollset);
        return (errno = rc);
    }
    memset(bpollset->bpollelts, 0, n);
    if (bpollset->fn_cb_event == NULL) {
        bpollset->results_sz = bpollset->bpollelts_sz;
        bpollset->results = (bpollelt_t **)
          bpollset->fn_mem_alloc(bpollset->vdata, n);
        if (__builtin_expect( (bpollset->results == NULL), 0)) {
            rc = errno;
            bpoll_cleanup(bpollset);
            return (errno = rc);
        }
    }

    rc = pthread_mutex_init(&bpollset->mutex, NULL);
    if (__builtin_expect( (rc != 0), 0)) {
        bpoll_cleanup(bpollset);
        return (errno = rc);
    }

    return 0;
}


/* (caller must ensure that this routine is called only once a bpollset) */
void  __attribute_regparm__((1))
bpoll_destroy (bpollset_t * const restrict bpollset)
{
    if (bpollset != NULL) {
        bpoll_cleanup(bpollset);
        if (bpollset->fn_mem_free != NULL)
            bpollset->fn_mem_free(bpollset->vdata, bpollset);
    }
}


/* (caller should not modify bpollelt, but macros using this need non-const) */
bpollelt_t *  __attribute_regparm__((2))
bpoll_elt_get (bpollset_t * const restrict bpollset, const int fd)
{
    return bpoll_elt_fetch(bpollset, fd);
}


bpollelt_t *  __attribute_regparm__((2))
bpoll_elt_init (bpollset_t * const restrict bpollset, 
                bpollelt_t * restrict bpollelt,
                const int fd,
                const bpoll_fdtype_e fdtype,
                const bpoll_flags_e flags)
{
    if (bpollelt == NULL) {
        bpollelt = bpoll_elt_alloc(bpollset);
        if (__builtin_expect( (bpollelt == NULL), 0))
            return NULL;
        /*(bpollelt->flpriv initialized in bpoll_elt_alloc())*/
        /*(bpollelt->udata is set to block->data */
    }
    else
        bpollelt->flpriv = 0;
        /*(bpollelt->udata not touched if caller provided non-NULL bpollelt)*/

    bpollelt->fd      = fd;
    bpollelt->events  = 0;
    bpollelt->revents = 0;
    bpollelt->idx     = ~0u;  /*(i.e. not ~1u; see bpoll_elt_alloc())*/
    bpollelt->fdtype  = fdtype;
    bpollelt->flags   = flags;
    return bpollelt;
}


int  __attribute_regparm__((3))
bpoll_elt_rearm_immed (bpollset_t * const restrict bpollset,
                       bpollelt_t ** const restrict bpollelt,
                       int * const restrict nelts,
                       const int events)
{
    /* Note: bpollelts expected to be BPOLLDISPATCH and have had events returned
     *       Other usage is undefined since there are race conditions with
     *       events returned in other threads.
     * Note: BPOLL_FL_DISPATCHED is cleared for all bollelt submitted to kernel
     *       (caller must remove events if temporarily not interested)
     * Note: events passed are set to be the same for all bpollelt in list, so
     *       make multiple calls if events differ (such usage not expected) */
    /*assert(events != 0);*//* does not make sense when adding to other thread*/
    const int n = *nelts;
    const int rc = bpoll_elt_rearm_immed_impl(bpollset, bpollelt, nelts,
                                              events, 0);/* !BPOLL_FL_CTL_ADD */
    if (__builtin_expect( (n != *nelts), 0)) {  /* unlikely */
        /* reset dispatched flags for bpollelt not successfully
         * submitted since bpollelt->events potentially modified.
         * Setting BPOLL_FL_DISPATCHED gives caller ability to attempt recover*/
        for (int i = *nelts; i < n; ++i)
            bpollelt[i]->flpriv |= BPOLL_FL_DISPATCHED;
    }
    return rc;
}


int  __attribute_regparm__((3))
bpoll_elt_add_immed (bpollset_t * const restrict bpollset,
                     bpollelt_t ** const restrict bpollelt,
                     int * const restrict nelts,
                     const int events)
{
    /*assert(events != 0);*//* does not make sense when adding to other thread*/
    const int n = *nelts;
    int rc = bpoll_fd_add_eltlist(bpollset, bpollelt, nelts);
    const int m = *nelts; /* nelts might have been reduced */
    if (__builtin_expect( (rc != 0), 0))
        return rc;

    rc = bpoll_elt_rearm_immed_impl(bpollset, bpollelt, nelts,
                                    events, BPOLL_FL_CTL_ADD);

    /* remove excess added to bpollelts but not submitted to kernel;
     * nelts might have been (further) reduced */
    if (__builtin_expect( (m != *nelts), 0))
        bpoll_fd_remove_eltlist(bpollset, bpollelt + *nelts, m - *nelts);

    /* some elements might have been added even if return value != 0 */
    return __builtin_expect( (n == *nelts), 1)
      ? rc
      : rc != 0 ? rc : ((errno = ENOSPC), -1);
}


int  __attribute_regparm__((3))
bpoll_elt_add (bpollset_t * const restrict bpollset,
               bpollelt_t * const restrict bpollelt,
               const int events)
{
   #if HAS_KQUEUE
    if (bpollset->mech == BPOLL_M_KQUEUE)
        return bpoll_elt_add_kqueue(bpollset, bpollelt, events);
    else
   #endif
   #if HAS_EVPORT
    if (bpollset->mech == BPOLL_M_EVPORT)
        return bpoll_elt_add_evport(bpollset, bpollelt, events);
    else
   #endif
   #if HAS_POLLSET
    if (bpollset->mech == BPOLL_M_POLLSET)
        return bpoll_elt_add_pollset(bpollset, bpollelt, events);
    else
   #endif
   #if HAS_DEVPOLL
    if (bpollset->mech == BPOLL_M_DEVPOLL)
        return bpoll_elt_add_devpoll(bpollset, bpollelt, events);
    else
   #endif
   #if HAS_EPOLL
    if (bpollset->mech == BPOLL_M_EPOLL)
        return bpoll_elt_add_epoll(bpollset, bpollelt, events);
    else
   #endif
    if (bpollset->mech == BPOLL_M_POLL)
        return bpoll_elt_add_pollfds(bpollset, bpollelt, events);
    else
        return (errno = EINVAL);
}


/* (it is caller's responsibility to make sure bpollelt is part of bpollset)
 * caller should not set bpollelt->events except through this API, although
 * caller may read bpollelt->events for use in & or | current set of flags
 */
int  __attribute_regparm__((3))
bpoll_elt_modify (bpollset_t * const restrict bpollset,
                  bpollelt_t * const restrict bpollelt,
                  const int events)
{
    if (__builtin_expect( (bpollelt == NULL), 0))
        return (errno = ENOENT);
    if (bpollelt->events == events  /* nothing to do; no change */
        && !(bpollelt->flpriv & BPOLL_FL_DISPATCHED)) /*(not dispatched event)*/
        return 0;
    /* make sure bpollelt not already marked for removal */
    if (__builtin_expect( ((bpollelt->flpriv & BPOLL_FL_CTL_DEL) != 0), 0))
        return (errno = EINVAL);

  #if HAS_KQUEUE
    if (bpollset->mech == BPOLL_M_KQUEUE)
        return bpoll_elt_modify_kqueue(bpollset, bpollelt, events);
    else
  #endif
  #if HAS_EVPORT
    if (bpollset->mech == BPOLL_M_EVPORT)
        return bpoll_elt_modify_evport(bpollset, bpollelt, events);
    else
  #endif
  #if HAS_POLLSET
    if (bpollset->mech == BPOLL_M_POLLSET)
        return bpoll_elt_modify_pollset(bpollset, bpollelt, events);
    else
  #endif
  #if HAS_DEVPOLL
    if (bpollset->mech == BPOLL_M_DEVPOLL)
        return bpoll_elt_modify_devpoll(bpollset, bpollelt, events);
    else
  #endif
  #if HAS_EPOLL
    if (bpollset->mech == BPOLL_M_EPOLL)
        return bpoll_elt_modify_epoll(bpollset, bpollelt, events);
    else
  #endif
    if (bpollset->mech == BPOLL_M_POLL)
        return bpoll_elt_modify_pollfds(bpollset, bpollelt, events);
    else
        return (errno = EINVAL);
}


int  __attribute_regparm__((2))
bpoll_elt_remove (bpollset_t * const restrict bpollset,
                  bpollelt_t * const restrict bpollelt)
{
    int rc = 0;

    if (__builtin_expect( (bpollelt == NULL), 0))
        return (errno = ENOENT);
    /* make sure bpollelt is part of bpollset */
    if (__builtin_expect( (bpoll_elt_fetch(bpollset,bpollelt->fd)!=bpollelt),0))
        return 0;
    /* make sure bpollelt not already marked for removal */
    if (__builtin_expect( ((bpollelt->flpriv & BPOLL_FL_CTL_DEL) != 0), 0))
        return (errno = EEXIST);
    /* make sure space for additional element in rmlist */
    if (__builtin_expect( (bpollset->rmidx == bpollset->rmsz), 0)
        && bpoll_rmlist_resize(bpollset) != 0)
        return (errno = ENOMEM);

  #if HAS_KQUEUE
    if (bpollset->mech == BPOLL_M_KQUEUE)
        rc = bpoll_elt_remove_kqueue(bpollset, bpollelt);
    else
  #endif
  #if HAS_EVPORT
    if (bpollset->mech == BPOLL_M_EVPORT)
        rc = bpoll_elt_remove_evport(bpollset, bpollelt);
    else
  #endif
  #if HAS_POLLSET
    if (bpollset->mech == BPOLL_M_POLLSET)
        rc = bpoll_elt_remove_pollset(bpollset, bpollelt);
    else
  #endif
  #if HAS_DEVPOLL
    if (bpollset->mech == BPOLL_M_DEVPOLL)
        rc = bpoll_elt_remove_devpoll(bpollset, bpollelt);
    else
  #endif
  #if HAS_EPOLL
    if (bpollset->mech == BPOLL_M_EPOLL)
        rc = bpoll_elt_remove_epoll(bpollset, bpollelt);
    else
  #endif
    if (bpollset->mech == BPOLL_M_POLL)
        rc = bpoll_elt_remove_pollfds(bpollset, bpollelt);
    else
        rc = (errno = EINVAL);

    if (rc == 0) {
        bpollelt->flpriv |= BPOLL_FL_CTL_DEL;
        bpollset->rmlist[bpollset->rmidx++] = bpollelt;
    }
    return rc;
}


int  __attribute_regparm__((2))
bpoll_elt_destroy (bpollset_t * const restrict bpollset,
                   bpollelt_t * const restrict bpollelt)
{
    const int fd = bpollelt->fd;
    if (bpoll_elt_fetch(bpollset, fd) == bpollelt)
        return bpoll_elt_remove(bpollset, bpollelt);
    else
        bpoll_elt_free(bpollset, bpollelt);
    return 0;
}


struct timespec *  __attribute_regparm__((2))
bpoll_timespec_set (bpollset_t * const bpollset,
                    const struct timespec * const timespec)
{
    if (__builtin_expect( (timespec != NULL), 1)
        && (__builtin_expect( (bpollset->timeout >= 0), 1)
            || timespec != &bpollset->ts)) {
        /*(catch above if bpoll_timespec_from_msec() given negative timeout)*/
        /*(silently reinterpret timeout if any numbers are out of range)*/
        bpollset->ts.tv_sec  = timespec->tv_sec <= INT_MAX / 1000 - 999
          ? timespec->tv_sec
          : INT_MAX / 1000 - 999;
        bpollset->ts.tv_nsec = timespec->tv_nsec < 1000000000
          ? timespec->tv_nsec
          : 999999999;
        bpollset->timeout = bpollset->ts.tv_sec * 1000
                          + (bpollset->ts.tv_nsec+999999) / 1000000;
                            /*(+999999 to round up to minimum precision)*/
      #ifdef __linux__
        /* libevent notes epoll limitation handling timeouts > 2147482 msec */
        if (__builtin_expect( (bpollset->timeout > 2147482), 0)
            && bpollset->mech == BPOLL_M_EPOLL) {
            bpollset->timeout = 2147482;
            bpollset->ts.tv_sec  = 2147;
            bpollset->ts.tv_nsec = 482000;
        }
      #endif
        /* FreeBSD documents kqueue timeouts > 24 hours treated as 24 hours */
    }
    else {
        bpollset->timeout    = -1;
        bpollset->ts.tv_sec  = 0;
        bpollset->ts.tv_nsec = 0;
    }
    return &bpollset->ts;
}

/* This routine has return values similar to poll()
 * -1 on error, 0 on timeout, else number of descriptors with pending events
 * caller must handle EINTR, because timeout < 0 can only be interrupted by a
 * signal, and so we do not want to automatically restart the call if EINTR is
 * received.  Other errors should result caller calling bpoll_destroy(bpollset)
 */
int  __attribute_regparm__((2))
bpoll_kernel (bpollset_t * const restrict bpollset,
              const struct timespec * const timespec)
{
    if (__builtin_expect( (timespec != &bpollset->ts), 0))
        bpoll_timespec_set(bpollset, timespec);

  #if HAS_KQUEUE
    if (bpollset->mech == BPOLL_M_KQUEUE)
        return bpoll_kernel_kqueue(bpollset);
    else
  #endif
  #if HAS_EVPORT
    if (bpollset->mech == BPOLL_M_EVPORT)
        return bpoll_kernel_evport(bpollset);
    else
  #endif
  #if HAS_POLLSET
    if (bpollset->mech == BPOLL_M_POLLSET)
        return bpoll_kernel_pollset(bpollset);
    else
  #endif
  #if HAS_DEVPOLL
    if (bpollset->mech == BPOLL_M_DEVPOLL)
        return bpoll_kernel_devpoll(bpollset);
    else
  #endif
  #if HAS_EPOLL
    if (bpollset->mech == BPOLL_M_EPOLL)
        return bpoll_kernel_epoll(bpollset);
    else
  #endif
    if (bpollset->mech == BPOLL_M_POLL)
        return bpoll_kernel_pollfds(bpollset);
    else  /* invalid bpollset->mech */
        return (errno = EINVAL), -1;
}


/* process each bpollelt with pending event(s) (e.g. run callback routine)
 * (intended to be called following bpoll_kernel())
 * Return value is same as bpoll_kernel()
 * (This could have been written from perspective of a get-next-event() style
 * routine, but that would require keeping additional state between invocations)
 */
int  __attribute_regparm__((1))
bpoll_process (bpollset_t * const restrict bpollset)
{
    const int nfound = bpollset->nfound;
    if (nfound <= 0)
        return nfound;
    if (bpollset->results_sz != 0
        && __builtin_expect( (bpollset->results_sz < (unsigned int)nfound), 0)
        && __builtin_expect( (bpoll_results_resize(bpollset,
                                                   (size_t)nfound) != 0), 0))
        return -1;

  #if HAS_KQUEUE
    if (bpollset->mech == BPOLL_M_KQUEUE)
        return bpoll_process_kqueue(bpollset);
    else
  #endif
  #if HAS_EVPORT
    if (bpollset->mech == BPOLL_M_EVPORT)
        return bpoll_process_evport(bpollset);
    else
  #endif
  #if HAS_DEVPOLL || HAS_POLLSET
  #if HAS_DEVPOLL
    if (bpollset->mech == BPOLL_M_DEVPOLL)
  #elif HAS_POLLSET
    if (bpollset->mech == BPOLL_M_POLLSET)
  #endif
        return bpoll_process_devpollset(bpollset);
    else
  #endif /* HAS_DEVPOLL || HAS_POLLSET */
  #if HAS_EPOLL
    if (bpollset->mech == BPOLL_M_EPOLL)
        return bpoll_process_epoll(bpollset);
    else
  #endif
    if (bpollset->mech == BPOLL_M_POLL)
        return bpoll_process_pollfds(bpollset);
    else  /* invalid bpollset->mech */
        return (errno = EINVAL), -1;
}


/* (convenience routine; see notes in bpoll.h)
 * poll kernel and process events
 * Wraps bpoll_kernel() and bpoll_process() routines
 * nfound return value from bpoll_kernel() is passed through (maybe adjusted).
 */
int  __attribute_regparm__((2))
bpoll_poll (bpollset_t * const restrict bpollset,
            const struct timespec * const timespec)
{
    const int rc = bpoll_kernel(bpollset, timespec);
    return (__builtin_expect( (rc > 0), 1)) ? bpoll_process(bpollset) : rc;
}


/* poll single descriptor (standalone, portable, convenience routine)
 * (overload sec == (time_t)-1 to mean infinite (no) timeout)
 * (overload fdtype to use empty sigmask if (fdtype & BPOLL_FD_SIGMASK))
 * (overload return value: 0 timeout, -1 interrupt/error, other: revents)
 */
int
bpoll_poll_single (const int fd, const int events, const int fdtype,
                   const time_t sec, const long nsec)
{
    int nfound;

 #if HAS_PPOLL

    /* Linux provides ppoll() that takes sigmask similar to SUSv3 pselect()
     * http://www.opengroup.org/onlinepubs/000095399/functions/select.html*/
    static const sigset_t emask; /* initialized to all zeros */
    struct pollfd pfd = { .fd = fd, .events = (short)events, .revents = 0 };
    const struct timespec ts = { .tv_sec = sec, .tv_nsec = nsec };
    nfound = ppoll(&pfd, 1, sec != (time_t)-1 ? &ts : NULL,
                   (fdtype & BPOLL_FD_SIGMASK) ? &emask : NULL);
    return nfound > 0 ? (int)pfd.revents : nfound;

 #elif HAS_POLL

    if (!(fdtype & BPOLL_FD_SIGMASK) || !HAS_PSELECT) {
        struct pollfd pfd = { fd, (short)events, 0 };
        nfound = poll(&pfd, 1, (sec != (time_t)-1)
                                 ? (sec*1000 + (nsec+999999)/1000000)
                                 : -1);
        return nfound > 0 ? (int)pfd.revents : nfound;
    } /*(fall through if fdtype & BPOLL_FD_SIGMASK requested and HAS_PSELECT)*/

 #endif /* HAS_POLL */

 #if !HAS_POLL || (HAS_PSELECT && !HAS_PPOLL)

    fd_set readset, writeset, exceptset;
    FD_ZERO(&readset);
    FD_ZERO(&writeset);
    FD_ZERO(&exceptset);
    if (events & (BPOLLIN))  { FD_SET(fd, &readset); }
    if (events & (BPOLLOUT)) { FD_SET(fd, &writeset); }
    if (events & (BPOLLPRI|BPOLLERR|BPOLLHUP|BPOLLNVAL)) {
        FD_SET(fd, &exceptset);
    }

  #if HAS_PSELECT  /* pselect() is POSIX.1-2001 */
    static const sigset_t emask; /* initialized to all zeros */
    const struct timespec ts = { .tv_sec = sec, .tv_nsec = nsec };
    nfound = pselect(fd+1, &readset, &writeset, &exceptset,
                     sec != (time_t)-1 ? &ts : NULL,
                     (fdtype & BPOLL_FD_SIGMASK) ? &emask : NULL);
  #else /* !HAS_PSELECT */
    /* note: struct timeval might be modified by select() */
    struct timeval tv = { sec, (nsec+999)/1000 };

   #ifdef NETWARE
    /* NetWare only has select() on sockets and pipe_select() on pipes
     * http://developer.novell.com/ndk/doc/libc/index.html \
     *   ?page=/ndk/doc/libc/libc_enu/data/sdk86.html#sdk86
     * http://developer.novell.com/ndk/doc/libc/index.html \
     *   ?page=/ndk/doc/libc/libc_enu/data/aktgeo5.html */
    if ((fdtype & ~BPOLL_FD_SIGMASK) == BPOLL_FD_PIPE)
        nfound = pipe_select(fd+1,&readset,&writeset,&exceptset,
                             sec != (time_t)-1 ? &tv : NULL);
    else
   #endif
        nfound = select(fd+1, &readset, &writeset, &exceptset,
                        sec != (time_t)-1 ? &tv : NULL);
  #endif /* !HAS_PSELECT */

    if (nfound > 0) {
        int revents = 0;
        if (FD_ISSET(fd, &readset))   { revents |= BPOLLIN;  }
        if (FD_ISSET(fd, &writeset))  { revents |= BPOLLOUT; }
        if (FD_ISSET(fd, &exceptset)) { revents |=
            ((fdtype&~BPOLL_FD_SIGMASK)== BPOLL_FD_SOCKET && (events & BPOLLIN))
              ? BPOLLPRI|BPOLLIN
              : BPOLLERR;
        }
        /* (notes on meanings of 'exception set')
         * fd to socket: out-of-band data received
         * fd to pipe: empty and not open for write / not open for read
         * fd to regular file, tty, directory, character-special file or
         *   block-special file: never has exceptional condition pending */
        return revents;
    }

    return nfound;  /* 0 (timeout) or -1 (interrupt/error) */
 #endif /* !HAS_POLL || (HAS_PSELECT && !HAS_PPOLL) */
}


#endif /* BPOLL_C */
