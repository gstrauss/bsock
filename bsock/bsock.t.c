/*
 * bsock.t.c - sample client code to obtain sockets from bsock daemon
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

#include <plasma/plasma_attr.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <bsock_addrinfo.h>
#include <bsock_bind.h>

__attribute_nonnull__
int
main (int argc, char *argv[])
{
    int nfd;
    struct sockaddr_storage addr;
    struct addrinfo ai = { .ai_flags = 0,
                           .ai_addr = (struct sockaddr *)&addr,
                           .ai_addrlen = sizeof(addr) };
    struct bsock_addrinfo_strs aistr;

    if (6 != argc) {
        fprintf(stderr, "invalid args\n");
        return EXIT_FAILURE;
    }

    aistr.family   = argv[1];
    aistr.socktype = argv[2];
    aistr.protocol = argv[3];
    aistr.service  = argv[4];
    aistr.addr     = argv[5];

  #if 1
    if (        bsock_addrinfo_from_strs(&ai, &aistr)
        &&-1 != (nfd = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol))
        && 0 == bsock_bind_addrinfo(nfd, &ai))
        return EXIT_SUCCESS;
  #else  /* load test (serial requests) */
    /* Use 'bsock -d' (no -F unless redirecting output to file) */
    /* Timing inaccurate and much slower if output to terminal (bsock -d -F) */
    int i;
    struct timeval tva, tvb;
    bsock_addrinfo_from_strs(&ai, &aistr);
    gettimeofday(&tva, NULL);
    for (i=0; i<10000; ++i) {
        if (-1 == (nfd = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol))
            || 0 != bsock_bind_addrinfo(nfd, &ai))
            break;
        close(nfd);
    }
    gettimeofday(&tvb, NULL);
    time_t secs = tvb.tv_sec - tva.tv_sec;
    long usecs = tvb.tv_usec - tva.tv_usec;
    if (usecs < 0) {
        usecs += 1000000;
        --secs;
    }
    fprintf(stderr, "count: %d in %u usecs\n", i,
            (unsigned)secs*1000000u + (unsigned)usecs);
    if (i == 10000)
        return EXIT_SUCCESS;
  #endif

    perror("bsock");
    return EXIT_FAILURE;
}
