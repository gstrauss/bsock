/*
 * bindsocket.t.c - sample client code to obtain sockets from bindsocket daemon
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include <bindsocket_addrinfo.h>
#include <bindsocket_bind.h>

int
main (int argc, char *argv[])
{
    int nfd;
    int addr[28];
    struct addrinfo ai = { .ai_addr = (struct sockaddr *)addr,
                           .ai_addrlen = sizeof(addr) };
    struct bindsocket_addrinfo_strs aistr;

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
    if (        bindsocket_addrinfo_from_strs(&ai, &aistr)
        &&-1 != (nfd = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol))
        && 0 == bindsocket_bind_addrinfo(nfd, &ai))
        return EXIT_SUCCESS;
  #else  /* load test (serial requests) */
    int i;
    struct timeval tva, tvb;
    bindsocket_addrinfo_from_strs(&ai, &aistr);
    gettimeofday(&tva, NULL);
    for (i=0; i<10000; ++i) {
        if (-1 == (nfd = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol))
            || 0 != bindsocket_bind_addrinfo(nfd, &ai))
            break;
        close(nfd);
    }
    gettimeofday(&tvb, NULL);
    time_t secs = tvb.tv_sec - tva.tv_sec;
    long usecs = tvb.tv_usec - tva.tv_usec;
    if (usecs < 0) {
        usecs = tva.tv_usec - tvb.tv_usec;
        --secs;
    }
    fprintf(stderr, "count: %d %u:%u\n", i, (unsigned)secs,(unsigned)usecs);
    if (i == 10000)
        return EXIT_SUCCESS;
  #endif

    perror("bindsocket");
    return EXIT_FAILURE;
}
