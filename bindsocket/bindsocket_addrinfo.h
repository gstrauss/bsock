/*
 * bindsocket_addrinfo - struct addrinfo string manipulation
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

#ifndef INCLUDED_BINDSOCKET_ADDRINFO_H
#define INCLUDED_BINDSOCKET_ADDRINFO_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

int
bindsocket_addrinfo_family_from_str (const char * const family);

int
bindsocket_addrinfo_socktype_from_str (const char * const restrict socktype);

int
bindsocket_addrinfo_protocol_from_str (const char * const restrict protocol);

bool
bindsocket_addrinfo_from_strings(struct addrinfo * const restrict ai,
                                 const char * const restrict family,
                                 const char * const restrict socktype,
                                 const char * const restrict protocol,
                                 const char * const restrict service,
                                 const char * const restrict addr);

#ifdef __cplusplus
}
#endif

#endif
