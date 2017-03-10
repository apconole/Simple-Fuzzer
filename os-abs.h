/**
 * Simple Fuzz
 * Copyright (c) 2009-2015, Aaron Conole <apconole@yahoo.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef __OS_ABSTRACTION_H__
#define __OS_ABSTRACTION_H__

#include <stdio.h>
#include <string.h>
#include "options-block.h"

/**
 * \brief An OS Abstraction for sending streaming data
 * 
 * os_send_tcp makes certain assumptions about the send/recv nature of the 
 * underlying transport. 
 * \param opts The options block which holds a valid stream interface socket
 * \param req A bunch of data to send
 * \param len The length of the data
 * \return 0 on success, <0 on failure.
 */
extern int  os_send_tcp(option_block *opts, char *req, size_t len);

/**
 * \brief An OS Abstraction for sending datagram data
 * 
 * os_send_udp makes certain assumptions about the send/recv nature of the 
 * underlying transport. 
 * \param opts The options block which holds a valid dgram interface socket
 * \param req A bunch of data to send
 * \param len The length of the data
 * \return 0 on success, <0 on failure.
 */
extern int  os_send_udp(option_block *opts, char *req, size_t len);

/**
 * \brief An OS Abstraction for sending datagram data
 * 
 * os_send_unix uses a SOCK_STREAM socket. 
 * \param opts The options block which holds a valid dgram interface socket
 * \param req A bunch of data to send
 * \param len The length of the data
 * \return 0 on success, <0 on failure.
 */
extern int  os_send_unix_stream(option_block *opts, char *req, size_t len);

/**
 * \brief An OS Abstraction for sending datagram data
 * 
 * os_send_unix uses a SOCK_DGRAM socket. 
 * \param opts The options block which holds a valid dgram interface socket
 * \param req A bunch of data to send
 * \param len The length of the data
 * \return 0 on success, <0 on failure.
 */
extern int  os_send_unix_dgram(option_block *opts, char *req, size_t len);

/**
 * \brief There is no cross-platform standard for string replacement. Here is
 * my version.
 *
 * strrepl takes an output *string* buffer, and buffer length. It will replace
 * as many instances of old with new as possible.
 *
 * \param buf A null-terminated printable string, ascii, buffer.
 * \param buflen The max length of the buffer
 * \param old A null-terminated string to remove.
 * \param new A null-terminated string to use in place of old.
 * \return The new string length of buf on success, <0 on failure.
 */
extern int  strrepl(char *buf, size_t buflen, char *old, char *new);

/**
 * \brief smemrepl is similar to strrepl in that it will perform "string" 
 * replacement.
 *
 * smemrepl, however, can work almost completely on binary data. The only ascii
 * formatted data it uses is for the old param. Otherwise, it uses memmem, and
 * memmove to reformat an arbitrary buffer of arbitrary bytes.
 *
 * \param buf A block of memory
 * \param buflen The current "usable" size of buf.
 * \param maxlen The maximum size that buf may occupy.
 * \param old An ascii string to to remove.
 * \param new An arbitrary block of memory to use in place of old.
 * \param newl The size of new to use.
 * \return The new useable buffer length on success, <0 on failure.
 */
extern int  smemrepl(char *buf, size_t buflen, size_t maxlen, char *old, char *new, int newl);

/**
 * \brief Takes an IPv4 dotted-notation address and returns the binary 
 * representation.
 * \param pIpStr A dotted-notation IPv4 address.
 * \return an IP Address, if one could be looked up. If pIpStr is actually 
 * IPv6, returns 1. If there was an error, returns -1 or 0. 
 */
extern int  atoip(const char *pIpStr);

/**
 * \brief dump the len bytes pointed to by b to file out.
 * \param b A block of memory
 * \param len The number of bytes to dump
 * \param out An output stream.
 */
extern void dump(void *b, int len, FILE *out);

#ifndef HAVE_MEMMEM
extern void *__internal_memmem(const void *hs, size_t hsl, const void *nd, size_t ndl);

static inline  void *memmem(const void *hs, size_t hsl, const void *nd, size_t ndl)
{
    return __internal_memmem(hs, hsl, nd, ndl);
}
#endif

#ifdef __WIN32__
#define RTLD_NOW 0
extern void *dlopen(char *, int);
extern void *dlsym(void *, const char *);
extern char *dlerror();

#endif

#endif
