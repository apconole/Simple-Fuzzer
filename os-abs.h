/**
 * Simple Fuzz
 * Copyright (c) 2009, Aaron Conole <apconole@yahoo.com>
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
#include "options-block.h"

extern int  os_send_tcp(option_block *opts, char *req, int len);
extern int  os_send_udp(option_block *opts, char *req, int len);
extern int  strrepl(char *buf, size_t buflen, char *old, char *new);
extern int  smemrepl(char *buf, size_t buflen, char *old, char *new, int newl);
extern int  atoip(const char *pIpStr);
extern void dump(void *b, int len, FILE *out);
extern int  mssleep(unsigned long int);

#ifdef __WIN32__
#define RTLD_NOW 0
extern void *dlopen(const char *, int);
extern void *dlsym(void *, const char *);
extern char *dlerror();
#endif

#endif
