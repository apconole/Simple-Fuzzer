/**
 * Simple Fuzz
 * Copyright (c) 2010, Aaron Conole <apconole@yahoo.com>
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

#include "sfuzz_fsm.h"

int last_known_error = 0;

#define NULLPTR          1
#define INVALID_PATTERN  2

int wildcards(char *pattern)
{
    int numWilds = 0;

    if(!pattern)
    {
        last_known_error = NULLPTR;
        return -1;
    }

    while(*pattern != '\0')
    {
        switch(*pattern++)
        {
        case '?':
        case '(':
        case '[':
        case '.':
        case '*':
            ++numWilds;
            break;

        case '\\':
            switch(*pattern)
            {
            case '\0':
                last_known_error = INVALID_PATTERN;
                return -1;
            case '?':
            case '(':
            case '[':
            case '.':
            case '*':
                --numWilds;
            }
        }
    }

    return numWilds;
}

int compiles(char *pattern) /* returns < 0 if there's an error */
{
    
}
extern void pfsmerror(); /* prints the last known error from an fsm call */
