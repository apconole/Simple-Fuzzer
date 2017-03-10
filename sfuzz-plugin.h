/**
 * Simple Fuzz
 * Copyright (c) 2009-2010, Aaron Conole <apconole@yahoo.com>
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

#ifndef __SFUZZ_PLUGIN_DEFS_H__
#define __SFUZZ_PLUGIN_DEFS_H__

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "options-block.h"

#define PLUGIN_PROVIDES_LINE_OPTS         0x00000001
#define PLUGIN_PROVIDES_PAYLOAD_PARSE     0x00000002
#define PLUGIN_PROVIDES_TRANSPORT_TYPE    0x00000004
#define PLUGIN_PROVIDES_FUZZ_MODIFICATION 0x00000008
#define PLUGIN_PROVIDES_POST_FUZZ         0x00000010

typedef int  (*plugin_capex)();

typedef int  (*plugin_config_line)(option_block *opts, char *l, int i);

typedef int  (*plugin_transport)(option_block *opts, void *d, size_t len);

typedef int  (*plugin_payload_transform)(option_block *opts, void *i, int il, 
                                        void *o, int *ol);

typedef int  (*plugin_fuzz_transform)(option_block *opts, void *inf, int infl, 
                                     void *of, int *ofl);

typedef void (*post_fuzz_mod)(option_block *opts, void *rbuf, int rblen);

typedef char *(*plugin_name)();
typedef char *(*plugin_version)();

/**
 * \brief A _pprovisor struct is the basic form of plugin interface.
 *
 * The plugin call flow looks like:
 *  - capex(), name(), version() are all called when the plugin is loaded.
 *  - config() is called during config file parsing, if there is a new syntax
 *    detected.
 *  - trans() is called to setup the transport layer
 *  - payload_trans() is called before any substitution happens
 *  - fuzz_trans() is called after all replacement has happened
 *  - post_fuzz() is called after the data has been sent
 */
typedef struct _pprovisor
{
    plugin_capex             capex;
    plugin_config_line       config;
    plugin_transport         trans;
    plugin_payload_transform payload_trans;
    plugin_fuzz_transform    fuzz_trans;
    post_fuzz_mod            post_fuzz;

    plugin_name              name;
    plugin_version           version;

} plugin_provisor;

#include <sys/types.h>
#include <unistd.h>

/**
 * \brief The basic sfuzz error message when parsing a config file.
 *
 * \param msg A message to display.
 * \param opts The options block (which holds state).
 */
static inline void file_error(char *msg, option_block *opts)
{
    fprintf(stderr, "[%s] error with file <%s:%d> : %s\n",
            "---", opts->pFilename, opts->lno, msg);
#ifdef SFUZZ_UTIL_COMPILE
    dump_paths();
#endif
    exit(-1);
}

static inline char *process_error()
{
    return
#ifndef WIN32
    strerror(errno);
#else
    "unknown";
#endif
}
#endif
