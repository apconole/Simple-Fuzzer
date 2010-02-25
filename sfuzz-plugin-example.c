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
/* demo plugin - does some skeleton work */

#include <stdio.h>
#include <string.h>

#include "sfuzz-plugin.h"

char *example_name()
{
    return "Simple Fuzzer plugin demo";
}

char *example_version()
{
    return "0.5";
}

int example_capex()
{
    /*note: you may provide any number of hooks by |'ing together
            each capability to provide. */
    return PLUGIN_PROVIDES_POST_FUZZ | PLUGIN_PROVIDES_LINE_OPTS;
}

void example_post_fuzz(option_block *opts, void *i, int l)
{
    printf("postFuzz!\n");
}

int example_line_opts(option_block *opts, char *s, int i)
{
  if(!strncasecmp(s, "example", 7))
    {
      printf("line handle: [%s]\n", s);
      return 0;
    }
  file_error("invalid line passed to plugin!", opts);
  return 1;
}

/*start here*/
void plugin_init(plugin_provisor *pr)
{
    if(pr == NULL)
    {
        fprintf(stderr, "error, unable to init plugin due to fatal call!\n");
        return;
    }
    
    pr->name = example_name;
    pr->version = example_version;
    pr->capex = example_capex;
    pr->post_fuzz = example_post_fuzz;
    pr->config = example_line_opts;
}
