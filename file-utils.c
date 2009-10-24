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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef __WIN32__
#include <dlfcn.h>
#endif

#include <errno.h>

#include "sfuzz.h"
#include "sfuzz-plugin.h"
#include "options-block.h"
#include "os-abs.h"

void read_config(option_block *opts);

#ifndef NOPLUGIN
void *plugin_handle = NULL;

typedef void (*plugin_init)(plugin_provisor *);

void plugin_sanity(option_block *opts)
{
    if(g_plugin == NULL)
        return;

    if(g_plugin->capex == NULL)
    {
        file_error("plugin doesn't provide a capex.", opts);
        free(g_plugin);
        g_plugin = NULL;
        return;        
    }

    if(((g_plugin->capex() & PLUGIN_PROVIDES_LINE_OPTS) ==
        PLUGIN_PROVIDES_LINE_OPTS) && 
       (g_plugin->config == NULL))
    {
        file_error(
          "plugin claims to provide config parsing but doesn't implement it!",
          opts);
        free(g_plugin);
        g_plugin = NULL;
        return;
    }

    if(((g_plugin->capex() & PLUGIN_PROVIDES_PAYLOAD_PARSE) ==
        PLUGIN_PROVIDES_PAYLOAD_PARSE) && 
       (g_plugin->payload_trans == NULL))
    {
        file_error(
         "plugin claims to provide payload parsing but doesn't implement it!",
         opts);
        free(g_plugin);
        g_plugin = NULL;
        return;
    }

    if(((g_plugin->capex() & PLUGIN_PROVIDES_TRANSPORT_TYPE) ==
        PLUGIN_PROVIDES_TRANSPORT_TYPE) && 
       (g_plugin->trans == NULL))
    {
        file_error(
          "plugin claims to provide transportation but doesn't implement it!",
          opts);
        free(g_plugin);
        g_plugin = NULL;
        return;
    }
    
    if(((g_plugin->capex() & PLUGIN_PROVIDES_FUZZ_MODIFICATION) ==
        PLUGIN_PROVIDES_FUZZ_MODIFICATION) && 
       (g_plugin->fuzz_trans == NULL))
    {
        file_error(
          "plugin claims to provide fuzz transform but doesn't implement it!",
          opts);
        free(g_plugin);
        g_plugin = NULL;
        return;
    }

    if(((g_plugin->capex() & PLUGIN_PROVIDES_POST_FUZZ) ==
        PLUGIN_PROVIDES_POST_FUZZ) && 
       (g_plugin->post_fuzz == NULL))
    {
        file_error(
            "plugin claims to provide postfuzz but doesn't implement it!",
            opts);
        free(g_plugin);
        g_plugin = NULL;
        return;
    }

    
}

void plugin_load(char *filename, option_block *opts)
{
    plugin_init ir;
    char fileline[8192] = {0};
    int  length         = strcspn(filename+1, " \n\r");
    
    if( length > 8191 )
    {
        file_error("filename for plugin is too large!", opts);
        return;
    }
    
    strncpy(fileline, filename+1, length);

    if( plugin_handle != NULL )
    {
        file_error("limit 1 plugin per script!", opts);
        return;
    }
    
    plugin_handle = dlopen(fileline, RTLD_NOW);
    if(plugin_handle == NULL)
    {
        fprintf(stderr, "[%s: %s] plugin\n", fileline, dlerror());
        file_error("unable to open plugin specified", opts);
        return;
    }
    
    ir = (plugin_init)dlsym(plugin_handle, "plugin_init");
    if(ir == NULL)
    {
        fprintf(stderr, "--- plugin loading: [%s][%s] ---\n", fileline,
                dlerror());
        file_error("unable to locate entrypoint in plugin", opts);
        return;
    }

    g_plugin = (plugin_provisor*)malloc(sizeof(plugin_provisor));
    
    if(g_plugin == NULL)
    {
        file_error("unable to allocate plugin descriptor", opts);
        return;
    }

    memset(g_plugin, 0, sizeof(plugin_provisor));
    
    ir(g_plugin);

    if(g_plugin->name == NULL || g_plugin->version == NULL)
    {
        file_error("plugin is invalid!", opts);
        return;
    }

    plugin_sanity(opts);
}
#endif

unsigned char convertAsciiHexCharToBin(char asciiHexChar)
{
    unsigned char binByte = 0xFF;
    if((asciiHexChar >= '0') && (asciiHexChar <= '9'))
    {
        binByte = asciiHexChar - '0';
    }
    else if((asciiHexChar >= 'a') && (asciiHexChar <= 'f'))
    {
        binByte = asciiHexChar - 'a' + 0x0A;
    }
    else if((asciiHexChar >= 'A') && (asciiHexChar <= 'f'))
    {
        binByte = asciiHexChar - 'A' + 0x0A;
    }
    return binByte;
}

unsigned int ascii_to_bin(char *str_bin)
{
    /*converts an ascii string to binary*/
    char *out = malloc(8192);
    char *str = malloc(8192);
    int size_no_ws = 0;
    int outBufIdx = 0;
    int binBufIdx = 0;

    int rewind = strlen(str_bin);

    unsigned char firstNibble;
    unsigned char secondNibble;

    while(*str_bin != 0)if(*str_bin++ != ' ')
                        {
                            if(*str_bin == 'x'){*str_bin = ' ';continue;}
                            str[size_no_ws] = *(str_bin-1);
                            size_no_ws++;
                        }

    str_bin -= rewind;

    if((size_no_ws % 2) != 0)
    {
        firstNibble = 0;
        secondNibble = convertAsciiHexCharToBin(str[0]);
        if(secondNibble == 0xFF)
        {
            free(out);
            free(str);
            return -1;
        }
        out[outBufIdx] = ((firstNibble<<4)&0xF0) | (secondNibble &0xF);
        outBufIdx++;
        binBufIdx = 1;
    }
    
    for(; binBufIdx < size_no_ws; binBufIdx += 2)
    {
        firstNibble = convertAsciiHexCharToBin(str[binBufIdx]);
        secondNibble = convertAsciiHexCharToBin(str[binBufIdx+1]);
        
        if((firstNibble == 0xFF) || (secondNibble == 0xFF))
        {
            free(out);
            free(str);
            return -1;
        }
        out[outBufIdx] = ((firstNibble<<4)&0xF0)|(secondNibble&0xF);
        outBufIdx++;
    }

/*debugging
  dump(out, outBufIdx);
*/
    memcpy(str_bin, out, outBufIdx);
    free(out);
    free(str);

    return outBufIdx;

}

void add_symbol(char *sym_name, int sym_len, char *sym_val, int sym_val_len,
                option_block *opts, int i)
{
    sym_t *pSym;
    char buf[8192]= {0};
    char buf2[8192] = {0};

    if((sym_len >= 8192) ||
       (sym_val_len >= 8192))
    {
        file_error("too large symbol!", opts);
    }

    opts->syms_array = realloc(opts->syms_array, 
                               sizeof(sym_t) * (opts->sym_count + 1));
    
    if(opts->syms_array == NULL)
    {
        file_error("out of memory adding symbol.", opts);
    }

    if(i == 0)
    {
	buf[0] = '%';
	memcpy(buf+1, sym_name, sym_len);
	
	snprintf(buf2, 8192, "%u", (unsigned int)strlen(sym_val));
	add_symbol(buf, strlen(buf), buf2, strlen(buf2), opts, 1);
	opts->syms_array = realloc(opts->syms_array, 
				   sizeof(sym_t) * (opts->sym_count + 1));
    
	if(opts->syms_array == NULL)
	{
	    file_error("out of memory adding symbol.", opts);
	}
    }
    opts->sym_count += 1;

    pSym = &(opts->syms_array[opts->sym_count - 1]);

    memset(pSym->sym_name, 0, 8192);
    memset(pSym->sym_val, 0, 8192);
    memcpy(pSym->sym_name, sym_name, sym_len);
    memcpy(pSym->sym_val,  sym_val,  sym_val_len);
    if(i == 1)
        pSym->is_len = 1;
}

void add_b_symbol(char *sym_name, int sym_len, char *sym_val, int sym_val_len,
                  option_block *opts)
{
    sym_t *pSym;

    if((sym_len >= 8192) ||
       (sym_val_len >= 8192))
    {
        file_error("too large symbol!", opts);
    }

    opts->b_syms_array = realloc(opts->b_syms_array, 
                               sizeof(sym_t) * (opts->b_sym_count + 1));
    
    if(opts->b_syms_array == NULL)
    {
        file_error("out of memory adding symbol.", opts);
    }

    opts->b_sym_count += 1;
    
    pSym = &(opts->b_syms_array[opts->b_sym_count - 1]);
    
    memset(pSym->sym_name, 0, 8192);
    memset(pSym->sym_val, 0, 8192);
    memcpy(pSym->sym_name, sym_name, sym_len);
    memcpy(pSym->sym_val,  sym_val,  sym_val_len);
    pSym->is_len = sym_val_len;
    pSym->increment = 0;
}

void set_bsym_increment(option_block *opts, char *symname)
{
    int i = 0;
    sym_t *pSym;

    for(;i<opts->b_sym_count;++i)
    {
        pSym = (sym_t*) &(opts->b_syms_array[i]);
        if(!strcmp(symname, pSym->sym_name))
	{
            pSym->increment = 1;  
            return;
	}
    }
    
    file_error("unable to locate symbol",opts);
}

void add_literal(option_block *opts, char *literal, int len)
{
    opts->litr = realloc(opts->litr, (opts->num_litr+1) * sizeof(char *));
    opts->litr_lens = realloc(opts->litr_lens, 
                              (opts->num_litr+1) * sizeof(int)); 
    if((opts->litr == NULL) || (opts->litr_lens == NULL))
    {
        file_error("too many literal strings - out of memory.", opts);
    }
    
    opts->litr[opts->num_litr] = malloc(len+1);
    if(opts->litr[opts->num_litr] == NULL)
    {
        file_error("literal too long - out of memory.", opts);
    }
    
    strncpy(opts->litr[opts->num_litr], literal, len);
    *((opts->litr[opts->num_litr])+len) = 0;    
    opts->litr_lens[opts->num_litr] = len;

    ++(opts->num_litr);
}

void add_sequence(option_block *opts, char *sequence, int len)
{
    opts->seq = realloc(opts->seq, (opts->num_seq+1) * sizeof(char *));
    opts->seq_lens = realloc(opts->seq_lens, 
                             (opts->num_seq+1) * sizeof(int)); 
    if((opts->seq == NULL) || (opts->seq_lens == NULL))
    {
        file_error("too many sequence strings - out of memory.", opts);
    }
    
    opts->seq[opts->num_seq] = malloc(len+1);
    if(opts->seq[opts->num_seq] == NULL)
    {
        file_error("sequence too long - out of memory.", opts);
    }
    
    strncpy(opts->seq[opts->num_seq], sequence, len);
    *((opts->seq[opts->num_seq])+len) = 0;
    opts->seq_lens[opts->num_seq] = len;

    ++(opts->num_seq);
}

int readLine(option_block *opts, char *line, int len, int ign_cr)
{
    int size = 0;
    char c = 0;

    if(opts == NULL)
        file_error("null options reading line.", opts);
    
    if(opts->fp == NULL)
        file_error("empty file reading line.", opts);
    
    while((!feof(opts->fp)) && (len--))
    {
        size += fread(&c, 1, 1, opts->fp);
        *(line+(size - 1)) = c;
        if((c == '\n') || ((c == '\r') && (!ign_cr)))
            break;
    }
    line[size-1] = 0;
    return size;
}

int processFileLine(option_block *opts, char *line, int line_len)
{
    FILE *t;
    char *f;
    int state;
    int lno;

    char *delim;
    int   sze;
    switch(line[0])
    {
    case '/':
        if(line[1] != '/')
            break;
    case ';':
    case '#':
    case 0:
    case '\n':
        return 0;
    case '\r':
        if(line[1] == '\n')
            return 0;
        break;
    }

    /*not a comment, regular state*/

#ifndef NOPLUGIN
    if(!strncasecmp("plugin", line, 6))
    {
        delim = strstr(line, " ");
        if(delim == NULL)
        {
            file_error("plugin line with no file specified. abort!", opts);
        }
        plugin_load(delim, opts);
        return 0;
    }
#endif

    if(!strncasecmp("literal", line, 7))
    {
        delim = strstr(line, "=");
        if(delim == NULL)
        {
            file_error("literal string not assigned!", opts);
        }
        sze = strlen(delim+1);
        if(sze == 0)
        {
            file_error("literal string is null!", opts);
        }
        add_literal(opts, delim+1, sze);
        return 0;
    }

    if(!strncasecmp("++", line, 2))
    {
        set_bsym_increment(opts, line+2);
        return 0;
    }

    if(!strncasecmp("sequence", line, 7))
    {
        delim = strstr(line, "=");
        if(delim == NULL)
        {
            file_error("sequence string not assigned!", opts);
        }
        sze = strlen(delim+1);
        if(sze == 0)
        {
            file_error("sequence string is null!", opts);
        }
        add_sequence(opts, delim+1, sze);
        return 0;
    }
    
    if(!strncasecmp("reqwait", line, 7))
    {
        delim = strstr(line, "=");
        if(delim == NULL)
            file_error("request wait string not assigned!", opts);
        sze = strlen(delim+1);
        if(sze == 0)
            file_error("request wait string is null!", opts);
        opts->reqw_inms = atoi(delim+1);
        return 0;
    }

    if(!strncasecmp("lineterm", line, 8))
    {
        delim = strstr(line, "=");
        if(delim == NULL)
            file_error("lineterm value not assigned!", opts);
        sze = strlen(delim+1);

        if(sze)
        {
            if((line[strlen(delim)] == '\\') || 
               (line[strlen(delim)] == '0'))
            {
                if(line[strlen(delim)+1] == 'x')
                    sze = ascii_to_bin(line+strlen(delim));
            }
            memcpy(opts->line_term, line+strlen(delim), sze);
        }
        opts->line_terminator_size = sze;
        return 0;
    }

    if(!strncasecmp("maxseqlen", line, 9))
    {
        delim = strstr(line, "=");
        if(delim == NULL)
            file_error("max seq len not assigned!", opts);
        sze = strlen(delim+1);
        if(sze == 0)
            file_error("max seq len is null!", opts);
        opts->mseql = atoi(delim+1);
        return 0;
    }

    if(!strncasecmp("seqstep", line, 7))
    {
        delim = strstr(line, "=");
        if(delim == NULL)
            file_error("seq step not assigned!", opts);
        sze = strlen(delim+1);
        if(sze == 0)
            file_error("seq step is null!", opts);
        opts->seqstep = atoi(delim+1);
        return 0;
    }

    if(!strncasecmp("endcfg", line, 6))
        return 1;

    if(!strncasecmp("include", line, 7))
    {
        delim = strstr(line, " ");
        if(delim == NULL)
            file_error("include not assigned!", opts);
        sze = strlen(delim+1);
        if(sze == 0)
            file_error("include is null!", opts);
        
        t = opts->fp;
        f = malloc(strlen(opts->pFilename));
        if(f == NULL)
        {
            file_error("unable to include file - out of memory.", opts);
        }
        
        /*yeah yeah...not safe. So fuzz it, already!*/
        strcpy(f, opts->pFilename);
        state = opts->state;
        
        strncpy(opts->pFilename, delim+1, MAX_FILENAME_SIZE-1);
        
        /*setup for inner parse.*/
        opts->state = INIT_READ;
        lno = opts->lno;

        /*do inner parse.*/
        read_config(opts);
        
        strcpy(opts->pFilename, f);
        opts->state = state;
        opts->lno   = lno;
        opts->fp    = t;
        
        free(f);
        return 0;
    }

    if(line[0] == '$')
    {
        delim = strstr(line+1, "=");
        if(delim == NULL)
        {
            file_error("symbol not assigned!", opts);
        }
        sze = strlen(delim+1);
        if(sze == 0)
        {
            file_error("symbol is null!", opts);
        }
        add_symbol(line+1, (delim - (line+1)), delim+1, sze, opts, 0);
        return 0;
    } else if (line[0] == '!')
    {
        /*binary stuff*/
        delim = strstr(line+1, "=");
        if(delim == NULL)
        {
            file_error("binary symbol not assigned!", opts);
        }
        sze = strlen(delim+1);
        if(sze == 0)
        {
            file_error("binary symbol is null!", opts);
        }
        sze = ascii_to_bin(delim+1);
        if(sze < 0)
        {
            file_error("binary text is invalid!", opts);
        }
        add_b_symbol(line+1, (delim - (line+1)), delim+1, sze, opts);
        return 0;
    }

#ifndef NOPLUGIN
    if(g_plugin != NULL && 
       ((g_plugin->capex() & PLUGIN_PROVIDES_LINE_OPTS) == 
        PLUGIN_PROVIDES_LINE_OPTS))
    {
        return g_plugin->config(opts, line, line_len);
    }
#endif

    fprintf(stderr, "[%s]\n", line);
    file_error("invalid config file.", opts);
    return 1;
}

void read_config(option_block *opts)
{
    char  done = 0;
    int   len  = 0;
    FILE *f;
    
    char line[8192]; // should never have more than an 8k line.

    if(opts->state != INIT_READ)
        file_error("invalid state for config reading.", opts);

    f = fopen(opts->pFilename, "r");

    if(f == NULL)
        file_error("unable to open file.", opts);

    opts->state = CONFIG_PARSE_BEGIN;
    opts->fp    = f;
    opts->lno   = 1;
    do
    {
        if((len = readLine(opts, line, 8192, 0)) == 0)
            done = 1;
        else
            done = processFileLine(opts, line, len);
        ++(opts->lno);
    }while(!done);

    if(opts->state != CONFIG_PARSE_BEGIN)
    {
        file_error("config file malformed!", opts);
    }

    opts->state = CONFIG_PARSE_END;
    return;
}
