/**
 * Simple Fuzz
 * Copyright (c) 2009,2011 Aaron Conole <apconole@yahoo.com>
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

#define SFUZZ_UTIL_COMPILE 1

/**
 * \brief Display the sfuzz search paths (for debug only)
 */
void dump_paths();

#include "sfuzz.h"
#include "sfuzz-plugin.h"
#include "sfuzz-plugin-internal.h"
#include "options-block.h"
#include "os-abs.h"

#define min(a,b)                                \
    ({ __typeof__ (a) _a = (a);                 \
        __typeof__ (b) _b = (b);                \
        _a < _b ? _a : _b; })

void read_config(option_block *opts);

static char **searchPath;
static int    searchPathCount;

void sfuzz_setsearchpath(const char *path)
{
    const char *cp, *tp;
    int pathLen, ii;
    char **pathStr;

    if(!path || !*path)
    {
        if(searchPath)free(searchPath);
        searchPath = 0;
        searchPathCount = 0;
        return;
    }

    for (cp = path, pathLen = 0; *cp; ++cp) {
        if(':' == *cp) ++pathLen;
    }

    ++pathLen;

    if(searchPath){
        free(searchPath);
        searchPath = 0;
        searchPathCount = 0;
    }

    searchPath = (char **)(calloc(pathLen, sizeof(char *)));

    for(cp = path, pathStr = searchPath, ii = 0, tp = strchr(path, ':');
        (NULL != tp) && (ii < pathLen); ++ii)
    {
        if(tp == cp) {
            *pathStr = strdup(".");
        }
        else {
            const char *sp;
            char *dp;
            *pathStr = (char *)malloc(tp-cp+1);
            if(*pathStr == NULL)
            {
                free(searchPath);
                searchPath = 0;
                searchPathCount = 0;
                return;
            }
            for(dp = *pathStr, sp = cp; sp < tp; *dp++ = *sp++);
            *dp = 0;
        }

        ++pathStr;
        cp = tp+1;
        tp = strchr(cp, ':');
    }

    if(*cp) 
    {
        *pathStr = strdup(cp);
    } else {
        *pathStr = strdup(".");
    }

    searchPathCount = pathLen;
}

void sfuzz_searchpath_prepend(const char *pathname)
{
    int searchPathStrLength = 0;
    char *searchPathStr = NULL;
    int i;

    if(!pathname || !*pathname) /* do nothing on null */
        return;

    searchPathStrLength = strlen(pathname)+1;

    for(i = 0; i < searchPathCount; ++i)
    {
        searchPathStrLength += strlen(searchPath[i]) + 1;
    }

    searchPathStr = malloc(searchPathStrLength+1);

    if(searchPathStr == NULL)
        return;

    strcpy(searchPathStr, pathname);

    for(i = 0; i < searchPathCount; ++i)
    {
        strcat(searchPathStr, ":");
        strcat(searchPathStr, searchPath[i]);
    }

    sfuzz_setsearchpath(searchPathStr);

    free(searchPathStr);
}

FILE *sfuzz_fopen(const char *filename, const char *perms)
{
    FILE *fp;
    const char *fileStr;
    char **pathStr;
    int ii;
    char *cp;
    char nameBuff[4096];

    if(strlen(filename) >= sizeof(nameBuff))
    {
        return NULL;
    }

    strcpy(nameBuff, filename);
    
    for(cp = nameBuff; *cp; ++cp)
    {
        if('\\' == *cp) *cp = '/';
    }

    fp = fopen(nameBuff, perms);
    if(fp != NULL)
    {
        if(strchr(nameBuff, '/'))
        {
            char bigpath[4096] = {0};
            memcpy(bigpath, nameBuff, strrchr(nameBuff, '/') - nameBuff);
            sfuzz_searchpath_prepend(nameBuff);
        }
        return fp;
    }

    for(pathStr = searchPath, ii=0; ii < searchPathCount; ++ii, ++pathStr)
    {
        for(fileStr = filename; fileStr && *fileStr; 
            fileStr = strpbrk(fileStr+1, "/\\")) 
        {
            if((strlen(*pathStr) >= 4096) ||
               (strlen(*pathStr) + strlen(fileStr) + 2 >= 4096))
            {
                return NULL;
            }
            memset(nameBuff, 0, sizeof(nameBuff));
            strcpy(nameBuff, *pathStr);
            if(*(nameBuff + strlen(nameBuff) - 1) != '/')
            {
                *(nameBuff + strlen(nameBuff)) = '/';
                *(nameBuff + strlen(nameBuff)+1) = '\0';
            }

            strcat(nameBuff, fileStr);
            for(cp = nameBuff; *cp; ++cp)
            {
                if('\\' == *cp) *cp = '/';
            }
            fp = fopen(nameBuff, perms);
            if(fp != NULL) return fp;
        }
    }

    return NULL;
}

FILE *sfuzz_dlopen(const char *filename, int flag)
{
    const char *fileStr;
    char nameBuff[4096];
    char **pathStr;
    void *fp;
    char *cp;
    int ii;

    if (strlen(filename) >= sizeof(nameBuff)) {
        return NULL;
    }

    strcpy(nameBuff, filename);

    for (cp = nameBuff; *cp; ++cp) {
        if('\\' == *cp) *cp = '/';
    }

    fp = dlopen(nameBuff, flag);
    if(fp != NULL) {
        return fp;
    }

    for (pathStr = searchPath, ii=0; ii < searchPathCount; ++ii, ++pathStr) {
        for (fileStr = filename; fileStr && *fileStr; 
             fileStr = strpbrk(fileStr+1, "/\\")) {

            if ((strlen(*pathStr) >= 4096) ||
                (strlen(*pathStr) + strlen(fileStr) + 2 >= 4096)) {
                return NULL;
            }

            memset(nameBuff, 0, sizeof(nameBuff));
            strcpy(nameBuff, *pathStr);
            if (*(nameBuff + strlen(nameBuff) - 1) != '/') {
                *(nameBuff + strlen(nameBuff)) = '/';
                *(nameBuff + strlen(nameBuff)+1) = '\0';
            }

            strcat(nameBuff, fileStr);
            for (cp = nameBuff; *cp; ++cp) {
                if ('\\' == *cp) *cp = '/';
            }
            fp = dlopen(nameBuff, flag);
            if (fp != NULL) {
                return fp;
            } else {
                char *p = strdup(dlerror());
                if (p && strstr(p, "undefined ")) {
                    fprintf(stderr, "Loading: [%s]: %s\n", nameBuff, p);
                    fprintf(stderr, "The plugin you're attempting to load has some undefined symbols\n");
                    fprintf(stderr, "Likely, you'll need to reconfigure sfuzz with the --force-symbols option\n");
                }
            }
        }
    }

    return NULL;
}

void dump_paths() {
    int ii;
    char **pathStr;

    for(pathStr = searchPath, ii=0; ii < searchPathCount; ++ii, ++pathStr)
    {
        fprintf(stderr, "Path [%d]: [%s]\n", ii, *pathStr);
    }
    
}

#ifndef NOPLUGIN

typedef void (*plugin_init)(plugin_provisor *);

void plugin_sanity(option_block *opts)
{
    if (g_plugin == NULL)
        return;

    if (g_plugin->capex == NULL) {
        file_error("plugin doesn't provide a capex.", opts);
        free(g_plugin);
        g_plugin = NULL;
        return;        
    }

    if (((g_plugin->capex() & PLUGIN_PROVIDES_LINE_OPTS) ==
         PLUGIN_PROVIDES_LINE_OPTS) && (g_plugin->config == NULL)) {
        file_error("plugin claims to provide config parsing but doesn't implement it!",
                   opts);
        free(g_plugin);
        g_plugin = NULL;
        return;
    }

    if (((g_plugin->capex() & PLUGIN_PROVIDES_PAYLOAD_PARSE) ==
         PLUGIN_PROVIDES_PAYLOAD_PARSE) && (g_plugin->payload_trans == NULL)) {
        file_error("plugin claims to provide payload parsing but doesn't implement it!",
                   opts);
        free(g_plugin);
        g_plugin = NULL;
        return;
    }

    if (((g_plugin->capex() & PLUGIN_PROVIDES_TRANSPORT_TYPE) ==
         PLUGIN_PROVIDES_TRANSPORT_TYPE) && (g_plugin->trans == NULL)) {
        file_error("plugin claims to provide transportation but doesn't implement it!",
                   opts);
        free(g_plugin);
        g_plugin = NULL;
        return;
    }

    if (((g_plugin->capex() & PLUGIN_PROVIDES_FUZZ_MODIFICATION) ==
        PLUGIN_PROVIDES_FUZZ_MODIFICATION) && (g_plugin->fuzz_trans == NULL)) {
        file_error("plugin claims to provide fuzz transform but doesn't implement it!",
                   opts);
        free(g_plugin);
        g_plugin = NULL;
        return;
    }

    if (((g_plugin->capex() & PLUGIN_PROVIDES_POST_FUZZ) ==
         PLUGIN_PROVIDES_POST_FUZZ) && (g_plugin->post_fuzz == NULL)) {
        file_error("plugin claims to provide postfuzz but doesn't implement it!",
                   opts);
        free(g_plugin);
        g_plugin = NULL;
        return;
    }
}

void plugin_load(char *filename, option_block *opts)
{
    int  length         = strcspn(filename+1, " \n\r");
    char fileline[8192] = {0};
    void *local_plugin_handle;
    plugin_init ir;

    if (length > 8191) {
        file_error("filename for plugin is too large!", opts);
        return;
    }

    strncpy(fileline, filename+1, length);

    local_plugin_handle = sfuzz_dlopen(fileline, RTLD_NOW);
    if (local_plugin_handle == NULL) {
        file_error("Unable to open plugin (check the search path?).", opts);
        return;
    }

    ir = (plugin_init)dlsym(local_plugin_handle, "plugin_init");
    if (ir == NULL) {
        fprintf(stderr, "--- plugin loading: [%s][%s] ---\n", fileline,
                dlerror());
        file_error("unable to locate entrypoint in plugin", opts);
        return;
    }

    if (g_plugin != NULL) {
        file_error("limit 1 plugin per script!", opts);
        return;
    }

    g_plugin = (plugin_provisor*)malloc(sizeof(plugin_provisor));

    if (g_plugin == NULL) {
        file_error("unable to allocate plugin descriptor", opts);
        return;
    }

    memset(g_plugin, 0, sizeof(plugin_provisor));

    ir(g_plugin);

    if (g_plugin->name == NULL || g_plugin->version == NULL) {
        file_error("plugin is invalid!", opts);
        return;
    }

    plugin_sanity(opts);
}
#endif

extern unsigned int ascii_to_bin(unsigned char *str_bin);

void add_str_array(char *sym_name, int sym_len, char *sym_val, int sym_val_len,
                   option_block *opts, int i)
{
    int l = 0;
    array_t *pArray = NULL;
    char *tm;
    int isbin = i;
    sym_name[sym_len] = 0;
    sym_val[sym_val_len] = 0;

    l = strrchr(sym_name, '[') - sym_name;
    if(strrchr(sym_name, ']') - sym_name < l)
    {
        file_error("array subscript delimiter not found", opts);
    }

    for(i = 0; i < opts->num_arrays; ++i)
    {
        pArray = opts->arrays[i];
        if(!strncmp(pArray->array_name, sym_name, l))
        {
            break;
        }
    }

    if(i == opts->num_arrays ||  (i < opts->num_arrays && 
                                  strncmp(pArray->array_name, sym_name,l)))
    {
        pArray = (array_t *)malloc(sizeof (array_t));
        if(!pArray)
        {
            file_error("OOM Adding new array element", opts);
        }
        printf("creating new array [%s]\n", sym_name);
        memset(pArray->array_name, 0, 8192);
        strncpy(pArray->array_name, sym_name, l <= 8192 ? l : 8192);
        pArray->array_name[8191] = 0;

        pArray->value_array = NULL;
        pArray->value_length = pArray->value_ctr =
            pArray->array_max_val = 0;
        
        opts->arrays = realloc(opts->arrays, (1 + i) * sizeof(array_t));
        if(!opts->arrays) file_error("OOM Adding new array element", opts);
        ++opts->num_arrays;
        opts->arrays[i] = pArray;
    }
    
    tm = sym_name+l+1;
    *(sym_name+l) = 0;
    
    i = atoi(tm); /* atoi will stop when it gets to a non-number character */
    //i += 1; /* 0 = 1, 1 = 2, etc. */
    if(i >= pArray->array_max_val)
    {
        pArray->array_max_val = i+1;
        pArray->value_array = realloc(pArray->value_array, 
                                      (1+i)*sizeof(sym_t));
        if(!pArray->value_array)
            file_error("OOM Adding array symbol element", opts);
        pArray->value_length ++;
    }

    if (!pArray->value_array)
        file_error("OOM allocating value array", opts);

    memset(pArray->value_array[i].sym_val, 0, 8192);
    
    if(isbin)
        memcpy(pArray->value_array[i].sym_val,  sym_val,  sym_val_len);
    else
        strncpy(pArray->value_array[i].sym_val, sym_val, 
                sym_val_len < 8192 ? sym_val_len : 8191);
    
    pArray->value_array[i].bin = isbin;
    pArray->value_array[i].is_len = sym_val_len;
}

void add_symbol(char *sym_name, int sym_len, char *sym_val, int sym_val_len,
                option_block *opts, int i)
{
    sym_t *pSym; char *tmp;
    char buf[8192]= {0};
    char buf2[8192] = {0};
    unsigned int tmpl;

    if((sym_len >= 8192) ||
       (sym_val_len >= 8192))
    {
        file_error("too large symbol!", opts);
    }

    tmp = memmem(sym_name, sym_len, "[", 1);
    if(tmp)
    {
        tmpl = tmp - sym_name;
        if(! memmem(sym_name+tmpl, sym_len - tmpl, "]", 1))
        {
            file_error("array subscript not terminated!", opts);
            /* exit after this point ... */
        }
        add_str_array(sym_name, sym_len, sym_val, sym_val_len, opts, 0);
        return;
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
    pSym->is_len = 0;
    if(i == 1)
        pSym->is_len = 1;
}

void add_b_symbol(char *sym_name, int sym_len, char *sym_val, int sym_val_len,
                  option_block *opts)
{
    sym_t *pSym; char *tmp;

    if((sym_len >= 8192) ||
       (sym_val_len >= 8192))
    {
        file_error("too large symbol!", opts);
    }

    if((tmp = memmem(sym_name, sym_len, "[", 1)))
    {
        if(!memmem(sym_name+(tmp - sym_name), sym_len - (tmp-sym_name),
                   "]", 1))
        {
            file_error("array subscript not terminated!", opts);
            /* exit after this point ... */
        }
        add_str_array(sym_name, sym_len, sym_val, sym_val_len, opts, 1);
        return;
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
        if(size)
            *(line+(size - 1)) = c;
        if((c == '\n') || ((c == '\r') && (!ign_cr)))
            break;
    }
    if(size)
        line[size-1] = 0;

    return size;
}

void add_subst_symbol(char *sym_name, int sym_len, char *sym_val, 
                      int sym_val_len, option_block *opts, int i)
{
    sym_t *pSym;
    size_t start_len = strspn(sym_val, " \t");
    if((*(sym_val+start_len) != '[') ||
       (*(sym_val+sym_val_len-1) != ']'))
    {
        file_error("substitution variable syntax error", opts);
    }

    ++start_len; *(sym_val+sym_val_len-1) = '\0';

    if(*(sym_val+start_len) == '/')
    {
        file_error("BETA version does not support this feature", opts);
    }
    else
    {
        char *string_tok;
        int subst_offset  = -1;
        int subst_length  = -1;
        char * subst_def = sym_val;

        /*should be in the format of offset:length:default value*/
        string_tok = strtok((sym_val+start_len), ":");
        subst_def += strlen(string_tok) + 1;
        subst_offset = strtol(string_tok, NULL, 10);
        if((errno) || (subst_offset < 0))
        {
            file_error("parse error during substitution - invalid number",
                       opts);
        }

        /*should be in the format of offset:length:default value*/
        string_tok = strtok(NULL, ":");
        subst_def += strlen(string_tok) + 1;
        subst_length = strtol(string_tok, NULL, 10);
        if((errno) || (subst_length <= 0))
        {
            file_error("parse error during substitution - invalid number",
                       opts);
        }

        ++subst_def;

        /*at this point, offset, length, and def are specified.
          build the symbol entry*/

        opts->s_syms = realloc(opts->s_syms, 
                               (opts->s_syms_count+1) * sizeof(sym_t));
        if(opts->s_syms == NULL)
        {
            file_error("OOM adding substitution symbol", opts);
        }

        opts->s_syms_count++;

        pSym = &(opts->s_syms[opts->s_syms_count - 1]);

        memset(pSym->sym_name, 0, 8192);
        memset(pSym->sym_val, 0, 8192);
        memcpy(pSym->sym_name, sym_name, sym_len);
        memcpy(pSym->sym_val, subst_def, min(strlen(subst_def), 8192));

        pSym->is_len = subst_length;
        pSym->offset = subst_offset;
        pSym->s_len =  min(strlen(subst_def), 8192);

        /*added "substitution" symbol*/
        
        return;
    }
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

    if (!strncasecmp("plugin", line, 6)) {
#ifndef NOPLUGIN
        delim = strstr(line, " ");
        if (delim == NULL) {
            file_error("plugin line with no file specified. abort!", opts);
        }
        plugin_load(delim, opts);
        return 0;
#else
        file_error("plugin line: sfuzz without plugin support", opts);
#endif
    }

    if (!strncasecmp("literal", line, 7)) {
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

    if(!strncasecmp("reppol", line, 6))
    {
        delim = strstr(line, "=");
        if(delim == NULL)
            file_error("replacement policy not specified.", opts);
        f = delim+1;
        if(!strncasecmp(f, "always", 6))
        {
            opts->repl_pol = 1;
        }
        else if(!strncasecmp(f, "once", 5))
        {
            opts->repl_pol = 2; 
        }
        else
            file_error("replacement policy not recognized.", opts);

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
        state = strlen(line) - sze;
        if(sze)
        {
            if((line[state] == '\\') || 
               (line[state] == '0'))
            {
                if(line[state] == 'x')
                    sze = ascii_to_bin((unsigned char *)(line+state));
            }
            memcpy(opts->line_term, line+state, sze);
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
        f = malloc(strlen(opts->pFilename)+1);
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
        sze = ascii_to_bin((unsigned char *)(delim+1));
        if(sze < 0)
        {
            file_error("binary text is invalid!", opts);
        }
        add_b_symbol(line+1, (delim - (line+1)), delim+1, sze, opts);
        return 0;
    } else if (line[0] == '|')
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
        add_subst_symbol(line+1, (delim - (line+1)), delim+1, sze, opts, 0);
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
    char path[1024] = {0};
    char *tmp;

    if(opts->state != INIT_READ)
        file_error("invalid state for config reading.", opts);

    if((tmp = strrchr(opts->pFilename, '/')) ||
       (tmp = strrchr(opts->pFilename, '\\')))
    {
        if((tmp - opts->pFilename) > sizeof(path)-1)
            file_error("file path too long.", opts);
        memcpy(path, opts->pFilename, (tmp - opts->pFilename));
        sfuzz_searchpath_prepend(path);
    }
    
    f = sfuzz_fopen(opts->pFilename, "r");
    
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
