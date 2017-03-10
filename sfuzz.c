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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "sfuzz.h"
#include "os-abs.h"
#include "version.h"
#include "options-block.h"
#include "sfuzz-plugin.h"
#include "sfuzz-plugin-internal.h"


#ifdef __WIN32__
#include "windows.h"
#include <sys/time.h>
#else
#include <sys/time.h>
#include <string.h>
#endif

#include "sfo_interface.h"

plugin_provisor *g_plugin;

extern int readLine(option_block *opts, char *line, int len, int ign_cr);
extern void read_config(option_block *opts);
int execute_fuzz(option_block *opts);
extern unsigned int ascii_to_bin(unsigned char *str_bin);
void dump_options(option_block *opts)
{
    int i;
    
    if(opts != NULL)
    {
        printf("[%s] dumping options:\n\tfilename: <%s>\n\tstate:    <%d>\n\tlineno:   <%d>\n\tliterals:  [%d]\n\tsequences: [%d]\n\tsymbols: [%d]\n\treq_del:  <%d>\n\tmseq_len: <%d>\n\tplugin: <%s>\n\ts_syms: <%d>\n",
               get_time_as_log(), opts->pFilename, opts->state, opts->lno, opts->num_litr, opts->num_seq, opts->sym_count / 2, opts->reqw_inms, opts->mseql,
               g_plugin ? g_plugin->name() : "none", opts->s_syms_count);
        
        for(i = 0; i < opts->num_litr; i++)
            printf("\tliteral[%d] = [%s]\n", i+1, opts->litr[i]);
        for(i = 0; i < opts->num_seq; i++)
            printf("\tsequence[%d] = [%s]\n", i+1, opts->seq[i]);
        for(i = 0; i < opts->sym_count; ++i)
        {
            if(!(opts->syms_array[i].is_len))
                printf("\tsym [%s]->[%s]\n", opts->syms_array[i].sym_name,
                       opts->syms_array[i].sym_val);
        }

        for(i = 0; i < opts->s_syms_count; ++i)
        {
            printf("\t|sym| [%s] -> %d[%d:%s]\n", 
                   opts->s_syms[i].sym_name, opts->s_syms[i].is_len,
                   opts->s_syms[i].offset, opts->s_syms[i].sym_val);
        }
    }
}

time_t birth;

void print_version()
{
    printf("version: %s\n", VERSION);
}

void print_help()
{
    printf("\t\tSimple Fuzzer\nBy:\t Aaron Conole\n");
    print_version();
    printf("url:\t http://aaron.bytheb.org/programs/sfuzz.html\n");
    printf("EMAIL:\t apconole@yahoo.com\n");
#ifndef __WIN32__
    printf("Build-prefix: %s", PREFIX);
#endif
    printf("\n");
    printf("\t-h\t This message.\n");
    printf("\t-V\t Version information.\n");
    printf("\n");
    printf("networking / output:\n");
    printf("\t-v\t Verbose output\n");
    printf("\t-q\t Silent output mode (generally for CLI fuzzing)\n");
    printf("\t-X\t prints the output in hex\n");
    printf("\n");
    printf("\t-b\t Begin fuzzing at the test specified.\n");
    printf("\t-e\t End testing on failure.\n");
    printf("\t-t\t Wait time for reading the socket\n");
    printf("\t-S\t Remote host\n");
    printf("\t-p\t Port\n");
    printf("\t-T|-U|-O TCP|UDP|Output mode\n");
    printf("\t-d|-u unix_dgram|unix_stream (unix-alike only)\n");
    printf("\t-R\t Refrain from closing connections (ie: \"leak\" them)\n");
    printf("\n");
    printf("\t-f\t Config File\n");
    printf("\t-L\t Log file\n");
    printf("\t-n\t Create a new logfile after each fuzz\n");
    printf("\t-r\t Trim the tailing newline\n");
    printf("\t-D\t Define a symbol and value (X=y).\n");
    printf("\t-l\t Only perform literal fuzzing\n");
    printf("\t-s\t Only perform sequence fuzzing\n");
}

/**
 * \brief Sanity checks the option block to ensure that the state and 
 * configuration are in agreement
 *
 * It could be possible due to bugs / misconfiguration / my idiocy for the
 * internal states to become corrupted. The idea behind this function is to
 * do basic sanity checking to ensure that we are in a minimally good state
 * to function.
 */
void sanity(option_block *opts)
{
    if (opts == NULL) {
        fprintf(stderr, "[%s] fatal: option block null\n", get_time_as_log());
        exit(-1);
    }

    if (!(opts->fuzz_flag)) {
        fprintf(stderr, "[%s] error: must specify a fuzzy output type.\n",
                get_time_as_log());
        print_help();
        exit(-1);
    }

    if (opts->pFilename[0] == 0) {
        fprintf(stderr, "[%s] error: must specify a config file.\n",
                get_time_as_log());
        print_help();
        exit(-1);
    }

    if ((is_netmode(opts)) && 
        ((opts->host == 0) || ((opts->port == 0) || (opts->port < 1) ||
                               (opts->port > 65535)))) {
        fprintf(stderr, 
                "[%s] error: must specify host and port when using netmode.\n",
                get_time_as_log());
        print_help();
        exit(-1);
    }
}


extern void add_symbol(char *sym_name, int sym_len, char *sym_val, 
                       int sym_val_len, option_block *opts, int i);

/**
 * \brief Processes an option from the commandline.
 */
void process_opt_str(char *line, char *lastarg, option_block *opts)
{
    char *delim;
    int   sze;
    int end=0;

    while (*line != 0) {
/*
used:
beslnqrtpvfh
XRSTUOLVD
 */
        switch (*line++) {
        case 'b':
            if (lastarg == NULL) {
                fprintf(stderr, "error: must specify a starting test.\n");
                exit(-1);
            }
            opts->start_test = atoi(lastarg);
            break;
        case 'e':
            opts->stop_on_fail = 1;
            break;
        case 's':
            opts->no_sequence_fuzz = 0;
            opts->no_literal_fuzz = 1;
            break;
        case 'l':
            opts->no_literal_fuzz = 0;
            opts->no_sequence_fuzz = 1;
            break;
        case 'n':
            opts->new_logfile = 1;
            break;
        case 'q':
            opts->verbosity = QUIET;
            break;
        case 'X':
            opts->hexl_dump = 1;
            break;
        case 'r':
            opts->trim_nl = 1;
            break;
        case 'R':
            opts->forget_conn = 1;
            break;
        case 'S':
            if (lastarg == NULL) {
                fprintf(stderr, "error: must specify a remote host.\n");
                exit(-1);
            }
            opts->host     = atoip(lastarg);
            strncpy(opts->host_spec, lastarg, MAX_HOSTSPEC_SIZE);
            opts->host_spec[MAX_HOSTSPEC_SIZE-1] = 0;
            break;
        case 't':
            if (lastarg == NULL) {
                fprintf(stderr, "error: must specify a wait time.\n");
                exit(-1);
            }
            opts->time_out = atoi(lastarg);
            break;
        case 'p':
            if (lastarg == NULL) {
                fprintf(stderr, "error: must specify a port.\n");
                exit(-1);
            }
            opts->port    = atoi(lastarg);
            strncpy(opts->port_spec, lastarg, MAX_PORTSPEC_SIZE);
            opts->port_spec[MAX_PORTSPEC_SIZE-1] = 0;
            break;
        case 'T':
            set_tcp(opts);
            break;
        case 'U':
            set_udp(opts);
            break;
        case 'O':
            set_output(opts);
            break;
        case 'u':
            set_unix_stream(opts);
            break;
        case 'd':
            set_unix_dgram(opts);
            break;
        case 'L':
            if (lastarg == NULL) {
                fprintf(stderr, "error: must specify a log file.\n");
                exit(-1);
            }
            strncpy(opts->pLogFilename, lastarg, MAX_FILENAME_SIZE-1);
            opts->pLogFilename[MAX_FILENAME_SIZE-1] = 0;            
            break;
        case 'v': /*when I put in better logging.*/
            opts->verbosity = VERBOSE;
            break;
        case 'f':
            if (lastarg == NULL) {
                fprintf(stderr, "error: must specify a config file.\n");
                exit(-1);
            }
            strncpy(opts->pFilename, lastarg, MAX_FILENAME_SIZE-1);
            opts->pFilename[MAX_FILENAME_SIZE-1] = 0;
            break;
        case 'h':
            print_help(); exit(0);
            break;
        case 'V':
            print_version(); exit(0);
            break;
        case 'D':
            if ((*line != '\0') && (lastarg == NULL)) {
                lastarg = line;
                end = 1;
            }

            if (lastarg == NULL) {
                fprintf(stderr, "error: define requires an argument.\n");
                exit(-1);
            }

            delim = strstr(lastarg, "=");
            if (delim == NULL) {
                fprintf(stderr, "error: delimiter not found for symbol.\n");
                exit(-1);
            }

            sze = strlen(delim+1);
            if (sze == 0) {
                fprintf(stderr, "error: symbol's value is null.\n");
                exit(-1);
            }

            add_symbol(lastarg, (delim - lastarg), delim+1, sze, opts, 0);
            if (end)
                return;
            break;
        default:
            printf("unknown option: %c\n", *line); exit(0);
        }
    }
}

/**
 * \brief Processes all options on the command line.
 */
void process_opts(int argc, char *argv[], option_block *opts)
{
    char *lastarg = 0;

    if (opts->state != CMD_LINE_OPTS) {
        fprintf(stderr,
                "[%s] fatal: attempt to invoke process_opts in improper state.!\n",
                get_time_as_log());
        exit(-1);
    }

    if (argc > 1) {
        --argc;
        while (argc > 0) {
            switch (argv[argc][0]) {
            case '-':
                process_opt_str((argv[argc])+1, lastarg, opts);
                break;
            default:
                lastarg = argv[argc];
                break;
            }
            argc--;
        }
    }
    sanity(opts);
}
extern void sfuzz_setsearchpath(const char *path);

/**
 * \brief main... duh.
 */
int main(int argc, char *argv[])
{
    FILE *log = stdout;
    struct timeval tv;
    option_block options;
    int i;

    g_plugin = NULL;
    sfuzz_setsearchpath(
#ifndef __WIN32__
        "./:"PREFIX"/share/sfuzz-db"
# ifdef AUXSEARCHPATH
        AUXSEARCHPATH
# endif
#else
        "./"
#endif
        );
    memset(&options, 0, sizeof(options));

    gettimeofday(&tv, NULL);
    birth = tv.tv_sec;

    options.pFilename = malloc(MAX_FILENAME_SIZE);
    options.pLogFilename = malloc(MAX_FILENAME_SIZE);
    options.host_spec = malloc(MAX_HOSTSPEC_SIZE);
    options.port_spec = malloc(MAX_PORTSPEC_SIZE);
    options.repl_pol = 2; /* once ! for always, choose 1. */
    memset(options.pFilename, 0, MAX_FILENAME_SIZE-1);
    memset(options.pLogFilename, 0, MAX_FILENAME_SIZE-1);
    memset(options.host_spec, 0, MAX_HOSTSPEC_SIZE - 1);
    memset(options.port_spec, 0, MAX_PORTSPEC_SIZE - 1);

    /*default line terminator*/
    options.line_term[0]         = '\n';
    options.line_terminator_size = 1;

    options.state     = CMD_LINE_OPTS;
    process_opts(argc, argv, &options);
    
    options.state     = INIT_READ;
    read_config(&options);

    options.link_oracle = -1;

    if(options.pLogFilename[0] != 0)
    {
        if(options.new_logfile)
        {
            strncat(options.pLogFilename, ".0", MAX_FILENAME_SIZE);
        }

        log = fopen(options.pLogFilename, "w");
        if (log != NULL) {
            options.fp_log = log;
        } else {
            fprintf(stderr,
                    "[%s] error: using stdout - unable to open log.\n",
                    get_time_as_log());
            log = stdout;
        }
    }

    if(options.verbosity == VERBOSE)
        dump_options(&options);
    
    if (options.verbosity != QUIET) {
        fprintf(log, "[%s] info: beginning fuzz - method:", get_time_as_log());
        if (is_tcp(&options)) {
            fprintf(log, " tcp,");
        } else if (is_udp(&options)) {
            fprintf(log, " udp,");
        } else {
            fprintf(log, " io,");
        }

        fprintf(log, " config from: [%s], out: [%s:%d]\n",
                options.pFilename, options.host_spec, options.port);
    }

    options.state     = FUZZ;
    execute_fuzz(&options);

    if (options.verbosity != QUIET)
        fprintf(log, "[%s] completed fuzzing.\n", get_time_as_log());
    
    free(options.pFilename);
    free(options.pLogFilename);
    free(options.host_spec);

    for (i = 0; i < options.num_litr; ++i) {
        free(options.litr[i]);
    }
    free(options.litr);
    free(options.litr_lens);

    for (i = 0; i < options.num_seq; ++i) {
        free(options.seq[i]);
    }

    free(options.seq);
    free(options.seq_lens);

    /*this might be the better way of doing things =)*/
    if(options.sym_count)
        free(options.syms_array);

    return 0;
}

int fuzznum = 0;

/**
 * \brief Perform an actual fuzz. Take care of replacing the fixed symbols here
 * (the arrays are processed elsewhere).
 *
 * This function invokes plugin routines if they are present. Also, it does
 * lots of crazy magic w.r.t. string replacement. All fixed-definition symbols
 * are replaced here - meaning you cannot use a fixed symbol which will be
 * defined by fuzz (however, if you want the text "FUZZ" to appear, you can
 * do that here)
 */
int fuzz(option_block *opts, char *req, int len)
{
    int i = 0;
    int res = 0;
    FILE *log = stdout;
    char *r2, *tmp = 0;
    char *p1, *tmp2 = 0;
    int r2_len,p1_len;
    sym_t *pSym;

    int fuzz_this_time = (opts->start_test <= ++fuzznum) ? 1 : 0;

    if (opts->fp_log)
        log = opts->fp_log;

    if (fuzz_this_time && opts->verbosity != QUIET)
        fprintf(log,
                "[%s] attempting fuzz - %d (len: %d).\n", get_time_as_log(),
                fuzznum, len);
#ifndef NOPLUGIN
    if(fuzz_this_time && g_plugin != NULL && 
       ((g_plugin->capex() & PLUGIN_PROVIDES_PAYLOAD_PARSE) ==
        PLUGIN_PROVIDES_PAYLOAD_PARSE)) {
        tmp2 = req;
        p1_len = len * 2;
        p1 = malloc(p1_len);
        g_plugin->payload_trans(opts, req, len, p1, &p1_len);
        req = p1;
        len = p1_len;
    }
#endif
    if (fuzz_this_time && ((opts->sym_count) || (opts->s_syms_count))) {
        /*xxx : enhancement - loop backwards allowing people to define
                a string (aaa for example) and use that string within
                other defines appearing later.
                THIS creates a problem - our length field substitution
                depends on having lengths before non-lengths. The answer
                of course, is to just have 2 loops, apply the lenghts first*/
        for (i = 0; i < opts->s_syms_count ; ++i) {
            pSym = &(opts->s_syms[ opts->s_syms_count - (i+1) ]);
            len = smemrepl(req, len, len, pSym->sym_name, pSym->sym_val,
                           pSym->s_len);
        }

        for (i = 0; i < opts->sym_count; ++i) {
            pSym = &(opts->syms_array[ opts->sym_count - (i+1) ]);
            if(pSym->is_len)
                len = smemrepl(req, len, len, pSym->sym_name, pSym->sym_val,
                               strlen(pSym->sym_val));
        }

        for (i = 0; i < opts->sym_count; ++i) {
            pSym = &(opts->syms_array[ opts->sym_count - (i+1) ]);
            if(!pSym->is_len)
                len = smemrepl(req, len, len, pSym->sym_name, pSym->sym_val,
                               strlen(pSym->sym_val));
        }

    }

    /* we let this one through in skip cases because we need the
       increments to happen. */
    if (opts->b_sym_count) {
        for (i = 0; i < opts->b_sym_count; ++i) {
            pSym = &(opts->b_syms_array[i]);
            len = smemrepl(req, len, len, pSym->sym_name, pSym->sym_val,
                           pSym->is_len);
            if (pSym->increment) {
                int *increm = (int*)pSym->sym_val;
                *increm = (*increm)+1;
            }
        }
    }

    if (fuzz_this_time && is_output(opts)) {
        if (opts->hexl_dump) {
            dump(req, len, log);
        } else {
            fwrite(req, len - 1, 1, log);
            fwrite("\n", 1, 1, log);
        }
    }

    if (fuzz_this_time && opts->link_oracle != -1) {
        oracle_pre_fuzz(opts, req, len);
    }

#ifndef NOPLUGIN
    if(fuzz_this_time && g_plugin != NULL && 
       ((g_plugin->capex() & PLUGIN_PROVIDES_FUZZ_MODIFICATION) ==
        PLUGIN_PROVIDES_FUZZ_MODIFICATION)) {
        r2 = malloc(len * 2);
        r2_len = len * 2;
        g_plugin->fuzz_trans(opts, req, len, r2, &r2_len);
        tmp = req;
        req = r2;
        len = r2_len;
    }

    /* NOTE: the critical *else* after this to make the following block
       behave correctly. */
    if(fuzz_this_time && g_plugin != NULL && 
       ((g_plugin->capex() & PLUGIN_PROVIDES_TRANSPORT_TYPE) == 
        PLUGIN_PROVIDES_TRANSPORT_TYPE)) {
      res = g_plugin->trans(opts, req, len);
    } else
#endif

    if (fuzz_this_time && is_tcp(opts)) {
      res = os_send_tcp(opts, req, len);
    } else if (fuzz_this_time && is_udp(opts)) {
      res = os_send_udp(opts, req, len);
    } else if(fuzz_this_time && is_unix(opts)) {
        res = -1; // no unix support, at this time
    }

    if (fuzz_this_time && opts->link_oracle != -1) {
        oracle_post_fuzz(opts, req, len);
    }

#ifndef NOPLUGIN

    if (fuzz_this_time && (g_plugin != NULL) &&
        ((g_plugin->capex() & PLUGIN_PROVIDES_POST_FUZZ) ==
         PLUGIN_PROVIDES_POST_FUZZ)) {
        g_plugin->post_fuzz(opts, req, len);
    }
    
    if (fuzz_this_time && g_plugin != NULL && 
        ((g_plugin->capex() & PLUGIN_PROVIDES_FUZZ_MODIFICATION) ==
         PLUGIN_PROVIDES_FUZZ_MODIFICATION)) {
        free(req);
        req = tmp;
    }

    if (fuzz_this_time && g_plugin != NULL && 
        ((g_plugin->capex() & PLUGIN_PROVIDES_PAYLOAD_PARSE) ==
         PLUGIN_PROVIDES_PAYLOAD_PARSE)) {
        free(req);
        req = tmp2;
    }
#endif

    if (fuzz_this_time && (opts->new_logfile) && (opts->pLogFilename)) {
        char *z_set;
        char z_buf[80] = {0};
        fclose(opts->fp_log);
        z_set = strrchr(opts->pLogFilename, '.');
        if(z_set)
            *z_set = 0;
        snprintf(z_buf, 80, ".%d", fuzznum);
        strncat(opts->pLogFilename, z_buf, MAX_FILENAME_SIZE);
        opts->fp_log = fopen(opts->pLogFilename, "w");
    }

    if (res < 0 && opts->stop_on_fail)
      return -1;

    return 0;
}

int array_execute_fuzz(option_block *opts, array_t *cur_array, int idx);
int in_array_execute_fuzz(option_block *opts);

/**
 * \brief Sets up the fuzz for execution. Called from main.
 *
 * This function figures out the array iterations for the array_execute_fuzz
 * function.
 */
int execute_fuzz(option_block *opts)
{
    if (!opts->num_arrays) {
        return array_execute_fuzz(opts, NULL, 0);
    } else {
        return array_execute_fuzz(opts, opts->arrays[0], 0);
    }
}

/**
 * \brief Does an array iteration for array based fuzzing.
 * 
 * This function recursively executes with progressively increasing array
 * indexes. The idea is that it will loop through the test cases over and over
 * modifying the array fetch values. This allows the in_array_execute_fuzz to
 * do all the 'dynamic' replacement (ie: arrays, literals, and strings) and
 * lets "fuzz" do all the static replacement.
 */
int array_execute_fuzz(option_block *opts, array_t *cur_array, int idx)
{
    int i;
    long offset = ftell(opts->fp);
    if (offset < 0) {
        perror("ftell");
        exit(1);
    }

    if (!cur_array) {
        i = in_array_execute_fuzz(opts);
        if (fseek(opts->fp, offset, SEEK_SET) < 0) {
            perror("fseek");
            exit(1);
        }
        return i;
    }
    ++idx;

    cur_array->value_ctr = 0; /* reset after we're done */

    for (i = 0; i < cur_array->array_max_val; ++i) {
        cur_array->value_ctr = i;
        if(idx < opts->num_arrays)
            array_execute_fuzz(opts, opts->arrays[idx], idx);
        else
            array_execute_fuzz(opts, NULL, 0);
        if (fseek(opts->fp, offset, SEEK_SET) < 0) {
            perror("fseek");
            exit(-1);
        }
    }
    cur_array->value_ctr = 0; /* reset after we're done */
    return i;
}

/**
 * \brief Does all the dynamic string replacement, and calls 'fuzz'
 *
 * Constructs blocks of strings to send to the remote side. NOTE: a test case
 * here has a fixed size of ~16384 bytes - we need to fix that magic number.
 */
int in_array_execute_fuzz(option_block *opts)
{
    char *line = malloc(8192);
    char *req  = malloc(opts->mseql + 16384);
    char *req2 = malloc(opts->mseql + 16384);
    char *preq = malloc(opts->mseql + 16384);
    char *p;
    char c,f,b;

    int tsze    = 0;
    size_t reqsize = 0;
    int preqsize= 0;
    int i       = 0;
    int k       = 0;
    unsigned int seq4b = 0;

    memset(req, 0, opts->mseql + 16384);
    memset(req2, 0, opts->mseql + 16384);
    memset(preq, 0, opts->mseql + 16384);

    if (opts->state != FUZZ) {
        fprintf(stderr, "[%s] fatal: corrupted state for execute_fuzz()\n",
                get_time_as_log());
        exit(-1);
    }

    /*setup the socket fd*/
    opts->sockfd = -1;

    while (!feof(opts->fp)) {
        tsze    = 0;
        reqsize = 0;
        line[0] = 0;
        while (strcmp(line, "--") && strcmp(line, "c-")) {
            tsze = readLine(opts, line, 8192, 1);
            if (!strcmp(line, "--") || !strcmp(line, "c-") || tsze == 0) {
                break;
            }

            if (opts->mseql && ((tsze + reqsize) > opts->mseql + 8192)) {
                /*ohnoes overflow*/
                fprintf(stderr, "[%s] error: overflow[%d:%zu].\n", 
                        get_time_as_log(), opts->mseql, 
                        (tsze + reqsize));
                exit(-1);
            }

            memcpy(req+reqsize, line, tsze);
            reqsize += tsze-1;

            if (opts->line_terminator_size) {
                memcpy(req+reqsize, opts->line_term, 
                       opts->line_terminator_size);
            }

            reqsize += opts->line_terminator_size;

            *(req+reqsize) = 0;
        }

        if(feof(opts->fp))
            break;

        if(!strcasecmp(line, "c-"))
            opts->close_conn = 0;
        else
            opts->close_conn = 1;

        /* TODO: implement this feature in an intuitive and useful manner */
        opts->send_initial_nonfuzz_again = 0;

        if(opts->trim_nl)
            req[reqsize-1] = 0;

        if (opts->seqstep <= 0) {
            opts->seqstep = opts->mseql;
        }

        /* first, resolve all array types once */
        for (tsze = opts->num_arrays - 1; tsze >= 0; --tsze) {
            unsigned int ilen = reqsize;
            array_t *current_array = opts->arrays[tsze];
            char sizeval[80] = {0};
            char sizerepl[sizeof(current_array->array_name) + 2] = {0};
            char ssizerepl[sizeof(current_array->array_name) + 1] = {0};

            snprintf(sizerepl, sizeof(sizerepl), "%%%%%s",
                     current_array->array_name);
            snprintf(ssizerepl, sizeof(ssizerepl), "%%%s",
                     current_array->array_name);

            if (!current_array->value_array[current_array->value_ctr].bin) {
                size_t bsizeval = strlen(current_array->value_array
                                         [current_array->value_ctr].sym_val);

                snprintf(sizeval, 80, "%zu", bsizeval);
                ilen = smemrepl(req, reqsize, opts->mseql + 16384, sizerepl,
                                (char *) &bsizeval, sizeof bsizeval);
                ilen = smemrepl(req, ilen, opts->mseql + 16384, ssizerepl,
                                sizeval, strlen(sizeval));
                ilen = smemrepl(req, ilen, opts->mseql + 16384,
                                current_array->array_name,
                                current_array->
                                value_array[current_array->value_ctr].sym_val,
                                current_array->
                                value_array[current_array->value_ctr].is_len);
            } else {
                char *blit = current_array->value_array[current_array->value_ctr].sym_val;
                size_t blit_len = current_array->value_array[current_array->value_ctr].is_len;

                snprintf(sizeval, 80, "%zu", blit_len);
                ilen = smemrepl(req, reqsize, opts->mseql + 16384, sizerepl,
                                (char *)&blit_len, sizeof blit_len);

                ilen = smemrepl(req, ilen, opts->mseql + 16384, ssizerepl,
                                sizeval, strlen(sizeval));

                ilen = smemrepl(req, ilen, opts->mseql + 16384,
                                current_array->array_name, blit, blit_len);

            }
            reqsize = ilen;
        }

        /*loaded a request.*/
        p = memmem(req, reqsize, "FUZZ", 4);

        if (!p) {
            if (fuzz(opts, req, reqsize) < 0) {
                goto done;
            }
            memcpy(preq, req, reqsize);
            preqsize = reqsize;
        } else {
            /* we have to FUZZ for real.  do the literals. */
            if (opts->no_literal_fuzz == 0) {
                for (tsze = 0; tsze < opts->num_litr; ++tsze) {
                    char litr_is_bin = 0;
                    i = 0;

                    /*first, do the literals, which are filled in as-is*/
                    strcpy(req2, req);
                    c = *((opts->litr[tsze]) + 
                          strspn(opts->litr[tsze], " "));

                    b = *(1 + (opts->litr[tsze]) + 
                          strspn(opts->litr[tsze], " "));
                    
                    f = *(2 + (opts->litr[tsze])+
                          strspn(opts->litr[tsze], " "));

                    if ((c == '0') || (c == '\\')) {
                        if (b == 'x' && f >= '0' && f <= '9')
                            litr_is_bin = 1;
                    }

                    if (c == 'x' && ((f >= '0') && (f <= '9')))
                        litr_is_bin = 1;

                    if (!litr_is_bin) {
                        size_t bsizeval = strlen(opts->litr[tsze]);
                        char sizeval[80] = {0};
                        snprintf(sizeval, 80, "%zu", bsizeval);
                        i = smemrepl(req2, reqsize, opts->mseql + 16384, "%%FUZZ", (char *)
                                     &bsizeval, sizeof bsizeval);
                        i = smemrepl(req2, i, opts->mseql + 16384, "%FUZZ", sizeval,
                                     strlen(sizeval));
                        i = smemrepl(req2, i, opts->mseql + 16384, "FUZZ", opts->litr[tsze],
                                     strlen(opts->litr[tsze]));
                    } else {
                        char *blit = malloc(8192);
                        int blit_len = 0;
                        char sizeval[80] = {0};

                        strcpy(blit,opts->litr[tsze]+
                               strspn(opts->litr[tsze]," "));

                        strrepl(blit, strlen(blit), "0x", " ");
                        strrepl(blit, strlen(blit), "\\x", " ");

                        blit_len = ascii_to_bin((unsigned char *)blit);
                        snprintf(sizeval, 80, "%d", blit_len);
                        i = smemrepl(req2, reqsize, opts->mseql + 16384, "%%FUZZ",
                                     (char *)&blit_len, sizeof blit_len);
                        i = smemrepl(req2, i, opts->mseql + 16384, "%FUZZ", sizeval,
                                     strlen(sizeval));
                        i = smemrepl(req2, i, opts->mseql + 16384, "FUZZ", blit, blit_len );
                        free( blit );
                    }

                    if (opts->send_initial_nonfuzz_again)
                        if(fuzz(opts, preq, preqsize) < 0)
                            goto done;

                    if (fuzz(opts, req2, i)<0)
                        goto done;
                }
            }

            if(opts->no_sequence_fuzz == 0) {
                /*do the sequences*/
                char *sequence_hold = NULL;
                for (tsze = 0; tsze < opts->num_seq; ++tsze) {
                    size_t bsizeval = 0;
                    char sizeval[80] = {0};
                    char seq_buf[5] = {0};
                    /*at this point, we do sequences. Sequencing will be done*/
                    /*by filling to maxseqlen, in increments of seqstep*/

                    // SUPPORT FOR MULTIPLE INSTANCES OF FUZZ!!

                    for (k = opts->seqstep; k <= opts->mseql;
                         k+= opts->seqstep) {
                        memset(req2, 0,   opts->mseql + 16384 );
                        memcpy(req2, req, strlen(req));

                        seq4b = 0;

                        if (sequence_hold)
                            free(sequence_hold);
                        sequence_hold = malloc(k+4);
                        if (!sequence_hold) {
                            fprintf(stderr, "error: sequence too large? OOM\n");
                            goto done;
                        }

                        memset(sequence_hold, 0, k+1);

                        for (i=0;i < k; ++i) {
                            sequence_hold[i] =
                                *(opts->seq[tsze] + (i % opts->seq_lens[tsze]));
                        }

                        bsizeval = strlen(sequence_hold);

                        snprintf(sizeval, 80, "%zu", bsizeval);

                        i = smemrepl(req2, reqsize, opts->mseql + 16384, "%%FUZZ",
                                     (char *)&bsizeval, sizeof bsizeval);

                        i = smemrepl(req2, i, opts->mseql + 16384, "%FUZZ", sizeval,
                                           strlen(sizeval));
                        
                        i = smemrepl(req2, i, opts->mseql + 16384, "FUZZ",
                                           sequence_hold,
                                           bsizeval);

                        seq4b++;
                        
                        if (strstr(req2, "__SEQUENCE_NUM_ASCII__")) {
                            snprintf(seq_buf, 5, "%04d", seq4b);
                            i = strrepl(req2, i, "__SEQUENCE_NUM_ASCII__",
                                        seq_buf);
                        }

                        if (opts->send_initial_nonfuzz_again)
                            if (fuzz(opts, preq, preqsize) < 0)
                                goto done;

                        if (fuzz(opts, req2, i)<0)
                            goto done;
                    }
                }
                if (sequence_hold)
                    free( sequence_hold );
            }
        }
    }

 done:
    free( line );
    free( req  );
    free( req2 );
    free( preq );

    return 0;
}
