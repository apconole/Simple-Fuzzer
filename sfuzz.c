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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "sfuzz.h"
#include "os-abs.h"
#include "version.h"
#include "options-block.h"
#include "sfuzz-plugin.h"

#ifdef __WIN32__
#include "windows.h"
#else
#include <sys/time.h>
#include <string.h>
#endif

plugin_provisor *g_plugin;

extern int readLine(option_block *opts, char *line, int len, int ign_cr);
extern void read_config(option_block *opts);
int execute_fuzz(option_block *opts);
extern unsigned int ascii_to_bin(char *str_bin);
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
    printf("url:\t http://aconole.brad-x.com/programs/sfuzz.html\n");
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

void sanity(option_block *opts)
{
    if(opts == NULL)
    {
        fprintf(stderr, "[%s] fatal: option block null\n", get_time_as_log());
        exit(-1);
    }
    
    if(!(opts->tcp_flag) && !(opts->udp_flag) && !(opts->out_flag))
    {
        fprintf(stderr, "[%s] error: must specify an output type.\n",
                get_time_as_log());
        print_help();
        exit(-1);
    }

    if(opts->pFilename[0] == 0)
    {
        fprintf(stderr, "[%s] error: must specify a config file.\n",
                get_time_as_log());
        print_help();
        exit(-1);
    }

    if(((opts->tcp_flag)||(opts->udp_flag)) && 
       ((opts->host == 0) || ((opts->port == 0) || (opts->port < 1) ||
                              (opts->port > 65535)))
        )
    {
        fprintf(stderr, 
             "[%s] error: must specify a host and port when using netmode.\n",
                get_time_as_log());
        print_help();
        exit(-1);
    }
}
extern void add_symbol(char *sym_name, int sym_len, char *sym_val, 
                       int sym_val_len, option_block *opts, int i);

void process_opt_str(char *line, char *lastarg, option_block *opts)
{
    char *delim;
    int   sze;
    while(*line != 0)
    {
/*
used:
beslnqrtpvfh
XRSTUOLVD
 */
        switch(*line++)
        {
        case 'b':
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
            opts->host     = atoip(lastarg);
            strncpy(opts->host_spec, lastarg, MAX_HOSTSPEC_SIZE);
            opts->host_spec[MAX_HOSTSPEC_SIZE-1] = 0;
            break;
	case 't':
            opts->time_out = atoi(lastarg);
            break;
        case 'p':
            opts->port    = atoi(lastarg);
            strncpy(opts->port_spec, lastarg, MAX_PORTSPEC_SIZE);
            opts->port_spec[MAX_PORTSPEC_SIZE-1] = 0;
            break;
        case 'T':
            opts->tcp_flag = 1;
            break;
        case 'U':
            opts->udp_flag = 1;
            break;
        case 'O':
            opts->out_flag = 1;
            break;
        case 'L':
            strncpy(opts->pLogFilename, lastarg, MAX_FILENAME_SIZE-1);
            opts->pLogFilename[MAX_FILENAME_SIZE-1] = 0;            
            break;
        case 'v': /*when I put in better logging.*/
            opts->verbosity = VERBOSE;
            break;
        case 'f':
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
            delim = strstr(lastarg, "=");
            if(delim == NULL)
            {
                fprintf(stderr, "error: delimiter not found for symbol.\n");
                exit(-1);
            }
            sze = strlen(delim+1);
            if(sze == 0)
            {
                fprintf(stderr, "error: symbol's value is null.\n");
                exit(-1);
            }

            add_symbol(lastarg, (delim - lastarg), delim+1, sze, opts, 0);
            break;
        default:
            printf("unknown option: %c\n", *line); exit(0);
        }
    }
}

void process_opts(int argc, char *argv[], option_block *opts)
{
    char *lastarg = 0;

    if(opts->state != CMD_LINE_OPTS)
    {
        fprintf(stderr, "[%s] fatal: attempt to invoke process_opts in improper state. ARE YOU HACKING ME?!\n",
                get_time_as_log());
        exit(-1);
    }

    if(argc > 1)
    {
        --argc;
        while(argc > 0)
        {
            switch(argv[argc][0])
            {
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

int main(int argc, char *argv[])
{
    FILE *log = stdout;
    struct timeval tv;
    option_block options;
    int i;

    g_plugin = NULL;
    sfuzz_setsearchpath(
#ifndef __WIN32__
        "./:"PREFIX"/sfuzz-db"
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

    /*default line terminator*/
    options.line_term[0]         = '\n';
    options.line_terminator_size = 1;

    options.state     = CMD_LINE_OPTS;
    process_opts(argc, argv, &options);
    
    options.state     = INIT_READ;
    read_config(&options);

    if(options.pLogFilename[0] != 0)
    {
        if(options.new_logfile)
        {
            strncat(options.pLogFilename, ".0", MAX_FILENAME_SIZE);
        }

        log = fopen(options.pLogFilename, "w");
        if(log != NULL)
        {
            options.fp_log = log;
        }else
        {
            fprintf(stderr, "[%s] error: using stdout - unable to open log.\n",
                    get_time_as_log());
            log = stdout;
        }
        
    }

    if(options.verbosity == VERBOSE)
        dump_options(&options);
    
    if(options.verbosity != QUIET)
    {
        fprintf(log, "[%s] info: beginning fuzz - method:", get_time_as_log());
        if(options.tcp_flag)
        {
            fprintf(log, " tcp,");
        } else if(options.udp_flag)
        {
            fprintf(log, " udp,");
        }
        else
        {
            fprintf(log, " io,");
        }
        
        fprintf(log, " config from: [%s], out: [%s:%d]\n",
                options.pFilename, options.host_spec, options.port);
    }
    
    options.state     = FUZZ;
    execute_fuzz(&options);

    if(options.verbosity != QUIET)
        fprintf(log, "[%s] completed fuzzing.\n", get_time_as_log());
    
    free( options.pFilename    );
    free( options.pLogFilename );
    free( options.host_spec    );

    for(i = 0; i < options.num_litr; ++i)
    {
        free(options.litr[i]);
    }
    free(options.litr);
    free(options.litr_lens);

    for(i = 0; i < options.num_seq; ++i)
    {
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

void fuzz(option_block *opts, char *req, int len)
{
    int i = 0;
    FILE *log = stdout;
    char *r2, *tmp = 0;
    char *p1, *tmp2 = 0;
    int r2_len,p1_len;
    sym_t *pSym;

    int fuzz_this_time = (opts->start_test <= ++fuzznum) ? 
        1 : 0;

    if(opts->fp_log)
        log = opts->fp_log;

    if( fuzz_this_time && opts->verbosity != QUIET )
        fprintf(log, "[%s] attempting fuzz - %d.\n", get_time_as_log(),
                fuzznum);

#ifndef NOPLUGIN
    if(fuzz_this_time && g_plugin != NULL && 
       ((g_plugin->capex() & PLUGIN_PROVIDES_PAYLOAD_PARSE) ==
        PLUGIN_PROVIDES_PAYLOAD_PARSE))
    {
        tmp2 = req;
        p1_len = len * 2;
        p1 = malloc(p1_len);
        g_plugin->payload_trans(opts, req, len, p1, &p1_len);
        req = p1;
        len = p1_len;
    }
#endif
    
    if(fuzz_this_time && ((opts->sym_count) || (opts->s_syms_count)))
    {
        /*xxx : enhancement - loop backwards allowing people to define
                a string (aaa for example) and use that string within
                other defines appearing later.
                THIS creates a problem - our length field substitution
                depends on having lengths before non-lengths. The answer
                of course, is to just have 2 loops, apply the lenghts first*/
        for(i = 0; i < opts->s_syms_count ; ++i)
        {
            pSym = &(opts->s_syms[ opts->s_syms_count - (i+1) ]);
            len = smemrepl(req, len, pSym->sym_name, pSym->sym_val, 
                               pSym->s_len);
        }
        
        for(i = 0; i < opts->sym_count; ++i)
        {
            pSym = &(opts->syms_array[ opts->sym_count - (i+1) ]);
            if(pSym->is_len)
                len = strrepl(req, len, pSym->sym_name, pSym->sym_val);
        }
        
        for(i = 0; i < opts->sym_count; ++i)
        {
            pSym = &(opts->syms_array[ opts->sym_count - (i+1) ]);
            if(!pSym->is_len)
                len = strrepl(req, len, pSym->sym_name, pSym->sym_val);
        }

    }

    if(opts->b_sym_count) /* we let this one through in skip cases
                             because we need the increments to happen. */
    {
        for(i = 0; i < opts->b_sym_count; ++i)
        {
            pSym = &(opts->b_syms_array[i]);
            len = smemrepl(req, len, pSym->sym_name, pSym->sym_val, 
                           pSym->is_len);
	    if(pSym->increment)
            {
                int *increm = (int*)pSym->sym_val;
                *increm = (*increm)+1;
            }
        }
    }

    if(fuzz_this_time && opts->out_flag)
    {
        if(opts->hexl_dump)
        {
            dump(req, len, log);
        }
        else
        {
            fwrite(req, len, 1, log);
            fwrite("\n", 1, 1, log);
        }
    }
    
#ifndef NOPLUGIN
    if(fuzz_this_time && g_plugin != NULL && 
       ((g_plugin->capex() & PLUGIN_PROVIDES_FUZZ_MODIFICATION) ==
        PLUGIN_PROVIDES_FUZZ_MODIFICATION))
    {
        r2 = malloc(len * 2);
        r2_len = len * 2;
        g_plugin->fuzz_trans(opts, req, len, r2, &r2_len);
        tmp = req;
        req = r2;
        len = r2_len;
    }

    if(fuzz_this_time && g_plugin != NULL && 
       ((g_plugin->capex() & PLUGIN_PROVIDES_TRANSPORT_TYPE) == 
        PLUGIN_PROVIDES_TRANSPORT_TYPE))
    {
        g_plugin->trans(opts, req, len);
    }
    else 
#endif
    if(fuzz_this_time && opts->tcp_flag)
    {
        os_send_tcp(opts, req, len);
    }
    else if(fuzz_this_time && opts->udp_flag)
    {
        os_send_udp(opts, req, len);
    }
#ifndef NOPLUGIN
    else if(fuzz_this_time && (g_plugin != NULL) &&
	    ((g_plugin->capex() & PLUGIN_PROVIDES_POST_FUZZ) ==
	     PLUGIN_PROVIDES_POST_FUZZ))
    {
        g_plugin->post_fuzz(opts, req, len);
    }
    

    if(fuzz_this_time && g_plugin != NULL && 
       ((g_plugin->capex() & PLUGIN_PROVIDES_FUZZ_MODIFICATION) ==
        PLUGIN_PROVIDES_FUZZ_MODIFICATION))
    {
        free(req);
        req = tmp;
    }

    if(fuzz_this_time && g_plugin != NULL && 
       ((g_plugin->capex() & PLUGIN_PROVIDES_PAYLOAD_PARSE) ==
        PLUGIN_PROVIDES_PAYLOAD_PARSE))
    {
        free(req);
        req = tmp2;
    }
#endif

    if(fuzz_this_time && (opts->new_logfile) && (opts->pLogFilename))
    {
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
    
}

int execute_fuzz(option_block *opts)
{
    char *line = malloc(8192);
    char *req  = malloc(opts->mseql + 16384);
    char *req2 = malloc(opts->mseql + 16384);
    char *preq = malloc(opts->mseql + 16384);
    char *p, *j;
    char c,f,b;

    int tsze    = 0;
    int reqsize = 0;
    int preqsize= 0;
    int i       = 0;
    int k       = 0;
    unsigned int seq4b = 0;

    memset(req, 0, opts->mseql + 16384);
    memset(req2, 0, opts->mseql + 16384);
    memset(preq, 0, opts->mseql + 16384);

    if(opts->state != FUZZ)
    {
        fprintf(stderr, "[%s] fatal: corrupted state for execute_fuzz()\n",
                get_time_as_log());
        exit(-1);
    }

    /*setup the socket fd*/
    opts->sockfd = -1;

    while(!feof(opts->fp))
    {
        tsze    = 0;
        reqsize = 0;
        line[0] = 0;
        while(strcmp(line, "--") && strcmp(line, "c-"))
        {
            tsze = readLine(opts, line, 8192, 1);
            if(!strcmp(line, "--") || !strcmp(line, "c-") || tsze == 0)
            {
                break;
            }
            
            if(opts->mseql && ((tsze + reqsize) > opts->mseql + 8192))
            {
                /*ohnoes overflow*/
                fprintf(stderr, "[%s] error: overflow[%d:%d].\n", 
			get_time_as_log(), opts->mseql, 
			(tsze + reqsize));
                exit(-1);
            }
            
            memcpy(req+reqsize, line, tsze);
            reqsize += tsze-1;

            if(opts->line_terminator_size)
            {
                memcpy(req+reqsize, opts->line_term, 
                       opts->line_terminator_size);
            }

            reqsize += opts->line_terminator_size;

            *(req+reqsize) = 0;
        }

        if(feof(opts->fp)) break;
        
        if(!strcasecmp(line, "c-"))
            opts->close_conn = 0;
        else
            opts->close_conn = 1;

        /* TODO: implement this feature in an intuitive and useful manner */
        opts->send_initial_nonfuzz_again = 0;

        if(opts->trim_nl)
            req[reqsize-1] = 0;

        if(opts->seqstep <= 0)
        {
            opts->seqstep = opts->mseql;
        }
        
        /*loaded a request.*/
        p = strstr(req, "FUZZ");
        
        if(!p)
        {
            fuzz(opts, req, reqsize);
            memcpy(preq, req, reqsize);
            preqsize = reqsize;
        }
        else /* we have to FUZZ for reals*/
        {
            /*do the literals*/
            if(opts->no_literal_fuzz == 0)
            {
                for(tsze = 0; tsze < opts->num_litr; ++tsze)
                {
                    char litr_is_bin = 0;
                    i = 0;
                    
                    /*first, do the literals, which are filled in as-is*/
                    strcpy(req2, req);
                    c = *(
                        (opts->litr[tsze]) + 
                        strspn(opts->litr[tsze], " "));

                    b = *(1+
                        (opts->litr[tsze]) + 
                        strspn(opts->litr[tsze], " "));
                    
                    f = *(2 +
                        (opts->litr[tsze])+
                        strspn(opts->litr[tsze], " "));

                    if((c == '0') ||
                       (c == '\\'))
                    {
                        if((b == 'x') &&
                           ((f >= '0') &&
                            (f <= '9')))
                           litr_is_bin = 1;
                    }

                    if(c == 'x')
                        if((f >= '0') && (f <= '9'))
                            litr_is_bin = 1;

                    if(!litr_is_bin)
                        i = strrepl(req2, reqsize, "FUZZ", opts->litr[tsze]);
                    else
                    {
                        char *blit = malloc(8192);
                        int blit_len = 0;
                        strcpy(blit,opts->litr[tsze]+
                               strspn(opts->litr[tsze]," "));

                        strrepl(blit, strlen(blit), "0x", " ");
                        strrepl(blit, strlen(blit), "\\x", " ");

                        blit_len = ascii_to_bin(blit);
                        i = smemrepl(req2, reqsize, "FUZZ",blit, blit_len );
                        free( blit );
                    }
                    
                    if(opts->send_initial_nonfuzz_again)
                        fuzz(opts, preq, preqsize);
                    
                    fuzz(opts, req2, i);
                }
            }
            
            if(opts->no_sequence_fuzz == 0)
            {
                /*do the sequences*/
                for(tsze = 0; tsze < opts->num_seq; ++tsze)
                {
                    char seq_buf[5] = {0};
                    /*at this point, we do sequences. Sequencing will be done*/
                    /*by filling to maxseqlen, in increments of seqstep*/
                    memcpy(req2, req, (p-req));
                    /*we've filled up req2 with everything BEFORE FUZZ*/
                    j = req2;
                    
                    for(k = opts->seqstep; k <= opts->mseql; k+= opts->seqstep)
                    {
                        seq4b = 0;
                        req2 = j;
                        req2 += (p-req);
                        
                        for(i=0;i < k; ++i)
                        {
                            *req2++ =
                                *(opts->seq[tsze] + 
                                  (i % opts->seq_lens[tsze]));
                            
                            if(strstr(j, "__SEQUENCE_NUM_ASCII__"))
                            {
                                snprintf(seq_buf, 5, "%04d", seq4b++);
                                strrepl(j, strlen(j), "__SEQUENCE_NUM_ASCII__",
                                        seq_buf);
                                req2 -= 18;
                            }
                               
                        }
                        
                        memcpy(req2, (char *)(p+4), strlen(p+4));
                        
                        *(req2+(strlen(p+4))) = 0;
                        
                        req2 = j;
                        
                        if(opts->send_initial_nonfuzz_again)
                            fuzz(opts, preq, preqsize);
                        fuzz(opts, req2, strlen(req2));
                    }
                }
            }
        }
    }

    free( line );
    free( req  );
    free( req2 );

    return 0;
}
