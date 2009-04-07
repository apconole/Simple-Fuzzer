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
#include <time.h>

#include "sfuzz.h"
#include "os-abs.h"
#include "version.h"
#include "options-block.h"

#ifdef __WIN32__
#include "windows.h"
#else
#include <sys/time.h>
#include <string.h>
#endif

extern int readLine(option_block *opts, char *line, int len, int ign_cr);
extern void read_config(option_block *opts);
int execute_fuzz(option_block *opts);

void dump_options(option_block *opts)
{
    int i;

    if(opts != NULL)
    {
        printf("[%s] dumping options:\n\tfilename: <%s>\n\tstate:    <%d>\n\tlineno:   <%d>\n\tliterals:  [%d]\n\tsequences: [%d]\n\tsymbols: [%d]\n\treq_del:  <%d>\n\tmseq_len: <%d>\n",
               get_time_as_log(), opts->pFilename, opts->state, opts->lno, opts->num_litr, opts->num_seq, opts->sym_count / 2, opts->reqw_inms, opts->mseql);

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
    printf("\n");
    printf("\t-h\t This message.\n");
    printf("\t-V\t Version information.\n");
    printf("\n");
    printf("networking / output:\n");
    printf("\t-v\t Verbose output\n");
    printf("\t-q\t Silent output mode (generally for CLI fuzzing)\n");
    printf("\t-X\t prints the output in hex\n");
    printf("\n");
    printf("\t-t\t Wait time for reading the socket\n");
    printf("\t-S\t Remote host\n");
    printf("\t-p\t Port\n");
    printf("\t-T|-U|-O TCP|UDP|Output mode\n");
    printf("\t-R\t Refrain from closing connections (ie: \"leak\" them)\n");
    printf("\n");
    printf("\t-f\t Config File\n");
    printf("\t-L\t Log file\n");
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
        switch(*line++)
        {
        case 's':
            opts->no_sequence_fuzz = 0;
            opts->no_literal_fuzz = 1;
            break;
        case 'l':
            opts->no_literal_fuzz = 0;
            opts->no_sequence_fuzz = 1;
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
            break;
	case 't':
            opts->time_out = atoi(lastarg);
            break;
        case 'p':
            opts->port    = atoi(lastarg);
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

int main(int argc, char *argv[])
{
    FILE *log = stdout;
    struct timeval tv;
    option_block options;
    int i;

    memset(&options, 0, sizeof(options));

    gettimeofday(&tv, NULL);
    birth = tv.tv_sec;

    options.pFilename = malloc(MAX_FILENAME_SIZE);
    options.pLogFilename = malloc(MAX_FILENAME_SIZE);
    options.host_spec = malloc(MAX_HOSTSPEC_SIZE);

    memset(options.pFilename, 0, MAX_FILENAME_SIZE-1);
    memset(options.pLogFilename, 0, MAX_FILENAME_SIZE-1);
    
    options.state     = CMD_LINE_OPTS;
    process_opts(argc, argv, &options);
    
    options.state     = INIT_READ;
    read_config(&options);

    if(options.pLogFilename[0] != 0)
    {
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
    free(options.syms_array);
    
    return 0;
}

int fuzznum = 0;

void fuzz(option_block *opts, char *req, int len)
{
    int i = 0;
    FILE *log = stdout;
    sym_t *pSym;

    if(opts->fp_log)
        log = opts->fp_log;

    if(opts->verbosity != QUIET)
        fprintf(log, "[%s] attempting fuzz - %d.\n", get_time_as_log(),
                ++fuzznum);
    
    if(opts->sym_count)
    {
        /*xxx : enhancement - loop backwards allowing people to define
                a string (aaa for example) and use that string within
                other defines appearing later.
                THIS creates a problem - our length field substitution
                depends on having lengths before non-lengths. The answer
                of course, is to just have 2 loops, apply the lenghts first*/
        for(i = opts->sym_count - 1; i >= 0; --i)
        {
            pSym = &(opts->syms_array[i]);
            if(pSym->is_len)
                len = strrepl(req, len, pSym->sym_name, pSym->sym_val);
        }

        for(i = opts->sym_count - 1; i >= 0; --i)
        {
            pSym = &(opts->syms_array[i]);
            if(!pSym->is_len)
            len = strrepl(req, len, pSym->sym_name, pSym->sym_val);
        }
    }

    if(opts->b_sym_count)
    {
        for(i = 0; i < opts->b_sym_count; ++i)
        {
            pSym = &(opts->b_syms_array[i]);
            len = smemrepl(req, len, pSym->sym_name, pSym->sym_val, 
                           pSym->is_len);
        }
    }

    if(opts->out_flag)
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
    
    if(opts->tcp_flag)
    {
        os_send_tcp(opts, req, len);
    }
    else if(opts->udp_flag)
    {
        os_send_udp(opts, req, len);
    }
    
}

int execute_fuzz(option_block *opts)
{
    char *line = malloc(8192);
    char *req  = malloc(opts->mseql + 8192);
    char *req2 = malloc(opts->mseql + 8192);
    char *preq = malloc(opts->mseql + 8192);
    char *p, *j;

    int tsze    = 0;
    int reqsize = 0;
    int preqsize= 0;
    int i       = 0;
    int k       = 0;

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
            
            if(opts->mseql && ((tsze + reqsize) > opts->mseql))
            {
                /*ohnoes overflow*/
                fprintf(stderr, "[%s] error: overflow.\n", get_time_as_log());
                exit(-1);
            }
            
            memcpy(req+reqsize, line, tsze);
            *(req+reqsize+tsze-1)='\n';
            *(req+reqsize+tsze) = 0;
            reqsize += tsze;
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
                    i = 0;
                    
                    /*first, do the literals, which are filled in as-is*/
                    strcpy(req2, req);
                    
                    /*because of this, we cannot properly handle binary atm.*/
                /*a more robust solution would be to have a memrepl function*/
                    strrepl(req2, reqsize, "FUZZ", opts->litr[tsze]);
                    
                    if(opts->send_initial_nonfuzz_again)
                        fuzz(opts, preq, preqsize);
                    
                    fuzz(opts, req2, strlen(req2));
                }
            }
            
            if(opts->no_sequence_fuzz == 0)
            {
                /*do the sequences*/
                for(tsze = 0; tsze < opts->num_seq; ++tsze)
                {
                    /*at this point, we do sequences. Sequencing will be done*/
                    /*by filling to maxseqlen, in increments of seqstep*/
                    memcpy(req2, req, (p-req));
                    /*we've filled up req2 with everything BEFORE FUZZ*/
                    j = req2;
                    
                    for(k = opts->seqstep; k <= opts->mseql; k+= opts->seqstep)
                    {
                        req2 = j;
                        req2 += (p-req);
                        
                        for(i=0;i < k; ++i)
                        {
                            *req2++ =
                                *(opts->seq[tsze] + (i % opts->seq_lens[tsze]));
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
