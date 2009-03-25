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
        printf("[%s] dumping options:\n\tfilename: <%s>\n\tstate:    <%d>\n\tlineno:   <%d>\n\tliterals:  [%d]\n\treq_del:  <%d>\n\tmseq_len: <%d>\n",
               get_time_as_log(), opts->pFilename, opts->state, opts->lno, opts->num_litr, opts->reqw_inms, opts->mseql);
        for(i = 0; i < opts->num_litr; i++)
            printf("\tliteral[%d] = [%s]\n", i+1, opts->litr[i]);
        for(i = 0; i < opts->num_seq; i++)
            printf("\tsequence[%d] = [%s]\n", i+1, opts->seq[i]);
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
    printf("\t-h\tThis message.\n");
    printf("\t-V\tVersion information.\n");
    printf("\t-D\tDefine a symbol and value (X=y).\n");
    printf("\t-T|-U|-O\tTCP|UDP|Output mode\n");
    printf("\t-L\tLog file\n");
    printf("\t-f\tConfig File\n");
    printf("\t-S\tRemote host\n");
    printf("\t-p\tPort\n");
    printf("\t-t\tWait time for reading the socket\n");
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
            opts->verb++;
            if(opts->verb <= 0)
            {
                printf("nice fuzz attempt.\n");
                exit(-1);
            }
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
        fprintf(stderr, "[%s] fatal: attempt to invoke process_opts in improper state. ARE YOU HACKING?!\n",
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
            dump_options(&options);
        }else
        {
            fprintf(stderr, "[%s] error: using stdout - unable to open log.\n",
                    get_time_as_log());
            log = stdout;
        }
        
    }

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
    
    options.state     = FUZZ;
    execute_fuzz(&options);

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
    
    fprintf(log, "[%s] attempting fuzz - %d.\n", get_time_as_log(),
            ++fuzznum);

    if(opts->sym_count)
    {
        for(i = 0; i < opts->sym_count; ++i)
        {
            pSym = &(opts->syms_array[i]);
            len = strrepl(req, len, pSym->sym_name, pSym->sym_val);
        }
    }
    
    if(opts->out_flag)
    {
        fprintf(log, "%s\n", req);
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
            for(tsze = 0; tsze < opts->num_litr; ++tsze)
            {
                i = 0;
                
                /*first, do the literals, which are filled in as-is*/
                memcpy(req2, req, (p - req));
                reqsize = opts->litr_lens[tsze];
                j = req2+(p-req);
                
                while(reqsize--)
                {
                    *(j+i) = *(opts->litr[tsze]+i);
                    i++;
                }
                *(j+i) = 0;

                /*because of this, we cannot properly handle binary atm.*/
                strncat(req2, (char *)(p+4), strlen((char *)(p+4)));
                
                if(opts->send_initial_nonfuzz_again)
                    fuzz(opts, preq, preqsize);
                
                fuzz(opts, req2, strlen(req2));
            }
            
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
    free( line );
    free( req  );
    free( req2 );
    return 0;
}
