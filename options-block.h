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

#ifndef __OPTIONS_BLOCK_H__
#define __OPTIONS_BLOCK_H__

/**
 * \brief the format of a fuzz 'symbol'
 */
typedef struct
{
    char sym_name[8192];
    char sym_val[8192];
    char *sym_match;
    int  is_len;
    int  s_len;
    int  offset;
    char increment;
    char bin;
} sym_t;

/**
 * \brief The format of a fuzz 'array'
 */
typedef struct
{
    char   array_name[8192];
    sym_t *value_array;
    int    value_length;
    int    value_ctr;
    int    array_max_val;
} array_t;

#define FUZZ_NONE       (      0)
#define FUZZ_OUT        (1 <<  1)
#define FUZZ_TCP        (1 <<  2)
#define FUZZ_UDP        (1 <<  3)
#define FUZZ_UNIX       (1 <<  4)
#define FUZZ_UNIX_DGRAM (1 <<  5)

/**
 * \brief All of the options and states associated with a fuzzing effort.
 *
 * This probably could have been a bunch of globals, but a future roadmap
 * effort could be to rewrite sfuzz to distribute over a number of nodes and
 * run multiple fuzz test cases. Having the opts block in this format makes
 * that job easier.
 */
typedef struct
{
    FILE *fp;
    char *pFilename;

    FILE *fp_log;
    char *pLogFilename;
    
    /*line number*/
    int lno;

    int state;
    
    /*literals*/
    char **litr;
    int   *litr_lens;
    int    num_litr;

    /*sequencess*/
    char **seq;
    int   *seq_lens;
    int    num_seq;

    /* string symbol arrays */
    array_t **arrays;
    int       num_arrays;

    /*delay in req xmission - in MS*/
    int reqw_inms;

    /*max seq len*/
    int mseql;

    /*fuzz type*/
    char fuzz_flag;

    /*reporting verbosity*/
    char verb;

    /*host reporting*/
    int host;
    char *host_spec;

    /*port num - int for atoi*/
    int port;
    char *port_spec;

    /*keep open*/
    char close_conn;
    int  sockfd;

    char send_initial_nonfuzz_again;

    int  seqstep;

    /*symbols*/
    sym_t *syms_array;
    int  sym_count;

    sym_t *b_syms_array;
    int  b_sym_count;

    /*time out in ms*/
    int time_out;

    /*close? this is different from the reuse*/
    int forget_conn;

    /*verbosity flag*/
    int verbosity;

    /*fuzzing types*/
    char no_literal_fuzz;
    char no_sequence_fuzz;

    /*trim newline at the end*/
    char trim_nl;

    /*dump output as hex*/
    char hexl_dump;

    char new_logfile;

    /*line terminator*/
    char line_terminator_size;
    char line_term[1024];

    /*begin-at-test*/
    unsigned int start_test;
    
    /*stop-testing-on-fail-to-connect*/
    char stop_on_fail;

    /*substitution symbols*/
    char repl_pol;
    sym_t *s_syms;
    unsigned int s_syms_count;

    /* file descriptor for transmission */
    int link_oracle;
} option_block;

static inline char is_tcp(option_block *opts) {
    return opts->fuzz_flag & FUZZ_TCP;
}

static inline void set_tcp(option_block *opts) {
    opts->fuzz_flag |= FUZZ_TCP;
}

static inline char is_udp(option_block *opts) {
    return opts->fuzz_flag & FUZZ_UDP;
}

static inline void set_udp(option_block *opts) {
    opts->fuzz_flag |= FUZZ_UDP;
}

static inline char is_unix_stream(option_block *opts) {
    return opts->fuzz_flag & FUZZ_UNIX;
}

static inline void set_unix_stream(option_block *opts) {
#ifndef __WIN32__
    opts->fuzz_flag |= FUZZ_UNIX;
#endif
}

static inline char is_unix_dgram(option_block *opts) {
    return opts->fuzz_flag & FUZZ_UNIX_DGRAM;
}

static inline void set_unix_dgram(option_block *opts) {
#ifndef __WIN32__
    opts->fuzz_flag |= FUZZ_UNIX_DGRAM;
#endif
}

static inline char is_unix(option_block *opts) {
    return is_unix_dgram(opts) || is_unix_stream(opts);
}

static inline char is_netmode(option_block *opts) {
    return is_tcp(opts) || is_udp(opts);
}

static inline char is_output(option_block *opts) {
    return opts->fuzz_flag & FUZZ_OUT;
}

static inline void set_output(option_block *opts) {
    opts->fuzz_flag |= FUZZ_OUT;
}


#define MAX_FILENAME_SIZE  1024
#define MAX_SUBCHAR_SIZE   1024
#define MAX_HOSTSPEC_SIZE  100
#define MAX_PORTSPEC_SIZE  50

#define CMD_LINE_OPTS         0
#define INIT_READ             1
#define CONFIG_PARSE_BEGIN    2
#define READ_MALFORM_BLOCK    4
#define CONFIG_PARSE_END      8
#define FUZZ                 16

#define VERBOSE   0
#define QUIET     1

#ifndef MIN
#define MIN(x,y) ((x < y) ? x : y)
#endif

#ifndef MAX
#define MAX(x,y) ((x > y) ? x : y)
#endif

#endif
