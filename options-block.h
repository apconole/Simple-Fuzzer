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

#ifndef __OPTIONS_BLOCK_H__
#define __OPTIONS_BLOCK_H__

typedef struct
{
    char sym_name[8192];
    char sym_val[8192];
    int  is_len;
} sym_t;

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

    /*delay in req xmission - in MS*/
    int reqw_inms;

    /*max seq len*/
    int mseql;

    /*fuzz type*/
    char tcp_flag;
    char udp_flag;
    char out_flag;

    /*reporting verbosity*/
    char verb;

    /*host reporting*/
    int host;
    char *host_spec;

    /*port num - int for atoi*/
    int port;

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

} option_block;

#define MAX_FILENAME_SIZE  1024
#define MAX_SUBCHAR_SIZE   1024
#define MAX_HOSTSPEC_SIZE  100

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
