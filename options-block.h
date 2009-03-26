#ifndef __OPTIONS_BLOCK_H__
#define __OPTIONS_BLOCK_H__

typedef struct
{
    char sym_name[8192];
    char sym_val[8192];
    char is_len;
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

    /*time out in ms*/
    int time_out;

    /*close? this is different from the reuse*/
    int forget_conn;

    /*verbosity flag*/
    int verbosity;

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
