/**
 * SFUZZ oracle
 */

/***
 * We need to use ptrace() on unix-y systems
 * and the mswin debug facilities on windows
 */

struct sfuzz_oracle_request
{
  unsigned char req_id;
  unsigned int  req_flags;
  unsigned int  req_length
  unsigned char *data
};

typedef struct sfuzz_oracle_request sfuzz_oracle_request_t;
