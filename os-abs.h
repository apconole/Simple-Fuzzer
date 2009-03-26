#ifndef __OS_ABSTRACTION_H__
#define __OS_ABSTRACTION_H__

#include "options-block.h"

extern void os_send_tcp(option_block *opts, char *req, int len);
extern void os_send_udp(option_block *opts, char *req, int len);
extern int  strrepl(char *buf, size_t buflen, char *old, char *new);
extern int  atoip(const char *pIpStr);
extern void dump(void *b, int len);

#endif
