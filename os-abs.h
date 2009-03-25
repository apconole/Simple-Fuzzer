#ifndef __OS_ABSTRACTION_H__
#define __OS_ABSTRACTION_H__

#include "options-block.h"

extern void os_send_tcp(option_block *opts, char *req, int len);
extern void os_send_udp(option_block *opts, char *req, int len);

#endif
