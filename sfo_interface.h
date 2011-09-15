#ifndef __SFO_INTERFACE_H__
#define __SFO_INTERFACE_H__

#include "options-block.h"

extern void oracle_pre_fuzz(option_block *opts, void *req, int reqlen);
extern void oracle_post_fuzz(option_block *opts, void *req, int reqlen);


#endif
