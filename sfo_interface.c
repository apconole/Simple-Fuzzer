#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "options-block.h"

void
oracle_pre_fuzz(option_block *opts, void *req, int reqlen)
{
    printf("[DEBUG] emit pre-fuzz\n");
}

void
oracle_post_fuzz(option_block *opts, void *req, int reqlen)
{
    printf("[DEBUG] emit post-fuzz\n");
}
