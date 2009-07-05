/* demo plugin - does some skeleton work */

#include <stdio.h>

#include "sfuzz-plugin.h"

char *example_name()
{
    return "sfuzz-plugin-example";
}

char *example_version()
{
    return "0.5";
}

int example_capex()
{
    return PLUGIN_PROVIDES_POST_FUZZ; /*you can add a bunch here using |*/
}

void example_post_fuzz(option_block *opts)
{
    printf("postFuzz!\n");
}

/*start here*/
void plugin_init(plugin_provisor *pr)
{
    if(pr == NULL)
    {
        fprintf(stderr, "error, unable to init plugin due to fatal call!\n");
        return;
    }
    
    pr->name = example_name;
    pr->version = example_version;

    pr->post_fuzz = example_post_fuzz;
}
