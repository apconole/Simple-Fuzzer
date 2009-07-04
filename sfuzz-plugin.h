#ifndef __SFUZZ_PLUGIN_DEFS_H__
#define __SFUZZ_PLUGIN_DEFS_H__

#include "options-block.h"

#define PLUGIN_PROVIDES_LINE_OPTS         0x00000001
#define PLUGIN_PROVIDES_PAYLOAD_PARSE     0x00000002
#define PLUGIN_PROVIDES_TRANSPORT_TYPE    0x00000004
#define PLUGIN_PROVIDES_FUZZ_MODIFICATION 0x00000008
#define PLUGIN_PROVIDES_POST_FUZZ         0x00000010

typedef int  (*plugin_capex)();

typedef void (*plugin_transport)(option_block *opts, void *d, int len);

typedef int (*plugin_payload_transform)(option_block *opts, void *i, int il, 
                                        void *o, int ol);

typedef int (*plugin_fuzz_transform)(option_block *opts, void *inf, int infl, 
                                     void *of, int ofl);

typedef void (*post_fuzz_mod)(option_block *opts);

typedef char *(*plugin_name)();
typedef char *(*plugin_version)();

typedef struct _pprovisor
{
    plugin_capex             capex;
    plugin_transport         trans;
    plugin_payload_transform payload_trans;
    plugin_fuzz_transform    fuzz_trans;
    post_fuzz_mod            post_fuzz;

    plugin_name              name;
    plugin_version           version;

} plugin_provisor;

#endif
