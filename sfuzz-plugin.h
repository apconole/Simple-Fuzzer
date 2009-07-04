#ifndef __SFUZZ_PLUGIN_DEFS_H__
#define __SFUZZ_PLUGIN_DEFS_H__

#include "options-block.h"

#define PLUGIN_PROVIDES_LINE_OPTS         0x00000001
#define PLUGIN_PROVIDES_PAYLOAD_PARSE     0x00000002
#define PLUGIN_PROVIDES_TRANSPORT_TYPE    0x00000004
#define PLUGIN_PROVIDES_FUZZ_MODIFICATION 0x00000008
#define PLUGIN_PROVIDES_POST_FUZZ         0x00000010

typedef int  (*p_capex)() plugin_capex;

typedef void (*p_transport)(option_block *opts, void *d, int len) 
    plugin_transport;

typedef int (*p_payloader)(option_block *opts, void *i, int il, void *o, int ol)
    plugin_payload_transform;

typedef int (*p_fuzz_mod)(option_block *opts, void *inf, int infl, void *of,
                          int ofl) payload_fuzz_transform;

typedef void (*p_post_fuzz)(option_block *opts) post_fuzz_mod;

typedef char *(*p_plugin_name)()    plugin_name;
typedef char *(*p_plugin_version)() plugin_version;

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
