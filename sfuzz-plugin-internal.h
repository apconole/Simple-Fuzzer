#ifndef SFUZZ_PLUGIN_INTERNAL_H__
#define SFUZZ_PLUGIN_INTERNAL_H__

/* only one "plugin" will be loaded at a time. */
extern plugin_provisor *g_plugin;

#ifdef __WIN32__
#ifdef __PLUGIN_BUILD__
plugin_provisor *g_plugin; /* needed for win32 issue */
#endif
#endif

/**
 * \brief Display the sfuzz search paths (for debug only)
 */

#endif

