/**
 * Simple Fuzz
 * Copyright (c) 2009, Aaron Conole <apconole@yahoo.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * Provides ssh transport facilities. This requires that you have the OpenSSH libraries
 * available for compiling.
 */

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>

#include "sfuzz-plugin.h"

BIO *ssl_bio = NULL;
plugin_provisor *ssl_plugin = NULL;

char *ssl_transport_name()
{
  return "SSL Transport layer";
}

char *ssl_transport_version()
{
  return "0.1";
}

void ssl_transport_close()
{
  BIO_reset(ssl_bio);
  BIO_free_all(ssl_bio);
  ssl_bio = NULL;
}

int ssl_transport_config(option_block *opts, char *l, int i)
{
  return 0;
}

int ssl_transport_insecure_send(option_block *opts, void *d, int i)
{
  FILE *log = stdout;
  char spec[2048] = {0};
  struct timeval tv;
  int sockfd;
  fd_set fds;
  unsigned long int to = MAX(100, opts->time_out);
  int ret;

  if(opts->fp_log)
    log = opts->fp_log;

  if(ssl_bio == NULL)
    {
      snprintf(spec, 2048, "%s:%d", opts->host_spec, opts->port);
      ssl_bio = BIO_new_connect(spec);
      if(ssl_bio == NULL)
	{
	  fprintf(stderr, "<ssl_transport:i-send> failure to acquire BIO: [%s]\n",
		  spec);
	  return -1;
	}
      
      if(BIO_do_connect(ssl_bio) <= 0)
	{
	  fprintf(stderr, "<ssl_transport:i-send> failure to simple connect to: [%s]\n",
		  spec);
	  return -1;
	}
    }
  
 retx:
  if(BIO_write(ssl_bio, d, i) <= 0)
    {
      if(!BIO_should_retry(ssl_bio))
	{
	  fprintf(stderr, "<ssl_transport:i-send> failure to transmit!\n");
	  ssl_transport_close();
	}
      goto retx;
    }
  
  if(opts->verbosity != QUIET)
    fprintf(log, "[%s] <ssl_transport:send> tx fuzz - scanning for reply.\n",
	    get_time_as_log());

    BIO_get_fd(ssl_bio, &sockfd);

    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);

    tv.tv_sec  = to / 1000;
    tv.tv_usec = (to % 1000) * 1000; /*time out*/

    ret = select(sockfd+1, &fds, NULL, NULL, &tv);
    if(ret > 0)
    {
        if(FD_ISSET(sockfd, &fds))
        {
            char buf[8192] = {0};
            int r_len = 0;

	    ret = BIO_read(ssl_bio, buf, 8192);
	    if(ret == 0)
	      {
		fprintf(stderr, "<ssl_transport:send> remote closed xon\n");
		ssl_transport_close();
	      }
	    else if(ret > 0)
	      {
		if(opts->verbosity != QUIET)
		  fprintf(log, 
			  "[%s] read:\n%s\n===============================================================================\n", 
			  get_time_as_log(),
			  buf);
	      }
	}
    }
    
    if((opts->close_conn) || ((opts->close_conn) && (!opts->forget_conn)))
      {
	ssl_transport_close();
      }
    
    mssleep(opts->reqw_inms);
    return 0;
}

int ssl_transport_capex()
{
  /*line parsing for certs/user-pass pairs, and the actual transport types*/
  return PLUGIN_PROVIDES_LINE_OPTS | PLUGIN_PROVIDES_TRANSPORT_TYPE;
}

void plugin_init(plugin_provisor *pr)
{
  if(pr == NULL)
    { /*this is checked by the calling function, but
        I'd like to reinforce the idea of paranoia*/
      fprintf(stderr, "<ssl_transport:init> null plugin object (perhaps a bug?!)\n");
      return;
    }

  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  pr->capex   = ssl_transport_capex;
  pr->name    = ssl_transport_name;
  pr->version = ssl_transport_version;
  pr->trans   = ssl_transport_insecure_send;
  pr->config  = ssl_transport_config;
}

