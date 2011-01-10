/**
 * SFUZZ oracle
 * this file implements the API side of the oracle.
 * sfuzz_oracle_daemon.c holds the implementation of the oracle daemon
 * sfuzz_oracle_client.c holds the implementation of a generic querying 
 *                       client
 */

/**
 * IMPORTANT NOTE:
 * We need to use ptrace() on unix-y systems
 * and the mswin debug facilities on windows
 */

