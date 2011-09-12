#ifndef __SFUZZ_ORACLE_H__
#define __SFUZZ_ORACLE_H__

#include <stdint.h>

#include "sfuzz.h"

// Ensure that the sfuzz_oracle_message type is sufficient for network 
// transmission

PACKED_ATTRIBUTE(                               \
    struct sfuzz_oracle_message                 \
    {                                           \
        uint8_t   msg_id;                       \
        uint32_t  msg_flags;                    \
        uint32_t  msg_length;                   \
        uint32_t  msg_version;                  \
        uint8_t  *data;                         \
    }) ;                                         

typedef struct sfuzz_oracle_message sfuzz_oracle_message_t;

/**
 * Following enum lists all the available messages that can be sent through the
 * oracle interface. NOTE: The oracle will have a client and server side 
 * interface, where the client generally requests, and the server generally
 * responds. HOWEVER, the notifier message type is reserved to send alerts to
 * out of the request-response paradigm.
 * The NOTIFIER message, then, does require a transmission of NOTIFIER_ACK to
 * ensure that the requisite alert was received (if it's a "required" type).
 */
enum SFuzzOracleMessageId
{
    SFUZZ_MSG_REQUEST_REGISTER,

    SFUZZ_MSG_REQUEST_PROCESS_INFO_TRACE,
    SFUZZ_MSG_REQUEST_PROCESS_STATUS,
    SFUZZ_MSG_REQUEST_PROCESS_RESTART,
    SFUZZ_MSG_REQUEST_PROCESS_STOP,
    SFUZZ_MSG_REQUEST_PROCESS_START,
    SFUZZ_MSG_REQUEST_PROCESS_TAINT_TRACE,
    
    SFUZZ_MSG_REPLY_ERROR_GENERIC,
    SFUZZ_MSG_REPLY_PROCESS_INFO_TRACE_UPDATE,
    SFUZZ_MSG_REPLY_PROCESS_INFO_TRACE_UNAVAILABLE,
    SFUZZ_MSG_REPLY_PROCESS_RESTART_SUCCESSFUL,
    SFUZZ_MSG_REPLY_PROCESS_RESTART_FAILED,
    SFUZZ_MSG_REPLY_PROCESS_STOP_SUCCESSFUL,
    SFUZZ_MSG_REPLY_PROCESS_STOP_FAILED,
    SFUZZ_MSG_REPLY_PROCESS_START_SUCCESSFUL,
    SFUZZ_MSG_REPLY_PROCESS_START_FAILED,
    SFUZZ_MSG_REPLY_PROCESS_TAINT_INFO_REPLY,
    SFUZZ_MSG_REPLY_PROCESS_TAINT_INFO_UNAVAILABLE,
    
    SFUZZ_MSG_NOTIFY_EVENT,
    SFUZZ_MSG_NOTIFY_ACK,

    SFUZZ_MSG_MAX /* MUST ALWAYS APPEAR AT THE END */
};

extern int32_t sfuzz_oracle_encode_registration_request(
    /* these are always required */
    uint8_t *buf, uint8_t in_len, uint8_t *out_len, 
    uint8_t transaction_id, uint8_t *secret_key, uint32_t secret_key_len,
    /* REG_REQ message info */
    uint8_t listener_id, uint8_t* process_name, uint32_t process_name_len);

extern int32_t sfuzz_oracle_encode_reply_error_generic(
    /* these are always required */
    uint8_t *buf, uint8_t in_len, uint8_t *out_len, 
    uint8_t transaction_id, uint8_t *secret_key, uint32_t secret_key_len,
    /* REPLY_ERROR code */
    uint32_t error_code);


#define MONITORED_STATUS_STOPPED 1
#define MONITORED_STATUS_KILLED  2
#define MONITORED_STATUS_CONT    3

extern int32_t spawn_monitored(char *outfile, char *errfile, uint32_t, char *argv[]);
extern int32_t monitored_signal(uint32_t signal, uint8_t status, int32_t pid);
extern int32_t monitored_exit  (int32_t  exit);
extern int32_t term_monitored ( int32_t id );

#endif
