#ifndef __CONNECTION_H_
#define __CONNECTION_H_

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ipfilter.h"
#include "list.h"
#include "mempool.h"
#include "ups.h"
#include "http.h"

enum conn_state{
    CLIENT_CONNECT_ESTABLISH = 0,
    READING_CLIENT,
    CONNECTING_UPS,
    CONNECT_UPS_ESTABLISH,
    WRITTING_UPS,
    READING_UPS,
    WRITTING_CLIENT,
    READ_UPS_WRITE_CLIENT,
    KEEP_ALIVE_IDLE,
    STATE_END
};

enum conn_proc_status{
    OP_FAIL = -99,
    OP_UNKNOWN,
    OP_SUCCESS = 0,
    OP_CLIENT_ABORT,
    OP_NEED_WAIT,
    OP_FINISH,
    OP_CLOSING
};

enum epoll_state{
    EP_STATE_NONE = 0,
    EP_STATE_READ,
    EP_STATE_WRITE,
    EP_STATE_ERROR
};

enum epoll_role{
    ROLE_CLIENT = 0,
    ROLE_UPS,
    ROLE_LISTEN,
    ROLE_CMD
};

typedef struct _conn_stat{
    uint32_t read_client_times;
    uint32_t read_ups_times;
    uint32_t keepalive_requests;
} conn_stat_t;

typedef struct _connpool_t{
    struct list_head keep_alive_head;
    struct list_head read_client_head;
    struct list_head connect_ups_head;
    struct list_head write_ups_head;
    struct list_head connect_ups_retry_head;
    struct list_head write_client_head;
    struct list_head closing_head;
} connpool_t;

typedef struct _ep_handler_t{
    void *conn;
    int fd;
    int role;
    int epstate;
}ep_handler_t;

typedef struct _connection_t{
    uint32_t seqno;
    uint32_t clientip;
    uint32_t clientport;
    ups_t    upstream;
    ep_handler_t cli;
    ep_handler_t ups;
    struct list_head link;
    time_t state_start_time;
    buf_t inbuf;
    buf_t outbuf;
    int state;
    int closing;
    http_req_t request;
    http_resp_t response;
    int reset_client;
    int keepalive;
    conn_stat_t conn_stat;
} connection_t;

int connection_init(size_t count);
connection_t *connection_alloc(int clientfd, uint32_t clientip, uint32_t clientport);
int connection_dealloc(connection_t *c);
int connection_close(connection_t *c);
int connection_close_half(connection_t *c);
int connection_set_closing(connection_t *c);
int connection_set_closing_reset_client(connection_t *c);

inline int add_connection_write_client_queue(connection_t *c);
inline int add_connection_connectups_queue(connection_t *c);
inline int add_connection_writeups_queue(connection_t *c);
inline int add_connection_connectups_retry_queue(connection_t *c);
inline int add_connection_readclient_queue(connection_t *c);
inline int add_connection_keepalive_queue(connection_t *c);

#endif
