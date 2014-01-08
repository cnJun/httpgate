#ifndef _UPS_H_
#define _UPS_H_

#include <stdint.h>
#include <time.h>
#include "list.h"

#define HOST_BUCKET_NUM 271
#define MAX_NODE_PER_URI 1024
#define MAX_SRV_LEN 128
#define MAX_PORT_LEN 16
#define MAX_URI_LEN 1024
#define MAX_HOST_LEN 1024

enum{
    BALANCE_UNAVAILABLE,
    BALANCE_RR = 0,
    BALANCE_IP,
    BALANCE_COOKIE
};

typedef struct ups_node{                                               
    char srv[MAX_SRV_LEN];
    char port[MAX_PORT_LEN];
    int fail_score;
    time_t fail_time;
} ups_node_t;

typedef struct ups_uri{
    char uri[MAX_URI_LEN];
    // uri_len: performance for uri compare
    int uri_len;
    ups_node_t node[MAX_NODE_PER_URI];
    int node_num;
    struct list_head link;
    int balance;
    int retry;
} ups_uri_t;

typedef struct ups_host{
    char host[MAX_HOST_LEN];
    struct list_head link;
    struct list_head head;
    ups_uri_t def;
} ups_host_t;

typedef struct ups_tree{
    struct list_head head[HOST_BUCKET_NUM];
    ups_uri_t def;
} ups_tree_t;

typedef struct ups{
    ups_uri_t *ups_list;
    char *srv;
    char *port;
    int index;
    int retry;
    int maxretry;
    int balance;
} ups_t;

int ups_tree_init(void);
int ups_init(ups_t *u);
int ups_register(char *host, char *uri, char *srv, char *port);

inline int ups_search(ups_t *u, uint32_t ip, char *host, char *uri, char *cookie);
int ups_search_next(ups_t *u, uint32_t ip);
int ups_set_balance(char *host, char *uri, int balance);
int ups_set_maxretry(char *host, char *uri, int retry);

inline int ups_set_success(ups_t *u);
inline int ups_set_fail(ups_t *u);

#endif
