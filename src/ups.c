#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "list.h"
#include "hash.h"
#include "ups.h"
#include "log.h"

#define FAILSCORE 20
#define RETRYTIMER 10
#define FAILSTEP 2
#define SUCCSTEP 1

static ups_tree_t ups_tree;
static int ups_tree_inited = 0;

static int ups_host_node_init(ups_host_t *t, const char *host);
static int ups_uri_node_init(ups_uri_t *t, const char *uri);
static int ups_node_init(ups_node_t *t,const char *srv,const char *port);

extern log_t *g_log;

/*
 * fun: init ups tree
 * arg: 
 * ret: success=0, error=-1
 *
 */

int ups_tree_init(void)
{
    int i, ret;

    if(ups_tree_inited){
        log(g_log, "error, ups_tree inited again\n");
        return -1;
    }

    for(i = 0; i < HOST_BUCKET_NUM; i++){
        INIT_LIST_HEAD(&(ups_tree.head[i]));
    }

    // init default proxy for hosts who are not defined
    ret = ups_uri_node_init(&(ups_tree.def), "");
    if(ret < 0){
        log(g_log, "ups_uri_node_init error\n");
        return -1;
    }

    ups_tree_inited = 1;

    return 0;
}

/*
 * fun: init ups
 * arg: ups pointer
 * ret: success=0, error=-1
 *
 */

int ups_init(ups_t *u)
{
    if(u == NULL){
        log(g_log, "ups_init error\n");
        return -1;
    }

    u->ups_list = NULL;
    u->srv = NULL;
    u->port = NULL;
    u->index = 0;
    u->retry = 0;
    u->maxretry = 0;
    u->balance = BALANCE_UNAVAILABLE;

    return 0;
}

/*
 * fun: register ups
 * arg: host, uri, srv, port
 * ret: success=0, error=-1
 *
 */

int ups_register(char *host, char *uri, char *srv, char *port)
{
    int index;
    struct list_head *head, *pos;
    ups_host_t *hostptr = NULL;
    ups_uri_t *uriptr = NULL;
    ups_node_t *nodeptr = NULL;

    if(!ups_tree_inited){
        log(g_log, "ups_tree not inited\n");
        return -1;
    }

    if( (srv == NULL) || (port == NULL) ){
        log(g_log, "ups_register error\n");
        return -1;
    }

    if(host == NULL){
        uriptr = &(ups_tree.def);
    } else {
        index = mmhash64(host, strlen(host)) % HOST_BUCKET_NUM;
        head = &(ups_tree.head[index]);

        list_for_each(pos, head){
            hostptr = list_entry(pos, ups_host_t, link);
            if(!strcmp(host, hostptr->host)){
                break;
            } else {
                hostptr = NULL;
            }
        }

        if(!hostptr){
            hostptr = malloc(sizeof(ups_host_t));
            if(hostptr == NULL){
                log(g_log, "host[%s] ups_host_t malloc error, %s\n", \
                                                host, strerror(errno));
                return -1;
            }

            ups_host_node_init(hostptr, host);
            list_add_tail(&(hostptr->link), head);
        }

        if(uri == NULL){
            uriptr = &(hostptr->def);
        } else {
            head = &(hostptr->head);
            list_for_each(pos, head){
                uriptr = list_entry(pos, ups_uri_t, link);
                if(!strcmp(uri, uriptr->uri)){
                    break;
                } else {
                    uriptr = NULL;
                }
            }

            if(!uriptr){
                uriptr = malloc(sizeof(ups_uri_t));
                if(uriptr == NULL){
                    log(g_log, "host[%s] uri[%s] ups_uri_t malloc error, %s\n", \
                                        host, uri, strerror(errno));
                    return -1;
                }

                ups_uri_node_init(uriptr, uri);
                list_add_tail(&(uriptr->link), head);
            }

            if(uriptr->node_num >= MAX_NODE_PER_URI){
                log(g_log, "host[%s] uri[%s] register error, reach maxnode[%d]\n", \
                                            host, uri, MAX_NODE_PER_URI);
                return -1;
            }
        }
    }

    nodeptr = &(uriptr->node[uriptr->node_num]);
    ups_node_init(nodeptr, srv, port);

    uriptr->node_num++;

    return 0;
}

/*
 * fun: search ups
 * arg: ups pointer, client ip, host, uri, cookie
 * ret: success=0, error=-1
 *
 */

inline int ups_search(ups_t *u, uint32_t ip, char *host, char *uri, char *cookie)
{
    int index, i, len;
    uint64_t key;
    struct list_head *head, *pos;
    ups_host_t *hostptr = NULL;
    ups_uri_t *uriptr = NULL;
    ups_node_t *nodeptr = NULL;

    if(!ups_tree_inited){
        log(g_log, "ups_tree not inited\n");
        return -1;
    }

    if( (u == NULL) || (ip == 0) || (host == NULL) || \
                               (uri == NULL) || (cookie == NULL) ){
        log(g_log, "ups_search parameter error\n");
        return -1;
    }

    if(u->balance == BALANCE_IP){
        return 0;
    }

    index = mmhash64(host, strlen(host)) % HOST_BUCKET_NUM;
    head = &(ups_tree.head[index]);

    list_for_each(pos, head){
        hostptr = list_entry(pos, ups_host_t, link);
        if(!strcmp(host, hostptr->host)){
            break;
        } else {
            hostptr = NULL;
        }
    }

    if(!hostptr){
        uriptr = &(ups_tree.def);
    } else {
        head = &(hostptr->head);
        list_for_each(pos, head){
            uriptr = list_entry(pos, ups_uri_t, link);
            if(!strncmp(uri, uriptr->uri, uriptr->uri_len)){
                break;
            } else {
                uriptr = NULL;
            }
        }

        if(!uriptr){
            uriptr = &(hostptr->def);
        }
    }

    switch(uriptr->balance)
    {
        case BALANCE_RR:
            key = random();
            break;
        case BALANCE_IP:
            key = ip;
            break;
        case BALANCE_COOKIE:
            len = strlen(cookie);
            if(len == 0){
                key = ip;
            } else {
                key = mmhash64(cookie, len);
            }
            break;
        default:
            key = ip;
    }

    if(uriptr->node_num == 0){
        log(g_log, "ups_search error, node_num[%d]\n", uriptr->node_num);
        return -1;
    }

    index = key % (uriptr->node_num);

    for(i = 0; i < uriptr->node_num; i++, index++){
        nodeptr = &(uriptr->node[index % (uriptr->node_num)]);
        if(nodeptr->fail_score < FAILSCORE){
            break;
        } else {
            if(time(NULL) - nodeptr->fail_time >= RETRYTIMER){
                nodeptr->fail_time = time(NULL);
                break;
            }
        }
    }

    if(i == uriptr->node_num){
        nodeptr = &(uriptr->node[random() % (uriptr->node_num)]);
    }

    u->ups_list = uriptr;
    u->srv = nodeptr->srv;
    u->port = nodeptr->port;
    u->index = index % (uriptr->node_num);
    u->retry = 0;
    u->maxretry = uriptr->retry;
    u->balance = uriptr->balance;

    return 0;
}

/*
 * fun: search next ups
 * arg: ups pointer, client ip
 * ret: success=0, error=-1
 *
 */

int ups_search_next(ups_t *u, uint32_t ip)
{
    int index, node_num, i, ret;

    ups_uri_t *uriptr = NULL;
    ups_node_t *nodeptr = NULL;

    if(!ups_tree_inited){
        log(g_log, "ups_tree not inited\n");
        return -1;
    }

    if( (u == NULL) || (ip == 0) ){
        log(g_log, "ups_search_next parameter error\n");
        return -1;
    }

    uriptr = u->ups_list;
    node_num = uriptr->node_num;

    if( (uriptr == NULL) || (node_num == 0) ){
        return -1;
    }

    ret = ups_set_fail(u);
    if(ret < 0){
        log(g_log, "ups_set_fail error\n");
    }

    if(node_num == 1){
        log(g_log, "node_num[%d], return old ups\n", node_num);
        return 0;
    } else {
        index = (u->index + ip % node_num) % node_num;
    }

    for(i = 0; i < node_num; i++, index++){
        nodeptr = &(uriptr->node[index % node_num]);
        if(nodeptr->fail_score < FAILSCORE){
            break;
        } else {
            if(time(NULL) - nodeptr->fail_time >= RETRYTIMER){
                nodeptr->fail_time = time(NULL);
                break;
            }
        }
    }

    if(i == uriptr->node_num){
        log(g_log, "no ups available, return old ups\n", node_num);
        return 0;
    }

    u->ups_list = uriptr;
    u->srv = nodeptr->srv;
    u->port = nodeptr->port;
    u->index = index % node_num;
    u->retry++;
    u->maxretry = uriptr->retry;

    return 0;
}

/*
 * fun: set ups balance method
 * arg: host, uri, balance method
 * ret: success=0, error=-1
 *
 */

int ups_set_balance(char *host, char *uri, int balance)
{
    int index;
    struct list_head *head, *pos;
    ups_host_t *hostptr = NULL;
    ups_uri_t *uriptr = NULL;

    if(!ups_tree_inited){
        log(g_log, "ups_tree not inited\n");
        return -1;
    }

    if(host){
        index = mmhash64(host, strlen(host)) % HOST_BUCKET_NUM;
        head = &(ups_tree.head[index]);

        list_for_each(pos, head){
            hostptr = list_entry(pos, ups_host_t, link);
            if(!strcmp(host, hostptr->host)){
                break;
            } else {
                hostptr = NULL;
            }
        }

        if(!hostptr){
            log(g_log, "host[%s] not registered\n", host);
            return -1;
        }

        if(uri){
            head = &(hostptr->head);
            list_for_each(pos, head){
                uriptr = list_entry(pos, ups_uri_t, link);
                if(!strcmp(uri, uriptr->uri)){
                    break;
                } else {
                    uriptr = NULL;
                }
            }
        } else {
            uriptr = &(hostptr->def);
        }
    } else {
        uriptr = &(ups_tree.def);
    }

    if(!uriptr){
        log(g_log, "host[%s] registered, uri[%s] not registered\n", \
                                                        host, uri);
        return -1;
    }

    switch(balance)
    {
        case BALANCE_RR:
            break;
        case BALANCE_IP:
            break;
        case BALANCE_COOKIE:
            break;
        default:
            return -1;
    }
    uriptr->balance = balance;

    return 0;
}

/*
 * fun: set ups maxretry
 * arg: host, uri, retry
 * ret: success=0, error=-1
 *
 */

int ups_set_maxretry(char *host, char *uri, int retry)
{
    int index;
    struct list_head *head, *pos;
    ups_host_t *hostptr = NULL;
    ups_uri_t *uriptr = NULL;

    if(!ups_tree_inited){
        log(g_log, "ups_tree not inited\n");
        return -1;
    }

    if(host){
        index = mmhash64(host, strlen(host)) % HOST_BUCKET_NUM;
        head = &(ups_tree.head[index]);

        list_for_each(pos, head){
            hostptr = list_entry(pos, ups_host_t, link);
            if(!strcmp(host, hostptr->host)){
                break;
            } else {
                hostptr = NULL;
            }
        }

        if(!hostptr){
            log(g_log, "host[%s] not registered\n", host);
            return -1;
        }

        if(uri){
            head = &(hostptr->head);
            list_for_each(pos, head){
                uriptr = list_entry(pos, ups_uri_t, link);
                if(!strcmp(uri, uriptr->uri)){
                    break;
                } else {
                    uriptr = NULL;
                }
            }
        } else {
            uriptr = &(hostptr->def);
        }
    } else {
        uriptr = &(ups_tree.def);
    }

    if(!uriptr){
        log(g_log, "host[%s] registered, uri[%s] not registered\n", \
                                                        host, uri);
        return -1;
    }

    uriptr->retry = retry;

    return 0;
}

/*
 * fun: set ups success
 * arg: ups pointer
 * ret: success=0, error=-1
 *
 */

inline int ups_set_success(ups_t *u)
{
    ups_node_t *node;
    ups_uri_t *uriptr;

    if(!ups_tree_inited){
        log(g_log, "ups_tree not inited\n");
        return -1;
    }

    if(u == NULL){
        log(g_log, "ups_set_success parameter error\n");
        return -1;
    }

    if( (uriptr = u->ups_list) == NULL ){
        return -1;
    }
    node = &(uriptr->node[u->index]);

    node->fail_score -= SUCCSTEP;
    if(node->fail_score <= 0){
        node->fail_score = 0;
    }

    return 0;
}

/*
 * fun: set ups fail
 * arg: ups pointer
 * ret: success=0, error=-1
 *
 */

inline int ups_set_fail(ups_t *u)
{
    ups_node_t *node;
    ups_uri_t *uriptr;

    if(!ups_tree_inited){
        log(g_log, "ups_tree not inited\n");
        return -1;
    }

    if(u == NULL){
        log(g_log, "ups_set_fail parameter error\n");
        return -1;
    }

    if( (uriptr = u->ups_list) == NULL ){
        return -1;
    }

    node = &(uriptr->node[u->index]);

    node->fail_score += FAILSTEP;
    if(node->fail_score >= FAILSCORE){
        log(g_log, "ups[%s:%s] set unavailable\n", node->srv, node->port);
        node->fail_score = FAILSCORE;
        node->fail_time = time(NULL);
    }

    return 0;
}

/*
 * fun: int ups_host_node
 * arg: ups_host_t pointer, host
 * ret: success=0, error=-1
 *
 */

static int ups_host_node_init(ups_host_t *t, const char *host)
{
    int ret;

    strncpy(t->host, host, MAX_HOST_LEN);
    INIT_LIST_HEAD(&(t->head));

    // init default proxy for uri who are not defined
    ret = ups_uri_node_init(&(t->def), "");
    if(ret < 0){
        log(g_log, "host[%s], ups_uri_node_init error\n", host);
        return -1;
    }

    return 0;
}

/*
 * fun: int ups_uri_t
 * arg: ups_uri_t pointer, uri
 * ret: always return 0
 *
 */

static int ups_uri_node_init(ups_uri_t *t, const char *uri)
{
    strncpy(t->uri, uri, MAX_URI_LEN);
    t->node_num = 0;
    t->balance = BALANCE_IP;
    t->uri_len = strlen(t->uri);
    t->retry = 0;

    return 0;
}

/*
 * fun: init ups_node
 * arg: ups_node_t pointer, srv, host
 * ret: always return 0
 *
 */

static int ups_node_init(ups_node_t *t, const char *srv, const char *port)
{
    strncpy(t->srv, srv, MAX_SRV_LEN);
    strncpy(t->port, port, MAX_PORT_LEN);
    t->fail_score = 0;
    t->fail_time = 0;

    return 0;
}
