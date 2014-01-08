/*
 * Copyright 2011-2013 Alibaba Group Holding Limited. All rights reserved.
 * Use and distribution licensed under the GPL license.
 *
 * Authors: XiaoJinliang <xiaoshi.xjl@taobao.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include "connection.h"
#include "list.h"
#include "genpool.h"
#include "ipfilter.h"
#include "log.h"
#include "http.h"
#include "iprange.h"
#include "timer.h"
#include "ups.h"
#include "conf.h"

static connpool_t *connpool_handler;
static genpool_handler_t *g;
static int connpool_inited = 0;

static uint32_t connection_seqno = 0;

extern conf_global_t g_global_conf;
extern conf_filter_t g_filter_conf;

extern log_t *g_log;
extern iprange_t *g_whitelist, *g_blacklist;
extern int g_epfd;

static inline int add_connection_to_queue(connection_t *c, struct list_head *head);
static int connection_close_client(connection_t *c);
static int connection_close_ups(connection_t *c);
static int connection_close_reset_client(connection_t *c);

static int connection_stat_init(connection_t *c);
static int connection_stat_info(connection_t *c, char *buf, size_t len);
static int _connection_timeout_clean(struct list_head *head, int timeout,
                                        const char *info, int reset, int max);

static int connection_keep_alive_clean_timer(unsigned long max);
static int connection_read_client_clean_timer(unsigned long max);
static int connection_connect_ups_clean_timer(unsigned long max);
static int connection_write_ups_clean_timer(unsigned long max);
static int connection_connect_ups_retry_timer(unsigned long max);
static int connection_write_client_clean_timer(unsigned long max);
static int connection_closing_clean_timer(unsigned long max);

static int connection_pool_status_timer(unsigned long arg);

/*
 * fun: connection pool init
 * arg: max connection be inited
 * ret: success=0 error=-1
 */
int connection_init(size_t count)
{
    int i, fd;
    connpool_t *ptr;

    if( (ptr = malloc(sizeof(connpool_t))) == NULL ){
        return -1;
    }

    if( (g = genpool_init(sizeof(connection_t), count)) == NULL ){
        free(ptr);
        return -1;
    }

    INIT_LIST_HEAD(&(ptr->keep_alive_head));
    INIT_LIST_HEAD(&(ptr->read_client_head));
    INIT_LIST_HEAD(&(ptr->connect_ups_head));
    INIT_LIST_HEAD(&(ptr->write_ups_head));
    INIT_LIST_HEAD(&(ptr->connect_ups_retry_head));
    INIT_LIST_HEAD(&(ptr->write_client_head));
    INIT_LIST_HEAD(&(ptr->closing_head));

    connpool_handler = ptr;

    connpool_inited = 1;

    if(timer_register(connection_keep_alive_clean_timer, 30, \
                        "connection_keep_alive_clean_timer", 1) < 0){
        log(g_log, "connection_keep_alive_clean_timer register error\n");
        return -1;
    }

    if(timer_register(connection_read_client_clean_timer, 30, \
                        "connection_read_client_clean_timer", 1) < 0){
        log(g_log, "connection_read_client_clean_timer register error\n");
        return -1;
    }

    if(timer_register(connection_connect_ups_clean_timer, 30, \
                        "connection_connect_ups_clean_timer", 1) < 0){
        log(g_log, "connection_connect_ups_clean_timer register error\n");
        return -1;
    }

    if(timer_register(connection_write_ups_clean_timer, 30, \
                        "connection_write_ups_clean_timer", 1) < 0){
        log(g_log, "connection_write_ups_clean_timer register error\n");
        return -1;
    }

    if(timer_register(connection_connect_ups_retry_timer, 30, \
                        "connection_connect_ups_retry_timer", 1) < 0){
        log(g_log, "connection_connect_ups_retry_timer register error\n");
        return -1;
    }

    if(timer_register(connection_write_client_clean_timer, 30, \
                        "connection_write_client_clean_timer", 1) < 0){
        log(g_log, "connection_write_client_clean_timer register error\n");
        return -1;
    }

    if(timer_register(connection_closing_clean_timer, 300, \
                        "connection_closing_clean_timer", 0) < 0){
        log(g_log, "connection_closing_clean_timer register error\n");
        return -1;
    }

    if(timer_register(connection_pool_status_timer, 0, \
                        "connection_pool_status_timer", 300) < 0){
        log(g_log, "connection_pool_status_timer register error\n");
        return -1;
    }

    return 0;
}

/*
 * fun: connection struct alloc
 * arg: init argument: client fd, client ip, client port
 * ret: success=ptr error=NULL
 */
connection_t *connection_alloc(int clientfd, uint32_t clientip, uint32_t clientport)
{
    int ret;
    connection_t *conn;

    if(connpool_inited == 0){
        log(g_log, "connection pool not inited\n");
        return NULL;
    }

    if( (conn = genpool_alloc_page(g)) == NULL ){
        return NULL;
    }

    if(connection_seqno == 0){
        // init connection seqno
        srand(getpid() * time(NULL));
        connection_seqno = rand();
        debug(g_log, "connection sequence number start %u\n", connection_seqno);
    }
    conn->seqno = connection_seqno++;

    conn->clientip = clientip;
    conn->clientport = clientport;

    ups_init(&(conn->upstream));

    conn->cli.conn = conn;
    conn->cli.fd = clientfd;
    conn->cli.role = ROLE_CLIENT;
    conn->cli.epstate = EP_STATE_NONE;

    conn->ups.conn = conn;
    conn->ups.fd = -1;
    conn->ups.role = ROLE_UPS;
    conn->ups.epstate = EP_STATE_NONE;

    INIT_LIST_HEAD(&(conn->link));

    conn->state_start_time = time(NULL);

    INIT_LIST_HEAD(&(conn->inbuf.buf_head));
    conn->inbuf.cur_read_mem_block = NULL;
    conn->inbuf.cur_write_mem_block = NULL;
    conn->inbuf.cur_rpos = 0;
    conn->inbuf.cur_wpos = 0;
    conn->inbuf.total_count = 0;

    INIT_LIST_HEAD(&(conn->outbuf.buf_head));
    conn->outbuf.cur_read_mem_block = NULL;
    conn->outbuf.cur_write_mem_block = NULL;
    conn->outbuf.cur_rpos = 0;
    conn->outbuf.cur_wpos = 0;
    conn->outbuf.total_count = 0;

    conn->state = CLIENT_CONNECT_ESTABLISH;

    conn->closing = 0;

    http_req_init(&(conn->request));
    http_resp_init(&(conn->response));

    conn->reset_client = 0;
    conn->keepalive = 0;

    connection_stat_init(conn);

    return conn;
}

/*
 * fun: connection struct dealloc
 * arg: connection pointer
 * ret: success=0
 */
int connection_dealloc(connection_t *c)
{

    if(connpool_inited == 0){
        log(g_log, "connection pool not inited\n");
        return -1;
    }
    
    genpool_release_page(g, c);

    return 0;
}

static int connection_close_client(connection_t *c)
{
    if(c->cli.fd >= 0){
        close(c->cli.fd);
        c->cli.fd = -1;
    }

    buf_clean_memblock(&(c->inbuf));

    return 0;
}

static int connection_close_ups(connection_t *c)
{
    if(c->ups.fd >= 0){
        close(c->ups.fd);
        c->ups.fd = -1;
    }

    buf_clean_memblock(&(c->outbuf));

    return 0;
}

static int connection_close_reset_client(connection_t *c)
{

    struct linger li;

    li.l_onoff = 1;
    li.l_linger = 0;

    if(c->cli.fd >= 0){
        if (setsockopt(c->cli.fd, SOL_SOCKET, SO_LINGER, \
                    (char *) &li, sizeof(struct linger)) < 0) {
            log(g_log, "conn[%u] setsockopt error\n", c->seqno);
        }
        close(c->cli.fd);
        c->cli.fd = -1;
    }

    buf_clean_memblock(&(c->inbuf));

    return 0;
}

int connection_close_half(connection_t *c)
{
    if(c->ups.fd >= 0){
        close(c->ups.fd);
        c->ups.fd = -1;
    }

    buf_clean_memblock(&(c->outbuf));

    return 0;
}

/*
 * fun: connection close.if client is abnormal, it will be reset
 * arg: connection ptr
 * ret: success=0
 */
int connection_close(connection_t *c)
{
    if(c->reset_client){
        connection_close_reset_client(c);
    } else {
        connection_close_client(c);
    }
    connection_close_ups(c);

    return 0;
}

/*
 * fun: connection set closing, connection only be closed in close_timer
 * arg: connection pointer
 * ret: success=0
 */
int connection_set_closing(connection_t *c)
{
    char buf[4096];

    c->closing = 1;

    list_del_init(&(c->link));
    list_add_tail(&(c->link), &(connpool_handler->closing_head));

    connection_stat_info(c, buf, sizeof(buf));
    debug(g_log, "conn[%u] %s\n", c->seqno, buf);

    return 0;
}

/*
 * fun: connection set closing and set client be reset
 * arg: connection pointer
 * ret: success=0
 */
int connection_set_closing_reset_client(connection_t *c)
{
    char buf[4096];

    c->closing = 1;
    c->reset_client = 1;

    list_del_init(&(c->link));
    list_add_tail(&(c->link), &(connpool_handler->closing_head));

    connection_stat_info(c, buf, sizeof(buf));
    debug(g_log, "conn[%u] %s\n", c->seqno, buf);

    return 0;
}

/*
 * fun: connection timeout clean
 * arg: max connection be cleaned once
 * ret: success=0 error=-1
 */
static int _connection_timeout_clean(struct list_head *head, int timeout,
                                        const char *info, int reset, int max)
{
    int ret, count = 0;
    char ip[32];
    struct list_head *pos, *n;
    connection_t *c;
    time_t now = time(NULL);

    if(connpool_inited == 0){
        log(g_log, "connection pool not inited\n");
        return -1;
    }

    list_for_each_safe(pos, n, head){
        if(count >= max){
            return count;
        }
        c = list_entry(pos, connection_t, link);
        if(now - c->state_start_time > timeout){
            ret = ipint2str(ip, sizeof(ip), c->clientip);
            if(ret < 0){
                log(g_log, "conn[%u] ipint2str error\n", c->seqno);
            } else {
                log(g_log, "conn[%u] client[%s:%u] %s\n", c->seqno, ip, c->clientport, info);
            }
            list_del_init(pos);
            if(reset){
                connection_set_closing_reset_client(c);
            } else {
                connection_set_closing(c);
            }
            count++;
        } else {
            break;
        }
    }

    return count;
}

/*
 * fun: connection keepalive timer
 * arg: max connection be cleaned once
 * ret: success=0 error=-1
 */
static int connection_keep_alive_clean_timer(unsigned long max)
{
    return _connection_timeout_clean(&(connpool_handler->keep_alive_head),
                                     g_global_conf.keepalive_timeout,
                                     "keep alive timeout", 
                                     0,
                                     max);
}

/*
 * fun: connection read client timer
 * arg: max connection be cleaned once
 * ret: success=0 error=-1
 */
static int connection_read_client_clean_timer(unsigned long max)
{
    return _connection_timeout_clean(&(connpool_handler->read_client_head),
                                     g_global_conf.read_client_timeout,
                                     "read client timeout", 
                                     1,
                                     max);
}

/*
 * fun: connection connect ups timer
 * arg: max connection be cleaned once
 * ret: success=0 error=-1
 */
static int connection_connect_ups_clean_timer(unsigned long max)
{
    int ret, count = 0, flag;
    char ip[32];
    struct list_head *pos, *n, *head;
    connection_t *c;
    time_t now = time(NULL);

    if(connpool_inited == 0){
        log(g_log, "connection not inited\n");
        return -1;
    }

    head = &(connpool_handler->connect_ups_head);
    list_for_each_safe(pos, n, head){
        if(count >= max){
            return count;
        }
        c = list_entry(pos, connection_t, link);
        if(now - c->state_start_time >= g_global_conf.connect_ups_timeout){
            ret = ipint2str(ip, sizeof(ip), c->clientip);
            if(ret < 0){
                log(g_log, "conn[%u] ipint2str error\n", c->seqno);
            } else {
                log(g_log, "conn[%u] ups[%s:%s] connect ups timeout\n", \
                                    c->seqno, c->upstream.srv, c->upstream.port);
            }
            add_connection_connectups_retry_queue(c);
            count++;
        } else {
            break;
        }
    }

    return count;
}

/*
 * fun: write ups clean timer
 * arg: max connection be cleaned once
 * ret: success=0 error=-1
 */
static int connection_write_ups_clean_timer(unsigned long max)
{
    return _connection_timeout_clean(&(connpool_handler->write_ups_head),
                                     g_global_conf.write_ups_timeout,
                                     "write ups timeout", 
                                     0,
                                     max);
}

/*
 * fun: connection connect ups retry timer
 * arg: max connection be retry
 * ret: success=0 error=-1
 */
static int connection_connect_ups_retry_timer(unsigned long max)
{
    int ret, count = 0, flag;
    char ip[32];
    struct list_head *pos, *n, *head;
    connection_t *c;
    ups_t *u;
    ep_handler_t *ups;
    struct epoll_event ev;

    if(connpool_inited == 0){
        log(g_log, "connection not inited\n");
        return -1;
    }

    head = &(connpool_handler->connect_ups_retry_head);
    list_for_each_safe(pos, n, head){
        if(count >= max){
            return count;
        }
        c = list_entry(pos, connection_t, link);
        ret = ipint2str(ip, sizeof(ip), c->clientip);
        if(ret < 0){
            log(g_log, "conn[%u] ipint2str error\n", c->seqno);
        }
        list_del_init(pos);
        connection_close_half(c);

        u = &(c->upstream);
        ups = &(c->ups);

        while(1){
            if(u->retry >= u->maxretry){
                log(g_log, "conn[%u] retrytimes[%d] connect ups fail\n", 
                                    c->seqno, 3);
                connection_set_closing(c);
                break;
            } else {
                u->retry++;
            }

            ret = ups_search_next(u, c->clientip);
            if(ret < 0){
                log(g_log, "conn[%u] no ups available\n", c->seqno);
                connection_set_closing(c);
                break;
            } else {
                log(g_log, "conn[%u] ups_search_next[%s:%s]\n", c->seqno, u->srv, u->port);
            }

            ret = connect_nonblock(u->srv, u->port, &flag);
            if(ret < 0){
                log(g_log, "conn[%u] connect ups error\n", c->seqno);
                continue;
            } else {
                if(flag == 1){
                    debug(g_log, "conn[%u] ups[%s:%s] connect ups success\n", \
                                            c->seqno, u->srv, u->port);
                    c->state = CONNECT_UPS_ESTABLISH;
                } else {
                    debug(g_log, "conn[%u] ups[%s:%s] connect ups in progress\n", 
                                            c->seqno, u->srv, u->port);
                    add_connection_connectups_queue(c);
                    c->state = CONNECTING_UPS;
                }

                ups->fd = ret;
                ups->epstate = EP_STATE_NONE;
                ev.events = EPOLLOUT;
                ev.data.ptr = ups;
                epoll_ctl(g_epfd, EPOLL_CTL_ADD,ups->fd,&ev);

                break;
            }
        }

        count++;
    }

    return count;
}

/*
 * fun: connection read ups write client timer
 * arg: max connection be cleaned once
 * ret: success=0 error=-1
 */
static int connection_write_client_clean_timer(unsigned long max)
{
    return 
    _connection_timeout_clean(&(connpool_handler->write_client_head),
                                     g_global_conf.write_client_timeout,
                                     "read ups write client timeout", 
                                     0,
                                     max);
}

/*
 * fun: connection close timer. connection really be closed
 * arg: max connection be cleaned once
 * ret: success=0 error=-1
 */
static int connection_closing_clean_timer(unsigned long max)
{
    int ret, count = 0;
    char ip[32];
    struct list_head *pos, *n, *head;
    connection_t *c;
    time_t now = time(NULL);

    if(connpool_inited == 0){
        log(g_log, "connection not inited\n");
        return -1;
    }

    head = &(connpool_handler->closing_head);
    list_for_each_safe(pos, n, head){
        if(count >= max){
            return count;
        }

        list_del_init(pos);
        c = list_entry(pos, connection_t, link);

        ret = ipint2str(ip, sizeof(ip), c->clientip);
        if(ret < 0){
            log(g_log, "conn[%u] ipint2str error\n", c->seqno);
        } else {
            if(c->reset_client){
                log(g_log, "conn[%u] connection reset\n", c->seqno);
            } else {
                debug(g_log, "conn[%u] connection closed\n", c->seqno);
            }
        }

        connection_close(c);
        connection_dealloc(c);
        count++;
    }

    return count;
}

/*
 * fun: move connection to other timer queue
 * arg: connection pointer & timer queue head
 * ret: success=0
 */
static inline int add_connection_to_queue(connection_t *c, struct list_head *head)
{
    time_t now = time(NULL);

    c->state_start_time = now;
    list_del_init(&(c->link));
    list_add_tail(&(c->link), head);

    return 0;
}

inline int add_connection_keepalive_queue(connection_t *c)
{
    if(connpool_inited == 0){
        log(g_log, "connection not inited\n");
        return -1;
    }
    return add_connection_to_queue(c, &(connpool_handler->keep_alive_head));
}

inline int add_connection_readclient_queue(connection_t *c)
{
    if(connpool_inited == 0){
        log(g_log, "connection not inited\n");
        return -1;
    }
    return add_connection_to_queue(c, &(connpool_handler->read_client_head));
}

inline int add_connection_connectups_queue(connection_t *c)
{
    if(connpool_inited == 0){
        log(g_log, "connection not inited\n");
        return -1;
    }
    return add_connection_to_queue(c, &(connpool_handler->connect_ups_head));
}

inline int add_connection_writeups_queue(connection_t *c)
{
    if(connpool_inited == 0){
        log(g_log, "connection not inited\n");
        return -1;
    }
    return add_connection_to_queue(c, &(connpool_handler->write_ups_head));
}

inline int add_connection_connectups_retry_queue(connection_t *c)
{
    if(connpool_inited == 0){
        log(g_log, "connection not inited\n");
        return -1;
    }
    return add_connection_to_queue(c, &(connpool_handler->connect_ups_retry_head));
}

inline int add_connection_write_client_queue(connection_t *c)
{
    if(connpool_inited == 0){
        log(g_log, "connection not inited\n");
        return -1;
    }
    return add_connection_to_queue(c, \
                        &(connpool_handler->write_client_head));
}

static int connection_stat_init(connection_t *c)
{
    conn_stat_t *stat; 

    stat = &(c->conn_stat);
    stat->read_client_times = 0;
    stat->read_ups_times = 0;
    stat->keepalive_requests = 0;

    return 0;
}

static int connection_stat_info(connection_t *c, char *buf, size_t len)
{
    int ret;
    conn_stat_t *stat; 

    stat = &(c->conn_stat);
    ret = snprintf(buf, len, "read_client[%u] read_ups[%u] keepalive_requests[%u]", 
                stat->read_client_times, stat->read_ups_times, stat->keepalive_requests);

    return ret;
}

static int connection_pool_status_timer(unsigned long arg)
{
    (void)arg;
    char buf[4096];

    genpool_status(g, buf, sizeof(buf));
    log(g_log, "%s\n", buf);

    return 0;
}
