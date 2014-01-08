/*
 * Copyright 2011-2013 Alibaba Group Holding Limited. All rights reserved.
 * Use and distribution licensed under the GPL license.                   
 *
 * Authors: XiaoJinliang <xiaoshi.xjl@taobao.com>                          
 *
 */                                                                       

#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/epoll.h>
#include <errno.h>
#include "connection.h"
#include "list.h"
#include "log.h"
#include "http.h"
#include "ups.h"
#include "common.h"
#include "conf.h"

#define MAX_COOKIE_LEN 65536

extern conf_global_t g_global_conf;
extern conf_filter_t g_filter_conf;

extern int g_epfd;
extern log_t *g_log;

#define donothing() {}

/*
 * fun: state machine, it is most important function
 * arg: connection struct, return code
 * ret: always return 0
 *
 */

int state(connection_t *c, int *retcode)
{
    int ret, state, flag, n;
    ep_handler_t *cli, *ups;
    struct epoll_event ev;
    char request[16384], cookie[MAX_COOKIE_LEN], uri[1024];
    char *ups_ip, *ups_port;
    char ipstr[64], host[128];

    if(c->closing){
        *retcode = OP_CLOSING;
        return 0;
    }

    cli = &(c->cli);
    ups = &(c->ups);

    state = c->state;

    switch(state)
    {
        case CLIENT_CONNECT_ESTABLISH:
            if(g_filter_conf.ipfilter){
                ip_stat_refresh(c->clientip);
            }
            debug(g_log, "conn[%u] prepare read client\n", c->seqno);
            read_client_prepare(c);
            read_ups_prepare(c);

            http_req_init(&(c->request));
            http_resp_init(&(c->response));

            debug(g_log, "conn[%u] add to connection_readclient_queue\n", c->seqno);
            add_connection_readclient_queue(c);

            ev.data.ptr = cli;
            ev.events = EPOLLIN;
            // it will be fail when keepalive. it is normal
            epoll_ctl(g_epfd, EPOLL_CTL_ADD, cli->fd, &ev);

            c->state = READING_CLIENT;
            *retcode = OP_FINISH;

            c->conn_stat.keepalive_requests ++;

        case READING_CLIENT:
            if(cli->epstate == EP_STATE_READ){
                cli->epstate = EP_STATE_NONE;
                debug(g_log, "conn[%u] read_client begin\n", c->seqno);
                ret = read_client(c, retcode);
                c->conn_stat.read_client_times ++;
                if(ret < 0){
                    log(g_log, "conn[%u] read client error\n", c->seqno);
                    connection_set_closing_reset_client(c);
                } else if(ret == 0) {
                    if(*retcode == OP_NEED_WAIT){
                        donothing();
                    } else if(*retcode == OP_CLIENT_ABORT) {
                        debug(g_log, "conn[%u] client close\n", c->seqno);
                        connection_set_closing(c);
                    }
                } else {
                    // http packet is ready
                    ret = req_test_and_parse(&(c->inbuf), &(c->request));
                    if(ret < 0){
                        log(g_log, "conn[%u] request header error\n", c->seqno);
                        connection_set_closing_reset_client(c);
                    } else if(ret == 0){
                        *retcode = OP_NEED_WAIT;
                    } else {
                        *retcode = OP_SUCCESS;
                        if(g_filter_conf.cookiefilter){
                            n = get_header_elem(&(c->request), HTTP_COOKIE, cookie, MAX_COOKIE_LEN - 1);
                            if(n < 0){
                                log(g_log, "conn[%u] get http cookie error\n", c->seqno);
                                connection_set_closing(c);
                                break;
                            }
                            cookie[n] = '\0';
                            if(cookie_filter(cookie, n)){
                                log(g_log, "conn[%u] cookie filtered\n%s\n", c->seqno, cookie);
                                connection_set_closing_reset_client(c);
                                break;
                            }
                        }

                        n = get_header_elem(&(c->request), HTTP_URI, uri, sizeof(uri));
                        if(n < 0){
                            log(g_log, "conn[%u] get http uri error\n", c->seqno);
                            connection_set_closing(c);
                            break;
                        }

                        n = get_header_elem(&(c->request), HTTP_HOST, host, sizeof(host));
                        if(n < 0){
                            log(g_log, "conn[%u] get http host error\n", c->seqno);
                            connection_set_closing(c);
                            break;
                        }

                        if( (ret = ipint2str(ipstr, sizeof(ipstr), c->clientip)) < 0 ){
                            log(g_log, "conn[%u] ipint2str error\n", c->seqno);
                        }

                        http_req_append_clientip(&(c->request), c->clientip);
                        http_req_header_dump(&(c->request), request, sizeof(request));
                        info(g_log, "conn[%u] http request header\n%s\n", c->seqno, request);

                        if(!strncasecmp(c->request.header.ver, "HTTP/1.1", 8)){
                            if(!strncasecmp(c->request.header.conntype, "close", 5)){
                                c->keepalive = 0;
                            } else {
                                c->keepalive = 1;
                            }
                        } else {
                            if(!strncasecmp(c->request.header.conntype, "keep-alive", 10)){
                                c->keepalive = 1;
                            } else {
                                c->keepalive = 0;
                            }
                        }

                        ret = ups_search(&(c->upstream), c->clientip, host, uri, cookie);
                        if(ret < 0){
                            log(g_log, "conn[%u] ups search error\n", c->seqno);
                            connection_set_closing(c);
                            break;
                        } else {
                            ups_ip = c->upstream.srv;
                            ups_port = c->upstream.port;
                        }

                        debug(g_log, "conn[%u] ups[%s:%s] search success\n", c->seqno, ups_ip, ups_port);
                        log(g_log, "conn[%u] client[%s:%d] host[%s] uri[%s] ups[%s:%s]\n", 
                                            c->seqno, ipstr, c->clientport, host, uri, ups_ip, ups_port);

                        ret = connect_nonblock(ups_ip, ups_port, &flag);
                        if(ret < 0){
                            *retcode = OP_FAIL;
                            log(g_log, "conn[%u] connect ups error\n", c->seqno);
                            add_connection_connectups_retry_queue(c);
                            c->state = CONNECTING_UPS;
                        } else {
                            debug(g_log, "conn[%u] connecting ups[%s:%s]\n", c->seqno, ups_ip, ups_port);
                            if(flag == 1){
                                debug(g_log, "conn[%u] connect ups[%s:%s] success\n", c->seqno, ups_ip, ups_port);
                                c->state = CONNECT_UPS_ESTABLISH;
                            } else {
                                debug(g_log, "conn[%u] connect ups[%s:%s] in progress\n", c->seqno, ups_ip, ups_port);
                                add_connection_connectups_queue(c);
                                c->state = CONNECTING_UPS;
                            }

                            ups->fd = ret;
                            ups->epstate = EP_STATE_NONE;
                            ev.events = EPOLLOUT;
                            ev.data.ptr = ups;
                            epoll_ctl(g_epfd, EPOLL_CTL_ADD,ups->fd,&ev);
                        }
                    }
                }
            } else if(cli->epstate == EP_STATE_ERROR) {
                cli->epstate = EP_STATE_NONE;
                *retcode = OP_FAIL;
                log(g_log, "conn[%u] client event error\n", c->seqno);
                connection_set_closing_reset_client(c);
                break;
            } else {
                cli->epstate = EP_STATE_NONE;
                donothing();
            }
            break;
        case CONNECTING_UPS:
            if(cli->epstate == EP_STATE_READ){
                cli->epstate = EP_STATE_NONE;
                ret = read_client(c, retcode);
                if( (ret == 0) && (*retcode == OP_CLIENT_ABORT) ){
                    log(g_log, "conn[%u] client close\n", c->seqno);
                    connection_set_closing(c);
                    break;
                }
            } else if(cli->epstate == EP_STATE_ERROR) {
                cli->epstate = EP_STATE_NONE;
                *retcode = OP_FAIL;
                log(g_log, "conn[%u] client event error\n", c->seqno);
                connection_set_closing_reset_client(c);
                break;
            } else {
                cli->epstate = EP_STATE_NONE;
                //it should not be happen
                donothing();
            }

            if(ups->epstate == EP_STATE_WRITE){
                int err = 0;
                int errlen = sizeof(err);
                if(getsockopt(ups->fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1){
                    log(g_log, "conn[%u] getsockopt SOL_SOCKET fail, error[%s]\n", c->seqno, strerror(errno));
                    connection_set_closing(c);
                    break;
                } else {
                    if(err){
                        errno = err;
                        log(g_log, "conn[%u] connect ups fail, error[%s]\n", c->seqno, strerror(errno));
                        add_connection_connectups_retry_queue(c);
                        c->state = CONNECTING_UPS;
                        break;
                    } else {
                        c->state = CONNECT_UPS_ESTABLISH;
                        // goto state: CONNECT_UPS_ESTABLISH
                    }
                }

            } else if(ups->epstate == EP_STATE_ERROR) {
                ups->epstate = EP_STATE_NONE;
                *retcode = OP_FAIL;
                log(g_log, "conn[%u] connect ups error\n", c->seqno);
                add_connection_connectups_retry_queue(c);
                c->state = CONNECTING_UPS;
                break;
            } else {
                ups->epstate = EP_STATE_NONE;
                donothing();
                break;
            }
        case CONNECT_UPS_ESTABLISH:
            debug(g_log, "conn[%u] connect ups establish\n", c->seqno);
            c->state = WRITTING_UPS;
            add_connection_writeups_queue(c);
            ups_set_success(&(c->upstream));
            // goto state: WRITTING_UPS
        case WRITTING_UPS:
            debug(g_log, "conn[%u] writting ups\n", c->seqno);
            if(cli->epstate == EP_STATE_READ){
                debug(g_log, "conn[%u] client can be read in writting ups\n", c->seqno);
                cli->epstate = EP_STATE_NONE;
                ret = read_client(c, retcode);
                if( (ret == 0) && (*retcode == OP_CLIENT_ABORT) ){
                    log(g_log, "conn[%u] client close\n", c->seqno);
                    connection_set_closing(c);
                    break;
                }
            } else if(cli->epstate == EP_STATE_ERROR) {
                debug(g_log, "conn[%u] client error in writting ups\n", c->seqno);
                cli->epstate = EP_STATE_NONE;
                *retcode = OP_FAIL;
                log(g_log, "conn[%u] client event error\n", c->seqno);
                connection_set_closing_reset_client(c);
                break;
            } else {
                cli->epstate = EP_STATE_NONE;
                //it should not be happen
                donothing();
            }

            if(ups->epstate == EP_STATE_WRITE){
                debug(g_log, "conn[%u] writting ups\n", c->seqno);
                ups->epstate = EP_STATE_NONE;
                ret = write_ups(c, retcode);
                if(ret < 0){
                    log(g_log, "conn[%u] write ups error\n", c->seqno);
                    *retcode = OP_FAIL;
                    connection_set_closing(c);
                    //wite ups fail, get next ups?
                    //try_again();
                } else if(ret == 0) {
                    if(*retcode == OP_FINISH){
                        debug(g_log, "conn[%u] write ups complete\n", c->seqno);
                        ev.data.ptr = ups;
                        ev.events = EPOLLIN;
                        epoll_ctl(g_epfd, EPOLL_CTL_MOD, ups->fd, &ev);

                        //c->state = READ_UPS_WRITE_CLIENT;
                        c->state = READING_UPS;
                        add_connection_write_client_queue(c);
                    } else if(*retcode == OP_NEED_WAIT) {
                        donothing();
                    } else {
                        //it should not be happen
                        donothing();
                    }
                } else {
                    // add to epool
                    *retcode = OP_NEED_WAIT;
                    donothing();
                }
            } else if(ups->epstate == EP_STATE_READ){
                debug(g_log, "conn[%u] epstate_read\n", c->seqno);
                //it should not be happen
                ups->epstate = EP_STATE_NONE;
                donothing();
            } else {
                debug(g_log, "conn[%u] epstate_error\n", c->seqno);
                ups->epstate = EP_STATE_NONE;
                *retcode = OP_FAIL;
                log(g_log, "conn[%u] ups event error\n", c->seqno);
                connection_set_closing(c);
            }
            break;
        case READING_UPS:
            if(cli->epstate == EP_STATE_READ){
                cli->epstate = EP_STATE_NONE;
                ret = read_client(c, retcode);
                if( (ret == 0) && (*retcode == OP_CLIENT_ABORT) ){
                    log(g_log, "conn[%u] client close\n", c->seqno);
                    connection_set_closing(c);
                } else if(ret < 0) {
                    *retcode = OP_FAIL;
                    log(g_log, "conn[%u] read client error\n", c->seqno);
                    connection_set_closing_reset_client(c);
                } else {
                    *retcode = OP_UNKNOWN;
                    debug(g_log, "conn[%u] client can be read when reading ups. pipeline unsupport\n", c->seqno);
                    connection_set_closing(c);
                }

                break;
            } else if(cli->epstate == EP_STATE_ERROR){
                cli->epstate = EP_STATE_NONE;
                //it should not be happen
                *retcode = OP_FAIL;
                log(g_log, "conn[%u] client event error\n", c->seqno);
                connection_set_closing_reset_client(c);

                break;
            }

            if(ups->epstate == EP_STATE_READ){
                ups->epstate = EP_STATE_NONE;
                ret = read_ups(c, retcode);
                c->conn_stat.read_ups_times ++;
                if(ret < 0){
                    log(g_log, "conn[%u] read ups error\n", c->seqno);
                    *retcode = OP_FAIL;
                    connection_set_closing(c);
                    break;
                } else if(ret == 0) {
                    if(*retcode == OP_FINISH){
                        if( (c->keepalive == 0) || \
                            (c->conn_stat.keepalive_requests >= g_global_conf.max_keepalive_requests) )
                        {
                            connection_set_closing(c);
                        } else {
                            debug(g_log, "conn[%u] connection keepalive\n", c->seqno);
                            connection_close_half(c);
                            ev.data.ptr = cli;
                            ev.events = EPOLLIN;
                            epoll_ctl(g_epfd, EPOLL_CTL_MOD,cli->fd,&ev);
                            c->state = CLIENT_CONNECT_ESTABLISH;
                            add_connection_keepalive_queue(c);
                        }
                    } else {
                        //it should not be happen
                    }
                } else {
                    c->state = WRITTING_CLIENT;
                    ev.data.ptr = cli;
                    ev.events = EPOLLIN | EPOLLOUT;
                    epoll_ctl(g_epfd, EPOLL_CTL_MOD, cli->fd, &ev);
                    epoll_ctl(g_epfd, EPOLL_CTL_DEL, ups->fd, &ev);
                }
            } else if(ups->epstate == EP_STATE_ERROR) {
                ups->epstate = EP_STATE_NONE;
                *retcode = OP_FAIL;
                log(g_log, "conn[%u] ups event error\n", c->seqno);
                connection_set_closing(c);
                break;
            } else {
                donothing();
            }
            break;
        case WRITTING_CLIENT:
            if(cli->epstate == EP_STATE_READ){
                cli->epstate = EP_STATE_NONE;
                ret = read_client(c, retcode);
                if( (ret == 0) && (*retcode == OP_CLIENT_ABORT) ){
                    log(g_log, "conn[%u] client close\n", c->seqno);
                    connection_set_closing(c);
                } else if(ret < 0) {
                    *retcode = OP_FAIL;
                    log(g_log, "conn[%u] read client error\n", c->seqno);
                    connection_set_closing_reset_client(c);
                } else {
                    *retcode = OP_UNKNOWN;
                    debug(g_log, "conn[%u] client can be read when writting ups. pipeline unsupport\n", c->seqno);
                    connection_set_closing(c);
                } 

                break;
            } else if(cli->epstate == EP_STATE_ERROR){
                cli->epstate = EP_STATE_NONE;
                //it should not be happen
                *retcode = OP_FAIL;
                log(g_log, "conn[%u] client event error\n", c->seqno);
                connection_set_closing_reset_client(c);

                break;
            } else {
                if(! c->response.conntype_cleaned){
                    c->response.conntype_cleaned = 1;
                    http_resp_clean_conntype(&(c->outbuf));
                }
                cli->epstate = EP_STATE_NONE;
                ret = write_client(c, retcode);
                if(ret < 0){
                    log(g_log, "conn[%u] write client error\n", c->seqno);
                    *retcode = OP_FAIL;
                    connection_set_closing_reset_client(c);
                    break;
                } else if(ret == 0) {
                    debug(g_log, "conn[%u] write client nothing\n", c->seqno);
                    //it should not be happen
                } else {
                    debug(g_log, "conn[%u] write client something\n", c->seqno);
                    if(*retcode == OP_NEED_WAIT){
                        donothing();
                    } else if(*retcode == OP_SUCCESS) {
                        ev.data.ptr = cli;
                        ev.events = EPOLLIN;
                        epoll_ctl(g_epfd, EPOLL_CTL_MOD, cli->fd, &ev);

                        ev.data.ptr = ups;
                        ev.events = EPOLLIN;
                        epoll_ctl(g_epfd, EPOLL_CTL_ADD, ups->fd, &ev);

                        c->state = READING_UPS;
                    }
                }
            }

            break;

        default:
            donothing();
    }

    return 0;
}
