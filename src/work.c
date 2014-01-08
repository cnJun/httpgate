/*
 * Copyright 2011-2013 Alibaba Group Holding Limited. All rights reserved.
 * Use and distribution licensed under the GPL license.                   
 *
 * Authors: XiaoJinliang <xiaoshi.xjl@taobao.com>                          
 *
 */                                                                       

#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include "connection.h"
#include "log.h"
#include "iprange.h"
#include "timer.h"
#include "conf.h"

#define MAX_EVENTS 1024

extern int g_listenfd;
extern log_t *g_log;
extern int g_epfd;
extern int g_reload;

extern iprange_t *g_whitelist, *g_blacklist;

extern conf_global_t g_global_conf;
extern conf_filter_t g_filter_conf;

static int reload(void);

/*
 * fun: real work process
 * arg: void
 * ret: always return 0, it is loop, it should not return
 *
 */

int work(void)
{
    int nfds, clientfd, retcode, i;
    uint32_t clientip, clientport;
    connection_t *c;
    ep_handler_t listenfd_handler, cmdfd_handler, *epptr;

    struct epoll_event ev, events[MAX_EVENTS];

    struct sockaddr_in cliaddr;
    socklen_t clen;

    listenfd_handler.conn = NULL;
    listenfd_handler.fd = g_listenfd;
    listenfd_handler.role = ROLE_LISTEN;
    listenfd_handler.epstate = EP_STATE_READ;

    if( (g_epfd = epoll_create(10000)) < 0 ){
        log(g_log, "create epoll fail, error[%s]\n", strerror(errno));
        return -1;
    } else {
        log(g_log, "create epoll success\n");
    }

    ev.data.ptr = &listenfd_handler;
    ev.events = EPOLLIN;
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_listenfd, &ev);

    while(1){
        nfds = epoll_wait(g_epfd, events, MAX_EVENTS, 1000);

        for(i = 0; i < nfds; ++i) {
            epptr = events[i].data.ptr;
            c = epptr->conn;
            if(epptr->role == ROLE_LISTEN){
                while(1){
                    clen = sizeof(cliaddr);
                    clientfd = accept_client(g_listenfd, &cliaddr, &clen);
                    if(clientfd < 0){
                        break;
                    }

                    clientip = ntohl(cliaddr.sin_addr.s_addr);
                    clientport = ntohs(cliaddr.sin_port);

                    c = connection_alloc(clientfd, clientip, clientport);
                    if(c == NULL){
                        log(g_log, "connection alloc fail, close connection\n");
                        close(clientfd);
                        continue;
                    } else {
                        debug(g_log, "connection alloc success\n");
                    }
                    debug(g_log, "conn[%u] client[%s:%d] connection accept\n", \
                                c->seqno, inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));

                    if(g_filter_conf.ipfilter){
                        if(!ipaddr_in_range(g_whitelist, c->clientip)){
                            if(ipaddr_in_range(g_blacklist, c->clientip)){
                                log(g_log, "conn[%u] clientip[%s] connection deny, in blacklist\n", \
                                            c->seqno, inet_ntoa(cliaddr.sin_addr));
                                connection_set_closing_reset_client(c);
                                continue;
                            } else {
                                if(ip_filter(c->clientip)){
                                    log(g_log, "conn[%u] clientip[%s] connection deny, in ipfilter\n", \
                                            c->seqno, inet_ntoa(cliaddr.sin_addr));
                                    connection_set_closing_reset_client(c);
                                    continue;
                                }
                            }
                        }
                    }

                    c->state = CLIENT_CONNECT_ESTABLISH;
                    debug(g_log, "conn[%u] connection established\n", c->seqno);
                    state(c, &retcode);
                    debug(g_log, "conn[%u] retcode[%d]\n", c->seqno, retcode);
                }

                //continue;

            } else if(epptr->role == ROLE_CLIENT) {
                if(events[i].events & EPOLLIN){
                    c->cli.epstate = EP_STATE_READ;
                    debug(g_log, "conn[%u] client can read\n", c->seqno);
                    state(c, &retcode);
                } else if(events[i].events & EPOLLOUT) {
                    debug(g_log, "conn[%u] client can written\n", c->seqno);
                    c->cli.epstate = EP_STATE_WRITE;
                    state(c, &retcode);
                } else if(events[i].events & EPOLLERR) {
                    debug(g_log, "conn[%u] client connection error\n", c->seqno);
                    c->cli.epstate = EP_STATE_ERROR;
                    state(c, &retcode);
                }

            } else if(epptr->role == ROLE_UPS) {
                if(events[i].events & EPOLLIN){
                    debug(g_log, "conn[%u] ups can read\n", c->seqno);
                    c->ups.epstate = EP_STATE_READ;
                    state(c, &retcode);
                } else if(events[i].events & EPOLLOUT) {
                    debug(g_log, "conn[%u] ups can written\n", c->seqno);
                    c->ups.epstate = EP_STATE_WRITE;
                    state(c, &retcode);
                } else if(events[i].events & EPOLLERR) {
                    debug(g_log, "conn[%u] ups connection error\n", c->seqno);
                    c->ups.epstate = EP_STATE_ERROR;
                    state(c, &retcode);
                }

            // fix me, next version?
            } else if(epptr->role == ROLE_CMD) {
                if(events[i].events & EPOLLIN){
                } else if(events[i].events & EPOLLIN) {
                } else if(events[i].events & EPOLLERR) {
                }
            }
        }

        // timer
        timer();

        //log(g_log, "reload ip whitelist and ip blacklist\n");
        if(g_reload){
            g_reload = 0;
            reload();
        }

        //log(g_log, "current loop finish\n");
    }

    return 0;
}

/*
 * fun: reload ip whitelist and ip blacklist(when catch SIGUSR1)
 * arg: 
 * ret: always return 0
 *
 */

static int reload(void)
{
    g_whitelist = iprange_reload(g_whitelist, g_filter_conf.whitelist, 1024);
    g_blacklist = iprange_reload(g_blacklist, g_filter_conf.blacklist, 1024);

    return 0;
}
