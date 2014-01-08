/*
 * Copyright 2011-2013 Alibaba Group Holding Limited. All rights reserved.
 * Use and distribution licensed under the GPL license.                   
 *
 * Authors: XiaoJinliang <xiaoshi.xjl@taobao.com>                          
 *
 */                                                                       

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <errno.h>
#include "sock.h"
#include "log.h"
#include "common.h"

extern log_t *g_log;

#define RESERVE_FOR_HEADER 64

/*
 * fun: make listen socket and set nonblock
 * arg: listen address string, listen port string
 * ret: success=0, error=-1
 *
 */

inline int make_listen_nonblock(const char *host, const char *serv)
{
    int                 fd;
    const int           on = 1;
    struct addrinfo     hints, *res, *ressave;

    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if( getaddrinfo(host, serv, &hints, &res) != 0 ) {
        return -1;
    } else {
        debug(g_log, "getaddrinfo success\n");
    }

    ressave = res;
    do{
        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if(fd < 0){
            log(g_log, "socket error, %s\n", strerror(errno));
            continue;
        }
        debug(g_log, "socket success\n");
        // set socket reusable
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        // disable nagle
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

        if(bind(fd, res->ai_addr, res->ai_addrlen) == 0){
            debug(g_log, "bind success\n");
            break;
        }
        log(g_log, "bind fail, %s\n", strerror(errno));
        close(fd);
    }while( (res = res->ai_next) != NULL );

    if(res == NULL) {
        return -1;
    }

    if(listen(fd, 1024) < 0) {
        log(g_log, "listen error, %s\n", strerror(errno));
        return -1;
    }
    debug(g_log, "listen success\n");

    if(setnonblock(fd) < 0){
        close(fd);
        return -1;
    }
    debug(g_log, "setnonblock success\n");

    freeaddrinfo(ressave);

    return(fd);
}

/*
 * fun: connect remote host:port
 * arg: remote host, remote port, connect status
 * ret: success=0, error=-1
 *
 */

inline int connect_nonblock(const char *host, const char *serv, int *flag)
{
    const int on = 1;
    int ret, sockfd;
    struct addrinfo hints,*res,*ressave;

    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if( (ret = getaddrinfo(host, serv, &hints, &res)) != 0 ){
        return -1;
    }

    ressave = res;

    do{
        if( (sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0 ){
            log(g_log, "socket error, %s\n", strerror(errno));
            return -1;
        }

        // set socket reusable
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        // disable nagle
        setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

        if( (ret = setnonblock(sockfd)) != 0 ){
            close(sockfd);
            return -1;
        }

        if( (ret = connect(sockfd, res->ai_addr, res->ai_addrlen)) < 0 ){
            if(errno != EINPROGRESS){
                log(g_log, "connect error, %s\n", strerror(errno));
                close(sockfd);
                return -1;
            } else {
                *flag = 0;
                break;
            }
        } else {
            *flag = 1;
            break;
        }
    }while( (res = res->ai_next) != NULL );

    freeaddrinfo(ressave);

    return(sockfd);
}

/*
 * fun: set fd nonblock
 * arg: fd
 * ret: success=0, error=-1
 *
 */

inline int setnonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/*
 * fun: accept client connection
 * arg: sockfd, remote address, address length
 * ret: success=0, error=-1
 *
 */

inline int accept_client(int sockfd, struct sockaddr_in *cliaddr, socklen_t *len)
{
    int fd, ret;

    fd = accept(sockfd, (struct sockaddr *)cliaddr, len);
    if(fd < 0){
        if( (errno != EAGAIN) || (errno != EWOULDBLOCK) ){
            log(g_log, "accept error, %s\n", strerror(errno));
        }
        return -1;
    }

    ret = setnonblock(fd);
    if(ret < 0){
        close(fd);
        return -1;
    }

    return fd;
}

/*
 * fun: prepare for reading client
 * arg: connection struct
 * ret: always return 0
 *
 */

inline int read_client_prepare(connection_t *c)
{
    memblock_t *mb;
    buf_t *buf;

    buf = &(c->inbuf);

    buf_clean_memblock(buf);
    mb = buf_alloc_memblock(buf);
    mb->used = 0;
    mb->reserve = RESERVE_FOR_HEADER;

    buf->cur_read_mem_block = mb;
    buf->cur_write_mem_block = mb;
    buf->cur_rpos = 0;
    buf->cur_wpos = 0;
    buf->total_count = 0;

    return 0;
}

/*
 * fun: prepare for reading ups
 * arg: connection struct
 * ret: always return 0
 *
 */

inline int read_ups_prepare(connection_t *c)
{
    memblock_t *mb;
    buf_t *buf;

    buf = &(c->outbuf);

    buf_clean_memblock(buf);
    mb = buf_alloc_memblock(buf);
    mb->used = 0;
    mb->reserve = RESERVE_FOR_HEADER;

    buf->cur_read_mem_block = mb;
    buf->cur_write_mem_block = mb;
    buf->cur_rpos = 0;
    buf->cur_wpos = 0;
    buf->total_count = 0;

    return 0;
}

/*
 * fun: read client
 * arg: connection struct, return code
 * ret: error=-1, success>=0
 *
 */

inline int read_client(connection_t *c, int *retcode)
{
    int n, ret, fd, m, rn;
    char *ptr;
    size_t pos;
    memblock_t *mb;
    buf_t *buf;
    char tmp[128], ipstr[128];

    fd = c->cli.fd;
    buf = &(c->inbuf);
    mb = buf->cur_read_mem_block;
    pos = buf->cur_rpos;
    n = mb->size - mb->used - mb->reserve;
    ptr = (char *)(mb->mem) + pos;

    while(1) {
        if( (ret = read(fd, ptr, n)) < 0 ){
            if(errno == EINTR){
                continue;
            } else if(errno == EAGAIN) {
                *retcode = OP_NEED_WAIT;
                return 0;
            } else {
                log(g_log, "read fail, %s\n", strerror(errno));
                *retcode = OP_FAIL;
                return -1;
            }
        } else if(ret == 0) {
            *retcode = OP_CLIENT_ABORT;
            return 0;
        } else {
            buf->cur_rpos += ret;
            buf->total_count += ret;
            mb->used += ret;
            if(mb->used == mb->size - mb->reserve){
                mb = buf_alloc_memblock(buf);
                buf->cur_rpos = 0;
                buf->cur_read_mem_block = mb;
            }

            *retcode = OP_SUCCESS;
            break;
        }
    }

    return ret;
}

/*
 * fun: write ups
 * arg: connection struct, return code
 * ret: error=-1, success>=0
 *
 */

inline int write_ups(connection_t *c, int *retcode)
{
    int n, ret, fd;
    char *ptr;
    size_t pos;
    memblock_t *mb;
    struct list_head *next;
    buf_t *buf;

    fd = c->ups.fd;
    buf = &(c->inbuf);
    mb = buf->cur_write_mem_block;
    pos = buf->cur_wpos;
    n = mb->used - pos;
    ptr = (char *)(mb->mem) + pos;

    if(n == 0){
        if(list_is_last(&(mb->link), &(buf->buf_head))){
            *retcode = OP_FINISH;
            return 0;
        } else {
            next = &(mb->link);
            mb = list_entry(next, memblock_t, link);
            n = mb->used;
            ptr = mb->mem;
            buf->cur_write_mem_block = mb;
            buf->cur_wpos = 0;
        }
    }

    while(1) {
        if( (ret = write(fd, ptr, n)) <= 0 ){
            if(errno == EINTR){
                continue;
            } else if(errno == EAGAIN) {
                *retcode = OP_NEED_WAIT;
                return 0;
            } else {
                *retcode = OP_FAIL;
                return -1;
            }
        } else {
            buf->cur_wpos += ret;
            *retcode = OP_SUCCESS;
            break;
        }
    }

    return ret;
}

/*
 * fun: read ups
 * arg: connection struct, return code
 * ret: error=-1, success>=0
 *
 */

inline int read_ups(connection_t *c, int *retcode)
{
    int ret, n;
    int upsfd, size, total = 0;
    size_t pos;
    memblock_t *mb;
    buf_t *buf;
    char *mem;

    read_ups_prepare(c);

    upsfd = c->ups.fd;

    buf = &(c->outbuf);
    pos = buf->cur_rpos;
    mb = buf->cur_read_mem_block;
    mem = mb->mem;
    size = mb->size;

    n = size - pos - mb->reserve;

    while(1){
        ret = read(upsfd, mem + pos, n);
        if(ret < 0){
            if(errno == EINTR){
                continue;
            } else if(errno == EAGAIN) {
                *retcode = OP_NEED_WAIT;
                return total;
            } else {
                log(g_log, "read fail, %s\n", strerror(errno));
                *retcode = OP_FAIL;
                return -1;
            }
        } else if(ret == 0) {
            if(total){
                *retcode = OP_SUCCESS;
            } else {
                *retcode = OP_FINISH;
            }
            return total;
        } else {
            pos += ret;
            buf->cur_rpos += ret;
            buf->total_count += ret;
            mb->used += ret;
            total += ret;
            n -= ret;

            if(n == 0){
                if(total){
                    *retcode = OP_SUCCESS;
                } else {
                    *retcode = OP_FINISH;
                }
                return total;
            }
        }
    }
}

/*
 * fun: write client
 * arg: connection struct, return code
 * error=-1, success>=0
 *
 */

inline int write_client(connection_t *c, int *retcode)
{
    int ret, n;
    int clifd, size, total = 0;
    size_t pos, used;
    memblock_t *mb;
    buf_t *buf;
    char *mem;

    clifd = c->cli.fd;

    buf = &(c->outbuf);
    pos = buf->cur_wpos;
    mb = buf->cur_write_mem_block;
    mem = mb->mem;
    used = mb->used;

    n = used - pos;

    while(1){
        ret = write(clifd, mem + pos, n);
        if(ret < 0){
            if(errno == EINTR){
                continue;
            } else if(errno == EAGAIN) {
                *retcode = OP_NEED_WAIT;
                return total;
            } else {
                log(g_log, "write error, %s\n", strerror(errno));
                *retcode = OP_FAIL;
                return -1;
            }
        } else if(ret == 0) {
            *retcode = OP_SUCCESS;
            return total;
        } else {
            pos += ret;
            total += ret;
            n -= ret;
            buf->cur_wpos += ret;
            if(n == 0){
                *retcode = OP_SUCCESS;
                return total;
            }
        }
    }
}
