/*
 * Copyright 2011-2013 Alibaba Group Holding Limited. All rights reserved.
 * Use and distribution licensed under the GPL license.                   
 *
 * Authors: XiaoJinliang <xiaoshi.xjl@taobao.com>                          
 *
 */                                                                       

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "http.h"
#include "mempool.h"

static int skip_blank(char *buf, int len);
static int skip_blank_comma(char *buf, int len);
static int find_blank(char *buf, int len);
static int find_rn_next(char *buf, int len);

static int req_map_init(req_map_t *map);
static int get_req_header_end(buf_t *buf, char **ptr);
static int parse_req_header(buf_t *buf, http_req_t *r);

/*
 * fun: init request map for header argument
 * arg: request http header argument map
 * ret: return 0
 */

static int req_map_init(req_map_t *map)
{
    req_elem_t *elem;

    map->ptr = NULL;
    elem = &(map->elems[0]);
    elem->elemstr = "METHOD";
    elem->elemstr_size = 6;
    elem->pos = 0;
    elem->len = 0;

    elem = &(map->elems[1]);
    elem->elemstr = "URI";
    elem->elemstr_size = 3;
    elem->pos = 0;
    elem->len = 0;

    elem = &(map->elems[2]);
    elem->elemstr = "VERSION";
    elem->elemstr_size = 7;
    elem->pos = 0;
    elem->len = 0;

    elem = &(map->elems[3]);
    elem->elemstr = "COOKIE";
    elem->elemstr_size = 6;
    elem->pos = 0;
    elem->len = 0;

    elem = &(map->elems[4]);
    elem->elemstr = "HOST";
    elem->elemstr_size = 4;
    elem->pos = 0;
    elem->len = 0;

    elem = &(map->elems[5]);
    elem->elemstr = "CONNECTION";
    elem->elemstr_size = 10;
    elem->pos = 0;
    elem->len = 0;

    elem = &(map->elems[6]);
    elem->elemstr = "CLIENTIP";
    elem->elemstr_size = 8;
    elem->pos = 0;
    elem->len = 0;

    elem = &(map->elems[7]);
    elem->elemstr = "CONTENT-LENGTH";
    elem->elemstr_size = 14;
    elem->pos = 0;
    elem->len = 0;

    map->elems_count = 8;

    return 0;
}

/*
 * fun: http request struct init
 * arg: http request struct pointer
 * ret: return 0
 */

int http_req_init(http_req_t *r)
{
    req_header_t *h;
    req_body_t *b;

    r->buf = NULL;

    h = &(r->header);
    b = &(r->body);

    h->hready = 0;
    h->hpos = 0;
    h->hlen = 0;
    req_map_init(&(h->hmap));
    bzero(h->method, sizeof(h->method));

    b->bready = 0;
    b->bpos = 0;
    b->blen = 0;

    return 0;
}

/*
 * fun: http response struct init
 * arg: http response struct pointer
 * ret: return 0
 */

int http_resp_init(http_resp_t *r)
{
    r->buf = NULL;
    r->conntype_cleaned = 0;

    return 0;
}

/*
 * fun: find request http header blank line
 * arg: request buffer
 * ret: success>0, error=0
 */

static int get_req_header_end(buf_t *buf, char **ptr)
{
    int i, rlen;
    char *request;
    memblock_t *mb;

    mb = list_first_entry(&(buf->buf_head), memblock_t, link);
    request = mb->mem;
    rlen = mb->used;
    if(ptr != NULL){
        *ptr = request;
    }

    if(rlen < 10){
        return 0;
    }

    if(!strncasecmp(request, "GET", 3)){
        if(request[rlen - 4] == '\r' && request[rlen - 3] == '\n' &&
           request[rlen - 2] == '\r' && request[rlen - 1] == '\n') {
            return rlen - 2;
        } else {
            return 0;
        }
    }
        
    for(i = 0; i < rlen - 3; i++) {
        if(request[i] == '\r' && request[i+1] == '\n' &&
                request[i+2] == '\r' && request[i+3] == '\n')
        {
            return i + 2;
        }
    }

    return 0;
}

/*
 * fun: parse request http header to map
 * arg: request http header argument map
 * ret: return 0
 */

static int parse_req_header(buf_t *buf, http_req_t *r)
{
    int  i, len, pos, k;
    char *ptr;
    memblock_t *mb;

    req_map_t *map = &(r->header.hmap);

    mb = list_first_entry(&(buf->buf_head), memblock_t, link);
    ptr = mb->mem;
    len = mb->used;
    map->ptr = ptr;
    
    if(! strncasecmp(ptr, "GET", 3)){
        map->elems[0].pos = 0;
        pos = map->elems[0].len = 3;
    } else if(! strncasecmp(ptr, "POST", 4)){
        map->elems[0].pos = 0;
        pos = map->elems[0].len = 4;
    } else {
        return -1;
    }

    for(i = pos; i < len; i++){
        if((ptr[i] != ' ') && (ptr[i] != '\t')){
            break;
        }
    }
    if(i == len){
        return -1;
    }

    map->elems[1].pos = i;

    for(; i < len; i++){
        if((ptr[i] == ' ') || (ptr[i] == '\t') || (ptr[i] == '?')){
            break;
        }
    }
    if(i == len){
        return -1;
    }

    map->elems[1].len = i - map->elems[1].pos;
    pos = i;

    for(i = pos; i < len; i++){
        if((ptr[i] != ' ') && (ptr[i] != '\t')){
            break;
        }
    }
    if(i == len){
        return -1;
    }

    map->elems[2].pos = i;

    for(; i < len; i++){
        if((ptr[i] == ' ') || (ptr[i] == '\t') || (ptr[i] == '\r')){
            break;
        }
    }
    if(i == len){
        return -1;
    }

    map->elems[2].len = i - map->elems[2].pos;
    pos = i;

    while(1){
        i = find_rn_next(ptr + pos, len - pos);
        if(i < 0){
            return -1;
        } else if(i == 0){
            return 0;
        }
        pos = pos + i;

        for(i = pos; i < len; i++, pos++){
            if((ptr[i] != ' ') && (ptr[i] != '\t')){
                break;
            }
        }
        if(i == len){
            return -1;
        }

        for(k = HTTP_COOKIE; k < HTTP_ELEM_END; k++){
            if(!strncasecmp(ptr+pos, map->elems[k].elemstr, map->elems[k].elemstr_size)){
                pos += map->elems[k].elemstr_size;

                for(i = pos; i < len; i++, pos++){
                    if((ptr[i]!=' ')&&(ptr[i]!='\t')&&(ptr[i]!=':')){
                        break;
                    }
                }
                if(i == len){
                    return -1;
                }

                map->elems[k].pos = pos;

                for(i = pos; i < len - 1; i++, pos++){
                    if( (ptr[i] == '\r') && (ptr[i+1] == '\n') ){
                        break;
                    }
                }
                if(i == len){
                    return -1;
                }

                map->elems[k].len = pos - map->elems[k].pos;
            }
        }
    }

    return 0;
}

/*
 * fun: find blank line
 * arg: data buffer
 * ret: found>0, not found=0, error=-1
 */

static int find_rn_next(char *buf, int len)
{
    int i;

    for(i = 0; i < len - 1; i++){
        if(buf[i] == '\r' && buf[i + 1] == '\n'){
            if(i + 2 == len){
                return 0;
            } else {
                return i + 2;
            }
        }
    }

    return -1;
}

/*
 * fun: skip blank
 * arg: data buffer
 * ret: 
 */

static int skip_blank(char *buf, int len)
{
    int i;

    for(i = 0; i < len; i++){
        if(buf[i] != ' ' && buf[i] != '\t'){
            return i;
        }
    }

    return -1;
}

/*
 * fun: skip blank and comma
 * arg: data buffer
 * ret: 
 */

static int skip_blank_comma(char *buf, int len)
{
    int i;

    for(i = 0; i < len; i++){
        if(buf[i] != ' ' && buf[i] != '\t' && buf[i] != ':'){
            return i;
        }
    }

    return -1;
}

/*
 * fun: find blank
 * arg: data buffer
 * ret: 
 */

static int find_blank(char *buf, int len)
{
    int i;

    for(i = 0; i < len; i++){
        if(buf[i] == ' ' || buf[i] == '\t'){
            return i;
        }
    }

    return -1;
}

/*
 * fun: get http header argument
 * arg: http request pointer, argument index, buf for argument and buf length
 * ret: 
 */

int get_header_elem(http_req_t *r, int elemseq, char *buf, int len)
{
    req_map_t *map = &(r->header.hmap);

    char *ptr = map->ptr + map->elems[elemseq].pos;

    if(len <= map->elems[elemseq].len){
        return -1;
    }

    if(map->elems[elemseq].len == 0){
        buf[0] = '\0';
        return 0;
    }

    memcpy(buf, ptr, map->elems[elemseq].len);
    buf[map->elems[elemseq].len] = '\0';

    return map->elems[elemseq].len;
}

/*
 * fun: test http request http and parse it
 * arg: data buf, http request pointer
 * ret: 
 */

int req_test_and_parse(buf_t *buf, http_req_t *r)
{
    int ret, rn, clen;
    char tmp[128];

    req_body_t *b = &(r->body);
    req_header_t *h = &(r->header);
    req_map_t *map = &(h->hmap);

    r->buf = buf;

    if(h->hready == 0){
        rn = get_req_header_end(buf, NULL);
        if(rn < 0){
            return -1;
        } else if(rn == 0) {
            return 0;
        } else {
            h->hready = 1;
            h->hpos = 0;
            h->hlen = rn;
        }

        ret = parse_req_header(buf, r);
        if(ret < 0){
            return ret;
        }

        ret = get_header_elem(r, HTTP_VER, tmp, sizeof(tmp));
        strncpy(h->ver, tmp, sizeof(h->ver));

        ret = get_header_elem(r, HTTP_CONNECTION, tmp, sizeof(tmp));
        strncpy(h->conntype, tmp, sizeof(h->conntype));

        ret = get_header_elem(r, HTTP_METHOD, tmp, sizeof(tmp));
        if(ret <= 0){
            return -1;
        } else {
            if(! strncasecmp(tmp, "GET", 3)){
                strncpy(h->method, "GET", sizeof(h->method));
                return 1;
            } else if(! strncasecmp(tmp, "POST", 4)) {
                strncpy(h->method, "POST", sizeof(h->method));
            } else {
                return -1;
            }
        }
    }

    ret = get_header_elem(r, HTTP_CONTENT, tmp, sizeof(tmp));
    if(ret <= 0){
        return -1;
    }

    clen = atoi(tmp);
    rn = rn + 2;

    if(clen == (buf->total_count - rn)){
        b->bready = 1;
        b->bpos = rn;
        b->blen = clen;
        return 1;
    } else {
        return 0;
    }
}

/*
 * fun: dump http request header
 * arg: http request pointer, buf for http request, buf length
 * ret: 0
 */

int http_req_header_dump(http_req_t *r, char *buf, size_t len)
{
    len = (r->header.hlen < len - 1)? r->header.hlen: len - 1;
    strncpy(buf, r->header.hmap.ptr, len);
    buf[len] = '\0';

    return 0;
}

/*
 * fun: append clientip to http request header
 * arg: http request pointer, ip
 * ret: success=0, error=-1
 */

int http_req_append_clientip(http_req_t *r, uint32_t ip)
{
    int n, oldpos, newpos, len;
    char *ptr, str[128], ipstr[64];
    memblock_t *mb;
    buf_t *buf;

    buf = r->buf;

    ptr = r->header.hmap.ptr;
    ipint2str(ipstr, sizeof(ipstr), ip);
    n = snprintf(str, sizeof(str), "X-Forwarded-For: %s\r\n", ipstr);

    if(n > buf->cur_read_mem_block->size - buf->cur_read_mem_block->used){
        return -1;
    }

    oldpos = r->header.hlen;
    newpos = oldpos + n;
    len = r->body.blen + 2;
    memmove(ptr + newpos, ptr + oldpos, len);
    memcpy(ptr + oldpos, str, n);

    r->header.hlen += n;
    r->body.bpos += n;
    buf->total_count += n;
    buf->cur_rpos += n;
    buf->cur_read_mem_block->used += n;

    return 0;
}

/*
 * fun: erase connection type of http response to support keepalive with client
 * arg: data buf
 * ret: success=0, error=-1
 */

int http_resp_clean_conntype(buf_t *buf)
{
    int rlen, size, pos1, pos2, rnpos;
    char *resp, *ptr1, *ptr2, *rnptr;
    memblock_t *mb;

    mb = list_first_entry(&(buf->buf_head), memblock_t, link);
    resp = mb->mem;
    rlen = mb->used;
    size = mb->size;

    if(rlen < size){
        resp[rlen] = '\0';
    }

    if( (rnptr = strstr(resp, "\r\n\r\n")) == NULL ){
        return -1;
    }

    rnpos = ((long)rnptr - (long)resp) / sizeof(char);

    if( ptr1 = strcasestr(resp, "Connection:") ){
        pos1 = ((long)ptr1 - (long)resp) / sizeof(char);
        if(pos1 > rnpos){
            return 0;
        }
        if( (ptr2 = strstr(ptr1, "\r\n")) ){
            ptr2 += 2;
            pos2 = ((long)ptr2 - (long)resp) / sizeof(char);
            memmove(ptr1, ptr2, mb->used - pos2);

            mb->used = mb->used - (pos2 - pos1);
            buf->total_count = buf->total_count - (pos2 - pos1);
            buf->cur_rpos = buf->cur_rpos - (pos2 - pos1);

            return pos2 - pos1;
        } else {
            return 0;
        }
    }

    return 0;
}
