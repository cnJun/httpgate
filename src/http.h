#ifndef _HTTP_H_
#define _HTTP_H_

#include <stdint.h>
#include "mempool.h"

enum req_elem_seq{
    HTTP_METHOD = 0,
    HTTP_URI,
    HTTP_VER,
    HTTP_COOKIE = 3,
    HTTP_HOST,
    HTTP_CONNECTION,
    HTTP_CLIENTIP,
    HTTP_CONTENT,
    HTTP_ELEM_END
};

typedef struct req_elem{
    char *elemstr;
    size_t elemstr_size;
    size_t pos;
    size_t len;
} req_elem_t;

typedef struct _req_map_t{
    char *ptr;
    req_elem_t elems[16];
    size_t elems_count;
} req_map_t;

typedef struct _req_header_t{
    int   hready;
    size_t hpos;
    size_t hlen;
    req_map_t hmap;
    char method[16];
    char ver[16];
    char conntype[16];
} req_header_t;

typedef struct _req_body_t{
    int   bready;
    size_t bpos;
    size_t blen;
} req_body_t;

typedef struct _http_req_t{
    buf_t *buf;
    req_header_t header;
    req_body_t   body;
} http_req_t;

typedef struct _http_resp_t{
    buf_t *buf;
    int conntype_cleaned;
} http_resp_t;

int http_req_init(http_req_t *r);
int http_resp_init(http_resp_t *r);

int get_header_elem(http_req_t *r, int elemseq, char *buf, int len);
int req_test_and_parse(buf_t *buf, http_req_t *r);
int http_req_header_dump(http_req_t *r, char *buf, size_t len);
int http_req_append_clientip(http_req_t *r, uint32_t ip);

int http_resp_clean_conntype(buf_t *buf);

#endif
