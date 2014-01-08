/*
 * Copyright 2011-2013 Alibaba Group Holding Limited. All rights reserved.
 * Use and distribution licensed under the GPL license.                   
 *
 * Authors: XiaoJinliang <xiaoshi.xjl@taobao.com>                          
 *
 */                                                                       

#include <stdlib.h>
#include <stdint.h>
#include "genpool.h"
#include "mempool.h"
#include "log.h"

static genpool_handler_t *g;
static size_t blocksize;
static int mempool_inited = 0;

static memblock_t *mempool_alloc_block(void);
static int mempool_dealloc_block(memblock_t *ptr);
static int mempool_status_timer(unsigned long arg);

extern log_t *g_log;

/*
 * fun: init mem pool
 * arg: mem block size, max mem block
 * ret: success=0, error=-1
 *
 */

int mempool_init(size_t size, size_t count)
{
    int ret;

    if( (g = genpool_init(size + sizeof(memblock_t), count)) == NULL ){
        return -1;
    }

    blocksize = size;
    mempool_inited = 1;

    ret = timer_register(mempool_status_timer, 0, "mempool_status_timer", 300);
    if(ret < 0){
        log(g_log, "mempool_status_timer register error\n");
        return -1;
    }

    return 0;
}

/*
 * fun: alloc mem block
 * arg:
 * ret: success!=NULL, error=NULL
 *
 */

static memblock_t *mempool_alloc_block(void)
{
    memblock_t *mb;

    if( ((mb = genpool_alloc_page(g)) == NULL) ){
        return NULL;
    }

    mb->size = blocksize;
    mb->used = 0;
    mb->reserve = 0;

    return mb;
}

/*
 * fun: dealloc mem block
 * arg: mem block pointer
 * ret: always return 0
 *
 */

static int mempool_dealloc_block(memblock_t *mb)
{
    genpool_release_page(g, mb);

    return 0;
}

/*
 * fun: alloc mem block for buf_t
 * arg: buf_t pointer
 * ret: success!=NULL, error=NULL
 *
 */

inline memblock_t *buf_alloc_memblock(buf_t *t)
{
    memblock_t *mb;

    if(mempool_inited == 0){
        log(g_log, "mempool not inited\n");
        return NULL;
    }

    if( (mb = mempool_alloc_block()) == NULL ){
        return NULL;
    }
    list_add_tail(&(mb->link), &(t->buf_head));

    if(t->cur_read_mem_block == NULL){
        t->cur_read_mem_block = mb;
    }

    if(t->cur_write_mem_block == NULL){
        t->cur_write_mem_block = mb;
    }

    t->cur_rpos = 0;
    t->cur_wpos = 0;

    return mb;
}

/*
 * fun: clean mem block of buf
 * arg: buf_t pointer
 * ret: success=0, error=-1
 *
 */

inline int buf_clean_memblock(buf_t *t)
{
    memblock_t *mb;
    struct list_head *pos, *n;

    if(mempool_inited == 0){
        log(g_log, "mempool not inited\n");
        return -1;
    }

    list_for_each_safe(pos, n, &(t->buf_head)){
        list_del_init(pos);
        mb = list_entry(pos, memblock_t, link);
        mempool_dealloc_block(mb);
    }

    INIT_LIST_HEAD(&(t->buf_head));
    t->cur_read_mem_block = NULL;
    t->cur_write_mem_block = NULL;
    t->cur_rpos = 0;
    t->cur_wpos = 0;
    t->total_count = 0;

    return 0;
}

static int mempool_status_timer(unsigned long arg)
{
    (void)arg;
    char buf[4096];

    genpool_status(g, buf, sizeof(buf));
    log(g_log, "%s\n", buf);

    return 0;
}
