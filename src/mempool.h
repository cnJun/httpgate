#ifndef _MEMPOOL_H_
#define _MEMPOOL_H_

#include <stdlib.h>
#include <stdint.h>
#include "list.h"

typedef struct _memblock_t{
    struct list_head link;
    size_t size;
    size_t used;
    size_t reserve;
    char mem[0];
} memblock_t;

typedef struct _buf_t{
    struct list_head buf_head;
    memblock_t *cur_read_mem_block;   
    memblock_t *cur_write_mem_block;   
    size_t cur_rpos;
    size_t cur_wpos;
    size_t total_count;
}buf_t;


int mempool_init(size_t size, size_t count);
inline int buf_clean_memblock(buf_t *t);
inline memblock_t *buf_alloc_memblock(buf_t *t);

#endif
