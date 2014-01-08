/*
 * Copyright 2011-2013 Alibaba Group Holding Limited. All rights reserved.
 * Use and distribution licensed under the GPL license.                   
 *
 * Authors: XiaoJinliang <xiaoshi.xjl@taobao.com>                          
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "genpool.h"
#include "list.h"
#include "md5.h"
#include "hash.h"
#include "log.h"
#include "cookiefilter.h"
#include "timer.h"

#define COOKIE_BUCKET_NUM 771973
#define COOKIE_TIMEOUT 300

extern log_t *g_log;

typedef struct _cookie_bucket_t{
    struct list_head head;
} cookie_bucket_t;

typedef struct _cookie_filter_conf{
    time_t   period1;
    time_t   period2;
    uint32_t threshold1;
    uint32_t threshold2;
    time_t   filter_interval1;
    time_t   filter_interval2;
    int      enable1;
    int      enable2;
} cookie_filter_conf;

typedef struct _cookie_node_t{
    uint32_t cookie_len;
    uint64_t cookie_mmhash64;
    uint64_t cookie_naivehash64;
    char cookie_md5[16];
    struct list_head link;
    struct list_head timer_link;
    cookie_req_stat stat;
    time_t last_access;
    cookie_filter_conf *filter_conf;
} cookie_node_t;

static genpool_handler_t *cookie_node_pool;
static cookie_bucket_t *cookie_bucket_array;
static struct list_head timer_head;
static struct list_head filter_head;

static cookie_filter_conf filter_conf_template;
static cookie_filter_inited = 0;

static inline int md5sum(char *digest, const char *buf, size_t len);
static inline int cookie_checksum(cookie_node_t *node, const char *cookie, int len);
static inline int cookie_is_equal(cookie_node_t *n1, cookie_node_t *n2);
static inline int cookie_is_filtered(cookie_node_t *node);
static inline int cookie_stat_refresh(cookie_req_stat *stat);
static inline int cookie_req_stat_init(cookie_req_stat *stat);

static int cookie_pool_clean_timer(unsigned long max);
static int cookie_pool_status_timer(unsigned long arg);

/*
 * fun: cookie pool init
 * arg: max cookie node in cookie pool
 * ret: success=0, error=-1
 *
 */

int cookie_pool_init(size_t max)
{
    int i;

    cookie_bucket_array = malloc(sizeof(cookie_bucket_t) * COOKIE_BUCKET_NUM);
    if(cookie_bucket_array == NULL){
        return -1;
    }

    for(i = 0; i < COOKIE_BUCKET_NUM; i++){
        INIT_LIST_HEAD(&(cookie_bucket_array[i].head));
    }

    INIT_LIST_HEAD(&timer_head);
    INIT_LIST_HEAD(&filter_head);

    cookie_node_pool = genpool_init(sizeof(cookie_node_t), max);
    if(cookie_node_pool == NULL){
        free(cookie_bucket_array);
        return -1;
    }

    if(timer_register(cookie_pool_clean_timer, 30, "cookie_pool_clean_timer", 5) < 0){
        log(g_log, "cookie_pool_clean_timer register error\n");
        return -1;
    }

    if(timer_register(cookie_pool_status_timer, 0, "cookie_pool_status_timer", 300) < 0){
        log(g_log, "cookie_pool_status_timer register error\n");
        return -1;
    }

    return 0;
}

/*
 * fun: calculate cookie string to md5
 * arg: digest: md5 buffer, buf: cookie string, len: cookie length
 * ret: always return 0
 *
 */

static inline int md5sum(char *digest, const char *buf, size_t len)
{
    md5ctx ctx;

    md5_init(&ctx);
    md5_update(&ctx, buf, len);
    md5_final(digest, &ctx);

    return 0;
}


/*
 * fun: transfer cookie to cookie_node_t
 * arg: node: cookie_node_t, cookie: cookie string, len: cookie length
 * ret: always return 0
 *
 */

static inline int cookie_checksum(cookie_node_t *node, const char *cookie, int len)
{
    node->cookie_len = len;
    node->cookie_mmhash64 = mmhash64(cookie, len);
    node->cookie_naivehash64 = naivehash64(cookie, len);
    md5sum(node->cookie_md5, cookie, len);

    return 0;
}

/*
 * fun: compare two cookie_node_t
 * arg: cookie_node_t node1 & node2
 * ret: equal=1, unequal=0
 *
 */

static inline int cookie_is_equal(cookie_node_t *n1, cookie_node_t *n2)
{
    return (\
    (n1->cookie_len == n2->cookie_len) && \
    (n1->cookie_mmhash64 == n2->cookie_mmhash64) && \
    (n1->cookie_naivehash64 == n2->cookie_naivehash64) && \
    (! memcmp(n1->cookie_md5, n2->cookie_md5, 16)));
}

/*
 * fun: check whether cookie is filtered or not
 * arg: cookie_node_t
 * ret: error=-1, _not_filtered=0, filtered=1
 *
 */

static inline int cookie_is_filtered(cookie_node_t *node)
{
    time_t now = time(NULL);
    int isfiltered = 0;
    cookie_req_stat *stat;
    cookie_filter_conf *filter_conf;

    stat = &(node->stat);
    filter_conf = node->filter_conf;

    if(cookie_filter_inited == 0){
        log(g_log, "cookie filter not inited\n");
        return -1;
    }

    if(filter_conf->enable1){
        if(now - stat->filter_time1 <= filter_conf->filter_interval1){
            isfiltered = 1;
        } else {
            stat->filter_time1 = 0;
            if(now - stat->time1 <= filter_conf->period1){
                if(stat->count1 > filter_conf->threshold1){
                    stat->filter_time1 = now;
                    isfiltered = 1;
                }
            } else {
                stat->time1 = now;
                stat->count1 = 0;
            }
        }
    }

    if(filter_conf->enable2){
        if(now - stat->filter_time2 <= filter_conf->filter_interval2){
            isfiltered = 1;
        } else {
            stat->filter_time2 = 0;
            if(now - stat->time2 <= filter_conf->period2){
                if(stat->count2 > filter_conf->threshold2){
                    stat->filter_time2 = now;
                    isfiltered = 1;
                }
            } else {
                stat->time2 = now;
                stat->count2 = 0;
            }
        }
    }

    return isfiltered;
}

/*
 * fun: filter connection cookie
 * arg: cookie: cookie string, len: cookie length
 * ret: filtered=1, _not_filtered=0
 *
 */

inline int cookie_filter(const char *cookie, int len)
{
    int found, ret;
    uint64_t index;
    cookie_node_t *node;
    struct list_head *head, *pos;
    cookie_node_t *tmp;

    found = 0;

    if(len == 0){
        return 0;
    }

    node = genpool_alloc_page(cookie_node_pool);
    if(node == NULL){
        return 0;
    }

    cookie_req_stat_init(&(node->stat));
    cookie_checksum(node, cookie, len);
    node->last_access = time(NULL);
    node->filter_conf = &filter_conf_template;

    index = node->cookie_mmhash64 % COOKIE_BUCKET_NUM;
    head = &(cookie_bucket_array[index].head);

    list_for_each(pos, head)
    {
        tmp = list_entry(pos, cookie_node_t, link);
        if(cookie_is_equal(tmp, node)){
            found = 1;
            genpool_release_page(cookie_node_pool, node);
            list_move(&(tmp->link), head);
            list_move_tail(&(tmp->timer_link), &timer_head);
            break;
        } else {
            continue;
        }
    }

    if(!found){
        tmp = node;
        list_add(&(node->link), head);
        list_add_tail(&(node->timer_link), &timer_head);
    }

    cookie_stat_refresh(&(tmp->stat));
    tmp->last_access = time(NULL);

    return cookie_is_filtered(tmp);
}

/*
 * fun: cookie pool clean timer
 * arg: max cookie cleaned
 * ret: number of cookie cleaned
 *
 */

static int cookie_pool_clean_timer(unsigned long max)
{
    struct list_head *pos, *n, *head;
    cookie_node_t *node;
    time_t now = time(NULL);
    int count = 0;

    head = &timer_head;
    list_for_each_safe(pos, n, head){
        node = list_entry(pos, cookie_node_t, timer_link);
        if(now - node->last_access > COOKIE_TIMEOUT){
            list_del_init(&(node->link));
            list_del_init(&(node->timer_link));
            genpool_release_page(cookie_node_pool, node);
            if(count >= max){
                return count;
            } else {
                count++;
            }
        } else {
            break;
        }
    }

    return count;
}

/*
 * fun: init cookie filter conf
 * arg: period1: t1, period: t2, threshold1: s1, threshold2: s2, filter1: p1, filter2: p2
 * ret: always return 0
 *
 */

int cookiefilter_conf_init(time_t t1, time_t t2, \
                            uint32_t s1, uint32_t s2, time_t p1, time_t p2)
{
    filter_conf_template.period1 = t1;
    filter_conf_template.period2 = t2;

    filter_conf_template.threshold1 = s1;
    filter_conf_template.threshold2 = s2;

    filter_conf_template.filter_interval1 = p1;
    filter_conf_template.filter_interval2 = p2;

    filter_conf_template.enable1 = 1;
    filter_conf_template.enable2 = 1;

    if(t1 == 0){
        filter_conf_template.enable1 = 0;
    }
    if(t2 == 0){
        filter_conf_template.enable2 = 0;
    }

    cookie_filter_inited = 1;
    return 0;
}

/*
 * fun: refresh cookie connection statistics
 * arg: statistics struct
 * ret: always return 0
 *
 */

static inline int cookie_stat_refresh(cookie_req_stat *stat)
{
    stat->count1++;
    stat->count2++;

    return 0;
}

/*
 * fun: init cookie connection statistics
 * arg: statistics struct
 * ret: always return 0
 *
 */

static inline int cookie_req_stat_init(cookie_req_stat *stat)
{
    stat->time1 = time(NULL);
    stat->time2 = time(NULL);

    stat->count1 = 0;
    stat->count2 = 0;

    stat->filter_time1 = 0;
    stat->filter_time2 = 0;

    return 0;
}

static int cookie_pool_status_timer(unsigned long arg)
{
    (void)arg;
    char buf[4096];
    genpool_status(cookie_node_pool, buf, sizeof(buf));

    log(g_log, "%s\n", buf);

    return 0;
}
