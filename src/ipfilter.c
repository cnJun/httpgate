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
#include "ipfilter.h"
#include "log.h"
#include "common.h"
#include "timer.h"

#define IP_BUCKET_NUM (1<<21)
#define IP_TIMEOUT 300

extern log_t *g_log;

typedef struct _ip_bucket_t{
    struct list_head head;
} ip_bucket_t;

typedef struct _ip_filter_conf{
    time_t   period1;
    time_t   period2;
    uint32_t threshold1;
    uint32_t threshold2;
    time_t   filter_interval1;
    time_t   filter_interval2;
    int      enable1;
    int      enable2;
} ip_filter_conf;

typedef struct _ip_node_t{
    uint32_t ip;
    struct list_head link;
    struct list_head timer_link;
    ip_req_stat stat;
    time_t last_access;
    ip_filter_conf *filter_conf;
} ip_node_t;

static genpool_handler_t *ip_node_pool;
static ip_bucket_t *ip_bucket_array;
static struct list_head timer_head;
static ip_filter_conf filter_conf_template;
static ip_filter_inited = 0;

static inline int ip_is_filtered(ip_node_t *node);
static inline int ip_req_stat_init(ip_req_stat *stat);

static int ip_pool_clean_timer(unsigned long max);
static int ip_pool_status_timer(unsigned long arg);

/*
 * fun: check ip is filtered or not
 * arg: ip node pointer
 * ret: filtered=1, not_filtered=0
 *
 */

static inline int ip_is_filtered(ip_node_t *node)
{
    time_t now = time(NULL);
    int isfiltered = 0, outoffilter = 0;
    ip_req_stat *stat;
    ip_filter_conf *filter_conf;
    char ipstr[32];

    stat = &(node->stat);
    filter_conf = node->filter_conf;

    if(ip_filter_inited == 0){
        log(g_log, "ip filter not inited\n");
        return -1;
    }

    if(filter_conf->enable1){
        if(now - stat->filter_time1 <= filter_conf->filter_interval1){
            isfiltered = 1;
        } else {
            if(stat->filter_time1 != 0){
                outoffilter = 1;
            }
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
            if(stat->filter_time2 != 0){
                outoffilter = 1;
            }
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

    if( (isfiltered == 0) && (outoffilter == 1) ){
        ipint2str(ipstr, sizeof(ipstr), node->ip);
        log(g_log, "ip[%s] outoffilter\n", ipstr);
    }

    return isfiltered;
}

/*
 * fun: ip pool init
 * arg: max ip node
 * ret: error=-1, success=0
 *
 */

int ip_pool_init(size_t max)
{
    int i;

    ip_bucket_array = malloc(sizeof(ip_bucket_t) * IP_BUCKET_NUM);
    if(ip_bucket_array == NULL){
        return -1;
    }

    for(i = 0; i < IP_BUCKET_NUM; i++){
        INIT_LIST_HEAD(&(ip_bucket_array[i].head));
    }

    INIT_LIST_HEAD(&timer_head);

    ip_node_pool = genpool_init(sizeof(ip_node_t), max);
    if(ip_node_pool == NULL){
        free(ip_bucket_array);
        return -1;
    }

    if(timer_register(ip_pool_clean_timer, 30, "ip_pool_clean_timer", 5) < 0){
        log(g_log, "ip_pool_clean_timer register error\n");
        return -1;
    }

    if(timer_register(ip_pool_status_timer, 0, "ip_pool_status_timer", 300) < 0){
        log(g_log, "ip_pool_status_timer register error\n");
        return -1;
    }

    return 0;
}

/*
 * fun: ip filter
 * arg: client ip
 * ret: filtered=1, not_filtered=0
 *
 */

inline int ip_filter(uint32_t ip)
{
    uint64_t index;
    ip_node_t *node;
    struct list_head *head, *pos;

    index = ip & (IP_BUCKET_NUM - 1);
    head = &(ip_bucket_array[index].head);

    list_for_each(pos, head)
    {
        node = list_entry(pos, ip_node_t, link);
        if(ip == node->ip){
            return ip_is_filtered(node);
        } else {
            continue;
        }
    }

    return 0;
}

/*
 * fun: ip pool clean timer
 * arg: max cleaned per time
 * ret: num of cleaned
 *
 */

static int ip_pool_clean_timer(unsigned long max)
{
    int count = 0;
    struct list_head *pos, *n, *head;
    ip_node_t *node;
    time_t now = time(NULL);
    char ipstr[32];

    head = &timer_head;
    list_for_each_safe(pos, n, head){
        node = list_entry(pos, ip_node_t, timer_link);
        if(now - node->last_access > IP_TIMEOUT){
            list_del_init(&(node->link));
            list_del_init(&(node->timer_link));
            ipint2str(ipstr, sizeof(ipstr), node->ip);
            debug(g_log, "ip[%s] release\n", ipstr);
            genpool_release_page(ip_node_pool, node);
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
 * fun: ip filter config init
 * arg: period1, period2, shreshold1, shreshold2, filter1, filter2
 * ret: always return 0
 *
 */

int ipfilter_conf_init(time_t t1, time_t t2, uint32_t s1, uint32_t s2, time_t p1, time_t p2)
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

    ip_filter_inited = 1;

    return 0;
}

/*
 * fun: init ip request stat
 * arg: ip request stat struct pointer
 * ret: always return 0
 *
 */

static inline int ip_req_stat_init(ip_req_stat *stat)
{
    stat->time1 = time(NULL);
    stat->time2 = time(NULL);

    stat->count1 = 0;
    stat->count2 = 0;

    stat->filter_time1 = 0;
    stat->filter_time2 = 0;

    return 0;
}

/*
 * fun: refresh ip request stat
 * arg: client ip
 * ret: always return 0
 *
 */

inline int ip_stat_refresh(uint32_t ip)
{
    uint64_t index;
    ip_node_t *node;
    struct list_head *head, *pos;
    ip_node_t *tmp;

    index = ip & (IP_BUCKET_NUM - 1);
    head = &(ip_bucket_array[index].head);

    list_for_each(pos, head)
    {
        tmp = list_entry(pos, ip_node_t, link);
        if(ip == tmp->ip){
            list_move(&(tmp->link), head);
            list_move_tail(&(tmp->timer_link), &timer_head);
            tmp->stat.count1 = tmp->stat.count1 + 1;
            tmp->stat.count2 = tmp->stat.count2 + 1;
            tmp->last_access = time(NULL);

            return 0;
        } else {
            continue;
        }
    }

    node = genpool_alloc_page(ip_node_pool);
    if(node == NULL){
        return 0;
    }

    node->ip = ip;
    ip_req_stat_init(&(node->stat));
    node->last_access = time(NULL);
    node->filter_conf = &filter_conf_template;
    
    node->stat.count1 = node->stat.count1 + 1;
    node->stat.count2 = node->stat.count2 + 1;

    list_add(&(node->link), head);
    list_add_tail(&(node->timer_link), &timer_head);

    return 0;
}

static int ip_pool_status_timer(unsigned long arg)
{
    (void)arg;
    char buf[4096];

    genpool_status(ip_node_pool, buf, sizeof(buf));
    log(g_log, "%s\n", buf);

    return 0;
}
