#ifndef _IPFILTER_H_
#define _IPFILTER_H_

#include <stdint.h>
#include <time.h>

typedef struct _ip_req_stat{
    time_t   time1;
    time_t   time2;
    uint32_t count1;
    uint32_t count2;
    time_t   filter_time1;
    time_t   filter_time2;
}ip_req_stat;

int ip_pool_init(size_t max);
inline int ip_filter(uint32_t ip);
inline int ip_stat_refresh(uint32_t ip);
int ipfilter_conf_init(time_t t1, time_t t2, uint32_t s1, uint32_t s2, time_t p1, time_t p2);

#endif
