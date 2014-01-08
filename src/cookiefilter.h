#ifndef _COOKIEPOOL_H_
#define _COOKIEPOOL_H_

#include <stdint.h>

typedef struct _cookie_req_stat{
    time_t   time1;
    time_t   time2;
    uint32_t count1;
    uint32_t count2;
    time_t   filter_time1;
    time_t   filter_time2;
}cookie_req_stat;

int cookie_pool_init(size_t max);
inline int cookie_filter(const char *cookie, int len);

int cookiefilter_conf_init(time_t t1, time_t t2, uint32_t s1, uint32_t s2, time_t p1, time_t p2);

#endif
