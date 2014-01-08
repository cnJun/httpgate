#ifndef _CONF_H_
#define _CONF_H_

typedef struct conf_global{
    int daemon;
    int max_connections;
    int buffer_size;
    int max_buffer;
    int workers;
    int cpu_attach;
    int keepalive_timeout;
    int max_keepalive_requests;
    int read_client_timeout;
    int connect_ups_timeout;
    int write_ups_timeout;
    int write_client_timeout;
    char *listen_addr;
    char *listen_port;
    char *log_path;
    char *log_level;
} conf_global_t;

typedef struct conf_filter{
    int ipfilter;
    int ipfilter_cycle1;
    int ipfilter_threshold1;
    int ipfilter_time1;
    int ipfilter_cycle2;
    int ipfilter_threshold2;
    int ipfilter_time2;

    int cookiefilter;
    int cookiefilter_cycle1;
    int cookiefilter_threshold1;
    int cookiefilter_time1;
    int cookiefilter_cycle2;
    int cookiefilter_threshold2;
    int cookiefilter_time2;

    char *whitelist;
    char *blacklist;
} conf_filter_t;

int conf_init(const char *conf);

#endif
