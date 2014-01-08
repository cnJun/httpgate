/*
 * Copyright 2011-2013 Alibaba Group Holding Limited. All rights reserved.
 * Use and distribution licensed under the GPL license.                   
 *
 * Authors: XiaoJinliang <xiaoshi.xjl@taobao.com>                          
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include "dict.h"
#include "conf.h"
#include "ups.h"
#include "log.h"

#define MAX_LINE_LEN 1024
#define MAX_HASH_BUCKET 67
#define MAX_KEY_LEN 512
#define MAX_VALUE_LEN 1024

static int inited;
static dict_t *dict;

static int parse(char *buf, unsigned long size, char **var, char **value);
static int trim(char *buf);
static char *conf_get(const char *var);
static int global_conf_init(void);
static int filter_conf_init(void);
static int upstream_conf_init(void);
static int get_var_int(const char *str, int def);
static char *get_var_str(const char *str, const char *def);

extern conf_global_t g_global_conf;
extern conf_filter_t g_filter_conf;
extern log_t *g_log;

/*
 * fun: init and parse conf file
 * arg: conf file
 * ret: success=0, error=-1
 *
 */

int conf_init(const char *conf)
{
    int ret, i, line = 1;
    uint64_t key;
    FILE *fp;
    char buffer[MAX_LINE_LEN];
    char *var, *value, *ptr;

    if(conf == NULL){
        return -1;
    }

    if(inited == 1){
        log(g_log, "conf[%s] inited duplicate\n", conf);
        return -1;
    } else {
        inited = 1;
    }

    dict = dict_init(MAX_HASH_BUCKET);
    if(dict == NULL){
        log(g_log, "dict_init error\n");
        return -1;
    }

    var = value = NULL;

    if( (fp = fopen(conf, "r")) == NULL){
        log(g_log, "fopen[%s] error, %s\n", conf, strerror(errno));
        return -1;
    }

    fgets(buffer, MAX_LINE_LEN, fp);
    while(!feof(fp)){
        line++;
        trim(buffer);
        if( (*buffer != '#') && (*buffer != '\0') ){
            ret = parse(buffer, strlen(buffer), &var, &value);
            if(ret < 0){
                log(g_log, "line %d, parse error, \"%s\"\n", line, buffer);
                return -1;
            } else if (ret == 0){
                ;
            } else {
                if( (var != NULL) && (value != NULL) ){
                    debug(g_log, "%s: %s\n", var, value);
                    ptr = dict_insert(dict, var, value);
                    if(ptr == NULL){
                        log(g_log, "line %d, dict_insert %s error\n", line, buffer);
                        return -1;
                    } else if(ptr != value) {
                        log(g_log, "line %d, dict_insert error, %s duplicate\n", line, buffer);
                        return -1;
                    }
                }
            }
        }
        fgets(buffer, sizeof(buffer), fp);
    }

    fclose(fp);

    ret = global_conf_init();
    if(ret < 0){
        log(g_log, "global_conf_init error\n");
        return -1;
    }
    ret = filter_conf_init();
    if(ret < 0){
        log(g_log, "filter_conf_init error\n");
        return -1;
    }
    ret = upstream_conf_init();
    if(ret < 0){
        log(g_log, "upstream_conf_init error\n");
        return -1;
    }

    return 0;
}

/*
 * fun: query value of var
 * arg: var string
 * ret: success!=NULL, error=NULL
 *
 */

static char *conf_get(const char *var)
{
    struct list_head *head, *pos;
    uint64_t key;
    char *value = NULL;

    if(inited == 0){
        log(g_log, "conf not inited\n");
        return NULL;
    }

    return dict_search(dict, (void *)var);
}

/*
 * fun: parse conf file line, it is ugly but it works
 * arg: conf file line buffer, buffer length, var pointer, value pointer
 * ret: error=-1, emptystring=0, success=1
 *
 */

static int parse(char *buf, unsigned long size, char **var, char **value)
{
    static int global, global_ok;
    static int filter, filter_ok;
    static int upstream, upstream_num;
    static int proxy, proxy_num;
    static int proxy_default, proxy_default_ok, host_default, host_default_ok;
    static int server_num;

    int ret;
    char k[MAX_KEY_LEN], v[MAX_VALUE_LEN], extra[MAX_VALUE_LEN];
    char o[MAX_KEY_LEN];

    ret = sscanf(buf, "%s%s%s", k, v, extra);
    if(ret <= 0){
        return -1;
    } else if(ret == 1) {
        if(!strncmp(k, "global{", 7)){
            if(global || global_ok || filter || upstream || proxy || proxy_default || host_default){
                return -1;
            } else {
                global = 1;
            }
        } else if(!strncmp(k, "filter{", 7)){
            if(filter || filter_ok || global || upstream || proxy || proxy_default || host_default){
                return -1;
            } else {
                filter = 1;
            }
        } else if(!strncmp(k, "upstream{", 9)){
            if(upstream || global || filter || proxy || proxy_default || host_default){
                return -1;
            } else {
                upstream = 1;
            }
        } else if(!strncmp(k, "proxy{", 6)){
            if(!upstream){
                return -1;
            } else {
                if(proxy || global || filter || proxy_default || host_default){
                    return -1;
                } else {
                    proxy = 1;
                }
            }
        } else if(!strncmp(k, "default{", 8)){
            if(proxy_default || host_default || proxy_default_ok || host_default || global || filter || proxy){
                return -1;
            } else {
                if(upstream){
                    proxy_default = 1;
                } else {
                    host_default = 1;
                }
            }
        } else if(!strncmp(k, "}", 1)){
            if(global){
                global = 0;
                global_ok = 1;
            } else if(filter){
                filter = 0;
                filter_ok = 1;
            } else if(proxy){
                proxy = 0;
                proxy_num++;
                server_num = 0;
            } else if(proxy_default){
                proxy_default = 0;
                proxy_default_ok = 1;
                server_num = 0;
            } else if(upstream){
                upstream = 0;
                upstream_num++;
                proxy_default_ok = 0;
                proxy_num = 0;
            } else if(host_default){
                host_default = 0;
                host_default_ok = 1;
                server_num = 0;
            } else {
                return -1;
            }
        } else {
            return -1;
        }

        return 0;
    } else if(ret == 2) {
        if(global){
            snprintf(o, sizeof(o), "global.%s", k);
        } else if(filter){
            snprintf(o, sizeof(o), "filter.%s", k);
        } else if(proxy){
            if(!strcmp(k, "server")){
                snprintf(o, sizeof(o), "upstream.%d.proxy.%d.%s.%d", \
                                    upstream_num, proxy_num, k, server_num);
                server_num++;
            } else {
                snprintf(o, sizeof(o), "upstream.%d.proxy.%d.%s", \
                                            upstream_num, proxy_num, k);
            }
        } else if(proxy_default){
            if(!strcmp(k, "server")){
                snprintf(o, sizeof(o), "upstream.%d.default.%s.%d", \
                                            upstream_num, k, server_num);
                server_num++;
            } else {
                snprintf(o, sizeof(o), "upstream.%d.default.%s", \
                                                    upstream_num, k);
            }
        } else if(upstream){
            snprintf(o, sizeof(o), "upstream.%d.%s", \
                                                    upstream_num, k);
        } else if(host_default){
            if(!strcmp(k, "server")){
                snprintf(o, sizeof(o), "default.%s.%d", k, server_num);
                server_num++;
            } else {
                snprintf(o, sizeof(o), "default.%s", k);
            }
        } else {
            return -1;
        }
        *var = strdup(o);
        *value = strdup(v);;

        return 1;
    } else {
        return -1;
    }
}

/*
 * fun: trim buffer
 * arg: character buffer
 * ret: number of character be trim
 *
 */

static int trim(char *buf)
{
    int i, len;
    int s_pos = 0, e_pos = 0, s_flag = 0, e_flag = 0;
    char *s, *e;

    len = strlen(buf);
    if(len == 0)
        return 0;

    s = buf;
    e = buf + len - 1;

    for(i = 0; i < len; i++){
        if(s_flag == 0){
            if(!isspace(*s)){
                s_flag = 1;
                if(e_flag == 1)
                    break;
            } else {
                s_pos++;
                s++;
            }
        }

        if(e_flag == 0){
            if(!isspace(*e)){
                e_flag = 1;
                if(s_flag == 1)
                    break;
            } else {
                e_pos++;
                e--;
            }
        }

        if(s_pos + e_pos >= len){
            break;
        }

    }

    if(s_pos + e_pos >= len){
        *buf = '\0';
        return len;
    }

    if(s_pos){
        memmove(buf, buf + s_pos, len - s_pos - e_pos);
    }
    buf[len - s_pos - e_pos] = '\0';

    return (s_pos + e_pos);
}

/*
 * fun: init global variable
 * arg: 
 * ret: always return 0
 *
 */

static int global_conf_init(void)
{
    g_global_conf.daemon = get_var_int("global.daemon", 1);
    g_global_conf.max_connections = get_var_int("global.max_connections", 1000000);
    g_global_conf.buffer_size = get_var_int("global.buffer_size", 16384);
    g_global_conf.max_buffer = get_var_int("global.max_buffer", 1000000);
    g_global_conf.workers = get_var_int("global.workers", 4);
    g_global_conf.cpu_attach = get_var_int("global.cpu_attach", 0);
    g_global_conf.keepalive_timeout = get_var_int("global.keepalive_timeout", 30);
    g_global_conf.max_keepalive_requests = get_var_int("global.max_keepalive_requests", 200);
    g_global_conf.read_client_timeout = get_var_int("global.read_client_timeout", 30);
    g_global_conf.connect_ups_timeout = get_var_int("global.connect_ups_timeout", 3);
    g_global_conf.write_ups_timeout = get_var_int("global.write_ups_timeout", 10);
    g_global_conf.write_client_timeout = get_var_int("global.write_client_timeout", 60);
    g_global_conf.listen_addr = get_var_str("global.listen_addr", "0.0.0.0");
    g_global_conf.listen_port = get_var_str("global.listen_port", "80");
    g_global_conf.log_path = get_var_str("global.log_path", "httpgate.log");
    g_global_conf.log_level = get_var_str("global.log_level", "log");

    return 0;
}

/*
 * fun: init filter variable
 * arg: 
 * ret: always return 0
 *
 */

static int filter_conf_init(void)
{
    g_filter_conf.ipfilter = get_var_int("filter.ipfilter", 1);
    g_filter_conf.ipfilter_cycle1 = get_var_int("filter.ipfilter_cycle1", 10);
    g_filter_conf.ipfilter_threshold1 = get_var_int("filter.ipfilter_threshold1", 150);
    g_filter_conf.ipfilter_time1 = get_var_int("filter.ipfilter_time1", 10);
    g_filter_conf.ipfilter_cycle2 = get_var_int("filter.ipfilter_cycle2", 10);
    g_filter_conf.ipfilter_threshold2 = get_var_int("filter.ipfilter_threshold2", 150);
    g_filter_conf.ipfilter_time2 = get_var_int("filter.ipfilter_time2", 10);

    g_filter_conf.cookiefilter = get_var_int("filter.cookiefilter", 0);
    g_filter_conf.cookiefilter_cycle1 = get_var_int("filter.cookiefilter_cycle1", 10);
    g_filter_conf.cookiefilter_threshold1 = get_var_int("filter.cookiefilter_threshold1", 60);
    g_filter_conf.cookiefilter_time1 = get_var_int("filter.cookiefilter_time1", 10);
    g_filter_conf.cookiefilter_cycle2 = get_var_int("filter.cookiefilter_cycle2", 10);
    g_filter_conf.cookiefilter_threshold2 = get_var_int("filter.cookiefilter_threshold2", 60);
    g_filter_conf.cookiefilter_time2 = get_var_int("filter.cookiefilter_time2", 10);

    g_filter_conf.whitelist = get_var_str("filter.whitelist", "./conf/whitelist");
    g_filter_conf.blacklist = get_var_str("filter.blacklist", "./conf/blacklist");

    return 0;
}

/*
 * fun: init upstream variable and register upstream
 * arg: 
 * ret: success=0, error<0
 *
 */

static int upstream_conf_init(void)
{
    int i, j, k, ret;
    char buf[1024];
    char *host, *uri, *srv, *port;
    int balance, retry;

    ret = ups_tree_init();
    if(ret < 0){
        log(g_log, "ups_tree_init error\n");
    }

    for(i = 0;;i++){
        snprintf(buf, sizeof(buf), "upstream.%d.host", i);
        host = conf_get(buf);
        if(host == NULL){
            break;
        } else {
            for(j = 0;;j++){
                snprintf(buf, sizeof(buf), 
                                "upstream.%d.proxy.%d.uri", i, j);
                uri = conf_get(buf);
                if(uri == NULL){
                    break;
                } else {
                    for(k = 0;;k++){
                        snprintf(buf, sizeof(buf), 
                            "upstream.%d.proxy.%d.server.%d", i, j, k);
                        srv = conf_get(buf);
                        if(srv == NULL){
                            if(k == 0){
                                log(g_log, "error, %s not exist\n", buf);
                                return -1;
                            } else {
                                break;
                            }
                        } else {
                            strncpy(buf, srv, sizeof(buf));
                            port = strchr(buf, ':');
                            if(port == NULL){
                                log(g_log, "parameter error, %s\n", buf);
                                return -1;
                            } else {
                                *port = '\0';
                                port++;
                            }

                            srv = buf;
                            ret = ups_register(host, uri, srv, port);
                            if(ret < 0){
                                log(g_log, "ups_register error, host[%s] uri[%s] srv[%s] port[%s]\n", \
                                                                                    host, uri, srv, port);
                                return ret;
                            } else {
                                log(g_log, "ups_register success, host[%s] uri[%s] srv[%s] port[%s]\n", \
                                                                                    host, uri, srv, port);
                            }
                        }
                    }
                    snprintf(buf, sizeof(buf), 
                                "upstream.%d.proxy.%d.balance", i, j);
                    balance = get_var_int(buf, BALANCE_IP);
                    ret = ups_set_balance(host, uri, balance);
                    if(ret < 0){
                        log(g_log, "ups_set_balance error, host[%s] uri[%s] balance[%d]\n", \
                                                                                host, uri, balance);
                        return ret;
                    } else {
                        log(g_log, "ups_set_balance success, host[%s] uri[%s] balance[%d]\n", \
                                                                                host, uri, balance);
                    }

                    snprintf(buf, sizeof(buf), 
                                "upstream.%d.proxy.%d.retry", i, j);
                    retry = get_var_int(buf, 3);
                    ret = ups_set_maxretry(host, uri, retry);
                    if(ret < 0){
                        log(g_log, "ups_set_maxretry error, host[%s] uri[%s] retry[%d]\n", \
                                                                        host, uri, retry);
                        return ret;
                    } else {
                        log(g_log, "ups_set_maxretry success, host[%s] uri[%s] retry[%d]\n", \
                                                                        host, uri, retry);
                    }
                }
            }

            for(k = 0;; k++){
                snprintf(buf, sizeof(buf), \
                            "upstream.%d.default.server.%d", i, k);
                srv = conf_get(buf);
                if(srv == NULL){
                    if(k == 0){
                        log(g_log, "%s not exist\n", buf);
                        return -1;
                    } else {
                        break;
                    }
                } else {
                    strncpy(buf, srv, sizeof(buf));
                    port = strchr(buf, ':');
                    if(port == NULL){
                        log(g_log, "%s parameter error\n", buf);
                        return -1;
                    } else {
                        *port = '\0';
                        port++;
                    }

                    srv = buf;
                    ret = ups_register(host, NULL, srv, port);
                    if(ret < 0){
                        log(g_log, "ups_register error, host[%s] uri[default] srv[%s] port[%s]\n", \
                                                                            host, srv, port);
                        return ret;
                    } else {
                        log(g_log, "ups_register success, host[%s] uri[default] srv[%s] port[%s]\n", \
                                                                            host, srv, port);
                    }
                }
            }

            snprintf(buf, sizeof(buf), "upstream.%d.default.balance", i);
            balance = get_var_int(buf, BALANCE_IP);
            ret = ups_set_balance(host, NULL, balance);
            if(ret < 0){
                log(g_log, "ups_set_balance error, host[%s] uri[default] balance[%d]\n", \
                                                                host, balance);
                return ret;
            } else {
                log(g_log, "ups_set_balance success, host[%s] uri[default] balance[%d]\n", \
                                                                host, balance);
            }

            snprintf(buf, sizeof(buf), "upstream.%d.default.retry", i);
            retry = get_var_int(buf, 3);
            ret = ups_set_maxretry(host, NULL, retry);
            if(ret < 0){
                log(g_log, "ups_set_maxretry error, host[%s] uri[default] retry[%d]\n", \
                                                                host, retry);
                return ret;
            } else {
                log(g_log, "ups_set_maxretry success, host[%s] uri[default] retry[%d]\n", \
                                                                host, retry);
            }

        }
    }

    for(k = 0;;k++){
        snprintf(buf, sizeof(buf), "default.server.%d", k);
        srv = conf_get(buf);
        if(srv == NULL){
            if(k == 0){
                log(g_log, "%s not exist\n", buf);
                return -1;
            } else {
                break;
            }
        } else {
            strncpy(buf, srv, sizeof(buf));
            port = strchr(buf, ':');
            if(port == NULL){
                log(g_log, "%s parameter error\n", buf);
                return -1;
            } else {
                *port = '\0';
                port++;
            }

            srv = buf;
            ret = ups_register(NULL, NULL, srv, port);
            if(ret < 0){
                log(g_log, "ups_register error, host[default] uri[default] srv[%s] port[%s]\n", \
                                                                                    srv, port);
                return ret;
            } else {
                log(g_log, "ups_register success, host[default] uri[default] srv[%s] port[%s]\n", \
                                                                                    srv, port);
            }
        }
    }

    snprintf(buf, sizeof(buf), "default.balance");
    balance = get_var_int(buf, BALANCE_IP);
    ret = ups_set_balance(NULL, NULL, balance);
    if(ret < 0){
        log(g_log, "ups_set_balance error, host[default] uri[default] balance[%d]\n", \
                                                                    balance);
        return ret;
    } else {
        log(g_log, "ups_set_balance success, host[default] uri[default] balance[%d]\n", \
                                                                    balance);
    }

    snprintf(buf, sizeof(buf), "default.retry");
    retry = get_var_int(buf, 3);
    ret = ups_set_maxretry(NULL, NULL, retry);
    if(ret < 0){
        log(g_log, "ups_set_maxretry error, host[default] uri[default] retry[%d]\n", \
                                                                    retry);
        return ret;
    } else {
        log(g_log, "ups_set_maxretry success, host[default] uri[default] retry[%d]\n", \
                                                                    retry);
    }

    return 0;
}

/*
 * fun: get int variable to string
 * arg: string & default variable
 * ret: int variable
 *
 */

static int get_var_int(const char *str, int def)
{
    long int var = 0;
    char *endptr, *ptr;

    if(str == NULL){
        log(g_log, "argument null, return default[%d]\n", str, def);
        return def;
    }

    ptr = conf_get(str);
    if(ptr == NULL){
        log(g_log, "argument[%s] not exist, return default[%d]\n", str, def);
        return def;
    }

    if(!strncmp(ptr, "", 1)){
        log(g_log, "argument[%s] empty, return default[%d]\n", str, def);
        return def;
    }

    errno = 0;
    var = strtol(ptr, &endptr, 10);

    if( (errno == ERANGE && (var == LONG_MAX || var == LONG_MIN)) 
                                            || (errno != 0 && var == 0) ) {
        log(g_log, "strtol[%s] error, return default[%d]\n", ptr, def);
        return def;
    }

    if(endptr == ptr){
        log(g_log, "No digits were found, return default[%d]\n", def);
        return def;
    }

    return var;
}

/*
 * fun: get string variable
 * arg: string and default string
 * ret: string variable
 *
 */

static char *get_var_str(const char *str, const char *def)
{
    int var = 0;
    char *endptr, *ptr;

    if(str == NULL){
        log(g_log, "argument null, return default[%s]\n", str, def);
        return (char *)def;
    }

    ptr = conf_get(str);
    if(ptr == NULL){
        log(g_log, "argument[%s] not exist, return default[%s]\n", str, def);
        return (char *)def;
    }

    if(!strncmp(ptr, "", 1)){
        log(g_log, "argument[%s] empty, return default[%s]\n", str, def);
        return (char *)def;
    }

    return ptr;
}
