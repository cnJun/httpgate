/*
 * Copyright 2011-2013 Alibaba Group Holding Limited. All rights reserved.
 * Use and distribution licensed under the GPL license.                   
 *
 * Authors: XiaoJinliang <xiaoshi.xjl@taobao.com>                          
 *
 */                                                                       

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "log.h"
#include "ipfilter.h"
#include "iprange.h"
#include "ups.h"
#include "conf.h"
#include "timer.h"

#define VERSION "1.2.0"

conf_global_t g_global_conf;
conf_filter_t g_filter_conf;

log_t *g_log;
iprange_t *g_whitelist, *g_blacklist;
int g_listenfd, g_epfd;
int g_reload;

static int signal_init(void);
static void signal_usr1(int signal);
static int cpu_attach(pid_t pid, int cpu);

#define USAGE(){ \
    fprintf(stderr, "Version: %s\n", VERSION); \
    fprintf(stderr, "Usage: %s config\n\n", argv[0]); \
    fprintf(stderr, "Copyright 2011-2013 Alibaba Group Holding Limited. All rights reserved.\n"); \
    fprintf(stderr, "Use and distribution licensed under the GPL license.\n\n"); \
    fprintf(stderr, "Authors: XiaoJinliang <xiaoshi.xjl@taobao.com>\n"); \
}

int main(int argc, char *argv[])
{
    int ret, i, cpu = 0, level;
    pid_t pid;
    char buf1[128], buf2[128], buf[8192];

    // argument parse
    if(argc != 2){
        USAGE();
        exit(-1);
    }

    if(!strcmp(argv[1], "-h")){
        USAGE();
        exit(0);
    }

    // config file parse
    if( (ret = conf_init(argv[1])) < 0 ){
        log(g_log, "conf[%s] init error\n", argv[1]);
        exit(-1);
    } else {
        log(g_log, "conf[%s] init success\n", argv[1]);
    }

    // log init
    if(!strncmp(g_global_conf.log_level, "log", 3)){
        level = LOG_LEVEL_LOG;
    } else if(!strncmp(g_global_conf.log_level, "debug", 5)){
        level = LOG_LEVEL_DEBUG;
    } else if(!strncmp(g_global_conf.log_level, "info", 4)){
        level = LOG_LEVEL_INFO;
    } else if(!strncmp(g_global_conf.log_level, "none", 4)){
        level = LOG_NONE;
    } else {
        log(g_log, "log_level[%s] unknown\n", g_global_conf.log_level);
        exit(-1);
    }

    if( (g_log = log_init(g_global_conf.log_path, level)) == NULL ){
        log(g_log, "log[%s] init error\n", g_global_conf.log_path);
        exit(-1);
    }

    // signal init
    if( (signal_init()) < 0 ){
        log(g_log, "signal init error\n");
        exit(-1);
    } else {
        log(g_log, "signal init success\n");
    }

    // timer init
    if( (timer_init()) < 0 ){
        log(g_log, "timer init error\n");
        exit(-1);
    } else {
        log(g_log, "timer init success\n");
    }

    // conneciont init
    if( (ret = connection_init(g_global_conf.max_connections)) < 0 ){
        log(g_log, "connection init error\n");
        exit(-1);
    } else {
        log(g_log, "connection init success\n");
    }

    // ipfilter init
    ret = ipfilter_conf_init(g_filter_conf.ipfilter_cycle1, g_filter_conf.ipfilter_cycle2, \
                        g_filter_conf.ipfilter_threshold1, g_filter_conf.ipfilter_threshold2, \
                        g_filter_conf.ipfilter_time1, g_filter_conf.ipfilter_time2);
    if(ret < 0){
        log(g_log, "ipfilter init error\n");
    } else {
        log(g_log, "ipfilter init success\n");
    }    

    // cookiefilter init
    ret = cookiefilter_conf_init(g_filter_conf.cookiefilter_cycle1, g_filter_conf.cookiefilter_cycle2, \
                        g_filter_conf.cookiefilter_threshold1, g_filter_conf.cookiefilter_threshold2, \
                        g_filter_conf.cookiefilter_time1, g_filter_conf.cookiefilter_time2);
    if(ret < 0){
        log(g_log, "cookiefilter init error\n");
    } else {
        log(g_log, "cookiefilter init success\n");
    }    

    // ippool & ipentry init
    if( (ret = ip_pool_init(g_global_conf.max_connections)) < 0 ){
        log(g_log, "ip pool init error\n");
        exit(-1);
    } else {
        log(g_log, "ip pool init success\n");
    }

    // cookie pool init
    if( (ret = cookie_pool_init(1000000)) < 0 ){
        log(g_log, "cookie pool init error\n");
        exit(-1);
    } else {
        log(g_log, "cookie pool init success\n");
    }

    // whitelist init
    if( (g_whitelist = iprange_init(g_filter_conf.whitelist, 1024)) == NULL ){
        log(g_log, "whitelist[%s] init error\n", g_filter_conf.whitelist);
        exit(-1);
    } else {
        log(g_log, "whitelist[%s] init success\n", g_filter_conf.whitelist);
    }

    // blacklist init
    if( (g_blacklist = iprange_init(g_filter_conf.blacklist, 1024)) == NULL ){
        log(g_log, "blacklist[%s] init error\n", g_filter_conf.blacklist);
        exit(-1);
    } else {
        log(g_log, "blacklist[%s] init success\n", g_filter_conf.blacklist);
    }

    // mempool init
    if( (ret = mempool_init(g_global_conf.buffer_size, g_global_conf.max_buffer)) < 0 ){
        log(g_log, "mempool init error\n");
        exit(-1);
    } else {
        log(g_log, "mempool init success\n");
    }

    log(g_log, "all init success\n");

    // make listen
    while(1){
        g_listenfd = make_listen_nonblock(g_global_conf.listen_addr, g_global_conf.listen_port);
        if(g_listenfd < 0){
            log(g_log, "make listen socket error\n");
        } else {
            log(g_log, "make listen socket success %s:%s\n", \
                                g_global_conf.listen_addr, g_global_conf.listen_port);
            break;
        }

        sleep(5);
    }

    if(g_global_conf.daemon){
        daemon(1, 0);
    }

    // fork children
    for(i = 0; i < g_global_conf.workers ; i++){
        if( (pid = fork()) < 0 ){
            log(g_log, "fork error: %s\n", strerror(errno));
            exit(-1);
        } else if(pid > 0) {
            if(g_global_conf.cpu_attach == 1){
                if(cpu_attach(pid, cpu++) == 0){
                    log(g_log, "cpu attach success\n");
                }
            }
            continue;
        } else {
            work();
            exit(-1);
        }
    }

    while(1){
        sleep(5);

        // reopen to release log file when deleted
        log_deinit(g_log);
        if( (g_log = log_init(g_global_conf.log_path, level)) == NULL ){
            log(g_log, "log init error\n");
        }

        pid = waitpid(-1, NULL, WNOHANG);

        if(pid > 0){
            log(g_log, "process[%d] exit, restart again\n", pid);

            while( (pid = fork()) == -1 ){
                log(g_log, "fork error: %s\n", strerror(errno));
                sleep(5);
            }

            if(pid > 0){
                log(g_log, "fork success\n");
                continue;
            } else {
                log(g_log, "goto work\n");
                work();
                exit(-1);
            }
        } else if(pid < 0) {
            log(g_log, "wait error: %s\n", strerror(errno));
        } else {
        }
    }

    return 0;
}

static int signal_init(void)
{
    //signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGILL, SIG_IGN);
    signal(SIGTRAP, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
    signal(SIGKILL, SIG_IGN);
    signal(SIGUSR1, signal_usr1);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, SIG_IGN);
    signal(SIGCONT, SIG_IGN);

    return 0;
}

static void signal_usr1(int signal)
{
    g_reload = 1;

    return;
}

static int cpu_attach(pid_t pid, int cpu)
{
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);

    if(sched_setaffinity(pid, sizeof(cpu_set_t), &mask)){
        log(g_log, "sched_setaffinity: %s\n", strerror(errno));
        return -1;
    }

    return 0;

}
