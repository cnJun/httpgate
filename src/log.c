/*
 * Copyright 2011-2013 Alibaba Group Holding Limited. All rights reserved.
 * Use and distribution licensed under the GPL license.                   
 *
 * Authors: XiaoJinliang <xiaoshi.xjl@taobao.com>                          
 *
 */                                                                       

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h>
#include <unistd.h>
#include "log.h"

#define BUFFSIZE 8192

static int log_inited = 0;

static int log_doit(log_t *log, int level, const char *file, int line, \
                            const char *func, const char *fmt, va_list ap);

/*
 * fun: open log file and init log_t
 * arg: logfile: fname, loglevel: level
 * ret: success!=NULL, error==NULL
 *
 */

log_t *log_init(const char *fname, int level)
{
    int fd, ret;
    struct stat statbuf;
    log_t *log;

    log = malloc(sizeof(log_t));
    if(log == NULL){
        fprintf(stderr, "malloc log_t error, %s", strerror(errno));
        return NULL;
    }

    bzero(log, sizeof(log));
    fd = open(fname, O_WRONLY|O_APPEND|O_CREAT, S_IRWXU|S_IRGRP|S_IROTH);
    if(fd < 0){
        fprintf(stderr, "open %s error, %s", fname, strerror(errno));
        free(log);
        return NULL;
    }

    ret = fstat(fd, &statbuf);
    if(ret < 0){
        fprintf(stderr, "stat %s error, %s", fname, strerror(errno));
        close(fd);
        free(log);
        return NULL;
    }


    log->fd = fd;
    log->level = level;
    log->fname = strdup(fname);
    if(log->fname == NULL){
        close(fd);
        free(log);
        return NULL;
    }
    log->statbuf = statbuf;

    log_inited = 1;

    return log;
}

/*
 * fun: close log file and free mem
 * arg: log_t
 * ret: always return 0
 *
 */

int log_deinit(log_t *log)
{
    int ret;

    close(log->fd);
    free(log->fname);

    free(log);

    log_inited = 0;

    return 0;
}

/*
 * fun: log format
 * arg: log handler, log level, program file, program line, program function, format...
 * ret: error=-1, success=log written
 *
 */

int log_ret(log_t *log, int level, const char *file, int line, const char *func, const char *fmt,...)
{
    int ret;
    va_list ap;

    va_start(ap, fmt);
    ret = log_doit(log, level, file, line, func, fmt, ap);
    va_end(ap);
    return ret;
}

/*
 * fun: real log function
 * arg: ...
 * ret: error=-1, success=log written
 *
 */

static int log_doit(log_t *log, int level, const char *file, int line, \
                            const char *func, const char *fmt, va_list ap)
{
    int n = 0, len = 0, ret, fd;
    char buf[BUFFSIZE];
    char timebuf[64];
    time_t t;
    struct tm tm;
    static time_t last = 0;

    struct stat statbuf;
    ino_t  i1, i2;

    if(log_inited){
        if(log->level < level){
            return 0;
        }
    } else {
        if(!isatty(STDERR_FILENO)){
            return -1;
        }
    }

    pid_t pid = getpid();

    t = time(NULL);
    localtime_r(&t, &tm);
    strftime(timebuf, sizeof(timebuf), "%F %T", &tm);

    n = snprintf(buf + len, BUFFSIZE - len - 1, "%s pid[%d] %s[%d] %s() - ", \
                                    timebuf, pid, file, line, func);

    if(n > BUFFSIZE - len - 1){
        n = BUFFSIZE - len - 1;
    }
    len += n;

    n = vsnprintf(buf + len, BUFFSIZE - len - 1, fmt, ap);
    if(n > BUFFSIZE - len - 1){
        n = BUFFSIZE - len - 1;
    }
    len += n;

    buf[len] = '\0';
    if(log_inited){
        n = write(log->fd, buf, len);
    } else {
        n = write(STDERR_FILENO, buf, len);
        return n;
    }

    if(t > last){
        last = t;
        i1 = log->statbuf.st_ino;

        ret = stat(log->fname, &statbuf);
        if(ret < 0){
            if(errno != ENOENT){
                fprintf(stderr, "stat %s error, %s", log->fname, strerror(errno));
                return -1;
            } else {
                fd = open(log->fname, O_WRONLY|O_APPEND|O_CREAT, S_IRWXU|S_IRGRP|S_IROTH);

                if(fd < 0){
                    fprintf(stderr, "open %s error, %s", log->fname, strerror(errno));
                    return -1;
                } else {
                    ret = fstat(fd, &statbuf);
                    if(ret < 0){
                        fprintf(stderr, "stat %s error, %s", log->fname, strerror(errno));
                        close(fd);
                        return -1;
                    } else {
                        close(log->fd);
                        log->fd = fd;
                        log->statbuf = statbuf;
                        fprintf(stdout, "reopen %s success\n", log->fname);
                    }

                }
            }
        } else {
            i2 = statbuf.st_ino;

            if(i1 != i2){
                fd = open(log->fname, O_WRONLY|O_APPEND|O_CREAT, S_IRWXU|S_IRGRP|S_IROTH);

                if(fd < 0){
                    fprintf(stderr, "open %s error, %s", log->fname, strerror(errno));
                    return -1;
                } else {
                    fprintf(stdout, "reopen %s success\n", log->fname);
                    close(log->fd);
                    log->fd = fd;
                    log->statbuf = statbuf;
                }
            }
        }

    }

    return n;
}
