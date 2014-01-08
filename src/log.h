#ifndef __LOG_H_
#define __LOG_H_

#include <pthread.h>
#include <sys/stat.h>

#define DEBUG

typedef struct _log_t{
    char *fname;
    int fd;
    struct stat statbuf;
    int level;
    pthread_mutex_t lock;
} log_t;

log_t *log_init(const char *fname, int level);
int log_deinit(log_t *log);
int log_ret(log_t *log, int level, const char *, int, const char *, const char *, ...);

enum{
    LOG_NONE = 0,
    LOG_LEVEL_LOG,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO
};

#define log(log, ...) log_ret(log, LOG_LEVEL_LOG, __FILE__, __LINE__, __func__, __VA_ARGS__)
#ifdef DEBUG
#define debug(log, ...) log_ret(log, LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define debug(...)
#endif

#define info(log, ...) log_ret(log, LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, __VA_ARGS__)

#endif
