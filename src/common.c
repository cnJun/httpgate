/*
 * Copyright 2011-2013 Alibaba Group Holding Limited. All rights reserved.
 * Use and distribution licensed under the GPL license.                   
 *
 * Authors: XiaoJinliang <xiaoshi.xjl@taobao.com>                          
 *
 */                                                                       

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include "common.h"

/*
 * fun: translate xxx.xxx.xxx.xxx to uint32_t
 * arg: uint32_t ip, xxx.xxx.xxx.xxx
 * ret: success=0 error=-1
 */
int ipstr2int(uint32_t *ip, const char *ipstr)
{
    int ret;
    struct in_addr addr;

    ret = inet_pton(AF_INET, ipstr, (void *)&addr);
    if(ret <= 0){
        return -1;
    }

    *ip = ntohl(addr.s_addr);

    return 0;
}

/*
 * fun: translate uint32_t to uint32_t
 * arg: xxx.xxx.xxx.xxx, uint32_t ip
 * ret: success=0 error=-1
 */
int ipint2str(char *ipstr, size_t n, uint32_t ip)
{
    struct in_addr addr;

    addr.s_addr = htonl(ip);
    if(inet_ntop(AF_INET, (void *)&addr, ipstr, n) == NULL){
        return -1;
    }

    return 0;
}
