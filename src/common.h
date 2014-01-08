#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdint.h>

int ipstr2int(uint32_t *ip, const char *ipstr);
int ipint2str(char *ipstr, size_t n, uint32_t ip);

#endif
