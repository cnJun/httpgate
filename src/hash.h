#ifndef _HASH_H_
#define _HASH_H_

#include <stdint.h>

inline uint64_t mmhash64(const void *key, int len);
inline uint64_t naivehash64(const void *key, int len);

#endif
