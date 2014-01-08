#ifndef _SOCK_H_
#define _SOCK_H_

#include <stdint.h>
#include "connection.h"

inline int make_listen_nonblock(const char *host, const char *serv);
inline int connect_nonblock(const char *host, const char *serv, int *flag);
inline int setnonblock(int fd);

inline int read_client_prepare(connection_t *c);
inline int read_ups_prepare(connection_t *c);

inline int read_client(connection_t *c, int *retcode);
inline int write_ups(connection_t *c, int *retcode);
inline int read_ups(connection_t *c, int *retcode);
inline int write_client(connection_t *c, int *retcode);

inline int accept_client(int sockfd, struct sockaddr_in *cliaddr, socklen_t *len);

#endif
