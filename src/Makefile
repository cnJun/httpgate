CC = gcc
CFLAGS = -O2
OBJECT = common.o connection.o genpool.o http.o ipfilter.o iprange.o log.o main.o mempool.o sock.o state.o work.o ups.o hash.o md5.o cookiefilter.o timer.o conf.o dict.o

all : $(OBJECT)
	gcc -o httpgate $(OBJECT)

main.o	:	main.c iprange.h log.h ipfilter.h ups.h conf.h timer.h
	gcc -c main.c $(CFLAGS) -D_GNU_SOURCE

common.o	:	common.c common.h
	gcc -c common.c $(CFLAGS)

connection.o	:	connection.c connection.h ipfilter.h list.h genpool.h log.h http.h iprange.h timer.h ups.h conf.h
	gcc -c connection.c $(CFLAGS)

genpool.o	:	genpool.c genpool.h list.h log.h
	gcc -c genpool.c $(CFLAGS)

http.o	:	http.c http.h mempool.h
	gcc -c http.c $(CFLAGS) -D_GNU_SOURCE

ipfilter.o	:	ipfilter.c ipfilter.h list.h common.h genpool.h log.h timer.h
	gcc -c ipfilter.c $(CFLAGS)

iprange.o	:	iprange.c iprange.h common.h log.h
	gcc -c iprange.c $(CFLAGS)

log.o	:	log.c log.h
	gcc -c log.c $(CFLAGS)

mempool.o	:	mempool.c mempool.h genpool.h log.h
	gcc -c mempool.c $(CFLAGS)

sock.o	:	sock.c sock.h log.h common.h
	gcc -c sock.c $(CFLAGS)

state.o	:   state.c http.h connection.h list.h log.h ups.h common.h conf.h
	gcc -c state.c $(CFLAGS)

work.o	:	work.c connection.h log.h timer.h iprange.h conf.h
	gcc -c work.c $(CFLAGS)

ups.o	:	ups.c ups.h hash.h log.h list.h
	gcc -c ups.c $(CFLAGS)

hash.o	:	hash.c hash.h
	gcc -c hash.c $(CFLAGS)

dict.o	:	dict.c list.h hash.h dict.h
	gcc -c dict.c $(CFLAGS)

md5.o   :   md5.c md5.h
	gcc -c md5.c $(CFLAGS)

cookiefilter.o    :   cookiefilter.c cookiefilter.h genpool.h list.h md5.h hash.h log.h timer.h
	gcc -c cookiefilter.c $(CFLAGS)

timer.o    :   timer.c log.h
	gcc -c timer.c $(CFLAGS)

conf.o    :   conf.c list.h conf.h dict.h ups.h log.h
	gcc -c conf.c $(CFLAGS)

install	: 
	gcc -o httpgate $(OBJECT)

clean 	:
	-rm -f $(OBJECT)

.PHONY	: install clean all
