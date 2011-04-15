.PHONY: all
all: bindsocket bindsocket.t

CC=gcc
CFLAGS+=-pipe -std=c99 -pedantic -O2 -D_XOPEN_SOURCE=600 -Wall -Winline -I.

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

bindsocket: bindsocket.m.o bindsocket_addrinfo.o bindsocket_unixdomain.o
	$(CC) $(CFLAGS) -o $@ $^

bindsocket.t: bindsocket.t.o bindsocket_addrinfo.o bindsocket_unixdomain.o
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	$(RM) bindsocket bindsocket.t *.o

bindsocket.m.o: bindsocket_addrinfo.h bindsocket_unixdomain.h
bindsocket.t.o: bindsocket_unixdomain.h
bindsocket_addrinfo.o: bindsocket_addrinfo.h
bindsocket_unixdomain.o: bindsocket_addrinfo.h bindsocket_unixdomain.h

