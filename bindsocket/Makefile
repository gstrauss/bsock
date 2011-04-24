TARGETS:= bindsocket bindsocket.t

PREFIX?=/usr/local
BINDSOCKET_CONFIG?=$(PREFIX)/etc/bindsocket
BINDSOCKET_SOCKET_DIR?=$(PREFIX)/var/run/bindsocket

.PHONY: all
all: $(TARGETS)

CC=gcc
CFLAGS+=-pipe -std=c99 -pedantic -O2 -D_XOPEN_SOURCE=600 -Wall -Winline -I.

# (daemon benefits from resolving symbols at load time; one-shot is extra cost)
LDFLAGS+= -Wl,-z,now

bindsocket.m.o: CFLAGS+=-DBINDSOCKET_CONFIG='"$(BINDSOCKET_CONFIG)"'
bindsocket.m.o: CFLAGS+=-DBINDSOCKET_SOCKET_DIR='"$(BINDSOCKET_SOCKET_DIR)"'
bindsocket.t.o: CFLAGS+=-DBINDSOCKET_SOCKET_DIR='"$(BINDSOCKET_SOCKET_DIR)"'

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

bindsocket: bindsocket.m.o bindsocket_addrinfo.o bindsocket_unixdomain.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

bindsocket.t: bindsocket.t.o bindsocket_addrinfo.o bindsocket_unixdomain.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

.PHONY: install install-suid
BINDSOCKET_MODE=0555
install-suid: BINDSOCKET_MODE=4555
install-suid: install ;
install:
	/bin/mkdir -p -m 0755 \
          $(dir $(BINDSOCKET_CONFIG)) $(PREFIX)/sbin $(BINDSOCKET_SOCKET_DIR)
	/usr/bin/install -m $(BINDSOCKET_MODE) -p bindsocket $(PREFIX)/sbin/
	[ -f $(BINDSOCKET_CONFIG) ] || \
          (/bin/touch $(BINDSOCKET_CONFIG) && \
           /bin/chmod 0644 $(BINDSOCKET_CONFIG))

.PHONY: clean
clean:
	$(RM) $(TARGETS) *.o

bindsocket.m.o: bindsocket_addrinfo.h bindsocket_unixdomain.h
bindsocket.t.o: bindsocket_unixdomain.h
bindsocket_addrinfo.o: bindsocket_addrinfo.h
bindsocket_unixdomain.o: bindsocket_addrinfo.h bindsocket_unixdomain.h
