TARGETS:= libbindsocket.so bindsocket bindsocket.t

PREFIX?=/usr/local
BINDSOCKET_EXE?=$(PREFIX)/sbin/bindsocket
BINDSOCKET_CONFIG?=$(PREFIX)/etc/bindsocket
BINDSOCKET_SOCKET_DIR?=$(PREFIX)/var/run/bindsocket

.PHONY: all
all: $(TARGETS)

CC=gcc
CFLAGS+=-pipe -std=c99 -pedantic -O2 -D_XOPEN_SOURCE=600 -Wall -Winline -I.

# (daemon benefits from resolving symbols at load time; one-shot is extra cost)
LDFLAGS+= -Wl,-z,now

RPATH= -Wl,-rpath=$(PREFIX)/lib

bindsocket.m.o:    CFLAGS+=-DBINDSOCKET_CONFIG='"$(BINDSOCKET_CONFIG)"'
bindsocket.m.o:    CFLAGS+=-DBINDSOCKET_SOCKET_DIR='"$(BINDSOCKET_SOCKET_DIR)"'
bindsocket.t.o:    CFLAGS+=-DBINDSOCKET_SOCKET_DIR='"$(BINDSOCKET_SOCKET_DIR)"'
bindsocket_bind.o: CFLAGS+=-DBINDSOCKET_SOCKET_DIR='"$(BINDSOCKET_SOCKET_DIR)"'
bindsocket_bind.o: CFLAGS+=-DBINDSOCKET_EXE='"$(BINDSOCKET_EXE)"'

bindsocket_sobjs=bindsocket_addrinfo.o bindsocket_bind.o bindsocket_unixdomain.o
$(bindsocket_sobjs):CFLAGS+=-fPIC

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

libbindsocket.so: LDFLAGS+= -ldl
libbindsocket.so: $(bindsocket_sobjs)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^

bindsocket: bindsocket.m.o libbindsocket.so
	$(CC) $(CFLAGS) $(LDFLAGS) $(RPATH) -o $@ $^

bindsocket.t: bindsocket.t.o libbindsocket.so
	$(CC) $(CFLAGS) $(LDFLAGS) $(RPATH) -o $@ $^

# (Note: not currently installing libbindsocket.so with any version suffix)
.PHONY: install install-suid
BINDSOCKET_MODE=0555
install-suid: BINDSOCKET_MODE=4555
install-suid: install ;
install:
	/bin/mkdir -p -m 0755 $(PREFIX)/lib $(PREFIX)/sbin \
          $(dir $(BINDSOCKET_CONFIG)) $(BINDSOCKET_SOCKET_DIR)
	/usr/bin/install -m $(BINDSOCKET_MODE) -p bindsocket $(PREFIX)/sbin/
	/usr/bin/install -m 0555 -p libbindsocket.so $(PREFIX)/lib/
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
