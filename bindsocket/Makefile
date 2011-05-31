TARGETS:= libbindsocket.so libbindsocket_preload.so bindsocket bindsocket.t

PREFIX?=/usr/local
BINDSOCKET_EXE?=$(PREFIX)/sbin/bindsocket
BINDSOCKET_CONFIG?=$(PREFIX)/etc/bindsocket
BINDSOCKET_SOCKET_DIR?=$(PREFIX)/var/run/bindsocket
BINDSOCKET_SOCKET_MODE?=0660
BINDSOCKET_GROUP?=daemon

.PHONY: all
all: $(TARGETS)

CC=gcc
CFLAGS+=-pipe -std=c99 -D_XOPEN_SOURCE=600 -pedantic -Wall -Winline -Werror -I.
CFLAGS+=-O2

RPATH= -Wl,-rpath=$(PREFIX)/lib

bindsocket.m.o:    CFLAGS+=-DBINDSOCKET_CONFIG='"$(BINDSOCKET_CONFIG)"'
bindsocket.m.o:    CFLAGS+=-DBINDSOCKET_GROUP='"$(BINDSOCKET_GROUP)"'
bindsocket.m.o:    CFLAGS+=-DBINDSOCKET_SOCKET_MODE='$(BINDSOCKET_SOCKET_MODE)'
bindsocket.m.o:    CFLAGS+=-DBINDSOCKET_SOCKET_DIR='"$(BINDSOCKET_SOCKET_DIR)"'
bindsocket.t.o:    CFLAGS+=-DBINDSOCKET_SOCKET_DIR='"$(BINDSOCKET_SOCKET_DIR)"'
bindsocket_bind.o: CFLAGS+=-DBINDSOCKET_SOCKET_DIR='"$(BINDSOCKET_SOCKET_DIR)"'
bindsocket_bind.o: CFLAGS+=-DBINDSOCKET_EXE='"$(BINDSOCKET_EXE)"'
bindsocket_resvaddr.o: CFLAGS+=-DBINDSOCKET_CONFIG='"$(BINDSOCKET_CONFIG)"'

bindsocket_sobjs=bindsocket_addrinfo.o bindsocket_bind.o bindsocket_unixdomain.o
$(bindsocket_sobjs):  CFLAGS+=-fPIC
bindsocket_preload.o: CFLAGS+=-fPIC

%.o: CFLAGS+=-pthread
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

libbindsocket.so: LDFLAGS+= -ldl
libbindsocket.so: $(bindsocket_sobjs)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^
libbindsocket_preload.so: LDFLAGS+= -L. -lbindsocket -ldl
libbindsocket_preload.so: bindsocket_preload.o | libbindsocket.so
	$(CC) $(CFLAGS) $(RPATH) $(LDFLAGS) -shared -o $@ $^

bindsocket: LDFLAGS+=-pthread
bindsocket: bindsocket.m.o bindsocket_bindresvport.o bindsocket_daemon.o \
            bindsocket_resvaddr.o bindsocket_syslog.o \
            libbindsocket.so
	$(CC) $(CFLAGS) $(RPATH) $(LDFLAGS) -o $@ $^

bindsocket.t: LDFLAGS+=-pthread
bindsocket.t: bindsocket.t.o libbindsocket.so
	$(CC) $(CFLAGS) $(RPATH) $(LDFLAGS) -o $@ $^

# (Note: not currently installing libbindsocket.so with any version suffix)
.PHONY: install install-suid install-headers
BINDSOCKET_MODE=0550
install-suid: BINDSOCKET_MODE=4550
install-suid: install ;
install:
	/bin/mkdir -p -m 0755 $(PREFIX)/lib $(PREFIX)/sbin \
          $(dir $(BINDSOCKET_CONFIG)) $(BINDSOCKET_SOCKET_DIR)
	/usr/bin/install -m $(BINDSOCKET_MODE) -g $(BINDSOCKET_GROUP) -p \
          bindsocket $(PREFIX)/sbin/
	/usr/bin/install -m 0555 -p libbindsocket.so $(PREFIX)/lib/
	/usr/bin/install -m 0555 -p libbindsocket_preload.so $(PREFIX)/lib/
	[ -f $(BINDSOCKET_CONFIG) ] || \
          (/bin/touch $(BINDSOCKET_CONFIG) && \
           /bin/chmod 0644 $(BINDSOCKET_CONFIG))
install-headers: bindsocket_addrinfo.h bindsocket_bind.h bindsocket_unixdomain.h
	/bin/mkdir -p -m 0755 $(PREFIX)/include/bindsocket
	/usr/bin/install -m 0555 -p $^ $(PREFIX)/include/bindsocket/

.PHONY: clean
clean:
	$(RM) $(TARGETS) *.o

bindsocket.m.o: bindsocket_addrinfo.h bindsocket_bindresvport.h \
                bindsocket_daemon.h bindsocket_resvaddr.h bindsocket_syslog.h \
                bindsocket_unixdomain.h
bindsocket.t.o: bindsocket_unixdomain.h
bindsocket_addrinfo.o: bindsocket_addrinfo.h bindsocket_unixdomain.h
bindsocket_bind.o: bindsocket_bind.h bindsocket_unixdomain.h
bindsocket_bindresvport.o: bindsocket_bindresvport.h
bindsocket_daemon.o: bindsocket_daemon.h bindsocket_syslog.h \
                     bindsocket_unixdomain.h
bindsocket_resvaddr.o: bindsocket_resvaddr.h bindsocket_syslog.h
bindsocket_unixdomain.o: bindsocket_unixdomain.h
bindsocket_syslog.o: bindsocket_syslog.h

OSNAME:=$(shell /bin/uname -s)
ifeq ($(OSNAME),SunOS)
  CFLAGS+=-D_POSIX_PTHREAD_SEMANTICS
endif
