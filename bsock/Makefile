# bsock

TARGETS:= libbsock.so libbsock_preload.so bsock bsock.t

PREFIX?=/usr/local
BSOCK_EXE?=$(PREFIX)/sbin/bsock
BSOCK_CONFIG?=$(PREFIX)/etc/bsock
BSOCK_SOCKET_DIR?=$(PREFIX)/var/run/bsock
BSOCK_SOCKET_MODE?=0660
BSOCK_GROUP?=daemon

.PHONY: all
all: $(TARGETS)

CC=gcc
CFLAGS+=-pipe -std=c99 -D_XOPEN_SOURCE=600 -pedantic-errors
CFLAGS+=-Werror -Wall -Wextra -Winline -Wstrict-overflow=5
CFLAGS+=-O3 -DNEBUG -fhosted
CFLAGS+=-I.

RPATH= -Wl,-rpath=$(PREFIX)/lib

bsock.m.o:        CFLAGS+=-DBSOCK_CONFIG='"$(BSOCK_CONFIG)"'
bsock.m.o:        CFLAGS+=-DBSOCK_GROUP='"$(BSOCK_GROUP)"'
bsock.m.o:        CFLAGS+=-DBSOCK_SOCKET_MODE='$(BSOCK_SOCKET_MODE)'
bsock.m.o:        CFLAGS+=-DBSOCK_SOCKET_DIR='"$(BSOCK_SOCKET_DIR)"'
bsock.t.o:        CFLAGS+=-DBSOCK_SOCKET_DIR='"$(BSOCK_SOCKET_DIR)"'
bsock_bind.o:     CFLAGS+=-DBSOCK_SOCKET_DIR='"$(BSOCK_SOCKET_DIR)"'
bsock_bind.o:     CFLAGS+=-DBSOCK_EXE='"$(BSOCK_EXE)"'
bsock_resvaddr.o: CFLAGS+=-DBSOCK_CONFIG='"$(BSOCK_CONFIG)"'

bsock_sobjs=  bsock_unix.o \
              bsock_addrinfo.o \
              bsock_bind.o \
              bsock_daemon.o \
              bsock_syslog.o
$(bsock_sobjs):  CFLAGS+=-fPIC
bsock_preload.o: CFLAGS+=-fPIC

%.o: CFLAGS+=-pthread
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

libbsock.so: LDFLAGS+= -ldl
libbsock.so: $(bsock_sobjs)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^
libbsock_preload.so: LDFLAGS+= -L. -lbsock -ldl
libbsock_preload.so: bsock_preload.o | libbsock.so
	$(CC) $(CFLAGS) $(RPATH) $(LDFLAGS) -shared -o $@ $^

bsock: LDFLAGS+=-pthread
bsock: bsock.m.o bsock_bindresvport.o bsock_resvaddr.o \
            libbsock.so
	$(CC) $(CFLAGS) $(RPATH) $(LDFLAGS) -o $@ $^

bsock.t: LDFLAGS+=-pthread
bsock.t: bsock.t.o libbsock.so
	$(CC) $(CFLAGS) $(RPATH) $(LDFLAGS) -o $@ $^

# (Note: not currently installing libbsock.so with any version suffix)
.PHONY: install install-suid install-headers
BSOCK_MODE=0550
install-suid: BSOCK_MODE=4550
install-suid: install ;
install:
	/bin/mkdir -p -m 0755 $(PREFIX)/lib $(PREFIX)/sbin \
          $(dir $(BSOCK_CONFIG)) $(BSOCK_SOCKET_DIR)
	/usr/bin/install -m $(BSOCK_MODE) -g $(BSOCK_GROUP) -p \
          bsock $(PREFIX)/sbin/
	/usr/bin/install -m 0555 -p libbsock.so $(PREFIX)/lib/
	/usr/bin/install -m 0555 -p libbsock_preload.so $(PREFIX)/lib/
	[ -f $(BSOCK_CONFIG) ] || \
          (/bin/touch $(BSOCK_CONFIG) && \
           /bin/chmod 0644 $(BSOCK_CONFIG))
install-headers: bsock_addrinfo.h bsock_bind.h bsock_unix.h \
                 bsock_daemon.h bsock_syslog.h
	/bin/mkdir -p -m 0755 $(PREFIX)/include/bsock
	/usr/bin/install -m 0444 -p $^ $(PREFIX)/include/bsock/

.PHONY: clean clean-bsock
clean: clean-bsock
clean-bsock:
	$(RM) $(TARGETS) *.o

bsock.m.o: bsock_addrinfo.h bsock_bindresvport.h bsock_daemon.h \
           bsock_resvaddr.h bsock_syslog.h bsock_unix.h
bsock.t.o: bsock_unix.h
bsock_addrinfo.o: bsock_addrinfo.h bsock_unix.h
bsock_bind.o: bsock_bind.h bsock_unix.h
bsock_bindresvport.o: bsock_bindresvport.h
bsock_daemon.o: bsock_daemon.h bsock_syslog.h bsock_unix.h
bsock_resvaddr.o: bsock_resvaddr.h bsock_syslog.h
bsock_unix.o: bsock_unix.h
bsock_syslog.o: bsock_syslog.h

OSNAME:=$(shell /bin/uname -s)
ifeq ($(OSNAME),SunOS)
  CFLAGS+=-D_POSIX_PTHREAD_SEMANTICS
endif
