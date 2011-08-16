# proxyexec

PREFIX?=/usr/local

.PHONY: all
all: proxyexec

CC=gcc
CFLAGS+=-pipe -std=c99 -D_XOPEN_SOURCE=600 -pedantic-errors
CFLAGS+=-Werror -Wall -Wextra -Winline -Wstrict-overflow=5
CFLAGS+=-O3 -DNEBUG -fhosted
CFLAGS+=-I $(PREFIX)/include

RPATH= -Wl,-rpath=$(PREFIX)/lib

%.o: CFLAGS+=-pthread
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# proxyexec
# (reused from libbsock.so: bsock_daemon.o bsock_syslog.o bsock_unix.o
# Override default socket dir by defining replacement.  Must end in '/'
#   -DPROXYEXEC_SOCKET_DIR='"/usr/local/var/run/proxyexec/"'
proxyexec: LDFLAGS+= -L $(PREFIX)/lib -lbsock
proxyexec: proxyexec.o
	$(CC) $(CFLAGS) $(RPATH) $(LDFLAGS) -o $@ $^

.PHONY: install
install:
	/bin/mkdir -p -m 0755 $(PREFIX)/sbin
	/usr/bin/install -m 0555 -p proxyexec $(PREFIX)/sbin/

.PHONY: clean clean-proxyexec
clean: clean-proxyexec
clean-proxyexec:
	$(RM) proxyexec proxyexec.o

proxyexec.o: $(PREFIX)/include/bsock/bsock_daemon.h \
             $(PREFIX)/include/bsock/bsock_syslog.h \
             $(PREFIX)/include/bsock/bsock_unix.h

OSNAME:=$(shell /bin/uname -s)
ifeq ($(OSNAME),SunOS)
  CFLAGS+=-D_POSIX_PTHREAD_SEMANTICS
endif
