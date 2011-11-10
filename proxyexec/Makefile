# proxyexec

OSNAME:=$(shell /bin/uname -s)

PREFIX?=/usr/local
BSOCK_LIBDIR?=../bsock
BSOCK_INCLUDE?=..

.PHONY: all
all: proxyexec

ifeq (x86_64,$(RPM_ARCH))
  ABI_BITS=64
  LIB_BITS=64
else
ifneq (,$(wildcard /lib64))
  ABI_BITS=64
  LIB_BITS=64
endif
endif

# 'gmake ABI_BITS=64' for 64-bit build (recommended on all 64-bit platforms)
ifeq (64,$(ABI_BITS))
ifeq ($(OSNAME),Linux)
ABI_FLAGS=-m64
endif
ifeq ($(OSNAME),AIX)
AR+=-X64
ABI_FLAGS=-maix64
endif
ifeq ($(OSNAME),HP-UX)
ABI_FLAGS=-mlp64
endif
ifeq ($(OSNAME),SunOS)
ABI_FLAGS=-m64
endif
endif

ifneq (,$(RPM_OPT_FLAGS))
  CFLAGS+=$(RPM_OPT_FLAGS)
  LDFLAGS+=$(RPM_OPT_FLAGS)
else
  CC=gcc -pipe
  CFLAGS+=-Werror -Wall -Wextra -Winline -pedantic-errors
  CFLAGS+=-O3 -g $(ABI_FLAGS)
  LDFLAGS+=$(ABI_FLAGS)
endif

PTHREAD_FLAGS?=-pthread -D_THREAD_SAFE
LDFLAGS+=$(PTHREAD_FLAGS)
%.o: CFLAGS+=-std=c99 -D_XOPEN_SOURCE=600 $(PTHREAD_FLAGS) -DNDEBUG
%.o: CFLAGS+=-I $(BSOCK_INCLUDE)
%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

ifeq ($(OSNAME),Linux)
  ifneq (,$(strip $(filter-out /usr,$(PREFIX))))
    RPATH= -Wl,-rpath,$(PREFIX)/lib$(LIB_BITS)
  endif
  ifeq (,$(RPM_OPT_FLAGS))
    CFLAGS+=-D_FORTIFY_SOURCE=2 -fstack-protector
  endif
  LDFLAGS+=-Wl,-O,1 -Wl,--hash-style,gnu -Wl,-z,relro,-z,now -Wl,-z,noexecstack
endif
ifeq ($(OSNAME),AIX)
  ifneq (,$(strip $(filter-out /usr,$(PREFIX))))
    RPATH= -Wl,-b,libpath:$(PREFIX)/lib$(LIB_BITS)
  endif
endif
ifeq ($(OSNAME),HP-UX)
  ifneq (,$(strip $(filter-out /usr,$(PREFIX))))
    RPATH= -Wl,+b,$(PREFIX)/lib$(LIB_BITS)
  endif
endif
ifeq ($(OSNAME),SunOS)
  ifneq (,$(strip $(filter-out /usr,$(PREFIX))))
    RPATH= -Wl,-R,$(PREFIX)/lib$(LIB_BITS)
  endif
  CFLAGS+=-D_POSIX_PTHREAD_SEMANTICS
  LDFLAGS+=-lsocket
endif

# proxyexec
# (reused from libbsock.so: bsock_daemon.o bsock_syslog.o bsock_unix.o
# Override default socket dir by defining replacement.  Must end in '/'
#   -DPROXYEXEC_SOCKET_DIR='"/usr/local/var/run/proxyexec/"'
ifneq (,$(PROXYEXEC_SOCKET_DIR))
proxyexec: CFLAGS+=-DPROXYEXEC_SOCKET_DIR='"$(PROXYEXEC_SOCKET_DIR)"'
endif
proxyexec: LDFLAGS+=-L $(BSOCK_LIBDIR) -lbsock
proxyexec: proxyexec.o
	$(CC) -o $@ $(RPATH) $(LDFLAGS) $^

.PHONY: install install-headers install-doc
install: proxyexec
	/bin/mkdir -p -m 0755 $(PREFIX)/sbin $(PREFIX)/var/run/proxyexec
	/usr/bin/install -m 0555 -p proxyexec $(PREFIX)/sbin/
install-headers: ;
install-doc: ;

.PHONY: clean clean-proxyexec
clean: clean-proxyexec
clean-proxyexec:
	$(RM) proxyexec proxyexec.o

proxyexec.o: $(BSOCK_INCLUDE)/bsock/bsock_daemon.h \
             $(BSOCK_INCLUDE)/bsock/bsock_syslog.h \
             $(BSOCK_INCLUDE)/bsock/bsock_unix.h
