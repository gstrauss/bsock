# proxyexec

ifneq (,$(wildcard /bin/uname))
OSNAME:=$(shell /bin/uname -s)
else
OSNAME:=$(shell /usr/bin/uname -s)
endif

PREFIX?=/usr/local
BSOCK_LIBDIR?=../bsock
BSOCK_INCLUDE?=..

.PHONY: all
all: proxyexec

ifneq (,$(RPM_ARCH))
ifeq (x86_64,$(RPM_ARCH))
  ABI_BITS=64
  LIB_BITS=64
endif
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
ifeq ($(OSNAME),Darwin)
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

# (plasma_atomic requires 64-bit POWER CPU for 8-byte atomics in 32-bit build)
# (gcc -mcpu=power5 results in _ARCH_PWR5 being defined)
ifeq ($(OSNAME),AIX)
ifneq (64,$(ABI_BITS))
ABI_FLAGS?=-maix32 -mcpu=power5
endif
endif
# XXX: Linux (not AIX) on POWER needs gcc -m32 -mpowerpc64 for 8-byte atomics
# in 32-bit builds, or gcc 4.8.1 with libatomic (or gcc 4.7 with end-user
# downloading and compiling libatomic) and linking with -latomic

ifeq (32,$(ABI_BITS))
ifeq ($(OSNAME),Linux)
ABI_FLAGS?=-m32
endif
ifeq ($(OSNAME),Darwin)
ABI_FLAGS?=-m32
endif
ifeq ($(OSNAME),AIX)
AR+=-X32
ABI_FLAGS?=-maix32
endif
ifeq ($(OSNAME),HP-UX)
ABI_FLAGS?=-milp32
endif
ifeq ($(OSNAME),SunOS)
ABI_FLAGS?=-m32
endif
endif

# cygwin needs -std=gnu99 or -D_GNU_SOURCE for mkstemp() and strerror_r()
# cygwin gcc does not support -fpic or -pthread
ifneq (,$(filter CYGWIN%,$(OSNAME)))
FPIC=
STDC99=-std=gnu99
PTHREAD_FLAGS=-D_THREAD_SAFE
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

# C99 and POSIX.1-2001 (SUSv3 _XOPEN_SOURCE=600)
# C99 and POSIX.1-2008 (SUSv4 _XOPEN_SOURCE=700)
STDC99?=-std=c99
STDC11?=-std=c11
POSIX_STD?=-D_XOPEN_SOURCE=700
CFLAGS+=$(STDC11) $(POSIX_STD)

PTHREAD_FLAGS?=-pthread -D_THREAD_SAFE
PTHREAD_LDFLAGS?=$(PTHREAD_FLAGS)
LDFLAGS+=$(PTHREAD_LDFLAGS)
%.o: CFLAGS+=$(PTHREAD_FLAGS) -DNDEBUG -I $(BSOCK_INCLUDE)
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
ifeq ($(OSNAME),Darwin)
  ifneq (,$(strip $(filter-out /usr,$(PREFIX))))
    RPATH= -Wl,-rpath,$(PREFIX)/lib$(LIB_BITS)
  endif
  ifeq (,$(RPM_OPT_FLAGS))
    CFLAGS+=-D_FORTIFY_SOURCE=2 -fstack-protector
  endif
  PTHREAD_LDFLAGS=
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
proxyexec: LDFLAGS+=$(BSOCK_LIBDIR)/libbsock.so
proxyexec: proxyexec.o
	$(CC) -o $@ $(RPATH) $^ $(LDFLAGS)

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

proxyexec.o: $(BSOCK_INCLUDE)/bsock/bsock_daemon.h      \
             $(BSOCK_INCLUDE)/bsock/bsock_syslog.h      \
             $(BSOCK_INCLUDE)/bsock/bsock_unix.h        \
             $(BSOCK_INCLUDE)/plasma/plasma_attr.h      \
             $(BSOCK_INCLUDE)/plasma/plasma_feature.h   \
             $(BSOCK_INCLUDE)/plasma/plasma_stdtypes.h
