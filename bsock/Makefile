# bsock

TARGETS:= libbsock.so libbsock_preload.so bsock bsock.t

ifneq (,$(wildcard /bin/uname))
OSNAME:=$(shell /bin/uname -s)
else
OSNAME:=$(shell /usr/bin/uname -s)
endif

PREFIX?=/usr/local
BSOCK_DOC_DIR?=$(PREFIX)/share/doc/bsock
BSOCK_EXE?=$(PREFIX)/sbin/bsock
BSOCK_CONFIG?=$(PREFIX)/etc/bsock
BSOCK_SOCKET_DIR?=$(PREFIX)/var/run/bsock
BSOCK_SOCKET_MODE?=0660
BSOCK_GROUP?=daemon

usr_bin_id:=$(wildcard /usr/xpg4/bin/id)
ifeq (,$(usr_bin_id))
usr_bin_id:=/usr/bin/id
endif
ifneq (0,$(shell $(usr_bin_id) -u))
BSOCK_GROUP:=$(shell $(usr_bin_id) -gn)
endif

.PHONY: all
all: $(TARGETS)

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

ifneq (,$(filter Linux Darwin,$(OSNAME)))
CFLAGS+=-fvisibility=hidden
endif

bsock.m.o:        CFLAGS+=-DBSOCK_GROUP='"$(BSOCK_GROUP)"'
bsock.m.o:        CFLAGS+=-DBSOCK_SOCKET_MODE='$(BSOCK_SOCKET_MODE)'
bsock.m.o:        CFLAGS+=-DBSOCK_SOCKET_DIR='"$(BSOCK_SOCKET_DIR)"'
bsock.t.o:        CFLAGS+=-DBSOCK_SOCKET_DIR='"$(BSOCK_SOCKET_DIR)"'
bsock_authz.o:    CFLAGS+=-DBSOCK_CONFIG='"$(BSOCK_CONFIG)"'
bsock_bind.o:     CFLAGS+=-DBSOCK_SOCKET_DIR='"$(BSOCK_SOCKET_DIR)"'
bsock_bind.o:     CFLAGS+=-DBSOCK_EXE='"$(BSOCK_EXE)"'
bsock_resvaddr.o: CFLAGS+=-DBSOCK_CONFIG='"$(BSOCK_CONFIG)"'

bsock_sobjs=  bsock_unix.o \
              bsock_addrinfo.o \
              bsock_bind.o \
              bsock_daemon.o \
              bsock_syslog.o
$(bsock_sobjs):  CFLAGS+=-fpic
bsock_preload.o: CFLAGS+=-fpic

# C99 and POSIX.1-2001 (SUSv3 _XOPEN_SOURCE=600)
# C99 and POSIX.1-2008 (SUSv4 _XOPEN_SOURCE=700)
STDC99?=-std=c99
STDC11?=-std=c11
POSIX_STD?=-D_XOPEN_SOURCE=700
CFLAGS+=$(STDC11) $(POSIX_STD)

PTHREAD_FLAGS?=-pthread -D_THREAD_SAFE
%.o: CFLAGS+=$(PTHREAD_FLAGS) -DNDEBUG -I. -I..
%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

PTHREAD_LDFLAGS?=$(PTHREAD_FLAGS)
LIBRT?=-lrt

ifeq ($(OSNAME),Linux)
  ifneq (,$(strip $(filter-out /usr,$(PREFIX))))
    RPATH= -Wl,-rpath,$(PREFIX)/lib$(LIB_BITS)
  endif
  ifeq (,$(RPM_OPT_FLAGS))
    CFLAGS+=-D_FORTIFY_SOURCE=2 -fstack-protector
  endif
  LDFLAGS+=-Wl,-O,1 -Wl,--hash-style,gnu -Wl,-z,relro,-z,now
  libbsock_preload.so: LDFLAGS+= -Wl,-z,interpose
  bsock bsock.t: LDFLAGS+=-Wl,-z,noexecstack
endif
ifeq ($(OSNAME),Darwin)
  ifneq (,$(strip $(filter-out /usr,$(PREFIX))))
    RPATH= -Wl,-rpath,$(PREFIX)/lib$(LIB_BITS)
  endif
  ifeq (,$(RPM_OPT_FLAGS))
    CFLAGS+=-D_FORTIFY_SOURCE=2 -fstack-protector
  endif
  PTHREAD_LDFLAGS=
  LIBRT=
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
  LDFLAGS+=-lsocket -lrt
endif

../plasma/libplasma.a: ../plasma/plasma_attr.h     \
                       ../plasma/plasma_feature.h  \
                       ../plasma/plasma_stdtypes.h \
                       ../plasma/plasma_atomic.c   \
                       ../plasma/plasma_atomic.h   \
                       ../plasma/plasma_membar.h
	$(MAKE) -C ../plasma --no-print-directory
../bpoll/bpoll.o: ../bpoll/bpoll.h
	$(MAKE) -C ../bpoll --no-print-directory
# (bpoll.o and objects in libplasma.a are built with -fpic)
bpoll_sobjs= ../bpoll/bpoll.o ../plasma/libplasma.a

ifeq ($(OSNAME),Linux)
libbsock.so: LDFLAGS+=-Wl,-soname,$(@F)
endif
libbsock.so: LDFLAGS+=$(PTHREAD_LDFLAGS)
libbsock.so: $(bsock_sobjs) $(bpoll_sobjs)
	$(CC) -o $@ $(LDFLAGS) -shared -fpic $^
ifeq ($(OSNAME),Linux)
libbsock_preload.so: LDFLAGS+=-Wl,-soname,$(@F)
endif
libbsock_preload.so: LDFLAGS+= libbsock.so -ldl
libbsock_preload.so: bsock_preload.o | libbsock.so
	$(CC) -o $@ $(RPATH) $(LDFLAGS) -shared -fpic $^

bsock: LDFLAGS+=$(PTHREAD_LDFLAGS) $(LIBRT)
bsock: bsock.m.o bsock_authz.o bsock_bindresvport.o bsock_resvaddr.o libbsock.so
	$(CC) -o $@ $(RPATH) $(LDFLAGS) $^

bsock.t: LDFLAGS+=$(PTHREAD_LDFLAGS)
bsock.t: bsock.t.o libbsock.so
	$(CC) -o $@ $(RPATH) $(LDFLAGS) $^

# (Note: not currently installing libbsock.so with any version suffix)
.PHONY: install install-suid install-headers install-headers-plasma install-doc
BSOCK_MODE=0550
install-suid: BSOCK_MODE=4550
install-suid: install ;
install: bsock libbsock.so libbsock_preload.so
	/bin/mkdir -p -m 0755 $(PREFIX)/lib$(LIB_BITS) $(PREFIX)/sbin \
          $(dir $(BSOCK_CONFIG)) $(BSOCK_SOCKET_DIR)
	/usr/bin/install -m $(BSOCK_MODE) -g $(BSOCK_GROUP) -p \
          bsock $(PREFIX)/sbin/
	/usr/bin/install -m 0555 -p libbsock.so $(PREFIX)/lib$(LIB_BITS)
	/usr/bin/install -m 0555 -p libbsock_preload.so $(PREFIX)/lib$(LIB_BITS)
	[ -f $(BSOCK_CONFIG) ] || \
          (/bin/touch $(BSOCK_CONFIG) && \
           /bin/chmod 0644 $(BSOCK_CONFIG))
install-headers: bsock_addrinfo.h bsock_bind.h bsock_unix.h bsock_daemon.h \
                 bsock_syslog.h ../bpoll/bpoll.h | install-headers-plasma
	/bin/mkdir -p -m 0755 $(PREFIX)/include/bsock
	/usr/bin/install -m 0444 -p $^ $(PREFIX)/include/bsock/
install-headers-plasma: ../plasma/plasma_attr.h \
                        ../plasma/plasma_feature.h \
                        ../plasma/plasma_stdtypes.h
	/bin/mkdir -p -m 0755 $(PREFIX)/include/bsock/plasma
	/usr/bin/install -m 0444 -p $^ $(PREFIX)/include/bsock/plasma/
install-doc: CHANGELOG COPYING FAQ INSTALL NOTES README
	/bin/mkdir -p -m 0755 $(BSOCK_DOC_DIR)
	/usr/bin/install -m 0444 -p $^ $(BSOCK_DOC_DIR)

.PHONY: clean clean-bsock
clean: clean-bsock
clean-bsock:
	$(RM) $(TARGETS) *.o
	$(MAKE) -C ../bpoll --no-print-directory clean
	$(MAKE) -C ../plasma --no-print-directory clean

bsock.m.o: bsock_addrinfo.h bsock_authz.h bsock_bindresvport.h bsock_daemon.h \
           bsock_resvaddr.h bsock_syslog.h bsock_unix.h ../bpoll/bpoll.h
bsock.t.o: bsock_addrinfo.h bsock_bind.h bsock_unix.h
bsock_addrinfo.o: bsock_addrinfo.h bsock_unix.h
bsock_authz.o: bsock_addrinfo.h bsock_authz.h bsock_syslog.h
bsock_bind.o: bsock_addrinfo.h bsock_bind.h bsock_unix.h
bsock_bindresvport.o: bsock_bindresvport.h
bsock_daemon.o: bsock_daemon.h bsock_syslog.h bsock_unix.h
bsock_resvaddr.o: bsock_addrinfo.h bsock_resvaddr.h bsock_syslog.h
bsock_unix.o: bsock_unix.h
bsock_syslog.o: bsock_syslog.h
%.o: ../plasma/plasma_attr.h \
     ../plasma/plasma_feature.h \
     ../plasma/plasma_stdtypes.h
