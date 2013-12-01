# bpoll

TARGETS:= bpoll.o

OSNAME:=$(shell /bin/uname -s)

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

CFLAGS+=-fvisibility=hidden

bpoll.o: CFLAGS+=-fpic

PTHREAD_FLAGS?=-pthread -D_THREAD_SAFE
%.o: CFLAGS+=-std=c99 -D_XOPEN_SOURCE=600 $(PTHREAD_FLAGS) -DNDEBUG -I. -I..
%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

ifeq ($(OSNAME),Linux)
  ifeq (,$(RPM_OPT_FLAGS))
    CFLAGS+=-D_FORTIFY_SOURCE=2 -fstack-protector
  endif
endif
ifeq ($(OSNAME),AIX)
endif
ifeq ($(OSNAME),HP-UX)
endif
ifeq ($(OSNAME),SunOS)
  CFLAGS+=-D_POSIX_PTHREAD_SEMANTICS
endif

.PHONY: clean clean-bpoll
clean: clean-bpoll
clean-bpoll:
	$(RM) $(TARGETS) *.o

bpoll.o: bpoll.h \
         ../plasma/plasma_attr.h \
         ../plasma/plasma_feature.h \
         ../plasma/plasma_stdtypes.h
