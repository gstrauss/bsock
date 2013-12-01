# bpoll microbenchmarking (bench*.c)
#
# Please see README and http://libev.schmorp.de/bench.html

TARGETS:= benchev-orig benchev-mod benchbpoll-v1 benchbpoll-v2

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
  CFLAGS+=-Wall -Wextra -Winline -pedantic
  CFLAGS+=-O3 -g $(ABI_FLAGS)
  LDFLAGS+=$(ABI_FLAGS)
endif

PTHREAD_FLAGS?=-pthread -D_THREAD_SAFE
%.o: CFLAGS+=-std=c99 -D_XOPEN_SOURCE=600 $(PTHREAD_FLAGS) -DNDEBUG
%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

../../bpoll.o: ../../bpoll.h \
               ../../../plasma/plasma_attr.h \
               ../../../plasma/plasma_feature.h \
               ../../../plasma/plasma_stdtypes.h
	$(MAKE) -C ../.. --no-print-directory

# benchev-*: add -D_BSD_SOURCE for u_char (not portable; avoid)
benchev-%: CFLAGS+= -D_BSD_SOURCE -I /usr/include/libev
benchev-mod: CFLAGS+= -DNATIVE

benchbpoll-%: CFLAGS+= -Werror -pedantic-errors -I../../..

benchev-orig: benchev-orig.o
	$(CC) -o $@ $(CFLAGS_DEV) $(CFLAGS) $< -lev
benchev-mod: benchev-mod.o
	$(CC) -o $@ $(CFLAGS_DEV) $(CFLAGS) $< -lev

benchbpoll-v1: benchbpoll-v1.o ../../bpoll.o
	$(CC) -o $@ $(CFLAGS_DEV) $(CFLAGS) $^
benchbpoll-v2: benchbpoll-v2.o ../../bpoll.o
	$(CC) -o $@ $(CFLAGS_DEV) $(CFLAGS) $^

.PHONY: clean clean-bench
clean: clean-bench
clean-bench:
	$(RM) $(TARGETS) *.o
