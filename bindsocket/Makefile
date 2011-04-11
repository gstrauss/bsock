.PHONY: all
all: bindsocket

CC=gcc
CFLAGS+=-pipe -std=c99 -pedantic -O2 -Wall -Winline

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

bindsocket: bindsocket.o
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	$(RM) bindsocket *.o
