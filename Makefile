.PHONY: bsock proxyexec
all: bsock proxyexec
bsock:
	$(MAKE) -C $@ --no-print-directory
proxyexec: bsock
	$(MAKE) -C $@ --no-print-directory

.PHONY: install install-headers install-doc
install install-headers install-doc:
	$(MAKE) -C bsock --no-print-directory $@
	$(MAKE) -C proxyexec --no-print-directory $@

.PHONY: clean clean-all
clean: clean-all
clean-all:
	$(MAKE) -C proxyexec --no-print-directory clean
	$(MAKE) -C bsock --no-print-directory clean
	$(MAKE) -C bpoll --no-print-directory clean
	$(MAKE) -C plasma --no-print-directory clean
