.PHONY: bsock proxyexec
all: bsock proxyexec
bsock:
	$(MAKE) -C $@ --no-print-directory
proxyexec: bsock
	$(MAKE) -C $@ --no-print-directory

.PHONY: install
install:
	$(MAKE) -C bsock --no-print-directory install
	$(MAKE) -C proxyexec --no-print-directory install

.PHONY: clean clean-all
clean: clean-all
clean-all:
	$(MAKE) -C proxyexec --no-print-directory clean
	$(MAKE) -C bsock --no-print-directory clean
