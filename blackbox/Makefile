ALL = \
	blackbox\
	vul-parser

.PHONY: all
all: $(ALL)

blackbox: blackbox.c blackbox-tests.inc blackbox-tests-patched.inc
	$(CC) -Wall -Wextra -g -o "$@" $<

vul-parser: vul-parser.c
	$(CC) -Wall -Wextra -g -o "$@" $^ -lpcap 

.PHONY: clean
clean:
	rm -f $(ALL)

.DELETE_ON_ERROR:
