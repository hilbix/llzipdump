#

PREFIX=/usr/local
PROG=$(basename $(wildcard *.c))

CFLAGS=-Wall -O3 -g

.PHONY:	love
love:	debug

.PHONY:	all
all:	$(PROG)

.PHONY:	install
install:	$(PROG)
	install $? '$(PREFIX)/bin/'

.PHONY:	debug
debug:	all
	/usr/bin/gdb -q -nx -nw -ex r --args '$(PROG)' -- *.zip

.PHONY:	clean
clean:
	rm -f $(PROG)

.PHONY:	test
test:	$(PROG)
	./llzipdump; [ 42 = $$? ]

