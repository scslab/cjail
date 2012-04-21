CFLAGS = -g -O -Wall -Werror

all: cjail cjail-init

cjail: cjail.c
	$(CC) $(CFLAGS) -o $@ cjail.c -lmount

cjail-init: cjail-init.c
	$(CC) $(CFLAGS) -o $@ cjail-init.c -lmount

.PHONY: clean
clean:
	rm -f *~ *.o cjail cjail-init
