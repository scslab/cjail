CFLAGS = -g -O -Wall -Werror

all: cjail cjail-init

cjail: cjail.c
	$(CC) $(CFLAGS) -o $@ cjail.c -lmount

cjail-init: cjail-init.c
	$(CC) $(CFLAGS) -o $@ cjail-init.c -lmount

.PHONY: install
install:
	makepkg $$(test `id -u` == 0 && echo --asroot) --skipinteg -fi

.PHONY: clean
clean:
	rm -f *~ *.o cjail cjail-init cjail-*.pkg.tar.xz
	rm -rf pkg src
