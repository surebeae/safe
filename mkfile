CC = cc
LD = ${CC}

PREFIX = /usr/local
MANPREFIX = ${PREFIX}/man

CPPFLAGS = -I/usr/local/include
CFLAGS = -g -Wall -Wextra -pedantic
LDFLAGS = -L/usr/local/lib
LDLIBS = -lsodium

safe: safe.o readpassphrase.o
	$LD -o $target $prereq $LDFLAGS $LDLIBS

%.o: %.c
	$CC $CPPFLAGS $CFLAGS -c $stem.c

clean:V:
	rm -f *.o safe

install:V: safe
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp safe ${DESTDIR}${PREFIX}/bin/safe
	chmod 755 ${DESTDIR}${PREFIX}/bin/safe
	mkdir -p ${DESTDIR}${MANPREFIX}/man1
	cp safe.1 ${DESTDIR}${MANPREFIX}/man1/safe.1
	chmod 644 ${DESTDIR}${MANPREFIX}/man1/safe.1

uninstall:V:
	rm ${DESTDIR}${PREFIX}/bin/safe
	rm ${DESTDIR}${MANPREFIX}/man1/safe.1
