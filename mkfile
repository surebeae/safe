CC = cc
LD = ${CC}

PREFIX = /usr/local
MANPREFIX = ${PREFIX}/man

CPPFLAGS = -D_XOPEN_SOURCE
CFLAGS = -g -Wall -Wextra -pedantic
LDFLAGS =
LDLIBS = -lsodium

all:V: safe safe-agent

safe-agent: safe-agent.o readpassphrase.o
	$LD -o $target $prereq $LDFLAGS $LDLIBS

safe: safe.o
	$LD -o $target $prereq $LDFLAGS $LDLIBS

%.o: %.c
	$CC $CPPFLAGS $CFLAGS -c $stem.c

clean:V:
	rm -f *.o safe safe-agent

install:V: ${BIN}
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp ${BIN} ${DESTDIR}${PREFIX}/bin/${BIN}
	chmod 755 ${DESTDIR}${PREFIX}/bin/${BIN}
	mkdir -p ${DESTDIR}${MANPREFIX}/man1
	cp ${BIN}.1 ${DESTDIR}${MANPREFIX}/man1/${BIN}.1
	chmod 644 ${DESTDIR}${MANPREFIX}/man1/${BIN}.1

uninstall:V:
	rm ${DESTDIR}${PREFIX}/bin/${BIN}
	rm ${DESTDIR}${MANPREFIX}/man1/${BIN}.1
