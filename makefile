CC = cc
LD = $(CC)

PREFIX = /usr/local
MANPREFIX = ${PREFIX}/man

CPPFLAGS = -I/usr/local/include
CFLAGS = -Wall -Wextra -pedantic
LDFLAGS = -L/usr/local/lib
LDLIBS = -lsodium

all: safe safe-agent

safe: safe.o readpassphrase.o
safe-agent: safe-agent.o

clean:
	rm -f *.o safe safe-agent

install: safe safe-agent
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp safe ${DESTDIR}${PREFIX}/bin/safe
	cp safe-agent ${DESTDIR}${PREFIX}/bin/safe-agent
	chmod 755 ${DESTDIR}${PREFIX}/bin/safe
	chmod 755 ${DESTDIR}${PREFIX}/bin/safe-agent
	mkdir -p ${DESTDIR}${MANPREFIX}/man1
	cp safe.1 ${DESTDIR}${MANPREFIX}/man1/safe.1
	chmod 644 ${DESTDIR}${MANPREFIX}/man1/safe.1
	cp safe-agent.1 ${DESTDIR}${MANPREFIX}/man1/safe-agent.1
	chmod 644 ${DESTDIR}${MANPREFIX}/man1/safe-agent.1


uninstall::
	rm ${DESTDIR}${PREFIX}/bin/safe
	rm ${DESTDIR}${PREFIX}/bin/safe-agent
	rm ${DESTDIR}${MANPREFIX}/man1/safe.1
	rm ${DESTDIR}${MANPREFIX}/man1/safe-agent.1
