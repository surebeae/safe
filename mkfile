<config.mk

all:V: safe safe-agent

safe: safe.o readpassphrase.o
	$LD -o $target $prereq $LDFLAGS $LDLIBS

safe-agent: safe-agent.o
	$LD -o $target $prereq $LDFLAGS $LDLIBS

%.o: %.c
	$CC $CPPFLAGS $CFLAGS -c $stem.c

clean:V:
	rm -f *.o safe safe-agent

install:V: safe safe-agent
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp safe ${DESTDIR}${PREFIX}/bin/safe
	cp safe-agent ${DESTDIR}${PREFIX}/bin/safe-agent
	chmod 755 ${DESTDIR}${PREFIX}/bin/safe
	chmod 755 ${DESTDIR}${PREFIX}/bin/safe-agent
	mkdir -p ${DESTDIR}${MANDIR}/man1
	cp safe.1 ${DESTDIR}${MANDIR}/man1/safe.1
	chmod 644 ${DESTDIR}${MANDIR}/man1/safe.1
	cp safe-agent.1 ${DESTDIR}${MANDIR}/man1/safe-agent.1
	chmod 644 ${DESTDIR}${MANDIR}/man1/safe-agent.1

uninstall:V:
	rm ${DESTDIR}${PREFIX}/bin/safe
	rm ${DESTDIR}${PREFIX}/bin/safe-agent
	rm ${DESTDIR}${MANDIR}/man1/safe.1
	rm ${DESTDIR}${MANDIR}/man1/safe-agent.1
