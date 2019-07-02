include config.mk
all: safe safe-agent

safe: safe.o readpassphrase.o
	$(LD) -o $@ safe.o readpassphrase.o $(LDFLAGS) $(LDLIBS)

safe-agent: safe-agent.o
	$(LD) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f *.o safe safe-agent

install: safe safe-agent
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


uninstall:
	rm ${DESTDIR}${PREFIX}/bin/safe
	rm ${DESTDIR}${PREFIX}/bin/safe-agent
	rm ${DESTDIR}${MANDIR}/man1/safe.1
	rm ${DESTDIR}${MANDIR}/man1/safe-agent.1
