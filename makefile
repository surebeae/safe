include config.mk
all: safe safe-agent

safe: safe.o readpassphrase.o
	$(LD) -o $@ safe.o readpassphrase.o $(LDFLAGS) $(LDLIBS)

safe-agent: safe-agent.o
	$(LD) -o $@ safe-agent.o $(LDFLAGS) $(LDLIBS)

clean:
	rm -f *.o safe safe-agent

install: safe safe-agent
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(MANPREFIX)/man1
	mkdir -p $(DESTDIR)$(MANPREFIX)/man5
	cp safe $(DESTDIR)$(PREFIX)/bin/safe
	cp safe-agent $(DESTDIR)$(PREFIX)/bin/safe-agent
	cp safe.1 $(DESTDIR)$(MANPREFIX)/man1/safe.1
	cp safe-agent.1 $(DESTDIR)$(MANPREFIX)/man1/safe-agent.1
	cp safe-store.5 $(DESTDIR)$(MANPREFIX)/man5/safe-store.5
	chmod 755 $(DESTDIR)$(PREFIX)/bin/safe
	chmod 755 $(DESTDIR)$(PREFIX)/bin/safe-agent

uninstall:
	rm $(DESTDIR)$(PREFIX)/bin/safe
	rm $(DESTDIR)$(PREFIX)/bin/safe-agent
	rm $(DESTDIR)$(MANPREFIX)/man1/safe.1
	rm $(DESTDIR)$(MANPREFIX)/man1/safe-agent.1
	rm $(DESTDIR)$(MANPREFIX)/man5/safe-store.5
