<config.mk

HARDENED_AGENT_SOCK = /run/safe/browser/agent.sock

all:V: safe safe-agent safe-fill-migrate safe-fill-host

safe: safe.o readpassphrase.o
	$LD -o $target $prereq $LDFLAGS $LDLIBS

safe-agent: safe-agent.o
	$LD -o $target $prereq $LDFLAGS $LDLIBS

safe-fill-migrate: safe-fill-migrate.o readpassphrase.o
	$LD -o $target $prereq $LDFLAGS -lsodium -lsqlite3 -lnss3 -lnssutil3 -lnspr4

safe-fill-host: safe-fill-host.o
	$LD -o $target $prereq $LDFLAGS -lsodium

%.o: %.c config.h validate.h proto.h
	$CC $CPPFLAGS $CFLAGS -c $stem.c

config.h: config.def.h
	cp $prereq $target

asan:V:
	mk clean
	mk 'CFLAGS=-Wall -Wextra -pedantic -O2 -fsanitize=address,undefined -fno-omit-frame-pointer -g -D_DEBUG' 'LDFLAGS=-L/usr/local/lib -fsanitize=address,undefined' all

fuzz-host: fuzz/fuzz_host.c safe-fill-host.c config.h validate.h proto.h
	$CC -fsanitize=fuzzer,address,undefined -DFUZZING -g -O1 -Wall -Wextra -pedantic -Wno-unused-function -o $target fuzz/fuzz_host.c safe-fill-host.c -lsodium

safe-fill-host-hardened.o: safe-fill-host.c config.h validate.h proto.h
	$CC $CPPFLAGS -DAGENT_SOCK_PATH='"'$HARDENED_AGENT_SOCK'"' $CFLAGS -c -o $target safe-fill-host.c

safe-fill-host-hardened: safe-fill-host-hardened.o
	$LD -o $target $prereq $LDFLAGS -lsodium

install-hardened:V: safe safe-agent safe-fill-migrate safe-fill-host-hardened
	if [ -z "${DESTDIR}" ]; then sh scripts/safe-hardened-setup users; fi
	mkdir -p ${DESTDIR}${PREFIX}/bin ${DESTDIR}${PREFIX}/sbin ${DESTDIR}${PREFIX}/libexec ${DESTDIR}${MANPREFIX}/man1 ${DESTDIR}${MANPREFIX}/man5
	install -m 0755 safe              ${DESTDIR}${PREFIX}/bin/safe
	install -m 0755 safe-agent        ${DESTDIR}${PREFIX}/bin/safe-agent
	install -m 0755 safe-fill-migrate ${DESTDIR}${PREFIX}/bin/safe-fill-migrate
	install -m 0755 scripts/safe-unlock     ${DESTDIR}${PREFIX}/bin/safe-unlock
	install -m 0755 scripts/safe-forget-all ${DESTDIR}${PREFIX}/bin/safe-forget-all
	install -m 0755 scripts/safe-fill-migrate-hardened ${DESTDIR}${PREFIX}/bin/safe-fill-migrate-hardened
	install -m 0755 scripts/safe-runtime-setup  ${DESTDIR}${PREFIX}/sbin/safe-runtime-setup
	install -m 0755 scripts/safe-hardened-setup ${DESTDIR}${PREFIX}/sbin/safe-hardened-setup
	install -m 0755 scripts/safe-wl-backend     ${DESTDIR}${PREFIX}/sbin/safe-wl-backend
	install -m 6750 -o _tatl -g safe-tatl safe-fill-host-hardened ${DESTDIR}${PREFIX}/libexec/safe-fill-host
	chmod 6750 ${DESTDIR}${PREFIX}/libexec/safe-fill-host
	if [ ! -u ${DESTDIR}${PREFIX}/libexec/safe-fill-host ] || [ ! -g ${DESTDIR}${PREFIX}/libexec/safe-fill-host ]; then echo "error: setuid/setgid missing on safe-fill-host" >&2; exit 1; fi
	install -m 0644 safe.1              ${DESTDIR}${MANPREFIX}/man1/safe.1
	install -m 0644 safe-agent.1        ${DESTDIR}${MANPREFIX}/man1/safe-agent.1
	install -m 0644 safe-fill-migrate.1 ${DESTDIR}${MANPREFIX}/man1/safe-fill-migrate.1
	install -m 0644 safe-fill-host.1    ${DESTDIR}${MANPREFIX}/man1/safe-fill-host.1
	install -m 0644 safe-store.5        ${DESTDIR}${MANPREFIX}/man5/safe-store.5

uninstall-hardened:V: uninstall
	rm -f ${DESTDIR}${PREFIX}/bin/safe-unlock ${DESTDIR}${PREFIX}/bin/safe-forget-all ${DESTDIR}${PREFIX}/bin/safe-fill-migrate-hardened
	rm -f ${DESTDIR}${PREFIX}/sbin/safe-runtime-setup ${DESTDIR}${PREFIX}/sbin/safe-hardened-setup ${DESTDIR}${PREFIX}/sbin/safe-wl-backend
	rm -f ${DESTDIR}${PREFIX}/libexec/safe-fill-host

clean:V:
	rm -f *.o safe safe-agent safe-fill-migrate safe-fill-host fuzz-host safe-fill-host-hardened safe-fill-host-hardened.o

install:V: safe safe-agent safe-fill-migrate safe-fill-host
	mkdir -p ${DESTDIR}${PREFIX}/bin
	mkdir -p ${DESTDIR}${MANPREFIX}/man1
	mkdir -p ${DESTDIR}${MANPREFIX}/man5
	cp safe ${DESTDIR}${PREFIX}/bin/safe
	cp safe-agent ${DESTDIR}${PREFIX}/bin/safe-agent
	cp safe-fill-migrate ${DESTDIR}${PREFIX}/bin/safe-fill-migrate
	cp safe-fill-host ${DESTDIR}${PREFIX}/bin/safe-fill-host
	cp safe.1 ${DESTDIR}${MANPREFIX}/man1/safe.1
	cp safe-agent.1 ${DESTDIR}${MANPREFIX}/man1/safe-agent.1
	cp safe-fill-migrate.1 ${DESTDIR}${MANPREFIX}/man1/safe-fill-migrate.1
	cp safe-fill-host.1 ${DESTDIR}${MANPREFIX}/man1/safe-fill-host.1
	cp safe-store.5 ${DESTDIR}${MANPREFIX}/man5/safe-store.5
	chmod 755 ${DESTDIR}${PREFIX}/bin/safe
	chmod 755 ${DESTDIR}${PREFIX}/bin/safe-agent
	chmod 755 ${DESTDIR}${PREFIX}/bin/safe-fill-migrate
	chmod 755 ${DESTDIR}${PREFIX}/bin/safe-fill-host

uninstall:V:
	rm -f ${DESTDIR}${PREFIX}/bin/safe
	rm -f ${DESTDIR}${PREFIX}/bin/safe-agent
	rm -f ${DESTDIR}${PREFIX}/bin/safe-fill-migrate
	rm -f ${DESTDIR}${PREFIX}/bin/safe-fill-host
	rm -f ${DESTDIR}${MANPREFIX}/man1/safe.1
	rm -f ${DESTDIR}${MANPREFIX}/man1/safe-agent.1
	rm -f ${DESTDIR}${MANPREFIX}/man1/safe-fill-migrate.1
	rm -f ${DESTDIR}${MANPREFIX}/man1/safe-fill-host.1
	rm -f ${DESTDIR}${MANPREFIX}/man5/safe-store.5
setup-ubuntu:V:
	sh scripts/safe-ubuntu-install
