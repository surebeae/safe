CC = cc
LD = ${CC}

PREFIX = /usr/local
MANPREFIX = ${PREFIX}/man

CPPFLAGS = -I/usr/local/include
CFLAGS = -Wall -Wextra -pedantic
LDFLAGS = -L/usr/local/lib
LDLIBS = -lsodium
