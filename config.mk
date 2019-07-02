CC = cc
LD = ${CC}

PREFIX = /usr/local
MANDIR = ${PREFIX}/man

CPPFLAGS = -I/usr/local/include
CFLAGS = -g -Wall -Wextra -pedantic
LDFLAGS = -L/usr/local/lib
LDLIBS = -lsodium
