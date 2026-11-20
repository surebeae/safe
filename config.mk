CC = clang
LD = ${CC}

PREFIX = /usr/local
MANPREFIX = ${PREFIX}/man

# Clipboard backend for safe-fill-host (see README, "Clipboard backend").
# Empty: wl-clipboard-rs (default; needs the wlr data-control protocol,
# i.e. wlroots compositors or KDE; tightest sandbox, --sensitive).
# -DWL_BACKEND_C: wl-clipboard (C), for GNOME/mutter, which lacks
# data-control; the host's sandbox is widened to /tmp for it.
# Override on the command line:  bmake WL_CPPFLAGS=-DWL_BACKEND_C
# scripts/safe-wl-backend detect  tells you which wl-copy is installed.
WL_CPPFLAGS =

CPPFLAGS = -I/usr/local/include -I/usr/include/nss -I/usr/include/nspr -D_DEFAULT_SOURCE ${WL_CPPFLAGS}
CFLAGS = -Wall -Wextra -pedantic -O2 -fstack-protector-strong -fPIE
LDFLAGS = -L/usr/local/lib -pie -Wl,-z,relro,-z,now
LDLIBS = -lsodium
