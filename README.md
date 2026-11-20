safe
====
Password protected secret keeper.

Fork of Willy Goiffon's safe. The storage format and crypto are
changed, the agent protocol is framed, and this tree adds a
browser-fill toolchain (safe-fill-host, safe-fill-migrate) that
upstream does not have. Stores made by upstream safe are not
readable here. See Compatibility.

Secrets are encrypted on disk with a key derived from the master
password. An agent can hold the key in memory so the password is
asked once; it decrypts and encrypts for its clients and never
hands the key out.

Differences from upstream
-----
- Format version 0x12, padded: every entry under 256 bytes has
  the same size on disk, so file sizes do not give away password
  lengths. 0x11 entries (unpadded, from before) are still read.
  CREAM header layout and Argon2id parameters are frozen; a store
  is readable by any build of this tree, on any libc.
- The entry path and header are bound into the AEAD. Renaming or
  swapping files, or editing a header, makes decryption fail.
- Truncated files and files with trailing data are rejected.
- Writes are atomic, and rename-without-replace unless -f is given.
- Entry names are checked: no absolute path, no "..", no "//", no
  leading "./", no trailing "/".
- The safe directory and the agent socket are checked for owner
  and mode.
- Linux release builds run safe, safe-agent and safe-fill-host
  under seccomp and Landlock.
- No key file to manage; the key comes from the password.
- Stream encryption, so entry size is not capped by the format.
- External askpass programs are supported.

Threat model
-----
Four cases are considered. Code execution as the user and root are
not among them.

A compromised page or extension can call the native messaging
host. The host does not decrypt. It asks the agent to decrypt one
path of the form passwords/<host>/<user>; the agent does the
openat, the header parse, and the secretstream pull. The plaintext
does not enter the browser's address space. The host does not read
SAFE_BIN or PATH, and runs wl-copy by absolute path. It can also
ask the agent to list the usernames saved for one origin (the L
command), so tatl can copy a username on hover; listing decrypts
nothing, needs an unlocked agent, and cannot enumerate the origins.

A clipboard reader on the same session can still see the paste.
wl-copy runs with --paste-once (and --sensitive with the default
wl-clipboard-rs backend; see Clipboard backend), and a backstop
wl-copy --clear fires after WL_CLEAR_DELAY_SEC. A reader that wins
the race against the paste is not stopped. That is a property of
the Wayland clipboard.

A bug in the host is contained. Landlock allows the agent socket,
/dev/null, /dev/urandom, /run/user/<real uid>, the dynamic linker
paths, and EXECUTE on WL_COPY_PATH; with the C wl-clipboard
backend it also allows reading, writing, creating and removing
files under /tmp. Seccomp allows the syscalls libc, libsodium and
wl-copy need and returns EPERM for the rest. A parser bug can pull
more passwords through the agent (the -p prefix limits which
paths, not how many) and can run wl-copy. With Landlock enforced
it cannot exec anything else by path or open files outside the
allowed set. It can still connect() to other AF_UNIX sockets the
uid can reach, and Landlock does not stop code running from a
memfd, so treat the sandbox as defense in depth. Sandboxed builds
have no per-request confirmation (safe-agent -c is unavailable).

Code execution as the user is not contained. The key sits in the
agent, mlocked and under seccomp, but any process running as the
user can speak the agent protocol, and in the hardened profile any
process in group safe-tatl can run the host.

Not covered:

- Phishing. A password is returned for the origin asked for.
  Nothing checks that the page in front of the user is the real
  one.
- A weak master password. Argon2id makes offline cracking
  expensive, not impossible.
- An unlocked agent on a machine someone else can touch. The -t
  timeout and safe-forget-all on lock are the mitigations; neither
  is automatic unless the session is set up that way.
- Code execution as _tatl through a route other than the
  installed safe-fill-host. The agent's uid check is the only gate
  here: -e cannot work across uids and sandboxed builds refuse it.
  See safe-agent(1).
- Root.

In the hardened profile (setuid host limited to group safe-tatl,
agents under their own uids, a nonzero -t on the browser agent) a
_tatl compromise gets the browser store and the clipboard, and,
with the C wl-clipboard backend, write access to /tmp. It does not
get the chat store, the master key, or the user's uid.

The doas or sudoers rule used for hardened migration (see
safe-fill-migrate(1)) lets processes running as the user decrypt
the browser store through the agent without the master password.
Remove it after migrating if that matters to you.

Usage
-----
See safe(1).

	safe -a mysecret < secret.jpg
	safe mysecret > secret.jpg

Entries are ordinary files under $SAFE_DIR:

	find ${SAFE_DIR} -type f

SAFE_DIR defaults to .secrets relative to the current directory;
set it to an absolute path.

With the agent:

	eval $(safe-agent -t 900)
	safe -r
	safe mysecret > secret.jpg

The agent needs a timeout; -t 0 (never forget) also needs
SAFE_UNSAFE_TIMEOUT=1.

Batch mode, for scripts (the password is the first line of stdin;
with -a, the rest of stdin is the secret; a new store reads the
password twice, on two lines):

	{ printf '%s\n' "$PASSWORD"; cat secret.jpg; } | safe -b -a mysecret

The tree builds four binaries:

	safe			encrypt, decrypt, push key to agent
	safe-agent		retain the derived key in memory
	safe-fill-host		native messaging host for tatl
	safe-fill-migrate	import Firefox logins into safe

Build
-----
The makefile is BSD make syntax: use bmake (it is make on Chimera
Linux). There is also an mkfile for Plan 9 mk.

Needs libsodium; safe-fill-migrate also needs NSS and SQLite. The
browser side needs a wl-copy and the tatl extension; see Clipboard
backend for which wl-copy.

Chimera Linux:

	doas apk add bmake libsodium-devel linux-headers \
	    nss-devel sqlite-devel pkgconf socat gitoxide rust cargo

	cd
	gix clone https://github.com/YaLTeR/wl-clipboard-rs
	cd ~/wl-clipboard-rs
	cargo build --release --package wl-clipboard-rs-tools
	doas cp target/release/wl-copy target/release/wl-paste \
	    target/release/wl-clip /usr/bin/

	cd ~/safe
	make
	doas make install

Debian/Ubuntu:

	sudo apt install bmake clang pkg-config libsodium-dev libnss3-dev \
	    libsqlite3-dev strace socat wl-clipboard opendoas gnupg wget

bmake, clang, pkg-config and the -dev packages are needed to build;
wl-clipboard is the C wl-copy (see Clipboard backend); opendoas is
for the hardened migration rule; strace and socat are for the
tests; gnupg and wget are for installing Mozilla's deb Firefox. On
Ubuntu, scripts/safe-ubuntu-install (make setup-ubuntu) installs
these and does the whole hardened setup.

Arch: libsodium nss sqlite, and a BSD make.

If mlock(2) fails (low RLIMIT_MEMLOCK, some containers), set
SAFE_UNSAFE_MLOCK=1 to turn the failure into a warning. The
setuid hardened host ignores it, and the hardened profile does
not set it: an agent that can not lock its memory refuses to
start. The agent needs only a few tens of kB.

Argon2id MODERATE takes 256 MiB during key derivation. On a
memory-constrained system it may fail. There is no fallback to a
weaker parameter set.

Clipboard backend
-----
safe-fill-host supports two wl-copy implementations, chosen at
build time with WL_CPPFLAGS (config.mk, or the make command line):

- wl-clipboard-rs, the default (WL_CPPFLAGS empty). Runs wl-copy
  --paste-once --sensitive. Needs a compositor with a data-control
  protocol: wlroots-based compositors and KDE. Tightest sandbox.
- wl-clipboard, the C implementation (WL_CPPFLAGS=-DWL_BACKEND_C).
  Needed on GNOME/mutter, which has no data-control protocol; this
  is the usual case on Ubuntu, whose wl-clipboard package is this
  one. No --sensitive. This wl-copy buffers what it copies in
  /tmp/wl-copy-buffer-XXXXXX/stdin, so the password sits in that
  file while it is on the clipboard (on disk if /tmp is not a
  tmpfs), and the host's sandbox is widened to /tmp for this build
  only.

	bmake WL_CPPFLAGS=-DWL_BACKEND_C
	doas bmake WL_CPPFLAGS=-DWL_BACKEND_C install-hardened

A host built for one and run with the other fails silently (rs
host, C wl-copy: every fill fails; C host, rs wl-copy: no
--sensitive). scripts/safe-wl-backend detect, flags and check tell
which wl-copy is installed, the matching WL_CPPFLAGS, and whether
the installed host matches; install-hardened installs it, and
safe-hardened-setup verify runs the check. safe-ubuntu-install
picks the backend from the installed wl-copy.

Hardened profile
-----
	bmake
	doas bmake install-hardened
	doas safe-hardened-setup
	doas safe-unlock

install-hardened installs the browser-fill stack: the agent runs as
_safe-browser, safe-fill-host goes to /usr/local/libexec as 6750
_tatl:safe-tatl (only members of safe-tatl can run it), and the
store lives under /var/lib/safe/browser. It first creates the users
and groups (_tatl, _safe-browser, _safe-chat, safe-tatl, safe-chat)
and adds you to safe-tatl; log out and in again so your browser
inherits the group.

safe-hardened-setup writes the services (safe-runtime-setup,
safe-browser-agent, safe-chat-agent) for systemd, with their files in
/etc/default, or for dinit, in /etc/dinit.d with .env files. It picks
the init system itself; -i systemd or -i dinit overrides that. It
creates /var/lib/safe/{browser,chat}, writes the Firefox
native-messaging manifest pointing at the libexec host, starts the
agents and checks that their memory is locked and that the host
matches the installed wl-copy. It does not edit doas.conf. A
configuration file that differs from what it would write is kept and
shown as a diff; run it with -f to replace it (the old file is copied
to /var/backups/safe-hardened first). Use -u USER when not running it
through doas or sudo, -e ID for another extension id, and -m BYTES to
add a memlock limit to the agent services.

On another service manager, run the users, dirs and manifest steps,
then create the equivalent services by hand: run
scripts/safe-runtime-setup once at boot, then

	safe-agent -d -s /var/lib/safe/browser \
	    -f /run/safe/browser/agent.sock -t 900 \
	    -u <uid of _tatl> -p passwords/ -g      (as _safe-browser)
	safe-agent -d -s /var/lib/safe/chat \
	    -f /run/safe/chat/agent.sock -t 0 -p chat/ -g
	                                    (as _safe-chat, with
	                                     SAFE_UNSAFE_TIMEOUT=1)

The chat agent serves a second, independent store for clients
outside this tree. It runs with -t 0 and SAFE_UNSAFE_TIMEOUT=1, so
it keeps its key until it is stopped or safe-forget-all runs.

make install also puts an unprivileged safe-fill-host in
/usr/local/bin. The hardened manifest does not use it; delete it if
you only run the hardened profile. make uninstall-hardened removes
the installed files; users, groups, units and stores stay.

Compatibility
-----
This fork does not read upstream stores. The Argon2id parameters
and the header layout are fixed; a store is readable by any binary
built from this tree, on any libc. See safe-store(5).

Entries are written in format 0x12 and 0x11 entries are read, so an
existing store keeps working and its entries become 0x12 as they
are rewritten (safe -f -a). Builds from before 0x12 cannot read
0x12 entries, nor a store created by a 0x12 build. Upgrade safe and
safe-agent together and restart the agents: an old safe refuses to
write through a new agent, and a new safe writing through an old
agent produces 0x11 entries.

Entry names, the number of entries, and their padded sizes stay
visible to anyone who can list the store; keep it, and its backups,
on encrypted storage if that matters.

Testing
-----
	bmake
	./tests.sh

Tests that need a running agent are skipped if safe-agent is not
built. Tests that speak the protocol directly are skipped if
socat is missing. Tests that need root (the setuid drop test; the
unwritable-directory test as root drops to another uid with
setpriv) skip or adapt when not root. The hardened-install test
runs only as root against a real install-hardened with the browser
agent unlocked; it writes one test entry to the browser store and
removes it again.

Skips do not fail the run; the script exits nonzero only on a
failure. Environment:

	STRICT=1	a skip is a failure, unless its prerequisite
			can not exist in this run
	HARDENED=1	require the hardened-install test under STRICT
	VERBOSE=<label>	run that one test with set -x and its output
	SAFE= AGENT= HOST=	binaries to test (default ./safe etc.)

[0]: https://z3bra.org/cream
[1]: https://libsodium.org
