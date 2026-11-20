#!/bin/sh

set -u

SAFE=${SAFE:-./safe}
AGENT=${AGENT:-./safe-agent}
HOST=${HOST:-./safe-fill-host}
MIGRATE=${MIGRATE:-./safe-fill-migrate}
[ -x "$SAFE" ] || { echo "error: $SAFE not executable" >&2; exit 1; }

case "$SAFE" in  /*) ;; *) SAFE="$PWD/$SAFE"   ;; esac
case "$AGENT" in /*) ;; *) AGENT="$PWD/$AGENT" ;; esac
case "$HOST" in  /*) ;; *) HOST="$PWD/$HOST"   ;; esac

TMP=$(mktemp -d) || { echo "error: mktemp failed" >&2; exit 1; }
TESTPASS="pw-$$"
ASKPASS="$TMP/askpass.sh"
WRONGASK="$TMP/wrongask.sh"
SAFEDIR="$TMP/safe"
trap 'rm -rf "$TMP"; rm -rf /tmp/safe-peeruid-$$ 2>/dev/null' EXIT INT TERM

export XDG_RUNTIME_DIR="$TMP/xdg"
mkdir -p "$XDG_RUNTIME_DIR"
chmod 0700 "$XDG_RUNTIME_DIR"

printf '#!/bin/sh\nprintf "%%s\\n" "%s"\n' "$TESTPASS" > "$ASKPASS"
printf '#!/bin/sh\nprintf "%%s\\n" "wrong-%s"\n' "$TESTPASS" > "$WRONGASK"
chmod +x "$ASKPASS" "$WRONGASK"
export SAFE_ASKPASS="$ASKPASS" SAFE_DIR="$SAFEDIR"

# tests running as another uid must reach $TMP
chmod 0711 "$TMP"

# unprivileged uid: ourselves, or the sudo/doas user, or nobody
unpriv_ids() {
	if [ "$(id -u)" -ne 0 ]; then
		up_uid=$(id -u); up_gid=$(id -g); unpriv_prefix=""
		return 0
	fi
	command -v setpriv >/dev/null 2>&1 || return 1
	up_uid=${SUDO_UID:-${DOAS_UID:-65534}}
	up_gid=${SUDO_GID:-${DOAS_GID:-65534}}
	if [ "$up_uid" -eq 0 ]; then up_uid=65534; up_gid=65534; fi
	unpriv_prefix="setpriv --reuid=$up_uid --regid=$up_gid --clear-groups"
}
as_unpriv() { $unpriv_prefix env -u XDG_RUNTIME_DIR "$@"; }

# printf format for a native-messaging frame of $1
nm_fmt() {
	_n=${#1}
	printf '\\%03o\\%03o\\%03o\\%03o%%s' \
	    $((_n & 0xff)) $(((_n >> 8) & 0xff)) \
	    $(((_n >> 16) & 0xff)) $(((_n >> 24) & 0xff))
}

# $1 = strace log, $2 = uid: wl-copy was exec'd, after setresuid($2, ...)
trace_shows_drop() {
	_l=$(grep -n 'execve(.*wl-copy' "$1" | head -1 | cut -d: -f1)
	[ -n "$_l" ] || return 1
	head -n "$_l" "$1" | grep -qE "setresuid\\($2,"
}

# skips that STRICT allows
skip_allowed() {
	case "$1" in
	# needs a root run (a setuid binary owned by another uid)
	host_drop_to_user_setuid)    [ "$(id -u)" -ne 0 ] ;;
	# needs `make install-hardened`; set HARDENED=1 to require it
	hardened_install_host_drop)  [ -z "${HARDENED:-}" ] ;;
	# needs a pre-padding (format 0x11) safe binary in LEGACY_SAFE
	legacy_v11_readable)         [ -z "${LEGACY_SAFE:-}" ] ;;
	migrate_logins_json)         ! have_migrate || ! have_nss_py ;;
	*) return 1 ;;
	esac
}

PASS=0; FAIL=0; SKIP=0

run() {
	local label="$1"; shift
	local rc
	if [ "${VERBOSE:-}" = "$label" ]; then
		( set -x; "$@" ); rc=$?
	else
		"$@" >/dev/null 2>&1; rc=$?
	fi
	case $rc in
	0)  echo "PASS: $label"; PASS=$((PASS+1)) ;;
	77) if [ -n "${STRICT:-}" ] && ! skip_allowed "$label"; then
		echo "FAIL: $label (skipped in strict mode)"; FAIL=$((FAIL+1))
	    else
		echo "SKIP: $label"; SKIP=$((SKIP+1))
	    fi ;;
	*)  echo "FAIL: $label"; FAIL=$((FAIL+1)) ;;
	esac
}

file_mode() {
	stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

have_socat() { command -v socat >/dev/null 2>&1; }
# agent_state SOCK: status byte of the agent's I reply (0 no key, 1 key ok)
agent_state() {
	v=$(printf 'I' | socat - UNIX-CONNECT:"$1" 2>/dev/null |
	    od -An -tu1 -j1 -N1 | tr -d ' ')
	echo "${v:-0}"
}
have_agent() { [ -x "$AGENT" ]; }
have_host()  { [ -x "$HOST" ]; }
have_migrate() { [ -x "$MIGRATE" ]; }
# python3 with the system NSS, to build a Firefox-style test profile
have_nss_py() {
	command -v python3 >/dev/null 2>&1 &&
	    python3 -c 'import ctypes; ctypes.CDLL("libnss3.so")' 2>/dev/null
}
have_fuzz_host() { [ -x ./fuzz-host ]; }

wait_sock() {
	local s="$1" i=0
	while [ ! -S "$s" ] && [ "$i" -lt 50 ]; do
		sleep 0.1
		i=$((i + 1))
	done
	[ -S "$s" ]
}

wait_listen() {
	local s="$1" i=0
	if command -v socat >/dev/null 2>&1; then
		while [ "$i" -lt 50 ]; do
			if printf '' | socat -T0.2 - UNIX-CONNECT:"$s" \
			    >/dev/null 2>&1; then
				return 0
			fi
			sleep 0.1
			i=$((i + 1))
		done
		return 1
	fi
	sleep 0.5
	return 0
}

new_safe() {
	local dir="$1"
	mkdir -p "$dir"
	chmod 0700 "$dir"
	printf 'x' | SAFE_DIR="$dir" "$SAFE" -k -a seed
}

poke() {
	printf "$3" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}

# byte at offset $2 of file $1, as a decimal number
peek() {
	od -An -tu1 -j"$2" -N1 "$1" | tr -d ' '
}

# on-disk size of a 0x12 entry holding $1 bytes
entry_size() {
	_full=$(($1 / 8192)) _r=$(($1 % 8192)) _b=256
	while [ "$_b" -lt $((_r + 1)) ]; do _b=$((_b * 2)); done
	echo $((40 + 24 + _full * (8192 + 17) + _b + 17))
}


t_basic() {
	printf 'hello world' > "$TMP/plain"
	"$SAFE" -k -a t1 < "$TMP/plain" || return 1
	"$SAFE" -k t1 | diff -q - "$TMP/plain"
}
run basic_roundtrip t_basic

t_bufsiz() {
	dd if=/dev/urandom of="$TMP/big" bs=8192 count=2 2>/dev/null || return 1
	"$SAFE" -k -a t2 < "$TMP/big" || return 1
	"$SAFE" -k t2 | cmp -s - "$TMP/big"
}
run exact_bufsiz_roundtrip t_bufsiz

t_empty() {
	: | "$SAFE" -k -a t3 || return 1
	[ -z "$("$SAFE" -k t3)" ]
}
run empty_secret t_empty

t_subdir() {
	printf 'nested' | "$SAFE" -k -a a/b/c/leaf || return 1
	[ -d "$SAFEDIR/a/b/c" ] || return 1
	m=$(file_mode "$SAFEDIR/a/b/c")
	[ "$m" = 700 ] || return 1
	[ "$("$SAFE" -k a/b/c/leaf)" = 'nested' ]
}
run subdir_creation t_subdir


t_trunc() {
	printf 'secret' | "$SAFE" -k -a t4 || return 1
	sz=$(wc -c < "$SAFEDIR/t4")
	head -c $((sz-1)) "$SAFEDIR/t4" > "$SAFEDIR/t4.tmp"
	mv "$SAFEDIR/t4.tmp" "$SAFEDIR/t4"
	! "$SAFE" -k t4 >/dev/null 2>&1
}
run truncation_rejected t_trunc

t_trailing() {
	printf 'secret' | "$SAFE" -k -a t5 || return 1
	printf 'junk' >> "$SAFEDIR/t5"
	! "$SAFE" -k t5 >/dev/null 2>&1
}
run trailing_data_rejected t_trailing

t_nameswap() {
	printf 'bankpass' | "$SAFE" -k -a bank6 || return 1
	printf 'redditpass' | "$SAFE" -k -a reddit6 || return 1
	cp "$SAFEDIR/bank6"   "$TMP/b"
	cp "$SAFEDIR/reddit6" "$SAFEDIR/bank6"
	cp "$TMP/b"           "$SAFEDIR/reddit6"
	! "$SAFE" -k bank6 >/dev/null 2>&1
}
run nameswap_rejected t_nameswap


t_path_dotdot()      { ! printf 'x' | "$SAFE" -k -a '../escape'    2>/dev/null; }
t_path_abs()         { ! printf 'x' | "$SAFE" -k -a '/etc/passwd'  2>/dev/null; }
t_path_dslash()      { ! printf 'x' | "$SAFE" -k -a 'foo//bar'     2>/dev/null; }
t_path_dot()         { ! printf 'x' | "$SAFE" -k -a '.'            2>/dev/null; }
t_path_trail()       { ! printf 'x' | "$SAFE" -k -a 'foo/'         2>/dev/null; }
t_path_dot_slash()   { ! printf 'x' | "$SAFE" -k -a './foo'        2>/dev/null; }
t_path_inner_dotdot() { ! printf 'x' | "$SAFE" -k -a 'sub/../foo'  2>/dev/null; }

run path_dotdot       t_path_dotdot
run path_absolute     t_path_abs
run path_dslash       t_path_dslash
run path_dot          t_path_dot
run path_trail        t_path_trail
run path_dot_slash    t_path_dot_slash
run path_inner_dotdot t_path_inner_dotdot

t_symlink() {
	printf 'x' | "$SAFE" -k -a t8 || return 1
	ln -s "$SAFEDIR/t8" "$SAFEDIR/t8link"
	! "$SAFE" -k t8link >/dev/null 2>&1
}
run symlink_rejected t_symlink


t_wrongpass() {
	printf 'x' | "$SAFE" -k -a t9 || return 1
	! SAFE_ASKPASS="$WRONGASK" "$SAFE" -k t9 >/dev/null 2>&1
}
run wrong_master_password t_wrongpass

t_master_reject_write() {
	printf 'x' | "$SAFE" -k -a master 2>/dev/null && return 1
	return 0
}
t_master_force_write() {
	printf 'x' | "$SAFE" -k -f -a master || return 1
	"$SAFE" -k master >/dev/null
}
run master_reject_write t_master_reject_write
run master_force_write  t_master_force_write

t_recovery() {
	printf 'recover-me' | "$SAFE" -k -a rec1 || return 1
	cp "$SAFEDIR/rec1" "$SAFEDIR/master"
	chmod 400 "$SAFEDIR/master"
	! "$SAFE" -k rec1 >/dev/null 2>&1 || return 1
	! "$SAFE" -k master >/dev/null 2>&1 || return 1
	printf 'x' | "$SAFE" -k -f -a master || return 1
	[ "$("$SAFE" -k rec1)" = 'recover-me' ] || return 1
	"$SAFE" -k master >/dev/null 2>&1 || return 1
}
run recovery_after_copy t_recovery


t_bad_magic() {
	d="$TMP/bm"; new_safe "$d" || return 1
	poke "$d/master" 0 'XXXXXX'
	! SAFE_DIR="$d" "$SAFE" -k seed >/dev/null 2>&1
}
run bad_magic t_bad_magic

t_bad_version() {
	d="$TMP/bv"; new_safe "$d" || return 1
	poke "$d/master" 7 '\020'
	! SAFE_DIR="$d" "$SAFE" -k seed >/dev/null 2>&1
}
run bad_version t_bad_version

t_low_memory() {
	d="$TMP/lm"; new_safe "$d" || return 1
	poke "$d/master" 12 '\000\000\020\000'
	! SAFE_DIR="$d" "$SAFE" -k seed >/dev/null 2>&1
}
run low_memory t_low_memory

t_zero_time() {
	d="$TMP/zt"; new_safe "$d" || return 1
	poke "$d/master" 16 '\000\000\000\000'
	! SAFE_DIR="$d" "$SAFE" -k seed >/dev/null 2>&1
}
run zero_time t_zero_time

t_bad_master_header() {
	bad="$TMP/badhdr"
	mkdir -p "$bad"; chmod 0700 "$bad"
	printf 'garbage-not-a-header' > "$bad/master"
	chmod 600 "$bad/master"
	! SAFE_DIR="$bad" "$SAFE" -k -a x < /dev/null >/dev/null 2>&1
}
run bad_master_header t_bad_master_header

t_oversized_bufsiz() {
	bad="$TMP/oversize"
	mkdir -p "$bad"; chmod 0700 "$bad"
	printf 'CREAM\001\000\021\000\020\000\001\000\001\000\000\000\002\000\000\000\001\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000' > "$bad/master"
	chmod 600 "$bad/master"
	! SAFE_DIR="$bad" "$SAFE" -k x >/dev/null 2>&1
}
run oversized_bufsiz t_oversized_bufsiz

t_read_without_master() {
	d="$TMP/nm"; new_safe "$d" || return 1
	rm "$d/master"
	! SAFE_DIR="$d" "$SAFE" -k seed >/dev/null 2>&1
	! SAFE_DIR="$d" "$SAFE" -k seed >/dev/null 2>&1
}
run read_without_master t_read_without_master

t_old_format_rejected() {
	d="$TMP/v10"; new_safe "$d" || return 1
	printf 'hi' | SAFE_DIR="$d" "$SAFE" -k -a v10 || return 1
	poke "$d/v10" 7 '\020'
	! SAFE_DIR="$d" "$SAFE" -k v10 >/dev/null 2>&1
}
run old_format_rejected t_old_format_rejected


t_nooverwrite() {
	printf 'one' | "$SAFE" -k -a t10 || return 1
	! printf 'two' | "$SAFE" -k -a t10 2>/dev/null || return 1
	[ "$("$SAFE" -k t10)" = 'one' ]
}
t_overwrite() {
	printf 'one' | "$SAFE" -k -a t10f || return 1
	printf 'two' | "$SAFE" -k -f -a t10f || return 1
	[ "$("$SAFE" -k t10f)" = 'two' ]
}
run no_overwrite_without_f t_nooverwrite
run overwrite_with_f       t_overwrite


t_batch_stdin_no_tty() {
	printf 'batchdata' > "$TMP/bp"
	"$SAFE" -k -a batch1 < "$TMP/bp" || return 1
	printf '%s\n' "$TESTPASS" | \
	    SAFE_ASKPASS=/bin/false "$SAFE" -b batch1 > "$TMP/bp.out" || return 1
	cmp -s "$TMP/bp" "$TMP/bp.out"
}
t_batch_wrong_pass() {
	printf 'definitely-wrong\n' | \
	    SAFE_ASKPASS=/bin/false "$SAFE" -b batch1 >/dev/null 2>&1 && return 1
	return 0
}
run batch_stdin_no_tty t_batch_stdin_no_tty
run batch_wrong_pass   t_batch_wrong_pass


t_symlinked_safe() {
	real="$TMP/realsafe"; link="$TMP/linksafe"
	mkdir -p "$real"; chmod 0700 "$real"
	ln -s "$real" "$link"
	printf 'via-link' | SAFE_DIR="$link" "$SAFE" -k -a sl1 || return 1
	[ "$(SAFE_DIR="$link" "$SAFE" -k sl1)" = 'via-link' ] || return 1
	[ "$(SAFE_DIR="$real" "$SAFE" -k sl1)" = 'via-link' ]
}
run symlinked_safe t_symlinked_safe

t_safe_dir_perms() {
	bad="$TMP/badperm"; mkdir -p "$bad"; chmod 0755 "$bad"
	! SAFE_DIR="$bad" "$SAFE" -k -a x </dev/null >/dev/null 2>&1
}
run safe_dir_insecure_perms t_safe_dir_perms

t_safe_dir_is_file() {
	: > "$TMP/notadir"
	! SAFE_DIR="$TMP/notadir" "$SAFE" -k -a x </dev/null >/dev/null 2>&1
}
run safe_dir_is_file t_safe_dir_is_file

t_safe_dir_unwritable() {
	unpriv_ids || return 77
	mkdir -p "$TMP/ro" "$TMP/rw"
	chmod 0555 "$TMP/ro"; chmod 0777 "$TMP/rw"
	# positive control
	printf 'x' | as_unpriv env SAFE_UNSAFE_MLOCK=1 SAFE_DIR="$TMP/rw/new" \
	    "$SAFE" -k -a x >/dev/null 2>&1 || return 1
	! as_unpriv env SAFE_UNSAFE_MLOCK=1 SAFE_DIR="$TMP/ro/new" \
	    "$SAFE" -k -a x </dev/null >/dev/null 2>&1
}
run safe_dir_unwritable t_safe_dir_unwritable

t_per_secret_header() {
	printf 'x' | "$SAFE" -k -a t11 || return 1
	"$SAFE" -k t11 >/dev/null
}
run per_secret_header_read t_per_secret_header


t_agent() {
	have_agent || return 77
	sock="$TMP/ag/agent.sock"
	mkdir -p "$TMP/ag"; chmod 0700 "$TMP/ag"
	"$AGENT" -d -f "$sock" -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	export SAFE_SOCK="$sock"
	printf 'agent-secret' | "$SAFE" -k -r -a agent11 || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	got=$("$SAFE" -k agent11 2>/dev/null)
	kill "$apid" 2>/dev/null; unset SAFE_SOCK
	[ "$got" = 'agent-secret' ]
}
run agent_roundtrip t_agent

t_agent_handshake() {
	have_agent || return 77
	sock="$TMP/agh/agent.sock"
	mkdir -p "$TMP/agh"; chmod 0700 "$TMP/agh"
	eval "$("$AGENT" -t 900 -f "$sock")" || return 1
	[ -S "$sock" ] || { kill "${SAFE_PID:-}" 2>/dev/null; return 1; }
	export SAFE_SOCK="$sock"
	printf 'hs-data' | "$SAFE" -k -r -a hs1 || {
		kill "${SAFE_PID:-}" 2>/dev/null; unset SAFE_SOCK SAFE_PID; return 1; }
	got=$("$SAFE" -k hs1)
	kill "${SAFE_PID:-}" 2>/dev/null; unset SAFE_SOCK SAFE_PID
	[ "$got" = 'hs-data' ]
}
run agent_handshake t_agent_handshake

t_agent_badsock_handshake() {
	have_agent || return 77
	! "$AGENT" -t 900 -f "/tmp/safe-test-$$.sock" >/dev/null 2>&1
}
run agent_badsock_handshake t_agent_badsock_handshake

t_agent_badsock() {
	have_agent || return 77
	! "$AGENT" -d -t 900 -f "/tmp/safe-test-$$.sock" >/dev/null 2>&1
}
run agent_rejects_worldwritable_parent t_agent_badsock

t_agent_tneg() {
	have_agent || return 77
	! "$AGENT" -d -t -1 -f "$TMP/tneg.sock" >/dev/null 2>&1
}
run agent_rejects_negative_t t_agent_tneg

t_agent_tgarbage() {
	have_agent || return 77
	! "$AGENT" -d -t 1x   -f "$TMP/tg1.sock" >/dev/null 2>&1 || return 1
	! "$AGENT" -d -t 0x10 -f "$TMP/tg2.sock" >/dev/null 2>&1 || return 1
	! "$AGENT" -d -t abc  -f "$TMP/tg3.sock" >/dev/null 2>&1 || return 1
	return 0
}
run agent_rejects_t_garbage t_agent_tgarbage

t_agent_t0_notimeout() {
	have_agent || return 77
	sock="$TMP/agt0/agent.sock"
	mkdir -p "$TMP/agt0"; chmod 0700 "$TMP/agt0"
	eval "$(SAFE_UNSAFE_TIMEOUT=1 "$AGENT" -t 0 -f "$sock")" || return 1
	export SAFE_SOCK="$sock"
	printf 't0-test' | "$SAFE" -k -r -a t0a || {
		kill "${SAFE_PID:-}" 2>/dev/null; unset SAFE_SOCK SAFE_PID; return 1; }
	sleep 2
	got=$("$SAFE" -b t0a </dev/null 2>/dev/null)
	kill "${SAFE_PID:-}" 2>/dev/null; unset SAFE_SOCK SAFE_PID
	[ "$got" = 't0-test' ]
}
run agent_t0_means_no_timeout t_agent_t0_notimeout

t_agent_socket_mode() {
	have_agent || return 77
	sock="$TMP/agmode/agent.sock"
	mkdir -p "$TMP/agmode"; chmod 0700 "$TMP/agmode"
	"$AGENT" -d -f "$sock" -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	mode=$(file_mode "$sock")
	kill "$apid" 2>/dev/null
	[ "$mode" = "600" ]
}
run agent_socket_mode_0600 t_agent_socket_mode

t_agent_sigterm_cleanup() {
	have_agent || return 77
	out=$("$AGENT" -t 900 2>/dev/null) || return 1
	sock=$(printf '%s\n' "$out" | sed -n 's/^SAFE_SOCK=\([^;]*\);.*/\1/p')
	apid=$(printf '%s\n' "$out" | sed -n 's/^SAFE_PID=\([^;]*\);.*/\1/p')
	[ -n "$sock" ] && [ -n "$apid" ] || return 1
	dir=$(dirname "$sock")
	i=0
	while [ -e "$sock" ] && [ "$i" -lt 5 ]; do
		kill -TERM "$apid" 2>/dev/null
		sleep 0.1
		i=$((i + 1))
	done
	[ ! -e "$sock" ] || return 1
	[ ! -d "$dir" ] || return 1
}
run agent_sigterm_cleanup t_agent_sigterm_cleanup

t_agent_sighup_cleanup() {
	have_agent || return 77
	out=$("$AGENT" -t 900 2>/dev/null) || return 1
	sock=$(printf '%s\n' "$out" | sed -n 's/^SAFE_SOCK=\([^;]*\);.*/\1/p')
	apid=$(printf '%s\n' "$out" | sed -n 's/^SAFE_PID=\([^;]*\);.*/\1/p')
	[ -n "$sock" ] && [ -n "$apid" ] || return 1
	dir=$(dirname "$sock")
	i=0
	while [ -e "$sock" ] && [ "$i" -lt 5 ]; do
		kill -HUP "$apid" 2>/dev/null
		sleep 0.1
		i=$((i + 1))
	done
	[ ! -e "$sock" ] || return 1
	[ ! -d "$dir" ] || return 1
}
run agent_sighup_cleanup t_agent_sighup_cleanup

t_agent_xdg_publish() {
	have_agent || return 77
	xdg="$TMP/xdgtest"
	mkdir -p "$xdg"; chmod 0700 "$xdg"
	out=$(XDG_RUNTIME_DIR="$xdg" "$AGENT" -t 900 2>/dev/null) || return 1
	sock=$(printf '%s\n' "$out" | sed -n 's/^SAFE_SOCK=\([^;]*\);.*/\1/p')
	apid=$(printf '%s\n' "$out" | sed -n 's/^SAFE_PID=\([^;]*\);.*/\1/p')
	[ -n "$sock" ] && [ -n "$apid" ] || return 1
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	i=0
	while [ ! -s "$xdg/safe/sock" ] && [ "$i" -lt 20 ]; do
		sleep 0.1
		i=$((i + 1))
	done
	[ -s "$xdg/safe/sock" ] || { kill "$apid" 2>/dev/null; return 1; }
	[ "$(cat "$xdg/safe/sock" 2>/dev/null)" = "$sock" ] || {
		kill "$apid" 2>/dev/null; return 1; }
	kill -TERM "$apid"
	i=0
	while [ -e "$xdg/safe/sock" ] && [ "$i" -lt 20 ]; do
		sleep 0.1
		i=$((i + 1))
	done
	[ ! -e "$xdg/safe/sock" ]
}
run agent_xdg_publish t_agent_xdg_publish

t_agent_relative_f() {
	have_agent || return 77
	oldpwd=$(pwd)
	mkdir -p "$TMP/relf"; chmod 0700 "$TMP/relf"
	cd "$TMP/relf" || { cd "$oldpwd"; return 1; }
	"$AGENT" -d -f agent.sock -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$TMP/relf/agent.sock" || {
		kill "$apid" 2>/dev/null; cd "$oldpwd"; return 1; }
	[ -f "$TMP/relf/agent.pid" ] || {
		kill "$apid" 2>/dev/null; cd "$oldpwd"; return 1; }
	kill "$apid" 2>/dev/null
	cd "$oldpwd"
	return 0
}
run agent_relative_f t_agent_relative_f


t_agent_timeout() {
	have_agent && have_socat || return 77
	sock="$TMP/agt/agent.sock"
	mkdir -p "$TMP/agt"; chmod 0700 "$TMP/agt"
	"$AGENT" -d -t 1 -f "$sock" >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	export SAFE_SOCK="$sock"
	printf 'x' | "$SAFE" -k -r -a to1 || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	sleep 2
	n=$(agent_state "$sock")
	kill "$apid" 2>/dev/null; unset SAFE_SOCK
	[ "$n" -eq 0 ]
}
run agent_timeout t_agent_timeout

t_agent_sigusr1() {
	have_agent && have_socat || return 77
	sock="$TMP/agu/agent.sock"
	mkdir -p "$TMP/agu"; chmod 0700 "$TMP/agu"
	"$AGENT" -d -f "$sock" -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	export SAFE_SOCK="$sock"
	printf 'x' | "$SAFE" -k -r -a su1 || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	kill -USR1 "$apid"
	sleep 0.2
	n=$(agent_state "$sock")
	kill "$apid" 2>/dev/null; unset SAFE_SOCK
	[ "$n" -eq 0 ]
}
run agent_sigusr1_forgets t_agent_sigusr1


t_agent_stale_socket() {
	have_agent || return 77
	sock="$TMP/ags/agent.sock"
	mkdir -p "$TMP/ags"; chmod 0700 "$TMP/ags"
	"$AGENT" -d -f "$sock" -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	kill -KILL "$apid" 2>/dev/null
	wait "$apid" 2>/dev/null
	[ -S "$sock" ] || return 77
	"$AGENT" -d -f "$sock" -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	export SAFE_SOCK="$sock"
	printf 'stale-ok' | "$SAFE" -k -r -a st1 || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	got=$("$SAFE" -k st1 2>/dev/null)
	kill "$apid" 2>/dev/null; unset SAFE_SOCK
	[ "$got" = 'stale-ok' ]
}
run agent_stale_socket t_agent_stale_socket

t_agent_repush_overwrites() {
	have_agent || return 77
	sock="$TMP/agrep/agent.sock"
	mkdir -p "$TMP/agrep"; chmod 0700 "$TMP/agrep"
	"$AGENT" -d -f "$sock" -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	export SAFE_SOCK="$sock"
	printf 'first' | "$SAFE" -k -r -a rp1 || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	sleep 0.1
	"$SAFE" -k -r </dev/null || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	sleep 0.1
	got=$("$SAFE" -b rp1 </dev/null 2>/dev/null)
	kill "$apid" 2>/dev/null; unset SAFE_SOCK
	[ "$got" = 'first' ]
}
run agent_repush t_agent_repush_overwrites

t_agent_partial_push_keeps_key() {
	have_agent && have_socat || return 77
	sock="$TMP/agp/agent.sock"
	mkdir -p "$TMP/agp"; chmod 0700 "$TMP/agp"
	"$AGENT" -d -f "$sock" -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	export SAFE_SOCK="$sock"
	printf 'keep-me' | "$SAFE" -k -r -a pp1 || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	printf 'P0123456789' | socat - UNIX-CONNECT:"$sock" >/dev/null 2>&1 || true
	got=$("$SAFE" -b pp1 </dev/null 2>/dev/null)
	kill "$apid" 2>/dev/null; unset SAFE_SOCK
	[ "$got" = 'keep-me' ]
}
run agent_partial_push_keeps_key t_agent_partial_push_keeps_key

t_agent_push_only() {
	have_agent || return 77
	printf 'init' | "$SAFE" -k -a init0 || return 1
	sock="$TMP/agpush/agent.sock"
	mkdir -p "$TMP/agpush"; chmod 0700 "$TMP/agpush"
	"$AGENT" -d -f "$sock" -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	export SAFE_SOCK="$sock"
	"$SAFE" -k -r || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	printf 'pushonly' | "$SAFE" -k -a pu1 || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	got=$("$SAFE" -b pu1 </dev/null 2>/dev/null)
	kill "$apid" 2>/dev/null; unset SAFE_SOCK
	[ "$got" = 'pushonly' ]
}
run agent_push_only t_agent_push_only

t_r_no_sock() {
	( unset SAFE_SOCK; "$SAFE" -k -r someentry </dev/null 2>/dev/null ) && return 1
	return 0
}
t_r_stale_sock() {
	( SAFE_SOCK=/tmp/does-not-exist-$$ "$SAFE" -k -r someentry \
	    </dev/null 2>/dev/null ) && return 1
	return 0
}
run r_no_sock    t_r_no_sock
run r_stale_sock t_r_stale_sock


t_fuzz_smoke() {
	have_fuzz_host || return 77
	local corpus rc
	corpus=$(mktemp -d) || return 1
	ASAN_OPTIONS=detect_leaks=0 \
	    ./fuzz-host -runs=10000 -max_total_time=60 \
	        -artifact_prefix="$corpus/" "$corpus" \
	        >/dev/null 2>&1
	rc=$?
	if [ "$rc" -ne 0 ]; then
		echo "  crash artifact(s) preserved in $corpus:" >&2
		ls -la "$corpus" >&2
		return "$rc"
	fi
	rm -rf "$corpus"
	return 0
}
run fuzz_parser_smoke t_fuzz_smoke


t_agent_D() {
	have_agent && have_socat || return 77
	sock="$TMP/agD/agent.sock"
	mkdir -p "$TMP/agD"; chmod 0700 "$TMP/agD"
	"$AGENT" -d -f "$sock" -s "$SAFEDIR" -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	export SAFE_SOCK="$sock"
	printf 'D-target' | "$SAFE" -k -a Dtest || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	"$SAFE" -k -r </dev/null || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	# reply: 'K' len[4] plaintext
	got=$(printf 'D\000\000\000\005Dtest' | \
	    socat - UNIX-CONNECT:"$sock" 2>/dev/null | tail -c +6)
	kill "$apid" 2>/dev/null; unset SAFE_SOCK
	[ "$got" = 'D-target' ]
}
run agent_D_command t_agent_D

t_agent_prefix_enforced() {
	have_agent && have_socat || return 77
	sock="$TMP/agpfx/agent.sock"
	mkdir -p "$TMP/agpfx"; chmod 0700 "$TMP/agpfx"
	printf 'allowed' | "$SAFE" -k -a passwords/allowed || return 1
	printf 'blocked' | "$SAFE" -k -a secrets/blocked  || return 1
	"$AGENT" -d -f "$sock" -s "$SAFEDIR" -p "passwords/" -t 900 \
	    >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	export SAFE_SOCK="$sock"
	"$SAFE" -k -r </dev/null || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	got_ok=$(printf 'D\000\000\000\021passwords/allowed' | \
	    socat - UNIX-CONNECT:"$sock" 2>/dev/null | tail -c +6)
	got_blocked=$(printf 'D\000\000\000\017secrets/blocked' | \
	    socat - UNIX-CONNECT:"$sock" 2>/dev/null)
	kill "$apid" 2>/dev/null; unset SAFE_SOCK
	[ "$got_ok" = 'allowed' ] && [ -z "$got_blocked" ]
}
run agent_prefix_enforced t_agent_prefix_enforced

# L lists the regular files of one directory beneath the -p prefix
t_agent_L() {
	have_agent && have_socat || return 77
	sock="$TMP/agL/agent.sock"
	mkdir -p "$TMP/agL"; chmod 0700 "$TMP/agL"
	printf 'p1' | "$SAFE" -k -a passwords/l.test/alice || return 1
	printf 'p2' | "$SAFE" -k -a passwords/l.test/bob   || return 1
	printf 'p3' | "$SAFE" -k -a passwords/l.test/sub/x || return 1
	"$AGENT" -d -f "$sock" -s "$SAFEDIR" -p "passwords/" -t 900 \
	    >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	# locked: no reply at all
	locked=$(printf 'L\000\000\000\020passwords/l.test' | \
	    socat - UNIX-CONNECT:"$sock" 2>/dev/null | wc -c)
	export SAFE_SOCK="$sock"
	"$SAFE" -k -r </dev/null || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	names=$(printf 'L\000\000\000\020passwords/l.test' | \
	    socat - UNIX-CONNECT:"$sock" 2>/dev/null | tail -c +6 | sort |
	    tr '\n' ' ')
	# a missing directory is an empty list: 'K' 0 0 0 0
	empty=$(printf 'L\000\000\000\022passwords/none.test' | \
	    socat - UNIX-CONNECT:"$sock" 2>/dev/null | od -An -tx1 | tr -d ' \n')
	# the prefix itself and paths outside it are refused
	top=$(printf 'L\000\000\000\011passwords' | \
	    socat - UNIX-CONNECT:"$sock" 2>/dev/null | wc -c)
	out=$(printf 'L\000\000\000\007secrets' | \
	    socat - UNIX-CONNECT:"$sock" 2>/dev/null | wc -c)
	dd=$(printf 'L\000\000\000\023passwords/l.test/..' | \
	    socat - UNIX-CONNECT:"$sock" 2>/dev/null | wc -c)
	kill "$apid" 2>/dev/null; unset SAFE_SOCK
	[ "$locked" -eq 0 ] && [ "$names" = 'alice bob ' ] &&
	    [ "$empty" = '4b00000000' ] && [ "$top" -eq 0 ] &&
	    [ "$out" -eq 0 ] && [ "$dd" -eq 0 ]
}
run agent_L_command t_agent_L

t_agent_c_sandbox_reject() {
	have_agent || return 77
	command -v timeout >/dev/null 2>&1 || return 77
	sock="$TMP/agc/agent.sock"
	mkdir -p "$TMP/agc"; chmod 0700 "$TMP/agc"
	out=$(timeout 2 "$AGENT" -d -f "$sock" -t 900 -c /bin/true 2>&1)
	rc=$?
	[ "$rc" -eq 124 ] && return 77	
	printf '%s\n' "$out" | grep -q 'not supported in this build' || return 1
	return 0
}
run agent_c_rejected_in_sandbox t_agent_c_sandbox_reject

t_agent_e_sandbox_reject() {
	have_agent || return 77
	command -v timeout >/dev/null 2>&1 || return 77
	sock="$TMP/age/agent.sock"
	mkdir -p "$TMP/age"; chmod 0700 "$TMP/age"
	out=$(timeout 2 "$AGENT" -d -f "$sock" -t 900 -e /bin/true 2>&1)
	rc=$?
	[ "$rc" -eq 124 ] && return 77	
	printf '%s\n' "$out" | \
	    grep -qE 'not supported in this build|Linux-only' || return 1
	return 0
}
run agent_e_rejected t_agent_e_sandbox_reject

t_agent_forget() {
	have_agent && have_socat || return 77
	sock="$TMP/agF/agent.sock"
	mkdir -p "$TMP/agF"; chmod 0700 "$TMP/agF"
	"$AGENT" -d -f "$sock" -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	export SAFE_SOCK="$sock"
	printf 'x' | "$SAFE" -k -r -a fg1 || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	n1=$(agent_state "$sock")
	if [ "$n1" -ne 1 ]; then
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1
	fi
	"$SAFE" -F || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	sleep 0.2
	n2=$(agent_state "$sock")
	kill "$apid" 2>/dev/null; unset SAFE_SOCK
	[ "$n2" -eq 0 ]
}
run agent_forget_command t_agent_forget

t_agent_once() {
	have_agent && have_socat || return 77
	sock="$TMP/agO/agent.sock"
	mkdir -p "$TMP/agO"; chmod 0700 "$TMP/agO"
	"$AGENT" -d -f "$sock" -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	export SAFE_SOCK="$sock"
	printf 'seed' | "$SAFE" -k -r -o -a on1 || {
		kill "$apid" 2>/dev/null; unset SAFE_SOCK; return 1; }
	n1=$(agent_state "$sock")
	# one use through the agent consumes the key
	got=$("$SAFE" -k on1 2>/dev/null)
	n2=$(agent_state "$sock")
	kill "$apid" 2>/dev/null; unset SAFE_SOCK
	[ "$n1" -eq 1 ] && [ "$got" = seed ] && [ "$n2" -eq 0 ]
}
run agent_once_flag t_agent_once


t_host_no_safe_bin() {
	have_host || return 77
	if grep -aq 'SAFE_BIN' "$HOST"; then
		return 1
	fi
	return 0
}
run host_no_safe_bin t_host_no_safe_bin

t_host_uses_agent() {
	have_agent || return 77
	have_host  || return 77
	unpriv_ids || return 77
	as_unpriv test -x "$AGENT" && as_unpriv test -x "$SAFE" \
	    && as_unpriv test -x "$HOST" || return 77

	# the host wants a socket owned by its (unprivileged) euid
	hsafe="$TMP/hosta/store"; sock="$TMP/hosta/agent.sock"
	mkdir -p "$TMP/hosta" "$hsafe"
	chmod 0700 "$TMP/hosta" "$hsafe"
	[ "$(id -u)" -ne 0 ] || chown -R "$up_uid:$up_gid" "$TMP/hosta"

	as_unpriv env SAFE_UNSAFE_MLOCK=1 "$AGENT" -d -f "$sock" -s "$hsafe" \
	    -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }

	printf 'host-secret' | as_unpriv env SAFE_UNSAFE_MLOCK=1 SAFE_SOCK="$sock" \
	    "$SAFE" -s "$hsafe" -k -a passwords/test.host/user1 || {
		kill "$apid" 2>/dev/null; return 1; }
	as_unpriv env SAFE_UNSAFE_MLOCK=1 SAFE_SOCK="$sock" \
	    "$SAFE" -s "$hsafe" -k -r </dev/null || {
		kill "$apid" 2>/dev/null; return 1; }

	msg='{"origin":"test.host","username":"user1"}'
	fmt=$(nm_fmt "$msg")
	out=$(printf "$fmt" "$msg" | as_unpriv env SAFE_UNSAFE_MLOCK=1 \
	    SAFE_SOCK="$sock" "$HOST" 2>/dev/null)
	kill "$apid" 2>/dev/null

	case "$out" in
	*'"success":true'*)             return 0 ;;
	*'"error":"clipboard_failed"'*) return 0 ;;
	*)                              return 1 ;;
	esac
}
run host_uses_agent t_host_uses_agent

# "op":"list" and "op":"user" go through the agent's L command
t_host_names() {
	have_agent || return 77
	have_host  || return 77
	unpriv_ids || return 77
	as_unpriv test -x "$AGENT" && as_unpriv test -x "$SAFE" \
	    && as_unpriv test -x "$HOST" || return 77

	hsafe="$TMP/hostn/store"; sock="$TMP/hostn/agent.sock"
	mkdir -p "$TMP/hostn" "$hsafe"
	chmod 0700 "$TMP/hostn" "$hsafe"
	[ "$(id -u)" -ne 0 ] || chown -R "$up_uid:$up_gid" "$TMP/hostn"

	as_unpriv env SAFE_UNSAFE_MLOCK=1 "$AGENT" -d -f "$sock" -s "$hsafe" \
	    -p passwords/ -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	for e in one.host/solo two.host/ann 'two.host/b"q'; do
		printf 'x' | as_unpriv env SAFE_UNSAFE_MLOCK=1 \
		    SAFE_SOCK="$sock" "$SAFE" -s "$hsafe" -k \
		    -a "passwords/$e" || { kill "$apid" 2>/dev/null; return 1; }
	done
	as_unpriv env SAFE_UNSAFE_MLOCK=1 SAFE_SOCK="$sock" \
	    "$SAFE" -s "$hsafe" -k -r </dev/null || {
		kill "$apid" 2>/dev/null; return 1; }

	hq() {
		printf "$(nm_fmt "$1")" "$1" | as_unpriv env \
		    SAFE_UNSAFE_MLOCK=1 SAFE_SOCK="$sock" "$HOST" 2>/dev/null |
		    tail -c +5
	}
	user1=$(hq '{"op":"user","origin":"one.host"}')
	user2=$(hq '{"op":"user","origin":"two.host"}')
	user0=$(hq '{"op":"user","origin":"none.host"}')
	list2=$(hq '{"op":"list","origin":"two.host"}')
	badop=$(hq '{"op":"rm","origin":"two.host"}')
	kill "$apid" 2>/dev/null

	case "$user1" in
	'{"success":true,"username":"solo"}') ;;
	*'"error":"clipboard_failed"'*) ;;
	*) return 1 ;;
	esac
	case "$user2" in *'"error":"ambiguous"'*'"ann"'*) ;; *) return 1 ;; esac
	case "$user2" in *'"b\"q"'*) ;; *) return 1 ;; esac
	[ "$user0" = '{"success":false,"error":"no_entry","usernames":[]}' ] ||
	    return 1
	case "$list2" in '{"success":true,"usernames":['*'"ann"'*) ;;
	*) return 1 ;; esac
	[ "$badop" = '{"success":false,"error":"bad_op"}' ]
}
run host_list_and_user t_host_names

t_host_drop() {
	have_agent || return 77
	have_host  || return 77
	command -v strace >/dev/null 2>&1 || return 77
	unpriv_ids || return 77
	as_unpriv test -x "$AGENT" && as_unpriv test -x "$SAFE" \
	    && as_unpriv test -x "$HOST" || return 77

	hsafe="$TMP/hostsafe"; sock="$TMP/hostd/agent.sock"
	mkdir -p "$hsafe" "$TMP/hostd"
	chmod 0700 "$hsafe" "$TMP/hostd"
	[ "$(id -u)" -ne 0 ] || chown -R "$up_uid:$up_gid" "$hsafe" "$TMP/hostd"

	as_unpriv env SAFE_UNSAFE_MLOCK=1 "$AGENT" -d -f "$sock" -s "$hsafe" \
	    -t 900 >/dev/null 2>"$TMP/hostd/agent.err" &
	apid=$!
	wait_sock "$sock" || {
		[ -n "${VERBOSE:-}" ] && cat "$TMP/hostd/agent.err" >&2
		kill "$apid" 2>/dev/null; return 1; }

	printf 'drop-secret' | as_unpriv env SAFE_UNSAFE_MLOCK=1 SAFE_SOCK="$sock" \
	    "$SAFE" -s "$hsafe" -k -a passwords/test.drop/user1 || {
		kill "$apid" 2>/dev/null; return 1; }
	as_unpriv env SAFE_UNSAFE_MLOCK=1 SAFE_SOCK="$sock" \
	    "$SAFE" -s "$hsafe" -k -r </dev/null || {
		kill "$apid" 2>/dev/null; return 1; }

	msg='{"origin":"test.drop","username":"user1"}'
	fmt=$(nm_fmt "$msg")
	trace=$(mktemp) || { kill "$apid" 2>/dev/null; return 1; }

	printf "$fmt" "$msg" | \
	    timeout 5 strace -f \
	        -e trace=setresuid,setresgid,setuid,setgid,execve \
	        -o "$trace" \
	        $unpriv_prefix env SAFE_UNSAFE_MLOCK=1 SAFE_SOCK="$sock" \
	        "$HOST" >/dev/null 2>&1
	kill "$apid" 2>/dev/null

	if trace_shows_drop "$trace" "$up_uid"; then
		rm -f "$trace"; return 0
	fi
	[ -n "${VERBOSE:-}" ] && cat "$trace" >&2
	rm -f "$trace"
	return 1
}
run host_drop_to_user t_host_drop

t_host_setuid_drop() {
	have_agent || return 77
	have_host  || return 77
	command -v strace >/dev/null 2>&1 || return 77
	# a setuid binary owned by another uid can only be made by root
	[ "$(id -u)" -eq 0 ] || return 77
	unpriv_ids || return 77
	svc_uid=65533; svc_gid=65533
	[ "$up_uid" -ne "$svc_uid" ] || { svc_uid=65532; svc_gid=65532; }
	as_svc() { setpriv --reuid="$svc_uid" --regid="$svc_gid" --clear-groups \
	    env -u XDG_RUNTIME_DIR "$@"; }

	d="$TMP/suid"; mkdir -p "$d/store" "$d/agent"
	chmod 0711 "$d"; chmod 0700 "$d/store" "$d/agent"
	chown "$svc_uid:$svc_gid" "$d/store" "$d/agent"
	cp "$HOST" "$d/safe-fill-host"
	# the service uid may not reach the checkout
	cp "$AGENT" "$d/safe-agent"; cp "$SAFE" "$d/safe"
	chmod 0755 "$d/safe-agent" "$d/safe" "$ASKPASS"
	chown "$svc_uid:$svc_gid" "$d/safe-fill-host"; chmod 6755 "$d/safe-fill-host"

	# skip on nosuid
	cp "$(command -v id)" "$d/id-probe"
	chown "$svc_uid:$svc_gid" "$d/id-probe"; chmod 4755 "$d/id-probe"
	eff=$(setpriv --reuid="$up_uid" --regid="$up_gid" --clear-groups \
	    "$d/id-probe" -u 2>/dev/null)
	[ "$eff" = "$svc_uid" ] || return 77

	sock="$d/agent/agent.sock"
	as_svc env SAFE_UNSAFE_MLOCK=1 "$d/safe-agent" -d -f "$sock" -s "$d/store" \
	    -t 900 >/dev/null 2>"$d/agent.err" &
	apid=$!
	wait_sock "$sock" || {
		[ -n "${VERBOSE:-}" ] && cat "$d/agent.err" >&2
		kill "$apid" 2>/dev/null; return 1; }

	printf 'suid-secret' | as_svc env SAFE_UNSAFE_MLOCK=1 SAFE_SOCK="$sock" \
	    "$d/safe" -s "$d/store" -k -a passwords/test.suid/user1 || {
		kill "$apid" 2>/dev/null; return 1; }
	as_svc env SAFE_UNSAFE_MLOCK=1 SAFE_SOCK="$sock" \
	    "$d/safe" -s "$d/store" -k -r </dev/null || {
		kill "$apid" 2>/dev/null; return 1; }

	msg='{"origin":"test.suid","username":"user1"}'
	fmt=$(nm_fmt "$msg")
	trace=$(mktemp) || { kill "$apid" 2>/dev/null; return 1; }

	# only reachable if setuid gave euid=svc_uid
	printf "$fmt" "$msg" | \
	    timeout 5 strace -f \
	        -e trace=setresuid,setresgid,setuid,setgid,execve \
	        -o "$trace" \
	        setpriv --reuid="$up_uid" --regid="$up_gid" --clear-groups \
	        env SAFE_UNSAFE_MLOCK=1 SAFE_SOCK="$sock" \
	        "$d/safe-fill-host" >/dev/null 2>&1
	kill "$apid" 2>/dev/null

	if trace_shows_drop "$trace" "$up_uid"; then
		rm -f "$trace"; return 0
	fi
	[ -n "${VERBOSE:-}" ] && cat "$trace" >&2
	rm -f "$trace"
	return 1
}
run host_drop_to_user_setuid t_host_setuid_drop

# Same property against a real `make install-hardened` install.
t_hardened_install_host_drop() {
	have_agent && have_socat || return 77
	command -v strace  >/dev/null 2>&1 || return 77
	command -v setpriv >/dev/null 2>&1 || return 77
	command -v doas    >/dev/null 2>&1 || return 77
	[ "$(id -u)" -eq 0 ] || return 77

	hostbin=/usr/local/libexec/safe-fill-host
	[ -x "$hostbin" ] || return 77
	[ -u "$hostbin" ] || return 77
	[ -g "$hostbin" ] || return 77
	[ -x /usr/local/bin/safe ] || return 77
	[ -S /run/safe/browser/agent.sock ] || return 77
	[ -d /var/lib/safe/browser ] || return 77

	real_uid=${SUDO_UID:-${DOAS_UID:-}}
	real_gid=${SUDO_GID:-${DOAS_GID:-}}
	if [ -z "$real_uid" ] || [ -z "$real_gid" ]; then
		return 77
	fi
	if [ "$real_uid" -eq 0 ]; then
		return 77
	fi

	# probe as _safe-browser; I status 1 = key loaded
	n=$(doas -u _safe-browser sh -c \
	    "printf I | socat - UNIX-CONNECT:/run/safe/browser/agent.sock" \
	    2>/dev/null | od -An -tu1 -j1 -N1 | tr -d ' ')
	[ "${n:-0}" -eq 1 ] || return 77

	# doas scrubs the environment, so pass SAFE_SOCK explicitly.
	if ! printf 'drop-secret' | doas -u _safe-browser env \
	        SAFE_SOCK=/run/safe/browser/agent.sock \
	        /usr/local/bin/safe -s /var/lib/safe/browser \
	        -k -f -a passwords/test.drop/user1 >/dev/null 2>&1; then
		return 77
	fi

	msg='{"origin":"test.drop","username":"user1"}'
	msglen=${#msg}
	fmt=$(printf '\\%03o\\%03o\\%03o\\%03o%%s' \
	    $((msglen & 0xff)) $(((msglen >> 8) & 0xff)) \
	    $(((msglen >> 16) & 0xff)) $(((msglen >> 24) & 0xff)))

	# real store: remove the entry whatever happens
	trace=$(mktemp) || {
		rm -f /var/lib/safe/browser/passwords/test.drop/user1
		rmdir /var/lib/safe/browser/passwords/test.drop 2>/dev/null
		return 1
	}

	printf "$fmt" "$msg" | \
	    timeout 5 strace -f \
	        -e trace=setresuid,setresgid,setuid,setgid,execve \
	        -o "$trace" \
	        setpriv --reuid="$real_uid" --regid="$real_gid" \
	                --init-groups \
	                env SAFE_SOCK=/run/safe/browser/agent.sock \
	                "$hostbin" >/dev/null 2>&1
	rm -f /var/lib/safe/browser/passwords/test.drop/user1
	rmdir /var/lib/safe/browser/passwords/test.drop 2>/dev/null

	wl_line=$(grep -n 'execve(.*wl-copy' "$trace" | head -1 | cut -d: -f1)
	if [ -z "$wl_line" ]; then
		rm -f "$trace"
		return 1
	fi
	if ! head -n "$wl_line" "$trace" | \
	     grep -qE "setresuid\\($real_uid,"; then
		rm -f "$trace"
		return 1
	fi
	rm -f "$trace"
	return 0
}
run hardened_install_host_drop t_hardened_install_host_drop

t_agent_rejects_empty_prefix() {
	have_agent || return 77
	! "$AGENT" -d -p "" -t 900 -f "$TMP/ep.sock" >/dev/null 2>&1
}
run agent_rejects_empty_prefix t_agent_rejects_empty_prefix

t_agent_t0_needs_env() {
	have_agent || return 77
	! env -u SAFE_UNSAFE_TIMEOUT "$AGENT" -d -t 0 -f "$TMP/t0e.sock" >/dev/null 2>&1
}
run agent_t0_needs_env t_agent_t0_needs_env

t_agent_no_second_instance() {
	have_agent || return 77
	sock="$TMP/ag2/agent.sock"
	mkdir -p "$TMP/ag2"; chmod 0700 "$TMP/ag2"
	"$AGENT" -d -f "$sock" -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	wait_listen "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	"$AGENT" -d -f "$sock" -t 900 >/dev/null 2>&1 &
	bpid=$!
	sleep 1
	if kill -0 "$bpid" 2>/dev/null; then
		kill "$bpid" "$apid" 2>/dev/null; return 1
	fi
	kill -0 "$apid" 2>/dev/null; rc=$?
	kill "$apid" 2>/dev/null
	return $rc
}
run agent_no_second_instance t_agent_no_second_instance

t_agent_seccomp_active() {
	have_agent || return 77
	[ -r /proc/self/status ] || return 77
	sock="$TMP/agsc/agent.sock"
	mkdir -p "$TMP/agsc"; chmod 0700 "$TMP/agsc"
	"$AGENT" -d -f "$sock" -t 900 >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	i=0; mode=
	while [ "$i" -lt 30 ]; do
		mode=$(awk '/^Seccomp:/ {print $2}' "/proc/$apid/status" 2>/dev/null)
		[ "$mode" = 2 ] && break
		sleep 0.1
		i=$((i+1))
	done
	kill "$apid" 2>/dev/null
	[ -n "$mode" ] || return 77
	[ -n "${DEBUG_BUILD:-}" ] && return 77
	[ "$mode" = 2 ]
}
run agent_seccomp_active t_agent_seccomp_active

t_readpass_sigterm() {
	mkfifo "$TMP/rp.fifo" || return 77
	SAFE_DIR="$TMP/rp" "$SAFE" -b x <"$TMP/rp.fifo" >/dev/null 2>&1 &
	spid=$!
	exec 9>"$TMP/rp.fifo"
	sleep 1
	kill -TERM "$spid" 2>/dev/null
	sleep 1
	if kill -0 "$spid" 2>/dev/null; then
		kill -KILL "$spid" 2>/dev/null; exec 9>&-; return 1
	fi
	exec 9>&-
	return 0
}
run readpass_sigterm t_readpass_sigterm


# --- agent as encrypt/decrypt oracle (the key never leaves the agent) ---

agent_up() {	# agent_up DIR [agent args...]; sets sock apid, exports SAFE_SOCK
	_d="$1"; shift
	sock="$TMP/$_d/agent.sock"
	mkdir -p "$TMP/$_d"; chmod 0700 "$TMP/$_d"
	"$AGENT" -d -f "$sock" -s "$SAFEDIR" -t 900 "$@" >/dev/null 2>&1 &
	apid=$!
	wait_sock "$sock" || { kill "$apid" 2>/dev/null; return 1; }
	export SAFE_SOCK="$sock"
	"$SAFE" -k -r </dev/null || { kill "$apid" 2>/dev/null; return 1; }
}
agent_down() { kill "$apid" 2>/dev/null; unset SAFE_SOCK; }

t_agent_G_removed() {
	have_agent && have_socat || return 77
	agent_up agG || return 1
	n=$(printf 'G' | socat - UNIX-CONNECT:"$sock" 2>/dev/null | wc -c)
	agent_down
	[ "$n" -eq 0 ]
}
run agent_G_removed t_agent_G_removed

t_agent_write_via_E() {
	have_agent && have_socat || return 77
	agent_up agE || return 1
	# multi-chunk, and an exact multiple of the chunk size
	head -c 20000 /dev/urandom > "$TMP/e1.in"
	head -c 16384 /dev/urandom > "$TMP/e2.in"
	"$SAFE" -a e1 < "$TMP/e1.in" || { agent_down; return 1; }
	"$SAFE" -a e2 < "$TMP/e2.in" || { agent_down; return 1; }
	"$SAFE" e1 > "$TMP/e1.out" || { agent_down; return 1; }
	agent_down
	cmp -s "$TMP/e1.in" "$TMP/e1.out" || return 1
	# the entries must also open with the password alone (no agent)
	"$SAFE" -k e1 | cmp -s - "$TMP/e1.in" || return 1
	# two full chunks, then an empty final chunk padded to 256
	[ "$(wc -c < "$SAFEDIR/e2")" -eq "$(entry_size 16384)" ]
}
run agent_write_via_E t_agent_write_via_E

t_agent_I_status() {
	have_agent && have_socat || return 77
	agent_up agE2 || return 1
	mkdir -p "$TMP/other"; chmod 700 "$TMP/other"
	# a different store must not be served by this agent
	printf 'pw\npw\n' | SAFE_DIR="$TMP/other" "$SAFE" -k -a o1 2>/dev/null
	st=$(printf 'I' | socat - UNIX-CONNECT:"$sock" 2>/dev/null | od -An -tu1 -j1 -N1 | tr -d ' ')
	agent_down
	[ "$st" = 1 ]
}
run agent_I_status t_agent_I_status

t_agent_D_tamper_no_output() {
	have_agent && have_socat || return 77
	printf 'tamper-me' | "$SAFE" -k -a tmp1 || return 1
	agent_up agT || return 1
	poke "$SAFEDIR/tmp1" 70 'Z'
	n=$(printf 'D\000\000\000\004tmp1' | socat - UNIX-CONNECT:"$sock" 2>/dev/null | wc -c)
	agent_down
	[ "$n" -eq 0 ]
}
run agent_D_tamper_no_output t_agent_D_tamper_no_output

t_agent_E_prefix() {
	have_agent && have_socat || return 77
	agent_up agEP -p "passwords/" || return 1
	printf 'x' | "$SAFE" -a secrets/nope 2>/dev/null && { agent_down; return 1; }
	[ ! -e "$SAFEDIR/secrets/nope" ]
	rc=$?
	agent_down
	return $rc
}
run agent_E_prefix_enforced t_agent_E_prefix


# --- padding and format 0x12 ---

t_new_entries_are_v12() {
	printf 'x' | "$SAFE" -k -a v12a || return 1
	[ "$(peek "$SAFEDIR/v12a" 7)" -eq 18 ] || return 1
	d="$TMP/v12m"; new_safe "$d" || return 1
	[ "$(peek "$d/master" 7)" -eq 18 ]
}
run new_entries_are_v12 t_new_entries_are_v12

t_padding_hides_length() {
	printf 'a' | "$SAFE" -k -a padlen1 || return 1
	head -c 200 /dev/urandom > "$TMP/p200"
	"$SAFE" -k -a padlen200 < "$TMP/p200" || return 1
	[ "$(wc -c < "$SAFEDIR/padlen1")" -eq "$(entry_size 1)" ] || return 1
	[ "$(wc -c < "$SAFEDIR/padlen200")" -eq "$(entry_size 1)" ] || return 1
	[ "$("$SAFE" -k padlen1)" = a ] || return 1
	"$SAFE" -k padlen200 | cmp -s - "$TMP/p200"
}
run padding_hides_length t_padding_hides_length

# lengths around every bucket and chunk edge, written and read directly
t_padding_boundaries() {
	for n in 0 254 255 256 511 4095 4096 8190 8191 8192 8193 16383 16384 20000; do
		head -c "$n" /dev/urandom > "$TMP/pb.in"
		"$SAFE" -k -a "pb/$n" < "$TMP/pb.in" || return 1
		[ "$(wc -c < "$SAFEDIR/pb/$n")" -eq "$(entry_size "$n")" ] || return 1
		"$SAFE" -k "pb/$n" | cmp -s - "$TMP/pb.in" || return 1
	done
}
run padding_boundaries t_padding_boundaries

# the same through the agent
t_padding_via_agent() {
	have_agent && have_socat || return 77
	agent_up agpad || return 1
	for n in 0 255 256 8191 8192 8193 16384; do
		head -c "$n" /dev/urandom > "$TMP/pa.in"
		"$SAFE" -a "pa/$n" < "$TMP/pa.in" || { agent_down; return 1; }
		"$SAFE" "pa/$n" | cmp -s - "$TMP/pa.in" || { agent_down; return 1; }
		[ "$(wc -c < "$SAFEDIR/pa/$n")" -eq "$(entry_size "$n")" ] ||
		    { agent_down; return 1; }
	done
	agent_down
	"$SAFE" -k pa/8193 >/dev/null
}
run padding_via_agent t_padding_via_agent

# 0x12 authenticates the header
t_header_bound() {
	printf 'hdr' | "$SAFE" -k -a hb1 || return 1
	cp "$SAFEDIR/hb1" "$TMP/hb1.orig"
	poke "$SAFEDIR/hb1" 30 'Z'
	"$SAFE" -k hb1 >/dev/null 2>&1 && return 1
	if have_agent && have_socat; then
		agent_up aghb || return 1
		n=$(printf 'D\000\000\000\003hb1' |
		    socat - UNIX-CONNECT:"$sock" 2>/dev/null | wc -c)
		agent_down
		[ "$n" -eq 0 ] || return 1
	fi
	cp "$TMP/hb1.orig" "$SAFEDIR/hb1"
	[ "$("$SAFE" -k hb1)" = hdr ]
}
run header_bound t_header_bound

# relabelling a 0x12 entry as 0x11 must not yield its padded plaintext
t_version_downgrade_rejected() {
	printf 'down' | "$SAFE" -k -a dg1 || return 1
	poke "$SAFEDIR/dg1" 7 '\021'
	! "$SAFE" -k dg1 >/dev/null 2>&1
}
run version_downgrade_rejected t_version_downgrade_rejected

# a pre-padding store (LEGACY_SAFE=path) stays readable and writable
t_legacy_v11_readable() {
	[ -n "${LEGACY_SAFE:-}" ] && [ -x "$LEGACY_SAFE" ] || return 77
	d="$TMP/legacy"; mkdir -p "$d"; chmod 700 "$d"
	printf 'old-short' | SAFE_DIR="$d" "$LEGACY_SAFE" -k -a old1 || return 1
	head -c 9000 /dev/urandom > "$TMP/old2.in"
	SAFE_DIR="$d" "$LEGACY_SAFE" -k -a old2 < "$TMP/old2.in" || return 1
	[ "$(peek "$d/master" 7)" -eq 17 ] || return 1
	[ "$(SAFE_DIR="$d" "$SAFE" -k old1)" = old-short ] || return 1
	SAFE_DIR="$d" "$SAFE" -k old2 | cmp -s - "$TMP/old2.in" || return 1
	printf 'new' | SAFE_DIR="$d" "$SAFE" -k -a new1 || return 1
	[ "$(peek "$d/new1" 7)" -eq 18 ] || return 1
	[ "$(SAFE_DIR="$d" "$SAFE" -k new1)" = new ] || return 1
	if have_agent; then
		s2="$TMP/aglg/agent.sock"
		mkdir -p "$TMP/aglg"; chmod 0700 "$TMP/aglg"
		"$AGENT" -d -f "$s2" -s "$d" -t 900 >/dev/null 2>&1 &
		lp=$!
		wait_sock "$s2" || { kill "$lp" 2>/dev/null; return 1; }
		SAFE_DIR="$d" SAFE_SOCK="$s2" "$SAFE" -k -r </dev/null ||
		    { kill "$lp" 2>/dev/null; return 1; }
		a=$(SAFE_DIR="$d" SAFE_SOCK="$s2" "$SAFE" old1)
		b=$(SAFE_DIR="$d" SAFE_SOCK="$s2" "$SAFE" new1)
		kill "$lp" 2>/dev/null
		[ "$a" = old-short ] && [ "$b" = new ] || return 1
	fi
	return 0
}
run legacy_v11_readable t_legacy_v11_readable

# --- safe-fill-migrate, logins.json (desktop Firefox) ---

# tests/mkprofile.py builds a real-NSS profile with logins.json
t_migrate_logins_json() {
	have_migrate && have_nss_py && have_agent || return 77
	prof="$TMP/fxprof"
	python3 tests/mkprofile.py "$prof" >/dev/null || return 1
	python3 -c "import sqlite3; c = sqlite3.connect('$prof/logins.db');
c.execute('create table loginsL(id integer primary key, origin text, secFields text, is_deleted integer)');
c.commit()" || return 1
	cp "$prof/logins.json" "$TMP/logins.json.orig"
	case $SAFE in /*) sb=$SAFE ;; *) sb=$PWD/$SAFE ;; esac
	agent_up agmig || return 1

	SAFE_BIN="$sb" "$MIGRATE" -s "$SAFEDIR" "$prof" > "$TMP/mig.out" 2>&1 ||
	    { agent_down; return 1; }
	grep -q '^4 migrated, 0 failed, 4 skipped$' "$TMP/mig.out" ||
	    { agent_down; return 1; }
	[ "$("$SAFE" passwords/discord.com/azulbeae@icloud.com)" = disc-pass-1 ] &&
	[ "$("$SAFE" passwords/accounts.google.com/azulbeae@icloud.com)" = 'goog\pass"2 ünïcode' ] &&
	[ "$("$SAFE" passwords/example.org:8443/bob)" = port-pass ] &&
	[ "$("$SAFE" passwords/example.org/alice | wc -c)" -eq 300 ] ||
	    { agent_down; return 1; }

	# blank mode is gone: -b is refused and changes nothing
	SAFE_BIN="$sb" "$MIGRATE" -b -s "$SAFEDIR" "$prof" >/dev/null 2>&1 &&
	    { agent_down; return 1; }
	agent_down
	# Firefox's store is only ever read
	cmp -s "$prof/logins.json" "$TMP/logins.json.orig"
}
run migrate_logins_json t_migrate_logins_json

# a missing entry is reported as missing, not as a decryption failure
t_agent_missing_entry_message() {
	have_agent || return 77
	agent_up agmiss || return 1
	msg=$("$SAFE" no/such/entry 2>&1 >/dev/null)
	agent_down
	case $msg in *"no such entry"*) return 0 ;; esac
	return 1
}
run agent_missing_entry_message t_agent_missing_entry_message

echo "passed: $PASS  failed: $FAIL  skipped: $SKIP"
[ "$FAIL" -eq 0 ]
