#!/bin/sh

# ISC License (ISC)

# Copyright (c) 2021, Paul W. Rankin <pwr@bydasein.com>

# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.

# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# This code is a rewrite of pass, copyright (c) 2018-2019 Roman Zolotarev.

program=$(basename "$0")
version=0.4.0
public_key="${PW_PUBLIC_KEY:-${HOME}/.keys/pw.pub}"
private_key="${PW_PRIVATE_KEY:-${HOME}/.keys/pw.sec}"
pw_dir="${PW_DIR:-${HOME}/.pw}"

fail() { echo "$1"; exit 1; }

# init()
# create private key
# create public key
# returns: 0
pkey_init() {
	if getopts h opt; then
		case "$opt" in
			(h)	cat <<EOF; exit 1 ;;
create private key located at:
    $private_key
create public key located at:
    $public_key
EOF
			(?)	exit 1 ;;
		esac
	fi
	[ -f "$private_key" ] && fail "$private_key already exists"
	[ -n "$PW_MASTER" ] && pkey_pass_args="-pass env:PW_MASTER"
	echo "Generating private RSA key: $private_key"
	openssl genpkey -algorithm RSA -aes-256-cbc $pkey_pass_args > "$private_key" ||
		fail "Private key generation failed: $private_key"
	chmod 0400 "$private_key"
	[ -n "$PW_MASTER" ] && pkey_pass_args="-passin env:PW_MASTER"
	echo "Generating public RSA key: $public_key"
	openssl pkey -in "$private_key" $pkey_pass_args -pubout > "$public_key" ||
		fail "Public key generation failed: $public_key"
	chmod 0600 "$public_key"
}

# print_env()
# print relevant environment variables
# returns: 0
print_env() {
	[ -n "$PW_MASTER" ] && unlock="***" || unlock="-"
	format='%-16s%s\n'
	printf "$format" PW_PUBLIC_KEY "$public_key"
	printf "$format" PW_PRIVATE_KEY "$private_key"
	printf "$format" PW_DIR "$pw_dir"
	printf "$format" PW_MASTER "$unlock"
	printf "$format" PW_SIGN "${PW_SIGN:--}"
	printf "$format" PW_VERIFY "${PW_VERIFY:--}"
	printf "$format" PW_CLIP "${PW_CLIP:--}"
}

# generate(length)
# returns: psuedo-random password of length (default 16)
generate() {
	if getopts h opt; then
		case "$opt" in
			(h)	cat <<EOF; exit 1 ;;
generate random password of LENGTH (default 16)
usage: $program gen|generate [LENGTH]
       $program gen|generate -h
EOF
			(?)	exit 1 ;;
		esac
	fi
	len="${1:-16}"
	export LC_ALL=C
	cat /dev/urandom | tr -cd '[:alnum:][:punct:]' | fold -w "$len" | head -n 1
}

# sign(data)
# create signature from data
# returns: 0
sign() {
	if getopts h opt; then
		case "$opt" in
			(h)	cat <<EOF; exit 1 ;;
create signature for ENTRY with private key
usage: $program sign <ENTRY>
       $program sign -h
EOF
			(?)	exit 1 ;;
		esac
	fi
	pw_id="$1"
	pw_tar="${1}.tar"
	pw_sig="${pw_tar}.sig"
	[ -n "$pw_id" ] || fail "Missing argument"
	[ -f "$pw_tar" ] || fail "$pw_id not found"
	[ -n "$PW_MASTER" ] && pkey_pass_args="-passin env:PW_MASTER"
	openssl dgst -sha256 -binary < "$pw_tar" |
		openssl pkeyutl -sign -inkey "$private_key" $pkey_pass_args > "$pw_sig"
	[ $? -eq 0 ] && echo "Created signature: $pw_sig"
}

# verify(pw_id)
# verify PW_ID against signature with public key
# returns: 0
verify() {
	if getopts h opt; then
		case "$opt" in
			(h)	cat <<EOF; exit 1 ;;
verify ENTRY against signature with public key
usage: $program verify <ENTRY>
       $program verify -h
EOF
			(?)	exit 1 ;;
		esac
	fi
	pw_id="$1"
	pw_tar="${1}.tar"
	pw_sig="${pw_tar}.sig"
	[ -n "$pw_id" ] || fail "Missing argument"
	[ -f "$pw_tar" ] || fail "$pw_id not found"
	[ -f "$pw_sig" ] || fail "$pw_id signature not found"
	openssl dgst -sha256 -binary < "$pw_tar" |
		openssl pkeyutl -verify -inkey "$public_key" -pubin -sigfile "$pw_sig" \
				>/dev/null 2>&1 || fail "Verification failure: $pw_id"
	[ $? -eq 0 ] && echo "Verified signature: $pw_sig"
}

# add(pw_id)
# create tar archive of encrypted password and AES key
# create signature of tar archive
# returns: 0
add() {
	sign=0; verify=0; force=0
	while getopts hfsv opt; do
		case "$opt" in
			(h)	cat <<EOF; exit 1 ;;
add ENTRY from stdin or prompt for multiline text
usage: $program add [-fsv] <ENTRY>
       $program add -h
EOF
			(f)	force=1 ;;
			(s)	sign=1 ;;
			(v)	verify=1 ;;
			(?)	exit 1 ;;
		esac
	done
	shift $(( OPTIND - 1 ))
	pw_id="$1"
	pw_key="${pw_id}.key"
	pw_enc="${pw_id}.enc"
	pw_tar="${pw_id}.tar"
	[ -n "$pw_id" ] || fail "Missing argument"
	[ -f "$public_key" ] || fail "Public key not found"
	[ ! -f "$pw_tar" ] || [ "$force" -eq 1 ] ||
		fail "$pw_id already exists; pass -f option to overwrite"
	content=$(cat)
	pw_workdir=$(mktemp -dt pw_work); trap "rm -rf $pw_workdir" EXIT
	key=$(generate 32)
	echo "$key" |
		openssl pkeyutl -encrypt -inkey "$public_key" -pubin \
				> "${pw_workdir}/${pw_key}" ||
		fail "Encryption failed: $pw_key"
	echo "$content" |
		openssl enc -pbkdf2 -aes-256-cbc -pass "pass:${key}" \
				> "${pw_workdir}/${pw_enc}" ||
		fail "Encryption failed: $pw_enc"
	unset key content
	tar -cf "$pw_tar" -C "$pw_workdir" "$pw_enc" "$pw_key"
	rm -rf "$pw_workdir"
	if [ -n "$PW_SIGN" ] || [ "$sign" -eq 1 ]; then
		sign "$pw_id"
	fi
	if [ -n "$PW_VERIFY" ] || [ "$verify" -eq 1 ]; then
		verify "$pw_id"
	fi
	echo "Encryption succeeded: $pw_id"
}

# copy(stdin)
# copies first line to clipboard
# returns: 0
copy() {
	[ -n "$PW_CLIP" ] || fail "PW_CLIP not set"
	sed 1q | tr -d \\n | $PW_CLIP
}

# get_field(stdin)
# returns: field value string
get_field() {
	sed -nE "/^${field}:/ s/.+:[ 	]*(.+)/\1/p"
}

# show(pw_id)
# returns: decrypted file contents
show() {
	copy=0; verify=0; totp=0
	while getopts hcvtk: opt; do
		case "$opt" in
			(h)		cat <<EOF; exit 1 ;;
decrypt and show ENTRY or ENTRY FIELD or ENTRY TOTP
usage: $program show [-cstv] <ENTRY>
       $program show [-csv] -k <FIELD> <ENTRY>
       $program show -h
EOF
			(c)	copy=1 ;;
			(v)	verify=1 ;;
			(k)	field="$OPTARG" ;;
			(t)	field=totp ;;
			(?)	exit 1 ;;
		esac
	done
	shift $(( OPTIND - 1 ))
	pw_id="$1"
	pw_tar="${pw_id}.tar"
	pw_target=$(readlink "$pw_tar")
	if [ -n "$pw_target" ]; then
		pw_id="${pw_target%.tar}"
		pw_tar="$pw_target"
	fi
	[ -f "$private_key" ] || fail "Private key not found"
	[ -n "$pw_id" ] || fail "Missing argument"
	[ -f "$pw_tar" ] || fail "$pw_id not found"
	[ -n "$PW_MASTER" ] && pkey_pass_args="-passin env:PW_MASTER"
	if [ -n "$PW_VERIFY" ] || [ "$verify" -eq 1 ]; then
		pw_sig="${pw_tar}.sig"
		verify "$pw_id"
	fi
	pw_key="${pw_id}.key"
	pw_enc="${pw_id}.enc"
	pw_workdir=$(mktemp -dt pw_work); trap "rm -rf $pw_workdir" EXIT
	tar -xf "$pw_tar" -C "$pw_workdir"
	key=$(openssl pkeyutl -decrypt -inkey "$private_key" $pkey_pass_args \
				  < "${pw_workdir}/${pw_key}" ||
			  fail "Decryption failed: $pw_key")
	return=$(openssl enc -d -pbkdf2 -aes-256-cbc -pass "pass:${key}" \
					 < "${pw_workdir}/${pw_enc}" ||
				 fail "Decryption failed: $pw_enc")
	[ $? -eq 0 ] || fail "$return"
	if [ "$field" = totp ]; then
		[ "$(command -v oathtool)" ] || fail "Command oathtool not found"
		secret=$(echo "$return" | get_field)
		[ -n "$secret" ] || fail "Missing TOTP secret: $pw_id"
		return=$(oathtool --base32 --totp "$secret")
	elif [ -n "$field" ]; then
		return=$(echo "$return" | get_field)
	fi
	if [ "$copy" -eq 1 ]; then
		echo "$return" | copy
	else
		echo "$return"
	fi
	unset key return secret
	rm -rf "$pw_workdir"
}

# list(string)
# returns: list of matching password IDs
list() {
	if getopts h opt; then
		case "$opt" in
			(h)	cat <<EOF; exit 1 ;;
list entries matching QUERY or list all
usage: $program ls|list [QUERY]
       $program ls|list -h
EOF
			(?)	exit 1 ;;
		esac
	fi
	[ -d "$pw_dir" ] || fail "$pw_dir not found"
	find "$pw_dir" -maxdepth 1 -name "*${1}*.tar" | sed 's/.*\///; s/\.tar$//' |
		sort
}

# edit(pw_id)
# returns: 0
edit() {
	if getopts h opt; then
		case "$opt" in
			(h)	cat <<EOF; exit 1 ;;
temporarily decrypt ENTRY and edit in EDITOR
usage: $program edit <ENTRY>
       $program edit -h
EOF
			(?)	exit 1 ;;
		esac
	fi
	pw_id="$1"
	[ -n "$pw_id" ] || fail "Missing argument"
	[ -f "${pw_id}.tar" ] || fail "$pw_id not found"
	workfile=$(mktemp -t pw_work); trap "rm -f $workfile" EXIT
	return=$(show "$pw_id")
	if [ $? -ne 0 ]; then
		fail "$return"
	else
		echo "$return" > "$workfile"
		unset return
		${EDITOR:-vi} "$workfile"
		add -f "$pw_id" < "$workfile"
	fi
	rm "$workfile"
}

# link(pw_id, link)
# create symbolic link between pw_id and link
# return: 0
link() {
	if getopts h opt; then
		case "$opt" in
			(h)	cat <<EOF; exit 1 ;;
create symbolic link for ENTRY
usage: $program ln|link ENTRY LINK
       $program -h
EOF
			(?)	exit 1 ;;
		esac
	fi
	pw_id="$1"; pw_ln="${2}.tar"
	[ -n "$pw_id" ] || fail "Missing argument"
	[ -f "${pw_id}.tar" ] || fail "$pw_id not found"
	readlink "${1}.tar" > /dev/null && fail "$pw_id is already a link"
	ln -si "${pw_id}.tar" "$pw_ln"
}

# pkey_master()
# change private key passphrase
# returns: 0
pkey_master() {
	if getopts h opt; then
		case "$opt" in
			(h)	cat <<EOF; exit 1 ;;
change passphrase for private key located at:
    $private_key
usage: $program master
       $program master -h
EOF
			(?)	exit 1 ;;
		esac
	fi
	[ -f "$private_key" ] || fail "Private key not found"
	workkey=$(mktemp -t pw_work); trap "rm -f $workkey" EXIT
	chmod 0600 "$private_key"
	openssl pkey -in "$private_key" -out "$workkey" -aes256 &&
		mv "$workkey" "$private_key" ||
			fail "Error changing password: $private_key"
	chmod 0400 "$private_key"
}

# main()
# with option, call appropriate function and exit
# with subcommand, call subcommand function
# without subcommand, call show()
# returns: 0
main() {
	cd "$pw_dir" 2>/dev/null || fail "$pw_dir not found or PW_DIR not set"
	while getopts :hEv opt; do
		case "$opt" in
			(h)	cat <<EOF; exit 1 ;;
usage: $program [-E] [-h] [-v]
       $program <COMMAND>
       $program <COMMAND> -h
       commands: init list add show edit sign verify generate master
EOF
			(E)	print_env; exit 1 ;;
			(v)	echo "$program v$version"; exit 1 ;;
			(:)	exit 1 ;;
		esac
	done
	OPTIND=0

	case "$1" in
		(ls|list)		shift; list "$@" ;;
		(add)			shift; add "$@" ;;
		(show)			shift; show "$@" ;;
		(ed|edit)		shift; edit "$@" ;;
		(sign)			shift; sign "$@" ;;
		(verify)		shift; verify "$@" ;;
		(ln|link)		shift; link "$@";;
		(gen|generate)	shift; generate "$@" ;;
		(init)			shift; pkey_init "$@" ;;
		(master)		shift; pkey_master "$@" ;;
		(git)			"$@" ;;
		(*)				show "$@" ;;
	esac
}

main "$@"

# Local Variables:
# tab-width: 4
# End:
