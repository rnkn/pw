#!/bin/sh
#
# ISC License (ISC)
#
# Copyright (c) 2021 Paul W. Rankin <pwr@bydasein.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# This code is a rewrite of pass, copyright (c) 2018-2019 Roman Zolotarev.

program=$(basename "$0")
public_key="${PW_PUBLIC_KEY:-${HOME}/.keys/key.pub}"
private_key="${PW_PRIVATE_KEY:-${HOME}/.keys/key.sec}"
pw_dir="${PW_DIR:-${HOME}/.pw}"

fail() { echo "$1"; exit 1; }

usage() {
	cat <<EOF
usage:
  $program init
    initialize RSA key pair:
      $public_key
      $private_key
  $program config
    print PW_* variables (passphrase hidden)
  $program ls|list|find [QUERY]
    list entries matching QUERY; without QUERY, list all
  $program add <ENTRY>
    add ENTRY, prompting for multiline text
  $program show <ENTRY>
    decrypt and show ENTRY
  $program cp|copy <ENTRY>
    decrypt and send first line of ENTRY to ${PW_CLIP:-\$PW_CLIP}
  $program edit <ENTRY>
    temporarily decrypt ENTRY and edit in ${EDITOR:-\$EDITOR}
  $program get-<FIELD> <ENTRY>
    decrypt ENTRY and return value of FIELD
  $program otp <ENTRY>
    return TOTP for ENTRY (requires oathtool)
  $program generate [LENGTH]
    generate random password of LENGTH (default 16)
  $program sign <ENTRY>
    create signature for ENTRY with private key
  $program verify <ENTRY>
    verify ENTRY against signature with public key
  $program git <ARGUMENTS>
    call git and pass ARGUMENTS verbatim
  $program passphrase
    change private key passphrase
EOF
}

# init()
# create private key
# create public key
# returns: 0
pkey_init() {
	[ -f "$private_key" ] && fail "$private_key already exists"
	[ -n "$PW_PASSPHRASE" ] && pkey_pass_args="-pass env:PW_PASSPHRASE"
	echo "Generating private RSA key: $private_key"
	openssl genpkey -algorithm RSA -aes-256-cbc $pkey_pass_args > "$private_key" ||
		fail "Private key generation failed: $private_key"
	chmod 0400 "$private_key"
	[ -n "$PW_PASSPHRASE" ] && pkey_pass_args="-passin env:PW_PASSPHRASE"
	echo "Generating public RSA key: $public_key"
	openssl pkey -in "$private_key" $pkey_pass_args -pubout > "$public_key" ||
		fail "Public key generation failed: $public_key"
	chmod 0600 "$public_key"
}

config() {
	[ -n "$PW_PASSPHRASE" ] && pass="***" || pass="-"
	[ -n "$PW_SIGN" ] || PW_SIGN="-"
	[ -n "$PW_VERIFY" ] || PW_VERIFY="-"
	[ -n "$PW_CLIP" ] || PW_CLIP="-"
	config=$(cat <<EOF
PW_PUBLIC_KEY:${PW_PUBLIC_KEY:-${HOME}/.keys/key.pub}
PW_PRIVATE_KEY:${PW_PRIVATE_KEY:-${HOME}/.keys/key.sec}
PW_DIR:${PW_DIR:-${HOME}/.pw}
PW_PASSPHRASE:$pass
PW_SIGN:$PW_SIGN
PW_VERIFY:$PW_VERIFY
PW_CLIP:$PW_CLIP
EOF
)
	echo "$config" | column -ts:
}

# generate(length)
# returns: random password of length (default 16)
generate() {
	len="${1:-16}"
	jot -rc "$len" 33 126 | rs -g0 1
}

# sign(data)
# create signature from data
# returns: 0
sign() {
	pw_id="$1"
	pw_tar="${1}.tar"
	pw_sig="${pw_tar}.sig"
	[ -n "$pw_id" ] || fail "Missing argument"
	[ -f "$pw_tar" ] || fail "$pw_id not found"
	[ -n "$PW_PASSPHRASE" ] && pkey_pass_args="-passin env:PW_PASSPHRASE"
	openssl dgst -sha256 -binary < "$pw_tar" |
		openssl pkeyutl -sign -inkey "$private_key" $pkey_pass_args > "$pw_sig"
}

# verify(data, pw_sig)
# returns: 0
verify() {
	pw_id="$1"
	pw_tar="${1}.tar"
	pw_sig="${pw_tar}.sig"
	[ -n "$pw_id" ] || fail "Missing argument"
	[ -f "$pw_tar" ] || fail "$pw_id not found"
	[ -f "$pw_sig" ] || fail "$pw_id signature not found"
	openssl dgst -sha256 -binary < "$pw_tar" |
		openssl pkeyutl -verify -inkey "$public_key" -pubin -sigfile "$pw_sig" >/dev/null 2>&1 ||
		fail "Verification failure: $pw_id"
}

# encrypt(pw_id)
# create tar archive of encrypted password and AES key
# create signature of tar archive
# returns: 0
encrypt() {
	pw_id="$1"
	pw_key="${pw_id}.key"
	pw_enc="${pw_id}.enc"
	pw_tar="${pw_id}.tar"
	[ -n "$pw_id" ] || fail "Missing argument"
	[ -f "$public_key" ] || fail "Public key not found"
	content=$(cat)
	pw_workdir=$(mktemp -dt pw_work); trap "rm -rf $pw_workdir" EXIT
	key=$(openssl rand -hex 16)
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
	[ -n "$PW_SIGN" ] && sign "$pw_id"
	echo "Encryption succeeded: $pw_id"
}

# decrypt(pw_id)
# returns: decrypted file contents
decrypt() {
	pw_id="$1"
	pw_tar="${pw_id}.tar"
	[ -f "$private_key" ] || fail "Private key not found"
	[ -n "$pw_id" ] || fail "Missing argument"
	[ -f "$pw_tar" ] || fail "$pw_id not found"
	[ -n "$PW_PASSPHRASE" ] && pkey_pass_args="-passin env:PW_PASSPHRASE"
	if [ -n "$PW_VERIFY" ]; then
		pw_sig="${pw_tar}.sig"
		[ -f "$pw_sig" ] || fail "$pw_id signature not found"
		verify "$pw_id"
	fi
	pw_key="${pw_id}.key"
	pw_enc="${pw_id}.enc"
	pw_workdir=$(mktemp -dt pw_work); trap "rm -rf $pw_workdir" EXIT
	tar -xf "$pw_tar" -C "$pw_workdir"
	key=$(openssl pkeyutl -decrypt -inkey "$private_key" $pkey_pass_args \
				  < "${pw_workdir}/${pw_key}" ||
			  fail "Decryption failed: $pw_key")
	openssl enc -d -pbkdf2 -aes-256-cbc -pass "pass:${key}" \
			< "${pw_workdir}/${pw_enc}" ||
		fail "Decryption failed: $pw_enc"
	unset key
	rm -rf "$pw_workdir"
}

# list(string)
# returns: list of matching password IDs
list() {
	[ -d "$pw_dir" ] || fail "$pw_dir not found"
	find "$pw_dir" -type f -maxdepth 1 -name "*${1}*.tar" | sed 's/.*\///; s/\.tar$//' | sort
}

# copy(pw_id)
# copies first line to clipboard
# returns: 0
copy() {
	pw_id="$1"
	[ -n "$PW_CLIP" ] || fail "\$PW_CLIP not set"
	return=$(decrypt "$pw_id")
	if [ $? -ne 0 ]; then
		fail "$return"
	else
		echo "$return" | sed 1q | tr -d \\n | "$PW_CLIP"
		unset return
	fi
}

# get_field(get-FIELD, pw_id)
# returns: field value string
get_field() {
	field=$(echo "$1" | cut -d- -f2)
	pw_id="$2"
	return=$(decrypt "$pw_id")
	if [ $? -ne 0 ]; then
		fail "$return"
	else
		echo "$return" | grep "^${field}:" | sed -E 's/.+:[ 	]*(.+)/\1/'
		unset return
	fi
}

# totp(pw_id)
# returns: TOTP
totp() {
	pw_id="$1"
	[ -n "$pw_id" ] || fail "Missing argument"
	[ "$(command -v oathtool)" ] || fail "Command oathtool not found"
	[ -f "${pw_id}.tar" ] || fail "$pw_id not found"
	secret=$(get_field "get-totp" "$pw_id")
	[ -n "$secret" ] || fail "Missing TOTP secret: $pw_id"
	oathtool --base32 --totp "$secret"
	unset secret
}

# edit(pw_id)
# returns: 0
edit() {
	pw_id="$1"
	[ -n "$pw_id" ] || fail "Missing argument"
	[ -f "${pw_id}.tar" ] || fail "$pw_id not found"
	workfile=$(mktemp -t pw_work); trap "rm -f $workfile" EXIT
	return=$(decrypt "$pw_id")
	if [ $? -ne 0 ]; then
		fail "$return"
	else
		echo "$return" > "$workfile"
		unset return
		${EDITOR:-vi} "$workfile"
		encrypt "$pw_id" < "$workfile"
	fi
	rm "$workfile"
}

# pkey_passphrase()
# returns: 0
pkey_passphrase() {
	[ -f "$private_key" ] || fail "Private key not found"
	workkey=$(mktemp -t pw_work); trap "rm -f $workkey" EXIT
	chmod 0600 "$private_key"
	openssl pkey -in "$private_key" -out "$workkey" -aes256 &&
		mv "$workkey" "$private_key" ||
			fail "Error changing passphrase: $private_key"
	chmod 0400 "$private_key"
}

main() {
	cd "$pw_dir" 2>/dev/null || fail "$pw_dir not found or \$PW_DIR not set"
	case "$1" in
		(ls|list|find)	shift; list "$@" ;;
		(add)			shift; encrypt "$@" ;;
		(show)			shift; decrypt "$@" ;;
		(cp|copy)		shift; copy "$@" ;;
		(edit)			shift; edit "$@" ;;
		(otp)			shift; totp "$@" ;;
		(sign)			shift; sign "$@" ;;
		(verify)		shift; verify "$@" ;;
		(generate)		shift; generate "$@" ;;
		(get-*)			get_field "$@" ;;
		(git)			"$@" ;;
		(init)			pkey_init ;;
		(passphrase)	pkey_passphrase ;;
		(config)		config ;;
		(*)				usage ;;
	esac
}

main "$@"
