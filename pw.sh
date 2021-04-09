#!/bin/sh
#
# ISC License (ISC)
#
# Copyright 2018-2019 Roman Zolotarev <hi@romanzolotarev.com>
# Copyright 2021 Paul W. Rankin <pwr@bydasein.com>
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

program=$(basename "$0")
public_key="${PW_PUBLIC_KEY:-${HOME}/.keys/public.key}"
private_key="${PW_PRIVATE_KEY:-${HOME}/.keys/private.key}"
pw_dir="${PW_DIR:-${HOME}/.pw}"

fail() { echo "$1"; exit 1; }

usage() {
	cat <<EOF
usage:
  $program init
    initialize RSA key pair:
      $public_key
      $private_key
  $program ls|find [QUERY]
    list entries matching QUERY, or all entries without QUERY
  $program add <ENTRY>
    add ENTRY, prompting for multiline text
  $program show <ENTRY>
    decrypt ENTRY
  $program head <ENTRY>
    decrypt ENTRY, returning only first line
  $program copy <ENTRY>
    decrypt and copy first line of ENTRY with ${PW_CLIP:-\$PW_CLIP}
  $program get-<FIELD> <ENTRY>
    decrypt and return value of FIELD from ENTRY
  $program otp <ENTRY>
    return TOTP for ENTRY (requires oathtool)
  $program generate [LENGTH]
    generate random password of LENGTH (default 20)
  $program passphrase
    change private key passphrase
EOF
}

# init()
# create private key
# create public key
# returns: 0
pkey_init() {
	[ -e "$private_key" ] && fail "Abort: $private_key already exists"
	echo "Generating private RSA key: $private_key"
	openssl genpkey -algorithm RSA -aes-256-cbc > "$private_key" ||
		fail "Private key generation failed: $private_key"
	chmod 0400 "$private_key"
	echo "Generating public RSA key: $public_key"
	openssl pkey -in "$private_key" "$pkey_pass_args" -pubout > "$public_key" ||
		fail "Public key generation failed: $public_key"
	chmod 0600 "$public_key"
	return 0
}

# generate(length)
# returns: random password of length (default 20)
generate() {
	len="${1:-20}"
	jot -rc "$len" 33 123 | rs -g0 1
}

# sign(data)
# create signature from data
# returns: 0
sign() {
	[ -n "$PW_PASSPHRASE" ] && pkey_pass_args="-passin env:PW_PASSPHRASE"
	data="$1"
	sig="${data}.sig"
	openssl dgst -sha256 -binary < "$data" |
		openssl pkeyutl -sign -inkey "$private_key" $pkey_pass_args > "$sig"
}

# verify(data, pw_sig)
# returns: 0
verify() {
	data="$1"
	sig="${data}.sig"
	[ -e "$sig" ] || fail "Signature not found: $sig"
	openssl dgst -sha256 -binary < "$data" |
		openssl pkeyutl -verify -inkey "$public_key" -pubin -sigfile "$sig" >/dev/null 2>&1 ||
		fail "Verification failure: $data"
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
	content=$(cat)
	pw_workdir=$(mktemp -dt pw_work); trap "rm -rf $pw_workdir" EXIT
	key=$(openssl rand -hex 16)
	echo "$key" |
		openssl pkeyutl -encrypt -inkey "$public_key" -pubin |
		openssl base64 > "${pw_workdir}/${pw_key}" ||
		fail "Encryption failed: $pw_key"
	echo "$content" |
		openssl enc -pbkdf2 -aes-256-cbc -base64 -pass "pass:${key}" > "${pw_workdir}/${pw_enc}" ||
		fail "Encryption failed: $pw_enc"
	tar -cf "$pw_tar" -C "$pw_workdir" "$pw_enc" "$pw_key"
	rm -rf "$pw_workdir"
	sign "$pw_tar"
	unset key content
	echo "Entry added: $pw_id"
}

# decrypt(pw_id)
# returns: decrypted file contents
decrypt() {
	pw_id="$1"
	pw_tar="${pw_id}.tar"
	pw_sig="${pw_id}.sig"
	pw_key="${pw_id}.key"
	pw_enc="${pw_id}.enc"
	[ -e "$pw_tar" ] || fail "Entry not found: $pw_id"
	verify "$pw_tar" "$pw_sig"
	pw_workdir=$(mktemp -dt pw_work); trap "rm -rf $pw_workdir" EXIT
	tar -xf "$pw_tar" -C "$pw_workdir"
	[ -n "$PW_PASSPHRASE" ] && pkey_pass_args="-passin env:PW_PASSPHRASE"
	key=$(openssl base64 -d < "${pw_workdir}/${pw_key}" |
			  openssl pkeyutl -decrypt -inkey "$private_key" $pkey_pass_args 2>/dev/null ||
			  fail "Decryption failed: $pw_key")
	openssl enc -d -pbkdf2 -aes-256-cbc -base64 -pass "pass:${key}" < "${pw_workdir}/${pw_enc}"
	rm -rf "$pw_workdir"
	unset key
}

# list(string)
# returns: list of matching password IDs
list() {
	find "$pw_dir" -type f -name "*${1}*.tar" | sed 's/.*\///; s/\.tar$//' | sort
}

# get_field(get-FIELD, pw_id)
# returns: field value string
get_field() {
	field=$(echo "$1" | cut -d- -f2)
	pw_id="$2"
	decrypt "$pw_id" | grep "^${field}:" | sed -E 's/.+:[ 	]*(.+)/\1/'
}

# otp(pw_id)
# returns: TOTP
otp() {
	[ $(command -v oathtool) ] || fail "Command not found: oathtool"
	pw_id="$1"
	[ -e "${pw_id}.tar" ] || fail "Entry not found: $pw_id"
	secret=$(get_field "get-totp" "$pw_id")
	[ -n "$secret" ] || exit
	oathtool --base32 --totp "$secret"
	unset secret
}

# pkey_passphrase()
# returns: 0
pkey_passphrase() {
	key_tmp=$(mktemp)
	chmod 600 "$private_key"
	openssl pkey -in "$private_key" -out "$key_tmp" -aes256 &&
		mv "$key_tmp" "$private_key" ||
			fail "Error changing passphrase for $private_key"
	chmod 400 "$private_key"
}

main() {
	cd "$pw_dir" || fail "\$PW_DIR not set"
	case "$1" in
		(init)			pkey_init ;;
		(ls|find)		list "$2" ;;
		(add)			encrypt "$2" ;;
		(show)			decrypt "$2" ;;
		(head)			decrypt "$2" | sed 1q ;;
		(copy)			[ -n "$PW_CLIP" ] || fail "\$PW_CLIP not set"
						decrypt "$2" | sed 1q | tr -d \\n | "$PW_CLIP" ;;
		(get-*)			get_field "$1" "$2" ;;
		(otp)			otp "$2" ;;
		(generate)		generate "$2" ;;
		(passphrase)	pkey_passphrase ;;
		(*)				usage ;;
	esac
}

main "$@"