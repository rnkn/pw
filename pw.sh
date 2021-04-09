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
    initialize public/private RSA key pair:
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
init() {
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
# returns: sha256 binary digest
sign() {
	[ -n "$PW_PASSWORD" ] && pkey_pass_args="-passin env:PW_PASSWORD"
	data="$1"
	openssl dgst -sha256 -binary < "$data" |
		openssl pkeyutl -sign -inkey "$private_key" $pkey_pass_args
}

# verify(data, pw_sig)
# returns: 0
verify() {
	data="$1"
	sig="$2"
	[ -f "$sig" ] || fail "Signature not found: $sig"
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
	pw_sig="${pw_id}.sig"
	pw_workdir="${pw_id}.work"
	content=$(cat)
	mkdir -p "$pw_workdir"
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
	sign "$pw_tar" > "$pw_sig"
	unset key content
	echo "Password added: $pw_id"
	# verify "$pw_tar" "$pw_sig"
}

# decrypt(pw_id)
# returns: decrypted file contents
decrypt() {
	pw_id="$1"
	pw_tar="${pw_id}.tar"
	pw_sig="${pw_id}.sig"
	pw_key="${pw_id}.key"
	pw_enc="${pw_id}.enc"
	pw_workdir="${pw_id}.work"
	[ -f "$pw_tar" ] || fail "Password not found: $pw_id"
	verify "$pw_tar" "$pw_sig"
	mkdir -p "$pw_workdir"
	tar -xf "$pw_tar" -C "$pw_workdir"
	[ -n "$PW_PASSWORD" ] && pkey_pass_args="-passin env:PW_PASSWORD"
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

# passphrase()
pw_change() {
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
		(init)
			init ;;
		(ls|find)
			list "$2" ;;
		(show)
			decrypt "$2" ;;
		(head)
			decrypt "$2" | sed -n 1p ;;
		(generate)
			generate "$2" ;;
		(add)
			encrypt "$2" ;;
		(passphrase)
			pw_change ;;
		(*)
			pw_usage ;;
	esac
}

main "$@"
