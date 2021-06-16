pw - POSIX shell password manager
=================================

pw is a rewrite of Roman Zolotarev's POSIX shell password manager [pass][1].

I've used a new name to avoid confusion with the more well-known
[pass][2], it's 50% quicker to type, and also because it's my initials.


Requirements
------------

- [`openssl`][3] handles all encryption processes
- [`urandom`][4] is required for generating random passwords
- [`oathtool`][5] is required for generating TOTPs


Installation
------------

The first step is to read and understand the source. I encourage you not to
encrypt your password data using a program you do not understand. (As a
fail-safe, pw requires its default directories to be manually created.)

After that:

	$ git clone git://git.bydasein.com/pw.git
	$ cd pw
	# make install

or

	$ make PREFIX=$HOME/bin install


Usage
-----

	pw [COMMAND] [ENTRY]
	pw -h

Commands:

	init
	  initialize RSA key pair
	ls|list [QUERY]
	  list entries matching QUERY; without QUERY, list all
	add <ENTRY>
	  add ENTRY, prompting for multiline text
	show <ENTRY>
	  decrypt and show ENTRY
	ed|edit <ENTRY>
	  temporarily decrypt ENTRY and edit in $EDITOR
	gen|generate [LENGTH]
	  generate random password of LENGTH (default 16)
	sign <ENTRY>
	  create signature for ENTRY with private key
	verify <ENTRY>
	  verify ENTRY against signature with public key
	git <ARGUMENTS>
	  call git and pass ARGUMENTS verbatim
	master
	  change private key password

Use the `-h` option after each command for usage.

Some configuration via environment variables:

	PW_PUBLIC_KEY	location of public key
	PW_PRIVATE_KEY	location of private key
	PW_DIR			location of password directory
	PW_MASTER		private key password (see below)
	PW_SIGN			when set, sign password tarballs
	PW_VERIFY		when set, verify password tarballs
	PW_CLIP			clipboard program name

To avoid needing to enter your private key password with every invocation of
pw, set the `PW_MASTER` environment variable to your private key password.
For convenience, add the following aliases to your profile:

	alias pw_unlock="stty -echo; read -r PW_MASTER; stty echo; export PW_MASTER"
	alias pw_lock="unset PW_MASTER"


How it works
------------

pw uses hybrid encryption, which combines the strengths of RSA asymmetric
encryption with AES symmetric encryption.

For example, adding a password for `example.com` generates an encryption key and
the password content is then encrypted with this key using AES-256-CBC
encryption, as `example.com.enc`. The key is then encrypted using your RSA
public key as `example.com.key` and the original key discarded. Both
`example.com.enc` and `example.com.key` are added to a tarball
`example.com.tar`, and an optional signed hash `example.com.tar.sig` is
generated using your RSA private key.

This is the resulting hierarchy:

	.PW_DIR/
	├── example.com.tar
	│   ├── example.com.enc
	│   └── example.com.key
	└── example.com.tar.sig


Bugs
----

Please email patches to the address in the source.


Hints
-----

To add a generated password:

	$ pw generate | pw add example.com

To generate a new password for an existing entry in-place:

	$ pw show example.com | awk -v pw=$(pw generate) '$0 = NR == 1 ? pw : $0' | pw add -f example.com

Set git to perform binary diffs:

	$ cd .pw
	$ cat > .gitattributes
	> *.tar diff=
	> *.tar.sig diff=

To import from `password-store`:

	$ pw_unlock
	$ cd $HOME/.password-store
	$ for file in *.gpg
	> do
	>	entry="${file%.gpg}"
	>	pass "$entry" | sed -E 's/^otpauth:.*secret=([A-Za-z2-7]+).*/totp: \1/' | pw add "$entry"
	> done

To batch edit all entries, e.g. to change an email:

	$ pw_unlock
	$ pw ls | while read -r entry
	> do
	>	pw show "$entry" | sed 's/@example\.com/@newaddress.com/' | pw add -f "$entry"
	> done

To rotate your private key:

	$ tar -cvf keybackup.tar $HOME/.keys
	$ PW_PRIVATE_KEY=$HOME/.keys/newkey.sec \
	> PW_PUBLIC_KEY=$HOME/.keys/newkey.pub \
	> pw init
	$ mkdir $HOME/.pw_new
	$ pw_unlock
	$ pw ls | while read -r entry
	> do
	>	pw show "$entry" |
	>		PW_PUBLIC_KEY=$HOME/.keys/newkey.pub \
	>		PW_DIR=$HOME/.pw_new \
	>		pw add "$entry"
	> done
	$ mv $HOME/.keys/{newkey,key}.sec
	$ mv $HOME/.keys/{newkey,key}.pub
	$ rm -rf $HOME/.pw
	$ mv $HOME/.pw_new $HOME/.pw


[1]: https://www.romanzolotarev.com/pass.html
[2]: https://www.passwordstore.org
[3]: https://man.openbsd.org/openssl
[4]: https://man.openbsd.org/urandom
[5]: https://www.nongnu.org/oath-toolkit/
