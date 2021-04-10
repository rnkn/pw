pw
==

pw is a fork/rewrite of Roman Zolotarev's POSIX shell [pass utility][1].

I've used a new name to avoid confusion with the more well-known
[pass][2], it's 50% quicker to type, and also because it's my initials.

Installation
------------

	$ git clone git://git.bydasein.com/pw
	$ cd pw
	# make install

or

	$ make PREFIX=$HOME/bin install

Usage
-----

	pw init
	  initialize RSA key pair.
	pw ls|list|find [QUERY]
	  list entries matching QUERY, or all entries without QUERY
	pw add <ENTRY>
	  add ENTRY, prompting for multiline text
	pw show <ENTRY>
	  decrypt and show ENTRY
	pw cp|copy <ENTRY>
	  decrypt and copy first line of ENTRY with $PW_CLIP
	pw edit <ENTRY>
	  temporarily decrypt ENTRY and edit in $EDITOR
	pw get-<FIELD> <ENTRY>
	  decrypt and return value of FIELD from ENTRY
	pw otp <ENTRY>
	  return TOTP for ENTRY (requires oathtool)
	pw generate [LENGTH]
	  generate random password of LENGTH (default 20)
	pw passphrase
	  change private key passphrase

Hints
-----

To avoid needing to enter your private key passphrase with every
invocation of pw, set the `PW_PASSPHRASE` environment variable. For
convenience, add the following aliases to your profile:

	alias pw_unlock="stty -echo; read -r PW_PASSPHRASE; stty echo; export PW_PASSPHRASE"
	alias pw_lock="unset PW_PASSPHRASE"
	alias pw_status='[ -n "$PW_PASSPHRASE" ]; echo $?'

To add a generated password:

	$ pw generate | pw add <ENTRY>

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
	$ for entry in $(pw ls)
	> do
	>	pw show "$entry" | sed 's/@example\.com/@newaddress.com/' | pw add "$entry"
	> done
	$ pw_lock

To rotate your private key:

	$ pw_unlock
	$ mkdir pwtmp
	$ for entry in $(pw ls)
	> do
	>	pw show "$entry" > "pwtmp/${entry}.txt"
	> done
	$ tar -cvf keybackup.tar $HOME/.keys
	$ rm -rf $HOME/.keys
	$ tar -cvf pwbackup.tar $HOME/.pw
	$ rm -rf $HOME/.pw
	$ pw init
	$ pw_unlock
	$ cd pwtmp
	$ for entry in *.txt
	> do
	>	pw add "${entry%.txt}" < "$entry"
	> done
	$ cd
	$ rm -rf pwtmp
	$ pw_lock

[1]: https://www.romanzolotarev.com/pass.html
[2]: https://www.passwordstore.org
