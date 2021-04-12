pw
==

pw is a rewrite of Roman Zolotarev's POSIX shell password manager [pass][1].

I've used a new name to avoid confusion with the more well-known
[pass][2], it's 50% quicker to type, and also because it's my initials.

Installation
------------

	$ git clone git://git.bydasein.com/pw
	$ cd pw
	# make install

or

	$ make PREFIX=$HOME/bin install

n.b. While you are free to use this code, I encourage you to do what I did and
write your password manager from scratch, which will give you a thorough
understanding of how your password data is managed.

Usage
-----

	pw init
	  initialize RSA key pair
	pw config
	  print PW_* variables (passphrase hidden)
	pw ls|list|find [QUERY]
	  list entries matching QUERY; without QUERY, list all
	pw add <ENTRY>
	  add ENTRY, prompting for multiline text
	pw show <ENTRY>
	  decrypt and show ENTRY
	pw cp|copy <ENTRY>
	  decrypt and send first line of ENTRY to $PW_CLIP
	pw edit <ENTRY>
	  temporarily decrypt ENTRY and edit in $EDITOR
	pw get-<FIELD> <ENTRY>
	  decrypt ENTRY and return value of FIELD
	pw otp <ENTRY>
	  return TOTP for ENTRY (requires oathtool)
	pw generate [LENGTH]
	  generate random password of LENGTH (default 20)
	pw sign <ENTRY>
	  create signature for ENTRY with private key
	pw verify <ENTRY>
	  verify ENTRY against signature with public key
	pw git <ARGUMENTS>
	  call git and pass ARGUMENTS verbatim
	pw passphrase
	  change private key passphrase


Hints
-----

To avoid needing to enter your private key passphrase with every invocation of
pw, set the `PW_PASSPHRASE` environment variable. For convenience, add the
following aliases to your profile:

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
	$ pw ls | while read -r entry
	> do
	>	pw show "$entry" | sed 's/@example\.com/@newaddress.com/' | pw add "$entry"
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
	>		PW_DIR=$HOME/.pw_new
	>		pw add "$entry"
	> done
	$ mv $HOME/.keys/newkey.sec $HOME/.keys/key.sec
	$ mv $HOME/.keys/newkey.pub $HOME/.keys/key.pub
	$ rm -rf $HOME/.pw
	$ mv $HOME/.pw_new $HOME/.pw

[1]: https://www.romanzolotarev.com/pass.html
[2]: https://www.passwordstore.org
