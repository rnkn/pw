pw
==

To add a generated password:

	$ pw generate | pw add <ENTRY>

To batch edit all entries, e.g. to change an email:

	$ pw_unlock
	$ for i in $(pw ls)
	> do
	>	pw show "$i" | sed 's/@example\.com/@newaddress.com/' | pw add "$i"
	> done
	$ pw_lock

To rotate your private key:

	$ pw_unlock
	$ mkdir pwtmp
	$ for i in $(pw ls)
	> do
	>	pw show "$i" > "pwtmp/${i}.txt"
	> done
	$ tar -cvf keybackup.tar $HOME/.keys
	$ rm -rf $HOME/.keys
	$ tar -cvf pwbackup.tar $HOME/.pw
	$ rm -rf $HOME/.pw
	$ pw init
	$ pw_unlock
	$ cd pwtmp
	$ for i in *.txt
	> do
	>	cat "$i" | pw add "${i%.txt}"
	> done
	$ cd
	$ rm -rf pwtmp
	$ pw_lock

To avoid needing to enter your private key passphrase with every
invocation of pw, add the following aliases to your profile:

	alias pw_unlock="stty -echo; read -r PW_PASSPHRASE; stty echo; export PW_PASSPHRASE"
	alias pw_lock="unset PW_PASSPHRASE"
	alias pw_status='[ -n "$PW_PASSPHRASE" ]; echo $?'
