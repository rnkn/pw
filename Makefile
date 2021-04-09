.POSIX:
SRC			= pw.sh
BIN			= pw
PREFIX		= /usr/local
HINT		= \
"To avoid needing to enter your private key passphrase with every \
invocation of ${BIN}, add the following aliases to your profile:"

install:
	install -m755 ${SRC} ${PREFIX}/bin/${BIN}

hint:
	@echo ${HINT} | fold -sw66
	@echo
	@echo 'alias pw_unlock="stty -echo; read -r PW_PASSPHRASE; stty echo; export PW_PASSPHRASE"'
	@echo 'alias pw_lock="unset PW_PASSPHRASE"'
	@echo "alias pw_status='[ -n \"\$$PW_PASSPHRASE\" ]; echo \$$?'"
	@echo
