.POSIX:
SRC			= pw.sh
BIN			= pw
PREFIX		= /usr/local

install:
	install -m 755 ${SRC} ${PREFIX}/bin/${BIN}
