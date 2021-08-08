.POSIX:
SRC		= pw.sh
BIN		= pw
PREFIX		= /usr/local

install:
	@mkdir -p ${PREFIX}/bin
	install -m 755 ${SRC} ${PREFIX}/bin/${BIN}
