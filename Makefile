.POSIX:
SRC		= pw.sh
MAN		= pw.1
BIN		= pw
PREFIX		= /usr/local
MANPREFIX	= ${PREFIX}/man

install:
	@mkdir -p ${PREFIX}/bin
	install -m 755 ${SRC} ${PREFIX}/bin/${BIN}
	install ${MAN} ${MANPREFIX}/man1
