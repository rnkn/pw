.POSIX:
SRC		= pw.sh
MAN		= pw.1
BIN		= pw
PREFIX		= /usr/local
MANPREFIX	= ${PREFIX}/man

install:
	@mkdir -p ${PREFIX}/bin
	install -m 755 ${SRC} ${PREFIX}/bin/${BIN}
	@mkdir -p ${MANPREFIX}/man1
	install ${MAN} ${MANPREFIX}/man1
