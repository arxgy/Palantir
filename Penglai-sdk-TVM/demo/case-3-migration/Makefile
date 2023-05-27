all:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-migratee
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-migrator
clean:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-migratee clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  case-migrator clean