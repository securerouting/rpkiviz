AC_INIT(rpkiviz, 1.0, melkins@tislabs.com)

AC_ARG_WITH([openssl],
	    [AC_HELP_STRING([--with-openssl],[use bundled OpenSSL rather than system libraries], [])],
	    [],
	    with_openssl=no)

need_openssl=yes
if test $with_openssl =  no; then
    AC_CHECK_LIB([crypto], [v3_addr_validate_path],[need_openssl=no])
    AC_MSG_CHECKING([if we need to build OpenSSL])
    AC_MSG_RESULT([$need_openssl])
fi

if test $need_openssl = yes; then
	EXTRA_TARGETS="openssl/libcrypto.a"
	AC_SUBST(EXTRA_TARGETS)
	EXTRA_LINK_ARGS="../openssl/libcrypto.a"
	INCLUDE_DIRS="../openssl/include"
	LIBS="../openssl/libcrypto.a"
	CFLAGS="-I../openssl/include"
else
	LIBRARIES="crypto"
	LIBS="-lcrypto"
fi
AC_SUBST(EXTRA_LINK_ARGS)
AC_SUBST(INCLUDE_DIRS)
AC_SUBST(LIBRARIES)

AC_CONFIG_FILES([Makefile rcynic/Makefile ext/autoconf.py])

AC_OUTPUT
