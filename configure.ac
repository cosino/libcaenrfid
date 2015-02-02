# Initial information about the project
AC_PREREQ([2.65])

AC_INIT([libcaenrfid],
	m4_esyscmd([dpkg-parsechangelog --format rfc822 | grep-dctrl -nesVersion -FSource . | tr -d '\n']),
	[info@cosino.io])
AC_CONFIG_SRCDIR([src/caenrfid.c])
AC_CONFIG_HEADERS([configure.h])

AM_INIT_AUTOMAKE([1.9 foreign -Wall -Werror])
AM_SILENT_RULES([yes])

# Global settings
AC_SUBST(EXTRA_CFLAGS, ['-Wall -D_GNU_SOURCE -include configure.h'])

# Checks for programs
AC_PROG_CXX
AM_PROG_AR
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AC_CHECK_FUNCS([atexit])
AC_CHECK_FUNCS([bzero])
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([select])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([strdup])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([syslog.h])

# Checks for libraries
AC_SEARCH_LIBS([dlopen], [dl dld], [],
	[AC_MSG_ERROR([unable to find the dlopen() function])])
AC_SEARCH_LIBS([msgbuff_alloc], [msgbuff], [],
	[AC_MSG_ERROR([unable to find the msgbuff_alloc() function])])
AC_SEARCH_LIBS([avp_add_cmd], [avp], [],
	[AC_MSG_ERROR([unable to find the avp_add_cmd() function])])

# Checks for header files
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics
AC_TYPE_INT32_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions
AC_FUNC_CHOWN
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([atexit bzero gettimeofday memset select socket strdup])

# Init libtool
LT_INIT([dlopen])

# use the C compiler for the following checks
AC_LANG([C])

# distribute additional compiler and linker flags
# --> set these variables instead of CXXFLAGS or LDFLAGS
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([LIBS])

# Add specific compiling options
AC_ARG_ENABLE(debug,
	AS_HELP_STRING([--enable-debug],
		[enable debugging messages (enlarge code size)]))
if test "x$enable_debug" = xyes ; then
	AC_DEFINE([ENABLE_DEBUG], 1, [debugging messages enabled])
fi

# files to generate via autotools (.am or .in source files)
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])

# generate the final Makefile etc.
AC_OUTPUT
