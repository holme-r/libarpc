#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(libarpc, 0.6.3)
AM_INIT_AUTOMAKE(libarpc, 0.6.3)
LT_INIT
AC_CONFIG_SRCDIR([libarpc/stack.c])
AC_CONFIG_HEADER([config.h:config.h.in])
AC_CONFIG_MACRO_DIR([m4])

AC_ARG_ENABLE(gss,[AS_HELP_STRING([--enable-gss], [Turn on gss api])],
	[case "${enableval}" in
	  yes)
		ac_enable_gss=yes
		;;
	  no)
		ac_enable_gss=no
		;;
	  *)
		AC_MSG_ERROR(bad value ${enableval} for --enable-gss)
		;;
	esac],
	[ac_enable_gss=no]
)
AM_CONDITIONAL(GSS, test x$ac_enable_gss = xyes)
if test x$ac_enable_gss = xyes; then
	AC_CHECK_LIB([gssapi],[gss_init_sec_context])
	AC_DEFINE(HAVE_LIBGSSAPI, 1, [])
fi

AC_ARG_WITH(atf,[AS_HELP_STRING([--with-atf], [Use NetBSD ATF])],
	[case "$withval" in
	  yes)
		ac_with_atf=yes
		;;
	  no)
		ac_with_atf=no
		;;
	  *)
		ac_with_atf=yes
		ATF_INCLUDES="-I$withval/include"
		ATF_LDFLAGS="-L$withval/lib"
		;;
	esac],
	[ac_with_atf=yes]
)
AM_CONDITIONAL(ATF, test x$ac_with_atf = xyes)
AC_SUBST(ATF_INCLUDES)
AC_SUBST(ATF_LDFLAGS)

# Checks for programs.
AC_LANG(C)
AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
AC_PROG_RANLIB
AC_PATH_PROG([ATFRUN], [atf-run])
AC_PATH_PROG([ATFREPORT], [atf-report])

CC_FOR_BUILD=${CC_FOR_BUILD:-${CC}}
AC_SUBST(CC_FOR_BUILD)

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lutil':
#AC_CHECK_LIB([util], [main])
AC_CHECK_LIB([wrap], [hosts_access])
AC_CHECK_LIB([event], [event_new])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_TIME
AC_HEADER_STDBOOL
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h sys/stat.h sys/time.h syslog.h unistd.h time.h ifaddrs.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_TYPES([struct ucred], [], [], [[#include <sys/socket.h>]])

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_GETGROUPS
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_FUNC_WAIT3
AC_CHECK_FUNCS([strlcpy strlcat alarm bzero clock_gettime dup2 endgrent gethostbyname gethostname gettimeofday inet_ntoa memmove memset socket strcasecmp strchr strdup strerror strpbrk strrchr strtol uname])

[
#include <sys/types.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
]

# Check for declarations
AC_CHECK_DECLS([clock_gettime, clockid_t])

# Checks for structure variants
AC_CHECK_MEMBERS([struct sockaddr_storage.ss_len,
		  struct sockaddr.sa_len], [], [],
[
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
])

AC_CONFIG_FILES([Makefile 
		 build/Makefile
		 libarpc/Makefile
		 arpcbind/Makefile
		 arpcgen/Makefile
		 arpcinfo/Makefile
		 test/Makefile])
AC_OUTPUT
