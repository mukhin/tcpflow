AC_INIT(/src/tcpflow.h)
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE(tcpflow, 0.21)
AM_CONFIG_HEADER(src/conf.h)


dnl ############# System Dependencies

AC_MSG_CHECKING([for special system dependencies])

case "$target_os" in

linux*)
	dnl libpcap's DLT_NULL seems to be broken under Linux.
	AC_DEFINE(DLT_NULL_BROKEN)
	AC_MSG_RESULT([Linux])
	;;

*)
	AC_MSG_RESULT([none])
	;;
esac


dnl ############# Compiler Check

AC_PROG_CC
AC_GCC_FLAGS

AC_ARG_WITH(pcap,
[  --with-pcap=PATH        Specify path to pcap library.],
    [
	AC_MSG_CHECKING(for --with-pcap option)
	case "$withval" in
	  yes|no)
	    AC_MSG_ERROR(PATH required with pcap option)
	    ;;
	  *)
	    if test '!' -d "$withval"; then
		AC_MSG_ERROR($withval does not exist!)
	    else
		AC_MSG_RESULT($withval)
		if test -d "$withval/include"; then
		  CFLAGS="$CFLAGS -I$withval/include -I../$withval/include"
		  CPPFLAGS="$CPPFLAGS -I$withval/include -I../$withval/include"
		else
		  CFLAGS="$CFLAGS -I$withval -I../$withval"
		  CPPFLAGS="$CPPFLAGS -I$withval -I../$withval"
		fi
	        if test -d "$withval/lib"; then
		  LIBS="$LIBS -L$withval/lib -L../$withval/lib"
		else
		  LIBS="$LIBS -L$withval -L../$withval"
		fi
	    fi
	    ;;
	  esac
    ]
)
	
dnl ############## Library Checks

dnl Checks for libraries.  We check for the library only if the function is
dnl not available without the library.
AC_CHECK_FUNC(gethostbyaddr, , [AC_CHECK_LIB(nsl, gethostbyaddr)])
AC_CHECK_FUNC(socket, , [AC_CHECK_LIB(socket, socket)])

dnl Note, the check for -lsocket and -lnsl must go before -lpcap;
dnl -lpcap uses those libraries.

AC_CHECK_LIB(pcap, pcap_lookupdev, , [
	AC_MSG_ERROR([
Can't find the pcap library (libpcap.a); install the pcap library (from
ftp://ftp.ee.lbl.gov/libpcap.tar.Z ) and/or use
--with-pcap to specify the path to it on your system

When installing libpcap do both 'make install' and 'make install-incl'])
])

dnl ############## Header Checks

AC_CHECK_HEADER(pcap.h, , [
	AC_MSG_ERROR([
Can't find pcap.h; install the pcap library (from
ftp://ftp.ee.lbl.gov/libpcap.tar.Z ) and/or use
--with-pcap to specify the path to it on your system

When installing libpcap do both 'make install' and 'make install-incl'])
])

AC_HEADER_STDC
AC_CHECK_HEADERS(standards.h)
AC_CHECK_HEADERS(string.h strings.h sys/resource.h sys/types.h unistd.h)
AC_CHECK_HEADERS(sys/bitypes.h sys/socket.h netinet/tcp.h netinet/in_systm.h)
AC_CHECK_HEADERS(netinet/in.h netinet/ip.h net/if.h)
AC_CHECK_HEADERS(netinet/if_ether.h linux/if_ether.h)
AC_CHECK_HEADERS(signal.h)

dnl ############## Function checks

AC_CHECK_FUNCS(sigaction)
AC_CHECK_FUNCS(sigset)

dnl ############## Type checks

AC_TYPE_SIGNAL
AC_CHECK_TYPE(u_int32_t, unsigned long)
AC_CHECK_TYPE(u_int16_t, unsigned short)
AC_CHECK_TYPE(u_int8_t, unsigned char)
AC_CHECK_TYPE(u_char, unsigned char)

dnl ############## Final Output

AC_OUTPUT(Makefile src/Makefile doc/Makefile doc/tcpflow.1 tcpflow.spec)

