dnl If we're using gcc, figure out which gcc options to use.

AC_DEFUN(AC_GCC_FLAGS,
[
if test $ac_cv_prog_gcc = yes; then

  dnl Determine if gcc -Wall causes warnings on isascii(), etc.
  AC_CACHE_CHECK(whether ${CC-cc} -Wall also needs -Wno-char-subscripts,
        ac_cv_char_warn,
  [
    OLDCFLAGS=$CFLAGS
    CFLAGS="$CFLAGS -Wall -Werror"
    AC_TRY_COMPILE([#include <ctype.h>],
       [ int i; char c = '0';
         i = isascii(c);
         i = isdigit(c);
         i = isprint(c);
       ], ac_cv_char_warn=no, ac_cv_char_warn=yes)
    CFLAGS=$OLDCFLAGS
  ])

  dnl Determine if gcc can accept -Wno-unused
  AC_CACHE_CHECK(whether ${CC-cc} accepts -Wno-unused, ac_cv_gcc_nounused,
  [
    OLDCFLAGS=$CFLAGS
    CFLAGS="$CFLAGS -Wno-unused"
    AC_TRY_COMPILE(, , ac_cv_gcc_nounused=yes, ac_cv_gcc_nounused=no)
    CFLAGS=$OLDCFLAGS
  ])

  dnl Determine if gcc can accept -Wno-char-subscripts
  AC_CACHE_CHECK(whether ${CC-cc} accepts -Wno-char-subscripts, ac_cv_gcc_ncs,
  [
    OLDCFLAGS=$CFLAGS
    CFLAGS="$CFLAGS -Wno-char-subscripts"
    AC_TRY_COMPILE(, , ac_cv_gcc_ncs=yes, ac_cv_gcc_ncs=no)
    CFLAGS=$OLDCFLAGS
  ])

  if test ${ac_cv_gcc_nounused:-ERROR} = yes; then
    UNUSED="-Wno-unused"
  else
    UNUSED=""
  fi

  dnl If gcc -Wall gives no warnings with isascii(), use "-Wall";
  dnl Otherwise, if gcc -Wall gives isascii warnings:
  dnl    If we can use -Wno-char-subscripts, use "-Wall -Wno-char-subscripts"
  dnl    If can't use -Wno-char-subscripts, use no flags at all.
  dnl In all cases use -Wno-unused if we have it and are using -Wall

  if test ${ac_cv_char_warn:-ERROR} = no; then
    EXTRAFLAGS="-Wall $UNUSED"
  else
    if test ${ac_cv_gcc_ncs:-ERROR} = yes; then
      EXTRAFLAGS="-Wall -Wno-char-subscripts $UNUSED"
    else
      EXTRAFLAGS=""
    fi
  fi

else
  EXTRAFLAGS=""
fi

CFLAGS="$CFLAGS $EXTRAFLAGS"
])


