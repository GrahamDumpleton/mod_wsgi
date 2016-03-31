dnl  vim: set sw=4 expandtab :
dnl
dnl  Copyright 2007-2016 GRAHAM DUMPLETON
dnl 
dnl  Licensed under the Apache License, Version 2.0 (the "License");
dnl  you may not use this file except in compliance with the License.
dnl  You may obtain a copy of the License at
dnl 
dnl      http://www.apache.org/licenses/LICENSE-2.0
dnl 
dnl  Unless required by applicable law or agreed to in writing, software
dnl  distributed under the License is distributed on an "AS IS" BASIS,
dnl  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl  See the License for the specific language governing permissions and
dnl  limitations under the License.

dnl Process this file with autoconf to produce a configure script.

AC_INIT(src/server/mod_wsgi.c)

AC_ARG_ENABLE(framework, AC_HELP_STRING([--enable-framework],
            [enable mod_wsgi framework link]),
            [ENABLE_FRAMEWORK=$enableval],
	    [ENABLE_FRAMEWORK=false])

AC_ARG_ENABLE(embedded, AC_HELP_STRING([--disable-embedded],
            [disable mod_wsgi embedded mode]),
            [ENABLE_EMBEDDED=$enableval],
	    [ENABLE_EMBEDDED=yes])

AC_ARG_WITH(apxs, AC_HELP_STRING([--with-apxs=NAME],
            [name of the apxs executable [[apxs]]]),
            [APXS="$with_apxs"])

if test -z "${APXS}"; then
    AC_PATH_PROGS(APXS, apxs2 apxs, [apxs],
                   [$PATH:/usr/local/apache/bin:/usr/sbin])
fi

XCODE_PREFIX="/Applications/Xcode.app/Contents/Developer/Toolchains/"
XCODE_CC="${XCODE_PREFIX}XcodeDefault.xctoolchain/usr/bin/cc"
XCODE_BIN_PATTERN="${XCODE_PREFIX}.*/usr/bin/"

if test -x "${APXS}"; then
    APXS_CC=`${APXS} -q CC`
    APXS_LIBTOOL=`${APXS} -q LIBTOOL | sed -e "s/ .*$//"`
    if [[[ ${APXS_CC} = ${XCODE_PREFIX}* ]]]; then
        if test ! -x ${XCODE_CC}; then
            cat "${APXS_LIBTOOL}" | sed -e \
                "s%${XCODE_BIN_PATTERN}%/usr/bin/%" > ./libtool
            cat "${APXS}" | sed -e "s%get_vars(\"CC\")%\"/usr/bin/cc\"%" \
                -e 's%^my $libtool = .*;%my $libtool = \"./libtool\";%' > ./apxs
        else
            cat "${APXS_LIBTOOL}" | sed -e \
                "s%OSX10.[[0-9]][[0-9]]*.xctoolchain%XcodeDefault.xctoolchain%" > ./libtool
            cat "${APXS}" | sed -e "s%get_vars(\"CC\")%\"${XCODE_CC}\"%" \
                -e 's%^my $libtool = .*;%my $libtool = \"./libtool\";%' > ./apxs
        fi

        chmod +x ./apxs ./libtool
        APXS=./apxs
    fi
fi

AC_SUBST(APXS)

AC_CHECK_FUNCS(prctl)

AC_MSG_CHECKING(Apache version)
HTTPD="`${APXS} -q SBINDIR`/`${APXS} -q TARGET`"
HTTPD_INCLUDEDIR="`${APXS} -q INCLUDEDIR`"
if test -x ${HTTPD}; then
    HTTPD_VERSION=`${HTTPD} -v | awk '/version/ {print $3}' \
     | awk -F/ '{print $2}'`
else
    if test -f ${HTTPD_INCLUDEDIR}/ap_release.h; then
        HTTPD_VERSION=`grep '^#define AP_SERVER_MAJORVERSION_NUMBER ' \
         ${HTTPD_INCLUDEDIR}/ap_release.h | sed -e \
         's/^#define AP_SERVER_MAJORVERSION_NUMBER \([0-9]\).*/\1.X/'`
    else
        if test -f ${HTTPD_INCLUDEDIR}/httpd.h; then
            HTTPD_VERSION=`grep '^#define APACHE_RELEASE ' \
             ${HTTPD_INCLUDEDIR}/httpd.h | sed -e \
             's/^#define APACHE_RELEASE \([0-9]\).*/\1.X/'`
        else
            HTTPD_VERSION="2.?"
        fi
    fi
fi
AC_MSG_RESULT($HTTPD_VERSION)

AC_ARG_WITH(python, AC_HELP_STRING([--with-python=NAME],
            [name of the python executable [[python]]]),
            [PYTHON="$with_python"])

if test -z "${PYTHON}"; then
    AC_PATH_PROGS(PYTHON, python, [python],
                   [$PATH:/usr/local/bin])
fi

AC_SUBST(PYTHON)

PYTHON_VERSION=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write(sysconfig.get_config_var("VERSION"))'`

PYTHON_LDVERSION=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write(sysconfig.get_config_var("LDVERSION") or "")'`

if test x"${PYTHON_LDVERSION}" = x""; then
    PYTHON_LDVERSION=${PYTHON_VERSION}
fi

CPPFLAGS1=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write("-I" + sysconfig.get_config_var("INCLUDEPY"))'`

CPPFLAGS2=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write(" ".join(filter(lambda x: x.startswith("-D"), \
    sysconfig.get_config_var("CFLAGS").split())))'`

if test "${ENABLE_EMBEDDED}" != "yes"; then
CPPFLAGS3="-DMOD_WSGI_DISABLE_EMBEDDED"
else
CPPFLAGS3=""
fi

CPPFLAGS="${CPPFLAGS} ${CPPFLAGS1} ${CPPFLAGS2} ${CPPFLAGS3}"

AC_SUBST(CPPFLAGS)

PYTHONLIBDIR=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write(sysconfig.get_config_var("LIBDIR"))'`
PYTHONCFGDIR=`${PYTHON} -c 'from sys import stdout; \
    import distutils.sysconfig; \
    stdout.write(distutils.sysconfig.get_python_lib(plat_specific=1, \
    standard_lib=1) +"/config")'`
PYTHONFRAMEWORKDIR=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write(sysconfig.get_config_var("PYTHONFRAMEWORKDIR"))'`
PYTHONFRAMEWORKPREFIX=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write(sysconfig.get_config_var("PYTHONFRAMEWORKPREFIX"))'`
PYTHONFRAMEWORK=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write(sysconfig.get_config_var("PYTHONFRAMEWORK"))'`

if test "${PYTHON_LDVERSION}" != "${PYTHON_VERSION}"; then
    PYTHONCFGDIR="${PYTHONCFGDIR}-${PYTHON_LDVERSION}"
fi

if test "${PYTHONFRAMEWORKDIR}" = "no-framework" -o \
        "${ENABLE_FRAMEWORK}" != "yes"; then
    LDFLAGS1="-L${PYTHONLIBDIR}"
    LDFLAGS2="-L${PYTHONCFGDIR}"

    LDLIBS1="-lpython${PYTHON_LDVERSION}"

    # MacOS X seems to be broken and doesn't use ABIFLAGS suffix
    # so add a check to try and work out what we need to do.

    if test -f "${PYTHONLIBDIR}/libpython${PYTHON_VERSION}.a"; then
        LDLIBS1="-lpython${PYTHON_VERSION}"
    fi

    if test -f "${PYTHONCFGDIR}/libpython${PYTHON_VERSION}.a"; then
        LDLIBS1="-lpython${PYTHON_VERSION}"
    fi

    LDLIBS2=`${PYTHON} -c 'from sys import stdout; \
        from distutils import sysconfig; \
        stdout.write(sysconfig.get_config_var("LIBS"))'`
    LDLIBS3=`${PYTHON} -c 'from sys import stdout; \
        from distutils import sysconfig; \
        stdout.write(sysconfig.get_config_var("SYSLIBS"))'`
else
    LDFLAGS1="-Wl,-F${PYTHONFRAMEWORKPREFIX} -framework ${PYTHONFRAMEWORK}"

    VERSION="${PYTHON_VERSION}"
    STRING="${PYTHONFRAMEWORKDIR}/Versions/${VERSION}/${PYTHONFRAMEWORK}"
    LDFLAGS2=`${PYTHON} -c "from sys import stdout; \
        from distutils import sysconfig; \
        stdout.write(sysconfig.get_config_var(
        \"LINKFORSHARED\").replace(\"${STRING}\", ''))" | \
        sed -e 's/-Wl,-stack_size,[[0-9]]*//'`

    LDLIBS1=`${PYTHON} -c 'from sys import stdout; \
        from distutils import sysconfig; \
        stdout.write(sysconfig.get_config_var("LIBS"))'`
fi

CFLAGS1=""
for arg in ${CFLAGS}
do
    CFLAGS1="${CFLAGS1} -Wc,$arg"
done

CFLAGS2=""
if test -x /usr/bin/lipo; then
    LDFLAGS3=""
    ARCHITECTURES=`/usr/bin/lipo -info $HTTPD | sed -e 's/.*://'`
    for ARCH in $ARCHITECTURES; do
        CFLAGS2="${CFLAGS2} -Wc,'-arch ${ARCH}'" 
        LDFLAGS3="${LDFLAGS3} -arch ${ARCH}" 
    done
fi

CFLAGS="${CFLAGS1} ${CFLAGS2}"
LDFLAGS="${LDFLAGS} ${LDFLAGS1} ${LDFLAGS2} ${LDFLAGS3}"
LDLIBS="${LDLIBS} ${LDLIBS1} ${LDLIBS2} ${LDLIBS3}"

AC_SUBST(CFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(LDLIBS)
AC_SUBST(DESTDIR)

LIBEXECDIR="`${APXS} -q LIBEXECDIR`"
AC_SUBST(LIBEXECDIR)

HTTPD_MAJOR_VERSION=`echo ${HTTPD_VERSION} | sed -e 's/\..*//'`

AC_OUTPUT(Makefile)
