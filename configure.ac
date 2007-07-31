dnl  vim: set sw=4 expandtab :
dnl
dnl  Copyright 2007 GRAHAM DUMPLETON
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

AC_INIT(mod_wsgi.c)

AC_ARG_WITH(apxs, AC_HELP_STRING([--with-apxs=NAME],
            [name of the apxs executable [[apxs]]]),
            [APXS="$with_apxs"])

if test -z "${APXS}"; then
    AC_PATH_PROGS(APXS, apxs2 apxs, [apxs],
                   [$PATH:/usr/local/apache/bin:/usr/sbin])
fi

AC_SUBST(APXS)

AC_ARG_WITH(python, AC_HELP_STRING([--with-python=NAME],
            [name of the python executable [[python]]]),
            [PYTHON="$with_python"])

if test -z "${PYTHON}"; then
    AC_PATH_PROGS(PYTHON, python, [python],
                   [$PATH:/usr/local/bin])
fi

AC_SUBST(PYTHON)

PYTHON_VERSION=`${PYTHON} -c 'from distutils import sysconfig; \
    print sysconfig.get_config_var("VERSION")'`

CPPFLAGS1=`${PYTHON} -c 'from distutils import sysconfig; \
    print "-I" + sysconfig.get_config_var("INCLUDEPY")'`

CPPFLAGS2=`${PYTHON} -c 'from distutils import sysconfig; \
    print " ".join(filter(lambda x: x.startswith("-D"), \
    sysconfig.get_config_var("CFLAGS").split()))'`

CPPFLAGS="${CPPFLAGS1} ${CPPFLAGS2}"

AC_SUBST(CPPFLAGS)

PYTHONFRAMEWORKDIR=`${PYTHON} -c 'from distutils import sysconfig; \
    print sysconfig.get_config_var("PYTHONFRAMEWORKDIR")'`
PYTHONFRAMEWORK=`${PYTHON} -c 'from distutils import sysconfig; \
    print sysconfig.get_config_var("PYTHONFRAMEWORK")'`

if test "${PYTHONFRAMEWORKDIR}" = "no-framework"; then
    LDFLAGS=`${PYTHON} -c 'import distutils.sysconfig; \
        print "-L" + distutils.sysconfig.get_python_lib(plat_specific=1, \
        standard_lib=1) +"/config"'`

    LDLIBS1="-lpython${PYTHON_VERSION}"
    LDLIBS2=`${PYTHON} -c 'from distutils import sysconfig; \
        print sysconfig.get_config_var("LIBS")'`

    LDLIBS="${LDLIBS1} ${LDLIBS2}"
else
    LDFLAGS1="-framework ${PYTHONFRAMEWORK}"

    VERSION="${PYTHON_VERSION}"
    STRING="${PYTHONFRAMEWORKDIR}/Versions/${VERSION}/${PYTHONFRAMEWORK}"
    LDFLAGS2=`${PYTHON} -c "from distutils import sysconfig; \
        print sysconfig.get_config_var(\"LINKFORSHARED\").replace( \
        \"${STRING}\", '')"`

    LDFLAGS="${LDFLAGS1} ${LDFLAGS2}"

    LDLIBS=`${PYTHON} -c 'from distutils import sysconfig; \
        print sysconfig.get_config_var("LIBS")'`
fi

AC_SUBST(LDFLAGS)
AC_SUBST(LDLIBS)

AC_MSG_CHECKING(Apache version)
HTTPD="`${APXS} -q SBINDIR`/`${APXS} -q TARGET`"
HTTPD_VERSION=`$HTTPD -v | awk '/version/ {print $3}' | awk -F/ '{print $2}'`
AC_MSG_RESULT($HTTPD_VERSION)

LIBEXECDIR="`${APXS} -q LIBEXECDIR`"
AC_SUBST(LIBEXECDIR)

HTTPD_MAJOR_VERSION=`echo ${HTTPD_VERSION} | sed -e 's/\..*//'`

rm -f Makefile.in
ln -s Makefile-${HTTPD_MAJOR_VERSION}.X.in Makefile.in

AC_OUTPUT(Makefile)
