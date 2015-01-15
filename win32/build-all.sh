set -x

rm -f /c/Apache*/modules/mod_wsgi-*.so

VERSION=`grep MOD_WSGI_VERSION_STRING ../src/server/wsgi_version.h \
    | sed -e 's/^[^"]*"//' -e 's/".*$//'`

TARGET=mod_wsgi-windows-$VERSION.tar.gz

rm -f $TARGET

NEED_VCVARSALL=1
export NEED_VCVARSALL

$COMSPEC /c build-win32-VC9.bat
$COMSPEC /c build-win64-VC9.bat
$COMSPEC /c build-win32-VC10.bat
$COMSPEC /c build-win64-VC10.bat

ls /c/Apache*/modules/mod_wsgi-*.so

(cd /c/; tar -c -v -z -f - --transform "s%^%mod_wsgi-windows-$VERSION/%" \
    Apache*/modules/mod_wsgi-*.so) > $TARGET
