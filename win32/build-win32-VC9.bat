IF DEFINED NEED_VCVARSALL (
    SET "PATH=%PATH%;%LOCALAPPDATA%\Programs\Common\Microsoft\Visual C++ for Python\9.0"
    CALL vcvarsall.bat x86
)

nmake -f common-VC9.mk clean
nmake -f ap22py26-win32-VC9.mk install

nmake -f common-VC9.mk clean
nmake -f ap22py27-win32-VC9.mk install

REM nmake -f common-VC9.mk clean
REM nmake -f ap22py32-win32-VC9.mk install

nmake -f common-VC9.mk clean
nmake -f ap24py26-win32-VC9.mk install

nmake -f common-VC9.mk clean
nmake -f ap24py27-win32-VC9.mk install

REM nmake -f common-VC9.mk clean
REM nmake -f ap24py32-win32-VC9.mk install

nmake -f common-VC9.mk clean
