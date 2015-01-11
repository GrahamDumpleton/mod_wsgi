IF DEFINED NEED_VCVARSALL (
    SET "PATH=%PATH%;%LOCALAPPDATA%\Programs\Common\Microsoft\Visual C++ for Python\9.0"
    CALL vcvarsall.bat amd64
)

nmake -f common-VC9.mk clean
nmake -f ap24py26-win64-VC9.mk install

nmake -f common-VC9.mk clean
nmake -f ap24py27-win64-VC9.mk install

REM nmake -f common-VC9.mk clean
REM nmake -f ap24py32-win64-VC9.mk install

nmake -f common-VC9.mk clean
