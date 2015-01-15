IF DEFINED NEED_VCVARSALL (
    SET "PATH=%PATH%;C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC"
    CALL vcvarsall.bat x86
)

nmake -f common-VC10.mk clean
nmake -f ap24py33-win32-VC10.mk install

nmake -f common-VC10.mk clean
nmake -f ap24py34-win32-VC10.mk install

nmake -f common-VC10.mk clean
