IF DEFINED NEED_VCVARSALL (
    SET "PATH=%PATH%;C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin"
    CALL SetEnv.cmd
)

nmake -f common-VC10.mk clean
nmake -f ap24py33-win64-VC10.mk install

nmake -f common-VC10.mk clean
nmake -f ap24py34-win64-VC10.mk install

nmake -f common-VC10.mk clean
