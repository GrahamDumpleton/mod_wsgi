CPPFLAGS = \
 /DWIN32 \
 /DNDEBUG \
 /I"$(APACHE_ROOTDIR)\include" \
 /I"$(PYTHON_ROOTDIR)\include"

CFLAGS = \
 /MD \
 /GF \
 /Gy \
 /O2 \
 /Wall \
 /Zc:wchar_t \
 /Zc:forScope

LDFLAGS = \
 /link \
 /LIBPATH:$(APACHE_ROOTDIR)\lib \
 /LIBPATH:$(PYTHON_ROOTDIR)\libs \
 /OPT:REF \
 /OPT:ICF=2 \
 /RELEASE \
 /SUBSYSTEM:WINDOWS

LDLIBS = \
 python$(PYTHON_VERSION).lib \
 libhttpd.lib \
 libapr-1.lib \
 libaprutil-1.lib

SRCFILES = ..\src\server\*.c

mod_wsgi.so : $(SRCFILES)
	cl $(CPPFLAGS) $(CFLAGS) $(SRCFILES) /LD $(LDFLAGS) $(LDLIBS) /OUT:$@
	mt -manifest $@.manifest -outputresource:$@;2

VARIANT = py$(PYTHON_VERSION)-VC9

install : mod_wsgi.so
	copy $? $(APACHE_ROOTDIR)\modules\mod_wsgi-$(VARIANT).so
	:
	:
	:
	:
	: You now need to edit $(APACHE_ROOTDIR)\conf\httpd.conf and add:
	:
	:   LoadModule wsgi_module modules/mod_wsgi-$(VARIANT).so
	:
	:
	:
	:

clean :
	del *.obj *.so *.so.manifest *.lib *.exp
