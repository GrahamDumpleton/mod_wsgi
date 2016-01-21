====================
WSGIScriptAliasMatch
====================

:Description: Maps a URL to a filesystem location and designates the target as a WSGI script.
:Syntax: ``WSGIScriptAliasMatch`` *regex file-path|directory-path*
:Context: server config, virtual host

This directive is similar to the WSGIScriptAlias directive, but makes use
of regular expressions, instead of simple prefix matching. The supplied
regular expression is matched against the URL-path, and if it matches, the
server will substitute any parenthesized matches into the given string and
use it as a filename.

For example, to map a URL to scripts contained within
a directory where the script files use the ``.wsgi`` extension, but it
is desired that the extension not appear in the URL, use::

  WSGIScriptAliasMatch ^/wsgi-scripts/([^/]+) /web/wsgi-scripts/$1.wsgi

Note that you should only use WSGIScriptAliasMatch if you know what you are
doing. In most cases you should be using WSGIScriptAlias instead. If you
use WSGIScriptAliasMatch and don't do things the correct way, then you risk
modifying the value of SCRIPT_NAME as passed to the WSGI application and
this can stuff things up badly causing URL mapping to not work correctly
within the WSGI application or stuff up reconstruction of the full URL when
doing redirects. This is because the substitution of the matched sub
pattern from the left hand side back into the right hand side is often
critical.

If you think you need to use WSGIScriptAliasMatch, you probably don't
really. If you really really think you need it, then check on the mod_wsgi
mailing list about how to use it properly.
