# Verify mod_wsgi collapses duplicate slashes in SCRIPT_NAME and
# PATH_INFO before the request reaches the WSGI application.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, assert_body_equals_headers, assert_body_equals
#
# Apache's MergeSlashes directive is disabled for the mount (see
# slash_collapse.conf) so duplicate slashes in the URL survive
# Apache's own parser and actually reach mod_wsgi's collapse pass.
# The ``curl --path-as-is`` flag keeps the client from normalising
# ``//`` sequences before they leave.

ROOT="$BASE_URL/test/wsgi/slash-collapse"

# ---------- Sanity check: confirm mod_wsgi (not Apache) is doing the collapse ----
#
# MergeSlashes Off keeps Apache from rewriting duplicate slashes in
# the request URL before handlers run. Echo REQUEST_URI to confirm
# the duplicates survive Apache's parser and therefore have to be
# collapsed by mod_wsgi itself for the PATH_INFO assertions below
# to pass.

assert_body_equals_headers "$ROOT/a//b?key=REQUEST_URI" \
    "value=/test/wsgi/slash-collapse/a//b?key=REQUEST_URI;end" \
    "REQUEST_URI retains duplicate slashes: MergeSlashes Off is in effect, mod_wsgi does the collapse" \
    --path-as-is

# ---------- PATH_INFO duplicate-slash collapse ----------

assert_body_equals_headers "$ROOT/a//b?key=PATH_INFO" \
    "value=/a/b;end" \
    "PATH_INFO: single duplicate slash in the middle collapses to one" \
    --path-as-is

assert_body_equals_headers "$ROOT//a/b?key=PATH_INFO" \
    "value=/a/b;end" \
    "PATH_INFO: duplicate slash at the start of the path collapses to one" \
    --path-as-is

assert_body_equals_headers "$ROOT/a///b///c?key=PATH_INFO" \
    "value=/a/b/c;end" \
    "PATH_INFO: triple slashes between segments collapse to single slashes" \
    --path-as-is

assert_body_equals_headers "$ROOT/a////b?key=PATH_INFO" \
    "value=/a/b;end" \
    "PATH_INFO: four adjacent duplicate slashes collapse to a single slash" \
    --path-as-is

assert_body_equals_headers "$ROOT/a//?key=PATH_INFO" \
    "value=/a/;end" \
    "PATH_INFO: trailing duplicate slashes collapse to a single trailing slash" \
    --path-as-is

assert_body_equals_headers "$ROOT//?key=PATH_INFO" \
    "value=/;end" \
    "PATH_INFO: pure duplicate-slash path collapses to a single slash" \
    --path-as-is

# ---------- SCRIPT_NAME is unaffected by duplicates in the request URL ----

# Duplicate slashes in the path after the mount point are part of
# PATH_INFO, so SCRIPT_NAME should remain the Apache-assigned mount
# regardless of what follows. Pinning this alongside the PATH_INFO
# cases above documents the split and guards against regressions
# where the collapse pass accidentally swallows characters from one
# key into the other.

assert_body_equals_headers "$ROOT/a//b?key=SCRIPT_NAME" \
    "value=/test/wsgi/slash-collapse;end" \
    "SCRIPT_NAME is the Apache-assigned mount and is unaffected by PATH_INFO duplicates" \
    --path-as-is

# ---------- SCRIPT_NAME duplicate-slash collapse ----------
#
# A secondary WSGIScriptAlias in slash_collapse.conf mounts the
# same echo app at ``//slashy-alias`` so the resulting SCRIPT_NAME
# carries a leading duplicate slash before mod_wsgi runs its
# normaliser. The assertion pins that the duplicate is collapsed
# to a single ``/`` before the WSGI application sees the value.

assert_body_equals_headers "$BASE_URL//slashy-alias?key=REQUEST_URI" \
    "value=//slashy-alias?key=REQUEST_URI;end" \
    "REQUEST_URI for //slashy-alias retains the duplicate leading slash (proving mod_wsgi collapses the SCRIPT_NAME)" \
    --path-as-is

assert_body_equals_headers "$BASE_URL//slashy-alias?key=SCRIPT_NAME" \
    "value=/slashy-alias;end" \
    "SCRIPT_NAME: leading duplicate slash in WSGIScriptAlias mount collapses to one" \
    --path-as-is
