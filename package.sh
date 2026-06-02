#!/bin/bash

set -eo pipefail

rm -rf build dist

rm -f pyproject.toml

pip install setuptools

python setup.py sdist

MOD_WSGI_HTTPD_VERSION=$(sed -n "s/.*mod_wsgi-httpd==\([0-9][0-9A-Za-z.+_-]*\)['\"].*/\1/p" setup.py)

if [ -z "${MOD_WSGI_HTTPD_VERSION}" ]; then
    echo "Could not determine mod_wsgi-httpd version from setup.py" >&2
    exit 1
fi

sed "s/@MOD_WSGI_HTTPD_VERSION@/${MOD_WSGI_HTTPD_VERSION}/" \
    pyproject.toml.in > pyproject.toml

python setup.py sdist

rm -f pyproject.toml
