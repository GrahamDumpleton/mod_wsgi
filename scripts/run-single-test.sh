#!/bin/bash

END=$((SECONDS+15))

# Prefer a project-local virtualenv install of mod_wsgi-express
# when run from a developer checkout, but fall through to a
# PATH-installed mod_wsgi-express (as used by CI, which installs
# via pip at the setup-python level with no .venv).
PATH=".venv/bin:$PATH" mod_wsgi-express setup-server tests/environ.wsgi \
    --server-root httpd-test --log-level info

trap "httpd-test/apachectl stop" EXIT

touch httpd-test/error_log

tail -f httpd-test/error_log &

httpd-test/apachectl start

while [ ! -f httpd-test/httpd.pid ]; do
    if [ $SECONDS -gt $END ]; then
        echo 'Failed'
        exit 1
    fi

    echo 'Waiting...'
    sleep 1
done

sleep 2

curl --silent --verbose --fail --show-error http://localhost:8000
