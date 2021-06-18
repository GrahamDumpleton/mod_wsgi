#!/bin/bash

END=$((SECONDS+15))

mod_wsgi-express setup-server tests/environ.wsgi \
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
