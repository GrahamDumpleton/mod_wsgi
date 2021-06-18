#!/bin/bash

END=$((SECONDS+15))

mod_wsgi-express setup-server tests/environ.wsgi \
    --server-root httpd --log-level info

trap "httpd/apachectl stop" EXIT

touch httpd/error_log

tail -f httpd/error_log &

httpd/apachectl start

while [ ! -f httpd/httpd.pid ]; do
    if [ $SECONDS -gt $END ]; then
        echo 'Failed'
        exit 1
    fi

    echo 'Waiting...'
    sleep 1
done

sleep 2

curl --verbose --fail --show-error http://localhost:8000
