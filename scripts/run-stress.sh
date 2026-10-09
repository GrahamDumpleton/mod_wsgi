#!/bin/bash

# Stress test process start under bursts of concurrent requests.
#
# Starts mod_wsgi-express with one of the scenarios in tests/stress/,
# which recycle processes after a fixed number of requests, and sends
# bursts of concurrent requests with a pause between bursts, so that
# every process start is exercised with all of its threads busy at
# once. The run fails if a process died, a request did not get a 200,
# a request saw per-thread state belonging to another thread, or the
# APR pool concurrency check fired.
#
# By default the Apache httpd that mod_wsgi-express uses is run with
# an APR built with --enable-pool-concurrency-check, which aborts the
# process with a message and a backtrace in the error log the moment
# two threads use one pool at the same time. That APR is built on
# first use under build/, which needs a C compiler, make, and network
# access to download the source. The error log of the run is left in
# httpd-stress/ for inspection.
#
# Usage:
#   ./scripts/run-stress.sh [options]
#
# Options:
#   -s, --scenario NAME       Scenario from tests/stress/ (default: daemon)
#   -d, --duration SECONDS    How long to send bursts (default: 60)
#   -c, --concurrency N       Requests per burst (default: 40)
#       --pause SECONDS       Pause between bursts (default: 0.05)
#   -t, --threads N           Threads per process (default: 20)
#       --maximum-requests N  Requests a process serves before it is
#                             recycled (default: 100)
#       --paths PATHS         Space separated paths to request, instead
#                             of every path the scenario declares
#       --telemetry           Enable the telemetry reporter, reporting
#                             every second with slow request records
#                             at 10 milliseconds, sending to a listener
#                             which this script runs
#       --no-debug-apr        Use the host's own APR instead of the
#                             concurrency check build
#   -P, --port PORT           Port to listen on (default: 8766)
#   -h, --help                Show this help

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_ROOT="$PROJECT_DIR/httpd-stress"
STRESS_DIR="$PROJECT_DIR/tests/stress"
BUILD_DIR="$PROJECT_DIR/build"

APR_VERSION=1.7.6

SCENARIO=daemon
DURATION=60
CONCURRENCY=40
PAUSE=0.05
THREADS=20
MAXIMUM_REQUESTS=100
PATHS=
TELEMETRY=0
DEBUG_APR=1
PORT=8766

usage() {
    awk '/^# Stress/,/^$/' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -s|--scenario)    SCENARIO="$2"; shift 2 ;;
        -d|--duration)    DURATION="$2"; shift 2 ;;
        -c|--concurrency) CONCURRENCY="$2"; shift 2 ;;
        --pause)          PAUSE="$2"; shift 2 ;;
        -t|--threads)     THREADS="$2"; shift 2 ;;
        --maximum-requests) MAXIMUM_REQUESTS="$2"; shift 2 ;;
        --paths)          PATHS="$2"; shift 2 ;;
        --telemetry)      TELEMETRY=1; shift ;;
        --no-debug-apr)   DEBUG_APR=0; shift ;;
        -P|--port)        PORT="$2"; shift 2 ;;
        -h|--help)        usage ;;
        *) echo "ERROR: Unknown option: $1" >&2; usage 1 ;;
    esac
done

SCENARIO_CONF="$STRESS_DIR/$SCENARIO.conf"

if [ ! -f "$SCENARIO_CONF" ]; then
    echo "ERROR: No scenario $SCENARIO in $STRESS_DIR" >&2
    exit 1
fi

# Each scenario file declares the mode it needs and the paths it
# mounts in comment lines at the top.

MODE="$(sed -n 's/^# Mode: //p' "$SCENARIO_CONF")"

if [ -z "$PATHS" ]; then
    PATHS="$(sed -n 's/^# Paths: //p' "$SCENARIO_CONF")"
fi

VENV_DIR="${MOD_WSGI_VENV:-$PROJECT_DIR/.venv}"
MOD_WSGI_EXPRESS="$VENV_DIR/bin/mod_wsgi-express"
PYTHON="$VENV_DIR/bin/python"

if [ ! -x "$MOD_WSGI_EXPRESS" ]; then
    echo "ERROR: $MOD_WSGI_EXPRESS not found; run 'just install' first" >&2
    exit 1
fi

# ---- Debug APR ----

# The APR is built once under build/ and reused. The pool concurrency
# check prints the pool and the two thread ids involved; the small
# patch applied to the source adds the C backtrace of the thread which
# detected the collision, so the error log shows where it happened.

build_debug_apr() {
    local tarball="$BUILD_DIR/apr-$APR_VERSION.tar.gz"
    local src="$BUILD_DIR/apr-$APR_VERSION-concurrency-check-src"
    local log="$BUILD_DIR/apr-$APR_VERSION-concurrency-check.log"

    if [ -f "$APR_PREFIX/.built" ]; then
        return
    fi

    mkdir -p "$BUILD_DIR"

    if [ ! -f "$tarball" ]; then
        echo "Downloading APR $APR_VERSION..."
        curl -fsSL -o "$tarball.download" \
            "https://archive.apache.org/dist/apr/apr-$APR_VERSION.tar.gz"
        mv "$tarball.download" "$tarball"
    fi

    echo "Building APR $APR_VERSION with the pool concurrency check..."
    echo "(build log in $log)"

    rm -rf "$src" "$APR_PREFIX"
    mkdir -p "$src"
    tar -x -C "$src" --strip-components=1 -f "$tarball"

    "$PYTHON" - "$src/memory/unix/apr_pools.c" <<'PYEOF'
import sys

path = sys.argv[1]
source = open(path).read()

# Several threads can detect the same collision at once, so the first
# one to report takes a mutex and keeps it: its message and backtrace
# come out whole, and the others block until the abort ends the process.

anchor = '    fprintf(stderr, "pool concurrency check: pool %p(%s), thread cur %lx "\n'
replacement = '''#if defined(__APPLE__) || defined(__GLIBC__)
    static pthread_mutex_t report_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&report_mutex);
#endif
''' + anchor

abort_anchor = '                    in_use_string[old], in_use_string[new]);\n    abort();\n'
abort_replacement = abort_anchor.replace('    abort();\n', '''#if defined(__APPLE__) || defined(__GLIBC__)
    {
        void *frames[64];
        int count = backtrace(frames, 64);
        backtrace_symbols_fd(frames, count, 2);
    }
#endif
    abort();
''')

include = '#if APR_POOL_CONCURRENCY_CHECK\n\nstatic const char * const in_use_string'
include_replacement = '''#if APR_POOL_CONCURRENCY_CHECK

#if defined(__APPLE__) || defined(__GLIBC__)
#include <execinfo.h>
#include <pthread.h>
#endif

static const char * const in_use_string'''

if (source.count(anchor) == 1 and source.count(abort_anchor) == 1
        and source.count(include) == 1):
    source = source.replace(anchor, replacement)
    source = source.replace(abort_anchor, abort_replacement)
    source = source.replace(include, include_replacement)
    open(path, 'w').write(source)
else:
    print('WARNING: apr_pools.c not patched for backtraces; aborts will '
          'show the pool and thread ids only')
PYEOF

    (
        cd "$src" &&
        ./configure --prefix="$APR_PREFIX" --enable-pool-concurrency-check &&
        make -j4 &&
        make install
    ) > "$log" 2>&1 || {
        echo "ERROR: APR build failed, see $log" >&2
        exit 1
    }

    touch "$APR_PREFIX/.built"
    rm -rf "$src"
}

# mod_wsgi-express takes the httpd to run from the HTTPD environment
# variable. The wrapper sets the shared library search path so that
# the debug APR is loaded in place of the one httpd was linked with,
# then runs the real httpd. The variable has to be set inside the
# wrapper: the generated apachectl runs under the system shell, and on
# macOS the system strips DYLD_LIBRARY_PATH from its environment.

HTTPD_WRAPPER=

if [ "$DEBUG_APR" = "1" ]; then
    APR_PREFIX="$BUILD_DIR/apr-$APR_VERSION-concurrency-check"

    build_debug_apr

    HTTPD_REAL="$("$PYTHON" -c 'from mod_wsgi.express import apxs_config; print(apxs_config.HTTPD)')"
    SHLIBPATH_VAR="$("$PYTHON" -c 'from mod_wsgi.express import apxs_config; print(apxs_config.SHLIBPATH_VAR)')"
    HTTPD_WRAPPER="$APR_PREFIX/bin/httpd-wrapper"

    cat > "$HTTPD_WRAPPER" <<EOF
#!/bin/sh
$SHLIBPATH_VAR="$APR_PREFIX/lib\${$SHLIBPATH_VAR:+:\$$SHLIBPATH_VAR}"
export $SHLIBPATH_VAR
exec "$HTTPD_REAL" "\$@"
EOF
    chmod +x "$HTTPD_WRAPPER"
fi

# ---- Server ----

LISTENER_PID=
INCLUDE_FILE=

cleanup() {
    if [ -f "$SERVER_ROOT/httpd.pid" ]; then
        "$SERVER_ROOT/apachectl" stop > /dev/null 2>&1 || true
    fi
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
    fi
    if [ -n "$INCLUDE_FILE" ]; then
        rm -f "$INCLUDE_FILE"
    fi
}
trap cleanup EXIT

if [ -f "$SERVER_ROOT/httpd.pid" ]; then
    "$SERVER_ROOT/apachectl" stop > /dev/null 2>&1 || true
    sleep 1
fi

# An earlier server can still hold the port after its pid file has
# gone, while its processes finish. Wait for it to be released.

port_in_use() {
    lsof -n -iTCP:"$PORT" -sTCP:LISTEN > /dev/null 2>&1
}

tries=0
while port_in_use; do
    tries=$((tries + 1))
    if [ $tries -gt 30 ]; then
        echo "ERROR: Port $PORT is still in use" >&2
        lsof -n -iTCP:"$PORT" -sTCP:LISTEN >&2
        exit 1
    fi
    sleep 1
done

rm -rf "$SERVER_ROOT"

INCLUDE_FILE=$(mktemp)

cat > "$INCLUDE_FILE" <<EOF
Define STRESS_DIR $STRESS_DIR
Define STRESS_THREADS $THREADS
Define STRESS_MAXIMUM_REQUESTS $MAXIMUM_REQUESTS
Include $SCENARIO_CONF
EOF

setup_args=(
    "$PROJECT_DIR/tests/hello.wsgi"
    --server-root "$SERVER_ROOT"
    --port "$PORT"
    --log-level info
    --include-file "$INCLUDE_FILE"
)

# In embedded mode the thread count is the MPM's threads per child,
# which mod_wsgi-express otherwise defaults to a handful.

if [ "$MODE" = "embedded" ]; then
    setup_args+=(--embedded-mode --threads "$THREADS")
fi

if [ "$TELEMETRY" = "1" ]; then
    setup_args+=(
        --telemetry-service "unix:$SERVER_ROOT/telemetry.sock"
        --telemetry-interval 1
        --slow-requests 0.01
    )
fi

SETUP_LOG=$(mktemp)

if [ -n "$HTTPD_WRAPPER" ]; then
    HTTPD="$HTTPD_WRAPPER" "$MOD_WSGI_EXPRESS" setup-server "${setup_args[@]}" \
        > "$SETUP_LOG" 2>&1 || setup_failed=1
else
    "$MOD_WSGI_EXPRESS" setup-server "${setup_args[@]}" \
        > "$SETUP_LOG" 2>&1 || setup_failed=1
fi

if [ -n "${setup_failed:-}" ]; then
    echo "ERROR: mod_wsgi-express setup-server failed:" >&2
    cat "$SETUP_LOG" >&2
    rm -f "$SETUP_LOG"
    exit 1
fi

rm -f "$SETUP_LOG"

# The listener only drains the socket so that the reporter's sends
# succeed. It exits on its own once the run is over.

if [ "$TELEMETRY" = "1" ]; then
    "$PYTHON" - "$SERVER_ROOT/telemetry.sock" "$((DURATION + 120))" <<'PYEOF' &
import os
import socket
import sys
import time

path = sys.argv[1]
deadline = time.monotonic() + float(sys.argv[2])

listener = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
listener.bind(path)
listener.settimeout(1.0)

while time.monotonic() < deadline:
    try:
        listener.recv(65536)
    except socket.timeout:
        pass

os.unlink(path)
PYEOF
    LISTENER_PID=$!
    disown "$LISTENER_PID"
fi

"$SERVER_ROOT/apachectl" start

tries=0
while [ ! -f "$SERVER_ROOT/httpd.pid" ]; do
    tries=$((tries + 1))
    if [ $tries -gt 15 ]; then
        echo "ERROR: Server did not start" >&2
        cat "$SERVER_ROOT/error_log" 2>/dev/null
        exit 1
    fi
    sleep 1
done

sleep 2

for path in $PATHS; do
    status=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT$path" || true)
    if [ "$status" != "200" ]; then
        echo "ERROR: $path returned '$status' before the load started" >&2
        tail -20 "$SERVER_ROOT/error_log" >&2
        exit 1
    fi
done

# ---- Load ----

echo "Scenario:        $SCENARIO ($MODE mode)"
echo "Paths:           $PATHS"
echo "Load:            $CONCURRENCY concurrent requests per burst, ${PAUSE}s pause, for ${DURATION}s"
if [ "$MODE" = "daemon" ]; then
    echo "Processes:       threads=$THREADS, recycled every $MAXIMUM_REQUESTS requests"
else
    echo "Processes:       Apache children with threads=$THREADS, recycled every $MAXIMUM_REQUESTS connections"
fi
echo "Telemetry:       $([ "$TELEMETRY" = "1" ] && echo on || echo off)"
echo "Debug APR:       $([ -n "$HTTPD_WRAPPER" ] && echo "$APR_PREFIX" || echo off)"
echo

"$PYTHON" "$STRESS_DIR/burst.py" --port "$PORT" --duration "$DURATION" \
    --concurrency "$CONCURRENCY" --pause "$PAUSE" $PATHS | tee "$SERVER_ROOT/burst.log"

"$SERVER_ROOT/apachectl" stop

tries=0
while [ -f "$SERVER_ROOT/httpd.pid" ] || port_in_use; do
    tries=$((tries + 1))
    if [ $tries -gt 30 ]; then
        break
    fi
    sleep 1
done

# ---- Results ----

ERROR_LOG="$SERVER_ROOT/error_log"

errors=$(sed -n 's/^TOTAL .*errors=\([0-9]*\).*/\1/p' "$SERVER_ROOT/burst.log")
starts=$(grep -c "Initializing Python runtime" "$ERROR_LOG" || true)
deaths=$(grep -c "exit signal" "$ERROR_LOG" || true)
shared=$(grep -c "^STRESS shared" "$ERROR_LOG" || true)
aborts=$(grep -c "pool concurrency check" "$ERROR_LOG" || true)

echo
echo "Process starts:            $starts"
echo "Process deaths:            $deaths"
echo "Requests not returning 200: $errors"
echo "Shared per-thread state:   $shared"
echo "Pool concurrency aborts:   $aborts"
echo
echo "Error log: $ERROR_LOG"

# The backtrace frames sit next to the abort line in the error log,
# before or after it depending on how the two writes were ordered,
# mixed with log lines from other processes, which all start with a
# bracket. Only the first abort is shown, up to the line of the next.

if [ "$aborts" -gt 0 ]; then
    echo
    echo "First pool concurrency abort:"
    first=$(grep -n -m 1 "pool concurrency check" "$ERROR_LOG" | cut -d: -f1)
    from=$((first > 40 ? first - 40 : 1))
    sed -n "${from},\$p" "$ERROR_LOG" | \
        awk '/pool concurrency check/ { n++ } n <= 1 && !/^\[/' | \
        head -24 | sed 's/^/  /'
fi

echo

if [ "$deaths" -gt 0 ] || [ "$errors" -gt 0 ] || [ "$shared" -gt 0 ] || [ "$aborts" -gt 0 ]; then
    echo "FAIL"
    exit 1
fi

echo "PASS"
