#!/bin/bash

# Benchmark mod_wsgi-express serving a simple hello-world WSGI application.
#
# Usage:
#   ./scripts/run-benchmark.sh [options]
#
# Options:
#   -d, --duration SECONDS    How long to run the benchmark (default: 10)
#   -c, --concurrency N       Number of concurrent clients (default: 50)
#   -m, --mode MODE           'daemon' (default) or 'embedded'
#   -p, --processes N         Worker processes (default: 1)
#   -t, --threads N           Threads per process (default: 5)
#   -P, --port PORT           Port to listen on (default: 8765)
#   -s, --script PATH         WSGI script to serve (default: tests/hello.wsgi)
#       --disable-reloading   Pass --disable-reloading to mod_wsgi-express.
#                             Only meaningful in daemon mode; no-op otherwise.
#       --queue-timeout SEC   Pass --queue-timeout SEC to mod_wsgi-express.
#                             Only meaningful in daemon mode; no-op otherwise.
#                             Setting to 0 combined with --disable-reloading
#                             bypasses the Apache-to-daemon handshake.
#       --delay SECONDS       Sleep this many (fractional) seconds per
#                             request inside the WSGI app to emulate I/O
#                             wait. Requires a benchmark script that reads
#                             BENCHMARK_DELAY (e.g. tests/benchmark.wsgi).
#   -h, --help                Show this help

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_ROOT="$PROJECT_DIR/httpd-benchmark"

DURATION=10
CONCURRENCY=50
MODE=daemon
PROCESSES=1
THREADS=5
PORT=8765
SCRIPT=tests/hello.wsgi
DISABLE_RELOADING=0
QUEUE_TIMEOUT=
DELAY=0

usage() {
    sed -n '3,16p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -d|--duration)    DURATION="$2"; shift 2 ;;
        -c|--concurrency) CONCURRENCY="$2"; shift 2 ;;
        -m|--mode)        MODE="$2"; shift 2 ;;
        -p|--processes)   PROCESSES="$2"; shift 2 ;;
        -t|--threads)     THREADS="$2"; shift 2 ;;
        -P|--port)        PORT="$2"; shift 2 ;;
        -s|--script)      SCRIPT="$2"; shift 2 ;;
        --disable-reloading) DISABLE_RELOADING=1; shift ;;
        --queue-timeout)  QUEUE_TIMEOUT="$2"; shift 2 ;;
        --delay)          DELAY="$2"; shift 2 ;;
        -h|--help)        usage ;;
        *) echo "ERROR: Unknown option: $1" >&2; usage 1 ;;
    esac
done

case "$MODE" in
    daemon|embedded) ;;
    *) echo "ERROR: --mode must be 'daemon' or 'embedded'" >&2; exit 1 ;;
esac

if ! command -v bombardier >/dev/null 2>&1; then
    echo "ERROR: bombardier not found in PATH" >&2
    echo "Install from https://github.com/codesenberg/bombardier" >&2
    exit 1
fi

if [ -x "$PROJECT_DIR/.venv/bin/mod_wsgi-express" ]; then
    MOD_WSGI_EXPRESS="$PROJECT_DIR/.venv/bin/mod_wsgi-express"
elif command -v mod_wsgi-express >/dev/null 2>&1; then
    MOD_WSGI_EXPRESS="$(command -v mod_wsgi-express)"
else
    echo "ERROR: mod_wsgi-express not found" >&2
    exit 1
fi

cd "$PROJECT_DIR"

cleanup() {
    if [ -f "$SERVER_ROOT/apachectl" ]; then
        "$SERVER_ROOT/apachectl" stop 2>/dev/null || true
    fi

    local tries=0
    while lsof -i :"$PORT" -t >/dev/null 2>&1; do
        tries=$((tries + 1))
        if [ $tries -gt 10 ]; then
            lsof -i :"$PORT" -t 2>/dev/null | xargs kill -9 2>/dev/null || true
            sleep 1
            break
        fi
        sleep 1
    done

    rm -rf "$SERVER_ROOT"
}

trap cleanup EXIT

cleanup

setup_args=(
    "$SCRIPT"
    --server-root "$SERVER_ROOT"
    --port "$PORT"
    --processes "$PROCESSES"
    --threads "$THREADS"
    --log-level warn
)

if [ "$MODE" = "embedded" ]; then
    setup_args+=(--embedded-mode)
else
    if [ "$DISABLE_RELOADING" = "1" ]; then
        setup_args+=(--disable-reloading)
    fi
    if [ -n "$QUEUE_TIMEOUT" ]; then
        setup_args+=(--queue-timeout "$QUEUE_TIMEOUT")
    fi
fi

if [ "$MODE" = "daemon" ] && [ "$DISABLE_RELOADING" = "1" ]; then
    reloading_state="disabled"
else
    reloading_state="default"
fi

if [ "$MODE" = "daemon" ] && [ -n "$QUEUE_TIMEOUT" ]; then
    queue_timeout_state="$QUEUE_TIMEOUT"
else
    queue_timeout_state="default"
fi

echo "Configuration:"
echo "  script         : $SCRIPT"
echo "  mode           : $MODE"
echo "  processes      : $PROCESSES"
echo "  threads        : $THREADS"
echo "  concurrency    : $CONCURRENCY"
echo "  duration       : ${DURATION}s"
echo "  port           : $PORT"
echo "  reloading      : $reloading_state"
echo "  queue-timeout  : $queue_timeout_state"
echo "  delay          : ${DELAY}s"
echo ""

export BENCHMARK_DELAY="$DELAY"

echo "Starting mod_wsgi-express..."
"$MOD_WSGI_EXPRESS" setup-server "${setup_args[@]}" >/dev/null
"$SERVER_ROOT/apachectl" start

tries=0
while [ ! -f "$SERVER_ROOT/httpd.pid" ]; do
    tries=$((tries + 1))
    if [ $tries -gt 15 ]; then
        echo "ERROR: Server did not start" >&2
        tail -20 "$SERVER_ROOT/error_log" 2>/dev/null >&2
        exit 1
    fi
    sleep 1
done

# Warmup request so the application is imported before we measure.
url="http://localhost:$PORT/"
warmup_tries=0
while ! curl -s -f -o /dev/null "$url"; do
    warmup_tries=$((warmup_tries + 1))
    if [ $warmup_tries -gt 10 ]; then
        echo "ERROR: Server not responding on $url" >&2
        exit 1
    fi
    sleep 1
done

echo "Warming up..."
bombardier -c "$CONCURRENCY" -d 2s -l "$url" >/dev/null

echo ""
echo "Running benchmark..."
echo ""
bombardier -c "$CONCURRENCY" -d "${DURATION}s" -l "$url"
