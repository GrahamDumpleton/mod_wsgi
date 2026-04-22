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
#       --cpu SECONDS         Run a GIL-holding busy loop for this many
#                             (fractional) seconds per request to emulate
#                             Python-level CPU work. Requires a benchmark
#                             script that reads BENCHMARK_CPU.
#       --chunks N            Split a mixed --delay + --cpu workload into
#                             N interleaved [sleep, cpu] iterations per
#                             request to scramble GIL acquisition timing
#                             across threads. Requires a benchmark script
#                             that reads BENCHMARK_CHUNKS. Default 1.
#       --distribution DIST   'fixed' (default) or 'lognormal'. Selects
#                             per-request sampling: fixed uses --delay /
#                             --cpu verbatim, lognormal draws from a
#                             distribution whose mean equals the nominal
#                             value, matching the right-skewed fall-off
#                             typical of real web response times.
#       --io-sigma N          Log-normal sigma for I/O delay (default
#                             0.6). Larger => heavier tail. Only applies
#                             with --distribution lognormal.
#       --cpu-sigma N         Log-normal sigma for CPU (default 0.0 =
#                             keep CPU constant). Set > 0 to also vary
#                             per-request CPU under --distribution
#                             lognormal.
#       --metrics             Capture mod_wsgi.request_metrics() around
#                             the benchmark run and print a per-process
#                             summary after bombardier. Requires a
#                             benchmark script that exposes the
#                             /metrics/reset and /metrics/report paths
#                             (e.g. tests/benchmark.wsgi).
#       --metrics-service T   Pass --metrics-service T to mod_wsgi-express
#                             to enable the metrics reporter. T is
#                             'unix:/path/to/sock' or 'udp:host:port'.
#                             Start the ingester separately from the
#                             telemetry/ directory:
#                               uv run mod-wsgi-telemetry \\
#                                   --listen T
#       --metrics-interval S
#                             Metrics sampling interval in seconds.
#                             Only applies with --metrics-service.
#                             Default: 1.0
#       --slow-requests SEC   Enable slow-request reporting and set the
#                             threshold in seconds above which a still-
#                             running request is reported. Requires
#                             --metrics-service.
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
CPU=0
CHUNKS=1
DISTRIBUTION=fixed
IO_SIGMA=0.6
CPU_SIGMA=0.0
METRICS=0
METRICS_SERVICE=
METRICS_INTERVAL=1.0
SLOW_REQUESTS=

usage() {
    awk '/^# Benchmark/,/^$/' "$0" | sed 's/^# \{0,1\}//'
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
        --cpu)            CPU="$2"; shift 2 ;;
        --chunks)         CHUNKS="$2"; shift 2 ;;
        --distribution)   DISTRIBUTION="$2"; shift 2 ;;
        --io-sigma)       IO_SIGMA="$2"; shift 2 ;;
        --cpu-sigma)      CPU_SIGMA="$2"; shift 2 ;;
        --metrics)        METRICS=1; shift ;;
        --metrics-service)    METRICS_SERVICE="$2"; shift 2 ;;
        --metrics-interval)   METRICS_INTERVAL="$2"; shift 2 ;;
        --slow-requests)      SLOW_REQUESTS="$2"; shift 2 ;;
        -h|--help)        usage ;;
        *) echo "ERROR: Unknown option: $1" >&2; usage 1 ;;
    esac
done

case "$MODE" in
    daemon|embedded) ;;
    *) echo "ERROR: --mode must be 'daemon' or 'embedded'" >&2; exit 1 ;;
esac

case "$DISTRIBUTION" in
    fixed|lognormal) ;;
    *) echo "ERROR: --distribution must be 'fixed' or 'lognormal'" >&2; exit 1 ;;
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

if [ -x "$PROJECT_DIR/.venv/bin/python" ]; then
    PYTHON="$PROJECT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="$(command -v python3)"
else
    PYTHON="python"
fi

cd "$PROJECT_DIR"

cleanup() {
    local httpd_pid=""
    if [ -f "$SERVER_ROOT/httpd.pid" ]; then
        httpd_pid="$(cat "$SERVER_ROOT/httpd.pid" 2>/dev/null || true)"
    fi

    if [ -f "$SERVER_ROOT/apachectl" ]; then
        "$SERVER_ROOT/apachectl" stop 2>/dev/null || true
    fi

    # Wait up to 10s for httpd to exit cleanly. Fall back to SIGKILL on
    # its own pid only — never use lsof on $PORT, since other processes
    # (e.g. the mod-wsgi-telemetry UI on the same default port) may also
    # be bound there and must not be disturbed.
    if [ -n "$httpd_pid" ]; then
        local tries=0
        while kill -0 "$httpd_pid" 2>/dev/null; do
            tries=$((tries + 1))
            if [ $tries -gt 10 ]; then
                kill -9 "$httpd_pid" 2>/dev/null || true
                sleep 1
                break
            fi
            sleep 1
        done
    fi

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

if [ -n "$METRICS_SERVICE" ]; then
    setup_args+=(--metrics-service "$METRICS_SERVICE")
    setup_args+=(--metrics-interval "$METRICS_INTERVAL")
    if [ -n "$SLOW_REQUESTS" ]; then
        setup_args+=(--slow-requests "$SLOW_REQUESTS")
    fi
elif [ -n "$SLOW_REQUESTS" ]; then
    echo "ERROR: --slow-requests requires --metrics-service" >&2
    exit 1
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

if [ "$METRICS" = "1" ]; then
    metrics_state="enabled"
else
    metrics_state="disabled"
fi

if [ -n "$METRICS_SERVICE" ]; then
    metrics_state="$METRICS_SERVICE (interval ${METRICS_INTERVAL}s)"
    if [ -n "$SLOW_REQUESTS" ]; then
        metrics_state="$metrics_state, slow>=${SLOW_REQUESTS}s"
    fi
else
    metrics_state="disabled"
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
echo "  cpu            : ${CPU}s"
echo "  chunks         : $CHUNKS"
if [ "$DISTRIBUTION" = "lognormal" ]; then
    echo "  distribution   : lognormal (io_sigma=${IO_SIGMA}, cpu_sigma=${CPU_SIGMA})"
else
    echo "  distribution   : fixed"
fi
echo "  metrics        : $metrics_state"
echo "  metrics        : $metrics_state"
echo ""

export BENCHMARK_DELAY="$DELAY"
export BENCHMARK_CPU="$CPU"
export BENCHMARK_CHUNKS="$CHUNKS"
export BENCHMARK_DISTRIBUTION="$DISTRIBUTION"
export BENCHMARK_IO_SIGMA="$IO_SIGMA"
export BENCHMARK_CPU_SIGMA="$CPU_SIGMA"

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

if [ "$METRICS" = "1" ]; then
    "$PYTHON" "$SCRIPT_DIR/benchmark_metrics.py" reset \
        "http://localhost:$PORT" "$PROCESSES" || true
fi

echo ""
echo "Running benchmark..."
echo ""
bombardier -c "$CONCURRENCY" -d "${DURATION}s" -l "$url"

if [ "$METRICS" = "1" ]; then
    "$PYTHON" "$SCRIPT_DIR/benchmark_metrics.py" report \
        "http://localhost:$PORT" "$PROCESSES" || true
fi
