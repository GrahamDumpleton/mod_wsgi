#!/bin/bash

# Benchmark mod_wsgi-express serving a simple hello-world WSGI application.
#
# Usage:
#   ./scripts/run-benchmark.sh [options]
#
# Options:
#   -d, --duration SECONDS    How long to run the benchmark (default: 10)
#   -c, --concurrency N       Number of concurrent clients (default: 50)
#   -r, --rate RPS            Cap bombardier's throughput at this many
#                             requests per second (shared across all
#                             concurrent clients). Default: unlimited.
#                             Useful for CPU-heavy workloads where you
#                             want steady, low-volume load instead of
#                             saturating the server.
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
#       --request-timeout SEC
#                             Pass --request-timeout SEC to mod_wsgi-express,
#                             overriding its default of 60s. Combined with
#                             --interrupt-timeout this is what bounds the
#                             total wedge unwind time. Only meaningful in
#                             daemon mode; no-op otherwise.
#       --interrupt-timeout SEC
#                             Pass --interrupt-timeout SEC to
#                             mod_wsgi-express, overriding its default
#                             of 10s. 0 disables per-thread RequestTimeout
#                             injection (request-timeout reverts to the
#                             average-across-threads behaviour). Only
#                             meaningful in daemon mode; no-op otherwise.
#       --restart-interval SEC
#                             Pass --restart-interval SEC to
#                             mod_wsgi-express. Daemon process is
#                             cycled after that many seconds, exposing
#                             the 'restart_interval' shutdown reason on
#                             telemetry STOPPING / STOPPED markers.
#                             Only meaningful in daemon mode; no-op
#                             otherwise.
#       --maximum-requests N  Pass --maximum-requests N to
#                             mod_wsgi-express. Daemon process is
#                             cycled after serving N requests, exposing
#                             the 'maximum_requests' shutdown reason on
#                             telemetry STOPPING / STOPPED markers.
#                             Only meaningful in daemon mode; no-op
#                             otherwise.
#       --wedge-interval SEC  Inject a request that spins in pure Python
#                             until the daemon's RequestTimeout injection
#                             unwinds it. SEC is the minimum gap (in
#                             seconds) between wedge end and the next
#                             wedge start, measured per process. The
#                             goal is to surface periodic 504 Gateway
#                             Timeout records in slow-request telemetry
#                             without disrupting bulk traffic. Requires a
#                             non-zero --interrupt-timeout (otherwise the
#                             wedged request takes the daemon process
#                             down via the request-timeout fallback).
#                             Requires a benchmark script that reads
#                             BENCHMARK_WEDGE_INTERVAL. Default 0
#                             (disabled).
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
#       --distribution DIST   'fixed' (default), 'lognormal' or
#                             'mixture'. Selects per-request sampling:
#                             fixed uses --delay / --cpu verbatim,
#                             lognormal draws from a distribution whose
#                             mean equals the nominal value (right-
#                             skewed fall-off typical of real web
#                             response times), mixture adds a 5% rare
#                             long-tail component centred around 2 s
#                             and capped at 5 s so the distribution
#                             has both a sharp body peak and a realistic
#                             long thin tail. See tests/benchmark.wsgi
#                             for parameter details.
#       --io-sigma N          Log-normal sigma for I/O delay (default
#                             0.6). Larger => heavier tail. Only applies
#                             with --distribution lognormal.
#       --cpu-sigma N         Log-normal sigma for CPU (default 0.0 =
#                             keep CPU constant). Set > 0 to also vary
#                             per-request CPU under --distribution
#                             lognormal.
#       --body-size SPEC      Response body length. SPEC is either a
#                             single value (e.g. 65536, 64K, 1M) or a
#                             range sampled uniformly per request
#                             (e.g. 1K-256K). Default 1024. Suffix K
#                             is 1024, M is 1024*1024. Requires a
#                             benchmark script that reads
#                             BENCHMARK_BODY_SIZE.
#       --body-chunks SPEC    How many pieces the body is yielded as.
#                             SPEC is a single integer or range
#                             (e.g. 1-128). Default 1. Equal to body
#                             size yields one byte at a time. Clamped
#                             to body size if larger. Requires a
#                             benchmark script that reads
#                             BENCHMARK_BODY_CHUNKS.
#       --4xx-rate RATE       Per-request probability (0..1) of returning
#                             a 4xx response (404 Not Found). Default 0.
#                             Independent of --5xx-rate; their sum must
#                             not exceed 1. Requires a benchmark script
#                             that reads BENCHMARK_4XX_RATE.
#       --5xx-rate RATE       Per-request probability (0..1) of returning
#                             a 5xx response (500 Internal Server Error).
#                             Default 0. Combine with --slow-requests to
#                             produce slow records that are also 5xx so
#                             the slow-record status field is exercised.
#                             Requires a benchmark script that reads
#                             BENCHMARK_5XX_RATE.
#       --metrics             Capture mod_wsgi.request_metrics() around
#                             the benchmark run and print a per-process
#                             summary after bombardier. Requires a
#                             benchmark script that exposes the
#                             /metrics/reset and /metrics/report paths
#                             (e.g. tests/benchmark.wsgi).
#       --telemetry-service T   Pass --telemetry-service T to mod_wsgi-express
#                             to enable the metrics reporter. T is
#                             'unix:/path/to/sock'. Start the ingester
#                             separately from the telemetry/ directory:
#                               uv run mod-wsgi-telemetry \\
#                                   --listen T
#       --telemetry-interval S
#                             Metrics sampling interval in seconds.
#                             Only applies with --telemetry-service.
#                             Default: 1.0
#       --slow-requests SEC   Enable slow-request reporting and set the
#                             threshold in seconds above which a still-
#                             running request is reported. Requires
#                             --telemetry-service.
#       --switch-interval SEC Override the Python GIL switch interval
#                             (sys.setswitchinterval). Applied at process
#                             start in both embedded and daemon mode.
#                             Defaults to Python's built-in 0.005 (5 ms)
#                             when unset. Useful for measuring how the
#                             GIL contention coefficient and per-phase
#                             histogram bumps shift with the interval.
#       --telemetry-options ARGS
#                             Pass one WSGITelemetryOptions directive
#                             through to mod_wsgi-express verbatim.
#                             Repeatable; each occurrence emits a
#                             separate directive in the generated
#                             config, so +/- / absolute / None / All
#                             forms compose just as they do when
#                             written by hand. Example:
#                               --telemetry-options "+CaptureUserAgent"
#       --bombardier-timeout SEC
#                             Per-request timeout passed to bombardier
#                             as --timeout. Default 10s. Bombardier's
#                             own default (2s) cancels long-tail
#                             requests mid-stream, which the daemon
#                             then reports as truncated slow records.
#       --log-level LEVEL     Apache LogLevel passed to mod_wsgi-express
#                             (e.g. emerg, alert, crit, error, warn,
#                             notice, info, debug). Default: warn.
#   -h, --help                Show this help

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_ROOT="$PROJECT_DIR/httpd-benchmark"

DURATION=10
CONCURRENCY=50
RATE=
MODE=daemon
PROCESSES=1
THREADS=5
PORT=8765
SCRIPT=tests/hello.wsgi
DISABLE_RELOADING=0
QUEUE_TIMEOUT=
REQUEST_TIMEOUT=
INTERRUPT_TIMEOUT=
RESTART_INTERVAL=
MAXIMUM_REQUESTS=
WEDGE_INTERVAL=0
DELAY=0
CPU=0
CHUNKS=1
DISTRIBUTION=fixed
IO_SIGMA=0.6
CPU_SIGMA=0.0
BODY_SIZE=1024
BODY_CHUNKS=1
RATE_4XX=0
RATE_5XX=0
METRICS=0
TELEMETRY_SERVICE=
TELEMETRY_INTERVAL=1.0
SLOW_REQUESTS=
SWITCH_INTERVAL=
TELEMETRY_OPTIONS=()
BOMBARDIER_TIMEOUT=10s
LOG_LEVEL=warn

usage() {
    awk '/^# Benchmark/,/^$/' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -d|--duration)    DURATION="$2"; shift 2 ;;
        -c|--concurrency) CONCURRENCY="$2"; shift 2 ;;
        -r|--rate)        RATE="$2"; shift 2 ;;
        -m|--mode)        MODE="$2"; shift 2 ;;
        -p|--processes)   PROCESSES="$2"; shift 2 ;;
        -t|--threads)     THREADS="$2"; shift 2 ;;
        -P|--port)        PORT="$2"; shift 2 ;;
        -s|--script)      SCRIPT="$2"; shift 2 ;;
        --disable-reloading) DISABLE_RELOADING=1; shift ;;
        --queue-timeout)  QUEUE_TIMEOUT="$2"; shift 2 ;;
        --request-timeout) REQUEST_TIMEOUT="$2"; shift 2 ;;
        --interrupt-timeout) INTERRUPT_TIMEOUT="$2"; shift 2 ;;
        --restart-interval) RESTART_INTERVAL="$2"; shift 2 ;;
        --maximum-requests) MAXIMUM_REQUESTS="$2"; shift 2 ;;
        --wedge-interval) WEDGE_INTERVAL="$2"; shift 2 ;;
        --delay)          DELAY="$2"; shift 2 ;;
        --cpu)            CPU="$2"; shift 2 ;;
        --chunks)         CHUNKS="$2"; shift 2 ;;
        --distribution)   DISTRIBUTION="$2"; shift 2 ;;
        --io-sigma)       IO_SIGMA="$2"; shift 2 ;;
        --cpu-sigma)      CPU_SIGMA="$2"; shift 2 ;;
        --body-size)      BODY_SIZE="$2"; shift 2 ;;
        --body-chunks)    BODY_CHUNKS="$2"; shift 2 ;;
        --4xx-rate)       RATE_4XX="$2"; shift 2 ;;
        --5xx-rate)       RATE_5XX="$2"; shift 2 ;;
        --metrics)        METRICS=1; shift ;;
        --telemetry-service)    TELEMETRY_SERVICE="$2"; shift 2 ;;
        --telemetry-interval)   TELEMETRY_INTERVAL="$2"; shift 2 ;;
        --slow-requests)      SLOW_REQUESTS="$2"; shift 2 ;;
        --switch-interval)    SWITCH_INTERVAL="$2"; shift 2 ;;
        --telemetry-options)    TELEMETRY_OPTIONS+=("$2"); shift 2 ;;
        --bombardier-timeout) BOMBARDIER_TIMEOUT="$2"; shift 2 ;;
        --log-level)      LOG_LEVEL="$2"; shift 2 ;;
        -h|--help)        usage ;;
        *) echo "ERROR: Unknown option: $1" >&2; usage 1 ;;
    esac
done

case "$MODE" in
    daemon|embedded) ;;
    *) echo "ERROR: --mode must be 'daemon' or 'embedded'" >&2; exit 1 ;;
esac

case "$DISTRIBUTION" in
    fixed|lognormal|mixture) ;;
    *) echo "ERROR: --distribution must be 'fixed', 'lognormal' or 'mixture'" >&2; exit 1 ;;
esac

# Validate the error rates are in [0, 1] and combined <= 1. Shell can't
# do float comparison directly, so delegate to awk and trust its exit
# status as a boolean.
if ! awk -v a="$RATE_4XX" -v b="$RATE_5XX" \
        'BEGIN { exit !(a >= 0 && a <= 1 && b >= 0 && b <= 1 && a + b <= 1) }'
then
    echo "ERROR: --4xx-rate and --5xx-rate must each be in [0, 1] and their sum <= 1" >&2
    exit 1
fi

if ! command -v bombardier >/dev/null 2>&1; then
    echo "ERROR: bombardier not found in PATH" >&2
    echo "Install from https://github.com/codesenberg/bombardier" >&2
    exit 1
fi

VENV_DIR="${MOD_WSGI_VENV:-$PROJECT_DIR/.venv}"

if [ -x "$VENV_DIR/bin/mod_wsgi-express" ]; then
    MOD_WSGI_EXPRESS="$VENV_DIR/bin/mod_wsgi-express"
elif command -v mod_wsgi-express >/dev/null 2>&1; then
    MOD_WSGI_EXPRESS="$(command -v mod_wsgi-express)"
else
    echo "ERROR: mod_wsgi-express not found" >&2
    exit 1
fi

if [ -x "$VENV_DIR/bin/python" ]; then
    PYTHON="$VENV_DIR/bin/python"
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

    # Wait up to 30s for httpd to exit cleanly. Fall back to SIGKILL on
    # its own pid only — never use lsof on $PORT, since other processes
    # (e.g. the mod-wsgi-telemetry UI on the same default port) may also
    # be bound there and must not be disturbed.
    if [ -n "$httpd_pid" ]; then
        local tries=0
        while kill -0 "$httpd_pid" 2>/dev/null; do
            tries=$((tries + 1))
            if [ $tries -gt 30 ]; then
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
    --log-level "$LOG_LEVEL"
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
    if [ -n "$REQUEST_TIMEOUT" ]; then
        setup_args+=(--request-timeout "$REQUEST_TIMEOUT")
    fi
    if [ -n "$INTERRUPT_TIMEOUT" ]; then
        setup_args+=(--interrupt-timeout "$INTERRUPT_TIMEOUT")
    fi
    if [ -n "$RESTART_INTERVAL" ]; then
        setup_args+=(--restart-interval "$RESTART_INTERVAL")
    fi
    if [ -n "$MAXIMUM_REQUESTS" ]; then
        setup_args+=(--maximum-requests "$MAXIMUM_REQUESTS")
    fi
fi

if [ -n "$TELEMETRY_SERVICE" ]; then
    setup_args+=(--telemetry-service "$TELEMETRY_SERVICE")
    setup_args+=(--telemetry-interval "$TELEMETRY_INTERVAL")
    if [ -n "$SLOW_REQUESTS" ]; then
        setup_args+=(--slow-requests "$SLOW_REQUESTS")
    fi
elif [ -n "$SLOW_REQUESTS" ]; then
    echo "ERROR: --slow-requests requires --telemetry-service" >&2
    exit 1
fi

# --telemetry-options is repeatable on both sides — each element of the
# array becomes one mod_wsgi-express invocation, which in turn emits
# one WSGITelemetryOptions line in the generated config so the +/- /
# absolute / None / All forms compose verbatim.
for opt in "${TELEMETRY_OPTIONS[@]}"; do
    setup_args+=(--telemetry-options "$opt")
done

if [ -n "$SWITCH_INTERVAL" ]; then
    setup_args+=(--switch-interval "$SWITCH_INTERVAL")
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

if [ "$MODE" = "daemon" ] && [ -n "$REQUEST_TIMEOUT" ]; then
    request_timeout_state="$REQUEST_TIMEOUT"
else
    request_timeout_state="default"
fi

if [ "$MODE" = "daemon" ] && [ -n "$INTERRUPT_TIMEOUT" ]; then
    interrupt_timeout_state="$INTERRUPT_TIMEOUT"
else
    interrupt_timeout_state="default"
fi

if [ "$MODE" = "daemon" ] && [ -n "$RESTART_INTERVAL" ]; then
    restart_interval_state="${RESTART_INTERVAL}s"
else
    restart_interval_state="default"
fi

if [ "$MODE" = "daemon" ] && [ -n "$MAXIMUM_REQUESTS" ]; then
    maximum_requests_state="$MAXIMUM_REQUESTS"
else
    maximum_requests_state="default"
fi

if [ "$WEDGE_INTERVAL" != "0" ] && [ -n "$WEDGE_INTERVAL" ]; then
    wedge_state="${WEDGE_INTERVAL}s gap"
else
    wedge_state="disabled"
fi

if [ "$METRICS" = "1" ]; then
    telemetry_state="enabled"
else
    telemetry_state="disabled"
fi

if [ -n "$TELEMETRY_SERVICE" ]; then
    telemetry_state="$TELEMETRY_SERVICE (interval ${TELEMETRY_INTERVAL}s)"
    if [ -n "$SLOW_REQUESTS" ]; then
        telemetry_state="$telemetry_state, slow>=${SLOW_REQUESTS}s"
    fi
else
    telemetry_state="disabled"
fi

echo "Configuration:"
echo "  script         : $SCRIPT"
echo "  mode           : $MODE"
echo "  processes      : $PROCESSES"
echo "  threads        : $THREADS"
echo "  concurrency    : $CONCURRENCY"
echo "  rate           : ${RATE:-unlimited}"
echo "  duration       : ${DURATION}s"
echo "  client timeout : $BOMBARDIER_TIMEOUT"
echo "  port           : $PORT"
echo "  reloading      : $reloading_state"
echo "  queue-timeout  : $queue_timeout_state"
echo "  request-tmo    : $request_timeout_state"
echo "  interrupt-tmo  : $interrupt_timeout_state"
echo "  restart-int    : $restart_interval_state"
echo "  max-requests   : $maximum_requests_state"
echo "  wedge          : $wedge_state"
echo "  delay          : ${DELAY}s"
echo "  cpu            : ${CPU}s"
echo "  chunks         : $CHUNKS"
echo "  body-size      : $BODY_SIZE"
echo "  body-chunks    : $BODY_CHUNKS"
echo "  4xx-rate       : $RATE_4XX"
echo "  5xx-rate       : $RATE_5XX"
echo "  switch-int     : ${SWITCH_INTERVAL:-default}"
if [ "$DISTRIBUTION" = "lognormal" ]; then
    echo "  distribution   : lognormal (io_sigma=${IO_SIGMA}, cpu_sigma=${CPU_SIGMA})"
elif [ "$DISTRIBUTION" = "mixture" ]; then
    echo "  distribution   : mixture (body io_sigma=${IO_SIGMA}, cpu_sigma=${CPU_SIGMA}; 5% tail ~N(2s, sigma=0.4), capped 5s)"
else
    echo "  distribution   : fixed"
fi
echo "  telemetry      : $telemetry_state"
echo ""

export BENCHMARK_DELAY="$DELAY"
export BENCHMARK_CPU="$CPU"
export BENCHMARK_CHUNKS="$CHUNKS"
export BENCHMARK_DISTRIBUTION="$DISTRIBUTION"
export BENCHMARK_IO_SIGMA="$IO_SIGMA"
export BENCHMARK_CPU_SIGMA="$CPU_SIGMA"
export BENCHMARK_BODY_SIZE="$BODY_SIZE"
export BENCHMARK_BODY_CHUNKS="$BODY_CHUNKS"
export BENCHMARK_4XX_RATE="$RATE_4XX"
export BENCHMARK_5XX_RATE="$RATE_5XX"
export BENCHMARK_WEDGE_INTERVAL="$WEDGE_INTERVAL"

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
bombardier -c "$CONCURRENCY" -d 2s -t "$BOMBARDIER_TIMEOUT" -l "$url" >/dev/null

if [ "$METRICS" = "1" ]; then
    "$PYTHON" "$SCRIPT_DIR/benchmark_metrics.py" reset \
        "http://localhost:$PORT" "$PROCESSES" || true
fi

echo ""
echo "Running benchmark..."
echo ""
bomb_args=(-c "$CONCURRENCY" -d "${DURATION}s" -t "$BOMBARDIER_TIMEOUT" -l)
if [ -n "$RATE" ]; then
    bomb_args+=(-r "$RATE")
fi
bombardier "${bomb_args[@]}" "$url"

if [ "$METRICS" = "1" ]; then
    "$PYTHON" "$SCRIPT_DIR/benchmark_metrics.py" report \
        "http://localhost:$PORT" "$PROCESSES" || true
fi
