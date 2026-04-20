# Test wsgi_reload_required branch coverage.
#
# Six scenarios exercise all reachable branches of
# wsgi_reload_required in src/server/wsgi_interp.c. Each fixture
# captures a module-level LOAD_ID (time.time_ns at module load)
# and returns it in the response body, so the test can observe
# whether the module was reloaded by comparing IDs across
# requests.
#
# In daemon mode (what the harness uses), "reload" means the
# daemon process is killed and Apache retries the request on a
# fresh daemon. The new daemon imports the module fresh, so the
# "Reloading WSGI script 'X'." log line from wsgi_load_source is
# never emitted on the reload path; only "Loading Python script
# file 'X'." appears. ID comparison is therefore the primary
# evidence of reload / no-reload.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, CURL_COMMON, PROJECT_DIR, PASS, FAIL, ERRORS,
#   assert_log_contains.

FIXTURES_DIR="$PROJECT_DIR/tests/wsgi/reload-fixtures"
TRIGGERED_FLAG='/tmp/mod_wsgi_reload_test_triggered'

# Ensure no stale flag file is left from a previous run.
rm -f "$TRIGGERED_FLAG"

# Local helpers. Kept here rather than in run-tests.sh because only
# this test compares response bodies as IDs.

assert_ids_differ() {
    local id1="$1"
    local id2="$2"
    local description="$3"

    if [ -n "$id1" ] && [ -n "$id2" ] && [ "$id1" != "$id2" ]; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (id1='$id1', id2='$id2')"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

assert_ids_equal() {
    local id1="$1"
    local id2="$2"
    local description="$3"

    if [ -n "$id1" ] && [ "$id1" = "$id2" ]; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (id1='$id1', id2='$id2')"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

fetch() {
    curl "${CURL_COMMON[@]}" -s "$1"
}

# Scenario 2: static.py has no reload_required callback and is
# not touched between requests. Expect the cached module to be
# reused.

STATIC_URL="$BASE_URL/test/wsgi/reload/static"
STATIC_FIXTURE="$FIXTURES_DIR/static.py"

s_id1=$(fetch "$STATIC_URL")
s_id2=$(fetch "$STATIC_URL")
sleep 1

assert_ids_equal "$s_id1" "$s_id2" \
    "static: LOAD_ID unchanged when file is not modified"

assert_log_contains "Loading Python script file '$STATIC_FIXTURE'" \
    "static: initial load is logged"

# Scenario 4: never_reload.py defines reload_required returning
# False. Expect cached module reuse.

NEVER_URL="$BASE_URL/test/wsgi/reload/never-reload"
NEVER_FIXTURE="$FIXTURES_DIR/never_reload.py"

n_id1=$(fetch "$NEVER_URL")
n_id2=$(fetch "$NEVER_URL")
sleep 1

assert_ids_equal "$n_id1" "$n_id2" \
    "never_reload: LOAD_ID unchanged when callback returns False"

assert_log_contains "Loading Python script file '$NEVER_FIXTURE'" \
    "never_reload: initial load is logged"

# Scenario 5: raising_reload.py's reload_required callback raises
# on every invocation. The callback's traceback is logged but
# reload is NOT forced (a forced reload on every call would turn
# a systematically-failing callback into a daemon restart loop in
# daemon mode). The cached module must still be serving requests.

RAISING_URL="$BASE_URL/test/wsgi/reload/raising"
RAISING_FIXTURE="$FIXTURES_DIR/raising_reload.py"

r_id1=$(fetch "$RAISING_URL")
r_id2=$(fetch "$RAISING_URL")
sleep 1

assert_ids_equal "$r_id1" "$r_id2" \
    "raising_reload: LOAD_ID unchanged when callback raises (no reload)"

assert_log_contains "RuntimeError: reload_required callback intentionally raising" \
    "raising_reload: callback traceback is logged"

# Scenario 1: touch static.py between requests to advance mtime.
# Expect a reload. The leading sleep 1 ensures the touched mtime
# is at least one second later than the original on filesystems
# whose stat resolution is seconds (macOS HFS+, some ext4
# configs).

sleep 1
touch "$STATIC_FIXTURE"

s_id3=$(fetch "$STATIC_URL")
sleep 1

assert_ids_differ "$s_id2" "$s_id3" \
    "static: LOAD_ID changes after touch (mtime-triggered reload)"

# Scenario 3: triggered_reload.py's callback is one-shot via a
# flag file. With the flag absent, the callback returns False and
# the module stays cached. Creating the flag before the next
# request forces the callback to return True (and delete the
# flag) exactly once, triggering a daemon restart.

TRIGGERED_URL="$BASE_URL/test/wsgi/reload/triggered"
TRIGGERED_FIXTURE="$FIXTURES_DIR/triggered_reload.py"

t_id1=$(fetch "$TRIGGERED_URL")
t_id2=$(fetch "$TRIGGERED_URL")

assert_ids_equal "$t_id1" "$t_id2" \
    "triggered_reload: LOAD_ID unchanged before flag file is created"

touch "$TRIGGERED_FLAG"
t_id3=$(fetch "$TRIGGERED_URL")
sleep 1

assert_ids_differ "$t_id2" "$t_id3" \
    "triggered_reload: LOAD_ID changes after flag file triggers callback True"

t_id4=$(fetch "$TRIGGERED_URL")
assert_ids_equal "$t_id3" "$t_id4" \
    "triggered_reload: LOAD_ID stable after one-shot trigger is consumed"

assert_log_contains "Loading Python script file '$TRIGGERED_FIXTURE'" \
    "triggered_reload: initial load is logged"

# Scenario 6: missing_mtime.py pops __mtime__ from its own module
# globals in the handler. The next reload check sees the "no
# __mtime__" branch and forces a reload. The retry on the
# restarted daemon imports the module fresh so __mtime__ is
# re-stamped; the handler on that retry strips it again, keeping
# the subsequent request's reload cycle self-sustaining.

MISSING_URL="$BASE_URL/test/wsgi/reload/missing-mtime"
MISSING_FIXTURE="$FIXTURES_DIR/missing_mtime.py"

m_id1=$(fetch "$MISSING_URL")
m_id2=$(fetch "$MISSING_URL")
sleep 1

assert_ids_differ "$m_id1" "$m_id2" \
    "missing_mtime: LOAD_ID changes after __mtime__ is stripped"

assert_log_contains "Loading Python script file '$MISSING_FIXTURE'" \
    "missing_mtime: initial load is logged"

# Cleanup: remove the flag if the last request somehow left it.
rm -f "$TRIGGERED_FLAG"
