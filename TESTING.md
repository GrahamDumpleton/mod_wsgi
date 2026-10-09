# Testing mod_wsgi

How the tests are laid out, how to run them, and the conventions for
adding new ones. Read this before doing any test related work.

## What there is to run

| What | Command | Covers |
| --- | --- | --- |
| Integration tests | `just test` | The module itself: requests made against a real Apache running the built module |
| Single smoke test | `just test-single` | One request through `mod_wsgi-express`. This is what CI runs |
| Oldest and newest Python | `just test-bounds` | The integration tests under both ends of the supported Python range |
| Build across Python versions | `just test-versions` | That the module compiles, installs and serves a request for each supported Python |
| Telemetry unit tests | `just test-telemetry` | The separate `mod_wsgi-telemetry` package |
| Documentation build | `just docs` | That the Sphinx docs build without warnings |
| Benchmark | `just benchmark` | Throughput and latency. Not a pass or fail test |
| Stress test | `just stress` | Process start under bursts of concurrent requests, with the APR pool concurrency check. Fails on a crash, an error response, shared per-thread state or a pool collision |

The Justfile targets are thin wrappers around the scripts in
`scripts/`, which can also be run directly. `just --list` shows them
all.

The integration tests are the main test suite. CI does not run them.
CI builds the packages, installs them for each Python version, runs
the single smoke test against both the `mod_wsgi` and
`mod_wsgi-standalone` packages, and checks that the classic
`./configure && make && sudo make install` build works. So for a
change to the C source, a local run of the integration tests is the
only thing that exercises it properly.

## Before running anything: rebuild

The module is C code compiled into a shared object. Editing a file
under `src/server/` changes nothing until it is rebuilt:

```
just build
```

This runs `uv pip install -e . --no-cache`. `just install` does the
same, creating `.venv` first if it does not exist. The `--no-cache`
option matters: without it uv can reuse a previously built wheel and
the edit is silently not picked up. An editable install on its own
does not recompile the extension.

The scripts expect the virtual environment to be `.venv` in the root
of the repository. `scripts/run-tests.sh` runs
`.venv/bin/mod_wsgi-express` directly.

## What the host needs

- An Apache httpd installation with its development files, with
  `apxs` on the `PATH`, since the build is done against it. On macOS
  this is normally the Homebrew `httpd` package.

- `mod_ssl` in that Apache, and the `openssl` command. The
  integration tests start an HTTPS listener using a throwaway self
  signed certificate.

- `curl` and `lsof`, used by the test runner.

- `uv`, for the virtual environment and for installing Python
  versions.

- `bombardier`, for the benchmark script only.

- A C compiler, `make` and network access the first time the stress
  test is run, to build its APR.

## Integration tests

```
just test                          # everything
just test tests/wsgi/file_wrapper  # one test
just test tests/wsgi/input tests/wsgi/method
```

`just test` runs `./scripts/run-tests.sh` with the same arguments.

A test is named by its path without an extension. The runner prints
`PASS` or `FAIL` for every assertion, then a total. The exit status
is non zero if anything failed, in which case the failures are
listed again along with the last 20 lines of the Apache error log.

How a run works:

- The runner generates an Apache configuration with
  `mod_wsgi-express setup-server`, using `httpd-tests/` in the root
  of the repository as the server root. That directory is deleted
  and recreated on every run, and is ignored by git.

- One server is started for the whole run, listening on port 9876
  for HTTP and 9877 for HTTPS. The runner first stops any server
  left over from an earlier run and waits for the ports to be free.

- Every test application is mounted into that one server. They all
  run in daemon mode, in the single daemon process group
  `localhost:9876`, in the main interpreter
  (`application-group=%{GLOBAL}`). `tests/dispatch.py` is installed
  as the `WSGIDispatchScript`, so that HTTPS requests reach the same
  process group.

- Each test script is then sourced in turn, in sorted order, and
  makes its requests with `curl`.

Because all tests share one server and one daemon process, a test
that crashes the process or leaves it in a bad state affects the
tests that follow it. A test that restarts the daemon process on
purpose has to wait for it to come back.

### The files that make up a test

Tests live in `tests/wsgi/`. A test called `example` is up to three
files with the same base name:

- `example.py`: the WSGI application, with a module docstring that
  says what is being tested and lists the endpoints it provides.
  Required.

- `example.sh`: the assertions. Required. It is sourced by the
  runner and is not executable on its own.

- `example.conf`: extra Apache configuration for the test, such as
  a `<Location>` block that sets a directive for one endpoint, or a
  second `WSGIScriptAlias`. Optional.

The URL the application is mounted at is derived from the file name,
with underscores turned into hyphens. `tests/wsgi/file_wrapper.py` is
mounted at `/test/wsgi/file-wrapper`. A `.sh` file with no matching
`.py` file is skipped with a warning.

The contents of the `.conf` file are written into the Apache
configuration before the `WSGIScriptAlias` for the test. Matching of
`WSGIScriptAlias` is first match wins, so a longer prefix alias
declared in the `.conf` file takes precedence over the main one.
`Define TESTS_DIR` is set to the `tests/` directory for use in these
files. Configuration that applies to the whole server, and not to one
test, goes in the block the runner writes at the top of the generated
include file.

Other files in `tests/`, such as `hello.wsgi`, `environ.wsgi` and
`sidecar.py`, are standalone scripts for running by hand with
`mod_wsgi-express` and are not part of the suite.

### Assertion helpers

The runner defines these for use in the `.sh` files, along with
`BASE_URL` and `HTTPS_BASE_URL`. Every helper takes the arguments
listed, followed by the description that is printed with the result.

| Helper | Arguments |
| --- | --- |
| `assert_status` | url, expected status |
| `assert_body_equals` | url, expected body |
| `assert_body_contains` | url, expected substring |
| `assert_body_length` | url, expected length in bytes |
| `assert_header_equals` | url, header name, expected value |
| `assert_header_count` | url, header name, expected number of occurrences |
| `assert_post_body_equals` | url, data to post, expected body |
| `assert_body_equals_headers` | url, expected body, then request headers |
| `assert_body_contains_headers` | url, expected substring, then request headers |
| `assert_status_curl` | url, expected status, then extra `curl` arguments |
| `assert_header_equals_curl` | url, header name, expected value, then extra `curl` arguments |
| `assert_post_body_equals_curl` | url, data to post, expected body, then extra `curl` arguments |
| `assert_log_contains` | text expected in the Apache error log |
| `assert_log_not_contains` | text that must not be in the Apache error log |

The helpers ending in `_headers` and `_curl` take their extra
arguments after the description. Check the definition in
`scripts/run-tests.sh` for the exact form before using one for the
first time.

### Adding a test

- Add to an existing test when the behaviour belongs with what is
  already there. Start a new one for a new area.

- Have each endpoint return something small and exact that the
  assertion can compare against, in preference to searching a large
  response for a substring. Where the interesting value cannot go in
  the body, return it in a response header.

- Give every assertion a description that says what behaviour is
  being confirmed, not how. It is what shows up in the output when
  it fails.

- If a new kind of assertion is needed, add a helper to
  `scripts/run-tests.sh` next to the others, in the same style, and
  list it in the table above.

- When fixing a bug, add the test first and confirm it fails without
  the fix.

- Do not write the total number of passing assertions into any file.
  It changes whenever a test is added.

## Stress test

```
just stress                        # the daemon scenario, 60 seconds
just stress -s embedded            # the embedded scenario
just stress --telemetry            # with the telemetry reporter on
just stress -d 300 -t 50           # longer, with more threads
```

`just stress` runs `./scripts/run-stress.sh` with the same arguments.
The options are listed at the top of the script.

The integration tests apply one request at a time to a long lived
process, so they never find a race at process start. The stress test
exists for that: it recycles processes after a fixed number of
requests and sends bursts of concurrent requests with a pause between
them, so that every process start is hit with all of its threads busy
at once. The pause is what lets the recycling happen, since a process
only restarts once no request is in flight.

How a run works:

- The first run downloads the APR source and builds it under `build/`
  with `--enable-pool-concurrency-check`, which makes a process abort
  with a message in the error log the moment two threads use one APR
  pool at the same time. A small patch adds a C backtrace to that
  message. Later runs reuse the build. `--no-debug-apr` skips it and
  runs the host's own APR, which still finds crashes and errors but
  only when a race happens to corrupt something.

- The server is set up with `mod_wsgi-express setup-server` into
  `httpd-stress/` in the root of the repository, with the Apache httpd
  run through a wrapper which loads the debug APR in place of the one
  it was linked with. A scenario file from `tests/stress/` is included
  into the configuration. It names its mode and the paths it mounts in
  comment lines at the top, and gets the thread count and recycling
  limit through `Define` variables.

- `tests/stress/burst.py` sends the bursts, spread across the paths in
  turn. `tests/stress/shared_state.py` is the application behind every
  path: it records which native thread first used each mod_wsgi thread
  id and each Python thread state, and reports to the error log when a
  different native thread turns up with the same one.

- The result is a count of process starts, process deaths, requests
  not returning 200, shared state reports and pool concurrency aborts.
  Anything but zero in the last four is a failure. The error log is
  left in `httpd-stress/error_log`, and when the check fired, the
  first abort's backtrace is printed. With the debug APR a collision
  aborts the process before it can show up as anything else, so the
  shared state count is normally zero in that mode and only becomes
  the signal with `--no-debug-apr`.

The two scenarios are `daemon`, with a sub interpreter preloaded at
process start, the main interpreter, and a sub interpreter created on
first request, and `embedded`, with the Apache children recycled
through `MaxConnectionsPerChild`. `--telemetry` turns on the reporter
with slow request records for either, which exercises the reporter
thread and the metrics paths alongside the request threads.

A new scenario is a `.conf` file in `tests/stress/` with the same two
comment lines at the top. Keep the daemon socket path short: the
server root is under the repository for that reason, and a long path
is silently truncated.

## Changes that depend on the Python version

When a change adds or alters a `#if PY_VERSION_HEX >= 0x...` guard
around Python C API code, only one side of the guard is compiled by
the Python in `.venv`. Both sides have to be checked, by running the
integration tests under the oldest and the newest supported Python.
As of this writing those are 3.10 and 3.15.

```
just test-bounds
```

This replaces `.venv` with one for the oldest version, rebuilds, and
runs the integration tests, then does the same for the newest
version, so that `.venv` is left on the newest. The two versions are
set at the top of the Justfile. `just test-python 3.10` does one
version on its own, and leaves `.venv` on that version.

Replacing `.venv` discards anything else that had been installed into
it, such as a web framework installed for trying something out. Look
at what is there first with `uv pip list`, and say in the summary of
the work if something will need to be installed again.

`just test-versions` checks something narrower: that for each of 3.10
to 3.15 the module builds, installs, and serves one request under
`mod_wsgi-express` on port 8000. It deletes and recreates `.venv` for
each version and deletes it at the end, so `.venv` has to be set up
again afterwards with `just install`. Specific versions can be given,
as in `just test-versions 3.12 3.13`.

## Telemetry package

`telemetry/` is a separate Python package with its own
`pyproject.toml` and `uv.lock`. Its tests are plain pytest and need
no Apache:

```
just test-telemetry
```

This runs `uv run pytest` inside `telemetry/`. Extra arguments are
passed to pytest.

## Documentation

The documentation under `docs/` is Sphinx with the Read the Docs
theme. To build it:

```
just docs
```

This runs Sphinx through `uvx`, with the packages listed in
`docs/requirements.txt`, so nothing is installed into `.venv`.
Warnings are treated as errors. `just docs-open` builds and then opens
the result in the browser, and `just docs-clean` removes
`docs/_build/`, which is ignored by git. Clean first after renaming
or removing a page, since an incremental build can carry stale
state.

A clean build does not mean the pages are right. reStructuredText
does not report inline markup it could not make sense of, such as an
inline literal inside bold text. It renders the markup characters
literally. After changing a page, open the generated HTML and look
at it.

## Definition of done

- For a change to the C source, or to `src/express/`: `just build`,
  then `just test` with no failures.

- For a change involving a Python version guard: `just test-bounds`
  with no failures under either version.

- For a change to how the module uses APR pools, threads or
  interpreters: `just stress` and `just stress -s embedded`, each
  with and without `--telemetry`, all passing.

- For a change under `telemetry/`: `just test-telemetry`.

- For a change under `docs/`: `just docs` with no warnings, and a
  look at the rendered page.

If a step was impractical to run, for example because the host has no
Apache with `mod_ssl`, say so in the summary of the work. Never skip
a step silently, and never report tests as passing that were not run.
