# Oldest and newest supported Python versions. A change which depends on
# the Python version has to be tested under both.
python_oldest := "3.10"
python_newest := "3.15"

# List available targets.
default:
    @just --list

# An existing .venv is left alone unless a version is given, in which
# case it is replaced, e.g. `just venv 3.10`.
# Create the Python virtual environment using uv.
venv python="":
    {{ if python == "" { "test -d .venv || uv venv" } else { "uv venv --clear --python " + python } }}

# Create the virtual environment if needed, then build and install mod_wsgi.
install: venv build

# The --no-cache option stops uv reusing a wheel built before the edit.
# Rebuild and install mod_wsgi into .venv after editing the source.
build:
    uv pip install -e . --no-cache

# Extra arguments go to mod_wsgi-express, e.g. `just serve --port 8001`.
# Run a hello world application under mod_wsgi-express, logging to the terminal.
serve *args:
    .venv/bin/mod_wsgi-express start-server tests/hello.wsgi --log-to-terminal --log-level info {{ args }}

# Name tests by path without extension, e.g. `just test tests/wsgi/input`.
# Run the integration tests, or only the tests named.
test *tests:
    ./scripts/run-tests.sh {{ tests }}

# Run the single smoke test which is what CI runs.
test-single:
    ./scripts/run-single-test.sh

# This replaces .venv, which is left on the version given. Anything else
# which had been installed into .venv is lost.
# Rebuild under one Python version and run the integration tests, e.g. `just test-python 3.10`.
test-python version *tests:
    just venv {{ version }}
    just build
    just test {{ tests }}

# The newest version is done last so that .venv is left on it.
# Run the integration tests under the oldest and newest supported Python versions.
test-bounds *tests:
    just test-python {{ python_oldest }} {{ tests }}
    just test-python {{ python_newest }} {{ tests }}

# This deletes .venv when it finishes; run `just install` afterwards.
# Build, install and serve one request under each supported Python version.
test-versions *versions:
    ./scripts/test-python-versions.sh {{ versions }}

# Run the tests for the mod_wsgi-telemetry package; extra args go to pytest.
test-telemetry *args:
    cd telemetry && uv run pytest {{ args }}

# Run the integration tests and the telemetry tests.
test-all: test test-telemetry

# Needs bombardier. Options are listed at the top of scripts/run-benchmark.sh.
# Run the benchmark script; extra args are passed through.
benchmark *args:
    ./scripts/run-benchmark.sh {{ args }}

# Warnings are treated as errors.
# Build the documentation into docs/_build/html.
docs:
    uvx --with-requirements docs/requirements.txt --from sphinx sphinx-build -W -b html docs docs/_build/html

# Build the documentation, then open it in the browser.
docs-open: docs
    open docs/_build/html/index.html

# An incremental Sphinx build can carry stale state across structural
# changes such as renamed or removed pages.
# Remove the built documentation, forcing the next build to start fresh.
docs-clean:
    rm -rf docs/_build

# Codes are spread across the source and docs/error-reference.rst. Always
# allocate above the highest and never reuse a gap, which is a retired code.
# Show the highest WSGI_APLOGNO code allocated and the next one to use.
aplogno:
    #!/usr/bin/env bash
    set -euo pipefail
    highest=$(grep -rhoIE 'WSGI_APLOGNO\(0*[0-9]+\)|WSGI[0-9]{4}' \
            --include='*.c' --include='*.h' --include='*.py' --include='*.rst' \
            --exclude-dir=_build src docs \
        | sed -E 's/[^0-9]//g' | sort -n | tail -1)
    printf 'Highest allocated: WSGI%04d\n' "$((10#$highest))"
    printf 'Next to allocate:  WSGI%04d\n' "$((10#$highest + 1))"

# This file is excluded because the patterns searched for appear in it.
# List the tracked files which contain emdashes, literal or escaped, with a count for each.
check-emdashes:
    #!/usr/bin/env bash
    set -uo pipefail
    if git grep -c -i -E $'\xe2\x80\x94|\\\\u2014|&mdash;|&#8212;|&#x2014;' -- . ':!Justfile'; then
        echo
        echo "The files above contain emdashes."
        exit 1
    fi
    echo "No emdashes found."

# Clean up build artifacts, virtual environment, and test directories.
clean: docs-clean
    rm -f configure.ac~
    rm -f configure~
    rm -f config.log
    rm -f config.status
    rm -rf autom4te.cache
    rm -rf src/server/.libs
    rm -f src/server/*.o
    rm -f src/server/*.la
    rm -f src/server/*.lo
    rm -f src/server/*.slo
    rm -f src/server/*.loT
    rm -f src/server/*.so
    rm -f src/server/apxs_config.py
    rm -rf build
    rm -rf dist
    rm -rf *.egg-info
    rm -rf __pycache__
    rm -rf src/__pycache__
    rm -rf src/server/__pycache__
    rm -rf .venv
    rm -rf httpd-test
    rm -rf httpd-tests
    rm -rf httpd-benchmark
    rm -f Makefile
