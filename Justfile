# List available targets.
default:
    @just --list

# Create a Python virtual environment using uv.
venv python="":
    {{ if python == "" { "uv venv" } else { "uv venv --python " + python } }}

# Install mod_wsgi in development mode.
install: venv
    uv pip install -e . --no-cache

# Clean up build artifacts, virtual environment, and test directories.
clean:
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
    rm -f Makefile

# Run test builds across all supported Python versions.
test-versions *versions:
    ./scripts/test-python-versions.sh {{ versions }}
