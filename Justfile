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
    rm -rf .venv
    rm -rf build
    rm -rf dist
    rm -rf *.egg-info
    rm -rf httpd-test
    rm -rf httpd-tests
    rm -rf __pycache__
    rm -rf src/__pycache__
    rm -rf src/server/__pycache__
    rm -f src/server/*.so
    rm -f src/server/apxs_config.py

# Run test builds across all supported Python versions.
test-versions *versions:
    ./scripts/test-python-versions.sh {{ versions }}
