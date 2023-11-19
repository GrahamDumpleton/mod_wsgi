#!/bin/bash

set -eo pipefail

rm -rf build dist

rm -f pyproject.toml

pip install setuptools

python setup.py sdist

ln -s pyproject.toml.in pyproject.toml

python setup.py sdist

rm -f pyproject.toml
