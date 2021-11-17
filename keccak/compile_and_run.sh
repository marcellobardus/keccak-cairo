#!/bin/bash
clear

set -ex

cd $(dirname $0)
./venv/bin/cairo-compile keccak_example.cairo --output keccak_example_compiled.json
PYTHONPATH=. ./venv/bin/cairo-run --tracer --program=keccak_example_compiled.json --layout=all \
    --cairo_pie_output keccak_example_cairo_pie.zip
