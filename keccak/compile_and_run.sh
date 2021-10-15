#!/bin/bash
clear

set -ex

cd $(dirname $0)
cairo-compile keccak_example.cairo --output keccak_example_compiled.json
PYTHONPATH=. cairo-run --program=keccak_example_compiled.json --layout=all \
    --cairo_pie_output keccak_example_cairo_pie.zip
