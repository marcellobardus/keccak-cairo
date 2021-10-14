#!/bin/bash

set -ex

cd $(dirname $0)
cairo-compile xor_state_example.cairo --output xor_state_example_compiled.json
PYTHONPATH=. cairo-run --program=xor_state_example_compiled.json --layout=all \
    --cairo_pie_output xor_example_cairo_pie.zip
