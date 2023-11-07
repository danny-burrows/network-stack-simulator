#!/usr/bin/env bash

set -euf -o pipefail

source "./cicd/helper-functions.sh"

wrap_command python -m pytest -vvv tests
