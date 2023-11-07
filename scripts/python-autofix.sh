#!/usr/bin/env bash

set -euf -o pipefail

source "./cicd/helper-functions.sh"

wrap_command python -m ruff . --fix
wrap_command python -m black .
