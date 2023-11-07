#!/usr/bin/env bash

set -euf -o pipefail

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "${script_dir}/../cicd/helper-functions.sh"

container_tag="python-autofix-${GIT_COMMIT_HASH}"

wrap_command docker build --rm --tag "${container_tag}" "${REPO_DIR}/docker/python/"

wrap_command docker run -u "$(id -u):$(id -g)" -v "${REPO_DIR}:/usr/src/app" "${container_tag}:latest" "./scripts/python-autofix.sh"
