#!/usr/bin/env bash

set -euf -o pipefail

GIT_COMMIT_HASH=$(git rev-parse --short HEAD)
REPO_DIR="$(git rev-parse --show-toplevel)"

TEXT_RED_BOLD='\033[1;31m'
TEXT_GREEN_BOLD='\033[1;32m'
TEXT_RESET='\033[0m'

single_quote_array() {
    local -n _single_quote_array_LOCAL_REF_out_array="${1}"
    shift

    local single_quote_array_LOCAL_element
    for single_quote_array_LOCAL_element in "${@}"; do
        _single_quote_array_LOCAL_REF_out_array+=("'${single_quote_array_LOCAL_element}'")
    done
}

wrap_command() {
    local command=("${@}")
    local -a quoted_args=()
    single_quote_array quoted_args "${command[@]}"
    echo "calling \`${quoted_args[*]}\`"
    local exit_code=0
    "${command[@]}" || exit_code=${?}
    if [[ "${exit_code}" -gt 0 ]]; then
        echo -e "${TEXT_RED_BOLD}exit code ${exit_code}${TEXT_RESET} from \`${quoted_args[*]}\`"
    else
        echo -e "${TEXT_GREEN_BOLD}success${TEXT_RESET} from \`${quoted_args[*]}\`"
    fi
    return "${exit_code}"
}