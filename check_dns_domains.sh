#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# readonly PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
readonly PROJECT_DIR="${SCRIPT_DIR}"
readonly PYTHON_SCRIPT="dns_check.py"
readonly DOMAINS_FILE="${PROJECT_DIR}/domaines.txt"

check_dependencies() {
    local -r deps=("jq" "python3" "pipenv")
    local missing_deps=()

    for dep in "${deps[@]}"; do
        if ! command -v "${dep}" &> /dev/null; then
            missing_deps+=("${dep}")
        fi
    done

    if [[ ${#missing_deps[@]} -ne 0 ]]; then
        printf "UNKNOWN: Dépendances manquantes : %s\n" "${missing_deps[*]}" >&2
        exit 3
    fi
}

run_dns_check() {
    local output
    if ! output=$(pipenv run python "${PYTHON_SCRIPT}" "${DOMAINS_FILE}" --summary --json 2>/dev/null); then
        printf "UNKNOWN: Erreur lors de l'exécution du script Python\n" >&2
        exit 3
    fi
    echo "${output}"
}


main() {
    check_dependencies

    if ! cd "${PROJECT_DIR}"; then
        printf "UNKNOWN: Impossible d'accéder au répertoire du projet\n" >&2
        exit 3
    fi

    local output
    output="$(run_dns_check)"

    local no_operational_ns other_problems total_domains
    no_operational_ns=$(jq '.problem_domains.no_operational_ns | length' <<< "${output}")
    other_problems=$(jq '.problem_domains.non_existent + .problem_domains.ns_not_operational + .problem_domains.inconsistent_soa + .problem_domains.other_errors | length' <<< "${output}")
    total_domains=$(jq '.total_domains' <<< "${output}")
    local compact_json
    if ! compact_json=$(jq -c '.' <<< "${output}"); then
        printf "UNKNOWN: Erreur lors de la création du JSON compact\n" >&2
        exit 3
    fi
    readonly compact_json


    if [[ "${no_operational_ns}" -gt 0 ]]; then
        printf "CRITICAL: %d domaine(s) sans serveur DNS opérationnel. %d autre(s) problème(s) sur %d domaines vérifiés. JSON: %s\n" \
               "${no_operational_ns}" "${other_problems}" "${total_domains}" "${compact_json}"
        exit 2
    elif [[ "${other_problems}" -gt 0 ]]; then
        printf "WARNING: %d domaine(s) avec des problèmes sur %d domaines vérifiés. JSON: %s\n" \
               "${other_problems}" "${total_domains}" "${compact_json}"
        exit 1
    else
        printf "OK: Tous les %d domaines sont opérationnels. JSON: %s\n" \
               "${total_domains}" "${compact_json}"
        exit 0
    fi
}

main "$@"
