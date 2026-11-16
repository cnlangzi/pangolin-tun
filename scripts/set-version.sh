#!/bin/sh
# Rewrites the version in the manifest and prints the rewritten files.
set -eu

cd "$(dirname "$0")/.."

usage() {
    printf 'usage: scripts/set-version.sh <version>\n' >&2
    printf '       <version> is x.y.z or x.y.z-<suffix>, for example 0.1.0 or 0.3.0-alpha.1\n' >&2
}

invalid() {
    printf "error: '%s' is not a valid version, expected x.y.z or x.y.z-<suffix>\n" "$1" >&2
    usage
    exit 2
}

if [ "$#" -ne 1 ]; then
    usage
    exit 2
fi

version="$1"

case "$version" in
    *[[:space:]]*) invalid "$version" ;;
esac

if [ -z "$(printf '%s' "$version" | sed -n -E '/^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/p')" ]; then
    invalid "$version"
fi

rewrite() {
    sed -i.bak -E "$1" "$2"
    rm -f "$2.bak"
}

rewrite "s|^version = \"[^\"]*\"\$|version = \"$version\"|" Cargo.toml

# The rewrite has to have taken: a manifest the pattern does not
# match would be reported as rewritten while it still carries the old
# version.
if ! grep -qxF "version = \"$version\"" Cargo.toml; then
    printf "error: Cargo.toml does not carry %s after the rewrite\n" "$version" >&2
    exit 1
fi

printf '%s\n' Cargo.toml
