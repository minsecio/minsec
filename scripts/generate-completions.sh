#!/usr/bin/env bash
# Run the generators on the build host, including during cross-compilation.
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-"$repo/target/completions"}
if (( $# > 1 )); then
    echo "usage: $0 [OUTPUT_DIRECTORY]" >&2
    exit 2
fi
mkdir -p -- "$output"
output=$(cd -- "$output" && pwd)
cd -- "$repo"
host=$(rustc -vV | sed -n 's/^host: //p')
for package in minsec minsec-sync; do
    cargo run --locked --quiet --target "$host" -p "$package" --example "$package-completions" -- "$output"
done
