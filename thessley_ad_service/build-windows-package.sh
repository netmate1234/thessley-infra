#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
output="${1:-/tmp/thessley-ad-service-windows-package}"
work="$(mktemp -d /tmp/thessley-ad-service-build.XXXXXX)"
trap 'rm -rf -- "$work"' EXIT

mkdir -p "$work/package/thessley_ad_service"
cp "$script_dir"/*.py "$work/package/thessley_ad_service/"
cp "$script_dir/install-python.ps1" "$script_dir/install-windows-service.ps1" "$work/"
cp "$script_dir/run_windows_service.py" "$script_dir/run_windows_admin.py" "$work/package/"
mkdir -p "$(dirname -- "$output")"
if [[ -e "$output" ]]; then
    echo "Refusing to overwrite existing output: $output" >&2
    exit 1
fi
cp -a "$work/." "$output"
echo "Windows AD API package prepared at $output"
