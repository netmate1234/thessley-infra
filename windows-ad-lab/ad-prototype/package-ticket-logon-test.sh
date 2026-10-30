#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../../.." && pwd)
provider_dir="$repo_root/infra/windows-ad-lab/ad-prototype/windows-logon-provider"
provider_build="${PROVIDER_OUT_DIR:-/tmp/thessley-ad-provider-build}"
broker_build="${BROKER_OUT_DIR:-/tmp}"
out_dir="${OUT_DIR:-/tmp/thessley-ad-ticket-test-package}"

required=(
  "$provider_build/ThessleyADTicketTestCredentialProvider.dll"
  "$provider_build/ThessleyADQrViewer.exe"
  "$broker_build/thessley-ad-ticket-broker.exe"
)
for path in "${required[@]}"; do
  if [[ ! -f "$path" ]]; then
    printf 'Required build output missing: %s\nBuild both the provider and ticket broker first.\n' "$path" >&2
    exit 1
  fi
done

mkdir -p "$out_dir"
cp "${required[0]}" "$out_dir/ThessleyADTicketTestCredentialProvider.dll"
cp "${required[1]}" "$out_dir/ThessleyADQrViewer.exe"
cp "${required[2]}" "$out_dir/ThessleyADTicketBroker.exe"
cp "$provider_dir/install-ticket-logon-test.ps1" "$out_dir/"
cp "$provider_dir/rollback-ticket-logon-test.ps1" "$out_dir/"
cp "$provider_dir/configure-ad-lab-ticket-test-user.ps1" "$out_dir/"
(cd "$out_dir" && sha256sum \
  ThessleyADTicketTestCredentialProvider.dll ThessleyADQrViewer.exe \
  ThessleyADTicketBroker.exe install-ticket-logon-test.ps1 \
  rollback-ticket-logon-test.ps1 configure-ad-lab-ticket-test-user.ps1 > SHA256SUMS.txt)
printf 'Prepared Clone 1-only test package in %s\n' "$out_dir"
cat "$out_dir/SHA256SUMS.txt"
printf 'No archive was created and no Windows files were changed.\n'
