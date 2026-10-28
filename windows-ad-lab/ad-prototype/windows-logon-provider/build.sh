#!/usr/bin/env bash
set -euo pipefail

provider_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$provider_dir/../../../../" && pwd)
serialization_dir="$repo_root/infra/windows-ad-lab/ad-prototype/credential-serialization"
viewer_dir="$provider_dir/qr-viewer"
tool_prefix=${MINGW_PREFIX:-x86_64-w64-mingw32}
out_dir="${OUT_DIR:-/tmp/thessley-ad-provider-build}"
mkdir -p "$out_dir"

"${tool_prefix}-windres" -O coff "$provider_dir/resources.rc" -o "$out_dir/provider-res.o"
"${tool_prefix}-g++" \
  -std=c++17 -O2 -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN \
  -include "$provider_dir/mingw_compat.h" -shared -static -pthread \
  -I"$serialization_dir" \
  "$provider_dir/ThessleyCredential.cpp" \
  "$provider_dir/CSampleProvider.cpp" "$provider_dir/Dll.cpp" \
  "$provider_dir/guid.cpp" "$provider_dir/helpers.cpp" \
  "$provider_dir/provider_diag.cpp" "$provider_dir/password_vault.cpp" \
  "$serialization_dir/kerb_certificate_serialization.cpp" \
  "$serialization_dir/ad_approval_client.cpp" \
  "$out_dir/provider-res.o" "$provider_dir/samplev2credentialprovider.def" \
  -lcredui -lole32 -loleaut32 -lshlwapi -lsecur32 -ladvapi32 -lgdi32 \
  -lws2_32 -luuid -lcrypt32 \
  -o "$out_dir/ThessleyADCredentialProvider.dll"

pushd "$viewer_dir" >/dev/null
"${tool_prefix}-windres" -O coff resources.rc -o "$out_dir/qr-viewer-res.o"
"${tool_prefix}-g++" -std=c++17 -O2 -municode -mwindows -static \
  -static-libgcc -static-libstdc++ -Wall -Wextra \
  ThessleyADQrViewer.cpp "$out_dir/qr-viewer-res.o" \
  -o "$out_dir/ThessleyADQrViewer.exe" \
  -lws2_32 -ladvapi32 -luser32 -lgdi32
popd >/dev/null

printf 'Built isolated AD provider and QR viewer in %s\n' "$out_dir"
printf 'Build only: no registration, installation, or VM changes were made.\n'
