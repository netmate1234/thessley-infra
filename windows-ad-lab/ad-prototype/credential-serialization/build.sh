#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
tool_prefix=${MINGW_PREFIX:-x86_64-w64-mingw32}
out="/tmp/thessley-ad-kerb-certificate-serialization.o"
client_out="/tmp/thessley-ad-approval-client.o"

"${tool_prefix}-g++" \
  -std=c++17 -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0601 \
  -Wall -Wextra -Werror \
  -I"$root" \
  -c "$root/kerb_certificate_serialization.cpp" \
  -o "$out"

"${tool_prefix}-g++" \
  -std=c++17 -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0601 \
  -Wall -Wextra -Werror \
  -I"$root" \
  -c "$root/ad_approval_client.cpp" \
  -o "$client_out"

printf 'Built isolated serialization object: %s\nBuilt isolated approval-client object: %s\n' "$out" "$client_out"
