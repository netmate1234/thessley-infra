#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
tool_prefix=${MINGW_PREFIX:-x86_64-w64-mingw32}
out="/tmp/thessley-ad-kerb-certificate-serialization.o"
client_out="/tmp/thessley-ad-approval-client.o"
ticket_out="/tmp/thessley-ad-kerb-ticket-serialization.o"
probe_out="/tmp/thessley-ad-ticket-logon-probe.exe"

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

"${tool_prefix}-g++" \
  -std=c++17 -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0601 \
  -Wall -Wextra -Werror \
  -I"$root" \
  -c "$root/kerb_ticket_serialization.cpp" \
  -o "$ticket_out"

"${tool_prefix}-g++" \
  -std=c++17 -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0601 \
  -Wall -Wextra -Werror -Os -s -static-libgcc -static-libstdc++ \
  -ffunction-sections -fdata-sections \
  -I"$root" \
  "$root/ticket_logon_probe.cpp" \
  -municode -ladvapi32 -lsecur32 -Wl,--gc-sections \
  -o "$probe_out"

printf 'Built isolated certificate serializer: %s\nBuilt isolated approval client: %s\nBuilt isolated Kerberos ticket serializer: %s\nBuilt LSA ticket-logon probe: %s\n' \
  "$out" "$client_out" "$ticket_out" "$probe_out"
