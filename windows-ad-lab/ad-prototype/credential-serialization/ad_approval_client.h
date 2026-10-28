#pragma once

#include <windows.h>

#include <atomic>
#include <string>

// Runs the isolated Python AD agent without a shell or visible console.
// The result is the agent's one-line JSON response (or bounded diagnostic).
// The caller should call ClearAdApprovalOutput as soon as it has consumed it.
HRESULT StartAdApprovalForSid(
    PCWSTR sid, PCWSTR context, const std::atomic_bool& cancelled,
    std::string* output);

HRESULT PollAdApproval(
    PCWSTR requestId, DWORD timeoutSeconds, const std::atomic_bool& cancelled,
    std::string* output);

void ClearAdApprovalOutput(std::string* output);
