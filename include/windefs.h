#pragma once
#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
  [in]            HANDLE           ProcessHandle,
  [in]            PROCESSINFOCLASS ProcessInformationClass,
  [out]           PVOID            ProcessInformation,
  [in]            ULONG            ProcessInformationLength,
  [out, optional] PULONG           ReturnLength
);

