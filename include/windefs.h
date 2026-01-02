#pragma once
#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
             HANDLE           ProcessHandle,
             PROCESSINFOCLASS ProcessInformationClass,
             PVOID            ProcessInformation,
             ULONG            ProcessInformationLength,
   PULONG           ReturnLength
);

