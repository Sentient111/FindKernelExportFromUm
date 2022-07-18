#pragma once
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;


PVOID NtQuerySystemInformationPtr = 0;

template<typename returnType = void, typename... args>
returnType CallPtr(PVOID Fn, args... Args) {typedef returnType(*functionPtr)(args...); return ((functionPtr)Fn)(Args...);}

NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	if (!NtQuerySystemInformationPtr)
	{
		HMODULE ntdllMod = GetModuleHandleA("Ntdll.dll");
		if (!ntdllMod)
		{
			ntdllMod = LoadLibraryA("Ntdll.dll");
			if (!ntdllMod)
				return STATUS_NOT_FOUND;
		}

		FARPROC querySysInfo = GetProcAddress(ntdllMod, "NtQuerySystemInformation");

		if (!querySysInfo)
			return STATUS_NOT_FOUND;

		NtQuerySystemInformationPtr = querySysInfo;
	}

	return CallPtr<NTSTATUS>(NtQuerySystemInformationPtr, SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}



PVOID QuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInfoClass, ULONG* size)
{
	int currAttempt = 0;
	int maxAttempt = 20;


QueryTry:
	if (currAttempt >= maxAttempt)
		return 0;

	currAttempt++;
	ULONG neededSize = 0;
	NtQuerySystemInformation(SystemInfoClass, NULL, neededSize, &neededSize);
	if (!neededSize)
		goto QueryTry;

	ULONG allocationSize = neededSize;
	PVOID informationBuffer = VirtualAlloc(NULL, allocationSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);// ExAllocatePool(NonPagedPool, allocationSize);
	if (!informationBuffer)
		goto QueryTry;

	NTSTATUS status = NtQuerySystemInformation(SystemInfoClass, informationBuffer, neededSize, &neededSize);
	if (status != STATUS_SUCCESS)
	{
		VirtualFree(informationBuffer, 0, MEM_RELEASE);
		goto QueryTry;
	}

	*size = allocationSize;
	return informationBuffer;
}
