#include "Exports.h"

int main()
{
	PVOID fnAddr = GetExportAddrFromDisk("ntoskrnl.exe", "NtQueryInformationFile");
	printf("function addr 0x%p\n", fnAddr);
	return 0;
}
