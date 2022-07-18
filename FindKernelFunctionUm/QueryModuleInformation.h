#pragma once
#include <Windows.h>
#include <ntstatus.h>
#include <iostream>
#include "Nt.h"

PVOID GetSystemModuleBase(const char* moduleName)
{
	ULONG size = 0;
	PSYSTEM_MODULE_INFORMATION moduleInformation = (PSYSTEM_MODULE_INFORMATION)QuerySystemInformation(SystemModuleInformation, &size);

	if (!moduleInformation || !size)
		return 0;

	for (size_t i = 0; i < moduleInformation->Count; i++)
	{
		char* fileName = (char*)moduleInformation->Module[i].FullPathName + moduleInformation->Module[i].OffsetToFileName;
		if (!strcmp(fileName, moduleName))
		{
			PVOID imageBase = moduleInformation->Module[i].ImageBase;
			VirtualFree(moduleInformation, 0, MEM_RELEASE);
			return imageBase;
		}
	}

	VirtualFree(moduleInformation, 0, MEM_RELEASE);
}


std::string GetSystemRootPath()
{
	int dirNameLength = GetSystemDirectoryA(NULL, NULL);
	char* tempBuffer = new char[dirNameLength];
	int copiedCharacterCount = GetSystemDirectoryA(tempBuffer, dirNameLength);
	if (copiedCharacterCount > dirNameLength)
	{
		printf("Failed to get system route path\n");
		return "";
	}

	std::string systemRootDir(tempBuffer);
	delete[] tempBuffer;
	return systemRootDir;
}


std::string GetKernelModuleFilePath(const char* moduleName)
{
	ULONG size = 0;
	PSYSTEM_MODULE_INFORMATION moduleInformation = (PSYSTEM_MODULE_INFORMATION)QuerySystemInformation(SystemModuleInformation, &size);

	if (!moduleInformation || !size)
		return "";

	for (size_t i = 0; i < moduleInformation->Count; i++)
	{
		char* fileName = (char*)moduleInformation->Module[i].FullPathName + moduleInformation->Module[i].OffsetToFileName;
		if (!strcmp(fileName, moduleName))
		{
			std::string filePath = GetSystemRootPath() + "\\";
			std::string moduleFilePath((char*)&moduleInformation->Module[i].FullPathName); 
			int offset = 21;
			filePath += moduleFilePath.substr(offset, moduleFilePath.length() - offset);

			VirtualFree(moduleInformation, 0, MEM_RELEASE);
			return filePath;
		}
	}

	VirtualFree(moduleInformation, 0, MEM_RELEASE);
	return std::string("");
}