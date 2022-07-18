#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>

#include "QueryModuleInformation.h"

UINT64 LoadFileToMemory(std::string path)
{
	std::ifstream inputPeFile(path, std::ios::binary);
	if (!inputPeFile.is_open())
	{
		printf("[PE] failed to open %s\n", path.c_str());
		return 0;
	}

	inputPeFile.seekg(0, std::ios::end);
	int fileSize = inputPeFile.tellg();
	inputPeFile.seekg(0, std::ios::beg);

	if (!fileSize)
	{
		printf("[PE] following driver has a invalid file size\n");
		printf("%s\n", path.c_str());
		inputPeFile.close();
		return 0;
	}

	UINT64 fileBuffer = (UINT64)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!fileBuffer)
	{
		printf("[PE] failed to allocate memory for file buffer %x\n", GetLastError());
		inputPeFile.close();
		return 0;
	}

	inputPeFile.read((char*)fileBuffer, fileSize);
	inputPeFile.close();
	

	return fileBuffer;
}


UINT64 TranslateVa(UINT64 rva, PVOID ntHeaders, UINT64 fileBuffer)
{
	PIMAGE_FILE_HEADER fileHeader = &((PIMAGE_NT_HEADERS)ntHeaders)->FileHeader;

	PIMAGE_SECTION_HEADER currentSection = IMAGE_FIRST_SECTION((PIMAGE_NT_HEADERS32)ntHeaders);

	for (size_t i = 0; i < ((PIMAGE_NT_HEADERS32)ntHeaders)->FileHeader.NumberOfSections; ++i, ++currentSection)
	{
		if (rva >= currentSection->VirtualAddress && rva < currentSection->VirtualAddress + currentSection->Misc.VirtualSize)
		{
			return fileBuffer + currentSection->PointerToRawData + (rva - currentSection->VirtualAddress);
		}
	}
	return 0;
}


UINT64 GetExport(UINT64 fileBuffer, const char* functionName)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(fileBuffer);
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(fileBuffer + dosHeader->e_lfanew);

	UINT64 exportDirVa = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!exportDirVa)
	{
		printf("Failed to find export dir\n");
		return 0;
	}

	PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(TranslateVa(exportDirVa, ntHeaders, fileBuffer));

	if (!exportDir)
	{
		printf("Failed to translate export dir\n");
		return 0;
	}

	DWORD* peat = (DWORD*)(TranslateVa(exportDir->AddressOfFunctions, ntHeaders, fileBuffer));
	DWORD* pent = (DWORD*)(TranslateVa(exportDir->AddressOfNames, ntHeaders, fileBuffer));
	WORD* peot = (WORD*)(TranslateVa(exportDir->AddressOfNameOrdinals, ntHeaders, fileBuffer));

	WORD ordinal = 0;


	for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
	{

		printf("%s\n", (char*)(TranslateVa(pent[i], ntHeaders, fileBuffer)));

	}

	return 0;
}

UINT64 GetExportFromFile(UINT64 fileBuffer, const char* functionName)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(fileBuffer);
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(fileBuffer + dosHeader->e_lfanew);

	if (!dosHeader || !ntHeaders)
	{
		printf("File buffer has invalid pe headers\n");
		return 0;
	}

	UINT64 exportDirVa = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!exportDirVa)
	{
		printf("Failed to find export dir\n");
		return 0;
	}

	PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(TranslateVa(exportDirVa, ntHeaders, fileBuffer));

	if (!exportDir)
	{
		printf("Failed to translate export dir\n");
		return 0;
	}

	DWORD* functionList = (DWORD*)(TranslateVa(exportDir->AddressOfFunctions, ntHeaders, fileBuffer));
	DWORD* nameList = (DWORD*)(TranslateVa(exportDir->AddressOfNames, ntHeaders, fileBuffer));
	WORD* ordinalList = (WORD*)(TranslateVa(exportDir->AddressOfNameOrdinals, ntHeaders, fileBuffer));

	for (int i = 0; i < exportDir->NumberOfNames; ++i)
	{
		char* currExportName = (char*)(TranslateVa(nameList[i], ntHeaders, fileBuffer));
		if (!strcmp(currExportName, functionName))
		{
			return functionList[ordinalList[i]] - ntHeaders->OptionalHeader.ImageBase;
		}
	}

	return 0;
}

PVOID GetExportAddrFromDisk(const char* moduleName, const char* functionName)
{
	std::string fullModulePath = GetKernelModuleFilePath(moduleName);
	if (!fullModulePath.length())
	{
		printf("failed to get module path\n");
		return 0;
	}

	UINT64 fileBuffer = LoadFileToMemory(fullModulePath);
	if (!fileBuffer)
	{
		printf("failed to load file to memory\n");
		return 0;
	}

	PVOID kernelModuleBase = GetSystemModuleBase(moduleName);
	if (!kernelModuleBase)
	{
		printf("failed to get kernel module base\n");
		return 0;
	}

	UINT64 functionOffset = GetExportFromFile(fileBuffer, functionName);
	if (!kernelModuleBase)
	{
		printf("failed to find export from disk\n");
		return 0;
	}

	VirtualFree((PVOID)fileBuffer, NULL, MEM_RELEASE);

	return (PVOID)((UINT64)kernelModuleBase + functionOffset);
}

