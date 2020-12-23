#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#include <winternl.h>

#pragma comment(lib, "ntdll")

using namespace std;

#define NT_SUCCESS 0

typedef BOOL(WINAPI* DllMain)(HMODULE, DWORD, LPVOID);

struct MMAP_DATA_STRUCTURE
{
	LPVOID ImageBase;
	HMODULE(__stdcall* fnLoadLibraryA)(LPCSTR);
	FARPROC(__stdcall* fnGetProcAddress)(HMODULE, LPCSTR);
};

CLIENT_ID GetClientId(LPCWSTR lpProcName)
{
	ULONG length = NULL;
	NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &length);

	if (length > 0)
	{
		SYSTEM_PROCESS_INFORMATION* pSPI = (SYSTEM_PROCESS_INFORMATION*)malloc(length);

		if (pSPI)
		{
			if (NtQuerySystemInformation(SystemProcessInformation, pSPI, length, NULL) == NT_SUCCESS)
			{
				for (PSYSTEM_PROCESS_INFORMATION pSPI_ = pSPI; pSPI_->NextEntryOffset; pSPI_ = (PSYSTEM_PROCESS_INFORMATION)(pSPI_->NextEntryOffset + (PBYTE)pSPI_)) {

					if (pSPI_->ImageName.Length && !wcscmp(pSPI_->ImageName.Buffer, lpProcName))
					{
						PSYSTEM_THREAD_INFORMATION pSTI = (PSYSTEM_THREAD_INFORMATION)(pSPI_ + 1);

						return pSTI->ClientId;
					}
				}
			}

			free(pSPI);
		}
	}

	return { 0, 0 };
}

void __stdcall LibraryLoader(MMAP_DATA_STRUCTURE *MMapData)
{
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)MMapData->ImageBase;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDOSHeader + pDOSHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)&pNTHeader->OptionalHeader;

	PBYTE pBase = (PBYTE)(MMapData->ImageBase);

	if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		PIMAGE_IMPORT_DESCRIPTOR pImportDescr = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pImportDescr->Name)
		{
			LPCSTR szMod = (LPCSTR)(pBase + pImportDescr->Name);
			HINSTANCE hDll = MMapData->fnLoadLibraryA(szMod);

			PULONG_PTR pThunkRef = (PULONG_PTR)(pBase + pImportDescr->OriginalFirstThunk);
			PULONG_PTR pFuncRef = (PULONG_PTR)(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; pThunkRef++, pFuncRef++)
			{
				if (*pThunkRef & IMAGE_ORDINAL_FLAG)
				{
					*pFuncRef = (ULONGLONG)(MMapData->fnGetProcAddress(hDll, MAKEINTRESOURCEA(*pThunkRef)));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)(pBase + *pThunkRef);
					*pFuncRef = (ULONGLONG)(MMapData->fnGetProcAddress(hDll, pImport->Name));
				}
			}
			++pImportDescr;
		}
	}

	if (pOptHeader->AddressOfEntryPoint)
	{
		DllMain EntryPoint = reinterpret_cast<DllMain>(pBase + pOptHeader->AddressOfEntryPoint);

		EntryPoint((HMODULE)(MMapData->ImageBase), DLL_PROCESS_ATTACH, NULL);
	}
}

void __stdcall stub() { }


int main()
{
	char Dll[MAX_PATH] = { };
	GetCurrentDirectoryA(MAX_PATH, Dll);
	strcat_s(Dll, "\\Dll_Example.dll");

	HANDLE hFile = CreateFileA(Dll, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, 0, NULL); // Open the DLL

	if (hFile == INVALID_HANDLE_VALUE)
		return -1;

	DWORD FileSize = GetFileSize(hFile, NULL);
	PBYTE FileBuffer = new BYTE[FileSize];

	if (!FileBuffer)
	{
		CloseHandle(hFile);
		return -1;
	}

	if (!ReadFile(hFile, FileBuffer, FileSize, NULL, NULL))
	{
		CloseHandle(hFile);
		return -1;
	}

	CloseHandle(hFile);

	DWORD ProcessId = (DWORD)GetClientId(L"x64 Target Process.exe").UniqueProcess;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + pDosHeader->e_lfanew);

	PVOID pImageBase = VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(hProcess, pImageBase, FileBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

	PIMAGE_SECTION_HEADER pSectHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(hProcess, (PVOID)((LPBYTE)pImageBase + pSectHeader[i].VirtualAddress),
			(PVOID)((LPBYTE)FileBuffer + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData, NULL);
	}

	delete[] FileBuffer;

	PVOID pLibraryLoader = VirtualAllocEx(hProcess, NULL, sizeof(MMAP_DATA_STRUCTURE) + ((PBYTE)stub - (PBYTE)LibraryLoader), MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!pLibraryLoader)
		return -1;

	MMAP_DATA_STRUCTURE MMapData = { };
	MMapData.ImageBase = pImageBase;
	MMapData.fnLoadLibraryA = LoadLibraryA;
	MMapData.fnGetProcAddress = GetProcAddress;

	WriteProcessMemory(hProcess, pLibraryLoader, &MMapData, sizeof(MMAP_DATA_STRUCTURE), NULL);

	WriteProcessMemory(hProcess, (PVOID)((MMAP_DATA_STRUCTURE*)pLibraryLoader + 1), LibraryLoader, (PBYTE)stub - (PBYTE)LibraryLoader, NULL);

	DWORD ThreadId = NULL;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((MMAP_DATA_STRUCTURE*)pLibraryLoader + 1),
		pLibraryLoader, 0, &ThreadId);

	if (!hThread || hThread == INVALID_HANDLE_VALUE)
	{
		VirtualFreeEx(hProcess, pLibraryLoader, 0, MEM_RELEASE);
		return -1;
	}

	printf("ThreadId : %04X\n", ThreadId);

	WaitForSingleObject(hThread, INFINITE);

	system("pause > nul");

	VirtualFreeEx(hProcess, pLibraryLoader, 0, MEM_RELEASE);

	return 0;
}