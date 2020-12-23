#include <Windows.h>

BOOL WINAPI DllMain(HMODULE hDll, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		MessageBoxA(NULL, "Dll Injected!", "ManualMapped Dll Example", MB_OK);

		return TRUE;
	}

	return FALSE;
}