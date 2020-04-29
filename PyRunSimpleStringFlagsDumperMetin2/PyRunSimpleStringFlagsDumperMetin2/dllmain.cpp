// dllmain.cpp : Definiuje punkt wejścia dla aplikacji DLL.
#include "header.h"
#include "detours.h"
#include <iostream>
#include <io.h>

#pragma comment(lib, "detours.lib")

typedef struct {
	int cf_flags;  /* bitmask of CO_xxx flags relevant to future */
} PyCompilerFlags;
typedef int(__cdecl*tPyRun_SimpleStringFlags)(const char *command, PyCompilerFlags *flags);

tPyRun_SimpleStringFlags nPyRun_SimpleStringFlags;
int __cdecl hkPyRun_SimpleStringFlags(const char *command, PyCompilerFlags *flags)
{
	FILE * fp;

	if (command && fopen_s(&fp, "C:\\dump.txt", "ab+") == 0)
	{
		fwrite(command, strlen(command), 1, fp);
		fclose(fp);
		printf("Dumped \n");
	}

	//printf("[Hook] PyRun_SimpleStringFlags: %i %i \n", *command, *flags);

	return nPyRun_SimpleStringFlags(command, flags);
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		auto oPyRun = tPyRun_SimpleStringFlags(GetProcAddress(GetModuleHandle(L"python27.dll"), "PyRun_SimpleStringFlags"));
		nPyRun_SimpleStringFlags = (tPyRun_SimpleStringFlags)DetourFunction((PBYTE)oPyRun, (PBYTE)hkPyRun_SimpleStringFlags);
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}