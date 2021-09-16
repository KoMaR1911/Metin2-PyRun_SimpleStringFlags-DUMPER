// dllmain.cpp : Definiuje punkt wejścia dla aplikacji DLL.
#include "header.h"
#include "detours.h"
#include <iostream>
#include <io.h>
#include "FindPattern.h"

#pragma comment(lib, "detours.lib")

typedef struct {
	int cf_flags;  
} PyCompilerFlags;
typedef int(__cdecl*tPyRun_SimpleStringFlags)(const char *command, PyCompilerFlags *flags);

tPyRun_SimpleStringFlags nPyRun_SimpleStringFlags;
int __cdecl hkPyRun_SimpleStringFlags(const char *command, PyCompilerFlags *flags)
{
	FILE * fp;

	if (command && fopen_s(&fp, "C:\\PythonDumpHook.txt", "ab+") == 0)
	{
		//MessageBoxA(nullptr, "Dumped", "Dumped", NULL);
		fwrite(command, strlen(command), 1, fp);
		fclose(fp);
		printf("Dumped \n");
	}

	//printf("[Hook] PyRun_SimpleStringFlags: %i %i \n", *command, *flags);

	return nPyRun_SimpleStringFlags(command, flags);
}

void FindPython()
{
	auto oPyRun = NULL;
	if (GetModuleHandleA("python27.dll") == NULL)
	{
		oPyRun = PatternScanFast::FindPatternIDA("55 8B EC 68 ? ? ? ? E8 ? ? ? ? 83 C4 ? 85 C0 74 ? 50");
	}
	else {
		oPyRun = (int)GetProcAddress(GetModuleHandleA("python27.dll"), "PyRun_SimpleStringFlags");
	}
		if (oPyRun != NULL) {
			nPyRun_SimpleStringFlags = (tPyRun_SimpleStringFlags)DetourFunction((PBYTE)oPyRun, (PBYTE)hkPyRun_SimpleStringFlags);
			MessageBoxA(nullptr, "Hooked PyRun_SimpleStringFlags!", "Found!", NULL);
		}
		else {
			MessageBoxA(nullptr, "Offset not found! try to find correct pattern using x64dbg / IDA Pro!", "ERROR Not found!", NULL);
		}
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
		CreateThread(0, NULL, (LPTHREAD_START_ROUTINE)&FindPython, NULL, NULL, NULL);
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}