#include "header.h"
#include "PatternScan.h"

inline bool Compare(const uint8_t* data, const uint8_t* pattern, const char* mask) {
	for (; *mask; ++mask, ++data, ++pattern)
		if (*mask == 'x' && *data != *pattern)
			return false;

	return (*mask) == 0;
}



uintptr_t FindPattern(const char* module, const char* pattern_string, const char* mask) {
	MODULEINFO module_info = {};
	GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(module), &module_info, sizeof MODULEINFO);

	uintptr_t module_start = uintptr_t(module_info.lpBaseOfDll);

	const uint8_t* pattern = reinterpret_cast<const uint8_t*>(pattern_string);

	for (size_t i = 0; i < module_info.SizeOfImage; i++)
		if (Compare(reinterpret_cast<uint8_t*>(module_start + i), pattern, mask))
			return module_start + i;

	return 0;
}
uint64_t FindPatternIDA(const char* szModule, const char* szSignature)
{

#define INRANGE(x, a, b) (x >= a && x <= b)
#define getBits(x) (INRANGE((x & (~0x20)), XorStr('A'), XorStr('F')) ? ((x & (~0x20)) - XorStr('A') + 0xa) : (INRANGE(x, XorStr('0'), XorStr('9')) ? x - XorStr('0') : 0))
#define getByte(x) (getBits(x[0]) << 4 | getBits(x[1]))
#define XorStr( s ) ( s )
	MODULEINFO modInfo;
	GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(szModule), &modInfo, sizeof(MODULEINFO));
	DWORD startAddress = (DWORD)modInfo.lpBaseOfDll;
	DWORD endAddress = startAddress + modInfo.SizeOfImage;
	const char* pat = szSignature;
	DWORD firstMatch = 0;
	for (DWORD pCur = startAddress; pCur < endAddress; pCur++) {
		if (!*pat)
			return firstMatch;
		if (*(PBYTE)pat == XorStr('\?') || *(BYTE*)pCur == getByte(pat)) {
			if (!firstMatch)
				firstMatch = pCur;
			if (!pat[2])
				return firstMatch;
			if (*(PWORD)pat == XorStr('\?\?') || *(PBYTE)pat != XorStr('\?'))
				pat += 3;
			else
				pat += 2; //one ?
		}
		else {
			pat = szSignature;
			firstMatch = 0;
		}
	}
	return NULL;
}

