#pragma once
class PatternScanFast
{
public:
	static DWORD  FindPatternIDA(const char* pPattern);
	static const void* SearchDa(const uint8_t* data, const uint32_t size, const uint8_t* pattern, const char* mask);

private:

};