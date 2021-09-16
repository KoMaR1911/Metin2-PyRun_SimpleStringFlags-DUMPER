// header.h: plik dołączany dla standardowych systemowych plików dołączanych,
// lub pliki dołączane specyficzne dla projektu
//

#pragma once

#include "targetver.h"

#pragma warning(disable : 4996)
#pragma warning(disable : 4244)

#define WIN32_LEAN_AND_MEAN             // Wyklucz rzadko używane rzeczy z nagłówków systemu Windows
// Pliki nagłówkowe systemu Windows
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <iterator>
#include <streambuf>
#include <tchar.h>


// w tym miejscu przywołaj dodatkowe nagłówki wymagane przez program
