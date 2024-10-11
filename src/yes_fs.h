#pragma once
#include <stdint.h>

struct FileRead {
    const char* data;
    uint64_t size;
};

bool initFS();
bool testFS();
bool fileExists(const char* path);
FileRead readFile(const char* path);
bool writeFile(const char* path, const char* data);
bool appendFile(const char* path, const char* data);