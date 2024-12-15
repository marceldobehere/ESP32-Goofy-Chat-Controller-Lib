#pragma once
#include <stdint.h>

bool initSymmKeyStuff();
const char* getSymmKey(uint64_t userId);
void setSymmKey(uint64_t userId, const char* key);
const char* getMySymmKey(uint64_t userId);

const char* getPubKey(uint64_t userId);
void setPubKey(uint64_t userId, const char* key);