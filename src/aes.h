#pragma once
#include "rsa.h"

bool aesTest();
StrRes AES_Decrypt(StrRes input, StrRes key, StrRes iv);
StrRes AES_Encrypt(StrRes input, const char* key);