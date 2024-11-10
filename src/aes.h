#pragma once
#include "rsa.h"
#include <string.h>

struct AesKeyMix {
    bool valid;
    char key[32];
    char iv[16];
    char salt[8];
    StrRes encryptedData;

    AesKeyMix() : 
        valid(false), key{0}, iv{0}, salt{0}, encryptedData(nullptr, 0)
    {
    };
    
    AesKeyMix(const char* key, const char* iv, const char* salt, StrRes encryptedData) :
        valid(true), key{0}, iv{0}, salt{0}, encryptedData(encryptedData)
    {
        memcpy((char*)this->key, key, sizeof(this->key));
        memcpy((char*)this->iv, iv, sizeof(this->iv));
        memcpy((char*)this->salt, salt, sizeof(this->salt));
    }
};

extern AesKeyMix invalid;

AesKeyMix ParseB64AesData(StrRes data, StrRes password);
StrRes CreateB64AesData(StrRes data, StrRes password);

StrRes AES_B64_Decrypt(StrRes input, StrRes password);
StrRes AES_B64_Encrypt(StrRes input, StrRes password);

bool aesTest();
StrRes AES_Decrypt(StrRes input, StrRes key, StrRes iv);
StrRes AES_Encrypt(StrRes input, StrRes key, StrRes iv);