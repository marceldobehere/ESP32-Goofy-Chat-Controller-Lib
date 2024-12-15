#pragma once
#include "rsa.h"
#include <stdint.h>

#define PRIV_KEY_PEM_SIZE 2000
#define PUB_KEY_PEM_SIZE 1000

extern unsigned char privKeyPem[PRIV_KEY_PEM_SIZE];
extern unsigned char pubKeyPem[PUB_KEY_PEM_SIZE];

void Crypt_SetPublicKey(const char* key);

bool testKeyGen();
bool CryptoInit();

bool Crypto_Verify(bool initisalised);
bool Crypto_GenerateKeyPair(bool shouldPrint);

bool Crypto_WriteKeyToFile(const char* privKeyPath, const char* pubKeyPath);
bool Crypto_ReadKeyFromFile(const char* privKeyPath, const char* pubKeyPath);

struct StrRes {
    const char* data;
    uint64_t size;

    StrRes(const char* data, uint64_t size) : data(data), size(size) {}
    StrRes(const char* data);
    StrRes();
};

StrRes Crypt_Encrypt(StrRes data);
StrRes Crypt_Decrypt(StrRes data);
StrRes Crypt_Sign(StrRes data);
bool testEncDec();

// For later reference
// https://mbed-tls.readthedocs.io/en/latest/kb/cryptography/rsa-key-pair-generator/
// https://mbed-tls.readthedocs.io/en/latest/kb/how-to/encrypt-and-decrypt-with-rsa/
// https://www.esp32.com/viewtopic.php?t=20736
