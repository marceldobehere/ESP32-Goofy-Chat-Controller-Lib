#pragma once
#include "rsa.h"

#define PRIV_KEY_PEM_SIZE 2000
#define PUB_KEY_PEM_SIZE 1000

extern unsigned char privKeyPem[PRIV_KEY_PEM_SIZE];
extern unsigned char pubKeyPem[PUB_KEY_PEM_SIZE];

bool testKeyGen();
bool CryptoInit();

bool Crypto_Verify(bool initisalised);
bool Crypto_GenerateKeyPair(bool shouldPrint);

bool Crypto_WriteKeyToFile(const char* privKeyPath, const char* pubKeyPath);
bool Crypto_ReadKeyFromFile(const char* privKeyPath, const char* pubKeyPath);

const char* Crypt_Encrypt(const char* data);
const char* Crypt_Decrypt(const char* data);

// For later reference
// https://mbed-tls.readthedocs.io/en/latest/kb/cryptography/rsa-key-pair-generator/
// https://mbed-tls.readthedocs.io/en/latest/kb/how-to/encrypt-and-decrypt-with-rsa/
// https://www.esp32.com/viewtopic.php?t=20736
