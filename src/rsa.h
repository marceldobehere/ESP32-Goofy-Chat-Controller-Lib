#pragma once
#include "rsa.h"

bool testKeyGen();

bool Crypto_Verify(bool initisalised);
bool Crypto_GenerateKeyPair();

// For later reference
// https://mbed-tls.readthedocs.io/en/latest/kb/cryptography/rsa-key-pair-generator/
// https://mbed-tls.readthedocs.io/en/latest/kb/how-to/encrypt-and-decrypt-with-rsa/
// https://www.esp32.com/viewtopic.php?t=20736
