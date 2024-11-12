#include "aes.h"
#include <Arduino.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <mbedtls/base64.h>
#include <mbedtls/aes.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <wolfssl/openssl/evp.h>

// https://www.base64decode.org
// https://www.toolhelper.cn/en/SymmetricEncryption/AES
// https://stackoverflow.com/questions/35472396/how-does-cryptojs-get-an-iv-when-none-is-specified
// https://cryptojs.gitbook.io/docs#ciphers
// https://stackblitz.com/edit/cryptojs-aes-encrypt-decrypt?file=index.js
// https://mbed-tls.readthedocs.io/en/latest/kb/how-to/encrypt-with-aes-cbc/

// https://mbed-tls.readthedocs.io/projects/api/en/development/api/file/hkdf_8h/
// OpenSSLKdf
// www.openssl.org/docs/crypto/EVP_BytesToKey.html


AesKeyMix invalid = AesKeyMix();

bool aesTest()
{
    Serial.println("> Testing AES encryption and decryption");
    wolfSSL_Init();

    // Hardcoded decryption test
    {
        const char* encryptedData = "VTJGc2RHVmtYMStQRlc5Rlo3aDFSSDIxVlZZNGgvWEhMZFRhYUkvbFFOMUhHUm02ZjJpVDhURjhMSHhSaDF4WlRNalExSVd4TXRoV253c1JiVjZzalMvQTRQUk5kVjUvMHdVc2FsTCt6blg1eXBNV1BpREE4ZHozcEhJY3V5d3pnWi9TeHJDTFR2S2g0WjFqdHRkK0k0a0taVXVFZUV5clJIOHpLOWpLM08rbURIUG5vN25BbzMvOGV0VFBiT1FU";
        const char* key = "7674140c7c1e0aaf98f8d3b240212151";

        AesKeyMix aesData = ParseB64AesData(StrRes(encryptedData), StrRes(key));
        if (!aesData.valid) {
            Serial.println(" > Failed to parse AES data");
            return false;
        }

        // Decrypt the data
        StrRes dataDecrypted = AES_Decrypt(
            StrRes((const char*)aesData.encryptedData.data, aesData.encryptedData.size),
            StrRes((const char*)aesData.key, 32),
            StrRes((const char*)aesData.iv, 16)
        );

        free((void*)aesData.encryptedData.data);

        if (dataDecrypted.data == NULL) {
            Serial.println(" > Failed to decrypt data");
            return false;
        }

        Serial.printf("  > Decrypted Data Content: %s\n", dataDecrypted.data);

        free((void*)dataDecrypted.data);
    }

    // full encryption / decryption test
    {
        const char* ogData = "\"This is a test\"";
        const char* password = "Hello123";

        StrRes encryptedData = AES_B64_Encrypt(StrRes(ogData), StrRes(password));
        if (encryptedData.data == NULL) {
            Serial.println(" > Failed to encrypt data");
            return false;
        }

        StrRes decryptedData = AES_B64_Decrypt(encryptedData, StrRes(password));
        if (decryptedData.data == NULL) {
            Serial.println(" > Failed to decrypt data");
            free((void*)encryptedData.data);
            return false;
        }

        Serial.printf("  > Original Data: %s\n", ogData);
        Serial.printf("  > Encrypted Size: %d\n", encryptedData.size);
        Serial.printf("  > Decrypted Size: %d\n", decryptedData.size);
        Serial.printf("  > Decrypted Data: %s\n", decryptedData.data);

        if (strcmp(ogData, decryptedData.data) != 0) {
            Serial.println(" > Decrypted data does not match original data");
            free((void*)encryptedData.data);
            free((void*)decryptedData.data);
            return false;
        }

        free((void*)encryptedData.data);
        free((void*)decryptedData.data);
    }

    return true;
}

StrRes AES_B64_Decrypt(StrRes input, StrRes password)
{
    if (input.data == NULL || password.data == NULL) {
        return StrRes(NULL, 0);
    }

    AesKeyMix aesData = ParseB64AesData(input, password);
    if (!aesData.valid) {
        Serial.println(" > Failed to parse AES data");
        return StrRes(NULL, 0);
    }

    // Decrypt the data
    StrRes dataDecrypted = AES_Decrypt(
        StrRes((const char*)aesData.encryptedData.data, aesData.encryptedData.size),
        StrRes((const char*)aesData.key, 32),
        StrRes((const char*)aesData.iv, 16)
    );

    free((void*)aesData.encryptedData.data);

    if (dataDecrypted.data == NULL) {
        Serial.println(" > Failed to decrypt data");
       return StrRes(NULL, 0);
    }

    Serial.printf("  > Decrypted Data Content: %s\n", dataDecrypted.data);

    //free((void*)dataDecrypted.data);
    return dataDecrypted;
}

AesKeyMix ParseB64AesData(StrRes data, StrRes password)
{
    if (data.data == NULL || password.data == NULL) {
        return invalid;
    }

    char phraseB64_1[5 * 1024];
    memset(phraseB64_1, 0, sizeof(phraseB64_1));
    strncpy(phraseB64_1, data.data, min((unsigned int)data.size, sizeof(phraseB64_1)));

    // Convert the phrase from base64 to bytes
    size_t phraseLen_1 = 0;
    unsigned char phraseBytes_1[4 * 1024];
    int res = mbedtls_base64_decode(
        phraseBytes_1, sizeof(phraseBytes_1), &phraseLen_1, 
        (const unsigned char*)phraseB64_1, strlen(phraseB64_1));
    if (res != 0) {
        Serial.printf(" > Failed to decode base64 phrase: %d\n", res);

        char errBuf[1024];
        mbedtls_strerror(res, errBuf, sizeof(errBuf));
        Serial.printf("Error: %s\n", errBuf);

        return invalid;
    }

    // Serial.printf(" > Phrase Bytes (%d): ", phraseLen_1);
    // for (int i = 0; i < phraseLen_1; i++) {
    //     char test[] = {0, 0};
    //     test[0] = phraseBytes_1[i];
    // 	Serial.print(test);
    // }
    // Serial.println();

    char phraseB64_2[5 * 1024];
    memset(phraseB64_2, 0, sizeof(phraseB64_2));
    strncpy(phraseB64_2, (const char*)phraseBytes_1, min(phraseLen_1, sizeof(phraseB64_2)));

    // Convert the phrase from base64 to bytes
    size_t phraseLen_2 = 0;
    unsigned char phraseBytes_2[4 * 1024];
    res = mbedtls_base64_decode(
        phraseBytes_2, sizeof(phraseBytes_2), &phraseLen_2, 
        (const unsigned char*)phraseB64_2, strlen(phraseB64_2));
    if (res != 0) {
        Serial.printf(" > Failed to decode base64 phrase: %d\n", res);

        char errBuf[1024];
        mbedtls_strerror(res, errBuf, sizeof(errBuf));
        Serial.printf("Error: %s\n", errBuf);

        return invalid;
    }

    // Serial.printf(" > Phrase Bytes (%d): ", phraseLen_2);
    // for (int i = 0; i < phraseLen_2; i++) {
    // 	Serial.print(phraseBytes_2[i], HEX);
    // 	Serial.print(" ");
    // }
    // Serial.println();

    // for (int i = 0; i < phraseLen_2; i++) {
    //     char test[] = {0, ' ', 0};
    //     test[0] = phraseBytes_2[i];
    // 	Serial.print(test);
    // }
    // Serial.println();

    // Format:
    // STRING "Salted__"
    // 8 bytes salt
    // Rest is encrypted data

    // Extract the salt
    const char* saltStart = strstr((const char*)phraseBytes_2, "Salted__");
    if (saltStart == NULL) {
        Serial.println(" > Failed to extract salt from encrypted data");
        return invalid;
    }

    saltStart += strlen("Salted__");
    const char* saltEnd = saltStart + 8;
    if (saltEnd == NULL) {
        Serial.println(" > Failed to extract salt from encrypted data");
        return invalid;
    }

    unsigned char saltBytes[8];
    memcpy(saltBytes, saltStart, 8);

    // Serial.print(" > Salt: ");
    // for (int i = 0; i < 8; i++) {
    // 	Serial.print(saltBytes[i], HEX);
    // 	Serial.print(" ");
    // }
    // Serial.println();


    // Extract the encrypted data
    const char* encryptedDataStart = saltEnd;
    size_t encryptedDataLen = phraseLen_2 - (encryptedDataStart - (const char*)phraseBytes_2);

    unsigned char encryptedDataBytes[4 * 1024];
    memcpy(encryptedDataBytes, encryptedDataStart, encryptedDataLen);

    // Serial.print(" > Encrypted Data: ");
    // for (int i = 0; i < encryptedDataLen; i++) {
    // 	Serial.print(encryptedDataBytes[i], HEX);
    // 	Serial.print(" ");
    // }
    // Serial.println();

    // Generate the key and IV from the password and salt
    unsigned char KeyBytes[32];
    unsigned char IvBytes[16];

    res = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), 
        saltBytes, (const unsigned char*)password.data, strlen(password.data), 1, KeyBytes, IvBytes);
    
    if (res == 0) {
        Serial.printf(" > Failed to generate key and IV: %d\n", res);
        return invalid;
    }


    // Serial.print(" > Key: ");
    // for (int i = 0; i < 32; i++) {
    // 	Serial.print(KeyBytes[i], HEX);
    // 	Serial.print(" ");
    // }
    // Serial.println();

    // Serial.print(" > IV: ");
    // for (int i = 0; i < 16; i++) {
    // 	Serial.print(IvBytes[i], HEX);
    // 	Serial.print(" ");
    // }
    // Serial.println();

    // malloc encrypted data
    unsigned char* encryptedDataBytesMalloc = (unsigned char*)malloc(encryptedDataLen + 1);
    memcpy(encryptedDataBytesMalloc, encryptedDataBytes, encryptedDataLen);
    encryptedDataBytesMalloc[encryptedDataLen] = '\0';
    return AesKeyMix{(const char*)KeyBytes, (const char*)IvBytes, (const char*)saltBytes, StrRes((const char*)encryptedDataBytesMalloc, encryptedDataLen)};
}



StrRes AES_B64_Encrypt(StrRes input, StrRes password)
{
    if (input.data == NULL || password.data == NULL) {
        return StrRes(NULL, 0);
    }

    bool newYes = false;
    if (input.size % 16 != 0) {
        // pad
        size_t newSize = input.size + (16 - (input.size % 16));
        char* newInput = (char*)malloc(newSize);
        memcpy(newInput, input.data, input.size);
        memset(newInput + input.size, 0, newSize - input.size);
        input = StrRes(newInput, newSize);
        newYes = true;
    }

    StrRes lol = CreateB64AesData(input, password);

    if (newYes)
        free((void*)input.data);

    return lol;
}


StrRes CreateB64AesData(StrRes data, StrRes password)
{
    if (data.data == NULL || password.data == NULL) {
        return StrRes(NULL, 0);
    }

    AesKeyMix aesData = invalid;

    // Generate a random salt
    // Write into aesData.salt
    for (int i = 0; i < 8; i++)
        aesData.salt[i] = random(0, 255);
    
    // Generate the key and IV from the password and salt
    unsigned char KeyBytes[32];
    unsigned char IvBytes[16];

    int res = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), 
        (const unsigned char*)aesData.salt, (const unsigned char*)password.data, strlen(password.data), 1, KeyBytes, IvBytes);
        
    if (res == 0) {
        Serial.printf(" > Failed to generate key and IV: %d\n", res);
        return StrRes(NULL, 0);
    }

    // Serial.print(" > Key: ");
    // for (int i = 0; i < 32; i++) {
    // 	Serial.print(KeyBytes[i], HEX);
    // 	Serial.print(" ");
    // }
    // Serial.println();

    // Serial.print(" > IV: ");
    // for (int i = 0; i < 16; i++) {
    // 	Serial.print(IvBytes[i], HEX);
    // 	Serial.print(" ");
    // }
    // Serial.println();

    // Encrypt the data
    StrRes encryptedData = AES_Encrypt(data, StrRes((const char*)KeyBytes, 32), StrRes((const char*)IvBytes, 16));
    if (encryptedData.data == NULL) {
        Serial.println(" > Failed to encrypt data");
        return StrRes(NULL, 0);
    }

    // malloc encrypted data
    size_t encryptedDataMallocSize = encryptedData.size + 8 + 8;
    unsigned char* encryptedDataBytesMalloc = (unsigned char*)malloc(encryptedDataMallocSize);
    memcpy(encryptedDataBytesMalloc, "Salted__", 8);
    memcpy(encryptedDataBytesMalloc + 8, aesData.salt, 8);
    memcpy(encryptedDataBytesMalloc + 16, encryptedData.data, encryptedData.size);

    free((void*)encryptedData.data);

    // Convert to first Base64
    size_t encryptedDataBytesMallocLen;
    unsigned char encryptedDataBytesB64_1[4 * 1024];
    res = mbedtls_base64_encode(
        encryptedDataBytesB64_1, sizeof(encryptedDataBytesB64_1), &encryptedDataBytesMallocLen, 
        encryptedDataBytesMalloc, encryptedDataMallocSize);
    
    if (res != 0) {
        Serial.printf(" > Failed to encode base64 phrase: %d\n", res);

        char errBuf[1024];
        mbedtls_strerror(res, errBuf, sizeof(errBuf));
        Serial.printf("Error: %s\n", errBuf);

        free((void*)encryptedDataBytesMalloc);

        return StrRes(NULL, 0);
    }

    free((void*)encryptedDataBytesMalloc);

    // Convert to second Base64
    size_t encryptedDataBytesB64_1Len;
    unsigned char encryptedDataBytesB64_2[4 * 1024];
    res = mbedtls_base64_encode(
        encryptedDataBytesB64_2, sizeof(encryptedDataBytesB64_2), &encryptedDataBytesB64_1Len, 
        encryptedDataBytesB64_1, encryptedDataBytesMallocLen);
    
    if (res != 0) {
        Serial.printf(" > Failed to encode base64 phrase: %d\n", res);

        char errBuf[1024];
        mbedtls_strerror(res, errBuf, sizeof(errBuf));
        Serial.printf("Error: %s\n", errBuf);

        return StrRes(NULL, 0);
    }

    // make new malloc
    unsigned char* encryptedDataBytesMalloc2 = (unsigned char*)malloc(encryptedDataBytesB64_1Len + 1);
    memcpy(encryptedDataBytesMalloc2, encryptedDataBytesB64_2, encryptedDataBytesB64_1Len);
    encryptedDataBytesMalloc2[encryptedDataBytesB64_1Len] = '\0';

    return StrRes((const char*)encryptedDataBytesMalloc2, encryptedDataBytesB64_1Len);
}








// check thats its a JSONNNNNNNNNN STR lol
StrRes AES_Decrypt(StrRes input, StrRes key, StrRes iv) 
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    if (mbedtls_aes_setkey_dec(&aes, (const unsigned char*)key.data, key.size * 8) != 0) {
        Serial.println("Failed to set AES decryption key");
        return StrRes(NULL, 0);
    }

    size_t inputLen = input.size;
    size_t outputLen = inputLen;
    unsigned char* output = (unsigned char*)malloc(outputLen + 1);
    if (output == NULL) {
        Serial.println("Failed to allocate memory for AES decryption output");
        return StrRes(NULL, 0);
    }
    memset(output, 0, outputLen + 1);



    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, input.size, (unsigned char*)iv.data, (const unsigned char*)input.data, output) != 0) {
        Serial.println("Failed to decrypt data with AES");
        free(output);
        return StrRes(NULL, 0);
    }

    mbedtls_aes_free(&aes);

    if (output[0] == '"') {
        int lastIndex = outputLen - 1;
        while (output[lastIndex] != '"') {
            lastIndex--;
        }
        lastIndex++;
        if (lastIndex < outputLen - 1) {
            output[lastIndex] = '\0';
        }
        outputLen = lastIndex;
    } else {
        Serial.printf("> FIRST CHAR IS NOT QUOTE: %c\n", output[0]);
    }

    return StrRes((const char*)output, outputLen);
}

StrRes AES_Encrypt(StrRes input, StrRes key, StrRes iv) 
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    if (mbedtls_aes_setkey_enc(&aes, (const unsigned char*)key.data, key.size * 8) != 0) {
        Serial.println("Failed to set AES encryption key");
        return StrRes(NULL, 0);
    }

    size_t inputLen = input.size;
    size_t outputLen = inputLen;
    unsigned char* output = (unsigned char*)malloc(outputLen);
    if (output == NULL) {
        Serial.println("Failed to allocate memory for AES encryption output");
        return StrRes(NULL, 0);
    }
    memset(output, 0, outputLen);

    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, input.size, (unsigned char*)iv.data, (const unsigned char*)input.data, output) != 0) {
        Serial.println("Failed to encrypt data with AES");
        free(output);
        return StrRes(NULL, 0);
    }

    mbedtls_aes_free(&aes);
    return StrRes((const char*)output, outputLen);
}