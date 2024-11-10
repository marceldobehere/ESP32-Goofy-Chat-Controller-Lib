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

bool aesTest()
{
    Serial.println("> Testing AES encryption and decryption");

    const char* encryptedData = "VTJGc2RHVmtYMStQRlc5Rlo3aDFSSDIxVlZZNGgvWEhMZFRhYUkvbFFOMUhHUm02ZjJpVDhURjhMSHhSaDF4WlRNalExSVd4TXRoV253c1JiVjZzalMvQTRQUk5kVjUvMHdVc2FsTCt6blg1eXBNV1BpREE4ZHozcEhJY3V5d3pnWi9TeHJDTFR2S2g0WjFqdHRkK0k0a0taVXVFZUV5clJIOHpLOWpLM08rbURIUG5vN25BbzMvOGV0VFBiT1FU";
    const char* key = "7674140c7c1e0aaf98f8d3b240212151";

    char phraseB64_1[5 * 1024];
    memset(phraseB64_1, 0, sizeof(phraseB64_1));
    strncpy(phraseB64_1, encryptedData, min(strlen(encryptedData), sizeof(phraseB64_1)));

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

        return false;
    }

    Serial.printf(" > Phrase Bytes (%d): ", phraseLen_1);
    for (int i = 0; i < phraseLen_1; i++) {
        char test[] = {0, 0};
        test[0] = phraseBytes_1[i];
    	Serial.print(test);
    }
    Serial.println();

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

        return false;
    }

    Serial.printf(" > Phrase Bytes (%d): ", phraseLen_2);
    for (int i = 0; i < phraseLen_2; i++) {
    	Serial.print(phraseBytes_2[i], HEX);
    	Serial.print(" ");
    }
    Serial.println();

    for (int i = 0; i < phraseLen_2; i++) {
        char test[] = {0, ' ', 0};
        test[0] = phraseBytes_2[i];
    	Serial.print(test);
    }
    Serial.println();

    // Format:
    // STRING "Salted__"
    // 8 bytes salt
    // Rest is encrypted data

    // We need to extract the salt and the encrypted data
    // Then we need to generate the key and IV from the password and salt
    // Then we need to decrypt the data with the key and IV



    // Extract the salt
    const char* saltStart = strstr((const char*)phraseBytes_2, "Salted__");
    if (saltStart == NULL) {
        Serial.println(" > Failed to extract salt from encrypted data");
        return false;
    }

    saltStart += strlen("Salted__");
    const char* saltEnd = saltStart + 8;
    if (saltEnd == NULL) {
        Serial.println(" > Failed to extract salt from encrypted data");
        return false;
    }

    unsigned char saltBytes[8];
    memcpy(saltBytes, saltStart, 8);

    Serial.print(" > Salt: ");
    for (int i = 0; i < 8; i++) {
    	Serial.print(saltBytes[i], HEX);
    	Serial.print(" ");
    }
    Serial.println();


    // Extract the encrypted data
    const char* encryptedDataStart = saltEnd;
    size_t encryptedDataLen = phraseLen_2 - (encryptedDataStart - (const char*)phraseBytes_2);

    unsigned char encryptedDataBytes[4 * 1024];
    memcpy(encryptedDataBytes, encryptedDataStart, encryptedDataLen);

    Serial.print(" > Encrypted Data: ");
    for (int i = 0; i < encryptedDataLen; i++) {
    	Serial.print(encryptedDataBytes[i], HEX);
    	Serial.print(" ");
    }
    Serial.println();

    // // Generate the key and IV from the password and salt
    // unsigned char keyBytes[16];
    // unsigned char ivBytes[16];
    // mbedtls_md_context_t md_ctx;

    // mbedtls_md_init(&md_ctx);    
    // mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_MD5), 1);
    // mbedtls_md_starts(&md_ctx);
    // mbedtls_md_update(&md_ctx, (const unsigned char*)key, strlen(key));
    // mbedtls_md_update(&md_ctx, saltBytes, 8);
    // mbedtls_md_finish(&md_ctx, keyBytes);

    // mbedtls_md_init(&md_ctx);
    // mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_MD5), 1);
    // mbedtls_md_starts(&md_ctx);
    // mbedtls_md_update(&md_ctx, (const unsigned char*)key, strlen(key));
    // mbedtls_md_update(&md_ctx, saltBytes, 8);
    // mbedtls_md_update(&md_ctx, keyBytes, 16);
    // mbedtls_md_finish(&md_ctx, ivBytes);

    // Generate the Key and IV using EVP_BytesToKey

    unsigned char KeyBytes[32];
    unsigned char IvBytes[16];

    // EVP_BytesToKey
    // https://stackoverflow.com/questions/29534656/c-version-of-openssl-evp-bytestokey-method
    

    // Use This function to generate the key and IV
    // WOLFSSL_API int wolfSSL_EVP_BytesToKey(const WOLFSSL_EVP_CIPHER* type,
    //     const WOLFSSL_EVP_MD* md, const byte* salt,
    //     const byte* data, int sz, int count, byte* key, byte* iv);

    wolfSSL_Init();

    Serial.printf(" > Password/Data: %s\n", key);

    res = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), 
        saltBytes, (const unsigned char*)key, strlen(key), 1, KeyBytes, IvBytes);
    
    if (res == 0) {
        Serial.printf(" > Failed to generate key and IV: %d\n", res);
        return false;
    }
    Serial.printf(" > Size: %d\n", res);


    Serial.print(" > Key: ");
    for (int i = 0; i < 32; i++) {
    	Serial.print(KeyBytes[i], HEX);
    	Serial.print(" ");
    }
    Serial.println();

    Serial.print(" > IV: ");
    for (int i = 0; i < 16; i++) {
    	Serial.print(IvBytes[i], HEX);
    	Serial.print(" ");
    }
    Serial.println();

    // Decrypt the data
    StrRes dataDecrypted = AES_Decrypt(
        StrRes((const char*)encryptedDataBytes, encryptedDataLen),
        StrRes((const char*)KeyBytes, 32),
        StrRes((const char*)IvBytes, 16)
    );

    if (dataDecrypted.data == NULL) {
        Serial.println(" > Failed to decrypt data");
        return false;
    }

    Serial.printf("  > Decrypted Data Content: %s\n", dataDecrypted.data);





    // // Serial.printf(" > Phrase Bytes (%d): ", phraseLen);
    // // for (int i = 0; i < phraseLen; i++) {
    // // 	Serial.print(phraseBytes[i], HEX);
    // // 	Serial.print(" ");
    // // }
    
    // StrRes dataDecrypted = AES_Decrypt(StrRes((const char*)phraseBytes, phraseLen), key);
    // if (dataDecrypted.data == NULL) {
    //     Serial.println(" > Failed to decrypt data");
    //     return false;
    // }

    // Serial.printf("  > Decrypted Data Content: %s\n", dataDecrypted.data);

    
    // return true;
    return false;
}

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
    unsigned char* output = (unsigned char*)malloc(outputLen);
    if (output == NULL) {
        Serial.println("Failed to allocate memory for AES decryption output");
        return StrRes(NULL, 0);
    }
    memset(output, 0, outputLen);



    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, input.size, (unsigned char*)iv.data, (const unsigned char*)input.data, output) != 0) {
        Serial.println("Failed to decrypt data with AES");
        free(output);
        return StrRes(NULL, 0);
    }

    mbedtls_aes_free(&aes);

    return StrRes((const char*)output, outputLen);
}

StrRes AES_Encrypt(StrRes input, const char* key) 
{
    return StrRes(NULL, 0);
}