#include "rsa.h"
#include <Arduino.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include "yes_fs.h"
#include <mbedtls/error.h>

bool testKeyGen()
{
    Serial.println("> Doing RSA Key Gen Test!");

    bool res = Crypto_GenerateKeyPair(true);
    if (!res) {
        Serial.println("Key pair generation failed");
        return false;
    }

    res = Crypto_Verify(false);
    if (!res) {
        Serial.println("Key pair verification failed");
        return false;
    }

    const char* privKeyPath = "/test_privkey.pem";
    const char* pubKeyPath = "/test_pubkey.pem";

    res = Crypto_WriteKeyToFile(privKeyPath, pubKeyPath);
    if (!res) {
        Serial.println("Key pair write to file failed");
        return false;
    }

    
    res = Crypto_ReadKeyFromFile(privKeyPath, pubKeyPath);
    if (!res) {
        Serial.println("Key pair read from file failed");
        return false;
    }

    Serial.println("> RSA Key Gen Test Done!");
    return true;
}


unsigned char privKeyPem[PRIV_KEY_PEM_SIZE];
unsigned char pubKeyPem[PUB_KEY_PEM_SIZE];

uint32_t privKeyOffset = 0 * CONFIG_WL_SECTOR_SIZE;
uint32_t pubKeyOffset = 1 * CONFIG_WL_SECTOR_SIZE;
uint32_t tamperDataOffset = 2 * CONFIG_WL_SECTOR_SIZE;
esp_partition_t *partStorage = NULL;

mbedtls_pk_context pk;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctrDrbg;

const char personalizationString[11] = "rsa_genkey";	//requires static size allocation in classes
#define KEY_SIZE 2048
#define EXPONENT 65537


bool Crypto_GenerateKeyPair(bool shouldPrint) 
{
	bool ret = false;	 //== ESP_OK

	/* Initialise variables */
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctrDrbg);
	mbedtls_pk_init(&pk);

	puts("Seeding the random number generator...");
	if ((ret = mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy, (const unsigned char *)personalizationString, strlen(personalizationString))) != 0) {
		Serial.printf("Failed to seed rng\nmbedtls_ctr_drbg_seed returned %d\n", ret);
		goto cleanup;
	}

	if ((ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0) {
		Serial.printf("pk_setup failed: %i\n", ret);
	}

	Serial.printf("Generating the RSA key [ %d-bit ]...", KEY_SIZE);

	/* force task yield before generate a key that could take several seconds to do */
	taskYIELD();
	puts("Generating a key pair takes up to 20s and will likely trigger task watchdog during this process");

	if ((ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctrDrbg, KEY_SIZE, EXPONENT)) != 0) {
		Serial.printf(" failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret);
		goto cleanup;
	}

	/* pk struct already intitialised */
	if (!Crypto_Verify(true)) {
		goto cleanup;
	}

	puts("Writing public key to string(PEM format)....");

	//unsigned char pubKeyPem[1000];
	memset(pubKeyPem, 0, PUB_KEY_PEM_SIZE);
	if (mbedtls_pk_write_pubkey_pem(&pk, pubKeyPem, PUB_KEY_PEM_SIZE) != 0) {
		puts("Err: Write public key to string failed");
		goto cleanup;
	}
    else
    {
        const char* t = (const char*)pubKeyPem;
        if (shouldPrint)
            Serial.println(t);
    }


	puts("Writing private key to string(PEM format)....");

	memset(privKeyPem, 0, PRIV_KEY_PEM_SIZE);
	ret = mbedtls_pk_write_key_pem(&pk, privKeyPem, PRIV_KEY_PEM_SIZE);
	if (ret != 0) {
		Serial.printf("write private key to string failed with code %04x\n", ret);
	}
    else
    {
        const char* t = (const char*)privKeyPem;
        if (shouldPrint)
            Serial.println(t);
    }

	puts("Success, Key pair created.");

cleanup:
	mbedtls_pk_free(&pk);
	mbedtls_ctr_drbg_free(&ctrDrbg);
	mbedtls_entropy_free(&entropy);

	return !ret;
}

bool Crypto_Verify(bool initisalised) {
	int ret = 0;
	/* Key has no password - parse in NULL size 0 */
	if (!initisalised) {
		mbedtls_pk_init(&pk);
		if ((ret = mbedtls_pk_parse_key(&pk, privKeyPem, strlen((const char *)privKeyPem) + 1, NULL, 0)) != 0) {
			Serial.printf("Unable to parse %d\n", ret);
			goto exit;
		}
	}

	/* Asumme keys are already loaded into internal variables */
	if ((ret = mbedtls_rsa_check_privkey(mbedtls_pk_rsa(pk))) != 0) {
		puts("Err: RSA context does not contain an rsa private key");
		goto exit;
	}

	if ((ret = mbedtls_rsa_check_pubkey(mbedtls_pk_rsa(pk))) != 0) {
		puts("Err: RSA context does not contain an rsa public key");
		goto exit;
	}

	puts("> RSA keys valid!");

exit:
	if (!initisalised) {
		mbedtls_pk_free(&pk);
	}
	return !ret;
}

bool Crypto_WriteKeyToFile(const char* privKeyPath, const char* pubKeyPath) 
{
    Serial.println("> Writing keys to file");

    bool res = writeFile(privKeyPath, (const char*)privKeyPem);
    if (!res) {
        Serial.println("Failed to write private key to file");
        return false;
    }

    res = writeFile(pubKeyPath, (const char*)pubKeyPem);
    if (!res) {
        Serial.println("Failed to write public key to file");
        return false;
    }

    Serial.println("> Keys written to file successfully");
    return true;
}

bool Crypto_ReadKeyFromFile(const char* privKeyPath, const char* pubKeyPath) 
{
    Serial.println("> Reading keys from file");

    FileRead privKey = readFile(privKeyPath);
    if (privKey.data == NULL) {
        Serial.println("Failed to read private key from file");
        return false;
    }

    FileRead pubKey = readFile(pubKeyPath);
    if (pubKey.data == NULL) {
        Serial.println("Failed to read public key from file");
        return false;
    }

    Serial.println("> PARSED CRYPTO KEYS:");
    Serial.println(" > Private Key:");
    Serial.println(privKey.data);
    Serial.println(" > Public Key:");
    Serial.println(pubKey.data);

    // Check size with the internal variables
    if (privKey.size > PRIV_KEY_PEM_SIZE || pubKey.size > PUB_KEY_PEM_SIZE) {
        Serial.println("Key size mismatch");
        return false;
    }

    // Write the keys to the internal variables
    memcpy(privKeyPem, privKey.data, privKey.size + 1);
    memcpy(pubKeyPem, pubKey.data, pubKey.size + 1);

    // Verify the keys
    Crypto_Verify(false);

    free((void*)privKey.data);
    free((void*)pubKey.data);

    Serial.println("> Keys read from file successfully");
    return true;
}


bool CryptoInit()
{
    Serial.println("> Initialising Crypto");

    const char* privKeyPath = "/internal_privKey.pem";
    const char* pubKeyPath = "/internal_pubKey.pem";

    Serial.println("> Checking if keys exist");
    bool res = true;
    if (fileExists(privKeyPath) && fileExists(pubKeyPath)) 
    {
        Serial.println("> Reading keys");
        res = Crypto_ReadKeyFromFile(privKeyPath, pubKeyPath);
        if (res)
            return Crypto_Verify(false);
    }

    Serial.println("> Generating keys");
    res = Crypto_GenerateKeyPair(true);
    if (!res) {
        Serial.println("Failed to generate keys");
        return false;
    }

    res = Crypto_WriteKeyToFile(privKeyPath, pubKeyPath);
    if (!res) {
        Serial.println("Failed to write keys to file");
        return false;
    }
    
    return Crypto_Verify(false);
}

StrRes::StrRes(const char* data) : data(data), size(strlen(data)) {}

bool testEncDec()
{
    Serial.println("> Testing RSA encryption and decryption");

    Serial.printf("> Status: %d\n", Crypto_Verify(false));

    const char* data = "Hello World!";
    StrRes encryptedData = Crypt_Encrypt(data);
    if (encryptedData.data == NULL) {
        Serial.println("> Failed to encrypt data");
        return false;
    }

    StrRes decryptedData = Crypt_Decrypt(encryptedData);
    if (decryptedData.data == NULL) {
        Serial.println("> Failed to decrypt data");
        return false;
    }

    Serial.println(" > Original data:");
    Serial.println(data);
    // Serial.println(" > Encrypted data:");
    // Serial.println(encryptedData.data);
    // Serial.printf(" > Encrypted data (%d): ", encryptedData.size);
    // for (int i = 0; i < encryptedData.size; i++) {
    //     Serial.print(encryptedData.data[i], HEX);
    //     Serial.print(" ");
    // }
    // Serial.println();
    Serial.println(" > Decrypted data:");
    Serial.println(decryptedData.data);

    // check 
    if (strcmp(data, decryptedData.data) != 0) {
        Serial.println("> Decrypted data does not match original data");
        return false;
    }
    Serial.println("> Decrypted data matches original data");

    // free memory
    free((void*)encryptedData.data);
    free((void*)decryptedData.data);

    return true;
}

StrRes Crypt_Encrypt(StrRes data)
{
    Serial.println("> Encrypting data");

    // initialise the random number generator
    int ret;
    mbedtls_ctr_drbg_init(&ctrDrbg);
    mbedtls_entropy_init(&entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy, (const unsigned char *)personalizationString, strlen(personalizationString))) != 0) {
		Serial.printf("Failed to seed rng\nmbedtls_ctr_drbg_seed returned %d\n", ret);
		return StrRes(NULL, 0);
	}

    // load the public key
    mbedtls_pk_init(&pk);
    if ((ret = mbedtls_pk_parse_public_key(&pk, pubKeyPem, strlen((const char *)pubKeyPem) + 1)) != 0) {
        Serial.printf("Unable to parse %d\n", ret);

        char errBuf[1024];
        mbedtls_strerror(ret, errBuf, sizeof(errBuf));
        Serial.printf("Error: %s\n", errBuf);

        return StrRes(NULL, 0);
    }

    // encrypt data with the loaded public key
    // return the encrypted data

    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    size_t olen = 0;

    int res = mbedtls_pk_encrypt(&pk, 
        (const unsigned char*)data.data, data.size, 
        buf, &olen, sizeof(buf), 
        mbedtls_ctr_drbg_random, &ctrDrbg);
    
    if (res != 0) {
        Serial.printf("Failed to encrypt data: %d\n", res);
        char errBuf[1024];
        mbedtls_strerror(res, errBuf, sizeof(errBuf));
        Serial.printf("Error: %s\n", errBuf);
        return StrRes(NULL, 0);
    }

    Serial.println("> Data encrypted successfully");
    // malloc and copy the encrypted data
    char* encryptedData = (char*)malloc(olen + 1);
    if (encryptedData == NULL) {
        Serial.println("Failed to allocate memory for encrypted data");
        return StrRes(NULL, 0);
    }

    memcpy(encryptedData, buf, olen);
    encryptedData[olen] = '\0';

    mbedtls_pk_free(&pk);
    return StrRes(encryptedData, olen);
}

StrRes Crypt_Decrypt(StrRes data)
{
    Serial.println("> Decrypting data");

    // initialise the random number generator
    int ret;
    mbedtls_ctr_drbg_init(&ctrDrbg);
    mbedtls_entropy_init(&entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy, (const unsigned char *)personalizationString, strlen(personalizationString))) != 0) {
		Serial.printf("Failed to seed rng\nmbedtls_ctr_drbg_seed returned %d\n", ret);
		return StrRes(NULL, 0);
	}

    // load the public key
    mbedtls_pk_init(&pk);
    if ((ret = mbedtls_pk_parse_key(&pk, privKeyPem, strlen((const char *)privKeyPem) + 1, NULL, 0)) != 0) {
        Serial.printf("Unable to parse %d\n", ret);
        return StrRes(NULL, 0);
    }

    // decrypt data with the loaded private key
    // return the decrypted data

    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    size_t olen = 0;

    int res = mbedtls_pk_decrypt(&pk, 
        (const unsigned char*)data.data, data.size, 
        buf, &olen, sizeof(buf), 
        mbedtls_ctr_drbg_random, &ctrDrbg);
    
    if (res != 0) {
        Serial.printf("Failed to decrypt data: %d\n", res);
        char errBuf[1024];
        mbedtls_strerror(res, errBuf, sizeof(errBuf));
        Serial.printf("Error: %s\n", errBuf);
        return StrRes(NULL, 0);
    }

    Serial.println("> Data decrypted successfully");
    // malloc and copy the decrypted data
    char* decryptedData = (char*)malloc(olen + 1);
    if (decryptedData == NULL) {
        Serial.println("Failed to allocate memory for decrypted data");
        return StrRes(NULL, 0);
    }

    memcpy(decryptedData, buf, olen);
    decryptedData[olen] = '\0';

    mbedtls_pk_free(&pk);
    return StrRes(decryptedData, olen);
}