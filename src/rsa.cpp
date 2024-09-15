#include "rsa.h"
#include <Arduino.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>


bool testKeyGen()
{
    Serial.println("> Doing RSA Key Gen Test!");

    bool res = Crypto_GenerateKeyPair();
    if (res) {
        Serial.println("Key pair generated successfully");
    } else {
        Serial.println("Key pair generation failed");
    }
    return res;
    
    // This test function will create a 2048 bit RSA key pair and print it in PEM format

    // Initialize the structures
    Serial.println("> Initializing RSA Context");
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // Initialize the contexts
    Serial.println("> Initializing Entropy and CTR_DRBG");
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Seed the entropy
    Serial.println("> Seeding Entropy");
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    // Generate the key pair
    Serial.println("> Generating RSA Key Pair");
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);

    // Print the key pair
    // Serial.println("> Printing RSA Key Pair");
    // char buf[1024];
    // mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    // mbedtls_mpi_init(&N);
    // mbedtls_mpi_init(&P);
    // mbedtls_mpi_init(&Q);
    // mbedtls_mpi_init(&D);
    // mbedtls_mpi_init(&E);
    // mbedtls_mpi_init(&DP);
    // mbedtls_mpi_init(&DQ);
    // mbedtls_mpi_init(&QP);
    // mbedtls_rsa_export(&rsa, &N, &P, &Q, &D, &E);
    // mbedtls_rsa_export_crt(&rsa, &DP, &DQ, &QP);
    // size_t oLen;
    // mbedtls_mpi_write_string(&N, 16, buf, sizeof(buf), &oLen);
    // Serial.println(buf);
    // mbedtls_mpi_write_string(&P, 16, buf, sizeof(buf), &oLen);
    // Serial.println(buf);
    // mbedtls_mpi_write_string(&Q, 16, buf, sizeof(buf), &oLen);
    // Serial.println(buf);
    // mbedtls_mpi_write_string(&D, 16, buf, sizeof(buf), &oLen);
    // Serial.println(buf);
    // mbedtls_mpi_write_string(&E, 16, buf, sizeof(buf), &oLen);
    // Serial.println(buf);
    // mbedtls_mpi_write_string(&DP, 16, buf, sizeof(buf), &oLen);
    // Serial.println(buf);
    // mbedtls_mpi_write_string(&DQ, 16, buf, sizeof(buf), &oLen);
    // Serial.println(buf);
    // mbedtls_mpi_write_string(&QP, 16, buf, sizeof(buf), &oLen);
    // Serial.println(buf);
    // works

    // Print the key pair in PEM format
    Serial.println("> Printing RSA Key Pair (1)");
    char buf[1024];
    mbedtls_pk_context pk;
    Serial.println("> Printing RSA Key Pair (2)");
    mbedtls_pk_init(&pk);
    Serial.println("> Printing RSA Key Pair (3)");
    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    Serial.println("> Printing RSA Key Pair (4)");
    mbedtls_rsa_copy(mbedtls_pk_rsa(pk), &rsa);
    Serial.println("> Printing RSA Key Pair (5)");
    mbedtls_pk_write_key_pem(&pk, (unsigned char *)buf, sizeof(buf));
    Serial.println("> Printing RSA Key Pair (6)");
    Serial.println(buf);
    Serial.println("> Printing RSA Key Pair (7)");
    mbedtls_pk_free(&pk);
    Serial.println("> Printing RSA Key Pair (8)");



    // Free the contexts
    Serial.println("> Freeing RSA Context");
    mbedtls_rsa_free(&rsa);
    Serial.println("> Freeing Entropy and CTR_DRBG");
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    Serial.println("> Done RSA Key Gen Test!");
}


static unsigned char privKeyPem[2000];
static unsigned char pubKeyPem[1000];

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


bool Crypto_GenerateKeyPair(void) 
{
	bool ret = false;	 //== ESP_OK

	/* Initialise variables */
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctrDrbg);
	mbedtls_pk_init(&pk);

	puts("Seeding the random number generator...");
	if ((ret = mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy, (const unsigned char *)personalizationString, strlen(personalizationString))) != 0) {
		printf("Failed to seed rng\nmbedtls_ctr_drbg_seed returned %d\n", ret);
		goto cleanup;
	}

	if ((ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0) {
		printf("pk_setup failed: %i\n", ret);
	}

	printf(" ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE);

	/* force task yield before generate a key that could take several seconds to do */
	taskYIELD();
	puts("Generating a key pair takes up to 20s and will likely trigger task watchdog during this process");

	if ((ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctrDrbg, KEY_SIZE, EXPONENT)) != 0) {
		printf(" failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret);
		goto cleanup;
	}

	/* pk struct already intitialised */
	if (!Crypto_Verify(true)) {
		goto cleanup;
	}

	puts("Writing public key to string(PEM format)....");

	//unsigned char pubKeyPem[1000];
	memset(pubKeyPem, 0, sizeof(pubKeyPem));
	if (mbedtls_pk_write_pubkey_pem(&pk, pubKeyPem, sizeof(pubKeyPem)) != 0) {
		puts("Err: Write public key to string failed");
		goto cleanup;
	}
    else
    {
        const char* t = (const char*)pubKeyPem;
        Serial.println(t);
    }


	puts("Writing private key to string(PEM format)....");

	memset(privKeyPem, 0, sizeof(privKeyPem));
	ret = mbedtls_pk_write_key_pem(&pk, privKeyPem, sizeof(privKeyPem));
	if (ret != 0) {
		printf("write private key to string failed with code %04x\n", ret);
	}
    else
    {
        const char* t = (const char*)privKeyPem;
        Serial.println(t);
    }

	puts(" ok\n  .");
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
			printf("Unable to parse %d\n", ret);
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

	puts("RSA keys confirmed");

exit:
	if (!initisalised) {
		mbedtls_pk_free(&pk);
	}
	return !ret;
}