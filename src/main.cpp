#include <Arduino.h>
#include "WiFi.h"
#include <SocketIoClient.h>
#include "init_wifi.h"
#include "LittleFS.h"
#include "rsa.h"
#include "aes.h"
#include "yes_fs.h"
#include "mbedtls/base64.h"
#include <ArduinoJson.h>
#include "symmKey.h"

bool initFS();
bool initWebsocket();
SocketIoClient webSocket;
bool initSuccess;

SET_LOOP_TASK_STACK_SIZE(32 * 1024); // 32KB

void setup() {
	
	Serial.begin(9600);
	initSuccess = true;

	initSuccess &= initFS();
	if (!initSuccess) return;
	// initSuccess &= testFS();
	// if (!initSuccess) return;
	// initSuccess &= testKeyGen();
	// if (!initSuccess) return;
	initSuccess &= CryptoInit();
	if (!initSuccess) return;
	initSuccess &= testEncDec();
	if (!initSuccess) return;
	initSuccess &= aesTest();
	if (!initSuccess) return;
	initSuccess &= initSymmKeyStuff();
	if (!initSuccess) return;
	initSuccess &= initWifi();
	if (!initSuccess) return;
	initSuccess &= initWebsocket();
	if (!initSuccess) return;
	

	Serial.println("> Setup done!");
}

void loop() {
	if (!initSuccess)
		return;
	
	// delay(10000);
	// Serial.println("Hello World!");
	webSocket.loop();
}

StrRes decryptBase64RsaArr(JsonArray dataContentArr) {
	if (dataContentArr.isNull())
		return StrRes(NULL, 0);

	char* resultConcatStr = (char*)malloc(6 * 1024);
	memset(resultConcatStr, 0, sizeof(6 * 1024));

	for (int i = 0; i < dataContentArr.size(); i++) {
		const char* dataContent = dataContentArr[i];
		// Serial.printf("  > Data Content %d: %s\n", i, dataContent);

		char phraseB64[1 * 1024];
		memset(phraseB64, 0, sizeof(phraseB64));
		strncpy(phraseB64, dataContent, min(strlen(dataContent), sizeof(phraseB64)));

		// Convert the phrase from base64 to bytes
		size_t phraseLen = 0;
		unsigned char phraseBytes[1 * 1024];
		int res = mbedtls_base64_decode(
			phraseBytes, sizeof(phraseBytes), &phraseLen, 
			(const unsigned char*)phraseB64, strlen(phraseB64));
		if (res != 0) {
			Serial.printf("  > Failed to decode base64 phrase: %d\n", res);

			char errBuf[1024];
			mbedtls_strerror(res, errBuf, sizeof(errBuf));
			Serial.printf("Error: %s\n", errBuf);

			free(resultConcatStr);
			return StrRes(NULL, 0);
		}

		// Serial.printf("  > Phrase Bytes (%d): ", phraseLen);
		// for (int i = 0; i < phraseLen; i++) {
		// 	Serial.print(phraseBytes[i], HEX);
		// 	Serial.print(" ");
		// }

		Serial.flush();

		StrRes dataDecrypted = Crypt_Decrypt(StrRes((const char*)phraseBytes, phraseLen));
		if (dataDecrypted.data == NULL) {
			Serial.println(" > Failed to decrypt data");
			free(resultConcatStr);
			return StrRes(NULL, 0);
		}

		Serial.printf("  > Decrypted Data Content: %s\n", dataDecrypted.data);

		strcat(resultConcatStr, dataDecrypted.data);
	}

	return StrRes(resultConcatStr);
}


bool initWebsocket()
{
	Serial.println("> Doing Websocket Init!");
	
	webSocket.on("connect", [](const char* payload, size_t length) {
		Serial.println("> Connected to WS!");

		Serial.println("> Sending login-1 event!");

		// Get the public key
		// "{\"public-key\":\"ABC\"}"
		char data[PUB_KEY_PEM_SIZE + 100];
		memset(data, 0, sizeof(data));

		// create temporary public key with \n replaced with \\n
		char tempPubKey[PUB_KEY_PEM_SIZE];
		memset(tempPubKey, 0, sizeof(tempPubKey));
		int i = 0;
		for (int i2 = 0; i2 < PUB_KEY_PEM_SIZE; i2++) {
			if (pubKeyPem[i2] == '\n') {
				tempPubKey[i++] = '\\';
				tempPubKey[i++] = 'n';
			} else if (pubKeyPem[i2] == '\0')
				break;
			else 
				tempPubKey[i++] = pubKeyPem[i2];
		}

		sprintf(data, "{\"public-key\": \"%s\"}", tempPubKey);

		Serial.printf(" > Sending Login Payload (%d %d %d): %s\n", 
		strlen((const char*)pubKeyPem), strlen(data), PUB_KEY_PEM_SIZE,
		data);
		webSocket.emit("login-1", data);
	});

	webSocket.on("disconnect", [](const char* payload, size_t length) {
		Serial.println("> Disconnected from WS!");
	});

	webSocket.on("message", [](const char* payload, size_t length) mutable {
		Serial.println("> Received message event from WS!");
		Serial.print(" > Payload: ");
		Serial.println(payload);
		JsonDocument doc;
		deserializeJson(doc, payload);

		int fromId = doc["from"];
		int toId = doc["to"];
		const char* date = doc["date"];
		const char* dataType = doc["data"]["type"];
		
		Serial.printf(" > From: %d\n", fromId);
		Serial.printf(" > To: %d\n", toId);
		Serial.printf(" > Date: %s\n", date);
		Serial.printf(" > Data Type: %s\n", dataType);

		if (strcmp(dataType, "aes") == 0) {
			Serial.println(" > Data Type: AES");
			Serial.flush();

			const char* dataContent = doc["data"]["data"];
			Serial.printf(" > Data Content: %s\n", dataContent);
			Serial.flush();

			const char* lastSymmKey = getSymmKey(fromId);
			if (lastSymmKey == NULL) {
				Serial.println(" > No symmetric key available");
				return;
			}

			StrRes decrypted = AES_B64_Decrypt(StrRes(dataContent), StrRes(lastSymmKey));
			if (decrypted.data == NULL) {
				Serial.println(" > Failed to decrypt AES data");
				return;
			}

			Serial.printf(" > Decrypted Data: %s\n", decrypted.data);

			if (decrypted.size < 4) {
				Serial.println(" > Invalid Decrypted Data");
				free((void*)decrypted.data);
				return;
			}

			// Parse JSON (Is a JSON in a string)
			JsonDocument msgDoc1;
			deserializeJson(msgDoc1, decrypted.data);
			Serial.println(" > Parsed JSON 1");

			// Parse actual JSON OBJ
			JsonDocument msgDoc;
			deserializeJson(msgDoc, msgDoc1.as<const char*>());
			Serial.println(" > Parsed JSON 2");

			const char* msgType = msgDoc["type"];
			Serial.printf(" > Message Type: %s\n", msgType);

			if (strcmp(msgType, "text") == 0) {
				const char* msgContent = msgDoc["data"];
				Serial.printf(" > Message Content: %s\n", msgContent);
			} else {
				Serial.printf(" > Invalid Message Type: %s\n", msgType);
			}


			free((void*)decrypted.data);
		}
		else if (strcmp(dataType, "rsa") == 0) {
			Serial.println(" > Data Type: RSA");
			Serial.flush();

			JsonObject obj = doc["data"];
			JsonArray dataContentArr = obj["data"].as<JsonArray>();

			Serial.printf(" > Data Content Arr Len: %d\n", dataContentArr.size());
			Serial.flush();

			StrRes decrypted = decryptBase64RsaArr(dataContentArr);
			if (decrypted.data == NULL) {
				Serial.println(" > Failed to decrypt RSA data");
				return;
			}

			Serial.printf(" > Decrypted Data: %s\n", decrypted.data);

			JsonDocument rsaDoc;
			deserializeJson(rsaDoc, decrypted.data);

			const char* msgType = rsaDoc["type"];
			
			if (strcmp(msgType, "symm-key") == 0) {
				const char* symmKey = rsaDoc["symmKey"];
				Serial.printf(" > Symmetric Key: %s\n", symmKey);
				setSymmKey(fromId, symmKey);
			} else {
				Serial.printf(" > Invalid Message Type: %s\n", msgType);
			}

			free((void*)decrypted.data);
		
		} else {
			Serial.println(" > Unknown data type");
			return;
		}
	});

	webSocket.on("login-2", [](const char* payload, size_t length) {
		Serial.println("> Received login-2 event from WS!");
		Serial.print(" > Payload: ");
		Serial.println(payload);
	});

	webSocket.on("login-1", [](const char* payload, size_t length) {
		Serial.println("> Received login-1 event from WS!");
		Serial.print(" > Payload: ");
		Serial.println(payload);

		// we get a payload like this
		// {"phrase":"JXqLmG80mMCTMK0FWhhqag..."}
		// we need to extract the phrase and decrypt it

		// extract the phrase
		const char* phraseStart = strstr(payload, "\"phrase\":\"");
		if (phraseStart == NULL) {
			Serial.println(" > Failed to extract phrase from payload");
			return;
		}
		phraseStart += strlen("\"phrase\":\"");
		const char* phraseEnd = strstr(phraseStart, "\"");
		if (phraseEnd == NULL) {
			Serial.println(" > Failed to extract phrase from payload");
			return;
		}

		char phraseB64[1024];
		memset(phraseB64, 0, sizeof(phraseB64));
		strncpy(phraseB64, phraseStart, phraseEnd - phraseStart);

		// print the phrase
		Serial.print(" > Phrase: ");
		Serial.println(phraseB64);

		// Convert the phrase from base64 to bytes
		size_t phraseLen = 0;
		unsigned char phraseBytes[2048];
		int res = mbedtls_base64_decode(
			phraseBytes, sizeof(phraseBytes), &phraseLen, 
			(const unsigned char*)phraseB64, strlen(phraseB64));
		if (res != 0) {
			Serial.printf(" > Failed to decode base64 phrase: %d\n", res);

			char errBuf[1024];
			mbedtls_strerror(res, errBuf, sizeof(errBuf));
			Serial.printf("Error: %s\n", errBuf);

			return;
		}

		// print the phrase bytes
		// Serial.printf(" > Phrase Bytes (%d): ", phraseLen);
		// for (int i = 0; i < phraseLen; i++) {
		// 	Serial.print(phraseBytes[i], HEX);
		// 	Serial.print(" ");
		// }
		// Serial.println();

		// decrypt the phrase
		const char* decryptedPhrase = Crypt_Decrypt(StrRes((const char*)phraseBytes, phraseLen)).data;
		if (decryptedPhrase == NULL) {
			Serial.println(" > Failed to decrypt phrase");
			return;
		}

		// print the decrypted phrase
		Serial.print(" > Decrypted Phrase: ");
		Serial.println(decryptedPhrase);


		char data[100];
		memset(data, 0, sizeof(data));
		sprintf(data, "{\"phrase\": \"%s\"}", decryptedPhrase);
		Serial.printf(" > Sending Login-2 Payload: %s\n", data);

		free((void*)decryptedPhrase);

		webSocket.emit("login-2", data);
	});

	Serial.println("> Connecting to WS at goofy2.marceldobehere.com at port 443!");
	webSocket.beginSSL("goofy2.marceldobehere.com", 443, "/socket.io/?EIO=3&transport=websocket");

	return true;
}