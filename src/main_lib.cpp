#include "main_lib.h"
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
uint64_t myUserId = 0;
bool initSuccess = false;
void (*extHandleMessage)(const char* message, uint64_t userIdFrom) = NULL;

int min(unsigned int a, unsigned int b)
{
    return a < b ? a : b;
}

StrRes* encryptBase64RsaStr(StrRes data, int* outArrLen)
{
	// Splits a string into 100 byte chunks
	// encrypts each chunk
	// converts each encrypted chunk to base64
	// returns an array of base64 strings

	// Calculate the number of chunks
	// Allocate memory for the array
	int chunkSize = 100;
	int numChunks = (data.size + chunkSize - 1) / chunkSize;
	StrRes* encryptedArr = (StrRes*)malloc(numChunks * sizeof(StrRes));
	if (encryptedArr == NULL) {
		Serial.println(" > Failed to allocate memory for encrypted array");
		return NULL;
	}

	// Encrypt each chunk
	for (int i = 0; i < numChunks; i++) {
		int start = i * chunkSize;
		int end = min((i + 1) * chunkSize, data.size);
		int len = end - start;

		StrRes chunk = StrRes(data.data + start, len);
		StrRes encrypted = Crypt_Encrypt(chunk);
		if (encrypted.data == NULL) {
			Serial.printf(" > Failed to encrypt chunk %d\n", i);
			for (int i2 = 0; i2 < i; i2++) {
				free((void*)encryptedArr[i2].data);
			}
			free(encryptedArr);
			return NULL;
		}

		// Convert the encrypted chunk to base64
		size_t encryptedB64Len = 0;
		unsigned char encryptedB64[1024];
		int res = mbedtls_base64_encode(
			encryptedB64, sizeof(encryptedB64), &encryptedB64Len, 
			(const unsigned char*)encrypted.data, strlen(encrypted.data));
		if (res != 0) {
			Serial.printf(" > Failed to encode base64 chunk %d: %d\n", i, res);
			char errBuf[1024];
			mbedtls_strerror(res, errBuf, sizeof(errBuf));
			Serial.printf("Error: %s\n", errBuf);

			free((void*)encrypted.data);
			for (int i2 = 0; i2 < i; i2++) {
				free((void*)encryptedArr[i2].data);
			}
			free(encryptedArr);
			return NULL;
		}
		
		// malloc and copy the base64 string
		char* encryptedB64Str = (char*)malloc(encryptedB64Len + 1);
		if (encryptedB64Str == NULL) {
			Serial.printf(" > Failed to allocate memory for base64 chunk %d\n", i);
			free((void*)encrypted.data);
			for (int i2 = 0; i2 < i; i2++) {
				free((void*)encryptedArr[i2].data);
			}
			free(encryptedArr);
			return NULL;
		}

		memcpy(encryptedB64Str, encryptedB64, encryptedB64Len);
		encryptedB64Str[encryptedB64Len] = '\0';

		encryptedArr[i] = StrRes(encryptedB64Str);
		free((void*)encrypted.data);
	}

	*outArrLen = numChunks;
	return encryptedArr;
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

// will always send a symm-key message
bool sendWsRsaMessage(uint64_t userId, const char* msg)
{
	// Create a message object from the msg
	JsonDocument doc;
	doc["type"] = "symm-key";
	doc["symmKey"] = msg;
	doc["messageId"] = random(0, 1000000);

	// Convert the message object into a string
	char msgStr[1024*3];
	memset(msgStr, 0, sizeof(msgStr));
	if (serializeJson(doc, msgStr) == 0) {
		Serial.println(" > Failed to serialize JSON");
		return false;
	}
	Serial.printf(" > Message: %s\n", msgStr);

    // Get the public key from the userid
    // TODO: Implement

	// Encrypt the message using RSA
	StrRes encryptedMsg = Crypt_Encrypt(StrRes(msgStr));
	if (encryptedMsg.data == NULL) {
		Serial.println(" > Failed to encrypt message");
		return false;
	}

	// Convert Encrypted Message into an Array of Base64 Strings
	int arrLen = 0;
	StrRes* encryptedMsgArr = encryptBase64RsaStr(encryptedMsg, &arrLen);
	if (encryptedMsgArr == NULL) {
		Serial.println(" > Failed to convert encrypted message to base64 array");
		free((void*)encryptedMsg.data);
		return false;
	}

	// Generate the Signature
	StrRes signature = Crypt_Sign(StrRes(msgStr));
	if (signature.data == NULL) {
		Serial.println(" > Failed to generate signature");
		free((void*)encryptedMsg.data);
		for (int i = 0; i < arrLen; i++) {
			free((void*)encryptedMsgArr[i].data);
		}
		return false;
	}

	// Convert the Signature into a Base64 String
	size_t signatureB64Len = 0;
	unsigned char signatureB64[1024];
	int res = mbedtls_base64_encode(
		signatureB64, sizeof(signatureB64), &signatureB64Len, 
		(const unsigned char*)signature.data, strlen(signature.data));
	if (res != 0) {
		Serial.printf(" > Failed to encode signature to base64: %d\n", res);
		free((void*)encryptedMsg.data);
		for (int i = 0; i < arrLen; i++) {
			free((void*)encryptedMsgArr[i].data);
		}
		free((void*)signature.data);
		return false;
	}
	
	Serial.printf(" > Signature: %s\n", signatureB64);

	// Package the message into a JSON object {type:"rsa", data: [base64, base64, ...], signature: "base64"}
	JsonDocument rsaDoc;
	rsaDoc["type"] = "rsa";
	JsonArray dataArr = rsaDoc.createNestedArray("data");
	for (int i = 0; i < arrLen; i++) {
		dataArr.add(encryptedMsgArr[i].data);
	}
	rsaDoc["signature"] = (const char*)signatureB64;

	// Package the JSON object into an object {"from": [my userid], "to": userId, data: {...}}
	JsonDocument finalDoc;
	finalDoc["from"] = myUserId;
	finalDoc["to"] = userId;
	finalDoc["data"] = rsaDoc;

	// Convert the JSON object into a string
	char finalStr[1024*4];
	memset(finalStr, 0, sizeof(finalStr));
	if (serializeJson(finalDoc, finalStr) == 0) {
		Serial.println(" > Failed to serialize final JSON");
		free((void*)encryptedMsg.data);
		for (int i = 0; i < arrLen; i++) {
			free((void*)encryptedMsgArr[i].data);
		}
		free((void*)signature.data);
		return false;
	}

	Serial.printf(" > Final Message: %s\n", finalStr);

	// Send the string to the websocket
	webSocket.emit("send-message", finalStr);

	// Cleanup
	free((void*)encryptedMsg.data);
	for (int i = 0; i < arrLen; i++) {
		free((void*)encryptedMsgArr[i].data);
	}
	free((void*)signature.data);
	return true;
}

bool sendWsAesMessage(uint64_t userId, const char* msg)
{
    // TODO: Implement
	return false;
}

bool replyMessage(const char* message, uint64_t userIdTo)
{
    // TODO: Implement
    return false;
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

				if (strcmp(msgContent, "symm") == 0)
				{
					// Send symm key back
					if (sendWsRsaMessage(fromId, getMySymmKey(fromId)))
						Serial.println(" > Sent Symmetric Key");
					else
						Serial.println(" > Failed to send Symmetric Key");
				}

                if (extHandleMessage != NULL)
                    extHandleMessage(msgContent, fromId);
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

			// TODO: Validate signature

			JsonDocument rsaDoc;
			deserializeJson(rsaDoc, decrypted.data);

			const char* msgType = rsaDoc["type"];
			
			if (strcmp(msgType, "symm-key") == 0) {
				const char* symmKey = rsaDoc["symmKey"];
				Serial.printf(" > Symmetric Key: %s\n", symmKey);
				setSymmKey(fromId, symmKey);

				// // Send symm key back
				// if (sendWsRsaMessage(fromId, getMySymmKey(fromId)))
				// 	Serial.println(" > Sent Symmetric Key");
				// else
				// 	Serial.println(" > Failed to send Symmetric Key");
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

		// TODO: Parse the JSON {"userId": 1234}

		// save to var
		myUserId = 504592230;
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


bool mainInit()
{
    initSuccess = true;

	initSuccess &= initFS();
	if (!initSuccess) return false;
	// initSuccess &= testFS();
	// if (!initSuccess) return;
	// initSuccess &= testKeyGen();
	// if (!initSuccess) return;
	initSuccess &= CryptoInit();
	if (!initSuccess) return false;
	initSuccess &= testEncDec();
	if (!initSuccess) return false;
	initSuccess &= aesTest();
	if (!initSuccess) return false;
	initSuccess &= initSymmKeyStuff();
	if (!initSuccess) return false;
	initSuccess &= initWifi();
	if (!initSuccess) return false;
	initSuccess &= initWebsocket();
	if (!initSuccess) return false;

    return true;
}

void mainLoop()
{
    webSocket.loop();
}