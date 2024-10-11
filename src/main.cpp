#include <Arduino.h>
#include "WiFi.h"
#include <SocketIoClient.h>
#include "init_wifi.h"
#include "LittleFS.h"
#include "rsa.h"
#include "yes_fs.h"

bool initFS();
bool initWebsocket();
SocketIoClient webSocket;
bool initSuccess;

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

	webSocket.on("login-2", [](const char* payload, size_t length) {
		Serial.println("> Received login-2 event from WS!");
		Serial.print(" > Payload: ");
		Serial.println(payload);
	});

	webSocket.on("login-1", [](const char* payload, size_t length) {
		Serial.println("> Received login-1 event from WS!");
		Serial.print(" > Payload: ");
		Serial.println(payload);

		const char* phrase = "ABC";

		char data[100];
		memset(data, 0, sizeof(data));
		sprintf(data, "{\"phrase\": \"%s\"}", phrase);
		Serial.printf(" > Sending Login-2 Payload: %s\n", data);

		webSocket.emit("login-2", data);
	});

	Serial.println("> Connecting to WS at goofy2.marceldobehere.com at port 443!");
	webSocket.beginSSL("goofy2.marceldobehere.com", 443, "/socket.io/?EIO=3&transport=websocket");

	return true;
}