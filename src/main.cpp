#include <Arduino.h>
#include "WiFi.h"
#include <SocketIoClient.h>
#include "init_wifi.h"
#include "LittleFS.h"
#include "rsa.h"

bool initFS();
bool initWebsocket();
SocketIoClient webSocket;
bool initSuccess;

void setup() {
	Serial.begin(9600);
	initSuccess = true;

	initSuccess &= initFS();
	if (!initSuccess) return;
	initSuccess &= testKeyGen();
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
		webSocket.emit("login-1", "\"Hello World!\"");
	});

	webSocket.on("disconnect", [](const char* payload, size_t length) {
		Serial.println("> Disconnected from WS!");
	});

	webSocket.on("login-1", [](const char* payload, size_t length) {
		Serial.println("> Received login-1 event from WS!");
		Serial.print(" > Payload: ");
		Serial.println(payload);
	});

	Serial.println("> Connecting to WS at goofy2.marceldobehere.com at port 443!");
	webSocket.beginSSL("goofy2.marceldobehere.com", 443, "/socket.io/?EIO=3&transport=websocket");

	return true;
}

bool testFS();
bool initFS()
{
	Serial.println("> Doing FS Init!");
	// Using LittleFS

	if (!LittleFS.begin()) {
		Serial.println("An Error has occurred while mounting LittleFS");
		return false;
	}

	Serial.println("LittleFS mounted successfully");

	return testFS();
}

bool testFS()
{
	Serial.println("> Doing FS Test!");

	// First check if test1.txt exists and print it if it does
	// Then check if test2.txt exists and if not create it
	// Print the contents of test2.txt
	// Then write the contents + "Hello World!" to test2.txt
	// Print the contents of test2.txt

	File file = LittleFS.open("/test1.txt", "r");
	if (!file) 
	{
		Serial.println(" > File test1.txt does not exist");
		return false;
	} 

	Serial.println(" > File test1.txt exists");
	Serial.println("  > Contents of test1.txt:");
	while (file.available()) 
		Serial.write(file.read());
	Serial.println();
	file.close();
	
	file = LittleFS.open("/test2.txt", "r");
	if (!file)
	{
		Serial.println(" > File test2.txt does not exist");
		Serial.println(" > Creating test2.txt");
		file = LittleFS.open("/test2.txt", "w");
		if (!file)
		{
			Serial.println(" > Failed to create test2.txt");
			return false;
		}
		file = LittleFS.open("/test2.txt", "r");
		if (!file)
		{
			Serial.println(" > Failed to open test2.txt after creation");
			return false;
		}
	}

	Serial.println(" > File test2.txt exists");
	Serial.println("  > Contents of test2.txt:");
	while (file.available())
		Serial.write(file.read());
	Serial.println();
	file.close();

	file = LittleFS.open("/test2.txt", "a");
	if (!file)
	{
		Serial.println(" > Failed to open test2.txt for appending");
		return false;
	}

	Serial.println(" > Appending \"Hello World!\" to test2.txt");
	file.println("Hello World!");
	file.close();

	file = LittleFS.open("/test2.txt", "r");
	if (!file)
	{
		Serial.println(" > Failed to open test2.txt after appending");
		return false;
	}

	Serial.println(" > File test2.txt exists");
	Serial.println("  > Contents of test2.txt:");
	while (file.available())
		Serial.write(file.read());
	Serial.println();
	file.close();

	return true;
}