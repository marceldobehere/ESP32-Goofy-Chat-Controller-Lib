#include <Arduino.h>
#include "WiFi.h"
#include <SocketIoClient.h>

#include "wifi_pass.h"
// #define LOCAL_WIFI_SSID "SSID"
// #define LOCAL_WIFI_PASS "PASS"

void initWifi();
void initWebsocket();
SocketIoClient webSocket;

void setup() {
	Serial.begin(9600);
	initWifi();
	initWebsocket();
}

void loop() {
	// delay(10000);
	// Serial.println("Hello World!");
	webSocket.loop();
}

void initWifi()
{
	Serial.println("> Doing WIFI Init!");
	
	// Set WiFi to station mode and disconnect from an AP if it was previously connected
	Serial.println("> Setting WIFI Mode");
	WiFi.mode(WIFI_STA);
    delay(100);

	Serial.println("> Connecting to WIFI");
	WiFi.begin(LOCAL_WIFI_SSID, LOCAL_WIFI_PASS);

    Serial.println("> Connecting...");
	while (WiFi.status() != WL_CONNECTED) 
	{
		if (WiFi.status() == WL_CONNECT_FAILED) {
			Serial.println("> Failed to connect to WIFI. Please verify credentials: ");
		}
		delay(5000);
    }

	
    Serial.println("");
    Serial.println("> WiFi connected!");
    Serial.println("IP address: ");
    Serial.println(WiFi.localIP());
}

void initWebsocket()
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
}