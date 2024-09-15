#include "init_wifi.h"
#include <Arduino.h>
#include "WiFi.h"

#include "wifi_pass.h"
// #define LOCAL_WIFI_SSID "SSID"
// #define LOCAL_WIFI_PASS "PASS"

bool initWifi()
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
			Serial.println("> Failed to connect to WIFI. Please verify credentials!");
			return false;
		}
		delay(5000);
    }

	
    Serial.println("");
    Serial.println("> WiFi connected!");
    Serial.println("IP address: ");
    Serial.println(WiFi.localIP());
	return true;
}