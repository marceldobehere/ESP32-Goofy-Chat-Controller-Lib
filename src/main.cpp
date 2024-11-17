#include <Arduino.h>
#include "main_lib.h"

SET_LOOP_TASK_STACK_SIZE(32 * 1024); // 32KB
#define LED_BUILTIN 2

void handleMessage(const char* message, uint64_t userIdFrom)
{
	Serial.printf(" > Handling Message from %llu: %s\n", userIdFrom, message);

	if (strcmp(message, "LED_ON") == 0)
	{
		Serial.println(" > Turning LED ON");
		digitalWrite(LED_BUILTIN, HIGH);
		delay(1000);
	}
	else if (strcmp(message, "BLINK") == 0)
	{
		Serial.println(" > Blinking LED");
		for (int i = 0; i < 5; i++)
		{
			digitalWrite(LED_BUILTIN, HIGH);
			delay(500);
			digitalWrite(LED_BUILTIN, LOW);
			delay(500);
		}
		Serial.println(" > Done blinking LED");
	}

	Serial.println("  > Done handling message");
}

void setup() 
{
	Serial.begin(9600);
	pinMode(LED_BUILTIN, OUTPUT);
	
	extHandleMessage = handleMessage;

	if (mainInit())
		Serial.println("> Setup done!");
	else
		Serial.println("> Setup failed!");
}

void loop() {

	if (!initSuccess)
		return;
	
	mainLoop();
}

