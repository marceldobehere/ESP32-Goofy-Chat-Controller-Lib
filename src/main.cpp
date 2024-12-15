#include <Arduino.h>
#include "main_lib.h"

SET_LOOP_TASK_STACK_SIZE(32 * 1024); // 32KB
#define LED_1 25 // BLUE
#define LED_2 27 // GREEN
#define LED_3 26 // RED

void handleMessage(const char* message, uint64_t userIdFrom)
{
	Serial.printf(" > Handling Message from %llu: %s\n", userIdFrom, message);
	// replyMessage("Received your message", userIdFrom);

	if (strcmp(message, "LED_1") == 0)
	{
		Serial.println(" > Turning LED 1 ON");
		replyMessage("> LED_1 IS ON", userIdFrom);
		digitalWrite(LED_1, HIGH);
		delay(3000);
		digitalWrite(LED_1, LOW);
		replyMessage("> LED_1 IS OFF", userIdFrom);
	}
	else if (strcmp(message, "LED_2") == 0)
	{
		Serial.println(" > Turning LED 2 ON");
		replyMessage	("> LED_2 IS ON", userIdFrom);
		digitalWrite(LED_2, HIGH);
		delay(3000);
		digitalWrite(LED_2, LOW);
		replyMessage("> LED_2 IS OFF", userIdFrom);
	}
	else if (strcmp(message, "LED_3") == 0)
	{
		Serial.println(" > Turning LED 3 ON");
		replyMessage("> LED_3 IS ON", userIdFrom);
		digitalWrite(LED_3, HIGH);
		delay(3000);
		digitalWrite(LED_3, LOW);
		replyMessage("> LED_3 IS OFF", userIdFrom);
	}
	else if (strcmp(message, "BLINK") == 0)
	{
		Serial.println(" > Blinking LEDS");
		replyMessage("> BLINKING LEDS", userIdFrom);
		for (int i = 0; i < 5; i++)
		{
			digitalWrite(LED_1, HIGH);
			delay(300);
			digitalWrite(LED_1, LOW);
			digitalWrite(LED_2, HIGH);
			delay(300);
			digitalWrite(LED_2, LOW);
			digitalWrite(LED_3, HIGH);
			delay(300);
			digitalWrite(LED_3, LOW);
			delay(300);
		}
		Serial.println(" > Done blinking LEDS");
		replyMessage("> DONE BLINKING LEDS", userIdFrom);
	}
	else if (strcmp(message, "LED_1 ON") == 0)
	{
		Serial.println(" > Turning LED 1 ON");
		digitalWrite(LED_1, HIGH);
		replyMessage("> LED_1 IS ON", userIdFrom);
	}
	else if (strcmp(message, "LED_2 ON") == 0)
	{
		Serial.println(" > Turning LED 2 ON");
		digitalWrite(LED_2, HIGH);
		replyMessage("> LED_2 IS ON", userIdFrom);
	}
	else if (strcmp(message, "LED_3 ON") == 0)
	{
		Serial.println(" > Turning LED 3 ON");
		digitalWrite(LED_3, HIGH);
		replyMessage("> LED_3 IS ON", userIdFrom);
	}
	else if (strcmp(message, "LED_1 OFF") == 0)
	{
		Serial.println(" > Turning LED 1 OFF");
		digitalWrite(LED_1, LOW);
		replyMessage("> LED_1 IS OFF", userIdFrom);
	}
	else if (strcmp(message, "LED_2 OFF") == 0)
	{
		Serial.println(" > Turning LED 2 OFF");
		digitalWrite(LED_2, LOW);
		replyMessage("> LED_2 IS OFF", userIdFrom);
	}
	else if (strcmp(message, "LED_3 OFF") == 0)
	{
		Serial.println(" > Turning LED 3 OFF");
		digitalWrite(LED_3, LOW);
		replyMessage("> LED_3 IS OFF", userIdFrom);
	}
	else 
	{
		Serial.println(" > Unknown command");
		replyMessage("> Unknown command", userIdFrom);
	}

	Serial.println("  > Done handling message");
}

void setup() 
{
	Serial.begin(9600);
	Serial.println("> Doing BOOT 1");

	pinMode(LED_1, OUTPUT);
	pinMode(LED_2, OUTPUT);
	pinMode(LED_3, OUTPUT);

	Serial.println("> Doing BOOT 2");

	digitalWrite(LED_1, LOW);
	digitalWrite(LED_2, LOW);
	digitalWrite(LED_3, LOW);
	
	Serial.println("> Doing BOOT 3");

	extHandleMessage = handleMessage;

	Serial.println("> Doing BOOT 4");

	if (mainInit())
		Serial.println("> Setup done!");
	else
		Serial.println("> Setup failed!");
}

void loop() 
{
	if (!initSuccess)
		return;
	
	mainLoop();
}

