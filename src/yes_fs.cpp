#include "yes_fs.h"
#include <Arduino.h>
#include "LittleFS.h"
#include "FS.h"


bool initFS()
{
	Serial.println("> Doing FS Init!");
	// Using LittleFS

	if (!LittleFS.begin()) {
		Serial.println("An Error has occurred while mounting LittleFS");
		return false;
	}

	Serial.println("LittleFS mounted successfully");
    return true;
}

bool fileExists(const char* path)
{
    File file = LittleFS.open(path, "r");
    if (!file) {
        return false;
    }
    file.close();
    return true;
}

FileRead readFile(const char* path)
{
    File file = LittleFS.open(path, "r");
    if (!file) {
        return FileRead{NULL, 0};
    }

    size_t size = file.size();
    char* data = (char*)malloc(size + 1);
    if (data == NULL) {
        file.close();
        return FileRead{NULL, 0};
    }

    size_t bytesRead = file.readBytes(data, size);
    file.close();
    if (bytesRead != size) {
        free(data);
        return FileRead{NULL, 0};
    }

    data[size] = '\0';
    return FileRead{data, size};
}

bool writeFile(const char* path, const char* data)
{
    File file = LittleFS.open(path, "w");
    if (!file) {
        return false;
    }

    size_t size = strlen(data);
    size_t bytesWritten = file.write((const uint8_t*)data, size);
    file.close();

    return bytesWritten == size;
}

bool appendFile(const char* path, const char* data)
{
    File file = LittleFS.open(path, "a");
    if (!file) {
        return false;
    }

    size_t size = strlen(data);
    size_t bytesWritten = file.write((const uint8_t*)data, size);
    file.close();

    return bytesWritten == size;
}

bool testFS()
{
    Serial.println("> Doing FS Test!");

    // First check if test1.txt exists and print it if it does
    // Then check if test2.txt exists and if not create it
    // Print the contents of test2.txt
    // Then write the contents + "Hello World!" to test2.txt
    // Print the contents of test2.txt
    // Use the functions defined above

    if (!fileExists("/test1.txt")) {
        Serial.println(" > File test1.txt does not exist");
        return false;
    }
    Serial.println(" > File test1.txt exists");
    
    const char* test1Contents = readFile("/test1.txt").data;
    if (test1Contents == NULL) {
        Serial.println(" > Failed to read test1.txt");
        return false;
    }
    Serial.println("  > Contents of test1.txt:");
    Serial.println(test1Contents);
    free((void*)test1Contents);

    if (!fileExists("/test2.txt")) {
        Serial.println(" > File test2.txt does not exist");
        Serial.println(" > Creating test2.txt");
        if (!writeFile("/test2.txt", "")) {
            Serial.println(" > Failed to create test2.txt");
            return false;
        }
    }
    Serial.println(" > File test2.txt exists");

    const char* test2Contents = readFile("/test2.txt").data;
    if (test2Contents == NULL) {
        Serial.println(" > Failed to read test2.txt");
        return false;
    }
    Serial.println("  > Contents of test2.txt:");
    Serial.println(test2Contents);
    free((void*)test2Contents);
    
    if (!appendFile("/test2.txt", "Hello World!")) {
        Serial.println(" > Failed to append to test2.txt");
        return false;
    }

    test2Contents = readFile("/test2.txt").data;
    if (test2Contents == NULL) {
        Serial.println(" > Failed to read test2.txt after appending");
        return false;
    }
    Serial.println("  > Contents of test2.txt:");
    Serial.println(test2Contents);
    free((void*)test2Contents);

    return true;
}


// bool testFS()
// {
// 	Serial.println("> Doing FS Test!");

// 	// First check if test1.txt exists and print it if it does
// 	// Then check if test2.txt exists and if not create it
// 	// Print the contents of test2.txt
// 	// Then write the contents + "Hello World!" to test2.txt
// 	// Print the contents of test2.txt

// 	File file = LittleFS.open("/test1.txt", "r");
// 	if (!file) 
// 	{
// 		Serial.println(" > File test1.txt does not exist");
// 		return false;
// 	} 

// 	Serial.println(" > File test1.txt exists");
// 	Serial.println("  > Contents of test1.txt:");
// 	while (file.available()) 
// 		Serial.write(file.read());
// 	Serial.println();
// 	file.close();
	
// 	file = LittleFS.open("/test2.txt", "r");
// 	if (!file)
// 	{
// 		Serial.println(" > File test2.txt does not exist");
// 		Serial.println(" > Creating test2.txt");
// 		file = LittleFS.open("/test2.txt", "w");
// 		if (!file)
// 		{
// 			Serial.println(" > Failed to create test2.txt");
// 			return false;
// 		}
// 		file = LittleFS.open("/test2.txt", "r");
// 		if (!file)
// 		{
// 			Serial.println(" > Failed to open test2.txt after creation");
// 			return false;
// 		}
// 	}

// 	Serial.println(" > File test2.txt exists");
// 	Serial.println("  > Contents of test2.txt:");
// 	while (file.available())
// 		Serial.write(file.read());
// 	Serial.println();
// 	file.close();

// 	file = LittleFS.open("/test2.txt", "a");
// 	if (!file)
// 	{
// 		Serial.println(" > Failed to open test2.txt for appending");
// 		return false;
// 	}

// 	Serial.println(" > Appending \"Hello World!\" to test2.txt");
// 	file.println("Hello World!");
// 	file.close();

// 	file = LittleFS.open("/test2.txt", "r");
// 	if (!file)
// 	{
// 		Serial.println(" > Failed to open test2.txt after appending");
// 		return false;
// 	}

// 	Serial.println(" > File test2.txt exists");
// 	Serial.println("  > Contents of test2.txt:");
// 	while (file.available())
// 		Serial.write(file.read());
// 	Serial.println();
// 	file.close();

// 	return true;
// }