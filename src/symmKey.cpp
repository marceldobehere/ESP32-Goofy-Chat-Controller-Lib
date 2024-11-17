#include "symmKey.h"
#include <map>
#include <string.h>
#include "yes_fs.h"

std::map<uint64_t, const char*> cache;

bool initSymmKeyStuff()
{
    cache.clear();
    return true;
}

const char* userIdSToStr(uint64_t userId)
{
    char* userIdStr = (char*)malloc(100);
    userIdStr = itoa(userId, userIdStr, 10);
    const char* path = "/symmKey_";
    const char* path2 = ".txt";
    char* fullPath = (char*)malloc(strlen(path) + strlen(userIdStr) + strlen(path2) + 1);
    strcpy(fullPath, path);
    strcat(fullPath, userIdStr);
    strcat(fullPath, path2);
    free((void*)userIdStr);
    return fullPath;
}

const char* getSymmKeyFromFile(uint64_t userId)
{
    const char* path = userIdSToStr(userId);
    FileRead fileRead = readFile(path);
    free((void*)path);
    return fileRead.data;
}

void saveSymmKeyToFile(uint64_t userId, const char* key)
{
    const char* path = userIdSToStr(userId);
    writeFile(path, key);
    free((void*)path);
}


const char* getSymmKey(uint64_t userId)
{
    if (cache.find(userId) == cache.end())
    {
        const char* potentialKey = getSymmKeyFromFile(userId);
        if (potentialKey != NULL)
            cache[userId] = potentialKey;
        return potentialKey;
    }

    return cache[userId];
}

const char* getMySymmKey(uint64_t userId)
{
    // TODO: Create a random key and save it to a file and stuff
    // instead of using the same key for both sides
    return getSymmKey(userId);
}

void setSymmKey(uint64_t userId, const char* key)
{
    if (cache.find(userId) != cache.end())
    {
        const char* oldKey = cache[userId];
        if (oldKey != NULL)
        {
            if (strcmp(oldKey, key) == 0)
                return;
            
            free((void*)oldKey);
        }
    }

    cache[userId] = strdup(key);
    saveSymmKeyToFile(userId, key);
}
