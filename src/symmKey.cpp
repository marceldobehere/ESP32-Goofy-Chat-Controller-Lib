#include "symmKey.h"
#include <map>
#include <string.h>
#include "yes_fs.h"

std::map<uint64_t, const char*> Symmcache;
std::map<uint64_t, const char*> pubKeyCache;

bool initSymmKeyStuff()
{
    Symmcache.clear();
    pubKeyCache.clear();
    return true;
}

const char* userIdSToStr(uint64_t userId)
{
    char* userIdStr = (char*)malloc(130);
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
    if (Symmcache.find(userId) == Symmcache.end())
    {
        const char* potentialKey = getSymmKeyFromFile(userId);
        if (potentialKey != NULL)
            Symmcache[userId] = potentialKey;
        return potentialKey;
    }

    return Symmcache[userId];
}

const char* getMySymmKey(uint64_t userId)
{
    // TODO: Create a random key and save it to a file and stuff
    // instead of using the same key for both sides
    return getSymmKey(userId);
}

void setSymmKey(uint64_t userId, const char* key)
{
    if (Symmcache.find(userId) != Symmcache.end())
    {
        const char* oldKey = Symmcache[userId];
        if (oldKey != NULL)
        {
            if (strcmp(oldKey, key) == 0)
                return;
            
            free((void*)oldKey);
        }
    }

    Symmcache[userId] = strdup(key);
    saveSymmKeyToFile(userId, key);
}


const char* userIdPubSToStr(uint64_t userId)
{
    char* userIdStr = (char*)malloc(130);
    userIdStr = itoa(userId, userIdStr, 10);
    const char* path = "/pubKey_";
    const char* path2 = ".txt";
    char* fullPath = (char*)malloc(strlen(path) + strlen(userIdStr) + strlen(path2) + 1);
    strcpy(fullPath, path);
    strcat(fullPath, userIdStr);
    strcat(fullPath, path2);
    free((void*)userIdStr);
    return fullPath;
}

const char* getPubKeyFromFile(uint64_t userId)
{
    const char* path = userIdPubSToStr(userId);
    FileRead fileRead = readFile(path);
    free((void*)path);
    return fileRead.data;
}

void savePubKeyToFile(uint64_t userId, const char* key)
{
    const char* path = userIdPubSToStr(userId);
    writeFile(path, key);
    free((void*)path);
}

const char* getPubKey(uint64_t userId)
{
    if (pubKeyCache.find(userId) == pubKeyCache.end())
    {
        const char* potentialKey = getPubKeyFromFile(userId);
        if (potentialKey != NULL)
            pubKeyCache[userId] = potentialKey;
        return potentialKey;
    }

    return pubKeyCache[userId];
}

void setPubKey(uint64_t userId, const char* key)
{
    if (pubKeyCache.find(userId) != pubKeyCache.end())
    {
        const char* oldKey = pubKeyCache[userId];
        if (oldKey != NULL)
        {
            if (strcmp(oldKey, key) == 0)
                return;
            
            free((void*)oldKey);
        }
    }

    pubKeyCache[userId] = strdup(key);
    savePubKeyToFile(userId, key);
}