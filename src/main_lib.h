#pragma once
#include <stdint.h>

extern uint64_t myUserId;
extern bool initSuccess;

// void handleMessage(const char* message, uint64_t userIdFrom)
extern void (*extHandleMessage)(const char* message, uint64_t userIdFrom);

bool replyMessage(const char* message, uint64_t userIdTo);

bool mainInit();
void mainLoop();
