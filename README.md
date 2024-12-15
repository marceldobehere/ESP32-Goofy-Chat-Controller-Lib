## ESP32 Goofy Chat Controller Lib

A Lib that aims to provide a way to control an ESP32 / call specific functions from anywhere using the [Goofy Chat 2](https://github.com/marceldobehere/goofy-chat-app-v2) infrastructure.

The Controller will be able to add specific userids with permissions to call certain functions, which can then connect with a custom web or native client and send commands.

The userids will communicated with encrypted data, making it all secure.

This allows the secure remote control of the microcontroller without needing to expose it or an extra server to the public internet.

Although the Goofy Chat 2 server can be self hosted if its wanted.



## NOTE

THIS IS FAR FROM DONE AND VERY WIP RIGHT NOW

Also if you compile / try to run this yourself, you might come across some compiler errors. Some are fixable by commenting out the error code.

### Errors:

#### WolfSSL

```
In file included from .pio/libdeps/esp32dev/wolfssl/src/wolfssl/wolfcrypt/types.h:34,
                 from .pio/libdeps/esp32dev/wolfssl/src/wolfssl/openssl/evp.h:33,
                 from src/aes.cpp:10:
.pio/libdeps/esp32dev/wolfssl/src/wolfssl/wolfcrypt/settings.h:3582:6: error: #error "Found both ESPIDF and ARDUINO. Pick one."
     #error "Found both ESPIDF and ARDUINO. Pick one."
      ^~~~~
src/init_wifi.cpp:5:10: fatal error: wifi_pass.h: No such file or directory
```

Comment out the `#error`


#### WIFI PASS
```
 #include "wifi_pass.h"
          ^~~~~~~~~~~~~
compilation terminated.
*** [.pio\build\esp32dev\src\init_wifi.cpp.o] Error 1
```

Create a file called `wifi_pass.h` in the `src` directory.

it should look like this:
```cpp
#pragma once

#define LOCAL_WIFI_SSID "<SSID>"
#define LOCAL_WIFI_PASS "<PASS>"
```

### SocketIOClient
```
.pio/libdeps/esp32dev/SocketIoClient/SocketIoClient.cpp: In member function 'void SocketIoClient::webSocketEvent(WStype_t, uint8_t*, size_t)':
.pio/libdeps/esp32dev/SocketIoClient/SocketIoClient.cpp:41:4: error: 'hexdump' was not declared in this scope
    hexdump(payload, length);
    ^~~~~~~
```

Comment out the statement


### WolfCrypt
```
c:/.../xtensa-esp32-elf/bin/ld.exe: .pio\build\esp32dev\lib0b2\libwolfssl.a(random.c.o):C:\...\.pio/libdeps/esp32dev/wolfssl/src/wolfcrypt/src/random.c:522: more undefined references to `wc_debug_pvPortMalloc' follow
collect2.exe: error: ld returned 1 exit status
*** [.pio\build\esp32dev\firmware.elf] Error 1
```

Find the code section: in `.pio/libdeps/esp32dev/wolfssl/src/wolfssl/wolfcrypt/settings.h`
```cpp
    #if !defined(XMALLOC_USER) && !defined(NO_WOLFSSL_MEMORY) && \
        !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_TRACK_MEMORY)

        /* XMALLOC */
        #if defined(WOLFSSL_ESPIDF) && \
           (defined(DEBUG_WOLFSSL) || defined(DEBUG_WOLFSSL_MALLOC))
            #include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>
            #define XMALLOC(s, h, type)  \
                           ((void)(h), (void)(type), wc_debug_pvPortMalloc( \
                           (s), (__FILE__), (__LINE__), (__FUNCTION__) ))
        #else
            #define XMALLOC(s, h, type)  \
                           ((void)(h), (void)(type), pvPortMalloc((s)))
        #endif
```

and replace the `/* XMALLOC */` part with this:

```cpp
        /* XMALLOC */
        #if defined(WOLFSSL_ESPIDF) && \
           (defined(DEBUG_WOLFSSL) || defined(DEBUG_WOLFSSL_MALLOC))
            #include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>
            #define XMALLOC(s, h, type)  \
                           ((void)(h), (void)(type), malloc( \
                           (s) ))
        #else
            #define XMALLOC(s, h, type)  \
                           ((void)(h), (void)(type), pvPortMalloc((s)))
        #endif
```