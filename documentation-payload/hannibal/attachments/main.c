#include <windows.h>
#include "BeaconApi.h"

// Parser functions
int ParseInt32(PBYTE* args) {
    int value = 0;
    memcpy(&value, *args, sizeof(int));
    *args += sizeof(int);
    return value;
}

char* ParseString(PBYTE* args) {
    int length = 0;
    PBYTE current = *args;
    
    // Find string length
    while (current[length] != 0) {
        length++;
    }
    
    char* string = (char*)*args;
    *args += length + 1; // Move past string and null terminator
    return string;
}

LPCWSTR ParseWideString(PBYTE* args) {
    int length = 0;
    PWCHAR current = (PWCHAR)*args;
    
    // Find wide string length
    while (current[length] != 0) {
        length++;
    }
    
    LPCWSTR string = (LPCWSTR)*args;
    *args += (length + 1) * sizeof(WCHAR); // Move past wide string and null terminator
    return string;
}

void go(PBYTE Args, ULONG Argc, PBYTE file_content, ULONG file_size, LPCWSTR buffer_message) {
    // Example usage of parsing functions
    PBYTE current = Args;
    
    // Parse an integer
    int value = ParseInt32(&current);
    
    // Parse a string
    char* str = ParseString(&current);
    
    // Parse a wide string
    LPCWSTR wstr = ParseWideString(&current);
    
    // Use the parsed values
    WCHAR output[256];
    BeaconWsprintf(output, L"[+] Int: %d, String: %S, WString: %s\n", value, str, wstr);

    WCHAR output2[256];
    // Use the file content and size
    BeaconWsprintf(output2, L"[+] File length: %d\n", file_size);
    BeaconAddMessage(buffer_message, output);
    BeaconAddMessage(buffer_message, output2);
}
