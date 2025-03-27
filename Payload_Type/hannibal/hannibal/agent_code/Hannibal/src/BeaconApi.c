#include "BeaconApi.h"


void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (parser == NULL) {
        return;
    }

    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size - 4;
    parser->size = size - 4;
    parser->buffer += 4;
}

int BeaconDataInt(datap* parser) {
    int fourbyteint = 0;
    if (parser->length < 4) {
        return 0;
    }
    memcpy(&fourbyteint, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return (int)fourbyteint;
}

short BeaconDataShort(datap* parser) {
    short retvalue = 0;
    if (parser->length < 2) {
        return 0;
    }
    memcpy(&retvalue, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return (short)retvalue;

}

int BeaconDataLength(datap* parser) {
    return parser->length;
}

char* BeaconDataExtract(datap* parser, int* size) {
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

void BeaconOutput(int type, char* data, int len) {
    // Output data to the controller
    int a = 0;
    for (int i = 0; i < 10; i++) {
        // Output data[i] to the controller
        a += i;
    }
    return;
}

void BeaconPrintf(int type, char* fmt, ...) {
    int a = 0;
    for (int i = 0; i < 10; i++) {
        // Output data[i] to the controller
        a += i;
    }
    return;
}


int BeaconWsprintf(wchar_t* dest, const wchar_t* format, ...) {
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

void BeaconStrcatW(wchar_t *wstr1, wchar_t *wstr2)
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

void BeaconAddMessage(LPCWSTR source_message, LPCWSTR new_message) {
    // Append new_message to source_message
    BeaconStrcatW(source_message, new_message);
    return;
}

int BeaconSprintf(char* dest, const char* format, ...) {
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