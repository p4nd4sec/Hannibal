#include "BeaconApi.h"
#include <stdio.h>

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
    puts(data);
}

void BeaconPrintf(int type, char* fmt, ...) {
    va_list VaList = { 0 };

    va_start(VaList, fmt);
    vprintf(fmt, VaList);
    va_end(VaList);
}
