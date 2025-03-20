#pragma once
#include "hannibal.h"
/* data API */
typedef struct {
	char* original; /* the original buffer [so we can free it] */
	char* buffer;   /* current pointer into our buffer */
	int    length;  /* remaining length of data */
	int    size;    /* total size of this buffer */
} datap;

void    BeaconDataParse(datap* parser, char* buffer, int size);
int     BeaconDataInt(datap* parser);
short   BeaconDataShort(datap* parser);
int     BeaconDataLength(datap* parser);
char*   BeaconDataExtract(datap* parser, int* size);

/* Output Functions */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

void BeaconOutputW(char *task_uuid, int type, char* data, int len);
void BeaconWPrintf(char *task_uuid, int type, char* fmt, ...);
