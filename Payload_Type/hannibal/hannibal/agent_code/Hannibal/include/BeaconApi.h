#pragma once
#include "hannibal.h"
#define MAX_MESSAGE_SIZE 0x1000

/* data API */
typedef struct {
	char* original; /* the original buffer [so we can free it] */
	char* buffer;   /* current pointer into our buffer */
	int    length;  /* remaining length of data */
	int    size;    /* total size of this buffer */
} datap;

typedef struct _MESSAGE_QUEUE { 
	unsigned int size; 
	LPCWSTR content; 
	struct _MESSAGE_QUEUE* next;	
} MESSAGE_QUEUE, *PMESSAGE_QUEUE;	
typedef struct _FILE_CONTENT { 
    int file_size;
    PBYTE file_content;
    struct _FILE_CONTENT* next_file; // pointer to the next file
} FILE_CONTENT, *PFILE_CONTENT;

typedef struct _FILE_ARGS {
    // represent the list of files.
    int number_of_files;
    PFILE_CONTENT file_content;
} FILE_ARGS, *PFILE_ARGS;

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

void BeaconOutput(DWORD64 type, char* data, int len);
void BeaconPrintf(DWORD64 pszDest, wchar_t* pszFormat, ...);
void BeaconAddMessage(LPCWSTR source, LPCWSTR message);
void BeaconStrcatW(wchar_t *wstr1, wchar_t *wstr2);
int BeaconWsprintf(wchar_t* dest, const wchar_t* format, ...);
int BeaconSprintf(char* dest, const char* format, ...);
int BeaconParseInt32(PBYTE* args);
char* ParseString(PBYTE* args);
LPCWSTR BeaconParseWideString(PBYTE* args);
void BeaconCharToWideString(char* str, wchar_t* wideStr);

PMESSAGE_QUEUE BeaconCreateMessageQueue();
BOOL BeaconAddMessageToQueue(PMESSAGE_QUEUE root, LPCWSTR message);
BOOL BeaconCleanUpMessageQueue(PMESSAGE_QUEUE root);
BOOL BeaconSendAllMessages(PMESSAGE_QUEUE root, LPCSTR task_uuid);