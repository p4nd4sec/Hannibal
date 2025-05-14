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
// typedef struct _FILE_CONTENT { 
//     int file_size;
//     PBYTE file_content;
//     struct _FILE_CONTENT* next_file; // pointer to the next file
// } FILE_CONTENT, *PFILE_CONTENT;

// typedef struct _FILE_ARGS {
//     // represent the list of files.
//     int number_of_files;
//     PFILE_CONTENT file_content;
// } FILE_ARGS, *PFILE_ARGS;

SECTION_CODE void    BeaconDataParse(datap* parser, char* buffer, int size);
SECTION_CODE int     BeaconDataInt32(datap* parser);
SECTION_CODE short   BeaconDataShort(datap* parser);
SECTION_CODE int     BeaconDataLength(datap* parser);
SECTION_CODE char*   BeaconDataExtract(datap* parser, int* size);

/* Output Functions */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

SECTION_CODE void BeaconOutput(DWORD64 type, char* data, int len);
SECTION_CODE void BeaconPrintf(DWORD64 pszDest, wchar_t* pszFormat, ...);
SECTION_CODE void BeaconAddMessage(LPCWSTR source, LPCWSTR message);
SECTION_CODE void BeaconStrcatW(wchar_t *wstr1, wchar_t *wstr2);
SECTION_CODE int BeaconWsprintf(wchar_t* dest, const wchar_t* format, ...);
SECTION_CODE int BeaconSprintf(char* dest, const char* format, ...);
SECTION_CODE int BeaconParseInt32(PBYTE* args);
SECTION_CODE char* BeaconParseString(PBYTE* args);
SECTION_CODE LPCWSTR BeaconParseWideString(PBYTE* args);
SECTION_CODE void BeaconCharToWideString(char* str, wchar_t* wideStr);
SECTION_CODE PMESSAGE_QUEUE BeaconCreateMessageQueue();
SECTION_CODE BOOL BeaconAddMessageToQueue(PMESSAGE_QUEUE root, LPCWSTR message);
SECTION_CODE BOOL BeaconCleanUpMessageQueue(PMESSAGE_QUEUE root);
SECTION_CODE BOOL BeaconSendAllMessages(PMESSAGE_QUEUE root, LPCSTR task_uuid);