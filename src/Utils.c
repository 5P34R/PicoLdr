#include <windows.h>
#include "Structs.h"
#include "Macros.h"
#include "Utils.h"



VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize = wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}


BOOL GetResourceFile( _In_ HMODULE hModule, _In_ DWORD dwResourceId, _Out_ PBYTE *ppBuffer, _Out_ PSIZE_T pResSize ) 
{

    if ( !hModule || !dwResourceId || !ppBuffer || !pResSize ) {
#ifdef DEBUG
        PRINTA("[-] Required arguments are not met");
#endif 
        return FALSE;
    }

    PVOID pPayloadBaseAddress = NULL;
    ULONG_PTR BaseAddress = hModule;

    PIMAGE_NT_HEADERS pImgHdr = (PIMAGE_NT_HEADERS)(BaseAddress + ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew);

    if ( !pImgHdr -> Signature == IMAGE_NT_SIGNATURE ) {
#ifdef DEBUG
        PRINTA("[-] Nt Signature Mismatch");
#endif 
        return FALSE;
    }

    PIMAGE_DATA_DIRECTORY pImgEntryResourceDataDir = &pImgHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    PIMAGE_RESOURCE_DIRECTORY           pResourceDir				= NULL, pResourceDir2	= NULL, pResourceDir3	= NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY     pResourceEntry				= NULL, pResourceEntry2 = NULL, pResourceEntry3 = NULL;
	PIMAGE_RESOURCE_DATA_ENTRY          pResource					= NULL;

    pResourceDir = (PIMAGE_RESOURCE_DIRECTORY)(BaseAddress + pImgEntryResourceDataDir->VirtualAddress);
    pResourceEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir + 1);;


    for (DWORD i = 0; i < (pResourceDir->NumberOfIdEntries + pResourceDir->NumberOfNamedEntries); i++) {

        if (pResourceEntry[i].DataIsDirectory == 0)
			break;

        pResourceDir2		= (PIMAGE_RESOURCE_DIRECTORY)(BaseAddress + pImgEntryResourceDataDir->VirtualAddress + (pResourceEntry[i].OffsetToDirectory & 0x7FFFFFFF));
		pResourceEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir2 + 1);


        if (pResourceEntry2->DataIsDirectory == 1 && pResourceEntry2->Id == dwResourceId) {

			pResourceDir3		= (PIMAGE_RESOURCE_DIRECTORY)(BaseAddress + pImgEntryResourceDataDir->VirtualAddress + (pResourceEntry2->OffsetToDirectory & 0x7FFFFFFF));
			pResourceEntry3		= (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir3 + 1);
			pResource			= (PIMAGE_RESOURCE_DATA_ENTRY)(BaseAddress + pImgEntryResourceDataDir->VirtualAddress + (pResourceEntry3->OffsetToData & 0x7FFFFFFF));
			pPayloadBaseAddress	= (PVOID)(BaseAddress + (pResource->OffsetToData));
			*pResSize			= pResource->Size;
			break;
        }    
    }
    
    if (!(*ppBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *pResSize))) {
#ifdef DEBUG
        PRINTA("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
#endif 
        return FALSE;
    }

    MmCopy(*ppBuffer, pPayloadBaseAddress, *pResSize);
    return TRUE;
}




/*
// Example:

CRC32_HASH(NTDLL);                  // Creates the NTDLL_HASH compile-time variable
GetModuleHandleH(NTDLL_HASH);       // Fetches the base address of ntdll.dll (module handle)
*/

// HMODULE GetModuleHandleH(IN UINT32 uDllNameHash) {

// 	PPEB                    pPeb			= NULL;
// 	PPEB_LDR_DATA           pLdrData		= NULL;
// 	PLDR_DATA_TABLE_ENTRY   pDataTableEntry = NULL;

// #ifdef _WIN64
// 	pPeb = (PEB*)(__readgsqword(0x60));
// #elif _WIN32
// 	pPeb = (PEB*)(__readfsdword(0x30));
// #endif

// 	pLdrData		= (PPEB_LDR_DATA)(pPeb->Ldr);
// 	pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)(pLdrData->InMemoryOrderModuleList.Flink);

// 	if (!uDllNameHash)
// 		return (HMODULE)(pDataTableEntry->InInitializationOrderLinks.Flink);

// 	while (pDataTableEntry->FullDllName.Buffer) {

// 		if (pDataTableEntry->FullDllName.Length > 0x00 && pDataTableEntry->FullDllName.Length < MAX_PATH) {

// 			CHAR	cUprDllFileName[MAX_PATH] = { 0x00 };

// 			// Dont copy ".dll" extension
// 			// Example: "ntdll.dll" -> "NTDLL"
// 			for (int i = 0; i < pDataTableEntry->FullDllName.Length && pDataTableEntry->FullDllName.Buffer[i] != '.'; i++) {
// 				if (pDataTableEntry->FullDllName.Buffer[i] >= 'a' && pDataTableEntry->FullDllName.Buffer[i] <= 'z')
// 					cUprDllFileName[i] = pDataTableEntry->FullDllName.Buffer[i] - 'a' + 'A';
// 				else
// 					cUprDllFileName[i] = pDataTableEntry->FullDllName.Buffer[i];
// 			}

// 			if (CRC32BA(cUprDllFileName) == uDllNameHash)
// 				return (HMODULE)(pDataTableEntry->InInitializationOrderLinks.Flink);
// 		}

// 		pDataTableEntry = *(PLDR_DATA_TABLE_ENTRY*)(pDataTableEntry);
// 	}

// 	return NULL;
// }



VOID PrintHexArray(IN PBYTE pBufferData, IN SIZE_T sBufferSize) {

	for (SIZE_T x = 0; x < sBufferSize; x++){

		if (x % 16 == 0)
			PRINTA("\n\t");

		if (x == sBufferSize - 1) {
			PRINTA("0x%0.2X", pBufferData[x]);
		}
		else {
			PRINTA("0x%0.2X, ", pBufferData[x]);
		}
	}

	PRINTA("\n};\n");
}