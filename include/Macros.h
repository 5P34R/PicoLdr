#include <windows.h>
#include "Structs.h"

#define NtCurrentProcess()        ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()         ((HANDLE)(LONG_PTR)-2)


#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR __VA_OPT__(,) __VA_ARGS__ );                      \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0x00, buf );                                        \
        }                                                                                   \
    }


#define DELETE_HANDLE(H)								\
	if (H != NULL && H != INVALID_HANDLE_VALUE){		\
		CloseHandle(H);									\
		H = NULL;										\
	}

// constexpr ULONG RandomCompileTimeSeed(void)
// {
// 	return (__TIME__[7] - '0') * 1ULL +
//            (__TIME__[6] - '0') * 10ULL +
//            (__TIME__[4] - '0') * 60ULL +
//            (__TIME__[3] - '0') * 600ULL +
//            (__TIME__[1] - '0') * 3600ULL +
//            (__TIME__[0] - '0') * 36000ULL;
// };

// // The compile time random seed
// constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;

// constexpr UINT32 CRC32BA(IN LPCSTR String)
// {

// 	UINT32      uMask	= 0x00,
// 				uHash	= 0xFFFFEFFF;
// 	INT         i		= 0x00;

// 	while (String[i] != 0) {

// 		uHash = uHash ^ (UINT32)String[i];

// 		for (int ii = 0; ii < 8; ii++) {

// 			uMask = -1 * (uHash & 1);
// 			uHash = (uHash >> 1) ^ (0xEDB88320 & uMask);
// 		}

// 		i++;
// 	}

// 	// XOR the msb & lsb with g_KEY
// 	return ~(((uHash & 0xFFFFFF00) | ((uHash & 0xFF) ^ g_KEY)) | ((uHash & 0x00FFFFFF) | (((uHash >> 24) ^ g_KEY) << 24)));
// }

// #define CRC32_HASH(str) constexpr auto str##_HASH = CRC32BA((LPCSTR)#str)
