#include <windows.h>

void* MmCopy(void* dest, const void* src, size_t count) {

	char* dest2			= (char*)dest;
	const char* src2	= (const char*)src;

	while (count--)
		*dest2++ = *src2++;

	return dest;
}


void* _malloc(size_t size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

void _free(void* mem) {
	HeapFree(GetProcessHeap(), 0x00, mem);
}