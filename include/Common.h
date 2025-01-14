#include <windows.h>
#include <Structs.h>


typedef NTSTATUS(NTAPI* fnNtCreateSection)(
	OUT PHANDLE				SectionHandle,
	IN  ACCESS_MASK			DesiredAccess,
	IN  POBJECT_ATTRIBUTES	ObjectAttributes	OPTIONAL,
	IN  PLARGE_INTEGER		MaximumSize			OPTIONAL,
	IN  ULONG				SectionPageProtection,
	IN  ULONG				AllocationAttributes,
	IN  HANDLE				FileHandle			OPTIONAL
	);

typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(
	IN		HANDLE			SectionHandle,
	IN		HANDLE			ProcessHandle,
	IN OUT	PVOID*			BaseAddress,
	IN		SIZE_T			ZeroBits,
	IN		SIZE_T			CommitSize,
	IN OUT	PLARGE_INTEGER	SectionOffset		OPTIONAL,
	IN OUT	PSIZE_T			ViewSize,
	IN		SECTION_INHERIT InheritDisposition,
	IN		ULONG			AllocationType,
	IN		ULONG			Protect
	);

typedef NTSTATUS(NTAPI* fnNtUnmapViewOfSection)(
	IN HANDLE	ProcessHandle,
	IN PVOID	BaseAddress			OPTIONAL
);

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
	IN		HANDLE		ProcessHandle,
	IN OUT	PVOID*		BaseAddress,
	IN OUT	PSIZE_T		NumberOfBytesToProtect,
	IN		ULONG		NewAccessProtection,
	OUT		PULONG		OldAccessPRotection
	);


typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
	IN	HANDLE	ProcessHandle,
	IN	PVOID	BaseAddress,
	IN	PVOID	Buffer,
	IN	ULONG	NumberOfBytesToWrite,
	OUT PULONG	NumberOfBytesWritten OPTIONAL
	);

typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)(
	OUT PHANDLE					ThreadHandle,
	IN	ACCESS_MASK             DesiredAccess,
	IN	POBJECT_ATTRIBUTES      ObjectAttributes	OPTIONAL,
	IN	HANDLE                  ProcessHandle,
	IN	PVOID                   StartRoutine,
	IN	PVOID                   Argument			OPTIONAL,
	IN	ULONG                   CreateFlags,
	IN	SIZE_T                  ZeroBits,
	IN	SIZE_T                  StackSize			OPTIONAL,
	IN	SIZE_T                  MaximumStackSize	OPTIONAL,
	OUT PPS_ATTRIBUTE_LIST      AttributeList		OPTIONAL
	);

typedef NTSTATUS(NTAPI* fnNtCreateFile)(
	OUT  PHANDLE            FileHandle,
	IN   ACCESS_MASK        DesiredAccess,
	IN   POBJECT_ATTRIBUTES ObjectAttributes,
	OUT  PIO_STATUS_BLOCK   IoStatusBlock,
	IN	 PLARGE_INTEGER     AllocationSize		OPTIONAL,
	IN   ULONG              FileAttributes,
	IN   ULONG              ShareAccess,
	IN   ULONG              CreateDisposition,
	IN   ULONG              CreateOptions,
	IN   PVOID              EaBuffer,
	IN   ULONG              EaLength
	);


typedef struct _NT_API {

	fnNtCreateFile				pNtCreateFile;
	fnNtCreateSection			pNtCreateSection;
	fnNtMapViewOfSection		pNtMapViewOfSection;
	fnNtUnmapViewOfSection		pNtUnmapViewOfSection;
	fnNtProtectVirtualMemory	pNtProtectVirtualMemory;
	fnNtWriteVirtualMemory		pNtWriteVirtualMemory;
	fnNtCreateThreadEx			pNtCreateThreadEx;

}NT_API, * PNT_API;

NT_API g_NtApi = { 0x00 };
