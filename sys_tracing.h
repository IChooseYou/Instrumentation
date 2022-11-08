#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment( lib, "ntdll.lib" )

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;
	ULONG Reserved;
	PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS  ExitStatus;
	PVOID     TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

#define NtCurrentProcess ( ( HANDLE )( LONG_PTR )-1 )

typedef NTSTATUS ( NTAPI* PFN_NtSetInformationProcess )(
	_In_ HANDLE           ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_In_ PVOID            ProcessInformation,
	_In_ ULONG            ProcessInformationLength );

typedef NTSTATUS ( NTAPI* PFN_NtContinue )(
	IN PCONTEXT ThreadContext,
	IN BOOLEAN  RaiseAlert );

typedef NTSTATUS ( NTAPI* PFN_ZwRaiseException )(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT          ContextRecord,
	IN BOOLEAN           FirstChance );

PFN_NtContinue       NtContinue       = NULL;
PFN_ZwRaiseException ZwRaiseException = NULL;

//
// defined in util.asm
//
extern "C" VOID __syscall_callback( );
//
// forward define, you add this to your code
//
extern "C" VOID SyscallCallback( ULONG_PTR ReturnAddress, LARGE_INTEGER ReturnValue, ULONG_PTR ReturnStack );
extern "C" VOID Exception( );

CONST ULONG_PTR OFFSET_TEB_ENABLE_TRACE = 0x19F0;
CONST ULONG_PTR OFFSET_TEB_LOCK_FLAG    = 0x19F8;

ULONG_PTR KiUserExceptionDispatcher = NULL;

__forceinline VOID __trace_lock( BOOL InCallback )
{
	ULONG_PTR Teb = ( ULONG_PTR )NtCurrentTeb( );
	*( ULONG_PTR* )( Teb + OFFSET_TEB_LOCK_FLAG ) = InCallback;
}

BOOL EnableTraceForThread( HANDLE Thread )
{
	THREAD_BASIC_INFORMATION ThreadBasicInformation;
	RtlZeroMemory( &ThreadBasicInformation, sizeof( ThreadBasicInformation ) );

	ULONG ReturnLength = 0;

	NTSTATUS Status = NtQueryInformationThread(
		Thread,
		THREADINFOCLASS( 0 ),
		&ThreadBasicInformation,
		( ULONG )sizeof( ThreadBasicInformation ),
		&ReturnLength );

	if ( !NT_SUCCESS( Status ) )
	{
		printf( "[%s] Failed to call NtQueryInformationThread( ), Status=0x%X\n",
				__FUNCTION__,
				Status );

		return FALSE;
	}

	printf( "[%s] Enable trace for Thread: %p, ThreadId: %p, Teb: %p\n",
			__FUNCTION__,
			Thread,
			ThreadBasicInformation.ClientId.UniqueThread,
			ThreadBasicInformation.TebBaseAddress );

	ULONG_PTR Teb = ULONG_PTR( ThreadBasicInformation.TebBaseAddress );
	*( ULONG_PTR* )( Teb + OFFSET_TEB_ENABLE_TRACE ) = 1;

	return TRUE;
}

BOOL SetPageGuard( PVOID Page )
{
	MEMORY_BASIC_INFORMATION Mbi;
	RtlZeroMemory( &Mbi, sizeof( Mbi ) );

	SIZE_T Size = VirtualQuery(
		Page,
		&Mbi,
		sizeof( MEMORY_BASIC_INFORMATION ) );

	if ( Size == 0 )
		return FALSE;

	//
	// Force STATUS_GUARD_PAGE_VIOLATION to be raised when
	// this page is accessed
	//

	DWORD flOldProtect = NULL;
	
	if ( VirtualProtect( Page, Size, Mbi.Protect | PAGE_GUARD, &flOldProtect ) )
	{
		//printf( "[%s] Failed to set PAGE_GUARD on addres: %p\n",
		//		__FUNCTION__,
		//		Page );

		return FALSE;
	}

	return TRUE;
}

BOOL RegisterInstrumentationCallback( PVOID CallbackFN )
{
	printf( "[%s] Using callback: %p\n", __FUNCTION__, CallbackFN );

	HMODULE Ntdll = LoadLibraryW( L"ntdll.dll" );

	if ( !Ntdll )
	{
		//
		// Would never happen, for intellisense
		//
		return FALSE;
	}

	FARPROC SetInformation = GetProcAddress( Ntdll, "NtSetInformationProcess" );

	if ( !SetInformation )
		return FALSE;

	//
	// Store address of KiUserExceptionDispatcher so we can
	// catch exceptions, also find NtContinue to for resume
	//
	KiUserExceptionDispatcher = ( ULONG_PTR )GetProcAddress( Ntdll, "KiUserExceptionDispatcher" );

	if ( !KiUserExceptionDispatcher )
		return FALSE;

	NtContinue = ( PFN_NtContinue )GetProcAddress( Ntdll, "NtContinue" );

	if ( !NtContinue )
		return FALSE;

	ZwRaiseException = ( PFN_ZwRaiseException )GetProcAddress( Ntdll, "ZwRaiseException" );

	if ( !ZwRaiseException )
		return FALSE;

	PFN_NtSetInformationProcess NtSetInformationProcess = PFN_NtSetInformationProcess( SetInformation );

	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION CallbackInformation;

	CallbackInformation.Callback = CallbackFN;
	CallbackInformation.Version  = 0;
	CallbackInformation.Reserved = 0;

	const PROCESSINFOCLASS ProcessInstrumentationCallback = PROCESSINFOCLASS( 0x28 );

	NTSTATUS Status = NtSetInformationProcess(
						NtCurrentProcess,
						ProcessInstrumentationCallback,
						&CallbackInformation,
						sizeof( CallbackInformation ) );

	if ( !NT_SUCCESS( Status ) )
	{
		printf( "[%s] NtSetInformationProcess( ) failed, Status=0x%X\n", __FUNCTION__, Status );
		return FALSE;
	}

	return TRUE;
}
