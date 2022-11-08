#include <windows.h>
#include <iostream>

#include "sys_tracing.h"

VOID SyscallCallback( ULONG_PTR ReturnAddress, LARGE_INTEGER ReturnValue, ULONG_PTR ReturnStack )
{    
    __trace_lock( 1 );

    if ( ReturnAddress == KiUserExceptionDispatcher )
    {
        //
        // CONTEXT Size (0x4d0) + CONTEXT_EX Size (0x18) + Alignment (0x8)
        //
        PEXCEPTION_RECORD ExceptionRecord = PEXCEPTION_RECORD( ReturnStack + 0x4F0 );
        PCONTEXT Context = PCONTEXT( ReturnStack );

        write_file_log( "[%s] Exception Raised, Address=%p Code=%X\n",
                __FUNCTION__,
                ExceptionRecord->ExceptionAddress,
                ExceptionRecord->ExceptionCode );

        __trace_lock( 0 );
        return;
    }

    WCHAR SymbolName[MAX_SYM_NAME];
    RtlZeroMemory( &SymbolName, sizeof( SymbolName ) );

    if ( SymbolFromAddress( ReturnAddress, SymbolName, MAX_SYM_NAME ) )
    {

        printf( "[%s] ReturnAddress: %ws (%llx) ReturnValue: %X\n",
                __FUNCTION__,
                SymbolName,
                ReturnAddress,
                ReturnValue.LowPart );

    } else {

        printf( "[%s] ReturnAddress: %llx ReturnValue: %X\n",
                __FUNCTION__,
                ReturnAddress,
                ReturnValue.LowPart );

    }

    __trace_lock( 0 );
    return;
}


int main( )
{
    RegisterInstrumentationCallback( __syscall_callback );
    EnableTraceForThread( GetCurrentThread( ) );

	printf( "[%s] Press SPACE to execute shellcode\n", __FUNCTION__ );

	while ( !GetAsyncKeyState( VK_SPACE ) )
		Sleep( 100 );

	return 0;
}
