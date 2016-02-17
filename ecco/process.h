#pragma once

#include "top.h"	

class CProcess
{
public:
	
	struct Module_t
	{
		uintptr_t	Base;

		size_t		Size;
	
		std::string Name;

		Module_t( uintptr_t _Base = 0, size_t _Size = 0, std::string _Name = "empty" )
		{
			Base = _Base;
			Size = _Size;
			Name = _Name;
		}
	};

	std::vector<Module_t> Modules;

	HANDLE Handle;

	int PID = 0;

	CProcess( std::string proc )
	{
		if ( ( Handle = Get( proc ) ) == INVALID_HANDLE_VALUE )
		{
			printf( "\n [x] %s not found.\n\n\npress any key to exit...", proc.c_str( ) );
			getchar( );
			exit( 1 );
		}
	}

	HANDLE Get( std::string proc )
	{
		HANDLE Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

		PROCESSENTRY32 Processes;

		Processes.dwSize = sizeof( PROCESSENTRY32 );

		do if ( !strcmp( Processes.szExeFile, proc.c_str( ) ) )
		{
			PID = Processes.th32ProcessID;

			return OpenProcess( PROCESS_ALL_ACCESS, 0, Processes.th32ProcessID );

		} while ( Process32Next( Snapshot, &Processes ) );

		return INVALID_HANDLE_VALUE;
	}

	bool AddModule( std::string mod )
	{
		MODULEENTRY32 ModEntry;

		HANDLE ModHandle = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, PID );

		ModEntry.dwSize = sizeof( MODULEENTRY32 );

		do if ( !strcmp( ModEntry.szModule, mod.c_str( ) ) )
		{
			CloseHandle( ModHandle );

			Modules.push_back( Module_t( ( uintptr_t ) ModEntry.modBaseAddr, ModEntry.modBaseSize, std::string( ModEntry.szModule ) ) );

			return true;

		} while ( Module32Next( ModHandle, &ModEntry ) );

		return 0;
	}

	Module_t FindModule( std::string mod )
	{
		for ( auto& module : Modules )
		{
			if ( strstr( mod.c_str( ), module.Name.c_str( ) ) )
			{
				return module;
			}
		}
	}

	template < class t >
	t Read( void* Dest )
	{
		t ret;
		ReadProcessMemory( Handle, Dest, &ret, sizeof( t ), 0 );
		return ret;
	}

	bool Read( void* Dest, byte* Out, size_t Size )
	{
		return ReadProcessMemory( Handle, Dest, Out, Size, 0 );
	}

	bool Write( void* Dest, byte* Data, size_t Size )
	{
		return WriteProcessMemory( Handle, Dest, Data, Size, 0 );
	}

	void* Allocate( size_t Size )
	{
		return VirtualAllocEx( Handle, 0, Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	}

	void* AllocateWrite( std::string str )
	{
		void* block = Allocate( str.length( ) + 1 );

		Write( block, ( byte* ) str.c_str( ), str.length( ) );
		
		return block;
	}

	void* AllocateWrite( byte* Data, size_t Size )
	{
		void* block = Allocate( Size + 1 );

		Write( block, Data, Size );

		return block;
	}

	bool FreeBlock( void* block, size_t size = 0 )
	{
		return VirtualFreeEx( Handle, block, size, MEM_RELEASE );
	}

	bool MakeThread( void* At )
	{
		if ( CreateRemoteThread( Handle, 0, 0, ( LPTHREAD_START_ROUTINE ) At, 0, 0, 0 ) == INVALID_HANDLE_VALUE )
			return false;

		return true;
	}

	bool CompareBytes( byte* data, byte* mask, char *_mask )
	{
		for ( ; *_mask; ++_mask, ++data, ++mask )
			if ( *_mask == 'x' && *data != *mask )
				return 0;

		return ( *_mask == 0 );
	}

	uintptr_t FindPattern( uintptr_t start, size_t size, char* sig, char* mask )
	{
		byte* Data = new byte[ size ];

		if ( !ReadProcessMemory( Handle, ( void* ) start, Data, size, 0 ) )
			return 0;

		for ( uintptr_t i = 0; i < size; i++ )
			if ( CompareBytes( ( byte* ) ( Data + i ), ( byte* ) sig, mask ) )
				return start + i;

		delete[ ] Data;

		return 0;
	}

}; extern CProcess * Process;