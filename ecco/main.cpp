#include "top.h"
#include "process.h"

CProcess * Process;

#define EngineClientPtrSig "\x8B\x0D\x00\x00\x00\x00\x8B\x01\xFF\x90\x00\x00\x00\x00\xA1\x00\x00\x00\x00\xB9\x00\x00\x00\x00\xFF\x50\x14"
#define EngineClientPtrMask "xx????xxxx????x????x????xxx"

#pragma warning( disable: 4996 )

std::vector<byte> make_shellcode( void* string, uintptr_t engine )
{
	std::vector<byte> shellcode;

	byte code[ ] = "\x8b\x0d\x00\x00\x00\x00\x68\x00\x00\x00\x00\x8b\x01\x8b\x80\xb0\x01\x00\x00\xff\xd0\xc3"; /* just a reconstructed thiscall */

	shellcode.insert( shellcode.end( ), &code[ 0 ], &code[ 22 ] );

	*( uint32_t* )	( &shellcode.at( 2 ) ) = engine;
	*( void** )	( &shellcode.at( 7 ) ) = string;

	return shellcode;
}

void main( )
{
	uintptr_t Client = 0;

	size_t ClientSize = 0;

	SetConsoleTitleA( "[e] ecco - external console for cs:go" );

	printf( "[e] starting up.\n" );

	printf( " [+] attaching to csgo.exe" );

	Process = new CProcess( "csgo.exe" );

	printf( "\t\t...done\n" );

	printf( " [+] finding client module" );

	Process->AddModule( "client.dll" );

	printf( "\t\t...done\n" );

	printf( " [+] finding IVEngineClient Pointer" );

	uintptr_t test = Process->FindPattern( Process->FindModule( "client.dll" ).Base, Process->FindModule( "client.dll" ).Size, EngineClientPtrSig, EngineClientPtrMask );

	uintptr_t engine = Process->Read<uintptr_t>( ( void* )( test + 2 ) );

	printf( "\t...done - [%X]\n\n", engine );

	char buffer[ 1024 ] = { 0 };
	
	printf( "[e] now its your turn\n" );

	while ( 1 )
	{
		memset( buffer, 0, 1024 );
		printf( " [+] input>" );
		fgets( buffer, 1023, stdin );
		strtok( buffer, "\0\r\n" );

		char* last = buffer;

		std::vector<std::string> commands;

		if ( !strstr( buffer, ";" ) )
			commands.push_back( buffer );

		for ( int i = 0; i < 1023; ++i )
		{
			if ( buffer[ i ] == ';' )
			{
				buffer[ i ] = '\0';

				commands.push_back( std::string( ( char* ) &buffer[ i ] - ( &buffer[ i ] - last ) ) );

				i += 1;

				last = &buffer[ i ];
			}
		}

		for ( int i = 0; i < commands.size( ); ++i )
		{
		start: 

			std::string com = commands.at( i );

			if ( com.at( 0 ) == ' ' ) /* make it a little prettier */
				com.erase( com.find_first_of( " " ), 1 );

			if ( strstr( com.c_str( ), "sleep" ) ) /* sleep a little bit */
			{
				Sleep( atoi( &com.at( 5 ) ) );
				continue;
			}

			if ( strstr( com.c_str( ), "goto" ) ) /* goto an old command - looping is cool :3 */
			{
				i = atoi( &com.at( 4 ) );
				goto start;
			}

			if ( strstr( com.c_str(), "clear" ) ) /* clear console just like the game ---- ghetto workaround using strstr because compare doesnt work */
			{
				system( "cls" );
				printf( "[e] cleared window\n" );
			}

			std::vector<byte> inject = make_shellcode( Process->AllocateWrite( com.c_str( ) ), engine );

			void* map = Process->AllocateWrite( &inject.at( 0 ), inject.size( ) );

			Process->MakeThread( map );

			Process->FreeBlock( map, inject.size( ) );
		}
	}
}
