#define STRICT
#define WIN32_LEAN_AND_MEAN

#define _WINSOCKAPI_

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <process.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <lm.h>
#include <wbemidl.h>
#include <ntsecapi.h>
#include <dsgetdc.h>
#include <winldap.h>
#include <winber.h>
#include <aclapi.h>
#include <time.h>
#include <sddl.h>
#include <mgmtapi.h>
#include <snmp.h>
#include "WinScanX.h"

#define MAX_THREADS 64

#pragma comment( lib, "kernel32.lib" )
#pragma comment( lib, "user32.lib" )
#pragma comment( lib, "ws2_32.lib" )
#pragma comment( lib, "iphlpapi.lib" )
#pragma comment( lib, "netapi32.lib" )
#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )
#pragma comment( lib, "wbemuuid.lib" )
#pragma comment( lib, "advapi32.lib" )
#pragma comment( lib, "wldap32.lib" )
#pragma comment( lib, "version.lib" )
#pragma comment( lib, "snmpapi.lib" )
#pragma comment( lib, "mgmtapi.lib" )

VOID                          CopySZ( CHAR *szDestination, size_t siDestination, CONST CHAR *szSource );
VOID                         CopyWSZ( WCHAR *wszDestination, size_t siDestination, WCHAR *wszSource );
VOID                  ConvertSZtoWSZ( WCHAR *wszDestination, size_t siDestination, CHAR *szSource );
VOID                  ConvertWSZtoSZ( CHAR *szDestination, size_t siDestination, WCHAR *wszSource );
VOID                           Usage( VOID );
VOID            KeyboardEventMonitor( VOID *pParameter );
VOID               RemoveBackslashes( CHAR *szText );
BOOL                       IsIPRange( CHAR *szTargetInput, CHAR *szIPNetwork );
VOID                            Trim( CHAR *szText, size_t siText );
VOID                     ThreadedSub( VOID *pParameter );
VOID                    CheckOptions( CHAR *szOptions, BOOL *bHasSMBOption, BOOL *bHasWMIOption );
VOID                 WriteToErrorLog( CHAR *szTarget, CHAR *szFunction, CHAR *szErrorMsg );
VOID        WriteLastErrorToErrorLog( CHAR *szTarget, CHAR *szFunction, DWORD *dwError );
VOID WriteLastErrorToConnectErrorLog( CHAR *szTarget, CHAR *szRemoteLocation, CHAR *szDomainName, CHAR *szUsername, CHAR *szPassword, DWORD *dwError );
BOOL                  PingRemoteHost( CHAR *szTarget );
BOOL                         Connect( CHAR *szTarget, CHAR *szUsername, CHAR *szPassword, BOOL bSuppressErrors );
BOOL                      Disconnect( CHAR *szTarget );
VOID                      WMIConnect( CHAR *szOptions, CHAR *szTarget, CHAR *szUsername, CHAR *szPassword, CHAR *szWMIRoot );
VOID            GetAccountPolicyInfo( CHAR *szTarget );
VOID              GetAuditPolicyInfo( CHAR *szTarget );
VOID             GetDisplayInfoUsers( CHAR *szTarget );
VOID          GetDisplayInfoMachines( CHAR *szTarget );
VOID                   GetDomainInfo( CHAR *szTarget );
VOID                     GetLDAPInfo( CHAR *szTarget );
VOID                       LDAPQuery( CHAR *szTarget, LDAP *pLDAPConnection, WCHAR *pBaseDN, WCHAR *pFilter, CHAR *szNewBaseDN, size_t siNewBaseDN );
VOID               GetLocalGroupInfo( CHAR *szTarget );
VOID              GetGlobalGroupInfo( CHAR *szTarget );
VOID               GetWMIProductInfo( CHAR *szTarget, IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate );
VOID               GetWMIProcessInfo( CHAR *szTarget, IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate );
VOID                GetLoggedOnUsers( CHAR *szTarget );
VOID                    GetPatchInfo( CHAR *szTarget );
BOOL                  SplitPatchInfo( CHAR *szText, CHAR *szSplitText, CHAR *szOSVersion, size_t siOSVersion, CHAR *szServicePack, size_t siServicePack, CHAR *szMSAdvisory, size_t siMSAdvisory, CHAR *szFilePath, size_t siFilePath, DWORD *dwHMS, DWORD *dwLMS, DWORD *dwHLS, DWORD *dwLLS );
BOOL                  GetFileVersion( CHAR *szTarget, CHAR *szFilePath, DWORD *dwHMS, DWORD *dwLMS, DWORD *dwHLS, DWORD *dwLLS );
VOID                 GetRegistryInfo( CHAR *szTarget );
BOOL               SplitRegistryInfo( CHAR *szText, CHAR *szSplitText, CHAR *szSubKeyName, CHAR *szKeyName );
VOID              GetWMIRegistryInfo( CHAR *szTarget, IWbemServices *pService );
VOID               RunRemoteCommands( CHAR *szTarget, IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, CHAR *szUsername, CHAR *szPassword );
BOOL                SplitCommandInfo( CHAR *szText, CHAR *szSplitText, CHAR *szCommandType, CHAR *szCommandText );
BOOL                IsProcessRunning( CHAR *szTarget, IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, DWORD *dwProcessID );
VOID                   GetServerInfo( CHAR *szTarget );
VOID                  GetServiceInfo( CHAR *szTarget );
VOID               GetWMIServiceInfo( CHAR *szTarget, IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate );
VOID                    GetShareInfo( CHAR *szTarget );
VOID             GetSharePermissions( CHAR *szTarget );
VOID                     GetUserInfo( CHAR *szTarget );
VOID                   GetRAUserInfo( CHAR *szTarget );
BOOL                   GetMachineSID( CHAR *szTarget, CHAR *szMachineSID );
BOOL           GetAccountNameFromSID( CHAR *szTarget, CHAR *szStringSID, CHAR *szDomainName, size_t siDomainName, CHAR *szAccountName, size_t siAccountName );
VOID               GetUserRightsInfo( CHAR *szTarget );
VOID       GuessSNMPCommunityStrings( CHAR *szTarget );
BOOL                     SNMPConnect( CHAR *szTarget, CHAR *szCommunityString );
VOID      LogGuessedCommunityStrings( CHAR *szTarget, CHAR *szCommunityString );
VOID           GuessWindowsPasswords( CHAR *szTarget );
VOID      LogGuessedWindowsPasswords( CHAR *szTarget, CHAR *szUsername, CHAR *szPassword );

typedef struct _THREAD_ARGS
{
	CHAR  Options[ 128 ];
	CHAR   Target[ 128 ];
	CHAR Username[ 128 ];
	CHAR Password[ 128 ];
} THREAD_ARGS, *PTHREAD_ARGS;

HANDLE hSemaphore;

BOOL bMultipleHosts         = FALSE;
BOOL bVerboseOptionSelected = FALSE;
BOOL bStopOptionSelected    = FALSE;

INT nThreads = 0;

INT main( INT argc, CHAR *argv[] )
{
	CHAR    szDirectory[ 128 ];
	WCHAR  wszDirectory[ 256 ];
	DWORD       dwError;
	CHAR      szOptions[ 128 ];
	CHAR  szTargetInput[ 128 ];
	CHAR     szUsername[ 128 ];
	CHAR     szPassword[ 128 ];
	FILE    *pInputFile;
	CHAR     szReadLine[ 128 ];
	CHAR       szTarget[ 128 ];
	CHAR    szIPNetwork[ 128 ];
	DWORD             i;

	PTHREAD_ARGS pThreadArgs;

	if ( argc < 3 || argc > 5 )
	{
		Usage();

		return 1;
	}

	CopySZ( szDirectory, sizeof( szDirectory ), "UserCache" );

	ConvertSZtoWSZ( wszDirectory, sizeof( wszDirectory ), szDirectory );

	if ( !CreateDirectory( wszDirectory, NULL ) )
	{
		dwError = GetLastError();

		if ( dwError != ERROR_ALREADY_EXISTS )
		{
			fprintf( stderr, "ERROR! Cannot create UserCache directory.\n" );

			fflush( stderr );

			return 1;
		}
	}

	CopySZ( szDirectory, sizeof( szDirectory ), "Reports" );

	ConvertSZtoWSZ( wszDirectory, sizeof( wszDirectory ), szDirectory );

	if ( !CreateDirectory( wszDirectory, NULL ) )
	{
		dwError = GetLastError();

		if ( dwError != ERROR_ALREADY_EXISTS )
		{
			fprintf( stderr, "ERROR! Cannot create Reports directory.\n" );

			fflush( stderr );

			return 1;
		}
	}

	hSemaphore = CreateSemaphore( NULL, 1, 1, NULL );

	_beginthread( KeyboardEventMonitor, 0, NULL );

	CopySZ( szOptions, sizeof( szOptions ), "" );
	CopySZ( szTargetInput, sizeof( szTargetInput ), "" );
	CopySZ( szUsername, sizeof( szUsername ), "" );
	CopySZ( szPassword, sizeof( szPassword ), "" );

	if ( argc > 1 )
	{
		CopySZ( szOptions, sizeof( szOptions ), argv[1] );

		if ( strstr( argv[1], "-1" ) != NULL )
		{
			sprintf( szOptions, "%sadgnsur", argv[1] );
		}

		if ( strstr( argv[1], "-2" ) != NULL )
		{
			sprintf( szOptions, "%sabdgpklijnostux", argv[1] );
		}
	}

	if ( argc > 2 )
	{
		CopySZ( szTargetInput, sizeof( szTargetInput ), argv[2] );
	}

	if ( argc > 3 )
	{
		CopySZ( szUsername, sizeof( szUsername ), argv[3] );
	}

	if ( argc > 4 )
	{
		CopySZ( szPassword, sizeof( szPassword ), argv[4] );
	}

	printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
	printf( "+                                                 +\n" );
	printf( "+  WinScanX v1.2 | https://github.com/reedarvin   +\n" );
	printf( "+                                                 +\n" );
	printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
	printf( "\n" );
	printf( "Running WinScanX v1.1 with the following arguments:\n" );
	printf( "[+] Options:      \"%s\"\n", argv[1] );
	printf( "[+] Host Input:   \"%s\"\n", szTargetInput );
	printf( "[+] Username:     \"%s\"\n", szUsername );
	printf( "[+] Password:     \"%s\"\n", szPassword );
	printf( "[+] # of Threads: \"64\"\n" );
	printf( "\n" );

	fflush( stdout );

	pInputFile = fopen( szTargetInput, "r" );

	if ( pInputFile != NULL )
	{
		bMultipleHosts = TRUE;

		while ( fscanf( pInputFile, "%s", szReadLine ) != EOF )
		{
			if ( !bStopOptionSelected )
			{
				RemoveBackslashes( szReadLine );

				CopySZ( szTarget, sizeof( szTarget ), szReadLine );

				while ( nThreads >= MAX_THREADS )
				{
					Sleep( 200 );
				}

				pThreadArgs = (PTHREAD_ARGS)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof( THREAD_ARGS ) );

				if ( pThreadArgs != NULL )
				{
					CopySZ( pThreadArgs->Options, sizeof( pThreadArgs->Options ), szOptions );
					CopySZ( pThreadArgs->Target, sizeof( pThreadArgs->Target ), szTarget );
					CopySZ( pThreadArgs->Username, sizeof( pThreadArgs->Username ), szUsername );
					CopySZ( pThreadArgs->Password, sizeof( pThreadArgs->Password ), szPassword );

					WaitForSingleObject( hSemaphore, INFINITE );

					nThreads++;

					ReleaseSemaphore( hSemaphore, 1, NULL );

					_beginthread( ThreadedSub, 0, (VOID *)pThreadArgs );
				}
			}
		}

		fclose( pInputFile );

		Sleep( 5000 );

		printf( "Waiting for threads to terminate...\n" );

		fflush( stdout );
	}
	else if ( IsIPRange( szTargetInput, szIPNetwork ) )
	{
		bMultipleHosts = TRUE;

		for ( i = 1; i < 255; i++ )
		{
			if ( !bStopOptionSelected )
			{
				sprintf( szTarget, "%s%d", szIPNetwork, i );

				while ( nThreads >= MAX_THREADS )
				{
					Sleep( 200 );
				}

				pThreadArgs = (PTHREAD_ARGS)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof( THREAD_ARGS ) );

				if ( pThreadArgs != NULL )
				{
					CopySZ( pThreadArgs->Options, sizeof( pThreadArgs->Options ), szOptions );
					CopySZ( pThreadArgs->Target, sizeof( pThreadArgs->Target ), szTarget );
					CopySZ( pThreadArgs->Username, sizeof( pThreadArgs->Username ), szUsername );
					CopySZ( pThreadArgs->Password, sizeof( pThreadArgs->Password ), szPassword );

					WaitForSingleObject( hSemaphore, INFINITE );

					nThreads++;

					ReleaseSemaphore( hSemaphore, 1, NULL );

					_beginthread( ThreadedSub, 0, (VOID *)pThreadArgs );
				}
			}
		}

		Sleep( 5000 );

		printf( "Waiting for threads to terminate...\n" );

		fflush( stdout );
	}
	else
	{
		RemoveBackslashes( szTargetInput );

		CopySZ( szTarget, sizeof( szTarget ), szTargetInput );

		pThreadArgs = (PTHREAD_ARGS)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof( THREAD_ARGS ) );

		if ( pThreadArgs != NULL )
		{
			CopySZ( pThreadArgs->Options, sizeof( pThreadArgs->Options ), szOptions );
			CopySZ( pThreadArgs->Target, sizeof( pThreadArgs->Target ), szTarget );
			CopySZ( pThreadArgs->Username, sizeof( pThreadArgs->Username ), szUsername );
			CopySZ( pThreadArgs->Password, sizeof( pThreadArgs->Password ), szPassword );

			WaitForSingleObject( hSemaphore, INFINITE );

			nThreads++;

			ReleaseSemaphore( hSemaphore, 1, NULL );

			_beginthread( ThreadedSub, 0, (VOID *)pThreadArgs );
		}
	}

	while ( nThreads > 0 )
	{
		Sleep( 200 );
	}

	CloseHandle( hSemaphore );

	return 0;
}

VOID CopySZ( CHAR szDestination[], size_t siDestination, CONST CHAR szSource[] )
{
	INT iBufferSize;

	iBufferSize = (INT)( siDestination / sizeof( CHAR ) );

	strcpy_s( szDestination, iBufferSize, szSource );
}

VOID CopyWSZ( WCHAR wszDestination[], size_t siDestination, WCHAR wszSource[] )
{
	INT iBufferSize;

	iBufferSize = (INT)( siDestination / sizeof( WCHAR ) );

	wcscpy_s( wszDestination, iBufferSize, wszSource );
}

VOID ConvertSZtoWSZ( WCHAR wszDestination[], size_t siDestination, CHAR szSource[] )
{
	INT iBufferSize;
	INT iStringSize;

	iBufferSize = (INT)( siDestination / sizeof( WCHAR ) );

	iStringSize = MultiByteToWideChar( CP_ACP, 0, szSource, -1, NULL, 0 );

	if ( iStringSize != 0 )
	{
		if ( iStringSize > iBufferSize )
		{
			iStringSize = MultiByteToWideChar( CP_ACP, 0, szSource, -1, wszDestination, iBufferSize );

			wszDestination[ iBufferSize - 1 ] = L'\0';
		}
		else
		{
			iStringSize = MultiByteToWideChar( CP_ACP, 0, szSource, -1, wszDestination, iStringSize );
		}
	}
}

VOID ConvertWSZtoSZ( CHAR szDestination[], size_t siDestination, WCHAR wszSource[] )
{
	INT iBufferSize;
	INT iStringSize;

	iBufferSize = (INT)( siDestination / sizeof( CHAR ) );

	iStringSize = WideCharToMultiByte( CP_ACP, 0, wszSource, -1, NULL, 0, NULL, NULL );

	if ( iStringSize != 0 )
	{
		if ( iStringSize > iBufferSize )
		{
			iStringSize = WideCharToMultiByte( CP_ACP, 0, wszSource, -1, szDestination, iBufferSize, NULL, NULL );

			szDestination[ iBufferSize - 1 ] = '\0';
		}
		else
		{
			iStringSize = WideCharToMultiByte( CP_ACP, 0, wszSource, -1, szDestination, iStringSize, NULL, NULL );
		}
	}
}

VOID Usage( VOID )
{
	printf( "WinScanX v1.2 | https://github.com/reedarvin\n" );
	printf( "\n" );
	printf( "Usage: WinScanX [-abcdegpklijmnosturxzSW12] <hostname | ip range | ip input file> <username> <password>\n" );
	printf( "\n" );
	printf( "[-abcdegpklijmnosturxzSW12]            -- required argument\n" );
	printf( "<hostname | ip range | ip input file>  -- required argument\n" );
	printf( "<username>                             -- optional argument\n" );
	printf( "<password>                             -- optional argument\n" );
	printf( "\n" );
	printf( "If the <username> and <password> arguments are omitted, this utility\n" );
	printf( "will attempt to establish a NetBIOS null session and gather information\n" );
	printf( "via the null session.\n" );
	printf( "\n" );
	printf( "If the <username> and <password> arguments are both plus signs (+), the\n" );
	printf( "existing credentials of the user running this utility will be used.\n" );
	printf( "\n" );
	printf( "Examples:\n" );
	printf( "WinScanX -1 10.10.10.10\n" );
	printf( "WinScanX -1 10.10.10.10 + +\n" );
	printf( "WinScanX -2 10.10.10.10 administrator password\n" );
	printf( "WinScanX -2 10.10.10.10 domain\\admin password\n" );
	printf( "\n" );
	printf( "WinScanX -1 WINSERVER01\n" );
	printf( "WinScanX -1 WINSERVER01 + +\n" );
	printf( "WinScanX -2 WINSERVER01 administrator password\n" );
	printf( "WinScanX -2 WINSERVER01 domain\\admin password\n" );
	printf( "\n" );
	printf( "WinScanX -1 192.168.1-254\n" );
	printf( "WinScanX -1 192.168.1-254 + +\n" );
	printf( "WinScanX -2 192.168.1-254 administrator password\n" );
	printf( "WinScanX -2 192.168.1-254 domain\\admin password\n" );
	printf( "\n" );
	printf( "WinScanX -1 IPInputFile.txt\n" );
	printf( "WinScanX -1 IPInputFile.txt + +\n" );
	printf( "WinScanX -2 IPInputFile.txt administrator password\n" );
	printf( "WinScanX -2 IPInputFile.txt domain\\admin password\n" );
	printf( "\n" );
	printf( "\n" );
	printf( "==== WinScanX Advanced Features ====\n" );
	printf( "\n" );
	printf( "-a  -- Get Account Policy Information\n" );
	printf( "-b  -- Get Audit Policy Information\n" );
	printf( "-c  -- Get Display Information\n" );
	printf( "-d  -- Get Domain Information\n" );
	printf( "-e  -- Get LDAP Information\n" );
	printf( "-g  -- Get Local & Global Group Information\n" );
	printf( "-p  -- Get Program Information\n" );
	printf( "-k  -- Get Process Information\n" );
	printf( "-l  -- Get Logged On Users\n" );
	printf( "-i  -- Get Patch Information\n" );
	printf( "-j  -- Get Registry Information\n" );
	printf( "-m  -- Run Remote Commands via WMI\n" );
	printf( "-n  -- Get Server Information\n" );
	printf( "-o  -- Get Service Information\n" );
	printf( "-s  -- Get Share Information\n" );
	printf( "-t  -- Get Share Permissions\n" );
	printf( "-u  -- Get User Information\n" );
	printf( "-r  -- Get User Information via RA Bypass\n" );
	printf( "-x  -- Get User Rights Information\n" );
	printf( "\n" );
	printf( "-z  -- Ping Remote Host Before Scanning\n" );
	printf( "\n" );
	printf( "-S  -- Guess SNMP Community Strings\n" );
	printf( "-W  -- Guess Windows Passwords\n" );
	printf( "\n" );
	printf( "-1  -- Group 1 (includes -adgnsur)\n" );
	printf( "-2  -- Group 2 (includes -abdgpklijnostux)\n" );
	printf( "\n" );
	printf( "\n" );
	printf( "==== Retrieving Patch Information ====\n" );
	printf( "\n" );
	printf( "The information that is queried for each host to determine the existance\n" );
	printf( "of a patch is included in the PatchInfo.input file.\n" );
	printf( "\n" );
	printf( "\n" );
	printf( "==== Retrieving Registry Information ====\n" );
	printf( "\n" );
	printf( "The registry key/value pairs that are queried for each host are included\n" );
	printf( "in the RegistryInfo.input file.\n" );
	printf( "\n" );
	printf( "\n" );
	printf( "==== Running Remote Commands via WMI ====\n" );
	printf( "\n" );
	printf( "The remote commands that are run on each host via WMI are included in the\n" );
	printf( "RemoteCommands.input file.\n" );
	printf( "\n" );
	printf( "\n" );
	printf( "==== SNMP Community String Guessing ====\n" );
	printf( "\n" );
	printf( "The SNMP community strings that are attempted for each host are included\n" );
	printf( "in the CommunityStrings.input file.\n" );
	printf( "\n" );
	printf( "\n" );
	printf( "==== Windows Password Guessing ====\n" );
	printf( "\n" );
	printf( "For Windows password guessing to occur, there must be a matching\n" );
	printf( "<hostname>.users file in the UserCache directory for each host on which\n" );
	printf( "you attempt to guess passwords. WinScanX options -c, -r, -u, and -S can be\n" );
	printf( "used to generate <hostname>.users cache files.\n" );
	printf( "\n" );
	printf( "The passwords that are attempted for each user account are included in the\n" );
	printf( "Dictionary.input file.\n" );
	printf( "\n" );
	printf( "The following can also be used in the Dictionary.input file:\n" );
	printf( "\n" );
	printf( "<username>   -- The name of the current user\n" );
	printf( "<lcusername> -- The name of the current user in lower case\n" );
	printf( "<ucusername> -- The name of the current user in upper case\n" );
	printf( "<blank>      -- A blank or null password\n" );
	printf( "\n" );
	printf( "(Written by Reed Arvin | reedlarvin@gmail.com)\n" );

	fflush( stdout );
}

VOID KeyboardEventMonitor( VOID *pParameter )
{
	HANDLE               hStdin;
	INPUT_RECORD       irBuffer[ 128 ];
	DWORD             dwNumRead;
	DWORD                     i;
	KEY_EVENT_RECORD    kerInfo;
	DWORD               dwError;
	CHAR               szTarget[ 128 ];
	CHAR             szFunction[ 128 ];

	hStdin = GetStdHandle( STD_INPUT_HANDLE );

	if ( hStdin != INVALID_HANDLE_VALUE )
	{
		while ( TRUE )
		{
			if ( ReadConsoleInput( hStdin, irBuffer, 128, &dwNumRead ) )
			{
				for ( i = 0; i < dwNumRead; i++ )
				{
					if ( irBuffer[i].EventType == KEY_EVENT )
					{
						kerInfo = irBuffer[i].Event.KeyEvent;

						if ( kerInfo.bKeyDown )
						{
							if ( kerInfo.wVirtualKeyCode == 86 ) // v key
							{
								if ( bVerboseOptionSelected == FALSE )
								{
									printf( "\n" );
									printf( "Verbose mode ON.\n" );
									printf( "\n" );

									fflush( stdout );

									bVerboseOptionSelected = TRUE;
								}
								else
								{
									printf( "\n" );
									printf( "Verbose mode OFF.\n" );
									printf( "\n" );

									fflush( stdout );

									bVerboseOptionSelected = FALSE;
								}
							}

							if ( kerInfo.wVirtualKeyCode == 81 ) // q key
							{
								if ( bStopOptionSelected == FALSE )
								{
									printf( "\n" );
									printf( "Stopping...\n" );
									printf( "\n" );

									fflush( stdout );

									bStopOptionSelected = TRUE;
								}
							}

							if ( kerInfo.wVirtualKeyCode == VK_SPACE )
							{
								printf( "\n" );
								printf( "%d threads currently running.\n", nThreads );
								printf( "\n" );

								fflush( stdout );
							}
						}
					}
				}
			}

			Sleep( 10 );
		}
	}
	else
	{
		dwError = GetLastError();

		CopySZ( szTarget, sizeof( szTarget ), "localhost" );
		CopySZ( szFunction, sizeof( szFunction ), "GetStdHandle (KeyboardEventMonitor)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
	}
}

VOID RemoveBackslashes( CHAR szText[] )
{
	CHAR *pLocation;

	pLocation = strstr( szText, "\\\\" );

	if ( pLocation != NULL )
	{
		pLocation++;
		pLocation++;

		CopySZ( szText, sizeof( szText ), pLocation );
	}
}

BOOL IsIPRange( CHAR szTargetInput[], CHAR szIPNetwork[] )
{
	BOOL  bReturn;
	DWORD       i;
	DWORD       j;

	bReturn = FALSE;

	if ( strstr( szTargetInput, "1-254" ) != NULL )
	{
		CopySZ( szIPNetwork, sizeof( szIPNetwork ), "" );

		i = 0;
		j = 0;

		while ( szTargetInput[i] != '\0' && j != 3 )
		{
			if ( szTargetInput[i] == '.' )
			{
				j++;
			}
			else
			{
				if ( szTargetInput[i] != '0' && szTargetInput[i] != '1' && szTargetInput[i] != '2' && szTargetInput[i] != '3' && szTargetInput[i] != '4' && szTargetInput[i] != '5' && szTargetInput[i] != '6' && szTargetInput[i] != '7' && szTargetInput[i] != '8' && szTargetInput[i] != '9' )
				{
					break;
				}
			}

			szIPNetwork[i] = szTargetInput[i];

			i++;
		}

		szIPNetwork[i] = '\0';

		if ( j == 3 )
		{
			bReturn = TRUE;
		}
	}

	return bReturn;
}

VOID Trim( CHAR szText[], size_t siText )
{
	DWORD            i;
	DWORD dwTextLength;
	DWORD  dwStartChar;
	DWORD    dwEndChar;
	CHAR    szTempText[ 10240 ];
	DWORD            j;

	i = 0;

	dwTextLength = (DWORD)strlen( szText );

	while ( i < dwTextLength )
	{
		if ( szText[i] == ' ' )
		{
			i++;
		}
		else
		{
			break;
		}
	}

	dwStartChar = i;

	i = dwTextLength - 1;

	while ( i > 0 )
	{
		if ( szText[i] == ' ' )
		{
			i--;
		}
		else
		{
			break;
		}
	}

	dwEndChar = i;

	i = dwStartChar;
	j = 0;

	while ( i <= dwEndChar )
	{
		szTempText[j] = szText[i];

		i++;
		j++;
	}

	szTempText[j] = '\0';

	CopySZ( szText, siText, szTempText );
}

VOID ThreadedSub( VOID *pParameter )
{
	CHAR       szOptions[ 128 ];
	CHAR        szTarget[ 128 ];
	CHAR      szUsername[ 128 ];
	CHAR      szPassword[ 128 ];
	BOOL   bHasSMBOption;
	BOOL   bHasWMIOption;
	BOOL       bSkipPing;
	BOOL       bPingable;
	BOOL bSkipIPCConnect;
	BOOL   bIPCConnected;
	CHAR       szWMIRoot[ 128 ];

	PTHREAD_ARGS pThreadArgs;

	pThreadArgs = (PTHREAD_ARGS)pParameter;

	CopySZ( szOptions, sizeof( szOptions ), pThreadArgs->Options );
	CopySZ( szTarget, sizeof( szTarget ), pThreadArgs->Target );
	CopySZ( szUsername, sizeof( szUsername ), pThreadArgs->Username );
	CopySZ( szPassword, sizeof( szPassword ), pThreadArgs->Password );

	HeapFree( GetProcessHeap(), 0, pThreadArgs );

	bHasSMBOption   = FALSE;
	bHasWMIOption   = FALSE;
	bSkipPing       = FALSE;
	bPingable       = FALSE;
	bSkipIPCConnect = FALSE;
	bIPCConnected   = FALSE;

	CheckOptions( szOptions, &bHasSMBOption, &bHasWMIOption );

	if ( bMultipleHosts )
	{
		printf( "Spawning thread for host %s...\n", szTarget );

		fflush( stdout );
	}

	if ( strchr( szOptions, 'z' ) == NULL )
	{
		bSkipPing = TRUE;
	}
	else
	{
		if ( PingRemoteHost( szTarget ) )
		{
			bPingable = TRUE;
		}
	}

	if ( bHasSMBOption )
	{
		if ( strcmp( szUsername, "+" ) == 0 && strcmp( szPassword, "+" ) == 0 )
		{
			bSkipIPCConnect = TRUE;
		}
		else
		{
			if ( Connect( szTarget, szUsername, szPassword, FALSE ) )
			{
				bIPCConnected = TRUE;
			}
		}

		if ( ( bSkipPing || bPingable ) && ( bSkipIPCConnect || bIPCConnected ) )
		{
			if ( strchr( szOptions, 'a' ) != NULL )
			{
				GetAccountPolicyInfo( szTarget );
			}

			if ( strchr( szOptions, 'b' ) != NULL )
			{
				GetAuditPolicyInfo( szTarget );
			}

			if ( strchr( szOptions, 'c' ) != NULL )
			{
				GetDisplayInfoUsers( szTarget );
				GetDisplayInfoMachines( szTarget );
			}

			if ( strchr( szOptions, 'd' ) != NULL )
			{
				GetDomainInfo( szTarget );
			}

			if ( strchr( szOptions, 'g' ) != NULL )
			{
				GetLocalGroupInfo( szTarget );
				GetGlobalGroupInfo( szTarget );
			}

			if ( strchr( szOptions, 'i' ) != NULL )
			{
				GetPatchInfo( szTarget );
			}

			if ( strchr( szOptions, 'j' ) != NULL )
			{
				GetRegistryInfo( szTarget );
			}

			if ( strchr( szOptions, 'l' ) != NULL )
			{
				GetLoggedOnUsers( szTarget );
			}

			if ( strchr( szOptions, 'n' ) != NULL )
			{
				GetServerInfo( szTarget );
			}

			if ( strchr( szOptions, 'o' ) != NULL )
			{
				GetServiceInfo( szTarget );
			}

			if ( strchr( szOptions, 's' ) != NULL )
			{
				GetShareInfo( szTarget );
			}

			if ( strchr( szOptions, 't' ) != NULL )
			{
				GetSharePermissions( szTarget );
			}

			if ( strchr( szOptions, 'u' ) != NULL )
			{
				GetUserInfo( szTarget );
			}

			if ( strchr( szOptions, 'r' ) != NULL )
			{
				GetRAUserInfo( szTarget );
			}

			if ( strchr( szOptions, 'x' ) != NULL )
			{
				GetUserRightsInfo( szTarget );
			}
		}

		if ( ( bSkipPing || bPingable ) && bIPCConnected )
		{
			Disconnect( szTarget );
		}
	}

	if ( ( bSkipPing || bPingable ) )
	{
		if ( strchr( szOptions, 'e' ) != NULL )
		{
			GetLDAPInfo( szTarget );
		}

		if ( bHasWMIOption )
		{
			if ( strchr( szOptions, 'j' ) != NULL )
			{
				CopySZ( szWMIRoot, sizeof( szWMIRoot ),  "root\\default" );

				WMIConnect( szOptions, szTarget, szUsername, szPassword, szWMIRoot );
			}

			if ( strchr( szOptions, 'k' ) != NULL || strchr( szOptions, 'm' ) != NULL || strchr( szOptions, 'o' ) != NULL || strchr( szOptions, 'p' ) != NULL )
			{
				CopySZ( szWMIRoot, sizeof( szWMIRoot ),  "root\\cimv2" );

				WMIConnect( szOptions, szTarget, szUsername, szPassword, szWMIRoot );
			}
		}

		if ( strchr( szOptions, 'S' ) != NULL )
		{
			GuessSNMPCommunityStrings( szTarget );
		}

		if ( strchr( szOptions, 'W' ) != NULL )
		{
			GuessWindowsPasswords( szTarget );
		}
	}

	WaitForSingleObject( hSemaphore, INFINITE );

	nThreads--;

	ReleaseSemaphore( hSemaphore, 1, NULL );

	_endthread();
}

VOID CheckOptions( CHAR szOptions[], BOOL *bHasSMBOption, BOOL *bHasWMIOption )
{
	if ( strchr( szOptions, 'a' ) != NULL )
	{
		*bHasSMBOption = TRUE;
	}

	if ( strchr( szOptions, 'b' ) != NULL )
	{
		*bHasSMBOption = TRUE;
	}

	if ( strchr( szOptions, 'c' ) != NULL )
	{
		*bHasSMBOption = TRUE;
	}

	if ( strchr( szOptions, 'd' ) != NULL )
	{
		*bHasSMBOption = TRUE;
	}

	if ( strchr( szOptions, 'g' ) != NULL )
	{
		*bHasSMBOption = TRUE;
	}

	if ( strchr( szOptions, 'i' ) != NULL )
	{
		*bHasSMBOption = TRUE;
	}

	if ( strchr( szOptions, 'j' ) != NULL )
	{
		*bHasSMBOption = TRUE;
		*bHasWMIOption = TRUE;
	}

	if ( strchr( szOptions, 'k' ) != NULL )
	{
		*bHasWMIOption = TRUE;
	}

	if ( strchr( szOptions, 'l' ) != NULL )
	{
		*bHasSMBOption = TRUE;
	}

	if ( strchr( szOptions, 'm' ) != NULL )
	{
		*bHasWMIOption = TRUE;
	}

	if ( strchr( szOptions, 'n' ) != NULL )
	{
		*bHasSMBOption = TRUE;
	}

	if ( strchr( szOptions, 'o' ) != NULL )
	{
		*bHasSMBOption = TRUE;
		*bHasWMIOption = TRUE;
	}

	if ( strchr( szOptions, 'p' ) != NULL )
	{
		*bHasWMIOption = TRUE;
	}

	if ( strchr( szOptions, 's' ) != NULL )
	{
		*bHasSMBOption = TRUE;
	}

	if ( strchr( szOptions, 't' ) != NULL )
	{
		*bHasSMBOption = TRUE;
	}

	if ( strchr( szOptions, 'u' ) != NULL )
	{
		*bHasSMBOption = TRUE;
	}

	if ( strchr( szOptions, 'r' ) != NULL )
	{
		*bHasSMBOption = TRUE;
	}

	if ( strchr( szOptions, 'x' ) != NULL )
	{
		*bHasSMBOption = TRUE;
	}
}

VOID WriteToErrorLog( CHAR szTarget[], CHAR szFunction[], CHAR szErrorMsg[] )
{
	FILE *pOutputFile;

	if ( !bMultipleHosts )
	{
		fprintf( stderr, "ERROR! %s - %s\n", szFunction, szErrorMsg );

		fflush( stderr );
	}

	WaitForSingleObject( hSemaphore, INFINITE );

	pOutputFile = fopen( "Reports\\ErrorLog.txt", "r" );

	if ( pOutputFile != NULL )
	{
		fclose( pOutputFile );
	}
	else
	{
		pOutputFile = fopen( "Reports\\ErrorLog.txt", "w" );

		if ( pOutputFile != NULL )
		{
			fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
			fprintf( pOutputFile, "\n" );
			fprintf( pOutputFile, "Hostname\tFunction Name\tError Number\tError Message\n" );

			fclose( pOutputFile );
		}
	}

	pOutputFile = fopen( "Reports\\ErrorLog.txt", "a+" );

	if ( pOutputFile != NULL )
	{
		fprintf( pOutputFile, "%s\t%s\t-\t%s\n", szTarget, szFunction, szErrorMsg );

		fclose( pOutputFile );
	}
	ReleaseSemaphore( hSemaphore, 1, NULL );
}

VOID WriteLastErrorToErrorLog( CHAR szTarget[], CHAR szFunction[], DWORD *dwError )
{
	DWORD     dwReturn;
	WCHAR  wszErrorMsg[ 256 ];
	CHAR    szErrorMsg[ 128 ];
	CHAR     *pNewLine;
	FILE  *pOutputFile;

	dwReturn = FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, *dwError, MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ), wszErrorMsg, 256, NULL );

	if ( dwReturn > 0 )
	{
		ConvertWSZtoSZ( szErrorMsg, sizeof( szErrorMsg ), wszErrorMsg );

		pNewLine = strchr( szErrorMsg, '\r' );

		if ( pNewLine != NULL )
		{
			*pNewLine = '\0';
		}

		pNewLine = strchr( szErrorMsg, '\n' );

		if ( pNewLine != NULL )
		{
			*pNewLine = '\0';
		}
	}
	else
	{
		CopySZ( szErrorMsg, sizeof( szErrorMsg ), "Unknown error occurred." );
	}

	if ( !bMultipleHosts )
	{
		fprintf( stderr, "ERROR! %s - %s\n", szFunction, szErrorMsg );

		fflush( stderr );
	}

	WaitForSingleObject( hSemaphore, INFINITE );

	pOutputFile = fopen( "Reports\\ErrorLog.txt", "r" );

	if ( pOutputFile != NULL )
	{
		fclose( pOutputFile );
	}
	else
	{
		pOutputFile = fopen( "Reports\\ErrorLog.txt", "w" );

		if ( pOutputFile != NULL )
		{
			fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
			fprintf( pOutputFile, "\n" );
			fprintf( pOutputFile, "Hostname\tFunction Name\tError Number\tError Message\n" );

			fclose( pOutputFile );
		}
	}

	pOutputFile = fopen( "Reports\\ErrorLog.txt", "a+" );

	if ( pOutputFile != NULL )
	{
		fprintf( pOutputFile, "%s\t%s\t%d\t%s\n", szTarget, szFunction, *dwError, szErrorMsg );

		fclose( pOutputFile );
	}

	ReleaseSemaphore( hSemaphore, 1, NULL );
}

VOID WriteLastErrorToConnectErrorLog( CHAR szTarget[], CHAR szRemoteLocation[], CHAR szDomainName[], CHAR szUsername[], CHAR szPassword[], DWORD *dwError )
{
	DWORD     dwReturn;
	WCHAR  wszErrorMsg[ 256 ];
	CHAR    szErrorMsg[ 128 ];
	CHAR     *pNewLine;
	FILE  *pOutputFile;

	dwReturn = FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, *dwError, MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ), wszErrorMsg, 256, NULL );

	if ( dwReturn > 0 )
	{
		ConvertWSZtoSZ( szErrorMsg, sizeof( szErrorMsg ), wszErrorMsg );

		pNewLine = strchr( szErrorMsg, '\r' );

		if ( pNewLine != NULL )
		{
			*pNewLine = '\0';
		}

		pNewLine = strchr( szErrorMsg, '\n' );

		if ( pNewLine != NULL )
		{
			*pNewLine = '\0';
		}
	}
	else
	{
		CopySZ( szErrorMsg, sizeof( szErrorMsg ), "Unknown error occurred." );
	}

	WaitForSingleObject( hSemaphore, INFINITE );

	pOutputFile = fopen( "Reports\\ConnectErrorLog.txt", "r" );

	if ( pOutputFile != NULL )
	{
		fclose( pOutputFile );
	}
	else
	{
		pOutputFile = fopen( "Reports\\ConnectErrorLog.txt", "w" );

		if ( pOutputFile != NULL )
		{
			fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
			fprintf( pOutputFile, "\n" );
			fprintf( pOutputFile, "Hostname\tRemote Location\tAccount Name\tPassword\tError Number\tError Message\n" );

			fclose( pOutputFile );
		}
	}

	pOutputFile = fopen( "Reports\\ConnectErrorLog.txt", "a+" );

	if ( pOutputFile != NULL )
	{
		if ( strcmp( szDomainName, "" ) == 0 && strcmp( szUsername, "" ) == 0 )
		{
			if ( strcmp( szPassword, "" ) == 0 )
			{
				fprintf( pOutputFile, "%s\t%s\t(Null)\t(Null)\t%d\t%s\n", szTarget, szRemoteLocation, *dwError, szErrorMsg );
			}
			else
			{
				fprintf( pOutputFile, "%s\t%s\t(Null)\t%s\t%d\t%s\n", szTarget, szRemoteLocation, szPassword, *dwError, szErrorMsg );
			}
		}
		else
		{
			if ( strcmp( szPassword, "" ) == 0 )
			{
				fprintf( pOutputFile, "%s\t%s\t%s\\%s\t<blank>\t%d\t%s\n", szTarget, szRemoteLocation, szDomainName, szUsername, *dwError, szErrorMsg );
			}
			else
			{
				fprintf( pOutputFile, "%s\t%s\t%s\\%s\t%s\t%d\t%s\n", szTarget, szRemoteLocation, szDomainName, szUsername, szPassword, *dwError, szErrorMsg );
			}
		}

		fclose( pOutputFile );
	}

	ReleaseSemaphore( hSemaphore, 1, NULL );
}

BOOL PingRemoteHost( CHAR szTarget[] )
{
	BOOL                  bReturn;
	INT                   nResult;
	WSADATA               wsaData;
	CHAR              szIPAddress[ 16 ];
	HANDLE              hICMPFile;
	CHAR               szSendData[ 32 ];
	DWORD             dwReplySize;
	VOID            *pReplyBuffer;
	DWORD                dwStatus;
	ICMP_ECHO_REPLY   *pEchoReply;
	FILE             *pOutputFile;
	DWORD                 dwError;
	CHAR              szLogTarget[ 128 ];
	CHAR               szFunction[ 128 ];

	struct hostent *remoteHost;

	bReturn = FALSE;

	nResult = WSAStartup( MAKEWORD( 2, 2 ), &wsaData );

	if ( nResult == NO_ERROR )
	{
		remoteHost = gethostbyname( szTarget );

		if ( remoteHost != NULL )
		{
			CopySZ( szIPAddress, sizeof( szIPAddress ), inet_ntoa( *(struct in_addr *)remoteHost->h_addr_list[0] ) );

			hICMPFile = IcmpCreateFile();

			if ( hICMPFile != INVALID_HANDLE_VALUE )
			{
				CopySZ( szSendData, sizeof( szSendData ), "ABCDEFGHIJKLMNOPQRSTUVWXYZ" );

				dwReplySize = sizeof( ICMP_ECHO_REPLY ) + sizeof( szSendData );

				pReplyBuffer = NULL;

				pReplyBuffer = (VOID *)LocalAlloc( LMEM_FIXED, dwReplySize );

				if ( pReplyBuffer != NULL )
				{
					dwStatus = IcmpSendEcho( hICMPFile, *(DWORD *)remoteHost->h_addr_list[0], szSendData, sizeof( szSendData ), NULL, pReplyBuffer, dwReplySize, 5000 );

					if ( dwStatus != 0 )
					{
						pEchoReply = (ICMP_ECHO_REPLY *)pReplyBuffer;

						bReturn = TRUE;

						if ( !bMultipleHosts )
						{
							printf( "Host %s is alive! (%d.%d.%d.%d, Time %dms, TTL %d)\n", szTarget, LOBYTE( LOWORD( pEchoReply->Address ) ), HIBYTE( LOWORD( pEchoReply->Address ) ), LOBYTE( HIWORD( pEchoReply->Address ) ), HIBYTE( HIWORD( pEchoReply->Address ) ), pEchoReply->RoundTripTime, pEchoReply->Options.Ttl );

							fflush( stdout );
						}

						if ( bVerboseOptionSelected && bMultipleHosts )
						{
							printf( "%s -> Host is alive! (%d.%d.%d.%d, Time %dms, TTL %d)\n", szTarget, LOBYTE( LOWORD( pEchoReply->Address ) ), HIBYTE( LOWORD( pEchoReply->Address ) ), LOBYTE( HIWORD( pEchoReply->Address ) ), HIBYTE( HIWORD( pEchoReply->Address ) ), pEchoReply->RoundTripTime, pEchoReply->Options.Ttl );

							fflush( stdout );
						}

						WaitForSingleObject( hSemaphore, INFINITE );

						pOutputFile = fopen( "Reports\\PingableHosts.txt", "r" );

						if ( pOutputFile != NULL )
						{
							fclose( pOutputFile );
						}
						else
						{
							pOutputFile = fopen( "Reports\\PingableHosts.txt", "w" );

							if ( pOutputFile != NULL )
							{
								fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
								fprintf( pOutputFile, "\n" );
								fprintf( pOutputFile, "Hostname\tIP Address\tPing Stats\n" );

								fclose( pOutputFile );
							}
						}

						pOutputFile = fopen( "Reports\\PingableHosts.txt", "a+" );

						if ( pOutputFile != NULL )
						{
							fprintf( pOutputFile, "%s\t%s\t(%d.%d.%d.%d, Time %dms, TTL %d)\n", szTarget, szIPAddress, LOBYTE( LOWORD( pEchoReply->Address ) ), HIBYTE( LOWORD( pEchoReply->Address ) ), LOBYTE( HIWORD( pEchoReply->Address ) ), HIBYTE( HIWORD( pEchoReply->Address ) ), pEchoReply->RoundTripTime, pEchoReply->Options.Ttl );

							fclose( pOutputFile );
						}

						ReleaseSemaphore( hSemaphore, 1, NULL );
					}
					else
					{
						dwError = GetLastError();

						CopySZ( szFunction, sizeof( szFunction ), "IcmpSendEcho (PingRemoteHost)" );

						WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
					}

					LocalFree( pReplyBuffer );
				}
				else
				{
					dwError = GetLastError();

					CopySZ( szFunction, sizeof( szFunction ), "LocalAlloc (PingRemoteHost)" );

					WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
				}

				IcmpCloseHandle( hICMPFile );
			}
			else
			{
				dwError = GetLastError();

				CopySZ( szFunction, sizeof( szFunction ), "IcmpCreateFile (PingRemoteHost)" );
				
				WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
			}
		}
		else
		{
			dwError = WSAGetLastError();

			CopySZ( szFunction, sizeof( szFunction ), "gethostbyname (PingRemoteHost)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}
	}
	else
	{
		dwError = WSAGetLastError();

		CopySZ( szLogTarget, sizeof( szLogTarget ), "localhost" );
		CopySZ( szFunction, sizeof( szFunction ), "WSAStartup (PingRemoteHost)" );

		WriteLastErrorToErrorLog( szLogTarget, szFunction, &dwError );
	}

	WSACleanup();

	return bReturn;
}

BOOL Connect( CHAR szTarget[], CHAR szUsername[], CHAR szPassword[], BOOL bSuppressErrors )
{
	BOOL                  bReturn;
	CHAR             szTempTarget[ 128 ];
	CHAR             szRemoteName[ 128 ];
	CHAR               *pLocation;
	DWORD          dwTextLocation;
	DWORD                       i;
	CHAR             szDomainName[ 128 ];
	DWORD                       j;
	CHAR           szTempUsername[ 128 ];
	WCHAR           wszRemoteName[ 256 ];
	WCHAR           wszDomainName[ 256 ];
	WCHAR             wszUsername[ 256 ];
	WCHAR             wszPassword[ 256 ];
	DWORD                 dwLevel;
	USE_INFO_2            ui2Info;
	NET_API_STATUS        nStatus;
	DWORD                 dwError;
	CHAR               szFunction[ 128 ];

	bReturn = FALSE;

	sprintf( szTempTarget, "\\\\%s", szTarget );

	sprintf( szRemoteName, "%s\\IPC$", szTempTarget );

	pLocation = strstr( szUsername, "\\" );

	if ( pLocation != NULL )
	{
		dwTextLocation = (INT)( pLocation - szUsername );

		i = 0;

		while ( i < dwTextLocation )
		{
			szDomainName[i] = szUsername[i];

			i++;
		}

		szDomainName[i] = '\0';

		i = dwTextLocation + 1;

		j = 0;

		while ( i < strlen( szUsername ) )
		{
			szTempUsername[j] = szUsername[i];

			i++;
			j++;
		}

		szTempUsername[j] = '\0';
	}
	else
	{
		if ( strcmp( szUsername, "" ) != 0 )
		{
			CopySZ( szDomainName, sizeof( szDomainName ), szTarget );
		}
		else
		{
			CopySZ( szDomainName, sizeof( szDomainName ), "" );
		}

		CopySZ( szTempUsername, sizeof( szTempUsername ), szUsername );
	}

	ConvertSZtoWSZ( wszRemoteName, sizeof( wszRemoteName ), szRemoteName );
	ConvertSZtoWSZ( wszDomainName, sizeof( wszDomainName ), szDomainName );
	ConvertSZtoWSZ( wszUsername, sizeof( wszUsername ), szTempUsername );
	ConvertSZtoWSZ( wszPassword, sizeof( wszPassword ), szPassword );

	dwLevel = 2;

	ui2Info.ui2_local      = NULL;
	ui2Info.ui2_remote     = wszRemoteName;
	ui2Info.ui2_password   = wszPassword;
	ui2Info.ui2_asg_type   = USE_IPC;
	ui2Info.ui2_username   = wszUsername;
	ui2Info.ui2_domainname = wszDomainName;

	nStatus = NetUseAdd( NULL, dwLevel, (BYTE *)&ui2Info, NULL );

	if ( nStatus == NERR_Success )
	{
		bReturn = TRUE;
	}
	else
	{
		dwError = nStatus;

		if ( !bSuppressErrors )
		{
			CopySZ( szFunction, sizeof( szFunction ), "NetUseAdd (Connect)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}

		WriteLastErrorToConnectErrorLog( szTarget, szRemoteName, szDomainName, szTempUsername, szPassword, &dwError );
	}

	return bReturn;
}

BOOL Disconnect( CHAR szTarget[] )
{
	BOOL                 bReturn;
	CHAR            szTempTarget[ 128 ];
	CHAR            szRemoteName[ 128 ];
	WCHAR          wszRemoteName[ 256 ];
	NET_API_STATUS       nStatus;
	DWORD                dwError;
	CHAR              szFunction[ 128 ];

	bReturn = FALSE;

	sprintf( szTempTarget, "\\\\%s", szTarget );

	sprintf( szRemoteName, "%s\\IPC$", szTempTarget );

	ConvertSZtoWSZ( wszRemoteName, sizeof( wszRemoteName ), szRemoteName );

	nStatus = NetUseDel( NULL, wszRemoteName, USE_LOTS_OF_FORCE );

	if ( nStatus == NERR_Success )
	{
		bReturn = TRUE;
	}
	else
	{
		dwError = nStatus;

		CopySZ( szFunction, sizeof( szFunction ), "NetUseDel (Disconnect)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
	}

	return bReturn;
}

VOID WMIConnect( CHAR szOptions[], CHAR szTarget[], CHAR szUsername[], CHAR szPassword[], CHAR szWMIRoot[] )
{
	BOOL                 bImpersonate;
	CHAR                   *pLocation;
	DWORD              dwTextLocation;
	DWORD                           i;
	CHAR                 szDomainName[ 128 ];
	DWORD                           j;
	CHAR               szTempUsername[ 128 ];
	HRESULT                   hResult;
	IWbemLocator            *pLocator;
	CHAR            szNetworkResource[ 128 ];
	WCHAR          wszNetworkResource[ 256 ];
	BSTR           bszNetworkResource;
	CHAR               szFullUsername[ 128 ];
	WCHAR             wszFullUsername[ 256 ];
	WCHAR                 wszPassword[ 256 ];
	BSTR              bszFullUsername;
	BSTR                  bszPassword;
	IWbemServices           *pService;
	WCHAR               wszDomainName[ 256 ];
	WCHAR                 wszUsername[ 256 ];
	COAUTHIDENTITY       authIdentity;
	CHAR                   szFunction[ 128 ];

	bImpersonate = FALSE;

	if ( strcmp( szUsername, "+" ) == 0 && strcmp( szPassword, "+" ) == 0 )
	{
		bImpersonate = TRUE;
	}

	pLocation = strstr( szUsername, "\\" );

	if ( pLocation != NULL )
	{
		dwTextLocation = (INT)( pLocation - szUsername );

		i = 0;

		while ( i < dwTextLocation )
		{
			szDomainName[i] = szUsername[i];

			i++;
		}

		szDomainName[i] = '\0';

		i = dwTextLocation + 1;

		j = 0;

		while ( i < strlen( szUsername ) )
		{
			szTempUsername[j] = szUsername[i];

			i++;
			j++;
		}

		szTempUsername[j] = '\0';
	}
	else
	{
		if ( strcmp( szUsername, "" ) != 0 )
		{
			CopySZ( szDomainName, sizeof( szDomainName ), szTarget );
		}
		else
		{
			CopySZ( szDomainName, sizeof( szDomainName ), "" );
		}

		CopySZ( szTempUsername, sizeof( szTempUsername ), szUsername );
	}

	hResult = CoInitializeEx( 0, COINIT_MULTITHREADED );

	if ( SUCCEEDED( hResult ) )
	{
		if ( bImpersonate )
		{
			hResult = CoInitializeSecurity( NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL );
		}
		else
		{
			hResult = CoInitializeSecurity( NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY, NULL, EOAC_NONE, NULL );
		}

		if ( SUCCEEDED( hResult ) )
		{
			pLocator = NULL;

			hResult = CoCreateInstance( CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (PVOID *)&pLocator );

			if ( SUCCEEDED( hResult ) )
			{
				sprintf( szNetworkResource, "\\\\%s\\%s", szTarget, szWMIRoot );

				ConvertSZtoWSZ( wszNetworkResource, sizeof( wszNetworkResource ), szNetworkResource );

				bszNetworkResource = SysAllocString( wszNetworkResource );

				sprintf( szFullUsername, "%s\\%s", szDomainName, szTempUsername );

				ConvertSZtoWSZ( wszFullUsername, sizeof( wszFullUsername ), szFullUsername );
				ConvertSZtoWSZ( wszPassword, sizeof( wszPassword ), szPassword );

				bszFullUsername = SysAllocString( wszFullUsername );
				bszPassword     = SysAllocString( wszPassword );

				pService = NULL;

				if ( bImpersonate )
				{
					hResult = pLocator->ConnectServer( bszNetworkResource, NULL, NULL, NULL, NULL, NULL, NULL, &pService );
				}
				else
				{
					hResult = pLocator->ConnectServer( bszNetworkResource, bszFullUsername, bszPassword, NULL, NULL, NULL, NULL, &pService );
				}

				if ( SUCCEEDED( hResult ) )
				{
					if ( bImpersonate )
					{
						hResult = CoSetProxyBlanket( pService, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE );
					}
					else
					{
						ConvertSZtoWSZ( wszDomainName, sizeof( wszDomainName ), szDomainName );
						ConvertSZtoWSZ( wszUsername, sizeof( wszUsername ), szTempUsername );

						memset( &authIdentity, 0, sizeof( COAUTHIDENTITY ) );

						authIdentity.Domain         = (USHORT*)wszDomainName;
						authIdentity.DomainLength   = (ULONG)wcslen( wszDomainName );
						authIdentity.User           = (USHORT*)wszUsername;
						authIdentity.UserLength     = (ULONG)wcslen( wszUsername );
						authIdentity.Password       = (USHORT*)wszPassword;
						authIdentity.PasswordLength = (ULONG)wcslen( wszPassword );

						authIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

						hResult = CoSetProxyBlanket( pService, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, &authIdentity, EOAC_NONE );
					}

					if ( SUCCEEDED( hResult ) )
					{
						if ( strcmp( szWMIRoot, "root\\cimv2" ) == 0 )
						{
							if ( strchr( szOptions, 'k' ) != NULL )
							{
								GetWMIProcessInfo( szTarget, pService, &authIdentity, &bImpersonate );
							}

							if ( strchr( szOptions, 'm' ) != NULL )
							{
								RunRemoteCommands( szTarget, pService, &authIdentity, &bImpersonate, szUsername, szPassword );
							}

							if ( strchr( szOptions, 'o' ) != NULL )
							{
								GetWMIServiceInfo( szTarget, pService, &authIdentity, &bImpersonate );
							}

							if ( strchr( szOptions, 'p' ) != NULL )
							{
								GetWMIProductInfo( szTarget, pService, &authIdentity, &bImpersonate );
							}
						}

						if ( strcmp( szWMIRoot, "root\\default" ) == 0 )
						{
							if ( strchr( szOptions, 'j' ) != NULL )
							{
								GetWMIRegistryInfo( szTarget, pService );
							}
						}
					}
					else
					{
						CopySZ( szFunction, sizeof( szFunction ), "CoSetProxyBlanket (WMIConnect)" );

						WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
					}

					pService->Release();
				}
				else
				{
					CopySZ( szFunction, sizeof( szFunction ), "ConnectServer (WMIConnect)" );

					WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
				}

				SysFreeString( bszNetworkResource );
				SysFreeString( bszFullUsername );
				SysFreeString( bszPassword );

				pLocator->Release();
			}
			else
			{
				CopySZ( szFunction, sizeof( szFunction ), "CoCreateInstance (WMIConnect)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
			}
		}
		else
		{
			CopySZ( szFunction, sizeof( szFunction ), "CoInitializeSecurity (WMIConnect)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
		}
	}
	else
	{
		CopySZ( szFunction, sizeof( szFunction ), "CoInitializeEx (WMIConnect)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
	}

	CoUninitialize();
}

VOID GetAccountPolicyInfo( CHAR szTarget[] )
{
	CHAR                     szTempTarget[ 128 ];
	WCHAR                       wszTarget[ 256 ];
	DWORD                         dwLevel;
	USER_MODALS_INFO_0            *pInfo0;
	NET_API_STATUS                nStatus;
	CHAR                   szMaxPasswdAge[ 128 ];
	CHAR                   szMinPasswdAge[ 128 ];
	CHAR                    szForceLogoff[ 128 ];
	USER_MODALS_INFO_1            *pInfo1;
	CHAR                      szPrimaryDC[ 128 ];
	USER_MODALS_INFO_2            *pInfo2;
	CHAR                     szDomainName[ 128 ];
	USER_MODALS_INFO_3            *pInfo3;
	CHAR                szLockoutDuration[ 128 ];
	CHAR                    szResetWindow[ 128 ];
	CHAR               szLockoutThreshold[ 128 ];
	FILE                     *pOutputFile;
	DWORD                         dwError;
	CHAR                       szFunction[ 128 ];

	sprintf( szTempTarget, "\\\\%s", szTarget );

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTempTarget );

	dwLevel = 0;
	pInfo0  = NULL;

	nStatus = NetUserModalsGet( wszTarget, dwLevel, (PBYTE *)&pInfo0 );

	if ( nStatus == NERR_Success )
	{
		if ( pInfo0 != NULL )
		{
			if ( pInfo0->usrmod0_max_passwd_age == TIMEQ_FOREVER )
			{
				CopySZ( szMaxPasswdAge, sizeof( szMaxPasswdAge ), "Passwords never expire" );
			}
			else
			{
				sprintf( szMaxPasswdAge, "%d days", pInfo0->usrmod0_max_passwd_age / 86400 );
			}

			sprintf( szMinPasswdAge, "%d days", pInfo0->usrmod0_min_passwd_age / 86400 );

			if ( pInfo0->usrmod0_force_logoff == TIMEQ_FOREVER )
			{
				CopySZ( szForceLogoff, sizeof( szForceLogoff ), "Users are not forced to logoff" );
			}
			else
			{
				sprintf( szForceLogoff, "%d seconds", pInfo0->usrmod0_force_logoff );
			}

			dwLevel = 1;
			pInfo1  = NULL;

			nStatus = NetUserModalsGet( wszTarget, dwLevel, (PBYTE *)&pInfo1 );

			if ( nStatus == NERR_Success )
			{
				if ( pInfo1 != NULL )
				{
					ConvertWSZtoSZ( szPrimaryDC, sizeof( szPrimaryDC ), pInfo1->usrmod1_primary );

					dwLevel = 2;
					pInfo2  = NULL;

					nStatus = NetUserModalsGet( wszTarget, dwLevel, (PBYTE *)&pInfo2 );

					if ( nStatus == NERR_Success )
					{
						if ( pInfo2 != NULL )
						{
							ConvertWSZtoSZ( szDomainName, sizeof( szDomainName ), pInfo2->usrmod2_domain_name );

							dwLevel = 3;
							pInfo3  = NULL;

							nStatus = NetUserModalsGet( wszTarget, dwLevel, (PBYTE *)&pInfo3 );

							if ( nStatus == NERR_Success )
							{
								if ( pInfo3 != NULL )
								{
									if ( pInfo3->usrmod3_lockout_duration == TIMEQ_FOREVER )
									{
										CopySZ( szLockoutDuration, sizeof( szLockoutDuration ), "Forever" );
									}
									else
									{
										sprintf( szLockoutDuration, "%d minutes", pInfo3->usrmod3_lockout_duration / 60 );
									}

									sprintf( szResetWindow, "%d minutes", pInfo3->usrmod3_lockout_observation_window / 60 );

									if ( pInfo3->usrmod3_lockout_threshold == 0 )
									{
										CopySZ( szLockoutThreshold, sizeof( szLockoutThreshold ), "Accounts do not lockout" );
									}
									else
									{
										sprintf( szLockoutThreshold, "%d attempts", pInfo3->usrmod3_lockout_threshold );
									}

									if ( !bMultipleHosts )
									{
										printf( "\n" );
										printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
										printf( "+++++       ACCOUNT POLICY INFORMATION        +++++\n" );
										printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
										printf( "\n" );

										printf( "Lockout Duration:          %s\n",            szLockoutDuration );
										printf( "Counter Reset After:       %s\n",            szResetWindow );
										printf( "Lockout Threshold:         %s\n",            szLockoutThreshold );
										printf( "Minimum Password Length:   %d characters\n", pInfo0->usrmod0_min_passwd_len );
										printf( "Maximum Password Age:      %s\n",            szMaxPasswdAge );
										printf( "Minimum Password Age:      %s\n",            szMinPasswdAge );
										printf( "Force Logoff After:        %s\n",            szForceLogoff );
										printf( "Password History Length:   %d passwords\n",  pInfo0->usrmod0_password_hist_len );
										printf( "Primary Domain Controller: %s\n",            szPrimaryDC );
										printf( "Domain Name:               %s\n",            szDomainName );
										printf( "\n" );

										fflush( stdout );
									}

									if ( bVerboseOptionSelected && bMultipleHosts )
									{
										printf( "%s -> Logging account policy information.\n", szTarget );

										fflush( stdout );
									}

									WaitForSingleObject( hSemaphore, INFINITE );

									pOutputFile = fopen( "Reports\\AccountPolicyInfo.txt", "r" );

									if ( pOutputFile != NULL )
									{
										fclose( pOutputFile );
									}
									else
									{
										pOutputFile = fopen( "Reports\\AccountPolicyInfo.txt", "w" );

										if ( pOutputFile != NULL )
										{
											fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
											fprintf( pOutputFile, "\n" );
											fprintf( pOutputFile, "Hostname\tLockout Duration\tCounter Reset After\tLockout Threshold\tMinimum Password Length\tMaximum Password Age\tMinimum Password Age\tForce Logoff After\tPassword History Length\tPrimary Domain Controller\tDomain Name\n" );

											fclose( pOutputFile );
										}
									}

									pOutputFile = fopen( "Reports\\AccountPolicyInfo.txt", "a+" );

									if ( pOutputFile != NULL )
									{
										fprintf( pOutputFile, "%s\t%s\t%s\t%s\t%d characters\t%s\t%s\t%s\t%d passwords\t%s\t%s\n", szTarget, szLockoutDuration, szResetWindow, szLockoutThreshold, pInfo0->usrmod0_min_passwd_len, szMaxPasswdAge, szMinPasswdAge, szForceLogoff, pInfo0->usrmod0_password_hist_len, szPrimaryDC, szDomainName );

										fclose( pOutputFile );
									}

									ReleaseSemaphore( hSemaphore, 1, NULL );

									NetApiBufferFree( pInfo3 );
								}
							}
							else
							{
								dwError = nStatus;

								CopySZ( szFunction, sizeof( szFunction ), "NetUserModalsGet (GetAccountPolicyInfo)" );

								WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
							}

							NetApiBufferFree( pInfo2 );
						}
					}
					else
					{
						dwError = nStatus;

						CopySZ( szFunction, sizeof( szFunction ), "NetUserModalsGet (GetAccountPolicyInfo)" );

						WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
					}

					NetApiBufferFree( pInfo1 );
				}
			}
			else
			{
				dwError = nStatus;

				CopySZ( szFunction, sizeof( szFunction ), "NetUserModalsGet (GetAccountPolicyInfo)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
			}

			NetApiBufferFree( pInfo0 );
		}
	}
	else
	{
		dwError = nStatus;

		CopySZ( szFunction, sizeof( szFunction ), "NetUserModalsGet (GetAccountPolicyInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
	}
}

VOID GetAuditPolicyInfo( CHAR szTarget[] )
{
	WCHAR                                    wszTarget[ 256 ];
	LSA_UNICODE_STRING                   lusSystemName;
	LSA_OBJECT_ATTRIBUTES                loaAttributes;
	NTSTATUS                                  ntStatus;
	LSA_HANDLE                        lsahPolicyHandle;
	POLICY_AUDIT_EVENTS_INFO                    *pInfo;
	CHAR                             szAuditingEnabled[ 16 ];
	CHAR                     szDirectoryServiceAccess1[ 16 ];
	CHAR                     szDirectoryServiceAccess2[ 16 ];
	CHAR                         szAccountLogonEvents1[ 16 ];
	CHAR                         szAccountLogonEvents2[ 16 ];
	DWORD                                            i;
	CHAR                               szSystemEvents1[ 16 ];
	CHAR                               szSystemEvents2[ 16 ];
	CHAR                                szLogonEvents1[ 16 ];
	CHAR                                szLogonEvents2[ 16 ];
	CHAR                               szObjectAccess1[ 16 ];
	CHAR                               szObjectAccess2[ 16 ];
	CHAR                               szPrivilegeUse1[ 16 ];
	CHAR                               szPrivilegeUse2[ 16 ];
	CHAR                            szProcessTracking1[ 16 ];
	CHAR                            szProcessTracking2[ 16 ];
	CHAR                               szPolicyChange1[ 16 ];
	CHAR                               szPolicyChange2[ 16 ];
	CHAR                          szAccountManagement1[ 16 ];
	CHAR                          szAccountManagement2[ 16 ];
	FILE                                  *pOutputFile;
	DWORD                                      dwError;
	CHAR                                    szFunction[ 128 ];

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTarget );

	lusSystemName.Buffer        = wszTarget;
	lusSystemName.Length        = (USHORT)( wcslen( wszTarget ) * sizeof( WCHAR ) );
	lusSystemName.MaximumLength = (USHORT)( ( wcslen( wszTarget ) + 1 ) * sizeof( WCHAR ) );

	ZeroMemory( &loaAttributes, sizeof( loaAttributes ) );

	ntStatus = LsaOpenPolicy( &lusSystemName, &loaAttributes, POLICY_VIEW_AUDIT_INFORMATION, &lsahPolicyHandle );

	if ( ntStatus == 0 )
	{
		ntStatus = LsaQueryInformationPolicy( lsahPolicyHandle, PolicyAuditEventsInformation, (PVOID *)&pInfo );

		if ( ntStatus == 0 )
		{
			if ( pInfo->AuditingMode )
			{
				CopySZ( szAuditingEnabled, sizeof( szAuditingEnabled ), "Yes" );
			}
			else
			{
				CopySZ( szAuditingEnabled, sizeof( szAuditingEnabled ), "No" );
			}

			CopySZ( szDirectoryServiceAccess1, sizeof( szDirectoryServiceAccess1 ), "N/A" );
			CopySZ( szDirectoryServiceAccess2, sizeof( szDirectoryServiceAccess2 ), "N/A\tN/A" );

			CopySZ( szAccountLogonEvents1, sizeof( szAccountLogonEvents1 ), "N/A" );
			CopySZ( szAccountLogonEvents2, sizeof( szAccountLogonEvents2 ), "N/A\tN/A" );

			for ( i = 0; i < pInfo->MaximumAuditEventCount; i++ )
			{
				switch ( pInfo->EventAuditingOptions[i] )
				{
					case POLICY_AUDIT_EVENT_SUCCESS:
						switch ( i )
						{
							case (POLICY_AUDIT_EVENT_TYPE)AuditCategorySystem:
								CopySZ( szSystemEvents1, sizeof( szSystemEvents1 ), "Success Only" );
								CopySZ( szSystemEvents2, sizeof( szSystemEvents2 ), "X\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryLogon:
								CopySZ( szLogonEvents1, sizeof( szLogonEvents1 ), "Success Only" );
								CopySZ( szLogonEvents2, sizeof( szLogonEvents2 ), "X\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryObjectAccess:
								CopySZ( szObjectAccess1, sizeof( szObjectAccess1 ), "Success Only" );
								CopySZ( szObjectAccess2, sizeof( szObjectAccess2 ), "X\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryPrivilegeUse:
								CopySZ( szPrivilegeUse1, sizeof( szPrivilegeUse1 ), "Success Only" );
								CopySZ( szPrivilegeUse2, sizeof( szPrivilegeUse2 ), "X\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryDetailedTracking:
								CopySZ( szProcessTracking1, sizeof( szProcessTracking1 ), "Success Only" );
								CopySZ( szProcessTracking2, sizeof( szProcessTracking2 ), "X\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryPolicyChange:
								CopySZ( szPolicyChange1, sizeof( szPolicyChange1 ), "Success Only" );
								CopySZ( szPolicyChange2, sizeof( szPolicyChange2 ), "X\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryAccountManagement:
								CopySZ( szAccountManagement1, sizeof( szAccountManagement1 ), "Success Only" );
								CopySZ( szAccountManagement2, sizeof( szAccountManagement2 ), "X\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryDirectoryServiceAccess:
								CopySZ( szDirectoryServiceAccess1, sizeof( szDirectoryServiceAccess1 ), "Success Only" );
								CopySZ( szDirectoryServiceAccess2, sizeof( szDirectoryServiceAccess2 ), "X\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryAccountLogon:
								CopySZ( szAccountLogonEvents1, sizeof( szAccountLogonEvents1 ), "Success Only" );
								CopySZ( szAccountLogonEvents2, sizeof( szAccountLogonEvents2 ), "X\t" );

								break;
						}

						break;

					case POLICY_AUDIT_EVENT_FAILURE:
						switch ( i )
						{
							case (POLICY_AUDIT_EVENT_TYPE)AuditCategorySystem:
								CopySZ( szSystemEvents1, sizeof( szSystemEvents1 ), "Failure Only" );
								CopySZ( szSystemEvents2, sizeof( szSystemEvents2 ), "\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryLogon:
								CopySZ( szLogonEvents1, sizeof( szLogonEvents1 ), "Failure Only" );
								CopySZ( szLogonEvents2, sizeof( szLogonEvents2 ), "\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryObjectAccess:
								CopySZ( szObjectAccess1, sizeof( szObjectAccess1 ), "Failure Only" );
								CopySZ( szObjectAccess2, sizeof( szObjectAccess2 ), "\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryPrivilegeUse:
								CopySZ( szPrivilegeUse1, sizeof( szPrivilegeUse1 ), "Failure Only" );
								CopySZ( szPrivilegeUse2, sizeof( szPrivilegeUse2 ), "\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryDetailedTracking:
								CopySZ( szProcessTracking1, sizeof( szProcessTracking1 ), "Failure Only" );
								CopySZ( szProcessTracking2, sizeof( szProcessTracking2 ), "\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryPolicyChange:
								CopySZ( szPolicyChange1, sizeof( szPolicyChange1 ), "Failure Only" );
								CopySZ( szPolicyChange2, sizeof( szPolicyChange2 ), "\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryAccountManagement:
								CopySZ( szAccountManagement1, sizeof( szAccountManagement1 ), "Failure Only" );
								CopySZ( szAccountManagement2, sizeof( szAccountManagement2 ), "\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryDirectoryServiceAccess:
								CopySZ( szDirectoryServiceAccess1, sizeof( szDirectoryServiceAccess1 ), "Failure Only" );
								CopySZ( szDirectoryServiceAccess2, sizeof( szDirectoryServiceAccess2 ), "\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryAccountLogon:
								CopySZ( szAccountLogonEvents1, sizeof( szAccountLogonEvents1 ), "Failure Only" );
								CopySZ( szAccountLogonEvents2, sizeof( szAccountLogonEvents2 ), "\tX" );

								break;
						}

						break;

					case (POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE):
						switch ( i )
						{
							case (POLICY_AUDIT_EVENT_TYPE)AuditCategorySystem:
								CopySZ( szSystemEvents1, sizeof( szSystemEvents1 ), "Success/Failure" );
								CopySZ( szSystemEvents2, sizeof( szSystemEvents2 ), "X\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryLogon:
								CopySZ( szLogonEvents1, sizeof( szLogonEvents1 ), "Success/Failure" );
								CopySZ( szLogonEvents2, sizeof( szLogonEvents2 ), "X\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryObjectAccess:
								CopySZ( szObjectAccess1, sizeof( szObjectAccess1 ), "Success/Failure" );
								CopySZ( szObjectAccess2, sizeof( szObjectAccess2 ), "X\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryPrivilegeUse:
								CopySZ( szPrivilegeUse1, sizeof( szPrivilegeUse1 ), "Success/Failure" );
								CopySZ( szPrivilegeUse2, sizeof( szPrivilegeUse2 ), "X\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryDetailedTracking:
								CopySZ( szProcessTracking1, sizeof( szProcessTracking1 ), "Success/Failure" );
								CopySZ( szProcessTracking2, sizeof( szProcessTracking2 ), "X\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryPolicyChange:
								CopySZ( szPolicyChange1, sizeof( szPolicyChange1 ), "Success/Failure" );
								CopySZ( szPolicyChange2, sizeof( szPolicyChange2 ), "X\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryAccountManagement:
								CopySZ( szAccountManagement1, sizeof( szAccountManagement1 ), "Success/Failure" );
								CopySZ( szAccountManagement2, sizeof( szAccountManagement2 ), "X\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryDirectoryServiceAccess:
								CopySZ( szDirectoryServiceAccess1, sizeof( szDirectoryServiceAccess1 ), "Success/Failure" );
								CopySZ( szDirectoryServiceAccess2, sizeof( szDirectoryServiceAccess2 ), "X\tX" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryAccountLogon:
								CopySZ( szAccountLogonEvents1, sizeof( szAccountLogonEvents1 ), "Success/Failure" );
								CopySZ( szAccountLogonEvents2, sizeof( szAccountLogonEvents2 ), "X\tX" );

								break;
						}

						break;

					default:
						switch ( i )
						{
							case (POLICY_AUDIT_EVENT_TYPE)AuditCategorySystem:
								CopySZ( szSystemEvents1, sizeof( szSystemEvents1 ), "None" );
								CopySZ( szSystemEvents2, sizeof( szSystemEvents2 ), "\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryLogon:
								CopySZ( szLogonEvents1, sizeof( szLogonEvents1 ), "None" );
								CopySZ( szLogonEvents2, sizeof( szLogonEvents2 ), "\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryObjectAccess:
								CopySZ( szObjectAccess1, sizeof( szObjectAccess1 ), "None" );
								CopySZ( szObjectAccess2, sizeof( szObjectAccess2 ), "\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryPrivilegeUse:
								CopySZ( szPrivilegeUse1, sizeof( szPrivilegeUse1 ), "None" );
								CopySZ( szPrivilegeUse2, sizeof( szPrivilegeUse2 ), "\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryDetailedTracking:
								CopySZ( szProcessTracking1, sizeof( szProcessTracking1 ), "None" );
								CopySZ( szProcessTracking2, sizeof( szProcessTracking2 ), "\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryPolicyChange:
								CopySZ( szPolicyChange1, sizeof( szPolicyChange1 ), "None" );
								CopySZ( szPolicyChange2, sizeof( szPolicyChange2 ), "\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryAccountManagement:
								CopySZ( szAccountManagement1, sizeof( szAccountManagement1 ), "None" );
								CopySZ( szAccountManagement2, sizeof( szAccountManagement2 ), "\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryDirectoryServiceAccess:
								CopySZ( szDirectoryServiceAccess1, sizeof( szDirectoryServiceAccess1 ), "None" );
								CopySZ( szDirectoryServiceAccess2, sizeof( szDirectoryServiceAccess2 ), "\t" );

								break;

							case (POLICY_AUDIT_EVENT_TYPE)AuditCategoryAccountLogon:
								CopySZ( szAccountLogonEvents1, sizeof( szAccountLogonEvents1 ), "None" );
								CopySZ( szAccountLogonEvents2, sizeof( szAccountLogonEvents2 ), "\t" );

								break;
						}

						break;
				}
			}

			if ( !bMultipleHosts )
			{
				printf( "\n" );
				printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
				printf( "+++++        AUDIT POLICY INFORMATION         +++++\n" );
				printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
				printf( "\n" );

				printf( "Auditing Enabled:         %s\n", szAuditingEnabled );
				printf( "System Events:            %s\n", szSystemEvents1 );
				printf( "Logon Events:             %s\n", szLogonEvents1 );
				printf( "Object Access:            %s\n", szObjectAccess1 );
				printf( "Privilege Use:            %s\n", szPrivilegeUse1 );
				printf( "Process Tracking:         %s\n", szProcessTracking1 );
				printf( "Policy Change:            %s\n", szPolicyChange1 );
				printf( "Account Management:       %s\n", szAccountManagement1 );
				printf( "Directory Service Access: %s\n", szDirectoryServiceAccess1 );
				printf( "Account Logon Events      %s\n", szAccountLogonEvents1 );
				printf( "\n" );

				fflush( stdout );
			}

			if ( bVerboseOptionSelected && bMultipleHosts )
			{
				printf( "%s -> Logging audit policy information.\n", szTarget );

				fflush( stdout );
			}

			WaitForSingleObject( hSemaphore, INFINITE );

			pOutputFile = fopen( "Reports\\AuditPolicyInfo.txt", "r" );

			if ( pOutputFile != NULL )
			{
				fclose( pOutputFile );
			}
			else
			{
				pOutputFile = fopen( "Reports\\AuditPolicyInfo.txt", "w" );

				if ( pOutputFile != NULL )
				{
					fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
					fprintf( pOutputFile, "\n" );
					fprintf( pOutputFile, "Hostname\tAuditing Enabled\tSystem Events\t\tLogon Events\t\tObject Access\t\tPrivilege Use\t\tProcess Tracking\t\tPolicy Change\t\tAccount Management\t\tDirectory Service Access\t\tAccount Logon Events\n" );
					fprintf( pOutputFile, "\t\tSuccess\tFailure\tSuccess\tFailure\tSuccess\tFailure\tSuccess\tFailure\tSuccess\tFailure\tSuccess\tFailure\tSuccess\tFailure\tSuccess\tFailure\tSuccess\tFailure\n" );

					fclose( pOutputFile );
				}
			}

			pOutputFile = fopen( "Reports\\AuditPolicyInfo.txt", "a+" );

			if ( pOutputFile != NULL )
			{
				fprintf( pOutputFile, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", szTarget, szAuditingEnabled, szSystemEvents2, szLogonEvents2, szObjectAccess2, szPrivilegeUse2, szProcessTracking2, szPolicyChange2, szAccountManagement2, szDirectoryServiceAccess2, szAccountLogonEvents2 );

				fclose( pOutputFile );
			}

			ReleaseSemaphore( hSemaphore, 1, NULL );

			LsaFreeMemory( pInfo );
		}
		else
		{
			dwError = LsaNtStatusToWinError( ntStatus );

			CopySZ( szFunction, sizeof( szFunction ), "LsaQueryInformationPolicy (GetAuditPolicyInfo)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}

		LsaClose( lsahPolicyHandle );
	}
	else
	{
		dwError = LsaNtStatusToWinError( ntStatus );

		CopySZ( szFunction, sizeof( szFunction ), "LsaOpenPolicy (GetAuditPolicyInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
	}
}

VOID GetDisplayInfoUsers( CHAR szTarget[] )
{
	CHAR              szTempTarget[ 128 ];
	WCHAR                wszTarget[ 256 ];
	CHAR               szCacheFile[ 128 ];
	DWORD                        i;
	DWORD                        j;
	DWORD                  dwLevel;
	DWORD                  dwIndex;
	DWORD            dwEntriesRead;
	NET_DISPLAY_USER        *pInfo;
	NET_API_STATUS         nStatus;
	NET_DISPLAY_USER    *pTempInfo;
	DWORD                        k;
	CHAR                szUsername[ 128 ];
	CHAR                 szComment[ 512 ];
	CHAR                   szFlags[ 128 ];
	FILE              *pOutputFile;
	FILE               *pCacheFile;
	DWORD                  dwError;
	CHAR                szFunction[ 128 ];

	sprintf( szTempTarget, "\\\\%s", szTarget );

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTempTarget );

	sprintf( szCacheFile, "UserCache\\%s.users", szTarget );

	i = 0;
	j = 0;

	dwLevel       = 1;
	dwIndex       = 0;
	dwEntriesRead = 0;

	do
	{
		pInfo = NULL;

		nStatus = NetQueryDisplayInformation( wszTarget, dwLevel, dwIndex, 100, MAX_PREFERRED_LENGTH, &dwEntriesRead, (PVOID *)&pInfo );

		if ( nStatus == NERR_Success || nStatus == ERROR_MORE_DATA )
		{
			if ( pInfo != NULL )
			{
				pTempInfo = pInfo;

				for ( k = 0; k < dwEntriesRead; k++ )
				{
					ConvertWSZtoSZ( szUsername, sizeof( szUsername ), pTempInfo->usri1_name );
					ConvertWSZtoSZ( szComment, sizeof( szComment ), pTempInfo->usri1_comment );

					CopySZ( szFlags, sizeof( szFlags ), "" );

					if ( pTempInfo->usri1_flags & UF_LOCKOUT )
					{
						sprintf( szFlags, "%s(Locked out) ", szFlags );
					}

					if ( pTempInfo->usri1_flags & UF_ACCOUNTDISABLE )
					{
						sprintf( szFlags, "%s(Disabled) ", szFlags );
					}

					if ( pTempInfo->usri1_flags & UF_DONT_EXPIRE_PASSWD )
					{
						sprintf( szFlags, "%s(Password never expires) ", szFlags );
					}

					if ( !bMultipleHosts )
					{
						if ( i == 0 )
						{
							printf( "\n" );
							printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
							printf( "+++++           DISPLAY INFORMATION           +++++\n" );
							printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
							printf( "\n" );

							i++;
						}

						printf( "Username: %s\n", szUsername );
						printf( "Comment:  %s\n", szComment );
						printf( "Flags:    %s\n", szFlags );
						printf( "User ID:  %d\n", pTempInfo->usri1_user_id );
						printf( "\n" );

						fflush( stdout );
					}

					if ( bVerboseOptionSelected && bMultipleHosts )
					{
						printf( "%s -> Logging display information.\n", szTarget );

						fflush( stdout );
					}

					WaitForSingleObject( hSemaphore, INFINITE );

					pOutputFile = fopen( "Reports\\DisplayInfoUsers.txt", "r" );

					if ( pOutputFile != NULL )
					{
						fclose( pOutputFile );
					}
					else
					{
						pOutputFile = fopen( "Reports\\DisplayInfoUsers.txt", "w" );

						if ( pOutputFile != NULL )
						{
							fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
							fprintf( pOutputFile, "\n" );
							fprintf( pOutputFile, "Hostname\tUsername\tComment\tFlags\tUser ID\n" );

							fclose( pOutputFile );
						}
					}

					pOutputFile = fopen( "Reports\\DisplayInfoUsers.txt", "a+" );

					if ( pOutputFile != NULL )
					{
						fprintf( pOutputFile, "%s\t%s\t%s\t%s\t%d\n", szTarget, szUsername, szComment, szFlags, pTempInfo->usri1_user_id );

						fclose( pOutputFile );
					}

					if ( j == 0 )
					{
						pCacheFile = fopen( szCacheFile, "w" );

						if ( pCacheFile != NULL )
						{
							fclose( pCacheFile );
						}

						j++;
					}

					pCacheFile = fopen( szCacheFile, "a+" );

					if ( pCacheFile != NULL )
					{
						fprintf( pCacheFile, "%s\n", szUsername);

						fclose( pCacheFile );
					}

					ReleaseSemaphore( hSemaphore, 1, NULL );

					dwIndex = pTempInfo->usri1_next_index;

					pTempInfo++;
				}
			}
		}
		else
		{
			dwError = nStatus;

			CopySZ( szFunction, sizeof( szFunction ), "NetQueryDisplayInformation (GetDisplayInfoUsers)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}

		if ( pInfo != NULL )
		{
			NetApiBufferFree( pInfo );
		}
	}
	while ( nStatus == ERROR_MORE_DATA );
}

VOID GetDisplayInfoMachines( CHAR szTarget[] )
{
	CHAR                 szTempTarget[ 128 ];
	WCHAR                   wszTarget[ 256 ];
	DWORD                           i;
	DWORD                     dwLevel;
	DWORD                     dwIndex;
	DWORD               dwEntriesRead;
	NET_DISPLAY_MACHINE        *pInfo;
	NET_API_STATUS            nStatus;
	NET_DISPLAY_MACHINE    *pTempInfo;
	DWORD                           j;
	CHAR                szMachineName[ 128 ];
	CHAR                    szComment[ 512 ];
	FILE                 *pOutputFile;
	DWORD                     dwError;
	CHAR                   szFunction[ 128 ];

	sprintf( szTempTarget, "\\\\%s", szTarget );

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTempTarget );

	i = 0;

	dwLevel       = 2;
	dwIndex       = 0;
	dwEntriesRead = 0;

	do
	{
		pInfo = NULL;

		nStatus = NetQueryDisplayInformation( wszTarget, dwLevel, dwIndex, 100, MAX_PREFERRED_LENGTH, &dwEntriesRead, (PVOID *)&pInfo );

		if ( nStatus == NERR_Success || nStatus == ERROR_MORE_DATA )
		{
			if ( pInfo != NULL )
			{
				pTempInfo = pInfo;

				for ( j = 0; j < dwEntriesRead; j++ )
				{
					ConvertWSZtoSZ( szMachineName, sizeof( szMachineName ), pTempInfo->usri2_name );
					ConvertWSZtoSZ( szComment, sizeof( szComment ), pTempInfo->usri2_comment );

					if ( szMachineName[strlen( szMachineName ) - 1] == '$' )
					{
						szMachineName[strlen( szMachineName ) - 1] = '\0';
					}

					if ( !bMultipleHosts )
					{
						if ( i == 0 )
						{
							printf( "\n" );
							printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
							printf( "+++++           DISPLAY INFORMATION           +++++\n" );
							printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
							printf( "\n" );

							i++;
						}

						printf( "Machine Name: %s\n", szMachineName );
						printf( "Comment:      %s\n", szComment );
						printf( "\n" );

						fflush( stdout );
					}

					if ( bVerboseOptionSelected && bMultipleHosts )
					{
						printf( "%s -> Logging display information.\n", szTarget );

						fflush( stdout );
					}

					WaitForSingleObject( hSemaphore, INFINITE );

					pOutputFile = fopen( "Reports\\DisplayInfoMachines.txt", "r" );

					if ( pOutputFile != NULL )
					{
						fclose( pOutputFile );
					}
					else
					{
						pOutputFile = fopen( "Reports\\DisplayInfoMachines.txt", "w" );

						if ( pOutputFile != NULL )
						{
							fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
							fprintf( pOutputFile, "\n" );
							fprintf( pOutputFile, "Hostname\tMachine Name\tComment\n" );

							fclose( pOutputFile );
						}
					}

					pOutputFile = fopen( "Reports\\DisplayInfoMachines.txt", "a+" );

					if ( pOutputFile != NULL )
					{
						fprintf( pOutputFile, "%s\t%s\t%s\n", szTarget, szMachineName, szComment );

						fclose( pOutputFile );
					}
					ReleaseSemaphore( hSemaphore, 1, NULL );

					dwIndex = pTempInfo->usri2_next_index;

					pTempInfo++;
				}
			}
		}
		else
		{
			dwError = nStatus;

			CopySZ( szFunction, sizeof( szFunction ), "NetQueryDisplayInformation (GetDisplayInfoMachines)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}

		if ( pInfo != NULL )
		{
			NetApiBufferFree( pInfo );
		}
	}
	while ( nStatus == ERROR_MORE_DATA );
}

VOID GetDomainInfo( CHAR szTarget[] )
{
	WCHAR                             wszTarget[ 256 ];
	LSA_UNICODE_STRING            lusSystemName;
	LSA_OBJECT_ATTRIBUTES         loaAttributes;
	NTSTATUS                           ntStatus;
	LSA_HANDLE                 lsahPolicyHandle;
	POLICY_ACCOUNT_DOMAIN_INFO          *pInfo1;
	DWORD                         dwBytesNeeded;
	WCHAR                          *pDomainName;
	CHAR                           szDomainName[ 128 ];
	CHAR                       szTrustedDomain1[ 128 ];
	CHAR                       szTrustedDomain2[ 128 ];
	CHAR                       szTrustedDomains[ 1024 ];
	DWORD                               lReturn;
	DS_DOMAIN_TRUSTS                    *pInfo2;
	ULONG                          uDomainCount;
	DWORD                                     i;
	FILE                           *pOutputFile;
	DWORD                               dwError;
	CHAR                             szFunction[ 128 ];

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTarget );

	lusSystemName.Buffer        = wszTarget;
	lusSystemName.Length        = (USHORT)( wcslen( wszTarget ) * sizeof( WCHAR ) );
	lusSystemName.MaximumLength = (USHORT)( ( wcslen( wszTarget ) + 1 ) * sizeof( WCHAR ) );

	ZeroMemory( &loaAttributes, sizeof( loaAttributes ) );

	ntStatus = LsaOpenPolicy( &lusSystemName, &loaAttributes, POLICY_VIEW_LOCAL_INFORMATION, &lsahPolicyHandle );

	if ( ntStatus == 0 )
	{
		pInfo1 = NULL;

		ntStatus = LsaQueryInformationPolicy( lsahPolicyHandle, PolicyAccountDomainInformation, (PVOID *)&pInfo1 );

		if ( ntStatus == 0 )
		{
			dwBytesNeeded = ( ( pInfo1->DomainName.Length + 1 ) * sizeof( WCHAR ) );

			pDomainName = NULL;

			pDomainName = (WCHAR *)LocalAlloc( LPTR, dwBytesNeeded );

			if ( pDomainName != NULL )
			{
				wcsncpy_s( pDomainName, dwBytesNeeded, pInfo1->DomainName.Buffer, pInfo1->DomainName.Length );

				ConvertWSZtoSZ( szDomainName, sizeof( szDomainName ), pDomainName );

				CopySZ( szTrustedDomains, sizeof( szTrustedDomains ), "" );

				lReturn = DsEnumerateDomainTrusts( wszTarget, DS_DOMAIN_DIRECT_INBOUND | DS_DOMAIN_DIRECT_OUTBOUND | DS_DOMAIN_DIRECT_OUTBOUND | DS_DOMAIN_NATIVE_MODE | DS_DOMAIN_PRIMARY | DS_DOMAIN_TREE_ROOT, &pInfo2, &uDomainCount );

				if ( lReturn == ERROR_SUCCESS )
				{
					for ( i = 0; i < uDomainCount; i++ )
					{
						ConvertWSZtoSZ( szTrustedDomain1, sizeof( szTrustedDomain1 ), pInfo2[i].DnsDomainName );
						ConvertWSZtoSZ( szTrustedDomain2, sizeof( szTrustedDomain2 ), pInfo2[i].NetbiosDomainName );

						sprintf( szTrustedDomains, "%s%s(%s) ", szTrustedDomains, szTrustedDomain1, szTrustedDomain2 );
					}

					NetApiBufferFree( pInfo2 );
				}

				if ( !bMultipleHosts )
				{
					printf( "\n" );
					printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
					printf( "+++++           DOMAIN INFORMATION            +++++\n" );
					printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
					printf( "\n" );

					printf( "Domain Name:     %s\n", szDomainName );
					printf( "Trusted Domains: %s\n", szTrustedDomains );
					printf( "\n" );

					fflush( stdout );
				}

				if ( bVerboseOptionSelected && bMultipleHosts )
				{
					printf( "%s -> Logging domain information.\n", szTarget );

					fflush( stdout );
				}

				WaitForSingleObject( hSemaphore, INFINITE );

				pOutputFile = fopen( "Reports\\DomainInfo.txt", "r" );

				if ( pOutputFile != NULL )
				{
					fclose( pOutputFile );
				}
				else
				{
					pOutputFile = fopen( "Reports\\DomainInfo.txt", "w" );

					if ( pOutputFile != NULL )
					{
						fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
						fprintf( pOutputFile, "\n" );
						fprintf( pOutputFile, "Hostname\tDomain Name\tTrusted Domains\n" );

						fclose( pOutputFile );
					}
				}

				pOutputFile = fopen( "Reports\\DomainInfo.txt", "a+" );

				if ( pOutputFile != NULL )
				{
					fprintf( pOutputFile, "%s\t%s\t%s\n", szTarget, szDomainName, szTrustedDomains );

					fclose( pOutputFile );
				}

				ReleaseSemaphore( hSemaphore, 1, NULL );

				LocalFree( pDomainName );
			}
			else
			{
				dwError = GetLastError();

				CopySZ( szFunction, sizeof( szFunction ), "LocalAlloc (GetDomainInfo)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
			}

			LsaFreeMemory( pInfo1 );
		}
		else
		{
			dwError = LsaNtStatusToWinError( ntStatus );

			CopySZ( szFunction, sizeof( szFunction ), "LsaQueryInformationPolicy (GetDomainInfo)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}

		LsaClose( lsahPolicyHandle );
	}
	else
	{
		dwError = LsaNtStatusToWinError( ntStatus );

		CopySZ( szFunction, sizeof( szFunction ), "LsaOpenPolicy (GetDomainInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
	}
}

VOID GetLDAPInfo( CHAR szTarget[] )
{
	WCHAR               wszTarget[ 256 ];
	WCHAR                *pTarget;
	LDAP         *pLDAPConnection;
	ULONG                 lReturn;
	LDAP_TIMEVAL              ltv;
	CHAR                 szBaseDN[ 128 ];
	WCHAR               wszBaseDN[ 256 ];
	WCHAR                *pBaseDN;
	CHAR                 szFilter[ 128 ];
	WCHAR               wszFilter[ 256 ];
	WCHAR                *pFilter;
	CHAR              szNewBaseDN[ 512 ];
	CHAR               szFunction[ 128 ];
	CHAR               szErrorMsg[ 128 ];

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTarget );

	pTarget = wszTarget;

	pLDAPConnection = ldap_init( pTarget, LDAP_PORT );
    
	if ( pLDAPConnection != NULL )
	{
		lReturn = ldap_set_option( pLDAPConnection, LDAP_OPT_PROTOCOL_VERSION, (VOID *)LDAP_VERSION3 );

		if ( lReturn == LDAP_SUCCESS )
		{
			ltv.tv_sec  = 2;
			ltv.tv_usec = 0;

			lReturn = ldap_connect( pLDAPConnection, &ltv );

			if ( lReturn == LDAP_SUCCESS )
			{
				lReturn = ldap_simple_bind( pLDAPConnection, NULL, NULL );

				if ( lReturn != -1 )
				{
					if ( !bMultipleHosts )
					{
						printf( "\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "+++++            LDAP INFORMATION             +++++\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "\n" );

						fflush( stdout );
					}

					if ( bVerboseOptionSelected && bMultipleHosts )
					{
						printf( "%s -> Logging LDAP information.\n", szTarget );

						fflush( stdout );
					}

					CopySZ( szBaseDN, sizeof( szBaseDN ), "" );

					ConvertSZtoWSZ( wszBaseDN, sizeof( wszBaseDN ), szBaseDN );

					pBaseDN = wszBaseDN;

					CopySZ( szFilter, sizeof( szFilter ), "(objectClass=*)" );

					ConvertSZtoWSZ( wszFilter, sizeof( wszFilter ), szFilter );

					pFilter = wszFilter;

					CopySZ( szNewBaseDN, sizeof( szNewBaseDN ), "" );

					LDAPQuery( szTarget, pLDAPConnection, pBaseDN, pFilter, szNewBaseDN, sizeof( szNewBaseDN ) );

					if ( strcmp( szNewBaseDN, "" ) != 0 )
					{
						ConvertSZtoWSZ( wszBaseDN, sizeof( wszBaseDN ), szNewBaseDN );

						pBaseDN = wszBaseDN;

						LDAPQuery( szTarget, pLDAPConnection, pBaseDN, pFilter, szNewBaseDN, sizeof( szNewBaseDN ) );
					}
				}

				ldap_unbind( pLDAPConnection );
			}
			else
			{
				if ( lReturn == LDAP_INSUFFICIENT_RIGHTS )
				{
					CopySZ( szFunction, sizeof( szFunction ), "ldap_connect (GetLDAPInfo)" );
					CopySZ( szErrorMsg, sizeof( szErrorMsg ), "The user does not have access to the requested information." );

					WriteToErrorLog( szTarget, szFunction, szErrorMsg );
				}
				else if ( lReturn == LDAP_SERVER_DOWN )
				{
					CopySZ( szFunction, sizeof( szFunction ), "ldap_connect (GetLDAPInfo)" );
					CopySZ( szErrorMsg, sizeof( szErrorMsg ), "Cannot contact the LDAP server." );

					WriteToErrorLog( szTarget, szFunction, szErrorMsg );
				}
				else if ( lReturn == LDAP_TIMEOUT )
				{
					CopySZ( szFunction, sizeof( szFunction ), "ldap_connect (GetLDAPInfo)" );
					CopySZ( szErrorMsg, sizeof( szErrorMsg ), "The search was aborted due to exceeding the limit of the client side timeout." );

					WriteToErrorLog( szTarget, szFunction, szErrorMsg );
				}
				else
				{
					CopySZ( szFunction, sizeof( szFunction ), "ldap_connect (GetLDAPInfo)" );
					CopySZ( szErrorMsg, sizeof( szErrorMsg ), "Unable to connect to the LDAP service." );

					WriteToErrorLog( szTarget, szFunction, szErrorMsg );
				}
			}
		}
	}
}

VOID LDAPQuery( CHAR szTarget[], LDAP *pLDAPConnection, WCHAR pBaseDN[], WCHAR pFilter[], CHAR szNewBaseDN[], size_t siNewBaseDN )
{
	ULONG           lMessageID;
	LDAPMessage *pSearchResult;
	ULONG              lReturn;
	ULONG             lEntries;
	ULONG                    i;
	LDAPMessage        *pEntry;
	WCHAR          *pAttribute;
	BerElement    *pBerElement;
	WCHAR           **ppValues;
	ULONG              lValues;
	CHAR              szBaseDN[ 128 ];
	CHAR           szAttribute[ 128 ];
	CHAR               szValue[ 512 ];
	ULONG                    j;
	FILE          *pOutputFile;

	struct l_timeval tv;

	lMessageID = ldap_search( pLDAPConnection, pBaseDN, LDAP_SCOPE_BASE, pFilter, NULL, 0 );

	if ( lMessageID != -1 )
	{
		tv.tv_sec  = 2;
		tv.tv_usec = 0;

		lReturn = ldap_result( pLDAPConnection, lMessageID, LDAP_MSG_ALL, &tv, &pSearchResult );

		if ( lReturn > 0 )
		{
			lEntries = ldap_count_entries( pLDAPConnection, pSearchResult );

			if ( lEntries != -1 )
			{
				for ( i = 0; i < lEntries; i++ )
				{
					pEntry = NULL;

					if ( i == 0 )
					{
						pEntry = ldap_first_entry( pLDAPConnection, pSearchResult );
					}
					else
					{
						pEntry = ldap_next_entry( pLDAPConnection, pEntry );
					}

					if ( pEntry != NULL )
					{
						pAttribute = ldap_first_attribute( pLDAPConnection, pEntry, &pBerElement );

						while ( pAttribute != NULL )
						{
							ppValues = ldap_get_values( pLDAPConnection, pEntry, pAttribute );

							if ( ppValues != NULL )
							{
								lValues = 0;

								lValues = ldap_count_values( ppValues );

								if ( lValues > 0 )
								{
									ConvertWSZtoSZ( szBaseDN, sizeof( szBaseDN ), pBaseDN );
									ConvertWSZtoSZ( szAttribute, sizeof( szAttribute ), pAttribute );
									ConvertWSZtoSZ( szValue, sizeof( szValue ), *ppValues );

									if ( !bMultipleHosts )
									{
										printf( "Base DN:   %s\n", szBaseDN );
										printf( "Attribute: %s\n", szAttribute );
										printf( "Value:     %s\n", szValue );

										fflush( stdout );
									}

									if ( bVerboseOptionSelected && bMultipleHosts )
									{
										printf( "%s -> Logging LDAP information.\n", szTarget );

										fflush( stdout );
									}

									WaitForSingleObject( hSemaphore, INFINITE );

									pOutputFile = fopen( "Reports\\LDAPInfo.txt", "r" );

									if ( pOutputFile != NULL )
									{
										fclose( pOutputFile );
									}
									else
									{
										pOutputFile = fopen( "Reports\\LDAPInfo.txt", "w" );

										if ( pOutputFile != NULL )
										{
											fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
											fprintf( pOutputFile, "\n" );
											fprintf( pOutputFile, "Hostname\tBase DN\tLDAP Attribute\tValue\n" );

											fclose( pOutputFile );
										}
									}

									pOutputFile = fopen( "Reports\\LDAPInfo.txt", "a+" );

									if ( pOutputFile != NULL )
									{
										fprintf( pOutputFile, "%s\t%s\t%s\t%s\n", szTarget, szBaseDN, szAttribute, szValue );

										fclose( pOutputFile );
									}

									ReleaseSemaphore( hSemaphore, 1, NULL );

									if ( strcmp( szAttribute, "defaultNamingContext" ) == 0 )
									{
										CopySZ( szNewBaseDN, siNewBaseDN, szValue );
									}

									if ( lValues > 1 )
									{
										for ( j = 1; j < lValues; j++ )
										{
											ConvertWSZtoSZ( szValue, sizeof( szValue ), ppValues[j] );

											if ( !bMultipleHosts )
											{
												printf( "Value:     %s\n", szValue );

												fflush( stdout );
											}

											if ( bVerboseOptionSelected && bMultipleHosts )
											{
												printf( "%s -> Logging LDAP information.\n", szTarget );

												fflush( stdout );
											}

											WaitForSingleObject( hSemaphore, INFINITE );

											pOutputFile = fopen( "Reports\\LDAPInfo.txt", "a+" );

											if ( pOutputFile != NULL )
											{
												fprintf( pOutputFile, "%s\t%s\t%s\t%s\n", szTarget, szBaseDN, szAttribute, szValue );

												fclose( pOutputFile );
											}

											ReleaseSemaphore( hSemaphore, 1, NULL );
										}
									}

									if ( !bMultipleHosts )
									{
										printf( "\n" );

										fflush( stdout );
									}
								}

								ldap_value_free( ppValues );
							}

							ldap_memfree( pAttribute );

							pAttribute = ldap_next_attribute( pLDAPConnection, pEntry, pBerElement );
						}

						if ( pAttribute != NULL )
						{
							ldap_memfree( pAttribute );
						}

						if ( pBerElement != NULL )
						{
							ber_free( pBerElement, 0 );
						}
					}
				}
			}

			ldap_msgfree( pSearchResult );
		}
	}
}

VOID GetLocalGroupInfo( CHAR szTarget[] )
{
	CHAR                         szTempTarget[ 128 ];
	WCHAR                           wszTarget[ 256 ];
	DWORD                                   i;
	DWORD                            dwLevel1;
	DWORD                      dwEntriesRead1;
	DWORD                     dwTotalEntries1;
	DWORD_PTR                 dwResumeHandle1;
	LOCALGROUP_INFO_1                 *pInfo1;
	NET_API_STATUS                   nStatus1;
	LOCALGROUP_INFO_1             *pTempInfo1;
	DWORD                                   j;
	WCHAR                        wszGroupName[ 256 ];
	CHAR                          szGroupName[ 128 ];
	DWORD                            dwLevel2;
	DWORD                      dwEntriesRead2;
	DWORD                     dwTotalEntries2;
	DWORD_PTR                 dwResumeHandle2;
	LOCALGROUP_MEMBERS_INFO_2         *pInfo2;
	NET_API_STATUS                   nStatus2;
	LOCALGROUP_MEMBERS_INFO_2     *pTempInfo2;
	DWORD                                   k;
	CHAR                           szUsername[ 128 ];
	FILE                         *pOutputFile;
	DWORD                             dwError;
	CHAR                           szFunction[ 128 ];

	sprintf( szTempTarget, "\\\\%s", szTarget );

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTempTarget );

	i = 0;

	dwLevel1        = 1;
	dwEntriesRead1  = 0;
	dwTotalEntries1 = 0;
	dwResumeHandle1 = 0;

	do
	{
		pInfo1 = NULL;

		nStatus1 = NetLocalGroupEnum( wszTarget, dwLevel1, (PBYTE *)&pInfo1, MAX_PREFERRED_LENGTH, &dwEntriesRead1, &dwTotalEntries1, &dwResumeHandle1 );

		if ( nStatus1 == NERR_Success || nStatus1 == ERROR_MORE_DATA )
		{
			if ( pInfo1 != NULL )
			{
				pTempInfo1 = pInfo1;

				for ( j = 0; j < dwEntriesRead1; j++ )
				{
					CopyWSZ( wszGroupName, sizeof( wszGroupName ), pTempInfo1->lgrpi1_name );

					ConvertWSZtoSZ( szGroupName, sizeof( szGroupName ), pTempInfo1->lgrpi1_name );

					dwLevel2        = 2;
					dwEntriesRead2  = 0;
					dwTotalEntries2 = 0;
					dwResumeHandle2 = 0;

					do
					{
						pInfo2 = NULL;

						nStatus2 = NetLocalGroupGetMembers( wszTarget, wszGroupName, dwLevel2, (PBYTE *)&pInfo2, MAX_PREFERRED_LENGTH, &dwEntriesRead2, &dwTotalEntries2, &dwResumeHandle2 );

						if ( nStatus2 == NERR_Success || nStatus2 == ERROR_MORE_DATA )
						{
							if ( pInfo2 != NULL )
							{
								pTempInfo2 = pInfo2;

								for ( k = 0; k < dwEntriesRead2; k++ )
								{
									ConvertWSZtoSZ( szUsername, sizeof( szUsername ), pTempInfo2->lgrmi2_domainandname );

									if ( !bMultipleHosts )
									{
										if ( i == 0 )
										{
											printf( "\n" );
											printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
											printf( "+++++         LOCAL GROUP INFORMATION         +++++\n" );
											printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
											printf( "\n" );

											i++;
										}

										printf( "Group Name: %s\n", szGroupName );
										printf( "Group Type: Local\n" );
										printf( "Username:   %s\n", szUsername );
										printf( "\n" );

										fflush( stdout );
									}

									if ( bVerboseOptionSelected && bMultipleHosts )
									{
										printf( "%s -> Logging local group information.\n", szTarget );

										fflush( stdout );
									}

									WaitForSingleObject( hSemaphore, INFINITE );

									pOutputFile = fopen( "Reports\\GroupInfo.txt", "r" );

									if ( pOutputFile != NULL )
									{
										fclose( pOutputFile );
									}
									else
									{
										pOutputFile = fopen( "Reports\\GroupInfo.txt", "w" );

										if ( pOutputFile != NULL )
										{
											fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
											fprintf( pOutputFile, "\n" );
											fprintf( pOutputFile, "Hostname\tGroup Name\tGroup Type\tUsername\n" );

											fclose( pOutputFile );
										}
									}

									pOutputFile = fopen( "Reports\\GroupInfo.txt", "a+" );

									if ( pOutputFile != NULL )
									{
										fprintf( pOutputFile, "%s\t%s\tLocal\t%s\n", szTarget, szGroupName, szUsername );

										fclose( pOutputFile );
									}

									ReleaseSemaphore( hSemaphore, 1, NULL );

									pTempInfo2++;
								}
							}
						}
						else
						{
							dwError = nStatus2;

							CopySZ( szFunction, sizeof( szFunction ), "NetLocalGroupGetMembers (GetLocalGroupInfo)" );

							WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
						}

						if ( pInfo2 != NULL )
						{
							NetApiBufferFree( pInfo2 );
						}
					}
					while ( nStatus2 == ERROR_MORE_DATA );

					pTempInfo1++;
				}
			}
		}
		else
		{
			dwError = nStatus1;

			CopySZ( szFunction, sizeof( szFunction ), "NetLocalGroupEnum (GetLocalGroupInfo)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}

		if ( pInfo1 != NULL )
		{
			NetApiBufferFree( pInfo1 );
		}
	}
	while ( nStatus1 == ERROR_MORE_DATA );
}

VOID GetGlobalGroupInfo( CHAR szTarget[] )
{
	CHAR                  szTempTarget[ 128 ];
	WCHAR                    wszTarget[ 256 ];
	DWORD                            i;
	DWORD                     dwLevel1;
	DWORD               dwEntriesRead1;
	DWORD              dwTotalEntries1;
	DWORD_PTR          dwResumeHandle1;
	GROUP_INFO_1               *pInfo1;
	NET_API_STATUS            nStatus1;
	GROUP_INFO_1           *pTempInfo1;
	DWORD                            j;
	WCHAR                 wszGroupName[ 256 ];
	CHAR                   szGroupName[ 128 ];
	DWORD                     dwLevel0;
	DWORD               dwEntriesRead2;
	DWORD              dwTotalEntries2;
	DWORD_PTR          dwResumeHandle2;
	GROUP_USERS_INFO_0         *pInfo0;
	NET_API_STATUS            nStatus2;
	GROUP_USERS_INFO_0     *pTempInfo0;
	DWORD                            k;
	CHAR                    szUsername[ 128 ];
	FILE                  *pOutputFile;
	DWORD                      dwError;
	CHAR                    szFunction[ 128 ];

	sprintf( szTempTarget, "\\\\%s", szTarget );

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTempTarget );

	i = 0;

	dwLevel1        = 1;
	dwEntriesRead1  = 0;
	dwTotalEntries1 = 0;
	dwResumeHandle1 = 0;

	do
	{
		pInfo1 = NULL;

		nStatus1 = NetGroupEnum( wszTarget, dwLevel1, (PBYTE *)&pInfo1, MAX_PREFERRED_LENGTH, &dwEntriesRead1, &dwTotalEntries1, &dwResumeHandle1 );

		if ( nStatus1 == NERR_Success || nStatus1 == ERROR_MORE_DATA )
		{
			if ( pInfo1 != NULL )
			{
				pTempInfo1 = pInfo1;

				for ( j = 0; j < dwEntriesRead1; j++ )
				{
					CopyWSZ( wszGroupName, sizeof( wszGroupName ), pTempInfo1->grpi1_name );

					ConvertWSZtoSZ( szGroupName, sizeof( szGroupName ), pTempInfo1->grpi1_name );

					dwLevel0        = 0;
					dwEntriesRead2  = 0;
					dwTotalEntries2 = 0;
					dwResumeHandle2 = 0;

					do
					{
						pInfo0 = NULL;

						nStatus2 = NetGroupGetUsers( wszTarget, wszGroupName, dwLevel0, (PBYTE *)&pInfo0, MAX_PREFERRED_LENGTH, &dwEntriesRead2, &dwTotalEntries2, &dwResumeHandle2 );

						if ( nStatus2 == NERR_Success || nStatus2 == ERROR_MORE_DATA )
						{
							if ( pInfo0 != NULL )
							{
								pTempInfo0 = pInfo0;

								for ( k = 0; k < dwEntriesRead2; k++ )
								{
									ConvertWSZtoSZ( szUsername, sizeof( szUsername ), pTempInfo0->grui0_name );

									if ( !bMultipleHosts )
									{
										if ( i == 0 )
										{
											printf( "\n" );
											printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
											printf( "+++++        GLOBAL GROUP INFORMATION         +++++\n" );
											printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
											printf( "\n" );

											i++;
										}

										printf( "Group Name: %s\n", szGroupName );
										printf( "Group Type: Global\n" );
										printf( "Username:   %s\n", szUsername );
										printf( "\n" );

										fflush( stdout );
									}

									if ( bVerboseOptionSelected && bMultipleHosts )
									{
										printf( "%s -> Logging global group information.\n", szTarget );

										fflush( stdout );
									}

									WaitForSingleObject( hSemaphore, INFINITE );

									pOutputFile = fopen( "Reports\\GroupInfo.txt", "r" );

									if ( pOutputFile != NULL )
									{
										fclose( pOutputFile );
									}
									else
									{
										pOutputFile = fopen( "Reports\\GroupInfo.txt", "w" );

										if ( pOutputFile != NULL )
										{
											fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
											fprintf( pOutputFile, "\n" );
											fprintf( pOutputFile, "Hostname\tGroup Name\tGroup Type\tUsername\n" );

											fclose( pOutputFile );
										}
									}

									pOutputFile = fopen( "Reports\\GroupInfo.txt", "a+" );

									if ( pOutputFile != NULL )
									{
										fprintf( pOutputFile, "%s\t%s\tGlobal\t%s\n", szTarget, szGroupName, szUsername );

										fclose( pOutputFile );
									}

									ReleaseSemaphore( hSemaphore, 1, NULL );

									pTempInfo0++;
								}
							}
						}
						else
						{
							dwError = nStatus2;

							CopySZ( szFunction, sizeof( szFunction ), "NetGroupGetUsers (GetGlobalGroupInfo)" );

							WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
						}

						if ( pInfo0 != NULL )
						{
							NetApiBufferFree( pInfo0 );
						}
					}
					while ( nStatus2 == ERROR_MORE_DATA );

					pTempInfo1++;
				}
			}
		}
		else
		{
			dwError = nStatus1;

			CopySZ( szFunction, sizeof( szFunction ), "NetGroupEnum (GetGlobalGroupInfo)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}

		if ( pInfo1 != NULL )
		{
			NetApiBufferFree( pInfo1 );
		}
	}
	while ( nStatus1 == ERROR_MORE_DATA );
}

VOID GetWMIProductInfo( CHAR szTarget[], IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate )
{
	DWORD                                i;
	CHAR                   szQueryLanguage[ 128 ];
	CHAR                           szQuery[ 128 ];
	WCHAR                 wszQueryLanguage[ 256 ];
	WCHAR                         wszQuery[ 256 ];
	BSTR                  bszQueryLanguage;
	BSTR                          bszQuery;
	IEnumWbemClassObject      *pEnumerator;
	HRESULT                        hResult;
	IWbemClassObject              *pObject;
	ULONG                        uReturned;
	VARIANT                     vtProperty;
	CHAR                     szDisplayName[ 128 ];
	CHAR                     szInstallDate[ 128 ];
	CHAR                 szInstallLocation[ 1024 ];
	FILE                      *pOutputFile;
	CHAR                        szFunction[ 128 ];

	i = 0;

	CopySZ( szQueryLanguage, sizeof( szQueryLanguage ), "WQL" );
	CopySZ( szQuery, sizeof( szQuery ), "Select * from Win32_Product" );

	ConvertSZtoWSZ( wszQueryLanguage, sizeof( wszQueryLanguage ), szQueryLanguage );
	ConvertSZtoWSZ( wszQuery, sizeof( wszQuery ), szQuery );

	bszQueryLanguage = SysAllocString( wszQueryLanguage );
	bszQuery         = SysAllocString( wszQuery );

	pEnumerator = NULL;

	hResult = pService->ExecQuery( bszQueryLanguage, bszQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator );

	if ( SUCCEEDED( hResult ) )
	{
		if ( *bImpersonate )
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE );
		}
		else
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, authIdentity, EOAC_NONE );
		}

		while ( pEnumerator )
		{
			pObject = NULL;

			hResult = pEnumerator->Next( WBEM_INFINITE, 1, &pObject, &uReturned );

			if ( SUCCEEDED( hResult ) )
			{
				if ( uReturned == 0 )
				{
					break;
				}

				hResult = pObject->Get( L"Caption", 0, &vtProperty, NULL, NULL );

				ConvertWSZtoSZ( szDisplayName, sizeof( szDisplayName ), vtProperty.bstrVal );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"InstallDate", 0, &vtProperty, NULL, NULL );

				ConvertWSZtoSZ( szInstallDate, sizeof( szInstallDate ), vtProperty.bstrVal );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"InstallLocation", 0, &vtProperty, NULL, NULL );

				ConvertWSZtoSZ( szInstallLocation, sizeof( szInstallLocation ), vtProperty.bstrVal );

				VariantClear( &vtProperty );

				pObject->Release();

				if ( !bMultipleHosts )
				{
					if ( i == 0 )
					{
						printf( "\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "+++++           PRODUCT INFORMATION           +++++\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "\n" );

						i++;
					}

					printf( "Display Name:     %s\n", szDisplayName );
					printf( "Install Date:     %s\n", szInstallDate );
					printf( "Install Location: %s\n", szInstallLocation );

					printf( "\n" );

					fflush( stdout );
				}

				if ( bVerboseOptionSelected && bMultipleHosts )
				{
					printf( "%s -> Logging product information.\n", szTarget );

					fflush( stdout );
				}

				WaitForSingleObject( hSemaphore, INFINITE );

				pOutputFile = fopen( "Reports\\ProductInfo.txt", "r" );

				if ( pOutputFile != NULL )
				{
					fclose( pOutputFile );
				}
				else
				{
					pOutputFile = fopen( "Reports\\ProductInfo.txt", "w" );

					if ( pOutputFile != NULL )
					{
						fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
						fprintf( pOutputFile, "\n" );
						fprintf( pOutputFile, "Hostname\tDisplay Name\tInstall Date\tInstall Location\n" );

						fclose( pOutputFile );
					}
				}

				pOutputFile = fopen( "Reports\\ProductInfo.txt", "a+" );

				if ( pOutputFile != NULL )
				{
					fprintf( pOutputFile, "%s\t%s\t%s\t%s\n", szTarget, szDisplayName, szInstallDate, szInstallLocation );

					fclose( pOutputFile );
				}

				ReleaseSemaphore( hSemaphore, 1, NULL );
			}
		}
	}
	else
	{
		CopySZ( szFunction, sizeof( szFunction ), "ExecQuery (GetWMIProductInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
	}

	SysFreeString( bszQueryLanguage );
	SysFreeString( bszQuery );
}

VOID GetWMIProcessInfo( CHAR szTarget[], IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate )
{
	DWORD                                    i;
	CHAR                       szQueryLanguage[ 128 ];
	CHAR                               szQuery[ 128 ];
	WCHAR                     wszQueryLanguage[ 256 ];
	WCHAR                             wszQuery[ 256 ];
	BSTR                      bszQueryLanguage;
	BSTR                              bszQuery;
	IEnumWbemClassObject          *pEnumerator;
	HRESULT                            hResult;
	BOOL                          bUseGetOwner;
	BSTR                          bszClassName;
	BSTR                         bszMethodName;
	IWbemClassObject                   *pClass;
	IWbemClassObject              *pGetOwnerIn;
	IWbemClassObject             *pGetOwnerOut;
	IWbemClassObject                  *pObject;
	ULONG                            uReturned;
	VARIANT                         vtProperty;
	CHAR                         szProcessName[ 128 ];
	CHAR                      szExecutablePath[ 512 ];
	CHAR                         szCommandLine[ 1024 ];
	CHAR                     szProcessUsername[ 128 ];
	CHAR                   szProcessDomainName[ 128 ];
	CHAR                 szProcessFullUsername[ 128 ];
	DWORD                          dwProcessID;
	BSTR                         bszObjectPath;
	FILE                          *pOutputFile;
	CHAR                            szFunction[ 128 ];

	i = 0;

	CopySZ( szQueryLanguage, sizeof( szQueryLanguage ), "WQL" );
	CopySZ( szQuery, sizeof( szQuery ), "Select * from Win32_Process" );

	ConvertSZtoWSZ( wszQueryLanguage, sizeof( wszQueryLanguage ), szQueryLanguage );
	ConvertSZtoWSZ( wszQuery, sizeof( wszQuery ), szQuery );

	bszQueryLanguage = SysAllocString( wszQueryLanguage );
	bszQuery         = SysAllocString( wszQuery );

	pEnumerator = NULL;

	hResult = pService->ExecQuery( bszQueryLanguage, bszQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator );

	if ( SUCCEEDED( hResult ) )
	{
		if ( *bImpersonate )
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE );
		}
		else
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, authIdentity, EOAC_NONE );
		}

		bUseGetOwner = FALSE;

		bszClassName  = SysAllocString( L"Win32_Process" );
		bszMethodName = SysAllocString( L"GetOwner" );

		pClass       = NULL;
		pGetOwnerIn  = NULL;
		pGetOwnerOut = NULL;

		hResult = pService->GetObject( bszClassName, 0, NULL, &pClass, NULL );

		if ( SUCCEEDED( hResult ) )
		{
			hResult = pClass->GetMethod( bszMethodName, 0, &pGetOwnerIn, &pGetOwnerOut );

			if ( SUCCEEDED( hResult ) )
			{
				bUseGetOwner = TRUE;
			}
		}

		while ( pEnumerator )
		{
			pObject = NULL;

			hResult = pEnumerator->Next( WBEM_INFINITE, 1, &pObject, &uReturned );

			if ( SUCCEEDED( hResult ) )
			{
				if ( uReturned == 0 )
				{
					break;
				}

				hResult = pObject->Get( L"Name", 0, &vtProperty, NULL, NULL );

				ConvertWSZtoSZ( szProcessName, sizeof( szProcessName ), vtProperty.bstrVal );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"ProcessId", 0, &vtProperty, NULL, NULL );

				dwProcessID = vtProperty.uintVal;

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"ExecutablePath", 0, &vtProperty, NULL, NULL );

				ConvertWSZtoSZ( szExecutablePath, sizeof( szExecutablePath ), vtProperty.bstrVal );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"CommandLine", 0, &vtProperty, NULL, NULL );

				ConvertWSZtoSZ( szCommandLine, sizeof( szCommandLine ), vtProperty.bstrVal );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"__PATH", 0, &vtProperty, 0, 0 );

				bszObjectPath = vtProperty.bstrVal;

				VariantClear( &vtProperty );

				CopySZ( szProcessUsername, sizeof( szProcessUsername ), "" );
				CopySZ( szProcessDomainName, sizeof( szProcessDomainName ), "" );
				CopySZ( szProcessFullUsername, sizeof( szProcessFullUsername ), "" );

				if ( bUseGetOwner )
				{
					hResult = pService->ExecMethod( bszObjectPath, bszMethodName, 0, NULL, pGetOwnerIn, &pGetOwnerOut, NULL );

					if ( SUCCEEDED( hResult ) )
					{
						hResult = pGetOwnerOut->Get( L"User", 0, &vtProperty, NULL, 0 );

						ConvertWSZtoSZ( szProcessUsername, sizeof( szProcessUsername ), vtProperty.bstrVal );

						VariantClear( &vtProperty );

						hResult = pGetOwnerOut->Get( L"Domain", 0, &vtProperty, NULL, 0 );

						ConvertWSZtoSZ( szProcessDomainName, sizeof( szProcessDomainName ), vtProperty.bstrVal );

						VariantClear( &vtProperty );

						if ( strcmp( szProcessUsername, "" ) != 0 )
						{
							sprintf( szProcessFullUsername, "%s\\%s", szProcessDomainName, szProcessUsername );
						}
					}
				}

				pObject->Release();

				if ( int( szExecutablePath[0] ) < 32 || int( szExecutablePath[0] ) > 255 )
				{
					CopySZ( szExecutablePath, sizeof( szExecutablePath ), "" );
				}

				if ( int( szCommandLine[0] ) < 32 || int( szCommandLine[0] ) > 255 )
				{
					CopySZ( szCommandLine, sizeof( szCommandLine ), "" );
				}

				if ( !bMultipleHosts )
				{
					if ( i == 0 )
					{
						printf( "\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "+++++           PROCESS INFORMATION           +++++\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "\n" );

						i++;
					}

					printf( "Process Name: %s\n", szProcessName );
					printf( "Process ID:   %d\n", dwProcessID );
					printf( "Owner:        %s\n", szProcessFullUsername );
					printf( "File Path:    %s\n", szExecutablePath );
					printf( "Command Line: %s\n", szCommandLine );

					printf( "\n" );

					fflush( stdout );
				}

				if ( bVerboseOptionSelected && bMultipleHosts )
				{
					printf( "%s -> Logging process information.\n", szTarget );

					fflush( stdout );
				}

				WaitForSingleObject( hSemaphore, INFINITE );

				pOutputFile = fopen( "Reports\\ProcessInfo.txt", "r" );

				if ( pOutputFile != NULL )
				{
					fclose( pOutputFile );
				}
				else
				{
					pOutputFile = fopen( "Reports\\ProcessInfo.txt", "w" );

					if ( pOutputFile != NULL )
					{
						fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
						fprintf( pOutputFile, "\n" );
						fprintf( pOutputFile, "Hostname\tProcess Name\tProcess ID\tOwner\tFile Path\tCommand Line\n" );

						fclose( pOutputFile );
					}
				}

				pOutputFile = fopen( "Reports\\ProcessInfo.txt", "a+" );

				if ( pOutputFile != NULL )
				{
					fprintf( pOutputFile, "%s\t%s\t%d\t%s\t%s\t%s\n", szTarget, szProcessName, dwProcessID, szProcessFullUsername, szExecutablePath, szCommandLine );

					fclose( pOutputFile );
				}

				ReleaseSemaphore( hSemaphore, 1, NULL );
			}
		}

		SysFreeString( bszMethodName );
		SysFreeString( bszClassName );

		if ( bUseGetOwner )
		{
			pClass->Release();
		}
	}
	else
	{
		CopySZ( szFunction, sizeof( szFunction ), "ExecQuery (GetWMIProcessInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
	}

	SysFreeString( bszQueryLanguage );
	SysFreeString( bszQuery );
}

VOID GetLoggedOnUsers( CHAR szTarget[] )
{
	CHAR                szTempTarget[ 128 ];
	WCHAR                  wszTarget[ 256 ];
	DWORD                          i;
	DWORD                    dwLevel;
	DWORD              dwEntriesRead;
	DWORD             dwTotalEntries;
	DWORD             dwResumeHandle;
	WKSTA_USER_INFO_1         *pInfo;
	NET_API_STATUS           nStatus;
	WKSTA_USER_INFO_1     *pTempInfo;
	DWORD                          j;
	CHAR                  szUsername[ 128 ];
	CHAR               szLogonDomain[ 128 ];
	CHAR              szOtherDomains[ 256 ];
	CHAR               szLogonServer[ 128 ];
	FILE                *pOutputFile;
	DWORD                    dwError;
	CHAR                  szFunction[ 128 ];

	sprintf( szTempTarget, "\\\\%s", szTarget );

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTempTarget );

	i = 0;

	dwLevel        = 1;
	dwEntriesRead  = 0;
	dwTotalEntries = 0;
	dwResumeHandle = 0;

	do
	{
		pInfo = NULL;

		nStatus = NetWkstaUserEnum( wszTarget, dwLevel, (PBYTE *)&pInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle );

		if ( nStatus == NERR_Success || nStatus == ERROR_MORE_DATA )
		{
			if ( pInfo != NULL )
			{
				pTempInfo = pInfo;

				for ( j = 0; j < dwEntriesRead; j++ )
				{
					ConvertWSZtoSZ( szUsername, sizeof( szUsername ), pTempInfo->wkui1_username );
					ConvertWSZtoSZ( szLogonDomain, sizeof( szLogonDomain ), pTempInfo->wkui1_logon_domain );
					ConvertWSZtoSZ( szOtherDomains, sizeof( szOtherDomains ), pTempInfo->wkui1_oth_domains );
					ConvertWSZtoSZ( szLogonServer, sizeof( szLogonServer ), pTempInfo->wkui1_logon_server );

					if ( !bMultipleHosts )
					{
						if ( i == 0 )
						{
							printf( "\n" );
							printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
							printf( "+++++             LOGGED ON USERS             +++++\n" );
							printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
							printf( "\n" );

							i++;
						}

						printf( "Username:      %s\n", szUsername );
						printf( "Logon Domain:  %s\n", szLogonDomain );
						printf( "Other Domains: %s\n", szOtherDomains );
						printf( "Logon Server:  %s\n", szLogonServer );
						printf( "\n" );

						fflush( stdout );
					}

					if ( bVerboseOptionSelected && bMultipleHosts )
					{
						printf( "%s -> Logging logged on users.\n", szTarget );

						fflush( stdout );
					}

					WaitForSingleObject( hSemaphore, INFINITE );

					pOutputFile = fopen( "Reports\\LoggedOnUsers.txt", "r" );

					if ( pOutputFile != NULL )
					{
						fclose( pOutputFile );
					}
					else
					{
						pOutputFile = fopen( "Reports\\LoggedOnUsers.txt", "w" );

						if ( pOutputFile != NULL )
						{
							fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
							fprintf( pOutputFile, "\n" );
							fprintf( pOutputFile, "Hostname\tUsername\tLogon Domain\tOther Domains\tLogon Server\n" );

							fclose( pOutputFile );
						}
					}

					pOutputFile = fopen( "Reports\\LoggedOnUsers.txt", "a+" );

					if ( pOutputFile != NULL )
					{
						fprintf( pOutputFile, "%s\t%s\t%s\t%s\t%s\n", szTarget, szUsername, szLogonDomain, szOtherDomains, szLogonServer );

						fclose( pOutputFile );
					}

					ReleaseSemaphore( hSemaphore, 1, NULL );

					pTempInfo++;
				}
			}
		}
		else
		{
			dwError = nStatus;

			CopySZ( szFunction, sizeof( szFunction ), "NetWkstaUserEnum (GetLoggedOnUsers)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}

		if ( pInfo != NULL )
		{
			NetApiBufferFree( pInfo );
		}
	}
	while ( nStatus == ERROR_MORE_DATA );
}

VOID GetPatchInfo( CHAR szTarget[] )
{
	CHAR       szTempTarget[ 128 ];
	WCHAR         wszTarget[ 256 ];
	LONG            lReturn;
	HKEY               hKey;
	CHAR       szSubKeyName[ 256 ];
	WCHAR     wszSubKeyName[ 512 ];
	HKEY            hSubKey;
	CHAR          szKeyName[ 128 ];
	WCHAR        wszKeyName[ 256 ];
	DWORD      dwBufferSize;
	WCHAR wszCurrentVersion[ 256 ];
	CHAR   szCurrentVersion[ 128 ];
	WCHAR   wszCurrentBuild[ 256 ];
	CHAR     szCurrentBuild[ 128 ];
	CHAR   szOSCurrentBuild[ 128 ];
	FILE    *pPatchInfoFile;
	DWORD                 i;
	CHAR             szLine[ 1024 ];
	CHAR         *pLocation;
	CHAR        szSplitText[ 128 ];
	CHAR        szOSVersion[ 128 ];
	CHAR      szServicePack[ 128 ];
	CHAR       szMSAdvisory[ 128 ];
	CHAR         szFilePath[ 256 ];
	DWORD      dwPatchedHMS;
	DWORD      dwPatchedLMS;
	DWORD      dwPatchedHLS;
	DWORD      dwPatchedLLS;
	CHAR     szFullFilePath[ 512 ];
	DWORD             dwHMS;
	DWORD             dwLMS;
	DWORD             dwHLS;
	DWORD             dwLLS;
	CHAR        szIsPatched[ 64 ];
	FILE       *pOutputFile;
	DWORD           dwError;
	CHAR         szFunction[ 128 ];
	CHAR         szErrorMsg[ 128 ];

	sprintf( szTempTarget, "\\\\%s", szTarget );

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTempTarget );

	lReturn = RegConnectRegistry( wszTarget, HKEY_LOCAL_MACHINE, &hKey );

	if ( lReturn == ERROR_SUCCESS )
	{
		CopySZ( szSubKeyName, sizeof( szSubKeyName ), "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" );

		ConvertSZtoWSZ( wszSubKeyName, sizeof( wszSubKeyName ), szSubKeyName );

		lReturn = RegOpenKeyEx( hKey, wszSubKeyName, 0, KEY_QUERY_VALUE, &hSubKey );

		if ( lReturn == ERROR_SUCCESS )
		{
			CopySZ( szKeyName, sizeof( szKeyName ), "CurrentVersion" );

			ConvertSZtoWSZ( wszKeyName, sizeof( wszKeyName ), szKeyName );

			dwBufferSize = (DWORD)sizeof( wszCurrentVersion );

			lReturn = RegQueryValueEx( hSubKey, wszKeyName, NULL, NULL, (BYTE *)wszCurrentVersion, &dwBufferSize );

			if ( lReturn == ERROR_SUCCESS )
			{
				ConvertWSZtoSZ( szCurrentVersion, sizeof( szCurrentVersion ), wszCurrentVersion );

				CopySZ( szKeyName, sizeof( szKeyName ), "CurrentBuild" );

				ConvertSZtoWSZ( wszKeyName, sizeof( wszKeyName ), szKeyName );

				dwBufferSize = (DWORD)sizeof( wszCurrentBuild );

				lReturn = RegQueryValueEx( hSubKey, wszKeyName, NULL, NULL, (BYTE *)wszCurrentBuild, &dwBufferSize );

				if ( lReturn == ERROR_SUCCESS )
				{
					ConvertWSZtoSZ( szCurrentBuild, sizeof( szCurrentBuild ), wszCurrentBuild );

					sprintf( szOSCurrentBuild, "%s:%s:", szCurrentVersion, szCurrentBuild );

					pPatchInfoFile = fopen( "PatchInfo.input", "r" );

					if ( pPatchInfoFile != NULL )
					{
						i = 0;

						while ( fgets( szLine, sizeof( szLine ), pPatchInfoFile ) != NULL )
						{
							Trim( szLine, sizeof( szLine ) );

							if ( szLine[0] != '#' && szLine[0] != '\n' )
							{
								if ( szLine[strlen( szLine ) - 1] == '\n' )
								{
									szLine[strlen( szLine ) - 1] = '\0';
								}

								pLocation = strstr( szLine, szOSCurrentBuild);

								if ( pLocation != NULL )
								{
									CopySZ( szSplitText, sizeof( szSplitText ), ":" );

									if ( SplitPatchInfo( szLine, szSplitText, szOSVersion, sizeof( szOSVersion ), szServicePack, sizeof( szServicePack ), szMSAdvisory, sizeof( szMSAdvisory ), szFilePath, sizeof( szFilePath ), &dwPatchedHMS, &dwPatchedLMS, &dwPatchedHLS, &dwPatchedLLS ) )
									{
										sprintf( szFullFilePath, "%s%s", szTempTarget, szFilePath );

										if ( GetFileVersion( szTarget, szFullFilePath, &dwHMS, &dwLMS, &dwHLS, &dwLLS ) )
										{
											CopySZ( szIsPatched, sizeof( szIsPatched ), "No" );

											if ( dwHMS == dwPatchedHMS )
											{
												if ( dwLMS == dwPatchedLMS )
												{
													if ( dwHLS == dwPatchedHLS )
													{
														if ( dwLLS == dwPatchedLLS )
														{
															CopySZ( szIsPatched, sizeof( szIsPatched ), "Yes" );
														}
														else
														{
															if ( dwLLS > dwPatchedLLS )
															{
																CopySZ( szIsPatched, sizeof( szIsPatched ), "Yes" );
															}
														}
													}
													else
													{
														if ( dwHLS > dwPatchedHLS )
														{
															CopySZ( szIsPatched, sizeof( szIsPatched ), "Yes" );
														}
													}
												}
												else
												{
													if ( dwLMS > dwPatchedLMS )
													{
														CopySZ( szIsPatched, sizeof( szIsPatched ), "Yes" );
													}
												}
											}
											else
											{
												if ( dwHMS > dwPatchedHMS )
												{
													CopySZ( szIsPatched, sizeof( szIsPatched ), "Yes" );
												}
											}

											if ( !bMultipleHosts )
											{
												if ( i == 0 )
												{
													printf( "\n" );
													printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
													printf( "+++++            PATCH INFORMATION            +++++\n" );
													printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
													printf( "\n" );

													i++;
												}

												printf( "MS Advisory:          %s\n", szMSAdvisory );
												printf( "OS Version:           %s\n", szCurrentVersion );
												printf( "Build Version:        %s\n", szCurrentBuild );
												printf( "File Path:            %s\n", szFullFilePath );
												printf( "File Version:         %d.%d.%d.%d\n", dwHMS, dwLMS, dwHLS, dwLLS );
												printf( "Patched File Version: %d.%d.%d.%d\n", dwPatchedHMS, dwPatchedLMS, dwPatchedHLS, dwPatchedLLS );
												printf( "Is Patched?:          %s\n", szIsPatched );
												printf( "\n" );

												fflush( stdout );
											}

											if ( bVerboseOptionSelected && bMultipleHosts )
											{
												printf( "%s -> Logging patch information.\n", szTarget );

												fflush( stdout );
											}

											WaitForSingleObject( hSemaphore, INFINITE );

											pOutputFile = fopen( "Reports\\PatchInfo.txt", "r" );

											if ( pOutputFile != NULL )
											{
												fclose( pOutputFile );
											}
											else
											{
												pOutputFile = fopen( "Reports\\PatchInfo.txt", "w" );

												if ( pOutputFile != NULL )
												{
													fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
													fprintf( pOutputFile, "\n" );
													fprintf( pOutputFile, "Hostname\tMS Advisory\tOS Version\tBuild Version\tFile Path\tFile Version\tPatched File Version\tIs Patched?\n" );

													fclose( pOutputFile );
												}
											}

											pOutputFile = fopen( "Reports\\PatchInfo.txt", "a+" );

											if ( pOutputFile != NULL )
											{
												fprintf( pOutputFile, "%s\t%s\t%s\t%s\t%s\t%d.%d.%d.%d\t%d.%d.%d.%d\t%s\n", szTarget, szMSAdvisory, szCurrentVersion, szCurrentBuild, szFullFilePath, dwHMS, dwLMS, dwHLS, dwLLS, dwPatchedHMS, dwPatchedLMS, dwPatchedHLS, dwPatchedLLS, szIsPatched );

												fclose( pOutputFile );
											}

											ReleaseSemaphore( hSemaphore, 1, NULL );
										}
									}
									else
									{
										CopySZ( szFunction, sizeof( szFunction ), "SplitPatchInfo (GetPatchInfo)" );
										CopySZ( szErrorMsg, sizeof( szErrorMsg ), "Split problem with file PatchInfo.input." );

										WriteToErrorLog( szTarget, szFunction, szErrorMsg );
									}
								}
							}
						}

						fclose( pPatchInfoFile );
					}
					else
					{
						CopySZ( szFunction, sizeof( szFunction ), "fopen (GetPatchInfo)" );
						CopySZ( szErrorMsg, sizeof( szErrorMsg ), "Cannot open file PatchInfo.input." );

						WriteToErrorLog( szTarget, szFunction, szErrorMsg );
					}
				}
				else
				{
					dwError = lReturn;

					CopySZ( szFunction, sizeof( szFunction ), "RegQueryValueEx (GetPatchInfo)" );

					WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
				}
			}
			else
			{
				dwError = lReturn;

				CopySZ( szFunction, sizeof( szFunction ), "RegQueryValueEx (GetPatchInfo)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
			}

			RegCloseKey( hSubKey );
		}
		else
		{
			dwError = lReturn;

			CopySZ( szFunction, sizeof( szFunction ), "RegOpenKeyEx (GetPatchInfo)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}

		RegCloseKey( hKey );
	}
	else
	{
		dwError = lReturn;

		CopySZ( szFunction, sizeof( szFunction ), "RegConnectRegistry (GetPatchInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
	}
}

BOOL SplitPatchInfo( CHAR szText[], CHAR szSplitText[], CHAR szOSVersion[], size_t siOSVersion, CHAR szServicePack[], size_t siServicePack, CHAR szMSAdvisory[], size_t siMSAdvisory, CHAR szFilePath[], size_t siFilePath, DWORD *dwHMS, DWORD *dwLMS, DWORD *dwHLS, DWORD *dwLLS )
{
	BOOL         bReturn;
	DWORD   dwTextLength;
	DWORD  dwSplitLength;
	CHAR      *pLocation;
	DWORD dwTextLocation;
	DWORD              i;
	DWORD              j;
	CHAR     szStartText[ 256 ];
	DWORD              k;
	CHAR       szEndText[ 256 ];
	CHAR           szHMS[ 64 ];
	CHAR           szLMS[ 64 ];
	CHAR           szHLS[ 64 ];
	CHAR           szLLS[ 64 ];

	bReturn = FALSE;

	dwTextLength  = (DWORD)strlen( szText );
	dwSplitLength = (DWORD)strlen( szSplitText );

	pLocation = strstr( szText, szSplitText );

	dwTextLocation = (INT)( pLocation - szText );

	i = 0;

	while ( pLocation != NULL )
	{
		j = 0;

		while ( j < dwTextLocation )
		{
			szStartText[j] = szText[j];

			j++;
		}

		szStartText[j] = '\0';

		j = dwTextLocation + dwSplitLength;

		k = 0;

		while ( j < dwTextLength )
		{
			szEndText[k] = szText[j];

			j++;
			k++;
		}

		szEndText[k] = '\0';

		CopySZ( szText, dwTextLength, szEndText );

		if ( i == 0 )
		{
			CopySZ( szOSVersion, siOSVersion, szStartText );
		}

		if ( i == 1 )
		{
			CopySZ( szServicePack, siServicePack, szStartText );
		}

		if ( i == 2 )
		{
			CopySZ( szMSAdvisory, siMSAdvisory, szStartText );
		}

		if ( i == 3 )
		{
			CopySZ( szFilePath, siFilePath, szStartText );
		}

		if ( i == 4 )
		{
			CopySZ( szHMS, sizeof( szHMS ), szStartText );

			*dwHMS = atoi( szHMS );
		}

		if ( i == 5 )
		{
			CopySZ( szLMS, sizeof( szLMS ), szStartText );

			*dwLMS = atoi( szLMS );
		}

		if ( i == 6 )
		{
			bReturn = TRUE;

			CopySZ( szHLS, sizeof( szHLS ), szStartText );
			CopySZ( szLLS, sizeof( szLLS ), szEndText );

			*dwHLS = atoi( szHLS );
			*dwLLS = atoi( szLLS );
		}

		i++;

		pLocation = strstr( szText, szSplitText );

		dwTextLocation = (INT)( pLocation - szText );
	}

	return bReturn;
}

BOOL GetFileVersion( CHAR szTarget[], CHAR szFilePath[], DWORD *dwHMS, DWORD *dwLMS, DWORD *dwHLS, DWORD *dwLLS )
{
	BOOL                     bReturn;
	WCHAR                wszFilePath[ 512 ];
	DWORD              dwVersionSize;
	DWORD                   dwHandle;
	CHAR                   *pVersion;
	CHAR                  szSubBlock[ 128 ];
	WCHAR                wszSubBlock[ 256 ];
	VS_FIXEDFILEINFO          *pInfo;
	UINT                        uLen;
	DWORD            dwFileVersionMS;
	DWORD            dwFileVersionLS;
	DWORD                    dwError;
	CHAR                  szFunction[ 128 ];

	bReturn = FALSE;

	ConvertSZtoWSZ( wszFilePath, sizeof( wszFilePath ), szFilePath );

	dwVersionSize = GetFileVersionInfoSize( wszFilePath, &dwHandle );

	if ( dwVersionSize != 0 )
	{
		pVersion = NULL;

		pVersion = (CHAR *)LocalAlloc( LPTR, dwVersionSize );

		if ( pVersion != NULL )
		{
			if ( GetFileVersionInfo( wszFilePath, dwHandle, dwVersionSize, pVersion ) )
			{
				CopySZ( szSubBlock, sizeof( szSubBlock ), "\\" );

				ConvertSZtoWSZ( wszSubBlock, sizeof( wszSubBlock ), szSubBlock );

				pInfo = NULL;

				if ( VerQueryValue( pVersion, wszSubBlock, (PVOID *)&pInfo, &uLen ) )
				{
					if ( pInfo != NULL )
					{
						bReturn = TRUE;

						dwFileVersionMS = pInfo->dwFileVersionMS;
						dwFileVersionLS = pInfo->dwFileVersionLS;

						*dwHMS = HIWORD( dwFileVersionMS );
						*dwLMS = LOWORD( dwFileVersionMS );
						*dwHLS = HIWORD( dwFileVersionLS );
						*dwLLS = LOWORD( dwFileVersionLS );
					}
				}
			}
			else
			{
				dwError = GetLastError();

				CopySZ( szFunction, sizeof( szFunction ), "GetFileVersionInfo (GetFileVersion)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
			}

			LocalFree( pVersion );
		}
		else
		{
			dwError = GetLastError();

			CopySZ( szFunction, sizeof( szFunction ), "LocalAlloc (GetFileVersion)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}
	}
	else
	{
		dwError = GetLastError();

		CopySZ( szFunction, sizeof( szFunction ), "GetFileVersionInfoSize (GetFileVersion)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
	}

	return bReturn;
}

VOID GetRegistryInfo( CHAR szTarget[] )
{
	CHAR        szTempTarget[ 128 ];
	WCHAR          wszTarget[ 128 ];
	FILE  *pRegistryInfoFile;
	DWORD                  i;
	CHAR              szLine[ 512 ];
	CHAR         szSplitText[ 128 ];
	CHAR        szSubKeyName[ 256 ];
	CHAR           szKeyName[ 128 ];
	WCHAR      wszSubKeyName[ 512 ];
	WCHAR         wszKeyName[ 256 ];
	LONG             lReturn;
	HKEY                hKey;
	HKEY             hSubKey;
	WCHAR        wszRegValue[ 256 ];
	DWORD       dwBufferSize;
	DWORD             dwType;
	CHAR          szRegValue[ 128 ];
	DWORD         dwRegValue;
	FILE        *pOutputFile;
	DWORD            dwError;
	CHAR          szFunction[ 128 ];
	CHAR          szErrorMsg[ 128 ];

	sprintf( szTempTarget, "\\\\%s", szTarget );

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTempTarget );

	pRegistryInfoFile = fopen( "RegistryInfo.input", "r" );

	if ( pRegistryInfoFile != NULL )
	{
		i = 0;

		while ( fgets( szLine, sizeof( szLine ), pRegistryInfoFile ) != NULL )
		{
			Trim( szLine, sizeof( szLine ) );

			if ( szLine[0] != '#' && szLine[0] != '\n' )
			{
				if ( szLine[strlen( szLine ) - 1] == '\n' )
				{
					szLine[strlen( szLine ) - 1] = '\0';
				}

				CopySZ( szSplitText, sizeof( szSplitText ), ":" );

				if ( SplitRegistryInfo( szLine, szSplitText, szSubKeyName, szKeyName ) )
				{
					ConvertSZtoWSZ( wszSubKeyName, sizeof( wszSubKeyName ), szSubKeyName );
					ConvertSZtoWSZ( wszKeyName, sizeof( wszKeyName ), szKeyName );

					lReturn = RegConnectRegistry( wszTarget, HKEY_LOCAL_MACHINE, &hKey );

					if ( lReturn == ERROR_SUCCESS )
					{
						lReturn = RegOpenKeyEx( hKey, wszSubKeyName, 0, KEY_QUERY_VALUE, &hSubKey );

						if ( lReturn == ERROR_SUCCESS )
						{
							dwBufferSize = (DWORD)sizeof( wszRegValue );

							lReturn = RegQueryValueEx( hSubKey, wszKeyName, NULL, &dwType, (BYTE *)wszRegValue, &dwBufferSize );

							if ( lReturn == ERROR_SUCCESS )
							{
								ConvertWSZtoSZ( szRegValue, sizeof( szRegValue ), wszRegValue );

								if ( dwType == REG_DWORD )
								{
									CopySZ( szRegValue, sizeof( szRegValue ), "" );

									dwBufferSize = (DWORD)sizeof( dwRegValue );

									lReturn = RegQueryValueEx( hSubKey, wszKeyName, NULL, NULL, (BYTE *)&dwRegValue, &dwBufferSize );

									if ( lReturn == ERROR_SUCCESS )
									{
										sprintf( szRegValue, "%d", dwRegValue );
									}
								}

								if ( !bMultipleHosts )
								{
									if ( i == 0 )
									{
										printf( "\n" );
										printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
										printf( "+++++          REGISTRY INFORMATION           +++++\n" );
										printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
										printf( "\n" );

										i++;
									}

									printf( "Registry Key:   HKLM\\%s\\\\%s\n", szSubKeyName, szKeyName );
									printf( "Registry Value: %s\n", szRegValue );
									printf( "\n" );

									fflush( stdout );
								}

								if ( bVerboseOptionSelected && bMultipleHosts )
								{
									printf( "%s -> Logging registry information.\n", szTarget );

									fflush( stdout );
								}

								WaitForSingleObject( hSemaphore, INFINITE );

								pOutputFile = fopen( "Reports\\RegistryInfo.txt", "r" );

								if ( pOutputFile != NULL )
								{
									fclose( pOutputFile );
								}
								else
								{
									pOutputFile = fopen( "Reports\\RegistryInfo.txt", "w" );

									if ( pOutputFile != NULL )
									{
										fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
										fprintf( pOutputFile, "\n" );
										fprintf( pOutputFile, "Hostname\tRegistry Key\tRegistry Value\n" );

										fclose( pOutputFile );
									}
								}

								pOutputFile = fopen( "Reports\\RegistryInfo.txt", "a+" );

								if ( pOutputFile != NULL )
								{
									fprintf( pOutputFile, "%s\tHKLM\\%s\\\\%s\t%s\n", szTarget, szSubKeyName, szKeyName, szRegValue );

									fclose( pOutputFile );
								}

								ReleaseSemaphore( hSemaphore, 1, NULL );
							}
							else
							{
								dwError = lReturn;

								CopySZ( szFunction, sizeof( szFunction ), "RegQueryValueEx (GetRegistryInfo)" );

								WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
							}

							RegCloseKey( hSubKey );
						}
						else
						{
							dwError = lReturn;

							CopySZ( szFunction, sizeof( szFunction ), "RegOpenKeyEx (GetRegistryInfo)" );

							WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
						}

						RegCloseKey( hKey );
					}
					else
					{
						dwError = lReturn;

						CopySZ( szFunction, sizeof( szFunction ), "RegConnectRegistry (GetRegistryInfo)" );

						WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
					}
				}
				else
				{
					CopySZ( szFunction, sizeof( szFunction ), "SplitRegistryInfo (GetRegistryInfo)" );
					CopySZ( szErrorMsg, sizeof( szErrorMsg ), "Split problem with file RegQueryKeys.input." );

					WriteToErrorLog( szTarget, szFunction, szErrorMsg );
				}
			}
		}

		fclose( pRegistryInfoFile );
	}
	else
	{
		CopySZ( szFunction, sizeof( szFunction ), "fopen (GetRegistryInfo)" );
		CopySZ( szErrorMsg, sizeof( szErrorMsg ), "Cannot open file RegistryInfo.input." );

		WriteToErrorLog( szTarget, szFunction, szErrorMsg );
	}
}

BOOL SplitRegistryInfo( CHAR szText[], CHAR szSplitText[], CHAR szSubKeyName[], CHAR szKeyName[] )
{
	BOOL         bReturn;
	DWORD  dwSplitLength;
	CHAR  *pTextLocation;
	DWORD dwTextLocation;
	DWORD              i;
	DWORD              j;

	bReturn = FALSE;

	dwSplitLength = (DWORD)strlen( szSplitText );

	pTextLocation = strstr( szText, szSplitText );

	dwTextLocation = (INT)( pTextLocation - szText );

	if ( pTextLocation != NULL )
	{
		bReturn = TRUE;

		i = 0;

		while ( i < dwTextLocation )
		{
			szSubKeyName[i] = szText[i];

			i++;
		}

		szSubKeyName[i] = '\0';

		i = dwTextLocation + dwSplitLength;

		j = 0;

		while ( i < strlen( szText ) )
		{
			szKeyName[j] = szText[i];

			i++;
			j++;
		}

		szKeyName[j] = '\0';
	}

	return bReturn;
}

VOID GetWMIRegistryInfo( CHAR szTarget[], IWbemServices *pService )
{
	HRESULT                     hResult;
	BSTR                   bszClassName;
	BSTR                 bszMethod1Name;
	BSTR                 bszMethod2Name;
	IWbemClassObject            *pClass;
	IWbemClassObject        *pInParams1;
	IWbemClassObject        *pInParams2;
	IWbemClassObject   *pClassInstance1;
	IWbemClassObject   *pClassInstance2;
	FILE             *pRegistryInfoFile;
	DWORD                             i;
	CHAR                         szLine[ 512 ];
	CHAR                    szSplitText[ 128 ];
	CHAR                   szSubKeyName[ 256 ];
	CHAR                      szKeyName[ 128 ];
	WCHAR                 wszSubKeyName[ 512 ];
	WCHAR                    wszKeyName[ 256 ];
	BSTR                  bszSubKeyName;
	BSTR                     bszKeyName;
	VARIANT                    vtDefKey;
	VARIANT                vtSubKeyName;
	VARIANT                 vtValueName;
	BOOL                      bContinue;
	CHAR                     szKeyValue[ 128 ];
	IWbemClassObject        *pOutParams;
	VARIANT                    vtResult;
	DWORD                    dwKeyValue;
	FILE                   *pOutputFile;
	CHAR                     szFunction[ 128 ];
	CHAR                     szErrorMsg[ 128 ];

	bszClassName   = SysAllocString( L"StdRegProv" );
	bszMethod1Name = SysAllocString( L"GetStringValue" );
	bszMethod2Name = SysAllocString( L"GetDWORDValue" );

	pClass = NULL;

	hResult = pService->GetObject( bszClassName, 0, NULL, &pClass, NULL );

	if ( SUCCEEDED( hResult ) )
	{
		pInParams1 = NULL;

		hResult = pClass->GetMethod( bszMethod1Name, 0, &pInParams1, NULL );

		pInParams2 = NULL;

		hResult = pClass->GetMethod( bszMethod2Name, 0, &pInParams2, NULL );

		if ( SUCCEEDED( hResult ) )
		{
			pClassInstance1 = NULL;

			hResult = pInParams1->SpawnInstance( 0, &pClassInstance1 );

			pClassInstance2 = NULL;

			hResult = pInParams2->SpawnInstance( 0, &pClassInstance2 );

			if ( SUCCEEDED( hResult ) )
			{
				pRegistryInfoFile = fopen( "RegistryInfo.input", "r" );

				if ( pRegistryInfoFile != NULL )
				{
					i = 0;

					while ( fgets( szLine, sizeof( szLine ), pRegistryInfoFile ) != NULL )
					{
						Trim( szLine, sizeof( szLine ) );

						if ( szLine[0] != '#' && szLine[0] != '\n' )
						{
							if ( szLine[strlen( szLine ) - 1] == '\n' )
							{
								szLine[strlen( szLine ) - 1] = '\0';
							}

							CopySZ( szSplitText, sizeof( szSplitText ), ":" );

							if ( SplitRegistryInfo( szLine, szSplitText, szSubKeyName, szKeyName ) )
							{
								ConvertSZtoWSZ( wszSubKeyName, sizeof( wszSubKeyName ), szSubKeyName );
								ConvertSZtoWSZ( wszKeyName, sizeof( wszKeyName ), szKeyName );

								bszSubKeyName = SysAllocString( wszSubKeyName );
								bszKeyName    = SysAllocString( wszKeyName );

								vtDefKey.vt   = VT_I4;
								vtDefKey.lVal = 0x80000002; // HKEY_LOCAL_MACHINE

								vtSubKeyName.vt      = VT_BSTR;
								vtSubKeyName.bstrVal = bszSubKeyName;

								vtValueName.vt      = VT_BSTR;
								vtValueName.bstrVal = bszKeyName;

								bContinue = FALSE;

								hResult    = NULL;
								pOutParams = NULL;

								hResult = pClassInstance1->Put( L"hDefKey", 0, &vtDefKey, 0 );
								hResult = pClassInstance1->Put( L"sSubKeyName", 0, &vtSubKeyName, 0 );
								hResult = pClassInstance1->Put( L"sValueName", 0, &vtValueName, 0 );

								hResult = pService->ExecMethod( bszClassName, bszMethod1Name, NULL, NULL, pClassInstance1, &pOutParams, NULL );

								if ( SUCCEEDED( hResult ) )
								{
									hResult = pOutParams->Get( L"sValue", 0, &vtResult, NULL, 0 );

									if ( SUCCEEDED( hResult ) && vtResult.bstrVal != NULL )
									{
										bContinue = TRUE;

										ConvertWSZtoSZ( szKeyValue, sizeof( szKeyValue ), vtResult.bstrVal );
									}
									else
									{
										hResult = pOutParams->Get( L"uValue", 0, &vtResult, NULL, 0 );

										if ( SUCCEEDED( hResult ) && vtResult.uintVal != NULL )
										{
											bContinue = TRUE;

											dwKeyValue = vtResult.uintVal;

											sprintf( szKeyValue, "%d", dwKeyValue );
										}
									}

									VariantClear( &vtResult );
								}
								else
								{
									CopySZ( szFunction, sizeof( szFunction ), "ExecMethod (GetWMIRegistryInfo)" );

									WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
								}

								if ( bContinue )
								{
									if ( !bMultipleHosts )
									{
										if ( i == 0 )
										{
											printf( "\n" );
											printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
											printf( "+++++        WMI REGISTRY INFORMATION         +++++\n" );
											printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
											printf( "\n" );

											i++;
										}

										printf( "Registry Key:   HKLM\\%s\\\\%s\n", szSubKeyName, szKeyName );
										printf( "Registry Value: %s\n", szKeyValue );

										printf( "\n" );

										fflush( stdout );
									}

									if ( bVerboseOptionSelected && bMultipleHosts )
									{
										printf( "%s -> Logging registry information.\n", szTarget );

										fflush( stdout );
									}

									WaitForSingleObject( hSemaphore, INFINITE );

									pOutputFile = fopen( "Reports\\WMIRegistryInfo.txt", "r" );

									if ( pOutputFile != NULL )
									{
										fclose( pOutputFile );
									}
									else
									{
										pOutputFile = fopen( "Reports\\WMIRegistryInfo.txt", "w" );

										if ( pOutputFile != NULL )
										{
											fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
											fprintf( pOutputFile, "\n" );
											fprintf( pOutputFile, "Hostname\tRegistry Key\tRegistry Value\n" );

											fclose( pOutputFile );
										}
									}

									pOutputFile = fopen( "Reports\\WMIRegistryInfo.txt", "a+" );

									if ( pOutputFile != NULL )
									{
										fprintf( pOutputFile, "%s\tHKLM\\%s\\\\%s\t%s\n", szTarget, szSubKeyName, szKeyName, szKeyValue );

										fclose( pOutputFile );
									}

									ReleaseSemaphore( hSemaphore, 1, NULL );

									pOutParams->Release();
								}

								VariantClear( &vtDefKey );
								VariantClear( &vtSubKeyName );
								VariantClear( &vtValueName );

								SysFreeString( bszSubKeyName );
								SysFreeString( bszKeyName );
							}
							else
							{
								CopySZ( szFunction, sizeof( szFunction ), "SplitRegistryInfo (GetWMIRegistryInfo)" );
								CopySZ( szErrorMsg, sizeof( szErrorMsg ), "Split problem with file RegQueryKeys.input." );

								WriteToErrorLog( szTarget, szFunction, szErrorMsg );
							}
						}
					}

					fclose( pRegistryInfoFile );
				}
				else
				{
					CopySZ( szFunction, sizeof( szFunction ), "fopen (GetWMIRegistryInfo)" );
					CopySZ( szErrorMsg, sizeof( szErrorMsg ), "Cannot open file RegistryInfo.input." );

					WriteToErrorLog( szTarget, szFunction, szErrorMsg );
				}

				pClassInstance1->Release();
				pClassInstance2->Release();
			}
			else
			{
				CopySZ( szFunction, sizeof( szFunction ), "SpawnInstance (GetWMIRegistryInfo)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
			}

			pInParams1->Release();
			pInParams2->Release();
		}
		else
		{
			CopySZ( szFunction, sizeof( szFunction ), "GetMethod (GetWMIRegistryInfo)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
		}

		pClass->Release();
	}
	else
	{
		CopySZ( szFunction, sizeof( szFunction ), "GetObject (GetWMIRegistryInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
	}

	SysFreeString( bszClassName );
	SysFreeString( bszMethod1Name );
	SysFreeString( bszMethod2Name );
}

VOID RunRemoteCommands( CHAR szTarget[], IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, CHAR szUsername[], CHAR szPassword[] )
{
	HRESULT                  hResult;
	BSTR                bszClassName;
	BSTR               bszMethodName;
	IWbemClassObject         *pClass;
	IWbemClassObject      *pInParams;
	IWbemClassObject *pClassInstance;
	FILE              *pCommandsFile;
	DWORD                          i;
	CHAR                      szLine[ 512 ];
	CHAR                 szSplitText[ 128 ];
	CHAR               szCommandType[ 128 ];
	CHAR               szCommandText[ 256 ];
	CHAR               szCommandLine[ 256 ];
	WCHAR             wszCommandLine[ 512 ];
	BSTR              bszCommandLine;
	VARIANT            vtCommandLine;
	IWbemClassObject     *pOutParams;
	VARIANT                 vtResult;
	DWORD                dwProcessID;
	DWORD                          j;
	BOOL                     bResult;
	BOOL             bSkipIPCConnect;
	BOOL               bIPCConnected;
	CHAR               szSaveFileSrc[ 128 ];
	CHAR              szSaveFileDest[ 128 ];
	WCHAR             wszSaveFileSrc[ 256 ];
	WCHAR            wszSaveFileDest[ 256 ];
	DWORD                    dwError;
	CHAR                  szFunction[ 128 ];
	CHAR                  szErrorMsg[ 128 ];

	bszClassName  = SysAllocString( L"Win32_Process" );
	bszMethodName = SysAllocString( L"Create" );

	pClass = NULL;

	hResult = pService->GetObject( bszClassName, 0, NULL, &pClass, NULL );

	if ( SUCCEEDED( hResult ) )
	{
		pInParams = NULL;

		hResult = pClass->GetMethod( bszMethodName, 0, &pInParams, NULL );

		if ( SUCCEEDED( hResult ) )
		{
			pClassInstance = NULL;

			hResult = pInParams->SpawnInstance( 0, &pClassInstance );

			if ( SUCCEEDED( hResult ) )
			{
				pCommandsFile = fopen( "RemoteCommands.input", "r" );

				if ( pCommandsFile != NULL )
				{
					i = 0;

					while ( fgets( szLine, sizeof( szLine ), pCommandsFile ) != NULL )
					{
						Trim( szLine, sizeof( szLine ) );

						if ( szLine[0] != '#' && szLine[0] != '\n' )
						{
							if ( szLine[strlen( szLine ) - 1] == '\n' )
							{
								szLine[strlen( szLine ) - 1] = '\0';
							}

							CopySZ( szSplitText, sizeof( szSplitText ), "_EXEC:" );

							if ( SplitCommandInfo( szLine, szSplitText, szCommandType, szCommandText ) )
							{
								if ( strcmp( szCommandType, "CMD" ) == 0 )
								{
									sprintf( szCommandLine, "cmd.exe /c %s", szCommandText );

									ConvertSZtoWSZ( wszCommandLine, sizeof( wszCommandLine ), szCommandLine );

									bszCommandLine = SysAllocString( wszCommandLine );

									vtCommandLine.vt      = VT_BSTR;
									vtCommandLine.bstrVal = bszCommandLine;

									pOutParams = NULL;

									hResult = pClassInstance->Put( L"CommandLine", 0, &vtCommandLine, 0 );

									hResult = pService->ExecMethod( bszClassName, bszMethodName, NULL, NULL, pClassInstance, &pOutParams, NULL );

									if ( SUCCEEDED( hResult ) )
									{
										hResult = pOutParams->Get( L"ProcessId", 0, &vtResult, NULL, 0 );

										if ( SUCCEEDED( hResult ) && vtResult.uintVal != NULL )
										{
											dwProcessID = vtResult.uintVal;

											if ( !bMultipleHosts )
											{
												if ( i == 0 )
												{
													printf( "\n" );
													printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
													printf( "+++++           RUN REMOTE COMMANDS           +++++\n" );
													printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
													printf( "\n" );

													i++;
												}

												printf( "Running Remote Command: %s\n", szCommandLine );

												fflush( stdout );
											}

											if ( bVerboseOptionSelected && bMultipleHosts )
											{
												printf( "%s -> Running remote command.\n", szTarget );

												fflush( stdout );
											}

											j = 0;

											while ( j < 20 )
											{
												bResult = IsProcessRunning( szTarget, pService, authIdentity, bImpersonate, &dwProcessID );

												if ( !bResult )
												{
													break;
												}

												Sleep( 500 );

												j++;
											}
										}

										VariantClear( &vtResult );

										pOutParams->Release();
									}
									else
									{
										CopySZ( szFunction, sizeof( szFunction ), "ExecMethod (RunRemoteCommands)" );

										WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
									}

									VariantClear( &vtCommandLine );

									SysFreeString( bszCommandLine );
								}

								if ( strcmp( szCommandType, "SAVE" ) == 0 )
								{
									bSkipIPCConnect = FALSE;
									bIPCConnected   = FALSE;

									if ( strcmp( szUsername, "+" ) == 0 && strcmp( szPassword, "+" ) == 0 )
									{
										bSkipIPCConnect = TRUE;
									}
									else
									{
										if ( Connect( szTarget, szUsername, szPassword, FALSE ) )
										{
											bIPCConnected = TRUE;
										}
									}

									if ( bSkipIPCConnect || bIPCConnected )
									{
										sprintf( szSaveFileSrc, "\\\\%s\\ADMIN$\\%s", szTarget, szCommandText );
										sprintf( szSaveFileDest, "Reports\\%s-%s", szTarget, szCommandText );

										ConvertSZtoWSZ( wszSaveFileSrc, sizeof( wszSaveFileSrc ), szSaveFileSrc );
										ConvertSZtoWSZ( wszSaveFileDest, sizeof( wszSaveFileDest ), szSaveFileDest );

										DeleteFile( wszSaveFileDest );

										bResult = MoveFile( wszSaveFileSrc, wszSaveFileDest );

										if ( bResult )
										{
											if ( !bMultipleHosts )
											{
												printf( "Saving Remote File:     %s\n", szSaveFileSrc );

												fflush( stdout );
											}
										}
										else
										{
											dwError = GetLastError();

											CopySZ( szFunction, sizeof( szFunction ), "MoveFile (RunRemoteCommands)" );

											WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
										}

										if ( bIPCConnected )
										{
											Disconnect( szTarget );
										}
									}
								}
							}
						}
					}

					if ( i > 0 )
					{
						if ( !bMultipleHosts )
						{
							printf( "\n" );

							fflush( stdout );
						}
					}

					fclose( pCommandsFile );
				}
				else
				{
					CopySZ( szFunction, sizeof( szFunction ), "fopen (RunRemoteCommands)" );
					CopySZ( szErrorMsg, sizeof( szErrorMsg ), "Cannot open file RemoteCommands.input." );

					WriteToErrorLog( szTarget, szFunction, szErrorMsg );
				}

				pClassInstance->Release();
			}
			else
			{
				CopySZ( szFunction, sizeof( szFunction ), "SpawnInstance (RunRemoteCommands)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
			}

			pInParams->Release();
		}
		else
		{
			CopySZ( szFunction, sizeof( szFunction ), "GetMethod (RunRemoteCommands)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
		}

		pClass->Release();
	}
	else
	{
		CopySZ( szFunction, sizeof( szFunction ), "GetObject (RunRemoteCommands)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
	}

	SysFreeString( bszClassName );
	SysFreeString( bszMethodName );
}

BOOL SplitCommandInfo( CHAR szText[], CHAR szSplitText[], CHAR szCommandType[], CHAR szCommandText[] )
{
	BOOL         bReturn;
	DWORD  dwSplitLength;
	CHAR  *pTextLocation;
	DWORD dwTextLocation;
	DWORD              i;
	DWORD              j;

	bReturn = FALSE;

	dwSplitLength = (DWORD)strlen( szSplitText );

	pTextLocation = strstr( szText, szSplitText );

	dwTextLocation = (INT)( pTextLocation - szText );

	if ( pTextLocation != NULL )
	{
		bReturn = TRUE;

		i = 0;

		while ( i < dwTextLocation )
		{
			szCommandType[i] = szText[i];

			i++;
		}

		szCommandType[i] = '\0';

		i = dwTextLocation + dwSplitLength;

		j = 0;

		while ( i < strlen( szText ) )
		{
			szCommandText[j] = szText[i];

			i++;
			j++;
		}

		szCommandText[j] = '\0';
	}

	return bReturn;
}

BOOL IsProcessRunning( CHAR szTarget[], IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate, DWORD *dwProcessID )
{
	BOOL                          bResult;
	CHAR                  szQueryLanguage[ 128 ];
	CHAR                          szQuery[ 128 ];
	WCHAR                wszQueryLanguage[ 256 ];
	WCHAR                        wszQuery[ 256 ];
	BSTR                 bszQueryLanguage;
	BSTR                         bszQuery;
	IEnumWbemClassObject     *pEnumerator;
	HRESULT                       hResult;
	IWbemClassObject             *pObject;
	ULONG                       uReturned;
	VARIANT                    vtProperty;
	CHAR                       szFunction[ 128 ];

	bResult = FALSE;

	CopySZ( szQueryLanguage, sizeof( szQueryLanguage ), "WQL" );

	sprintf( szQuery, "Select * from Win32_Process Where ProcessId = %d", *dwProcessID );

	ConvertSZtoWSZ( wszQueryLanguage, sizeof( wszQueryLanguage ), szQueryLanguage );
	ConvertSZtoWSZ( wszQuery, sizeof( wszQuery ), szQuery );

	bszQueryLanguage = SysAllocString( wszQueryLanguage );
	bszQuery         = SysAllocString( wszQuery );

	pEnumerator = NULL;

	hResult = pService->ExecQuery( bszQueryLanguage, bszQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator );

	if ( SUCCEEDED( hResult ) )
	{
		if ( *bImpersonate )
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE );
		}
		else
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, authIdentity, EOAC_NONE );
		}

		while ( pEnumerator )
		{
			pObject = NULL;

			hResult = pEnumerator->Next( WBEM_INFINITE, 1, &pObject, &uReturned );

			if ( SUCCEEDED( hResult ) )
			{
				if ( uReturned == 0 )
				{
					break;
				}

				hResult = pObject->Get( L"Name", 0, &vtProperty, NULL, NULL );
				
				if ( SUCCEEDED( hResult ) && vtProperty.bstrVal != NULL )
				{
					bResult = TRUE;
				}

				VariantClear( &vtProperty );

				pObject->Release();
			}
		}
	}
	else
	{
		CopySZ( szFunction, sizeof( szFunction ), "ExecQuery (IsProcessRunning)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
	}

	SysFreeString( bszQueryLanguage );
	SysFreeString( bszQuery );

	return bResult;
}

VOID GetServerInfo( CHAR szTarget[] )
{
	CHAR             szTempTarget[ 128 ];
	WCHAR               wszTarget[ 256 ];
	DWORD                 dwLevel;
	SERVER_INFO_101        *pInfo;
	NET_API_STATUS        nStatus;
	CHAR                szComment[ 512 ];
	BOOL                bIsServer;
	CHAR             szServerType[ 128 ];
	CHAR                 szOSType[ 128 ];
	CHAR            szServerFlags[ 256 ];
	FILE             *pOutputFile;
	DWORD                 dwError;
	CHAR               szFunction[ 128 ];

	sprintf( szTempTarget, "\\\\%s", szTarget );

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTempTarget );

	dwLevel = 101;
	pInfo   = NULL;

	nStatus = NetServerGetInfo( wszTarget, dwLevel, (PBYTE *)&pInfo );

	if ( nStatus == NERR_Success )
	{
		if ( pInfo != NULL )
		{
			bIsServer = TRUE;

			ConvertWSZtoSZ( szComment, sizeof( szComment ), pInfo->sv101_comment );

			if ( ( pInfo->sv101_type & SV_TYPE_DOMAIN_CTRL ) || ( pInfo->sv101_type & SV_TYPE_DOMAIN_BAKCTRL ) )
			{
				CopySZ( szServerType, sizeof( szServerType ), "Domain Controller" );
			}
			else if ( ( pInfo->sv101_type & SV_TYPE_SERVER_NT ) )
			{
				CopySZ( szServerType, sizeof( szServerType ), "Server" );
			}
			else
			{
				CopySZ( szServerType, sizeof( szServerType ), "Workstation" );

				bIsServer = FALSE;
			}

			if ( pInfo->sv101_version_major == 4 && pInfo->sv101_version_minor == 0 )
			{
				CopySZ( szOSType, sizeof( szOSType ), "Windows NT 4.0" );
			}
			else if ( pInfo->sv101_version_major == 5 && pInfo->sv101_version_minor == 0 )
			{
				CopySZ( szOSType, sizeof( szOSType ), "Windows 2000" );
			}
			else if ( pInfo->sv101_version_major == 5 && pInfo->sv101_version_minor == 1 )
			{
				CopySZ( szOSType, sizeof( szOSType ), "Windows XP" );
			}
			else if ( pInfo->sv101_version_major == 5 && pInfo->sv101_version_minor == 2 )
			{
				if ( bIsServer )
				{
					CopySZ( szOSType, sizeof( szOSType ), "Windows Server 2003 / Windows Server 2003 R2" );
				}
				else
				{
					sprintf( szOSType, "Other (%d.%d)", pInfo->sv101_version_major, pInfo->sv101_version_minor );
				}
			}
			else if ( pInfo->sv101_version_major == 6 && pInfo->sv101_version_minor == 0 )
			{
				if ( bIsServer )
				{
					CopySZ( szOSType, sizeof( szOSType ), "Windows Server 2008" );
				}
				else
				{
					CopySZ( szOSType, sizeof( szOSType ), "Windows Vista" );
				}
			}
			else if ( pInfo->sv101_version_major == 6 && pInfo->sv101_version_minor == 1 )
			{
				if ( bIsServer )
				{
					CopySZ( szOSType, sizeof( szOSType ), "Windows Server 2008 R2" );
				}
				else
				{
					CopySZ( szOSType, sizeof( szOSType ), "Windows 7" );
				}
			}
			else if ( pInfo->sv101_version_major == 6 && pInfo->sv101_version_minor == 2 )
			{
				if ( bIsServer )
				{
					CopySZ( szOSType, sizeof( szOSType ), "Windows Server 2012" );
				}
				else
				{
					CopySZ( szOSType, sizeof( szOSType ), "Windows 8" );
				}
			}
			else if ( pInfo->sv101_version_major == 6 && pInfo->sv101_version_minor == 3 )
			{
				if ( bIsServer )
				{
					CopySZ( szOSType, sizeof( szOSType ), "Windows Server 2012 R2" );
				}
				else
				{
					CopySZ( szOSType, sizeof( szOSType ), "Windows 8.1" );
				}
			}
			else if ( pInfo->sv101_version_major == 10 && pInfo->sv101_version_minor == 0 )
			{
				if ( bIsServer )
				{
					CopySZ( szOSType, sizeof( szOSType ), "Windows Server 2016 / Windows Server 2019" );
				}
				else
				{
					CopySZ( szOSType, sizeof( szOSType ), "Windows 10" );
				}
			}
			else
			{
				sprintf( szOSType, "Other (%d.%d)", pInfo->sv101_version_major, pInfo->sv101_version_minor );
			}

			CopySZ( szServerFlags, sizeof( szServerFlags ), "" );

			if ( ( pInfo->sv101_type & SV_TYPE_DIALIN_SERVER ) )
			{
				sprintf( szServerFlags, "%s(RAS Server) ", szServerFlags );
			}

			if ( ( pInfo->sv101_type & SV_TYPE_DFS ) )
			{
				sprintf( szServerFlags, "%s(DFS Server) ", szServerFlags );
			}

			if ( ( pInfo->sv101_type & SV_TYPE_DOMAIN_MASTER ) )
			{
				sprintf( szServerFlags, "%s(Domain Master Browser) ", szServerFlags );
			}

			if ( ( pInfo->sv101_type & SV_TYPE_NOVELL ) )
			{
				sprintf( szServerFlags, "%s(Novell Server) ", szServerFlags );
			}

			if ( ( pInfo->sv101_type & SV_TYPE_PRINTQ_SERVER ) )
			{
				sprintf( szServerFlags, "%s(Print Server) ", szServerFlags );
			}

			if ( ( pInfo->sv101_type & SV_TYPE_SQLSERVER ) )
			{
				sprintf( szServerFlags, "%s(MS SQL Server) ", szServerFlags );
			}

			if ( ( pInfo->sv101_type & SV_TYPE_TERMINALSERVER ) )
			{
				sprintf( szServerFlags, "%s(Terminal Server) ", szServerFlags );
			}

			if ( !bMultipleHosts )
			{
				printf( "\n" );
				printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
				printf( "+++++           SERVER INFORMATION            +++++\n" );
				printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
				printf( "\n" );

				printf( "Server Type:      %s\n", szServerType );
				printf( "Operating System: %s\n", szOSType );
				printf( "Server Comment:   %s\n", szComment );
				printf( "Other Flags:      %s\n", szServerFlags );
				printf( "\n" );

				fflush( stdout );
			}

			if ( bVerboseOptionSelected && bMultipleHosts )
			{
				printf( "%s -> Logging server information.\n", szTarget );

				fflush( stdout );
			}

			WaitForSingleObject( hSemaphore, INFINITE );

			pOutputFile = fopen( "Reports\\ServerInfo.txt", "r" );

			if ( pOutputFile != NULL )
			{
				fclose( pOutputFile );
			}
			else
			{
				pOutputFile = fopen( "Reports\\ServerInfo.txt", "w" );

				if ( pOutputFile != NULL )
				{
					fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
					fprintf( pOutputFile, "\n" );
					fprintf( pOutputFile, "Hostname\tServer Type\tOperating System\tServer Comment\tOther Flags\n" );

					fclose( pOutputFile );
				}
			}

			pOutputFile = fopen( "Reports\\ServerInfo.txt", "a+" );

			if ( pOutputFile != NULL )
			{
				fprintf( pOutputFile, "%s\t%s\t%s\t%s\t%s\n", szTarget, szServerType, szOSType, szComment, szServerFlags );

				fclose( pOutputFile );
			}

			ReleaseSemaphore( hSemaphore, 1, NULL );

			NetApiBufferFree( pInfo );
		}
	}
	else
	{
		dwError = nStatus;

		CopySZ( szFunction, sizeof( szFunction ), "NetServerGetInfo (GetServerInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
	}
}

VOID GetServiceInfo( CHAR szTarget[] )
{
	WCHAR                           wszTarget[ 256 ];
	DWORD                                   i;
	SC_HANDLE                    schSCManager;
	DWORD                       dwBytesNeeded;
	DWORD                  dwServicesReturned;
	DWORD                      dwResumeHandle;
	DWORD                             dwError;
	ENUM_SERVICE_STATUS       *pServiceStatus;
	DWORD                                   j;
	CHAR                        szServiceName[ 128 ];
	CHAR                        szDisplayName[ 128 ];
	CHAR                          szStartType[ 128 ];
	CHAR                            szAccount[ 128 ];
	CHAR                        szDescription[ 1024 ];
	SC_HANDLE                      schService;
	QUERY_SERVICE_CONFIG      *pServiceConfig;
	SERVICE_DESCRIPTION  *pServiceDescription;
	FILE                         *pOutputFile;
	CHAR                           szFunction[ 128 ];

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTarget );

	i = 0;

	schSCManager = NULL;

	schSCManager = OpenSCManager( wszTarget, NULL, SC_MANAGER_ENUMERATE_SERVICE );
 
	if ( schSCManager != NULL )
	{
		dwBytesNeeded      = 0;
		dwServicesReturned = 0;
		dwResumeHandle     = 0;

		EnumServicesStatus( schSCManager, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle );

		dwError = GetLastError();

		if ( dwError == ERROR_MORE_DATA )
		{
			pServiceStatus = NULL;

			pServiceStatus = (ENUM_SERVICE_STATUS *)LocalAlloc( LMEM_FIXED, dwBytesNeeded );

			if ( pServiceStatus != NULL )
			{
				if ( EnumServicesStatus( schSCManager, SERVICE_WIN32, SERVICE_STATE_ALL, pServiceStatus, dwBytesNeeded, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle ) )
				{
					for ( j = 0; j < dwServicesReturned; j++ )
					{
						ConvertWSZtoSZ( szServiceName, sizeof( szServiceName ), pServiceStatus[j].lpServiceName );
						ConvertWSZtoSZ( szDisplayName, sizeof( szDisplayName ), pServiceStatus[j].lpDisplayName );

						CopySZ( szStartType, sizeof( szStartType ), "" );
						CopySZ( szDescription, sizeof( szDescription ), "" );

						schService = NULL;

						schService = OpenService( schSCManager, pServiceStatus[j].lpServiceName, SERVICE_QUERY_CONFIG );

						if ( schService != NULL )
						{
							dwBytesNeeded = 0;

							QueryServiceConfig( schService, NULL, 0, &dwBytesNeeded );

							dwError = GetLastError();

							if ( dwError == ERROR_INSUFFICIENT_BUFFER )
							{
								pServiceConfig = NULL;

								pServiceConfig = (QUERY_SERVICE_CONFIG *)LocalAlloc( LMEM_FIXED, dwBytesNeeded );

								if ( pServiceConfig != NULL )
								{
									if ( QueryServiceConfig( schService, pServiceConfig, dwBytesNeeded, &dwBytesNeeded ) )
									{
										switch ( pServiceConfig->dwStartType )
										{
											case SERVICE_BOOT_START:
												CopySZ( szStartType, sizeof( szStartType ), "Device Driver (Boot Start)" );

												break;

											case SERVICE_SYSTEM_START:
												CopySZ( szStartType, sizeof( szStartType ), "Device Driver (System Start)" );

												break;

											case SERVICE_AUTO_START:
												CopySZ( szStartType, sizeof( szStartType ), "Auto Start" );

												break;

											case SERVICE_DEMAND_START:
												CopySZ( szStartType, sizeof( szStartType ), "Manual Start" );

												break;

											case SERVICE_DISABLED:
												CopySZ( szStartType, sizeof( szStartType ), "Service Disabled" );

												break;
										}

										ConvertWSZtoSZ( szAccount, sizeof( szAccount ), pServiceConfig->lpServiceStartName );

										pServiceDescription = NULL;

										dwBytesNeeded = 0;

										QueryServiceConfig2( schService, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &dwBytesNeeded );

										dwError = GetLastError();

										if ( dwError == ERROR_INSUFFICIENT_BUFFER )
										{
											pServiceDescription = (SERVICE_DESCRIPTION *)LocalAlloc( LMEM_FIXED, dwBytesNeeded );

											if ( pServiceDescription != NULL )
											{
												if ( QueryServiceConfig2( schService, SERVICE_CONFIG_DESCRIPTION, (BYTE *)pServiceDescription, dwBytesNeeded, &dwBytesNeeded ) )
												{
													if ( pServiceDescription->lpDescription != NULL )
													{
														ConvertWSZtoSZ( szDescription, sizeof( szDescription ), pServiceDescription->lpDescription );
													}
												}
												else
												{
													dwError = GetLastError();

													CopySZ( szFunction, sizeof( szFunction ), "QueryServiceConfig2 (GetServiceInfo)" );

													WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
												}
											}
											else
											{
												dwError = GetLastError();

												CopySZ( szFunction, sizeof( szFunction ), "LocalAlloc (GetServiceInfo)" );

												WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
											}
										}
										else
										{
											dwError = GetLastError();

											CopySZ( szFunction, sizeof( szFunction ), "QueryServiceConfig2 (GetServiceInfo)" );

											WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
										}

										if ( !bMultipleHosts )
										{
											if ( i == 0 )
											{
												printf( "\n" );
												printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
												printf( "+++++           SERVICE INFORMATION           +++++\n" );
												printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
												printf( "\n" );

												i++;
											}

											printf( "Service Name: %s\n", szServiceName );
											printf( "Display Name: %s\n", szDisplayName );
											printf( "Start Type:   %s\n", szStartType );
											printf( "Account:      %s\n", szAccount );
											printf( "Description:  %s\n", szDescription );

											printf( "\n" );

											fflush( stdout );
										}

										if ( bVerboseOptionSelected && bMultipleHosts )
										{
											printf( "%s -> Logging service information.\n", szTarget );

											fflush( stdout );
										}

										WaitForSingleObject( hSemaphore, INFINITE );

										pOutputFile = fopen( "Reports\\ServiceInfo.txt", "r" );

										if ( pOutputFile != NULL )
										{
											fclose( pOutputFile );
										}
										else
										{
											pOutputFile = fopen( "Reports\\ServiceInfo.txt", "w" );

											if ( pOutputFile != NULL )
											{
												fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
												fprintf( pOutputFile, "\n" );
												fprintf( pOutputFile, "Hostname\tService Name\tDisplay Name\tStart Type\tAccount\tDescription\n" );

												fclose( pOutputFile );
											}
										}

										pOutputFile = fopen( "Reports\\ServiceInfo.txt", "a+" );

										if ( pOutputFile != NULL )
										{
											fprintf( pOutputFile, "%s\t%s\t%s\t%s\t%s\t%s\n", szTarget, szServiceName, szDisplayName, szStartType, szAccount, szDescription );

											fclose( pOutputFile );
										}

										ReleaseSemaphore( hSemaphore, 1, NULL );

										if ( pServiceDescription != NULL )
										{
											LocalFree( pServiceDescription );
										}
									}
									else
									{
										dwError = GetLastError();

										CopySZ( szFunction, sizeof( szFunction ), "QueryServiceConfig (GetServiceInfo)" );

										WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
									}

									LocalFree( pServiceConfig );
								}
								else
								{
									dwError = GetLastError();

									CopySZ( szFunction, sizeof( szFunction ), "LocalAlloc (GetServiceInfo)" );

									WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
								}
							}
							else
							{
								dwError = GetLastError();

								CopySZ( szFunction, sizeof( szFunction ), "QueryServiceConfig (GetServiceInfo)" );

								WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
							}

							CloseServiceHandle( schService );
						}
						else
						{
							dwError = GetLastError();

							CopySZ( szFunction, sizeof( szFunction ), "OpenService (GetServiceInfo)" );

							WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
						}
					}
				}
				else
				{
					dwError = GetLastError();

					CopySZ( szFunction, sizeof( szFunction ), "EnumServicesStatus (GetServiceInfo)" );

					WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
				}

				LocalFree( pServiceStatus );
			}
			else
			{
				dwError = GetLastError();

				CopySZ( szFunction, sizeof( szFunction ), "LocalAlloc (GetServiceInfo)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
			}
		}
		else
		{
			dwError = GetLastError();

			CopySZ( szFunction, sizeof( szFunction ), "EnumServicesStatus (GetServiceInfo)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}

		CloseServiceHandle( schSCManager );
	}
	else
	{
		dwError = GetLastError();

		CopySZ( szFunction, sizeof( szFunction ), "OpenSCManager (GetServiceInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
	}
}

VOID GetWMIServiceInfo( CHAR szTarget[], IWbemServices *pService, COAUTHIDENTITY *authIdentity, BOOL *bImpersonate )
{
	DWORD                               i;
	CHAR                  szQueryLanguage[ 128 ];
	CHAR                          szQuery[ 128 ];
	WCHAR                wszQueryLanguage[ 256 ];
	WCHAR                        wszQuery[ 256 ];
	BSTR                 bszQueryLanguage;
	BSTR                         bszQuery;
	IEnumWbemClassObject     *pEnumerator;
	HRESULT                       hResult;
	IWbemClassObject             *pObject;
	ULONG                       uReturned;
	CHAR                    szDisplayName[ 128 ];
	CHAR                    szServiceName[ 128 ];
	CHAR                       szPathName[ 1024 ];
	CHAR                      szStartName[ 128 ];
	CHAR                      szStartMode[ 128 ];
	CHAR                          szState[ 128 ];
	CHAR                    szDescription[ 1024 ];
	VARIANT                    vtProperty;
	FILE                     *pOutputFile;
	CHAR                       szFunction[ 128 ];

	i = 0;

	CopySZ( szQueryLanguage, sizeof( szQueryLanguage ), "WQL" );
	CopySZ( szQuery, sizeof( szQuery ), "Select * from Win32_Service" );

	ConvertSZtoWSZ( wszQueryLanguage, sizeof( wszQueryLanguage ), szQueryLanguage );
	ConvertSZtoWSZ( wszQuery, sizeof( wszQuery ), szQuery );

	bszQueryLanguage = SysAllocString( wszQueryLanguage );
	bszQuery         = SysAllocString( wszQuery );

	pEnumerator = NULL;

	hResult = pService->ExecQuery( bszQueryLanguage, bszQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator );

	if ( SUCCEEDED( hResult ) )
	{
		if ( *bImpersonate )
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE );
		}
		else
		{
			hResult = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, authIdentity, EOAC_NONE );
		}

		while ( pEnumerator )
		{
			pObject = NULL;

			hResult = pEnumerator->Next( WBEM_INFINITE, 1, &pObject, &uReturned );

			if ( SUCCEEDED( hResult ) )
			{
				if ( uReturned == 0 )
				{
					break;
				}

				CopySZ( szDisplayName, sizeof( szDisplayName ), "" );
				CopySZ( szServiceName, sizeof( szServiceName ), "" );
				CopySZ( szPathName, sizeof( szPathName ), "" );
				CopySZ( szStartName, sizeof( szStartName ), "" );
				CopySZ( szStartMode, sizeof( szStartMode ), "" );
				CopySZ( szState, sizeof( szState ), "" );
				CopySZ( szDescription, sizeof( szDescription ), "" );

				hResult = pObject->Get( L"DisplayName", 0, &vtProperty, NULL, NULL );

				ConvertWSZtoSZ( szDisplayName, sizeof( szDisplayName ), vtProperty.bstrVal );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"Name", 0, &vtProperty, NULL, NULL );

				ConvertWSZtoSZ( szServiceName, sizeof( szServiceName ), vtProperty.bstrVal );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"PathName", 0, &vtProperty, NULL, NULL );

				ConvertWSZtoSZ( szPathName, sizeof( szPathName ), vtProperty.bstrVal );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"StartName", 0, &vtProperty, NULL, NULL );

				ConvertWSZtoSZ( szStartName, sizeof( szStartName ), vtProperty.bstrVal );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"StartMode", 0, &vtProperty, NULL, NULL );

				ConvertWSZtoSZ( szStartMode, sizeof( szStartMode ), vtProperty.bstrVal );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"State", 0, &vtProperty, NULL, NULL );

				ConvertWSZtoSZ( szState, sizeof( szState ), vtProperty.bstrVal );

				VariantClear( &vtProperty );

				hResult = pObject->Get( L"Description", 0, &vtProperty, NULL, NULL );

				ConvertWSZtoSZ( szDescription, sizeof( szDescription ), vtProperty.bstrVal );

				VariantClear( &vtProperty );

				pObject->Release();

				if ( !bMultipleHosts )
				{
					if ( i == 0 )
					{
						printf( "\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "+++++         WMI SERVICE INFORMATION         +++++\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "\n" );

						i++;
					}

					printf( "Display Name: %s\n", szDisplayName );
					printf( "Service Name: %s\n", szServiceName );
					printf( "File Path:    %s\n", szPathName );
					printf( "Account:      %s\n", szStartName );
					printf( "Start Type:   %s\n", szStartMode );
					printf( "Status:       %s\n", szState );
					printf( "Description:  %s\n", szDescription );

					printf( "\n" );

					fflush( stdout );
				}

				if ( bVerboseOptionSelected && bMultipleHosts )
				{
					printf( "%s -> Logging service information.\n", szTarget );

					fflush( stdout );
				}

				WaitForSingleObject( hSemaphore, INFINITE );

				pOutputFile = fopen( "Reports\\WMIServiceInfo.txt", "r" );

				if ( pOutputFile != NULL )
				{
					fclose( pOutputFile );
				}
				else
				{
					pOutputFile = fopen( "Reports\\WMIServiceInfo.txt", "w" );

					if ( pOutputFile != NULL )
					{
						fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
						fprintf( pOutputFile, "\n" );
						fprintf( pOutputFile, "Hostname\tDisplay Name\tService Name\tFile Path\tAccount\tStart Type\tStatus\tDescription\n" );

						fclose( pOutputFile );
					}
				}

				pOutputFile = fopen( "Reports\\WMIServiceInfo.txt", "a+" );

				if ( pOutputFile != NULL )
				{
					fprintf( pOutputFile, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", szTarget, szDisplayName, szServiceName, szPathName, szStartName, szStartMode, szState, szDescription );

					fclose( pOutputFile );
				}

				ReleaseSemaphore( hSemaphore, 1, NULL );
			}
		}
	}
	else
	{
		CopySZ( szFunction, sizeof( szFunction ), "ExecQuery (GetWMIServiceInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, (DWORD *)&hResult );
	}

	SysFreeString( bszQueryLanguage );
	SysFreeString( bszQuery );
}

VOID GetShareInfo( CHAR szTarget[] )
{
	CHAR             szTempTarget[ 128 ];
	WCHAR               wszTarget[ 256 ];
	DWORD                       i;
	DWORD                 dwLevel;
	DWORD           dwEntriesRead;
	DWORD          dwTotalEntries;
	DWORD          dwResumeHandle;
	SHARE_INFO_1           *pInfo;
	NET_API_STATUS        nStatus;
	SHARE_INFO_1       *pTempInfo;
	DWORD                       j;
	CHAR              szShareName[ 128 ];
	CHAR              szShareType[ 128 ];
	CHAR                 szRemark[ 512 ];
	FILE             *pOutputFile;
	DWORD                 dwError;
	CHAR               szFunction[ 128 ];

	sprintf( szTempTarget, "\\\\%s", szTarget );

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTempTarget );

	i = 0;

	dwLevel        = 1;
	dwEntriesRead  = 0;
	dwTotalEntries = 0;
	dwResumeHandle = 0;

	do
	{
		pInfo = NULL;

		nStatus = NetShareEnum( wszTarget, dwLevel, (PBYTE *)&pInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle );

		if ( nStatus == NERR_Success || nStatus == ERROR_MORE_DATA )
		{
			if ( pInfo != NULL )
			{
				pTempInfo = pInfo;

				for ( j = 0; j < dwEntriesRead; j++ )
				{
					ConvertWSZtoSZ( szShareName, sizeof( szShareName ), pTempInfo->shi1_netname );
					ConvertWSZtoSZ( szRemark, sizeof( szRemark ), pTempInfo->shi1_remark );

					CopySZ( szShareType, sizeof( szShareType ), "" );

					if ( pTempInfo->shi1_type == STYPE_DISKTREE )
					{
						CopySZ( szShareType, sizeof( szShareType ), "Disk drive" );
					}

					if ( pTempInfo->shi1_type == STYPE_PRINTQ )
					{
						CopySZ( szShareType, sizeof( szShareType ), "Print queue" );
					}

					if ( pTempInfo->shi1_type == STYPE_DEVICE )
					{
						CopySZ( szShareType, sizeof( szShareType ), "Communication device" );
					}

					if ( pTempInfo->shi1_type == STYPE_IPC )
					{
						CopySZ( szShareType, sizeof( szShareType ), "Interprocess communication (IPC)" );
					}

					if ( pTempInfo->shi1_type == STYPE_SPECIAL )
					{
						CopySZ( szShareType, sizeof( szShareType ), "Administrative share" );
					}

					if ( !bMultipleHosts )
					{
						if ( i == 0 )
						{
							printf( "\n" );
							printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
							printf( "+++++            SHARE INFORMATION            +++++\n" );
							printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
							printf( "\n" );

							i++;
						}

						printf( "Share Name: %s\n", szShareName );
						printf( "Share Type: %s\n", szShareType );
						printf( "Remark:     %s\n", szRemark );
						printf( "\n" );

						fflush( stdout );
					}

					if ( bVerboseOptionSelected && bMultipleHosts )
					{
						printf( "%s -> Logging share information.\n", szTarget );

						fflush( stdout );
					}

					WaitForSingleObject( hSemaphore, INFINITE );

					pOutputFile = fopen( "Reports\\ShareInfo.txt", "r" );

					if ( pOutputFile != NULL )
					{
						fclose( pOutputFile );
					}
					else
					{
						pOutputFile = fopen( "Reports\\ShareInfo.txt", "w" );

						if ( pOutputFile != NULL )
						{
							fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
							fprintf( pOutputFile, "\n" );
							fprintf( pOutputFile, "Hostname\tShare Name\tShare Type\tRemark\n" );

							fclose( pOutputFile );
						}
					}

					pOutputFile = fopen( "Reports\\ShareInfo.txt", "a+" );

					if ( pOutputFile != NULL )
					{
						fprintf( pOutputFile, "%s\t%s\t%s\t%s\n", szTarget, szShareName, szShareType, szRemark );

						fclose( pOutputFile );
					}

					ReleaseSemaphore( hSemaphore, 1, NULL );

					pTempInfo++;
				}
			}
		}
		else
		{
			dwError = nStatus;

			CopySZ( szFunction, sizeof( szFunction ), "NetShareEnum (GetShareInfo)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}

		if ( pInfo != NULL )
		{
			NetApiBufferFree( pInfo );
		}
	}
	while ( nStatus == ERROR_MORE_DATA );
}

VOID GetSharePermissions( CHAR szTarget[] )
{
	CHAR               szTempTarget[ 128 ];
	WCHAR                 wszTarget[ 256 ];
	DWORD                         i;
	DWORD                   dwLevel;
	DWORD             dwEntriesRead;
	DWORD            dwTotalEntries;
	DWORD            dwResumeHandle;
	SHARE_INFO_2             *pInfo;
	NET_API_STATUS          nStatus;
	SHARE_INFO_2         *pTempInfo;
	DWORD                         j;
	CHAR                szShareName[ 128 ];
	CHAR                szSharePath[ 512 ];
	CHAR            szFullShareName[ 256 ];
	WCHAR          wszFullShareName[ 512 ];
	ACL                      *pDACL;
	DWORD                   lReturn;
	DWORD                         k;
	ACE_HEADER                *pACE;
	CHAR               szAccessType[ 128 ];
	CHAR              szPermissions[ 128 ];
	PSID                       pSID;
	DWORD             dwAccountName;
	DWORD              dwDomainName;
	WCHAR            wszAccountName[ 256 ];
	WCHAR             wszDomainName[ 256 ];
	CHAR              szAccountName[ 128 ];
	CHAR               szDomainName[ 128 ];
	SID_NAME_USE              snUse;
	FILE               *pOutputFile;
	DWORD                   dwError;
	CHAR                 szFunction[ 128 ];

	sprintf( szTempTarget, "\\\\%s", szTarget );

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTempTarget );

	i = 0;

	dwLevel        = 2;
	dwEntriesRead  = 0;
	dwTotalEntries = 0;
	dwResumeHandle = 0;

	do
	{
		pInfo = NULL;

		nStatus = NetShareEnum( wszTarget, dwLevel, (PBYTE *)&pInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle );

		if ( nStatus == NERR_Success || nStatus == ERROR_MORE_DATA )
		{
			if ( pInfo != NULL )
			{
				pTempInfo = pInfo;

				for ( j = 0; j < dwEntriesRead; j++ )
				{
					if ( pTempInfo->shi2_type == STYPE_DISKTREE || pTempInfo->shi2_type == STYPE_SPECIAL )
					{
						ConvertWSZtoSZ( szShareName, sizeof( szShareName ), pTempInfo->shi2_netname );
						ConvertWSZtoSZ( szSharePath, sizeof( szSharePath ), pTempInfo->shi2_path );

						sprintf( szFullShareName, "\\\\%s\\%s", szTarget, szShareName );

						ConvertSZtoWSZ( wszFullShareName, sizeof( wszFullShareName ), szFullShareName );

						pDACL = NULL;

						lReturn = GetNamedSecurityInfo( wszFullShareName, SE_LMSHARE, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, NULL );

						if ( lReturn == ERROR_SUCCESS )
						{
							if ( pDACL != NULL )
							{
								if ( !bMultipleHosts )
								{
									if ( i == 0 )
									{
										printf( "\n" );
										printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
										printf( "+++++            SHARE PERMISSIONS            +++++\n" );
										printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
										printf( "\n" );

										i++;
									}

									printf( "Share Name:        %s\n", szShareName );
									printf( "Share Path:        %s\n", szSharePath );

									fflush( stdout );
								}

								if ( bVerboseOptionSelected && bMultipleHosts )
								{
									printf( "%s -> Logging share permissions.\n", szTarget );

									fflush( stdout );
								}

								for ( k = 0; k < pDACL->AceCount; k++ )
								{
									if ( GetAce( pDACL, k, (PVOID *)&pACE ) )
									{
										CopySZ( szAccessType, sizeof( szAccessType ), "" );
										CopySZ( szPermissions, sizeof( szPermissions ), "" );

										pSID = NULL;

										if ( pACE->AceType == ACCESS_ALLOWED_ACE_TYPE )
										{
											CopySZ( szAccessType, sizeof( szAccessType ), "Allow" );

											if ( ( (ACCESS_ALLOWED_ACE *)pACE )->Mask & FILE_SHARE_READ )
											{
												sprintf( szPermissions, "%sR", szPermissions );
											}

											if ( ( (ACCESS_ALLOWED_ACE *)pACE )->Mask & FILE_SHARE_WRITE )
											{
												sprintf( szPermissions, "%sW", szPermissions );
											}

											if ( ( (ACCESS_ALLOWED_ACE *)pACE )->Mask & FILE_SHARE_DELETE )
											{
												sprintf( szPermissions, "%sD", szPermissions );
											}

											pSID = &( (ACCESS_ALLOWED_ACE *)pACE )->SidStart;
										}

										if ( pACE->AceType == ACCESS_DENIED_ACE_TYPE )
										{
											CopySZ( szAccessType, sizeof( szAccessType ), "Deny" );

											if ( ( (ACCESS_DENIED_ACE *)pACE )->Mask & FILE_SHARE_READ )
											{
												sprintf( szPermissions, "%sR", szPermissions );
											}

											if ( ( (ACCESS_DENIED_ACE *)pACE )->Mask & FILE_SHARE_WRITE )
											{
												sprintf( szPermissions, "%sW", szPermissions );
											}

											if ( ( (ACCESS_DENIED_ACE *)pACE )->Mask & FILE_SHARE_DELETE )
											{
												sprintf( szPermissions, "%sD", szPermissions );
											}

											pSID = &( (ACCESS_DENIED_ACE *)pACE )->SidStart;
										}		

										dwAccountName = sizeof( wszAccountName );
										dwDomainName  = sizeof( wszDomainName );

										if ( LookupAccountSid( wszTarget, pSID, wszAccountName, &dwAccountName, wszDomainName, &dwDomainName, &snUse ) )
										{
											ConvertWSZtoSZ( szAccountName, sizeof( szAccountName ), wszAccountName );
											ConvertWSZtoSZ( szDomainName, sizeof( szDomainName ), wszDomainName );

											if ( strcmp( szAccessType, "" ) == 0 )
											{
												CopySZ( szAccessType, sizeof( szAccessType ), "Other" );
											}

											if ( strcmp( szPermissions, "" ) == 0 )
											{
												CopySZ( szPermissions, sizeof( szPermissions ), "Other (Not R,W or D)" );
											}

											if ( !bMultipleHosts )
											{
												printf( "Account Name:      %s\\%s\n", szDomainName, szAccountName );
												printf( "Access Type:       %s\n", szAccessType );
												printf( "Share Permissions: %s\n", szPermissions );

												fflush( stdout );
											}

											if ( bVerboseOptionSelected && bMultipleHosts )
											{
												printf( "%s -> Logging share permissions.\n", szTarget );

												fflush( stdout );
											}

											WaitForSingleObject( hSemaphore, INFINITE );

											pOutputFile = fopen( "Reports\\SharePermissions.txt", "r" );

											if ( pOutputFile != NULL )
											{
												fclose( pOutputFile );
											}
											else
											{
												pOutputFile = fopen( "Reports\\SharePermissions.txt", "w" );

												if ( pOutputFile != NULL )
												{
													fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
													fprintf( pOutputFile, "\n" );
													fprintf( pOutputFile, "Hostname\tShare Name\tShare Path\tPermission Type\tAccount Name\tAccess Type\tPermissions\n" );

													fclose( pOutputFile );
												}
											}

											pOutputFile = fopen( "Reports\\SharePermissions.txt", "a+" );

											if ( pOutputFile != NULL )
											{
												fprintf( pOutputFile, "%s\t%s\t%s\tShare\t%s\\%s\t%s\t%s\n", szTarget, szShareName, szSharePath, szDomainName, szAccountName, szAccessType, szPermissions );

												fclose( pOutputFile );
											}

											ReleaseSemaphore( hSemaphore, 1, NULL );
										}
									}
									else
									{
										dwError = GetLastError();

										CopySZ( szFunction, sizeof( szFunction ), "GetAce (GetSharePermissions)" );

										WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
									}
								}
							}
						}
						else
						{
							dwError = lReturn;

							CopySZ( szFunction, sizeof( szFunction ), "GetNamedSecurityInfo (GetSharePermissions)" );

							WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
						}

						pDACL = NULL;

						lReturn = GetNamedSecurityInfo( wszFullShareName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, NULL );

						if ( lReturn == ERROR_SUCCESS )
						{
							if ( pDACL != NULL )
							{
								if ( !bMultipleHosts )
								{
									if ( i == 0 )
									{
										printf( "\n" );
										printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
										printf( "+++++            SHARE PERMISSIONS            +++++\n" );
										printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
										printf( "\n" );

										i++;
									}

									printf( "Share Name:        %s\n", szShareName );
									printf( "Share Path:        %s\n", szSharePath );

									fflush( stdout );
								}

								for ( k = 0; k < pDACL->AceCount; k++ )
								{
									if ( GetAce( pDACL, k, (PVOID *)&pACE ) )
									{
										CopySZ( szAccessType, sizeof( szAccessType ),  "" );
										CopySZ( szPermissions, sizeof( szPermissions ), "" );

										pSID = NULL;

										if ( pACE->AceType == ACCESS_ALLOWED_ACE_TYPE )
										{
											CopySZ( szAccessType, sizeof( szAccessType ), "Allow" );

											if ( ( (ACCESS_ALLOWED_ACE *)pACE )->Mask & FILE_GENERIC_READ )
											{
												sprintf( szPermissions, "%sR", szPermissions );
											}

											if ( ( (ACCESS_ALLOWED_ACE *)pACE )->Mask & FILE_GENERIC_WRITE )
											{
												sprintf( szPermissions, "%sW", szPermissions );
											}

											if ( ( (ACCESS_ALLOWED_ACE *)pACE )->Mask & FILE_GENERIC_EXECUTE )
											{
												sprintf( szPermissions, "%sX", szPermissions );
											}

											if ( ( (ACCESS_ALLOWED_ACE *)pACE )->Mask & DELETE )
											{
												sprintf( szPermissions, "%sD", szPermissions );
											}

											pSID = &( (ACCESS_ALLOWED_ACE *)pACE )->SidStart;
										}

										if ( pACE->AceType == ACCESS_DENIED_ACE_TYPE )
										{
											CopySZ( szAccessType, sizeof( szAccessType ), "Deny" );

											if ( ( (ACCESS_DENIED_ACE *)pACE )->Mask & FILE_GENERIC_READ )
											{
												sprintf( szPermissions, "%sR", szPermissions );
											}

											if ( ( (ACCESS_DENIED_ACE *)pACE )->Mask & FILE_GENERIC_WRITE )
											{
												sprintf( szPermissions, "%sW", szPermissions );
											}

											if ( ( (ACCESS_DENIED_ACE *)pACE )->Mask & FILE_GENERIC_EXECUTE )
											{
												sprintf( szPermissions, "%sX", szPermissions );
											}

											if ( ( (ACCESS_DENIED_ACE *)pACE )->Mask & DELETE )
											{
												sprintf( szPermissions, "%sD", szPermissions );
											}

											pSID = &( (ACCESS_DENIED_ACE *)pACE )->SidStart;
										}

										dwAccountName = sizeof( wszAccountName );
										dwDomainName  = sizeof( wszDomainName );

										if ( LookupAccountSid( wszTarget, pSID, wszAccountName, &dwAccountName, wszDomainName, &dwDomainName, &snUse ) )
										{
											ConvertWSZtoSZ( szAccountName, sizeof( szAccountName ), wszAccountName );
											ConvertWSZtoSZ( szDomainName, sizeof( szDomainName ), wszDomainName );

											if ( strcmp( szAccessType, "" ) == 0 )
											{
												CopySZ( szAccessType, sizeof( szAccessType ), "Other" );
											}

											if ( strcmp( szPermissions, "" ) == 0 )
											{
												CopySZ( szPermissions, sizeof( szPermissions ), "Other (Not R,W,X or D)" );
											}

											if ( !bMultipleHosts )
											{
												printf( "Account Name:      %s\\%s\n", szDomainName, szAccountName );
												printf( "Access Type:       %s\n", szAccessType );
												printf( "NTFS Permissions:  %s\n", szPermissions );

												fflush( stdout );
											}

											if ( bVerboseOptionSelected && bMultipleHosts )
											{
												printf( "%s -> Logging share permissions.\n", szTarget );

												fflush( stdout );
											}

											WaitForSingleObject( hSemaphore, INFINITE );

											pOutputFile = fopen( "Reports\\SharePermissions.txt", "r" );

											if ( pOutputFile != NULL )
											{
												fclose( pOutputFile );
											}
											else
											{
												pOutputFile = fopen( "Reports\\SharePermissions.txt", "w" );

												if ( pOutputFile != NULL )
												{
													fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
													fprintf( pOutputFile, "\n" );
													fprintf( pOutputFile, "Hostname\tShare Name\tShare Path\tPermission Type\tAccount Name\tAccess Type\tPermissions\n" );

													fclose( pOutputFile );
												}
											}

											pOutputFile = fopen( "Reports\\SharePermissions.txt", "a+" );

											if ( pOutputFile != NULL )
											{
												fprintf( pOutputFile, "%s\t%s\t%s\tNTFS\t%s\\%s\t%s\t%s\n", szTarget, szShareName, szSharePath, szDomainName, szAccountName, szAccessType, szPermissions );

												fclose( pOutputFile );
											}

											ReleaseSemaphore( hSemaphore, 1, NULL );
										}
									}
									else
									{
										dwError = GetLastError();

										CopySZ( szFunction, sizeof( szFunction ), "GetAce (GetSharePermissions)" );

										WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
									}
								}
							}
						}
						else
						{
							dwError = lReturn;

							CopySZ( szFunction, sizeof( szFunction ), "GetNamedSecurityInfo (GetSharePermissions)" );

							WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
						}

						if ( !bMultipleHosts )
						{
							printf( "\n" );

							fflush( stdout );
						}
					}

					pTempInfo++;
				}
			}
		}
		else
		{
			dwError = nStatus;

			CopySZ( szFunction, sizeof( szFunction ), "NetShareEnum (GetSharePermissions)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}

		if ( pInfo != NULL )
		{
			NetApiBufferFree( pInfo );
		}
	}
	while ( nStatus == ERROR_MORE_DATA );
}

VOID GetUserInfo( CHAR szTarget[] )
{
	CHAR             szTempTarget[ 128 ];
	WCHAR               wszTarget[ 256 ];
	CHAR              szCacheFile[ 128 ];
	DWORD                       i;
	DWORD                       j;
	DWORD                dwLevel3;
	DWORD           dwEntriesRead;
	DWORD          dwTotalEntries;
	DWORD          dwResumeHandle;
	USER_INFO_3            *pInfo;
	NET_API_STATUS        nStatus;
	USER_INFO_3        *pTempInfo;
	DWORD                       k;
	CHAR               szUsername[ 128 ];
	CHAR                szHomeDir[ 128 ];
	CHAR                szComment[ 512 ];
	CHAR             szScriptPath[ 512 ];
	CHAR               szFullName[ 128 ];
	CHAR           szWorkstations[ 128 ];
	CHAR            szLogonServer[ 128 ];
	CHAR                szProfile[ 128 ];
	CHAR           szHomeDirDrive[ 128 ];
	CHAR               *pLocation;
	DWORD                dwTmpAge;
	DWORD                  dwDays;
	DWORD                 dwHours;
	DWORD               dwMinutes;
	DWORD               dwSeconds;
	CHAR            szPasswordAge[ 128 ];
	CHAR             szPrivileges[ 128 ];
	CHAR                  szFlags[ 128 ];
	CHAR              szLastLogon[ 128 ];
	CHAR             szAcctExpiry[ 128 ];
	CHAR           szPasswdExpiry[ 128 ];
	FILE             *pOutputFile;
	FILE              *pCacheFile;
	DWORD                 dwError;
	CHAR               szFunction[ 128 ];

	struct tm *pTime;

	sprintf( szTempTarget, "\\\\%s", szTarget );

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTempTarget );

	sprintf( szCacheFile, "UserCache\\%s.users", szTarget );

	i = 0;
	j = 0;

	dwLevel3       = 3;
	dwEntriesRead  = 0;
	dwTotalEntries = 0;
	dwResumeHandle = 0;

	do
	{
		pInfo = NULL;

		nStatus = NetUserEnum( wszTarget, dwLevel3, FILTER_NORMAL_ACCOUNT, (PBYTE *)&pInfo, 4096, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle );

		if ( nStatus == NERR_Success || nStatus == ERROR_MORE_DATA )
		{
			if ( pInfo != NULL )
			{
				pTempInfo = pInfo;

				for ( k = 0; k < dwEntriesRead; k++ )
				{
					ConvertWSZtoSZ( szUsername, sizeof( szUsername ), pTempInfo->usri3_name );
					ConvertWSZtoSZ( szHomeDir, sizeof( szHomeDir ), pTempInfo->usri3_home_dir );
					ConvertWSZtoSZ( szComment, sizeof( szComment ), pTempInfo->usri3_comment );
					ConvertWSZtoSZ( szScriptPath, sizeof( szScriptPath ), pTempInfo->usri3_script_path );
					ConvertWSZtoSZ( szFullName, sizeof( szFullName ), pTempInfo->usri3_full_name );
					ConvertWSZtoSZ( szWorkstations, sizeof( szWorkstations ), pTempInfo->usri3_workstations );
					ConvertWSZtoSZ( szLogonServer, sizeof( szLogonServer ), pTempInfo->usri3_logon_server );
					ConvertWSZtoSZ( szProfile, sizeof( szProfile ), pTempInfo->usri3_profile );
					ConvertWSZtoSZ( szHomeDirDrive, sizeof( szHomeDirDrive ), pTempInfo->usri3_home_dir_drive );

					pLocation = strchr( szComment, '\r' );

					if ( pLocation != NULL )
					{
						*pLocation = '\0';
					}

					pLocation = strchr( szComment, '\n' );

					if ( pLocation != NULL )
					{
						*pLocation = '\0';
					}

					dwTmpAge = pTempInfo->usri3_password_age;

					dwDays    = dwTmpAge / 86400;
					dwTmpAge  = dwTmpAge % 86400;
					dwHours   = dwTmpAge / 3600;
					dwTmpAge  = dwTmpAge % 3600;
					dwMinutes = dwTmpAge / 60;
					dwTmpAge  = dwTmpAge % 60;
					dwSeconds = dwTmpAge;

					sprintf( szPasswordAge, "%dd %dh %dm %ds", dwDays, dwHours, dwMinutes, dwSeconds );

					CopySZ( szPrivileges, sizeof( szPrivileges ), "" );

					if ( pTempInfo->usri3_priv == USER_PRIV_GUEST )
					{
						CopySZ( szPrivileges, sizeof( szPrivileges ), "Guest user" );
					}

					if ( pTempInfo->usri3_priv == USER_PRIV_USER )
					{
						CopySZ( szPrivileges, sizeof( szPrivileges ), "Normal user" );
					}

					if ( pTempInfo->usri3_priv == USER_PRIV_ADMIN )
					{
						CopySZ( szPrivileges, sizeof( szPrivileges ), "Administrative user" );
					}

					CopySZ( szFlags, sizeof( szFlags ), "" );

					if ( pTempInfo->usri3_flags & UF_LOCKOUT )
					{
						sprintf( szFlags, "%s(Locked out) ", szFlags );
					}

					if ( pTempInfo->usri3_flags & UF_ACCOUNTDISABLE )
					{
						sprintf( szFlags, "%s(Disabled) ", szFlags );
					}

					if ( pTempInfo->usri3_flags & UF_DONT_EXPIRE_PASSWD )
					{
						sprintf( szFlags, "%s(Password never expires) ", szFlags );
					}

					CopySZ( szLastLogon, sizeof( szLastLogon ), "" );

					if ( pTempInfo->usri3_last_logon == 0 )
					{
						CopySZ( szLastLogon, sizeof( szLastLogon ), "Account has never logged on" );
					}
					else
					{
						pTime = localtime( (CONST time_t *)&pTempInfo->usri3_last_logon );

						if ( pTime != NULL )
						{
							CopySZ( szLastLogon, sizeof( szLastLogon ), asctime( pTime ) );

							pLocation = strchr( szLastLogon, '\n' );

							if ( pLocation != NULL )
							{
								*pLocation = '\0';
							}
						}
						else
						{
							CopySZ( szLastLogon, sizeof( szLastLogon ), "" );
						}
					}

					CopySZ( szAcctExpiry, sizeof( szAcctExpiry ), "" );

					if ( pTempInfo->usri3_acct_expires == TIMEQ_FOREVER )
					{
						CopySZ( szAcctExpiry, sizeof( szAcctExpiry ), "Account never expires" );
					}
					else
					{
						pTime = localtime( (CONST time_t *)&pTempInfo->usri3_acct_expires );

						if ( pTime != NULL )
						{
							CopySZ( szAcctExpiry, sizeof( szAcctExpiry ), asctime( pTime ) );

							pLocation = strchr( szAcctExpiry, '\n' );

							if ( pLocation != NULL )
							{
								*pLocation = '\0';
							}
						}
						else
						{
							CopySZ( szAcctExpiry, sizeof( szAcctExpiry ), "" );
						}
					}

					CopySZ( szPasswdExpiry, sizeof( szPasswdExpiry ), "" );

					if ( pTempInfo->usri3_password_expired == 0 )
					{
						CopySZ( szPasswdExpiry, sizeof( szPasswdExpiry ), "Password has not expired" );
					}
					else
					{
						CopySZ( szPasswdExpiry, sizeof( szPasswdExpiry ), "Password expired" );
					}

					if ( !bMultipleHosts )
					{
						if ( i == 0 )
						{
							printf( "\n" );
							printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
							printf( "+++++            USER INFORMATION             +++++\n" );
							printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
							printf( "\n" );

							i++;
						}

						printf( "Username:           %s\n", szUsername );
						printf( "Full Name:          %s\n", szFullName );
						printf( "Comment:            %s\n", szComment );
						printf( "Privileges:         %s\n", szPrivileges );
						printf( "Flags:              %s\n", szFlags );
						printf( "Password Age:       %s\n", szPasswordAge );
						printf( "Bad Password Count: %d\n", pTempInfo->usri3_bad_pw_count );
						printf( "Number of Logons:   %d\n", pTempInfo->usri3_num_logons );
						printf( "Last Logon:         %s\n", szLastLogon );
						printf( "Logon Server:       %s\n", szLogonServer );
						printf( "Home Dir:           %s\n", szHomeDir );
						printf( "Home Dir Drive:     %s\n", szHomeDirDrive );
						printf( "Script Path:        %s\n", szScriptPath );
						printf( "Profile:            %s\n", szProfile );
						printf( "Workstations:       %s\n", szWorkstations );
						printf( "User ID:            %d\n", pTempInfo->usri3_user_id );
						printf( "Primary Group ID:   %d\n", pTempInfo->usri3_primary_group_id );
						printf( "Account Expiry:     %s\n", szAcctExpiry );
						printf( "Password Expiry:    %s\n", szPasswdExpiry );
						printf( "\n" );

						fflush( stdout );
					}

					if ( bVerboseOptionSelected && bMultipleHosts )
					{
						printf( "%s -> Logging user information.\n", szTarget );

						fflush( stdout );
					}

					WaitForSingleObject( hSemaphore, INFINITE );

					pOutputFile = fopen( "Reports\\UserInfo.txt", "r" );

					if ( pOutputFile != NULL )
					{
						fclose( pOutputFile );
					}
					else
					{
						pOutputFile = fopen( "Reports\\UserInfo.txt", "w" );

						if ( pOutputFile != NULL )
						{
							fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
							fprintf( pOutputFile, "\n" );
							fprintf( pOutputFile, "Hostname\tUsername\tFull Name\tComment\tPrivileges\tFlags\tPassword Age\tBad Password Count\tNumber of Logons\tLast Logon\tLogon Server\tHome Dir\tHome Dir Drive\tScript Path\tProfile\tWorkstations\tUser ID\tPrimary Group ID\tAccount Expiry\tPassword Expiry\n" );

							fclose( pOutputFile );
						}
					}

					pOutputFile = fopen( "Reports\\UserInfo.txt", "a+" );

					if ( pOutputFile != NULL )
					{
						fprintf( pOutputFile, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n", szTarget, szUsername, szFullName, szComment, szPrivileges, szFlags, szPasswordAge, pTempInfo->usri3_bad_pw_count, pTempInfo->usri3_num_logons, szLastLogon, szLogonServer, szHomeDir, szHomeDirDrive, szScriptPath, szProfile, szWorkstations, pTempInfo->usri3_user_id, pTempInfo->usri3_primary_group_id, szAcctExpiry, szPasswdExpiry );

						fclose( pOutputFile );
					}

					if ( j == 0 )
					{
						pCacheFile = fopen( szCacheFile, "w" );

						if ( pCacheFile != NULL )
						{
							fclose( pCacheFile );
						}

						j++;
					}

					pCacheFile = fopen( szCacheFile, "a+" );

					if ( pCacheFile != NULL )
					{
						fprintf( pCacheFile, "%s\n", szUsername);

						fclose( pCacheFile );
					}

					ReleaseSemaphore( hSemaphore, 1, NULL );

					pTempInfo++;
				}
			}
		}
		else
		{
			dwError = nStatus;

			CopySZ( szFunction, sizeof( szFunction ), "NetUserEnum (GetUserInfo)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}

		if ( pInfo != NULL )
		{
			NetApiBufferFree( pInfo );
		}
	}
	while ( nStatus == ERROR_MORE_DATA );
}

VOID GetRAUserInfo( CHAR szTarget[] )
{
	CHAR    szCacheFile[ 128 ];
	DWORD             i;
	DWORD             j;
	CHAR   szMachineSID[ 128 ];
	CHAR      szUserSID[ 128 ];
	CHAR   szDomainName[ 128 ];
	CHAR  szAccountName[ 128 ];
	DWORD             k;
	FILE   *pOutputFile;
	FILE    *pCacheFile;
	DWORD       dwError;
	CHAR     szFunction[ 128 ];

	sprintf( szCacheFile, "UserCache\\%s.users", szTarget );

	i = 0;
	j = 0;

	if ( GetMachineSID( szTarget, szMachineSID ) )
	{
		for ( k = 500; k < 502; k++ )
		{
			sprintf( szUserSID, "%s-%d", szMachineSID, k );

			CopySZ( szDomainName, sizeof( szDomainName ), "" );
			CopySZ( szAccountName, sizeof( szAccountName ), "" );

			if ( GetAccountNameFromSID( szTarget, szUserSID, szDomainName, sizeof( szDomainName ), szAccountName, sizeof( szAccountName ) ) )
			{
				if ( !bMultipleHosts )
				{
					if ( i == 0 )
					{
						printf( "\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "+++++     USER INFORMATION VIA RA BYPASS      +++++\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "\n" );

						i++;
					}

					printf( "Username: %s\\%s\n", szDomainName, szAccountName );
					printf( "User ID:  %d\n", k );
					printf( "\n" );

					fflush( stdout );
				}

				if ( bVerboseOptionSelected && bMultipleHosts )
				{
					printf( "%s -> Logging user information.\n", szTarget );

					fflush( stdout );
				}

				WaitForSingleObject( hSemaphore, INFINITE );

				pOutputFile = fopen( "Reports\\RAUserInfo.txt", "r" );

				if ( pOutputFile != NULL )
				{
					fclose( pOutputFile );
				}
				else
				{
					pOutputFile = fopen( "Reports\\RAUserInfo.txt", "w" );

					if ( pOutputFile != NULL )
					{
						fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
						fprintf( pOutputFile, "\n" );
						fprintf( pOutputFile, "Hostname\tUsername\tUser ID\n" );

						fclose( pOutputFile );
					}
				}

				pOutputFile = fopen( "Reports\\RAUserInfo.txt", "a+" );

				if ( pOutputFile != NULL )
				{
					fprintf( pOutputFile, "%s\t%s\\%s\t%d\n", szTarget, szDomainName, szAccountName, k );

					fclose( pOutputFile );
				}

				if ( j == 0 )
				{
					pCacheFile = fopen( szCacheFile, "r" );

					if ( pCacheFile != NULL )
					{
						fclose( pCacheFile );
					}
					else
					{
						pCacheFile = fopen( szCacheFile, "w" );

						if ( pCacheFile != NULL )
						{
							fclose( pCacheFile );
						}

						j++;
					}
				}

				if ( j > 0 )
				{
					pCacheFile = fopen( szCacheFile, "a+" );

					if ( pCacheFile != NULL )
					{
						fprintf( pCacheFile, "%s\n", szAccountName );

						fclose( pCacheFile );
					}
				}

				ReleaseSemaphore( hSemaphore, 1, NULL );
			}
			else
			{
				dwError = GetLastError();

				CopySZ( szFunction, sizeof( szFunction ), "ConvertStringSidToSid (LookupAccountSid)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );

				break;
			}
		}

		for ( k = 1000; k < 2000; k++ )
		{
			sprintf( szUserSID, "%s-%d", szMachineSID, k );

			CopySZ( szDomainName, sizeof( szDomainName ), "" );
			CopySZ( szAccountName, sizeof( szAccountName ), "" );

			if ( GetAccountNameFromSID( szTarget, szUserSID, szDomainName, sizeof( szDomainName ), szAccountName, sizeof( szAccountName ) ) )
			{
				if ( !bMultipleHosts )
				{
					if ( i == 0 )
					{
						printf( "\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "+++++     USER INFORMATION VIA RA BYPASS      +++++\n" );
						printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
						printf( "\n" );

						i++;
					}

					printf( "Username: %s\\%s\n", szDomainName, szAccountName );
					printf( "User ID:  %d\n", k );
					printf( "\n" );

					fflush( stdout );
				}

				if ( bVerboseOptionSelected && bMultipleHosts )
				{
					printf( "%s -> Logging user information.\n", szTarget );

					fflush( stdout );
				}

				WaitForSingleObject( hSemaphore, INFINITE );

				pOutputFile = fopen( "Reports\\RAUserInfo.txt", "r" );

				if ( pOutputFile != NULL )
				{
					fclose( pOutputFile );
				}
				else
				{
					pOutputFile = fopen( "Reports\\RAUserInfo.txt", "w" );

					if ( pOutputFile != NULL )
					{
						fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
						fprintf( pOutputFile, "\n" );
						fprintf( pOutputFile, "Hostname\tUsername\tUser ID\n" );

						fclose( pOutputFile );
					}
				}

				pOutputFile = fopen( "Reports\\RAUserInfo.txt", "a+" );

				if ( pOutputFile != NULL )
				{
					fprintf( pOutputFile, "%s\t%s\\%s\t%d\n", szTarget, szDomainName, szAccountName, k );

					fclose( pOutputFile );
				}

				if ( j == 0 )
				{
					pCacheFile = fopen( szCacheFile, "r" );

					if ( pCacheFile != NULL )
					{
						fclose( pCacheFile );
					}
					else
					{
						pCacheFile = fopen( szCacheFile, "w" );

						if ( pCacheFile != NULL )
						{
							fclose( pCacheFile );
						}

						j++;
					}
				}

				if ( j > 0 )
				{
					pCacheFile = fopen( szCacheFile, "a+" );

					if ( pCacheFile != NULL )
					{
						fprintf( pCacheFile, "%s\n", szAccountName );

						fclose( pCacheFile );
					}
				}

				ReleaseSemaphore( hSemaphore, 1, NULL );
			}
		}
	}

}

BOOL GetMachineSID( CHAR szTarget[], CHAR szMachineSID[] )
{
	BOOL                                bReturn;
	WCHAR                             wszTarget[ 256 ];
	LSA_UNICODE_STRING            lusSystemName;
	LSA_OBJECT_ATTRIBUTES         loaAttributes;
	NTSTATUS                           ntStatus;
	LSA_HANDLE                 lsahPolicyHandle;
	POLICY_ACCOUNT_DOMAIN_INFO           *pInfo;
	WCHAR                           *pStringSID;
	DWORD                               dwError;
	CHAR                             szFunction[ 128 ];

	bReturn = FALSE;

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTarget );

	lusSystemName.Buffer        = wszTarget;
	lusSystemName.Length        = (USHORT)( wcslen( wszTarget ) * sizeof( WCHAR ) );
	lusSystemName.MaximumLength = (USHORT)( ( wcslen( wszTarget ) + 1 ) * sizeof( WCHAR ) );

	ZeroMemory( &loaAttributes, sizeof( loaAttributes ) );

	ntStatus = LsaOpenPolicy( &lusSystemName, &loaAttributes, POLICY_VIEW_LOCAL_INFORMATION, &lsahPolicyHandle );

	if ( ntStatus == 0 )
	{
		pInfo = NULL;

		ntStatus = LsaQueryInformationPolicy( lsahPolicyHandle, PolicyAccountDomainInformation, (PVOID *)&pInfo );

		if ( ntStatus == 0 )
		{
			if ( ConvertSidToStringSid( pInfo->DomainSid, &pStringSID ) )
			{
				ConvertWSZtoSZ( szMachineSID, 128, pStringSID );

				LocalFree( pStringSID );

				bReturn = TRUE;
			}
			else
			{
				dwError = GetLastError();

				CopySZ( szFunction, sizeof( szFunction ), "ConvertSidToStringSid (GetMachineSID)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
			}

			LsaFreeMemory( pInfo );
		}
		else
		{
			dwError = LsaNtStatusToWinError( ntStatus );

			CopySZ( szFunction, sizeof( szFunction ), "LsaQueryInformationPolicy (GetMachineSID)" );

			WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
		}

		LsaClose( lsahPolicyHandle );
	}
	else
	{
		dwError = LsaNtStatusToWinError( ntStatus );

		CopySZ( szFunction, sizeof( szFunction ), "LsaOpenPolicy (GetMachineSID)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
	}

	return bReturn;
}

BOOL GetAccountNameFromSID( CHAR szTarget[], CHAR szStringSID[], CHAR szDomainName[], size_t siDomainName, CHAR szAccountName[], size_t siAccountName )
{
	BOOL                   bReturn;
	WCHAR                wszTarget[ 256 ];
	WCHAR             wszStringSID[ 256 ];
	PSID                      pSID;
	DWORD            dwAccountName;
	DWORD             dwDomainName;
	WCHAR           wszAccountName[ 256 ];
	WCHAR            wszDomainName[ 256 ];
	SID_NAME_USE             snUse;
	DWORD                  dwError;
	CHAR                szFunction[ 128 ];

	bReturn = FALSE;

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTarget );
	ConvertSZtoWSZ( wszStringSID, sizeof( wszStringSID ), szStringSID );

	pSID = NULL;

	if ( ConvertStringSidToSid( wszStringSID, &pSID ) )
	{
		dwAccountName = sizeof( wszAccountName );
		dwDomainName  = sizeof( wszDomainName );

		if ( LookupAccountSid( wszTarget, pSID, wszAccountName, &dwAccountName, wszDomainName, &dwDomainName, &snUse ) )
		{
			ConvertWSZtoSZ( szAccountName, siAccountName, wszAccountName );
			ConvertWSZtoSZ( szDomainName, siDomainName, wszDomainName );

			bReturn = TRUE;
		}

		LocalFree( pSID );
	}
	else
	{
		dwError = GetLastError();

		CopySZ( szFunction, sizeof( szFunction ), "ConvertStringSidToSid (GetAccountNameFromSID)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
	}

	return bReturn;
}

VOID GetUserRightsInfo( CHAR szTarget[] )
{
	WCHAR                        wszTarget[ 256 ];
	DWORD                                i;
	LSA_UNICODE_STRING       lusSystemName;
	LSA_OBJECT_ATTRIBUTES    loaAttributes;
	NTSTATUS                      ntStatus;
	LSA_HANDLE            lsahPolicyHandle;
	DWORD                                j;
	CHAR                       szUserRight[ 64 ];
	WCHAR                     wszUserRight[ 256 ];
	LSA_UNICODE_STRING        lusUserRight;
	VOID                            *pInfo;
	DWORD                          dwCount;
	DWORD                                k;
	PSID                            *pSIDs;
	WCHAR                   wszAccountName[ 256 ];
	WCHAR                    wszDomainName[ 256 ];
	DWORD                    dwAccountName;
	DWORD                     dwDomainName;
	SID_NAME_USE                     snUse;
	CHAR                     szAccountName[ 128 ];
	CHAR                      szDomainName[ 128 ];
	FILE                      *pOutputFile;
	DWORD                          dwError;
	CHAR                        szFunction[ 128 ];

	ConvertSZtoWSZ( wszTarget, sizeof( wszTarget ), szTarget );

	i = 0;

	lusSystemName.Buffer        = wszTarget;
	lusSystemName.Length        = (USHORT)( wcslen( wszTarget ) * sizeof( WCHAR ) );
	lusSystemName.MaximumLength = (USHORT)( ( wcslen( wszTarget ) + 1 ) * sizeof( WCHAR ) );

	ZeroMemory( &loaAttributes, sizeof( loaAttributes ) );

	ntStatus = LsaOpenPolicy( &lusSystemName, &loaAttributes, POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES, &lsahPolicyHandle );

	if ( ntStatus == 0 )
	{
		for ( j = 0; j < 6; j++ )
		{
			if ( j == 0 )
			{
				CopySZ( szUserRight, sizeof( szUserRight ), "SeInteractiveLogonRight" );
			}

			if ( j == 1 )
			{
				CopySZ( szUserRight, sizeof( szUserRight ), "SeNetworkLogonRight" );
			}

			if ( j == 2 )
			{
				CopySZ( szUserRight, sizeof( szUserRight ), "SeRemoteInteractiveLogonRight" );
			}

			if ( j == 3 )
			{
				CopySZ( szUserRight, sizeof( szUserRight ), "SeServiceLogonRight" );
			}

			if ( j == 4 )
			{
				CopySZ( szUserRight, sizeof( szUserRight ), "SeShutdownPrivilege" );
			}

			if ( j == 5 )
			{
				CopySZ( szUserRight, sizeof( szUserRight ), "SeRemoteShutdownPrivilege" );
			}

			ConvertSZtoWSZ( wszUserRight, sizeof( wszUserRight ), szUserRight );

			lusUserRight.Buffer        = wszUserRight;
			lusUserRight.Length        = (USHORT)( wcslen( wszUserRight ) * sizeof( WCHAR ) );
			lusUserRight.MaximumLength = (USHORT)( ( wcslen( wszUserRight ) + 1 ) * sizeof( WCHAR ) );

			pInfo = NULL;

			ntStatus = LsaEnumerateAccountsWithUserRight( lsahPolicyHandle, &lusUserRight, &pInfo, &dwCount );

			if ( ntStatus == 0 )
			{
				if ( pInfo != NULL )
				{
					pSIDs = (PSID *)pInfo;

					for ( k = 0; k < dwCount; k++ )
					{
						dwAccountName = sizeof( wszAccountName );
						dwDomainName  = sizeof( wszDomainName );

						if ( LookupAccountSid( wszTarget, pSIDs[k], wszAccountName, &dwAccountName, wszDomainName, &dwDomainName, &snUse ) )
						{
							ConvertWSZtoSZ( szAccountName, sizeof( szAccountName ), wszAccountName );
							ConvertWSZtoSZ( szDomainName, sizeof( szDomainName ), wszDomainName );

							if ( !bMultipleHosts )
							{
								if ( i == 0 )
								{
									printf( "\n" );
									printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
									printf( "+++++         USER RIGHTS INFORMATION         +++++\n" );
									printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
									printf( "\n" );

									i++;
								}

								printf( "User Right: %s\n", szUserRight );
								printf( "Username:   %s\\%s\n", szDomainName, szAccountName );
								printf( "\n" );

								fflush( stdout );
							}

							if ( bVerboseOptionSelected && bMultipleHosts )
							{
								printf( "%s -> Logging user rights information.\n", szTarget );

								fflush( stdout );
							}

							WaitForSingleObject( hSemaphore, INFINITE );

							pOutputFile = fopen( "Reports\\UserRightsInfo.txt", "r" );

							if ( pOutputFile != NULL )
							{
								fclose( pOutputFile );
							}
							else
							{
								pOutputFile = fopen( "Reports\\UserRightsInfo.txt", "w" );

								if ( pOutputFile != NULL )
								{
									fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
									fprintf( pOutputFile, "\n" );
									fprintf( pOutputFile, "Hostname\tUser Right\tUsername\n" );

									fclose( pOutputFile );
								}
							}

							pOutputFile = fopen( "Reports\\UserRightsInfo.txt", "a+" );

							if ( pOutputFile != NULL )
							{
								fprintf( pOutputFile, "%s\t%s\t%s\\%s\n", szTarget, szUserRight, szDomainName, szAccountName );

								fclose( pOutputFile );
							}

							ReleaseSemaphore( hSemaphore, 1, NULL );
						}
						else
						{
							dwError = GetLastError();

							CopySZ( szFunction, sizeof( szFunction ), "LookupAccountSid (GetUserRightsInfo)" );

							WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
						}
					}

					LsaFreeMemory( pInfo );
				}
			}
			else
			{
				dwError = LsaNtStatusToWinError( ntStatus );

				CopySZ( szFunction, sizeof( szFunction ), "LsaEnumerateAccountsWithUserRight (GetUserRightsInfo)" );

				WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
			}
		}

		LsaClose( lsahPolicyHandle );
	}
	else
	{
		dwError = LsaNtStatusToWinError( ntStatus );

		CopySZ( szFunction, sizeof( szFunction ), "LsaOpenPolicy (GetUserRightsInfo)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
	}
}

VOID GuessSNMPCommunityStrings( CHAR szTarget[] )
{
	FILE  *pCommStringFile;
	CHAR szCommunityString[ 128 ];
	CHAR        szFunction[ 128 ];
	CHAR        szErrorMsg[ 128 ];

	pCommStringFile = fopen( "CommunityStrings.input", "r" );

	if ( pCommStringFile != NULL )
	{
		if ( !bMultipleHosts )
		{
			printf( "\n" );
			printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
			printf( "+++++      GUESS SNMP COMMUNITY STRINGS       +++++\n" );
			printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
			printf( "\n" );

			fflush( stdout );
		}

		while ( fgets( szCommunityString, sizeof( szCommunityString ), pCommStringFile ) != NULL )
		{
			Trim( szCommunityString, sizeof( szCommunityString ) );

			if ( szCommunityString[0] != '#' && szCommunityString[0] != '\n' )
			{
				if ( szCommunityString[strlen( szCommunityString ) - 1] == '\n' )
				{
					szCommunityString[strlen( szCommunityString ) - 1] = '\0';
				}

				if ( bVerboseOptionSelected || !bMultipleHosts )
				{
					printf( "Trying community string... %s\n", szCommunityString );

					fflush( stdout );
				}

				if ( SNMPConnect( szTarget, szCommunityString ) )
				{
					LogGuessedCommunityStrings( szTarget, szCommunityString );

					if ( bVerboseOptionSelected || !bMultipleHosts )
					{
						printf( "\n" );
						printf( "COMMUNITY STRING GUESSED! %s\n", szCommunityString );

						fflush( stdout );
					}
				}
			}
		}

		if ( bVerboseOptionSelected || !bMultipleHosts )
		{
			printf( "\n" );

			fflush( stdout );
		}

		fclose( pCommStringFile );
	}
	else
	{
		CopySZ( szFunction, sizeof( szFunction ), "fopen (GuessSNMPCommunityStrings)" );
		CopySZ( szErrorMsg, sizeof( szErrorMsg ), "Cannot open file CommunityStrings.input." );

		WriteToErrorLog( szTarget, szFunction, szErrorMsg );
	}
}

BOOL SNMPConnect( CHAR szTarget[], CHAR szCommunityString[] )
{
	BOOL                bLogonSuccess;
	CHAR                  szCacheFile[ 128 ];
	DWORD                           i;
	LPSNMP_MGR_SESSION     smsSession;
	CHAR                        szOID[ 128 ];
	AsnObjectIdentifier        aoiOID;
	RFC1157VarBindList         vbInfo;
	DWORD                    dwResult;
	AsnInteger          aiErrorStatus;
	AsnInteger           aiErrorIndex;
	CHAR                   szUsername[ 128 ];
	AsnAny                     *pInfo;
	DWORD                           j;
	FILE                  *pCacheFile;
	DWORD                     dwError;
	CHAR                   szFunction[ 128 ];

	bLogonSuccess = FALSE;

	sprintf( szCacheFile, "UserCache\\%s.users", szTarget );

	i = 0;

	smsSession = NULL;

	smsSession = SnmpMgrOpen( szTarget, szCommunityString, 1000, 1 );

	if ( smsSession != NULL )
	{
		CopySZ( szOID, sizeof( szOID ), ".1.3.6.1.4.1.77.1.2.25.1.1" );

		if ( SnmpMgrStrToOid( szOID, &aoiOID ) )
		{
			vbInfo.len  = 1;
			vbInfo.list = NULL;

			vbInfo.list = (RFC1157VarBind *)SnmpUtilMemReAlloc( vbInfo.list, sizeof( RFC1157VarBind ) * vbInfo.len );

			vbInfo.list[0].name = aoiOID;

			while ( TRUE )
			{
				vbInfo.list[0].value.asnType = ASN_NULL;

				dwResult = SnmpMgrRequest( smsSession, ASN_RFC1157_GETNEXTREQUEST, &vbInfo, &aiErrorStatus, &aiErrorIndex );

				if ( dwResult != 0 )
				{
					if ( aiErrorStatus == SNMP_ERRORSTATUS_NOERROR )
					{
						bLogonSuccess = TRUE;

						CopySZ( szUsername, sizeof( szUsername ), "" );

						pInfo = &vbInfo.list[0].value;

						j = 0;

						while ( j < pInfo->asnValue.string.length )
						{
							szUsername[j] = pInfo->asnValue.string.stream[j];

							j++;
						}

						szUsername[j] = '\0';

						if ( strcmp( szUsername, "" ) == 0 )
						{
							break;
						}

						WaitForSingleObject( hSemaphore, INFINITE );

						if ( i == 0 )
						{
							pCacheFile = fopen( szCacheFile, "w" );

							if ( pCacheFile != NULL )
							{
								fclose( pCacheFile );
							}

							i++;
						}

						pCacheFile = fopen( szCacheFile, "a+" );

						if ( pCacheFile != NULL )
						{
							fprintf( pCacheFile, "%s\n", szUsername );

							fclose( pCacheFile );
						}

						ReleaseSemaphore( hSemaphore, 1, NULL );
					}
					else if ( aiErrorStatus == SNMP_ERRORSTATUS_NOSUCHNAME )
					{
						bLogonSuccess = TRUE;

						break;
					}
					else
					{
						break;
					}
				}
				else
				{
					break;
				}
			}

			SnmpUtilVarBindFree( &vbInfo.list[0] );

			SnmpUtilVarBindListFree( &vbInfo );
		}

		SnmpMgrClose( smsSession );
	}
	else
	{
		dwError = GetLastError();

		CopySZ( szFunction, sizeof( szFunction ), "SNMPMgrOpen (SNMPConnect)" );

		WriteLastErrorToErrorLog( szTarget, szFunction, &dwError );
	}

	return bLogonSuccess;
}

VOID LogGuessedCommunityStrings( CHAR szTarget[], CHAR szCommunityString[] )
{
	FILE *pOutputFile;

	WaitForSingleObject( hSemaphore, INFINITE );

	pOutputFile = fopen( "Reports\\GuessedSNMPCommunityStrings.txt", "r" );

	if ( pOutputFile != NULL )
	{
		fclose( pOutputFile );
	}
	else
	{
		pOutputFile = fopen( "Reports\\GuessedSNMPCommunityStrings.txt", "w" );

		if ( pOutputFile != NULL )
		{
			fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
			fprintf( pOutputFile, "\n" );
			fprintf( pOutputFile, "Hostname\tSNMP Community String\n" );

			fclose( pOutputFile );
		}
	}

	pOutputFile = fopen( "Reports\\GuessedSNMPCommunityStrings.txt", "a+" );

	if ( pOutputFile != NULL )
	{
		fprintf( pOutputFile, "%s\t%s\n", szTarget, szCommunityString );

		fclose( pOutputFile );
	}

	ReleaseSemaphore( hSemaphore, 1, NULL );
}

VOID GuessWindowsPasswords( CHAR szTarget[] )
{
	BOOL bSuppressErrors;
	CHAR     szCacheFile[ 512 ];
	FILE     *pCacheFile;
	CHAR      szUsername[ 128 ];
	FILE  *pPasswordFile;
	CHAR      szPassword[ 128 ];
	CHAR  szTempPassword[ 128 ];
	CHAR      szFunction[ 128 ];
	CHAR      szErrorMsg[ 128 ];

	bSuppressErrors = TRUE;

	sprintf( szCacheFile, "UserCache\\%s.users", szTarget );

	pCacheFile = fopen( szCacheFile, "r" );

	if ( pCacheFile != NULL )
	{
		if ( !bMultipleHosts )
		{
			printf( "\n" );
			printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
			printf( "+++++         GUESS WINDOWS PASSWORDS         +++++\n" );
			printf( "+++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
			printf( "\n" );

			fflush( stdout );
		}

		while ( fgets( szUsername, sizeof( szUsername ), pCacheFile ) != NULL )
		{
			Trim( szUsername, sizeof( szUsername ) );

			if ( szUsername[0] != '\n' )
			{
				if ( szUsername[strlen( szUsername ) - 1] == '\n' )
				{
					szUsername[strlen( szUsername ) - 1] = '\0';
				}

				pPasswordFile = fopen( "Dictionary.input", "r" );

				if ( pPasswordFile != NULL )
				{
					while ( fgets( szPassword, sizeof( szPassword ), pPasswordFile ) != NULL )
					{
						Trim( szPassword, sizeof( szPassword ) );

						if ( szPassword[0] != '#' && szPassword[0] != '\n' )
						{
							if ( szPassword[strlen( szPassword ) - 1] == '\n' )
							{
								szPassword[strlen( szPassword ) - 1] = '\0';
							}

							CopySZ( szTempPassword, sizeof( szTempPassword ), szPassword );

							_strupr( szTempPassword );

							if ( strcmp( szTempPassword, "<USERNAME>" ) == 0 )
							{
								CopySZ( szTempPassword, sizeof( szTempPassword ), szUsername );
							}
							else if ( strcmp( szTempPassword, "<UCUSERNAME>" ) == 0 )
							{
								CopySZ( szTempPassword, sizeof( szTempPassword ), szUsername );

								_strupr( szTempPassword );
							}
							else if ( strcmp( szTempPassword, "<LCUSERNAME>" ) == 0 )
							{
								CopySZ( szTempPassword, sizeof( szTempPassword ), szUsername );

								_strlwr( szTempPassword );
							}
							else if ( strcmp( szTempPassword, "<BLANK>" ) == 0 )
							{
								CopySZ( szTempPassword, sizeof( szTempPassword ), "" );
							}
							else
							{
								CopySZ( szTempPassword, sizeof( szTempPassword ), szPassword );
							}

							if ( bVerboseOptionSelected || !bMultipleHosts )
							{
								if ( strcmp( szTempPassword, "" ) == 0 )
								{
									printf( "Trying username:password... %s:<blank>\n", szUsername );
								}
								else
								{
									printf( "Trying username:password... %s:%s\n", szUsername, szTempPassword );
								}

								fflush( stdout );
							}

							if ( Connect( szTarget, szUsername, szTempPassword, TRUE ) )
							{
								Disconnect( szTarget );

								LogGuessedWindowsPasswords( szTarget, szUsername, szTempPassword );

								if ( bVerboseOptionSelected || !bMultipleHosts )
								{
									printf( "\n" );

									if ( strcmp( szTempPassword, "" ) == 0 )
									{
										printf( "PASSWORD GUESSED! Account %s, password is <blank>\n", szUsername );
									}
									else
									{
										printf( "PASSWORD GUESSED! Account %s, password is %s\n", szUsername, szTempPassword );
									}

									fflush( stdout );
								}

								break;
							}
						}
					}

					fclose( pPasswordFile );
				}
				else
				{
					CopySZ( szFunction, sizeof( szFunction ), "fopen (GuessWindowsPasswords)" );
					CopySZ( szErrorMsg, sizeof( szErrorMsg ), "Cannot open file Dictionary.input." );

					WriteToErrorLog( szTarget, szFunction, szErrorMsg );
				}
			}
		}

		if ( bVerboseOptionSelected || !bMultipleHosts )
		{
			printf( "\n" );

			fflush( stdout );
		}

		fclose( pCacheFile );
	}
	else
	{
		CopySZ( szFunction, sizeof( szFunction ), "fopen (GuessWindowsPasswords)" );

		sprintf( szErrorMsg, "Cannot open file %s.", szCacheFile );

		WriteToErrorLog( szTarget, szFunction, szErrorMsg );
	}
}

VOID LogGuessedWindowsPasswords( CHAR szTarget[], CHAR szUsername[], CHAR szPassword[] )
{
	FILE *pOutputFile;

	WaitForSingleObject( hSemaphore, INFINITE );

	pOutputFile = fopen( "Reports\\GuessedWindowsPasswords.txt", "r" );

	if ( pOutputFile != NULL )
	{
		fclose( pOutputFile );
	}
	else
	{
		pOutputFile = fopen( "Reports\\GuessedWindowsPasswords.txt", "w" );

		if ( pOutputFile != NULL )
		{
			fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
			fprintf( pOutputFile, "\n" );
			fprintf( pOutputFile, "Hostname\tUsername\tPassword\n" );

			fclose( pOutputFile );
		}
	}

	pOutputFile = fopen( "Reports\\GuessedWindowsPasswords.txt", "a+" );

	if ( pOutputFile != NULL )
	{
		if ( strcmp( szPassword, "" ) == 0 )
		{
			fprintf( pOutputFile, "%s\t%s\t<blank>\n", szTarget, szUsername );
		}
		else
		{
			fprintf( pOutputFile, "%s\t%s\t%s\n", szTarget, szUsername, szPassword );
		}

		fclose( pOutputFile );
	}

	ReleaseSemaphore( hSemaphore, 1, NULL );
}
