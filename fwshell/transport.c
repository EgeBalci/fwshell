#include "fwshell.h"

/*****************************************************************************/
/* Socket transport.                                                         */
/*****************************************************************************/

BOOL
TransportSocketInit(PCTX_TRANSPORT_INFO *self, LPCWSTR lpHostname, LPCWSTR lpPort)
{
    *self = MALLOC(sizeof(CTX_TRANSPORT_INFO));
    if (*self == NULL)
        return FALSE;

    (*self)->lpCtxInfo = MALLOC(sizeof(CTX_SOCKET_INFO));
    if ((*self)->lpCtxInfo == NULL)
    {
        FREE(*self);
        return FALSE;
    }

    ((PCTX_SOCKET_INFO)(*self)->lpCtxInfo)->lpHostname = lpHostname;
    ((PCTX_SOCKET_INFO)(*self)->lpCtxInfo)->lpPort = lpPort;

    (*self)->Deinit = &TransportSocketDeinit;
    (*self)->Connect = &TransportSocketConnect;
    (*self)->Disconnect = &TransportSocketDisconnect;
    (*self)->Read = &TransportSocketRead;
    (*self)->Write = &TransportSocketWrite;
    (*self)->GetMaxBufferSize = &TransportSocketGetMaxBufferSize;

    return TRUE;
}

BOOL
TransportSocketDeinit(PCTX_TRANSPORT_INFO *self)
{
    FREE(*self);
    *self = NULL;

    return TRUE;
}

BOOL
TransportSocketConnect(PCTX_TRANSPORT_INFO self)
{
    ((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->Socket = Tcp4Connect(((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->lpHostname,
        ((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->lpPort);
    if (((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->Socket == SOCKET_ERROR)
        return FALSE;

    return TRUE;
}

BOOL
TransportSocketDisconnect(PCTX_TRANSPORT_INFO self)
{
    if (Tcp4Close(((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->Socket) == 1)
        return TRUE;

    return FALSE;
}

DWORD
TransportSocketRead(PCTX_TRANSPORT_INFO self, PBYTE lpBuffer, DWORD dwSize)
{
    return recv(((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->Socket, lpBuffer, dwSize, 0);
}

DWORD
TransportSocketWrite(PCTX_TRANSPORT_INFO self, PBYTE lpBuffer, DWORD dwSize)
{
    return send(((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->Socket, lpBuffer, dwSize, 0);
}

SIZE_T
TransportSocketGetMaxBufferSize(PCTX_TRANSPORT_INFO self)
{
    return 0x10000;
}

/*****************************************************************************/
/* Tls transport.                                                            */
/*****************************************************************************/

BOOL
TransportTlsInit(PCTX_TRANSPORT_INFO *self, LPCWSTR lpHostname, LPCWSTR lpPort)
{
    if (LoadSecurityInterface() == 0)
        return FALSE;

    *self = MALLOC(sizeof(CTX_TRANSPORT_INFO));
    if (*self == NULL)
        return FALSE;

    (*self)->lpCtxInfo = MALLOC(sizeof(CTX_TLS_INFO));
    if ((*self)->lpCtxInfo == NULL)
    {
        FREE(*self);
        return FALSE;
    }

    ((PCTX_TLS_INFO)(*self)->lpCtxInfo)->lpHostname = lpHostname;
    ((PCTX_TLS_INFO)(*self)->lpCtxInfo)->lpPort = lpPort;

    if (TlsCreateCredentials(&((PCTX_TLS_INFO)(*self)->lpCtxInfo)->hClientCreds) == 0)
    {
        wprintf(L"[-] TlsCreateCredentials() failed.\n");
        TransportSocketDeinit(self);
        return FALSE;
    }

    (*self)->Deinit = &TransportSocketDeinit;
    (*self)->Connect = &TransportTlsConnect;
    (*self)->Disconnect = &TransportTlsDisconnect;
    (*self)->Read = &TransportTlsRead;
    (*self)->Write = &TransportTlsWrite;
    (*self)->GetMaxBufferSize = &TransportTlsGetMaxBufferSize;

    return TRUE;
}

BOOL
TransportTlsConnect(PCTX_TRANSPORT_INFO self)
{
    SecBuffer ExtraData;

    ((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->Socket = Tcp4Connect(((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->lpHostname,
        ((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->lpPort);
    if (((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->Socket == SOCKET_ERROR)
        return FALSE;

    if (TlsPerformClientHandshake(((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->Socket,
        &((PCTX_TLS_INFO)(self)->lpCtxInfo)->hClientCreds,
        ((PCTX_TLS_INFO)(self)->lpCtxInfo)->lpHostname,
        &((PCTX_TLS_INFO)(self)->lpCtxInfo)->hContext,
        &ExtraData) != SEC_E_OK)
    {
        wprintf(L"[-] Tls handshake failed.\n");
        return FALSE;
    }

    wprintf(L"[+] Tls handshake successful.\n");

    return TRUE;
}

BOOL
TransportTlsDisconnect(PCTX_TRANSPORT_INFO self)
{
    if (TlsClose(((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->Socket,
        &((PCTX_TLS_INFO)(self)->lpCtxInfo)->hClientCreds,
        &((PCTX_TLS_INFO)(self)->lpCtxInfo)->hContext) == 0)
        return FALSE;

    return TRUE;
}

DWORD
TransportTlsRead(PCTX_TRANSPORT_INFO self, PBYTE lpBuffer, DWORD dwSize)
{
    return TlsRecv(((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->Socket,
        &((PCTX_TLS_INFO)(self)->lpCtxInfo)->hClientCreds,
        &((PCTX_TLS_INFO)(self)->lpCtxInfo)->hContext,
        lpBuffer,
        dwSize);
}

DWORD
TransportTlsWrite(PCTX_TRANSPORT_INFO self, PBYTE lpBuffer, DWORD dwSize)
{
    return TlsSend(((PCTX_SOCKET_INFO)(self)->lpCtxInfo)->Socket,
        &((PCTX_TLS_INFO)(self)->lpCtxInfo)->hClientCreds,
        &((PCTX_TLS_INFO)(self)->lpCtxInfo)->hContext,
        lpBuffer,
        dwSize);
}

SIZE_T
TransportTlsGetMaxBufferSize(PCTX_TRANSPORT_INFO self)
{
    return TlsGetMaxBufferSize(&((PCTX_TLS_INFO)(self)->lpCtxInfo)->hContext);
}