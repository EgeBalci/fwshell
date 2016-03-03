#include "fwshell.h"

SOCKET
Tcp4Bind(WORD wPort)
{
    WSADATA wsa;
    SOCKET Socket = INVALID_SOCKET;
    struct sockaddr_in server;
    int yes = 1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        wprintf(L"[-] WSAStartup() failed: %d.\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Socket == INVALID_SOCKET)
    {
        wprintf(L"[-] socket() failed: %d.\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(wPort);

    if (bind(Socket, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR)
    {
        wprintf(L"[-] bind() failed: %d.\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    listen(Socket, 3);

    return Socket;
}

SOCKET
Tcp4Connect(LPCWSTR lpHostname, LPCWSTR lpPort)
{
    WSADATA wsa;
    SOCKET Socket = INVALID_SOCKET;
    ADDRINFOW *result = NULL;
    ADDRINFOW *ptr = NULL;
    ADDRINFOW hints;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        wprintf(L"[-] WSAStartup() failed: %d.\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Socket == INVALID_SOCKET)
    {
        wprintf(L"[-] socket() failed: %d.\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (GetAddrInfoW(lpHostname, lpPort, &hints, &result) != 0)
    {
        wprintf(L"[-] Could not resolve `%s`.\n", lpHostname);
        return INVALID_SOCKET;
    }

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
    {
        if (connect(Socket, ptr->ai_addr, ptr->ai_addrlen) == 0)
            break;
    }

    if (ptr == NULL)
        return INVALID_SOCKET;

    return Socket;
}

DWORD
Tcp4ListenLoop(SOCKET SocketServer, LPTCP4HANDLER lpHandler)
{
    DWORD dwRet = 0;
    SOCKET SocketClient = INVALID_SOCKET;
    struct sockaddr_in client;
    DWORD dwClientSize = 0;

    while (1)
    {
        ZeroMemory(&client, sizeof(client));
        dwClientSize = sizeof(struct sockaddr_in);
        SocketClient = accept(SocketServer, (struct sockaddr *)&client, &dwClientSize);
        if (SocketClient == INVALID_SOCKET)
        {
            wprintf(L"[-] accept() failed: %d.\n", WSAGetLastError());
            return 0;
        }

        wprintf(L"[+] New connection received.\n");
        dwRet = lpHandler(SocketClient);

        closesocket(SocketClient);
        wprintf(L"[+] New connection closed.\n");
    }

    return dwRet;
}

DWORD
Tcp4Close(SOCKET Socket)
{
    closesocket(Socket);
    WSACleanup();

    return 1;
}