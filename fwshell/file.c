#include "fwshell.h"

DWORD
FileReceive(PCTX_TRANSPORT_INFO lpTransportInfo, LPCWSTR lpFilename)
{
    DWORD dwRet = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PBYTE lpBuffer = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBytesRead = 0;

    hFile = CreateFile(lpFilename,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] Could not open `%s` for writing.\n", lpFilename);
        return 0;
    }

    dwBufferSize = lpTransportInfo->GetMaxBufferSize(lpTransportInfo);
    lpBuffer = MALLOC(dwBufferSize);
    if (lpBuffer == NULL)
        goto cleanup;

    while (1)
    {
        dwBytesRead = lpTransportInfo->Read(lpTransportInfo, lpBuffer, dwBufferSize);
        if (dwBytesRead == 0)
            break;

        if (WriteFile(hFile, lpBuffer, dwBytesRead, &dwBytesRead, 0) == FALSE)
            goto cleanup;
    }

    dwRet = 1;
cleanup:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    lpTransportInfo->Disconnect(lpTransportInfo);

    return dwRet;
}

DWORD
FileSend(PCTX_TRANSPORT_INFO lpTransportInfo, LPCWSTR lpFilename)
{
    DWORD dwRet = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PBYTE lpBuffer = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBytesRead = 0;

    hFile = CreateFile(lpFilename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] Could not open `%s` for reading.\n", lpFilename);
        return 0;
    }

    dwBufferSize = lpTransportInfo->GetMaxBufferSize(lpTransportInfo);
    lpBuffer = MALLOC(dwBufferSize);
    if (lpBuffer == NULL)
        goto cleanup;

    while (1)
    {
        if (ReadFile(hFile, lpBuffer, dwBufferSize, &dwBytesRead, NULL) == FALSE)
            goto cleanup;

        if (dwBytesRead == 0)
            break;

        dwBytesRead = lpTransportInfo->Write(lpTransportInfo, lpBuffer, dwBytesRead);
        if (dwBytesRead == 0)
            goto cleanup;
    }

    dwRet = 1;
cleanup:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    lpTransportInfo->Disconnect(lpTransportInfo);

    return dwRet;
}