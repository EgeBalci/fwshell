#include "fwshell.h"

BOOL
ParseCommandLine(PCONFIG lpConfig, int argc, PWCHAR *argv)
{
    int i = 0;
    BOOL bPortSet = FALSE;
    BOOL bRet = FALSE;

    if (argc < 2)
        goto cleanup;

    for (i = 1; i < argc; i++)
    {
        if (!wcscmp(argv[i], L"-r"))
        {
            if (i >= argc)
                goto cleanup;

            lpConfig->doShell = FALSE;
            lpConfig->doSendFile = TRUE;
            lpConfig->lpFilename = argv[++i];
        }
        else if (!wcscmp(argv[i], L"-w"))
        {
            if (i >= argc)
                goto cleanup;

            lpConfig->doShell = FALSE;
            lpConfig->doReceiveFile = TRUE;
            lpConfig->lpFilename = argv[++i];
        }
        else if (!wcscmp(argv[i], L"-c"))
        {
            SSIZE_T Size = 0;
            if (i >= argc)
                goto cleanup;

            Size = (wcslen(argv[++i]) + 1);
            lpConfig->lpCommandLine = MALLOC(Size * sizeof(WCHAR));
            if (lpConfig->lpCommandLine == NULL)
                return FALSE;

            wcscpy_s(lpConfig->lpCommandLine, Size, argv[i]);
        }
        else if (!wcscmp(argv[i], L"-E"))
        {
            lpConfig->useTLs = FALSE;
        }
        else if (!wcscmp(argv[i], L"-t"))
        {
            if (i >= argc)
                goto cleanup;

            lpConfig->dwDelay = wcstol(argv[++i], NULL, 10);
            if (lpConfig->dwDelay == 0)
            {
                goto cleanup;
            }
        }
        else if (!wcscmp(argv[i], L"-s"))
        {
            lpConfig->doShell = FALSE;
            lpConfig->doShellcode = TRUE;
        }
        else
        {
            if (lpConfig->lpHostname == NULL)
                lpConfig->lpHostname = argv[i];
            else
            {
                if (bPortSet == TRUE)
                    goto cleanup;

                lpConfig->lpPort = argv[i];
                bPortSet = TRUE;
            }
        }
    }

    bRet = TRUE;
cleanup:
    if (bRet == FALSE && lpConfig->lpCommandLine != NULL)
        FREE(lpConfig->lpCommandLine);

    return bRet;
}