#include "fwshell.h"

#ifndef MIN
#define MIN(x, y) ((x < y) ? x : y)
#endif

VOID
Hexline(PCHAR lpData, DWORD dwSize)
{
    DWORD i = 0;

    for (i = 0; i < MIN(8, dwSize); i++)
        printf("%02x ", (BYTE)lpData[i]);

    if (dwSize > 8)
    {
        printf(" ");
        for (i = 8; i < dwSize; i++)
            printf("%02x ", (BYTE)lpData[i]);
    }

    if (dwSize < 16)
    {
        i = ((16 * 3) + 1) - (dwSize * 3);
        if (dwSize > 8) i--;
        printf("%*c", i, ' ');
    }

    for (i = 0; i < dwSize; i++)
    {
        if (lpData[i] > 0x20 && lpData[i] < 0x7f)
            printf("%c", lpData[i]);
        else
            printf(".");
    }

    return;
}

VOID
Hexdump(PCHAR lpData, DWORD dwSize)
{
    DWORD dwOffset = 0;
    PCHAR lpDataPtr = lpData;

    printf("[ %d (0x%x) bytes]\n", dwSize, dwSize);

    while (dwSize > 16)
    {
        printf("%08x: ", dwOffset);
        Hexline(lpDataPtr, 16);
        printf("\n");
        lpDataPtr += 16;
        dwOffset += 16;
        dwSize -= 16;
    }
    printf("%08x: ", dwOffset);
    Hexline(lpDataPtr, dwSize);
    printf("\n");

    return;
}