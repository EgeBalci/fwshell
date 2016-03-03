#include "fwshell.h"

/* Freely inspired from http://www.coastrd.com/c-schannel-smtp */

#define IO_BUFFER_SIZE  0x10000

HMODULE g_hSecurity = NULL;
PSecurityFunctionTable g_pSSPI; /* FIXME: Look at W function. */

DWORD
LoadSecurityInterface()
{
    INIT_SECURITY_INTERFACE pInitSecurityInterface;

    g_hSecurity = LoadLibrary(TEXT("Secur32.dll"));
    if (g_hSecurity == NULL)
    {
        wprintf(L"[-] LoadLibrary() failed: %d.\n", GetLastError());
        return 0;
    }

    pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(g_hSecurity, "InitSecurityInterfaceW");
    if (pInitSecurityInterface == NULL)
    {
        wprintf(L"[-] Could not resolve pInitSecurityInterface.\n");
        FreeLibrary(g_hSecurity);
        return 0;
    }

    g_pSSPI = pInitSecurityInterface();
    if (g_pSSPI == NULL)
    {
        wprintf(L"[-] pInitSecurityInterface() failed: %d.\n", GetLastError());
        return 0;
    }

    return 1;
}

DWORD
TlsCreateCredentials(PCredHandle phCreds)
{
    SCHANNEL_CRED SchannelCred;
    SECURITY_STATUS Status;
    PCCERT_CONTEXT pCertContext = NULL;
    TimeStamp tsExpiry;
    ALG_ID Algs[2];

    ZeroMemory(&SchannelCred, sizeof(SchannelCred));
    SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;

    SchannelCred.grbitEnabledProtocols = SP_PROT_TLS1 | SP_PROT_TLS1_1 | SP_PROT_TLS1_2;
    Algs[0] = CALG_AES_256;
    Algs[1] = CALG_3DES;    /* For Windows XP */

    SchannelCred.cSupportedAlgs = 2;
    SchannelCred.palgSupportedAlgs = Algs;

    SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
    SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;

    /* Create an SSPI credential. */
    Status = g_pSSPI->AcquireCredentialsHandle(NULL,   
        UNISP_NAME,
        SECPKG_CRED_OUTBOUND,
        NULL,
        &SchannelCred,
        NULL,
        NULL,
        phCreds,
        &tsExpiry);

    if (Status != SEC_E_OK)
    {
        wprintf(L"[-] AcquireCredentialsHandle() failed: status %x.\n", Status);
        return 0;
    }

    return 1;
}

SECURITY_STATUS
TlsPerformClientHandshake(SOCKET Socket, PCredHandle phCreds, LPCWSTR pszServerName, PCtxtHandle phContext, PSecBuffer pExtraData)
{
    SecBufferDesc Message;
    SecBuffer Buffers[1];
    ULONG dwSSPIFlags = 0;
    ULONG dwSSPIOutFlags = 0;
    DWORD dwSent = 0;
    TimeStamp tsExpiry;
    SECURITY_STATUS Status = 0;

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
        ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

    /* Sending a ClientHello message and generate a token. */
    Buffers[0].pvBuffer = NULL;
    Buffers[0].BufferType = SECBUFFER_TOKEN;
    Buffers[0].cbBuffer = 0;

    Message.cBuffers = 1;
    Message.pBuffers = Buffers;
    Message.ulVersion = SECBUFFER_VERSION;

    /* FIXME: Use unicode functions. */
    Status = g_pSSPI->InitializeSecurityContext(phCreds,
        NULL,
        pszServerName,
        dwSSPIFlags,
        0,
        SECURITY_NATIVE_DREP,
        NULL,
        0,
        phContext,
        &Message,
        &dwSSPIOutFlags,
        &tsExpiry);

    if (Status != SEC_I_CONTINUE_NEEDED)
    { 
        wprintf(L"[-] InitializeSecurityContext() failed: status %d\n", Status); 
        return Status;
    }

    /* Sending the message. */
    if (Buffers[0].cbBuffer != 0 && Buffers[0].pvBuffer != NULL)
    {
        dwSent = send(Socket, Buffers[0].pvBuffer, Buffers[0].cbBuffer, 0);
        if (dwSent == SOCKET_ERROR || dwSent == 0)
        {
            wprintf(L"[-] Sending ClientHello failed: %d.\n", WSAGetLastError());
            g_pSSPI->FreeContextBuffer(Buffers[0].pvBuffer);
            g_pSSPI->DeleteSecurityContext(phContext);
            return SEC_E_INTERNAL_ERROR;
        }

        g_pSSPI->FreeContextBuffer(Buffers[0].pvBuffer);
        Buffers[0].pvBuffer = NULL;
    }

    return ClientHandshakeLoop(Socket, phCreds, phContext, TRUE, pExtraData);
}


SECURITY_STATUS 
ClientHandshakeLoop(SOCKET Socket, PCredHandle phCreds, PCtxtHandle phContext, BOOL bDoInitialRead, PSecBuffer pExtraData)
{
    SecBufferDesc MessageOut;
    SecBufferDesc MessageIn;
    SecBuffer BuffersIn[2];
    SecBuffer BuffersOut[1];
    ULONG dwSSPIFlags = 0;
    ULONG dwSSPIOutFlags = 0;
    DWORD dwReceived = 0;
    DWORD dwTotalReceived = 0;
    TimeStamp tsExpiry;
    SECURITY_STATUS Status = 0;
    PBYTE lpBuffer = NULL;
    BOOL fDoRead = TRUE;

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
        ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

    // Allocate data buffer.
    lpBuffer = MALLOC(IO_BUFFER_SIZE);
    if (lpBuffer == NULL)
        return SEC_E_INTERNAL_ERROR;

    fDoRead = bDoInitialRead;

    /* Loop until the handshake is finished or an error occurs. */
    Status = SEC_I_CONTINUE_NEEDED;

    while (Status == SEC_I_CONTINUE_NEEDED ||
           Status == SEC_E_INCOMPLETE_MESSAGE ||
           Status == SEC_I_INCOMPLETE_CREDENTIALS)
    {
        /* Receiving challenge. */
        if (0 == dwTotalReceived || Status == SEC_E_INCOMPLETE_MESSAGE)
        {
            if (fDoRead)
            {
                dwReceived = recv(Socket, lpBuffer + dwTotalReceived, IO_BUFFER_SIZE - dwTotalReceived, 0);
                if (dwReceived == SOCKET_ERROR)
                {
                    Status = SEC_E_INTERNAL_ERROR;
                    break;
                }
                else if (dwReceived == 0)
                {
                    Status = SEC_E_INTERNAL_ERROR;
                    break;
                }

                dwTotalReceived += dwReceived;
                if (dwTotalReceived < dwReceived)
                {
                    Status = SEC_E_INTERNAL_ERROR;
                    break;
                }

            }
            else
            {
                /* We want to skip receiving data only once. */
                fDoRead = TRUE;
            }
        }

        /* This contains data to be sent to the remote server.
           To be used with InitializeSecurityContext. */
        BuffersIn[0].pvBuffer = lpBuffer;
        BuffersIn[0].cbBuffer = dwTotalReceived;
        BuffersIn[0].BufferType = SECBUFFER_TOKEN;

        BuffersIn[1].pvBuffer = NULL;
        BuffersIn[1].cbBuffer = 0;
        BuffersIn[1].BufferType = SECBUFFER_EMPTY;

        MessageIn.cBuffers = 2;
        MessageIn.pBuffers = BuffersIn;
        MessageIn.ulVersion = SECBUFFER_VERSION;

        /* This contains data to be received to the remote server.
           To be used with InitializeSecurityContext. */
        BuffersOut[0].pvBuffer = NULL;
        BuffersOut[0].BufferType = SECBUFFER_TOKEN;
        BuffersOut[0].cbBuffer = 0;

        MessageOut.cBuffers = 1;
        MessageOut.pBuffers = BuffersOut;
        MessageOut.ulVersion = SECBUFFER_VERSION;

        Status = g_pSSPI->InitializeSecurityContext(phCreds,
            phContext,
            NULL,
            dwSSPIFlags,
            0,
            SECURITY_NATIVE_DREP,
            &MessageIn,
            0,
            NULL,
            &MessageOut,
            &dwSSPIOutFlags,
            &tsExpiry);

        if (Status == SEC_E_OK ||
            Status == SEC_I_CONTINUE_NEEDED ||
            FAILED(Status) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))
        {
            /* InitializeSecurityContext() may return a successful code but buffers are empty. */
            if (BuffersOut[0].cbBuffer != 0 && BuffersOut[0].pvBuffer != NULL)
            {
                /* Sending response. */
                dwReceived = send(Socket, BuffersOut[0].pvBuffer, BuffersOut[0].cbBuffer, 0);
                if (dwReceived == SOCKET_ERROR || dwReceived == 0)
                {
                    g_pSSPI->FreeContextBuffer(BuffersOut[0].pvBuffer);
                    g_pSSPI->DeleteSecurityContext(phContext);
                    FREE(lpBuffer);
                    return SEC_E_INTERNAL_ERROR;
                }

                g_pSSPI->FreeContextBuffer(BuffersOut[0].pvBuffer);
                BuffersOut[0].pvBuffer = NULL;
            }
        }

        /* Looping once more to receive the rest of the data. */
        if (Status == SEC_E_INCOMPLETE_MESSAGE)
        {
            continue;
        }

        /* Handshake was successful. */
        if (Status == SEC_E_OK)
        {
            if (BuffersIn[1].BufferType == SECBUFFER_EXTRA)
            {
                pExtraData->pvBuffer = MALLOC(BuffersIn[1].cbBuffer);
                if (pExtraData->pvBuffer == NULL) 
                {
                    FREE(lpBuffer);
                    return SEC_E_INTERNAL_ERROR;
                }

                MoveMemory(pExtraData->pvBuffer,
                    lpBuffer + (dwTotalReceived - BuffersIn[1].cbBuffer),
                    BuffersIn[1].cbBuffer);

                pExtraData->cbBuffer = BuffersIn[1].cbBuffer;
                pExtraData->BufferType = SECBUFFER_TOKEN;
            }
            else
            {
                pExtraData->pvBuffer = NULL;
                pExtraData->cbBuffer = 0;
                pExtraData->BufferType = SECBUFFER_EMPTY;
            }

            /* Nothing more to do. */
            break;
        }

        if (FAILED(Status))
        { 
            wprintf(L"[-] InitializeSecurityContext() failed: status %d\n", Status);
            break;
        }

        if (Status == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            /* Client authentication is not supported. */
            FREE(lpBuffer);
            return SEC_E_INTERNAL_ERROR;
        }

        /* Copy what's left in the extra buffer and loop once more. */
        if (BuffersIn[1].BufferType == SECBUFFER_EXTRA)
        {
            MoveMemory(lpBuffer, lpBuffer + (dwTotalReceived - BuffersIn[1].cbBuffer), BuffersIn[1].cbBuffer);
            dwTotalReceived = BuffersIn[1].cbBuffer;
        }
        else
            dwTotalReceived = 0;
    }

    if (FAILED(Status))
        g_pSSPI->DeleteSecurityContext(phContext);
    
    FREE(lpBuffer);

    return Status;
}

DWORD
TlsSend(SOCKET Socket, PCredHandle phCreds, CtxtHandle *phContext, PBYTE lpBuffer, DWORD dwLength)
{
    SECURITY_STATUS Status;
    SecBufferDesc Message;
    SecBuffer Buffers[4];
    PBYTE lpEncryptedBuffer = NULL;  
    SecPkgContext_StreamSizes Sizes;
    DWORD dwEncryptedLength = 0;

    /* Allocating memory for the encrypted buffer. */
    Status = g_pSSPI->QueryContextAttributes(phContext, SECPKG_ATTR_STREAM_SIZES, &Sizes);
    if (Status != SEC_E_OK)
        return 0;

    dwEncryptedLength = Sizes.cbHeader + dwLength + Sizes.cbTrailer;

    lpEncryptedBuffer = MALLOC(dwEncryptedLength);
    if (lpEncryptedBuffer == NULL)
        return 0;

    /* Copying the clear-text content. */
    CopyMemory(lpEncryptedBuffer + Sizes.cbHeader, lpBuffer, dwLength);

    /* Setting the buffer information for EncryptMessage(). */
    Buffers[0].pvBuffer = lpEncryptedBuffer;
    Buffers[0].cbBuffer = Sizes.cbHeader;
    Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    Buffers[1].pvBuffer = lpEncryptedBuffer + Sizes.cbHeader;
    Buffers[1].cbBuffer = dwLength;
    Buffers[1].BufferType = SECBUFFER_DATA;
    Buffers[2].pvBuffer = lpEncryptedBuffer + Sizes.cbHeader + dwLength;
    Buffers[2].cbBuffer = Sizes.cbTrailer;
    Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    Buffers[3].pvBuffer = SECBUFFER_EMPTY;
    Buffers[3].cbBuffer = SECBUFFER_EMPTY;
    Buffers[3].BufferType = SECBUFFER_EMPTY;

    Message.ulVersion = SECBUFFER_VERSION;
    Message.cBuffers = 4;
    Message.pBuffers = Buffers;

    Status = g_pSSPI->EncryptMessage(phContext, 0, &Message, 0);
    if (FAILED(Status)) 
    { 
        wprintf(L"[-] Encryption failed.\n");
        return 0;
    }

    dwEncryptedLength = Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer;
    if (send(Socket, lpEncryptedBuffer, dwEncryptedLength, 0) != dwEncryptedLength)
    {
        wprintf(L"[-] send() failed: %d.\n", WSAGetLastError());
        return 0;
    }

    FREE(lpEncryptedBuffer);

    return dwLength;
}

DWORD
TlsRecv(SOCKET Socket, PCredHandle phCreds, CtxtHandle *phContext, PBYTE lpBuffer, DWORD dwSize)
{
    DWORD dwBytesRead = 0;
    SecBuffer Buffers[4];
    SecBufferDesc Message;
    SECURITY_STATUS Status = 0;
    SecBuffer *pDataBuffer = NULL;
    SecBuffer *pExtraBuffer = NULL;
    PBYTE lpEncryptedBuffer = NULL;
    DWORD dwEncryptedBufferSize = 0;
    SecPkgContext_StreamSizes Sizes;
    int i = 0;

    Status = g_pSSPI->QueryContextAttributes(phContext, SECPKG_ATTR_STREAM_SIZES, &Sizes);
    if (Status != SEC_E_OK)
        return 0;

    /* FIXME: Support to read a lot. */
    if (dwSize > Sizes.cbMaximumMessage)
    {
        wprintf(L"[-] Trying to read too much\n");
        return 0;
    }

    dwEncryptedBufferSize = Sizes.cbHeader + dwSize + Sizes.cbTrailer;
    lpEncryptedBuffer = MALLOC(dwEncryptedBufferSize);
    if (lpEncryptedBuffer == NULL)
        return 0;

    while (1)
    {
        if (dwBytesRead == 0)
        {
            dwBytesRead = recv(Socket, lpEncryptedBuffer, dwEncryptedBufferSize, 0);
            if (dwBytesRead == SOCKET_ERROR)
            {
                return 0;
            }
        }

        /* Attempting to decrypt the buffer. */
        Buffers[0].pvBuffer = lpEncryptedBuffer;
        Buffers[0].cbBuffer = dwBytesRead;
        Buffers[0].BufferType = SECBUFFER_DATA;
        Buffers[1].BufferType = SECBUFFER_EMPTY;
        Buffers[2].BufferType = SECBUFFER_EMPTY;
        Buffers[3].BufferType = SECBUFFER_EMPTY;

        Message.ulVersion = SECBUFFER_VERSION;
        Message.cBuffers = 4;
        Message.pBuffers = Buffers;

        /* Decrypting the message. */
        Status = g_pSSPI->DecryptMessage(phContext, &Message, 0, NULL);

        if (Status == SEC_I_CONTEXT_EXPIRED)
        {
            wprintf(L"[-] Context expired.\n");
            return 0;
        }

        if (Status == SEC_E_INCOMPLETE_MESSAGE)
        {
            /* Server has dropped the connextion. */
            FREE(lpEncryptedBuffer);
            return 0;
        }

        if (Status != SEC_E_OK &&
            Status != SEC_I_RENEGOTIATE &&
            Status != SEC_I_CONTEXT_EXPIRED)
        {
            wprintf(L"[-] DecryptMessage() failed: Status %x.\n", Status);
            return 0;
        }

        pDataBuffer = NULL;
        pExtraBuffer = NULL;
        for (i = 1; i < 4; i++)
        {
            if (pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA)
                pDataBuffer = &Buffers[i];

            if (pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA) 
                pExtraBuffer = &Buffers[i];
        }

        if (pDataBuffer == NULL)
        {
            wprintf(L"[-] No decrypted buffer.\n");
        }

        /* DecryptMessage() may return successfully but with an empty buffer.
           When this happens, we need to loop once more to call DecryptMessage() again.
        */
        else if (pDataBuffer->cbBuffer != 0)
        {
            CopyMemory(lpBuffer, pDataBuffer->pvBuffer, pDataBuffer->cbBuffer);
            FREE(lpEncryptedBuffer);
            return pDataBuffer->cbBuffer;
        }

        if (pExtraBuffer != NULL)
        {
            CopyMemory(lpEncryptedBuffer, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
            dwBytesRead = pExtraBuffer->cbBuffer;
        }

        /* Server asked to renegotiate. */
        if (Status == SEC_I_RENEGOTIATE)
        {
            SecBuffer ExtraBuffer;

            Status = ClientHandshakeLoop(Socket, phCreds, phContext, FALSE, &ExtraBuffer);
            if (Status != SEC_E_OK) 
                return Status;

            if (ExtraBuffer.pvBuffer)
            {
                CopyMemory(lpEncryptedBuffer, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
                dwBytesRead = pExtraBuffer->cbBuffer;
            }

        }

    }

    return SEC_E_OK;
}

DWORD
TlsClose(SOCKET Socket, PCredHandle phCreds, PCtxtHandle phContext)
{
    DWORD dwRet = 0;
    SecBuffer Buffers[1];
    SecBufferDesc Message;
    DWORD dwType = SCHANNEL_SHUTDOWN;
    SECURITY_STATUS Status = 0;
    TimeStamp tsExpiry;
    ULONG SSPIFlags = 0;
    ULONG SSPIOutFlags = 0;
    DWORD dwBytesSent = 0;

    Buffers[0].pvBuffer = &dwType;
    Buffers[0].BufferType = SECBUFFER_TOKEN;
    Buffers[0].cbBuffer = sizeof(dwType);

    Message.cBuffers = 1;
    Message.pBuffers = Buffers;
    Message.ulVersion = SECBUFFER_VERSION;

    Status = g_pSSPI->ApplyControlToken(phContext, &Message);
    if (Status != SEC_E_OK)
    {
        wprintf(L"[-] ApplyControlToken() failed: status %x.\n", Status);
        return 0;
    }

    Buffers[0].pvBuffer = NULL;
    Buffers[0].BufferType = SECBUFFER_TOKEN;
    Buffers[0].cbBuffer = 0;

    Message.cBuffers = 1;
    Message.pBuffers = Buffers;
    Message.ulVersion = SECBUFFER_VERSION;

    /* TLS close notify message. */
    SSPIFlags = ISC_REQ_SEQUENCE_DETECT |
        ISC_REQ_REPLAY_DETECT |
        ISC_REQ_CONFIDENTIALITY |
        ISC_RET_EXTENDED_ERROR |
        ISC_REQ_ALLOCATE_MEMORY |
        ISC_REQ_STREAM;

    Status = g_pSSPI->InitializeSecurityContext(phCreds,
        phContext,
        NULL,
        SSPIFlags,
        0,
        SECURITY_NATIVE_DREP,
        NULL,
        0,
        phContext,
        &Message,
        &SSPIOutFlags,
        &tsExpiry);

    if (Status != SEC_E_OK)
    {
        wprintf(L"[-] InitializeSecurityContext() failed: status %x.\n", Status);
        goto cleanup;
    }

    /* Sending the notify message. */
    if (Buffers[0].pvBuffer != NULL && Buffers[0].cbBuffer != 0)
    {
        dwBytesSent = send(Socket, Buffers[0].pvBuffer, Buffers[0].cbBuffer, 0);
        if (dwBytesSent == SOCKET_ERROR || dwBytesSent == 0)
        {
            wprintf(L"[-] send() failed: %d.\n", WSAGetLastError());
            goto cleanup;
        }

        g_pSSPI->FreeContextBuffer(Buffers[0].pvBuffer);
    }

    dwRet = 1;
cleanup:
    g_pSSPI->DeleteSecurityContext(phContext);
    closesocket(Socket);

    return dwRet;
}

SSIZE_T
TlsGetMaxBufferSize(PCtxtHandle phContext)
{
    SECURITY_STATUS Status;
    SecPkgContext_StreamSizes Sizes;

    /* Allocating memory for the encrypted buffer. */
    Status = g_pSSPI->QueryContextAttributes(phContext, SECPKG_ATTR_STREAM_SIZES, &Sizes);
    if (Status != SEC_E_OK)
        return 0;

    return Sizes.cbMaximumMessage;
}