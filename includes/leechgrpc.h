// leechgrpc.h : external header of the libleechgrpc library.
//
// libleechgrpc is a library used by LeechCore to communicate with a LeechAgent
// gRPC server. The library provides functions to create a gRPC client and
// server, submit commands to the server, and handle incoming commands.
// 
// libleechgrpc offers a platform-independent way to communicate with remote
// LeechAgent instances, using gRPC as the underlying communication protocol.
// The library supports both insecure and secure connections, with secure
// connections using mTLS.
//
// For more information visit the project page at:
// https://github.com/ufrisk/libleechgrpc
//
// (c) Ulf Frisk, 2025
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __LEECHGRPC_H__
#define __LEECHGRPC_H__
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define LEECHGRPC_MESSAGE_SIZE_MAX          (64*1024*1024)
#define LEECHGRPC_CLIENT_TIMEOUT_MS         (5000)

#ifdef _WIN32

#include <Windows.h>
#define LEECHGRPC_EXPORTED_FUNCTION         __declspec(dllexport)

#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)

#include <inttypes.h>
#include <stdlib.h>
#define LEECHGRPC_EXPORTED_FUNCTION         __attribute__((visibility("default")))
typedef void                                VOID, *PVOID, *HANDLE;
typedef size_t                              SIZE_T;
typedef uint32_t                            DWORD, BOOL;
typedef uint8_t                             BYTE, *PBYTE;
typedef char                                CHAR, *LPSTR;
typedef const char                          *LPCSTR;
#define _Success_(x)
#define _In_
#define _Out_
#define _In_opt_

#endif /* LINUX || MACOS */

typedef void                                *LEECHGRPC_CLIENT_HANDLE, *LEECHGRPC_SERVER_HANDLE;



//-----------------------------------------------------------------------------
// LeechgRPC Client API:
//-----------------------------------------------------------------------------

/*
* Submit a command to the gRPC server.
* -- hGRPC: Handle to the gRPC client.
* -- pbIn: Pointer to the input buffer.
* -- cbIn: Size of the input buffer.
* -- ppbOut: Pointer to receive the output buffer. The caller is responsible for freeing this buffer with LocalFree/free.
* -- pcbOut: Pointer to receive the size of the output buffer.
* -- return: TRUE if the command was successfully submitted; otherwise, FALSE.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return)
BOOL leechgrpc_client_submit_command(
    _In_ LEECHGRPC_CLIENT_HANDLE hGRPC,
    _In_ PBYTE pbIn,
    _In_ SIZE_T cbIn,
    _Out_ PBYTE *ppbOut,
    _Out_ SIZE_T *pcbOut
);

typedef BOOL(*pfn_leechgrpc_client_submit_command)(
    _In_ LEECHGRPC_CLIENT_HANDLE hGRPC,
    _In_ PBYTE pbIn,
    _In_ SIZE_T cbIn,
    _Out_ PBYTE *ppbOut,
    _Out_ SIZE_T *pcbOut
);

/*
* Free the gRPC client connection.
* -- hGRPC: Handle to the gRPC client.
*/
LEECHGRPC_EXPORTED_FUNCTION
VOID leechgrpc_client_free(
    _In_ LEECHGRPC_CLIENT_HANDLE hGRPC
);

typedef VOID(*pfn_leechgrpc_client_free)(
    _In_ LEECHGRPC_CLIENT_HANDLE hGRPC
);

/*
* Create an insecure unauthenticated unencrypted gRPC client connection to the gRPC server.
* -- pszAddress: Address of the gRPC server.
* -- dwPort: Port of the gRPC server.
* -- return: Handle to the gRPC client connection, or NULL on failure.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_CLIENT_HANDLE leechgrpc_client_create_insecure(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort
);

typedef LEECHGRPC_CLIENT_HANDLE(*pfn_leechgrpc_client_create_insecure)(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort
);

/*
* Create a gRPC client connection to the gRPC server with mTLS.
* -- pszAddress: Address of the gRPC server.
* -- dwPort: Port of the gRPC server.
* -- szTlsServerHostnameOverride: Optional hostname to verify against the server certificate (if different from address).
* -- szTlsServerCertPath: Server CA certificate to trust for mTLS connections.
* -- szTlsClientP12Path: Path to the client's TLS certificate (incl. chain) & private key (.p12 / .pfx).
* -- szTlsClientP12Password: Password for the client's TLS certificate & private key (.p12 / .pfx).
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_CLIENT_HANDLE leechgrpc_client_create_secure_p12(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ LPCSTR szTlsServerHostnameOverride,
    _In_opt_ LPCSTR szTlsServerCertPath,
    _In_ LPCSTR szTlsClientP12Path,
    _In_ LPCSTR szTlsClientP12Password
);

typedef LEECHGRPC_CLIENT_HANDLE(*pfn_leechgrpc_client_create_secure_p12)(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ LPCSTR szTlsServerHostnameOverride,
    _In_opt_ LPCSTR szTlsServerCertPath,
    _In_ LPCSTR szTlsClientP12Path,
    _In_ LPCSTR szTlsClientP12Password
);

/*
* Create a gRPC client connection to the gRPC server with mTLS.
* -- pszAddress: Address of the gRPC server.
* -- dwPort: Port of the gRPC server.
* -- szTlsServerHostnameOverride: Optional hostname to verify against the server certificate (if different from address).
* -- szTlsServerCert: Server CA certificate to trust for mTLS connections.
* -- szTlsClientCert: Cerver TLS certificate.
* -- szTlsClientCertPrivateKey: Client TLS certificate private key.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_CLIENT_HANDLE leechgrpc_client_create_secure_pemraw(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ LPCSTR szTlsServerHostnameOverride,
    _In_opt_ LPCSTR szTlsServerCert,
    _In_ LPCSTR szTlsClientCert,
    _In_ LPCSTR szTlsClientCertPrivateKey
);

typedef LEECHGRPC_CLIENT_HANDLE(*pfn_leechgrpc_client_create_secure_pemraw)(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ LPCSTR szTlsServerHostnameOverride,
    _In_opt_ LPCSTR szTlsServerCert,
    _In_ LPCSTR szTlsClientCert,
    _In_ LPCSTR szTlsClientCertPrivateKey
);

/*
* Create a gRPC client connection to the gRPC server with mTLS.
* -- pszAddress: Address of the gRPC server.
* -- dwPort: Port of the gRPC server.
* -- szTlsServerHostnameOverride: Optional hostname to verify against the server certificate (if different from address).
* -- szTlsServerCertPath: Server CA certificate to trust for mTLS connections.
* -- szTlsClientCertPath: Cerver TLS certificate.
* -- szTlsClientCertPrivateKeyPath: Client TLS certificate private key.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_CLIENT_HANDLE leechgrpc_client_create_secure_pemfile(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ LPCSTR szTlsServerHostnameOverride,
    _In_opt_ LPCSTR szTlsServerCertPath,
    _In_ LPCSTR szTlsClientCertPath,
    _In_ LPCSTR szTlsClientCertPrivateKeyPath
);

typedef LEECHGRPC_CLIENT_HANDLE(*pfn_leechgrpc_client_create_secure_pemfile)(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ LPCSTR szTlsServerHostnameOverride,
    _In_opt_ LPCSTR szTlsServerCertPath,
    _In_ LPCSTR szTlsClientCertPath,
    _In_ LPCSTR szTlsClientCertPrivateKeyPath
);



//-----------------------------------------------------------------------------
// LeechgRPC Server API:
//-----------------------------------------------------------------------------

/*
* Callback function used to pass on a command received by the gRPC server.
* -- pbIn: Pointer to the input buffer.
* -- cbIn: Size of the input buffer.
* -- ppbOut: Pointer to receive the output buffer allocated by the callback function, freed by the caller.
* -- pcbOut: Pointer to receive the size of the output buffer.
*/
typedef VOID(*PFN_RESERVED_SUBMIT_COMMAND_CB)(_In_opt_ PVOID ctx, _In_ PBYTE pbIn, _In_ SIZE_T cbIn, _Out_ PBYTE *ppbOut, _Out_ SIZE_T *pcbOut);

/*
* Wait for the gRPC server to shutdown.
* -- hGRPC: Handle to the gRPC server.
*/
LEECHGRPC_EXPORTED_FUNCTION
VOID leechgrpc_server_wait(_In_ LEECHGRPC_SERVER_HANDLE hGRPC);

typedef VOID(*pfn_leechgrpc_server_wait)(_In_ LEECHGRPC_SERVER_HANDLE hGRPC);

/*
* Shut down the gRPC server.
* -- hGRPC: Handle to the gRPC server.
*/
LEECHGRPC_EXPORTED_FUNCTION
VOID leechgrpc_server_shutdown(_In_ LEECHGRPC_SERVER_HANDLE hGRPC);

typedef VOID(*pfn_leechgrpc_server_shutdown)(_In_ LEECHGRPC_SERVER_HANDLE hGRPC);

/*
* Create an insecure gRPC server without any authentication / encryption.
* -- szAddress: Address to listen on, e.g., "localhost" or "0.0.0.0".
* -- dwPort: Port to listen on.
* -- pfnReservedSubmitCommandCB: Callback function to handle incoming commands.
* -- return: Handle to the gRPC server, or NULL on failure.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_SERVER_HANDLE leechgrpc_server_create_insecure(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ PVOID ctx,
    _In_ PFN_RESERVED_SUBMIT_COMMAND_CB pfnReservedSubmitCommandCB
);

typedef LEECHGRPC_SERVER_HANDLE(*pfn_leechgrpc_server_create_insecure)(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ PVOID ctx,
    _In_ PFN_RESERVED_SUBMIT_COMMAND_CB pfnReservedSubmitCommandCB
);

/*
* Create a gRPC server with mTLS.
* -- szAddress: Address to listen on, e.g., "localhost" or "
* -- dwPort: Port to listen on.
* -- ctx: Optional context to pass to the callback function.
* -- pfnReservedSubmitCommandCB: Callback function to handle incoming commands.
* -- szTlsClientCertPath: Client CA certificate to trust for mTLS connections.
* -- szTlsServerP12Path: Path to the server's TLS certificate (incl. chain) & private key (.p12 / .pfx).
* -- szTlsServerP12Password: Password for the server's TLS certificate & private key (.p12 / .pfx).
* -- return: Handle to the gRPC server, or NULL on failure.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_SERVER_HANDLE leechgrpc_server_create_secure_p12(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ PVOID ctx,
    _In_ PFN_RESERVED_SUBMIT_COMMAND_CB pfnReservedSubmitCommandCB,
    _In_ LPCSTR szTlsClientCertPath,
    _In_ LPCSTR szTlsServerP12Path,
    _In_ LPCSTR szTlsServerP12Password
);

typedef LEECHGRPC_SERVER_HANDLE(*pfn_leechgrpc_server_create_secure_p12)(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ PVOID ctx,
    _In_ PFN_RESERVED_SUBMIT_COMMAND_CB pfnReservedSubmitCommandCB,
    _In_ LPCSTR szTlsClientCertPath,
    _In_ LPCSTR szTlsServerP12Path,
    _In_ LPCSTR szTlsServerP12Password
);

/*
* Create a gRPC server with mTLS.
* -- szAddress: Address to listen on, e.g., "localhost" or "
* -- dwPort: Port to listen on.
* -- ctx: Optional context to pass to the callback function.
* -- pfnReservedSubmitCommandCB: Callback function to handle incoming commands.
* -- szTlsClientCert: Client CA certificate to trust for mTLS connections.
* -- szTlsServerCert: Server TLS certificate (incl. chain).
* -- szTlsServerCertPrivateKey: Server TLS certificate private key.
* -- return: Handle to the gRPC server, or NULL on failure.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_SERVER_HANDLE leechgrpc_server_create_secure_pemraw(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ PVOID ctx,
    _In_ PFN_RESERVED_SUBMIT_COMMAND_CB pfnReservedSubmitCommandCB,
    _In_ LPCSTR szTlsClientCert,
    _In_ LPCSTR szTlsServerCert,
    _In_ LPCSTR szTlsServerCertPrivateKey
);

typedef LEECHGRPC_SERVER_HANDLE(*pfn_leechgrpc_server_create_secure_pemraw)(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ PVOID ctx,
    _In_ PFN_RESERVED_SUBMIT_COMMAND_CB pfnReservedSubmitCommandCB,
    _In_ LPCSTR szTlsClientCert,
    _In_ LPCSTR szTlsServerCert,
    _In_ LPCSTR szTlsServerCertPrivateKey
);

/*
* Create a gRPC server with mTLS.
* -- szAddress: Address to listen on, e.g., "localhost" or "
* -- dwPort: Port to listen on.
* -- ctx: Optional context to pass to the callback function.
* -- pfnReservedSubmitCommandCB: Callback function to handle incoming commands.
* -- szTlsClientCertPath: Client CA certificate to trust for mTLS connections.
* -- szTlsServerCertPath: Server TLS certificate (incl. chain).
* -- szTlsServerCertPrivateKeyPath: Server TLS certificate private key.
* -- return: Handle to the gRPC server, or NULL on failure.
*/
LEECHGRPC_EXPORTED_FUNCTION _Success_(return != NULL)
LEECHGRPC_SERVER_HANDLE leechgrpc_server_create_secure_pemfile(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ PVOID ctx,
    _In_ PFN_RESERVED_SUBMIT_COMMAND_CB pfnReservedSubmitCommandCB,
    _In_ LPCSTR szTlsClientCertPath,
    _In_ LPCSTR szTlsServerCertPath,
    _In_ LPCSTR szTlsServerCertPrivateKeyPath
);

typedef LEECHGRPC_SERVER_HANDLE(*pfn_leechgrpc_server_create_secure_pemfile)(
    _In_ LPCSTR szAddress,
    _In_ DWORD dwPort,
    _In_opt_ PVOID ctx,
    _In_ PFN_RESERVED_SUBMIT_COMMAND_CB pfnReservedSubmitCommandCB,
    _In_ LPCSTR szTlsClientCertPath,
    _In_ LPCSTR szTlsServerCertPath,
    _In_ LPCSTR szTlsServerCertPrivateKeyPath
);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* __LEECHGRPC_H__ */
