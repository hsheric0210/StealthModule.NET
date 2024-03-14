#pragma once

#include <Windows.h>
#include <winternl.h>

// 'MM' stands for 'ManualMap'

#define MM_MAX_PACKET_SIZE 16384 // 16KiB - Max guaranteed named pipe transmission message size

#define MM_ERROR_NO_EXPORT 0x1
#define MM_ERROR_OPEN_PIPE 0x2
#define MM_ERROR_READ_PIPE 0x3
#define MM_ERROR_WRITE_PIPE 0x4

#define MMRPC_OP_QUERY_PEB 0x1
#define MMRPC_OP_IS_MODULE_LOADED 0x2
#define MMRPC_OP_LOAD_DLL 0x3
#define MMRPC_OP_CALL_ENTRY 0x4
#define MMRPC_OP_ADD_FUNCTION_TABLE 0x5
#define MMRPC_OP_TERMINATE 0x6
#define MMRPC_OP_UNKNOWN 0xffff

typedef struct _PAYLOAD_PARAMETERS
{
    WCHAR namedPipePath[MAX_PATH];
} PAYLOAD_PARAMETERS, *PPAYLOAD_PARAMETERS;

typedef struct _MMRPC_PACKET
{
    DWORD opCode;
} MMRPC_PACKET, *PMMRPC_PACKET;

#pragma region Query PEB

typedef struct _MMRPC_PACKET_QUERY_PEB_RESPONSE
{
    DWORD opCode;
    UINT_PTR pebAddress;
} MMRPC_PACKET_QUERY_PEB_RESPONSE, *PMMRPC_PACKET_QUERY_PEB_RESPONSE;

#pragma endregion

#pragma region Is Module Loaded

typedef struct _MMRPC_PACKET_IS_MODULE_LOADED_REQUEST
{
    DWORD opCode;
    DWORD moduleNameHash;
} MMRPC_PACKET_IS_MODULE_LOADED_REQUEST, *PMMRPC_PACKET_IS_MODULE_LOADED_REQUEST;

#pragma endregion

#pragma region Load DLL

typedef struct _MMRPC_PACKET_LOAD_DLL_REQUEST
{
    DWORD opCode;
    PUNICODE_STRING addressToDllNameUnicodeString;
} MMRPC_PACKET_LOAD_DLL_REQUEST, *PMMRPC_PACKET_LOAD_DLL_REQUEST;

#pragma endregion

#pragma region Call Entrypoint or TLS

typedef struct _MMRPC_PACKET_CALL_ENTRY_REQUEST
{
    DWORD opCode;
    FARPROC entryAddress;
    PVOID baseAddress;
    DWORD callReason;
} MMRPC_PACKET_CALL_ENTRY_REQUEST, *PMMRPC_PACKET_CALL_ENTRY_REQUEST;

#pragma endregion

#pragma region Add Function Table (x64)

typedef struct _MMRPC_PACKET_ADD_FUNCTION_TABLE_REQUEST
{
    DWORD opCode;
    PRUNTIME_FUNCTION functionTableAddress;
    DWORD functionTableLength;
    PVOID baseAddress;
} MMRPC_PACKET_ADD_FUNCTION_TABLE_REQUEST, *PMMRPC_PACKET_ADD_FUNCTION_TABLE_REQUEST;

#pragma endregion

typedef struct _MMRPC_PACKET_DWORD_RESPONSE
{
    DWORD opCode;
    DWORD returnCode;
} MMRPC_PACKET_DWORD_RESPONSE, *PMMRPC_PACKET_DWORD_RESPONSE;

typedef struct _MMRPC_PACKET_NTSTATUS_RESPONSE
{
    DWORD opCode;
    NTSTATUS ntStatus;
} MMRPC_PACKET_NTSTATUS_RESPONSE, *PMMRPC_PACKET_NTSTATUS_RESPONSE;
