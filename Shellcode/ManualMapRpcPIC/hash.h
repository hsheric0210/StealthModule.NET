#pragma once

#define HASH_NTDLL /*<djb2:ntdll.dll>*/0x22D3B5ED/*</djb2>*/
#define HASH_KERNEL32DLL /*<djb2:kernel32.dll>*/0x7040EE75/*</djb2>*/

// ntdll

#define HASH_LDRLOADDLL /*<djb2:LdrLoadDll>*/0x0307DB23/*</djb2>*/
#define HASH_RTLINITUNICODESTRING /*<djb2:RtlInitUnicodeString>*/0x29B75F89/*</djb2>*/
#define HASH_RTLADDFUNCTIONTABLE /*<djb2:RtlAddFunctionTable>*/0xBDB9F1AE/*</djb2>*/

// kernel32

#define HASH_CREATEFILEW /*<djb2:CreateFileW>*/0xEB96C610/*</djb2>*/
#define HASH_READFILE /*<djb2:ReadFile>*/0x71019921/*</djb2>*/
#define HASH_WRITEFILE /*<djb2:WriteFile>*/0x663CECB0/*</djb2>*/
#define HASH_CLOSEHANDLE /*<djb2:CloseHandle>*/0x3870CA07/*</djb2>*/
#define HASH_VIRTUALALLOC /*<djb2:VirtualAlloc>*/0x382C0F97/*</djb2>*/
#define HASH_VIRTUALFREE /*<djb2:VirtualFree>*/0x668FCF2E/*</djb2>*/
