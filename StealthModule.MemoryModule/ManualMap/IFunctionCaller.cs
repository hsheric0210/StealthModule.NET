using System;
using StealthModule.MemoryModule.Native;

namespace StealthModule.MemoryModule.ManualMap
{
    public interface IFunctionCaller
    {
        bool CallDllEntry(Pointer functionAddress, Pointer moduleHandle, DllReason callReason, Pointer reserved);

        int CallExeEntry(Pointer functionAddress);

        NTSTATUS AddFunctionTable(Pointer functionTableAddress, uint functionTableSize, Pointer baseAddress);

        Pointer LoadLibrary(string dllName);

        bool FreeLibrary(Pointer dllHandle);

        Pointer GetProcAddress(Pointer dllHandle, string functionName);

        Pointer GetProcAddress(Pointer dllHandle, ushort functionOrdinal);
    }
}
